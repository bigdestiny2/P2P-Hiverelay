import test from 'brittle'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const RELEASE_BASE = `https://github.com/${REPOSITORY}/releases/download/v9.9.9`
const REGISTRY_URL = 'https://registry.start9.com/startos'
const REGISTRY_PACKAGE_URL = `${REGISTRY_URL}/blindspark`
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const WRITE_STARTOS_REGISTRY_EVIDENCE_SCRIPT = path.join(process.cwd(), 'scripts/write-startos-registry-evidence.mjs')
const PACKAGE_BYTES = 'startos package\n'
const IMAGE_MANIFEST_BYTES = '{"kind":"release-image-manifest"}\n'
const IMAGE_SMOKE_BYTES = '{"kind":"release-image-smoke"}\n'
const PACKAGE_SHA256 = sha256(PACKAGE_BYTES)
const IMAGE_MANIFEST_SHA256 = sha256(IMAGE_MANIFEST_BYTES)
const IMAGE_SMOKE_SHA256 = sha256(IMAGE_SMOKE_BYTES)
const LINKED_EVIDENCE_FILES = [
  'release-image-manifest-evidence.json',
  'release-image-smoke-evidence.json'
]

async function runWriter (outFile, env, opts = {}) {
  const cwd = opts.cwd || path.dirname(path.resolve(outFile))
  if (opts.linkedEvidence !== false) await writeLinkedEvidence(cwd, opts.linkedEvidence || {})
  if (opts.packageBytes !== false) {
    const packageBytes = opts.packageBytes || PACKAGE_BYTES
    await mkdir(path.join(cwd, 'startos'), { recursive: true })
    await writeFile(path.join(cwd, 'startos/blindspark.s9pk'), packageBytes)
  }
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [WRITE_STARTOS_REGISTRY_EVIDENCE_SCRIPT, '--out', outFile], {
      cwd,
      env: { ...process.env, ...env },
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}

async function writeLinkedEvidence (dir, overrides = {}) {
  const evidence = {
    'release-image-manifest-evidence.json': IMAGE_MANIFEST_BYTES,
    'release-image-smoke-evidence.json': IMAGE_SMOKE_BYTES
  }
  await mkdir(dir, { recursive: true })
  for (const file of LINKED_EVIDENCE_FILES) {
    if (overrides[file] === false) continue
    await writeFile(path.join(dir, file), Object.prototype.hasOwnProperty.call(overrides, file) ? overrides[file] : evidence[file])
  }
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function env (overrides = {}) {
  return {
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: REPOSITORY,
    GITHUB_RUN_ID: '12345',
    GITHUB_RUN_ATTEMPT: '2',
    HIVERELAY_RELEASE_VERSION: 'v9.9.9',
    HIVERELAY_RELEASE_SEMVER: '9.9.9',
    HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: 'release-image-manifest-evidence.json',
    HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256: IMAGE_MANIFEST_SHA256,
    HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE: 'release-image-smoke-evidence.json',
    HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: IMAGE_SMOKE_SHA256,
    HIVERELAY_STARTOS_PACKAGE_ID: 'blindspark',
    HIVERELAY_STARTOS_PACKAGE_SHA256: PACKAGE_SHA256,
    HIVERELAY_STARTOS_REGISTRY_URL: REGISTRY_URL,
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: REGISTRY_PACKAGE_URL,
    ...overrides
  }
}

test('StartOS registry evidence writer keeps a closed public schema', async (t) => {
  const script = await readFile(WRITE_STARTOS_REGISTRY_EVIDENCE_SCRIPT, 'utf8')

  t.ok(script.includes('assertStartosRegistryEvidenceSchema(body)'))
  t.ok(script.includes('function assertStartosRegistryEvidenceSchema'))
  t.ok(script.includes("requireOnlyKeys('StartOS registry evidence'"))
  t.ok(script.includes('has unsupported fields'))
})

test('StartOS registry evidence writer records public package and registry facts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  await runWriter(outFile, env())

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.ok(ISO_TIMESTAMP_PATTERN.test(body.generatedAt), 'StartOS registry evidence generatedAt is an ISO timestamp')
  t.is(body.kind, 'startos-registry-publication')
  t.is(body.status, 'published')
  t.is(body.release.version, 'v9.9.9')
  t.is(body.package.id, 'blindspark')
  t.is(body.package.sha256, PACKAGE_SHA256)
  t.is(body.package.url, REGISTRY_PACKAGE_URL)
  t.is(body.registry.url, REGISTRY_URL)
  t.is(body.workflow.runUrl, `https://github.com/${REPOSITORY}/actions/runs/12345`)
  t.is(body.evidenceLinks.releaseEvidence, `${RELEASE_BASE}/release-evidence.json`)
  t.is(body.evidenceLinks.releaseImageManifest, `${RELEASE_BASE}/release-image-manifest-evidence.json`)
  t.is(body.evidenceLinks.releaseImageSmoke, `${RELEASE_BASE}/release-image-smoke-evidence.json`)
  t.is(body.evidenceLinks.startosPackage, `${RELEASE_BASE}/blindspark.s9pk`)
  t.is(body.evidenceLinks.registryPackage, REGISTRY_PACKAGE_URL)
})

test('StartOS registry evidence writer verifies present package artifacts before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const packageBytes = 'startos package\n'
  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/blindspark.s9pk'), packageBytes)

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  await runWriter(outFile, env({
    HIVERELAY_STARTOS_PACKAGE_SHA256: sha256(packageBytes)
  }), { cwd: dir })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.package.path, 'startos/blindspark.s9pk')
  t.is(body.package.sha256, sha256(packageBytes))
})

test('StartOS registry evidence writer hashes present package artifacts as a stream', async (t) => {
  const script = await readFile(WRITE_STARTOS_REGISTRY_EVIDENCE_SCRIPT, 'utf8')
  t.ok(script.includes('fs.createReadStream(file)'), 'package hash check streams the .s9pk')
  t.absent(script.includes('fs.readFileSync(file)'), 'package hash check does not load the full .s9pk into memory')
})

test('StartOS registry evidence writer requires the local package artifact before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env(), { cwd: dir, packageBytes: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package file is required before writing registry evidence'))
})

test('StartOS registry evidence writer requires linked release image evidence before writing registry evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const missingFile = path.join(dir, 'missing-linked-image-proof.json')
  let missingErr = null
  try {
    await runWriter(missingFile, env(), {
      cwd: dir,
      linkedEvidence: { 'release-image-manifest-evidence.json': false }
    })
  } catch (e) {
    missingErr = e
  }
  t.ok(missingErr)
  t.ok(missingErr.stderr.includes('release image manifest evidence file is required before writing registry evidence: release-image-manifest-evidence.json'))

  const symlinkDir = path.join(dir, 'symlink')
  await mkdir(symlinkDir, { recursive: true })
  await writeFile(path.join(symlinkDir, 'manifest-target.json'), '{}\n')
  await symlink('manifest-target.json', path.join(symlinkDir, 'release-image-manifest-evidence.json'))
  const symlinkFile = path.join(symlinkDir, 'symlink-linked-image-proof.json')
  let symlinkErr = null
  try {
    await runWriter(symlinkFile, env(), { cwd: symlinkDir, linkedEvidence: false })
  } catch (e) {
    symlinkErr = e
  }
  t.ok(symlinkErr)
  t.ok(symlinkErr.stderr.includes('release image manifest evidence file must not be a symlink: release-image-manifest-evidence.json'))

  const oversizedDir = path.join(dir, 'oversized')
  await mkdir(oversizedDir, { recursive: true })
  await writeFile(path.join(oversizedDir, 'release-image-manifest-evidence.json'), IMAGE_MANIFEST_BYTES)
  await writeFile(path.join(oversizedDir, 'release-image-smoke-evidence.json'), Buffer.alloc(2 * 1024 * 1024 + 1, 'x'))
  const oversizedFile = path.join(oversizedDir, 'oversized-linked-image-proof.json')
  let oversizedErr = null
  try {
    await runWriter(oversizedFile, env(), { cwd: oversizedDir, linkedEvidence: false })
  } catch (e) {
    oversizedErr = e
  }
  t.ok(oversizedErr)
  t.ok(oversizedErr.stderr.includes('release image smoke evidence file must be 2097152 bytes or smaller'))
})

test('StartOS registry evidence writer rejects linked release image evidence hash drift', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'stale-linked-image-proof.json')
  let err = null
  try {
    await runWriter(outFile, env(), {
      cwd: dir,
      linkedEvidence: {
        'release-image-smoke-evidence.json': '{"kind":"release-image-smoke","stale":true}\n'
      }
    })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image smoke evidence SHA-256 does not match release-image-smoke-evidence.json'))
})

test('StartOS registry evidence writer rejects miswired release image evidence env before writing registry evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const wrongPathFile = path.join(dir, 'wrong-linked-image-path.json')
  let wrongPathErr = null
  try {
    await runWriter(wrongPathFile, env({
      HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: 'manifest.json'
    }), { cwd: dir })
  } catch (e) {
    wrongPathErr = e
  }
  t.ok(wrongPathErr)
  t.ok(wrongPathErr.stderr.includes('release image manifest evidence path'))

  const badShaFile = path.join(dir, 'bad-linked-image-sha.json')
  let badShaErr = null
  try {
    await runWriter(badShaFile, env({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: 'not-a-sha'
    }), { cwd: dir })
  } catch (e) {
    badShaErr = e
  }
  t.ok(badShaErr)
  t.ok(badShaErr.stderr.includes('release image smoke evidence SHA-256'))
})

test('StartOS registry evidence writer rejects unsafe linked release image evidence before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const unsafe = '{"kind":"release-image-smoke","token":"Bearer abcdefghijklmnopqrstuvwxyz"}\n'
  const outFile = path.join(dir, 'unsafe-linked-image-proof.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: sha256(unsafe)
    }), {
      cwd: dir,
      linkedEvidence: {
        'release-image-smoke-evidence.json': unsafe
      }
    })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image smoke evidence must not contain bearer token'))
})

test('StartOS registry evidence writer rejects linked release image evidence kind drift', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const wrongManifest = '{"kind":"release-image-smoke"}\n'
  const outFile = path.join(dir, 'wrong-linked-image-kind.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256: sha256(wrongManifest)
    }), {
      cwd: dir,
      linkedEvidence: {
        'release-image-manifest-evidence.json': wrongManifest
      }
    })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest evidence kind must be "release-image-manifest"'))
})

test('StartOS registry evidence writer rejects symlinked present package artifacts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/package-target.s9pk'), 'startos package\n')
  await symlink('package-target.s9pk', path.join(dir, 'startos/blindspark.s9pk'))

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env(), { cwd: dir, packageBytes: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package file must not be a symlink'))
})

test('StartOS registry evidence writer rejects non-regular present package artifacts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'startos/blindspark.s9pk'), { recursive: true })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env(), { cwd: dir, packageBytes: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package file must be a regular file'))
})

test('StartOS registry evidence writer rejects present package artifact hash drift', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const packageBytes = 'stale startos package\n'
  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/blindspark.s9pk'), packageBytes)

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_PACKAGE_SHA256: '0'.repeat(64)
    }), { cwd: dir, packageBytes: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package SHA-256 does not match startos/blindspark.s9pk'))
  t.ok(err.stderr.includes(sha256(packageBytes)), 'reports the actual present package hash')
})

test('StartOS registry evidence writer derives package URL from registry and package id', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  await runWriter(outFile, env({
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: ''
  }))

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.package.url, REGISTRY_PACKAGE_URL)
  t.is(body.evidenceLinks.registryPackage, REGISTRY_PACKAGE_URL)
})

test('StartOS registry evidence writer rejects non-canonical release repositories', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      GITHUB_REPOSITORY: 'attacker/P2P-Hiverelay'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes(`workflow repository must be "${REPOSITORY}"`))
})

test('StartOS registry evidence writer rejects non-https registry URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_URL: 'http://registry.start9.com/startos'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry URL'))
})

test('StartOS registry evidence writer rejects credentialed registry URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_URL: 'https://user:pass@registry.start9.com/startos'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('URL credentials') || err.stderr.includes('without embedded credentials'))
})

test('StartOS registry evidence writer rejects mismatched package URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: 'https://registry.start9.com/startos/other'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry package URL'))
})

test('StartOS registry evidence writer rejects non-numeric run attempts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      GITHUB_RUN_ATTEMPT: 'not-a-number'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('workflow run attempt'))

  const zeroAttemptFile = path.join(dir, 'zero-attempt.json')
  let zeroAttemptErr = null
  try {
    await runWriter(zeroAttemptFile, env({
      GITHUB_RUN_ATTEMPT: '0'
    }))
  } catch (e) {
    zeroAttemptErr = e
  }

  t.ok(zeroAttemptErr)
  t.ok(zeroAttemptErr.stderr.includes('workflow run attempt'))

  const zeroRunIdFile = path.join(dir, 'zero-run-id.json')
  let zeroRunIdErr = null
  try {
    await runWriter(zeroRunIdFile, env({
      GITHUB_RUN_ID: '0'
    }))
  } catch (e) {
    zeroRunIdErr = e
  }

  t.ok(zeroRunIdErr)
  t.ok(zeroRunIdErr.stderr.includes('workflow run id'))

  const badServerFile = path.join(dir, 'bad-workflow-server.json')
  let badServerErr = null
  try {
    await runWriter(badServerFile, env({
      GITHUB_SERVER_URL: 'https://github.com/attacker'
    }))
  } catch (e) {
    badServerErr = e
  }

  t.ok(badServerErr)
  t.ok(badServerErr.stderr.includes('workflow URL'))
})

test('StartOS registry evidence writer rejects whitespace-normalized metadata before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const cases = [
    ['run-id', { GITHUB_RUN_ID: ' 12345' }, 'workflow run id'],
    ['run-attempt', { GITHUB_RUN_ATTEMPT: '2 ' }, 'workflow run attempt'],
    ['server-url', { GITHUB_SERVER_URL: 'https://github.com ' }, 'workflow URL'],
    ['package-id', { HIVERELAY_STARTOS_PACKAGE_ID: 'blindspark ' }, 'StartOS package id'],
    ['package-sha', { HIVERELAY_STARTOS_PACKAGE_SHA256: `${PACKAGE_SHA256} ` }, 'StartOS package SHA-256'],
    ['registry-url', { HIVERELAY_STARTOS_REGISTRY_URL: `${REGISTRY_URL} ` }, 'StartOS registry URL'],
    ['image-manifest-path', { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: ' release-image-manifest-evidence.json' }, 'release image manifest evidence path']
  ]

  for (const [name, overrides, message] of cases) {
    const outFile = path.join(dir, `${name}.json`)
    let err = null
    try {
      await runWriter(outFile, env(overrides))
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)

    let evidenceErr = null
    try {
      await readFile(outFile, 'utf8')
    } catch (e) {
      evidenceErr = e
    }
    t.ok(evidenceErr, `${name} does not write public evidence`)
  }
})

test('StartOS registry evidence writer rejects secret-looking public values before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      GITHUB_RUN_ATTEMPT: 'Bearer abcdefghijklmnopqrstuvwxyz'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('bearer token') || err.stderr.includes('workflow run attempt'))
})

test('StartOS registry evidence writer rejects control-character public values before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_URL: 'https://registry.start9.com/startos\nnext'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry evidence must not contain control characters'))
})

test('StartOS registry evidence writer rejects placeholder registry hosts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-registry-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'startos-registry-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_URL: 'https://registry.example/startos'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('reserved/local hostnames'))
})
