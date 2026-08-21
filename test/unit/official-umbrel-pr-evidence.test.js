import test from 'brittle'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const HEAD_SHA = 'a'.repeat(40)
const REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const RELEASE_BASE = `https://github.com/${REPOSITORY}/releases/download/v9.9.9`
const STARTOS_REGISTRY_PACKAGE_URL = 'https://registry.start9.com/startos/blindspark'
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const WRITE_OFFICIAL_UMBREL_PR_EVIDENCE_SCRIPT = path.join(process.cwd(), 'scripts/write-official-umbrel-pr-evidence.mjs')
const IMAGE_MANIFEST_BYTES = '{"kind":"release-image-manifest"}\n'
const IMAGE_SMOKE_BYTES = '{"kind":"release-image-smoke"}\n'
const UMBREL_SMOKE_BYTES = '{"kind":"umbrel-package-smoke"}\n'
const FLEET_ROLLOUT_BYTES = '{"kind":"fleet-rollout"}\n'
const STARTOS_REGISTRY_BYTES = '{"kind":"startos-registry-publication"}\n'
const STARTOS_PACKAGE_BYTES = 's9pk\n'
const IMAGE_MANIFEST_SHA = sha256(IMAGE_MANIFEST_BYTES)
const IMAGE_SMOKE_SHA = sha256(IMAGE_SMOKE_BYTES)
const UMBREL_SMOKE_SHA = sha256(UMBREL_SMOKE_BYTES)
const FLEET_ROLLOUT_SHA = sha256(FLEET_ROLLOUT_BYTES)
const STARTOS_REGISTRY_SHA = sha256(STARTOS_REGISTRY_BYTES)
const STARTOS_PACKAGE_SHA = sha256(STARTOS_PACKAGE_BYTES)
const LINKED_EVIDENCE_FILES = [
  'release-evidence.json',
  'release-image-manifest-evidence.json',
  'release-image-smoke-evidence.json',
  'umbrel-package-smoke-evidence.json',
  'fleet-rollout-evidence.json',
  'startos-registry-evidence.json'
]

async function runWriter (outFile, env, opts = {}) {
  const cwd = opts.cwd || path.dirname(path.resolve(outFile))
  if (opts.linkedArtifacts !== false) await writeLinkedArtifacts(cwd)
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [WRITE_OFFICIAL_UMBREL_PR_EVIDENCE_SCRIPT, '--out', outFile], {
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

async function writeLinkedArtifacts (dir, overrides = {}) {
  const artifacts = {
    'release-evidence.json': releaseEvidenceBytes(),
    'release-image-manifest-evidence.json': IMAGE_MANIFEST_BYTES,
    'release-image-smoke-evidence.json': IMAGE_SMOKE_BYTES,
    'umbrel-package-smoke-evidence.json': UMBREL_SMOKE_BYTES,
    'fleet-rollout-evidence.json': FLEET_ROLLOUT_BYTES,
    'startos-registry-evidence.json': STARTOS_REGISTRY_BYTES,
    'startos/blindspark.s9pk': STARTOS_PACKAGE_BYTES
  }
  await mkdir(path.join(dir, 'startos'), { recursive: true })
  for (const file of LINKED_EVIDENCE_FILES) {
    if (overrides[file] === false) continue
    await writeFile(path.join(dir, file), bytesFor(file, artifacts, overrides))
  }
  if (overrides['startos/blindspark.s9pk'] !== false) {
    await writeFile(path.join(dir, 'startos/blindspark.s9pk'), bytesFor('startos/blindspark.s9pk', artifacts, overrides))
  }
}

function bytesFor (file, artifacts, overrides) {
  return Object.prototype.hasOwnProperty.call(overrides, file) ? overrides[file] : artifacts[file]
}

function env (overrides = {}) {
  return {
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: REPOSITORY,
    GITHUB_RUN_ID: '12345',
    GITHUB_RUN_ATTEMPT: '2',
    HIVERELAY_RELEASE_VERSION: 'v9.9.9',
    HIVERELAY_RELEASE_SEMVER: '9.9.9',
    HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/getumbrel/umbrel-apps/pull/123',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: 'bigdestiny2:blindspark-v9.9.9',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: HEAD_SHA,
    HIVERELAY_UMBREL_OFFICIAL_PR_STATE: 'OPEN',
    HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: 'true',
    HIVERELAY_UMBREL_OFFICIAL_PR_BASE: 'master',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: 'bigdestiny2',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: 'blindspark-v9.9.9',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: HEAD_SHA,
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: STARTOS_REGISTRY_PACKAGE_URL,
    ...overrides
  }
}

function releaseEvidenceBytes (overrides = {}) {
  return JSON.stringify(deepMerge({
    schemaVersion: 1,
    release: {
      version: 'v9.9.9',
      semver: '9.9.9',
      workflow: {
        scope: 'release-surfaces/pre-handoff-checkpoint',
        status: 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure',
        repository: REPOSITORY,
        runId: '12345',
        runAttempt: '2',
        runUrl: `https://github.com/${REPOSITORY}/actions/runs/12345`
      },
      closure: { status: 'pending-startos-0.4', evidence: 'release-closure-evidence.json' }
    },
    artifacts: {
      startosPackage: {
        path: 'startos/blindspark.s9pk',
        sha256: STARTOS_PACKAGE_SHA
      }
    },
    gates: {
      imageManifestEvidence: {
        path: 'release-image-manifest-evidence.json',
        sha256: IMAGE_MANIFEST_SHA
      },
      pushedImageSmokeEvidence: {
        path: 'release-image-smoke-evidence.json',
        sha256: IMAGE_SMOKE_SHA
      },
      umbrelPackageSmokeEvidence: {
        path: 'umbrel-package-smoke-evidence.json',
        sha256: UMBREL_SMOKE_SHA
      }
    },
    surfaces: {
      fleetRolloutEvidence: {
        path: 'fleet-rollout-evidence.json',
        sha256: FLEET_ROLLOUT_SHA
      },
      startosRegistryPackageUrl: STARTOS_REGISTRY_PACKAGE_URL,
      startosRegistryEvidence: {
        path: 'startos-registry-evidence.json',
        sha256: STARTOS_REGISTRY_SHA
      },
      umbrelOfficial: {
        status: 'draft-pr-ready',
        prUrl: 'https://github.com/getumbrel/umbrel-apps/pull/123',
        head: 'bigdestiny2:blindspark-v9.9.9',
        headSha: HEAD_SHA,
        state: 'OPEN',
        isDraft: true,
        base: 'master',
        headOwner: 'bigdestiny2',
        headRef: 'blindspark-v9.9.9',
        headOid: HEAD_SHA
      }
    }
  }, overrides), null, 2) + '\n'
}

function deepMerge (target, overrides) {
  for (const [key, value] of Object.entries(overrides)) {
    if (isPlainObject(value) && isPlainObject(target[key])) {
      deepMerge(target[key], value)
    } else {
      target[key] = value
    }
  }
  return target
}

function isPlainObject (value) {
  return value != null && typeof value === 'object' && !Array.isArray(value)
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

test('official Umbrel PR evidence writer keeps a closed public schema', async (t) => {
  const script = await readFile('scripts/write-official-umbrel-pr-evidence.mjs', 'utf8')

  t.ok(script.includes('assertOfficialUmbrelPrEvidenceSchema(body)'))
  t.ok(script.includes('function assertOfficialUmbrelPrEvidenceSchema'))
  t.ok(script.includes("requireOnlyKeys('official Umbrel PR evidence'"))
  t.ok(script.includes('has unsupported fields'))
})

test('official Umbrel PR evidence writer records public release links', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  await runWriter(outFile, env())

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.ok(ISO_TIMESTAMP_PATTERN.test(body.generatedAt), 'official Umbrel PR evidence generatedAt is an ISO timestamp')
  t.is(body.kind, 'official-umbrel-pr')
  t.is(body.status, 'updated')
  t.is(body.release.version, 'v9.9.9')
  t.is(body.pr.url, 'https://github.com/getumbrel/umbrel-apps/pull/123')
  t.is(body.pr.number, '123')
  t.is(body.pr.head, 'bigdestiny2:blindspark-v9.9.9')
  t.is(body.pr.headSha, HEAD_SHA)
  t.is(body.pr.state, 'OPEN')
  t.is(body.pr.isDraft, true)
  t.is(body.pr.base, 'master')
  t.is(body.pr.headOwner, 'bigdestiny2')
  t.is(body.pr.headRef, 'blindspark-v9.9.9')
  t.is(body.pr.headOid, HEAD_SHA)
  t.is(body.workflow.runUrl, `https://github.com/${REPOSITORY}/actions/runs/12345`)
  t.is(body.runtimeReview.status, 'pending-real-device-review')
  t.is(body.runtimeReview.evidenceFile, 'umbrel-runtime-review-evidence.json')
  t.is(body.runtimeReview.verifier, 'npm run umbrel:verify-runtime-review')
  t.is(body.evidenceLinks.releaseEvidence, `${RELEASE_BASE}/release-evidence.json`)
  t.is(body.evidenceLinks.releaseImageManifest, `${RELEASE_BASE}/release-image-manifest-evidence.json`)
  t.is(body.evidenceLinks.releaseImageSmoke, `${RELEASE_BASE}/release-image-smoke-evidence.json`)
  t.is(body.evidenceLinks.umbrelPackageSmoke, `${RELEASE_BASE}/umbrel-package-smoke-evidence.json`)
  t.is(body.evidenceLinks.fleetRollout, `${RELEASE_BASE}/fleet-rollout-evidence.json`)
  t.is(body.evidenceLinks.startosPackage, `${RELEASE_BASE}/blindspark.s9pk`)
  t.is(body.evidenceLinks.startosRegistryPackage, STARTOS_REGISTRY_PACKAGE_URL)
  t.is(body.evidenceLinks.startosRegistry, `${RELEASE_BASE}/startos-registry-evidence.json`)
})

test('official Umbrel PR evidence writer records gateway rollout as deferred without a false fleet link', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const releaseBytes = releaseEvidenceBytes({
    release: {
      channel: 'none',
      publicGateway: {
        enabled: true,
        manifestStatus: 'enabled',
        manifestPath: 'fleet/public-hive-gateway-release.json',
        manifestSha256: '4'.repeat(64),
        releaseTarget: 'v9.9.9',
        commitSha: HEAD_SHA,
        admissionProfile: 'blind-substrate-public-v1',
        cohortSize: 3
      }
    },
    surfaces: {
      fleetRollout: 'deferred-gateway-canary-gated',
      fleetRolloutEvidence: { path: '', sha256: '' }
    }
  })
  await writeLinkedArtifacts(dir, {
    'release-evidence.json': releaseBytes,
    'fleet-rollout-evidence.json': false
  })
  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  await runWriter(outFile, env({
    HIVERELAY_PUBLIC_GATEWAY_RELEASE_ENABLED: 'true'
  }), { cwd: dir, linkedArtifacts: false })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.evidenceLinks.fleetRollout, '')
})

test('official Umbrel PR evidence writer requires linked release artifacts before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const missingFile = path.join(dir, 'missing-artifacts.json')
  let missingErr = null
  try {
    await runWriter(missingFile, env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    missingErr = e
  }
  t.ok(missingErr)
  t.ok(missingErr.stderr.includes('linked evidence artifact is required before writing official Umbrel PR evidence: release-evidence.json'))

  await writeLinkedArtifacts(dir, { 'release-image-smoke-evidence.json': false })
  await symlink('release-evidence.json', path.join(dir, 'release-image-smoke-evidence.json'))
  const symlinkFile = path.join(dir, 'symlink-artifact.json')
  let symlinkErr = null
  try {
    await runWriter(symlinkFile, env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    symlinkErr = e
  }
  t.ok(symlinkErr)
  t.ok(symlinkErr.stderr.includes('linked evidence artifact must not be a symlink: release-image-smoke-evidence.json'))

  const missingPackageDir = path.join(dir, 'missing-package')
  await writeLinkedArtifacts(missingPackageDir, { 'startos/blindspark.s9pk': false })
  const missingPackageFile = path.join(missingPackageDir, 'missing-package.json')
  let missingPackageErr = null
  try {
    await runWriter(missingPackageFile, env(), { cwd: missingPackageDir, linkedArtifacts: false })
  } catch (e) {
    missingPackageErr = e
  }
  t.ok(missingPackageErr)
  t.ok(missingPackageErr.stderr.includes('StartOS package is required before writing official Umbrel PR evidence: startos/blindspark.s9pk'))

  await rm(path.join(dir, 'release-image-smoke-evidence.json'), { force: true })
  await writeLinkedArtifacts(dir, { 'startos-registry-evidence.json': 'x'.repeat(2 * 1024 * 1024 + 1) })
  const oversizedFile = path.join(dir, 'oversized-artifact.json')
  let oversizedErr = null
  try {
    await runWriter(oversizedFile, env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    oversizedErr = e
  }
  t.ok(oversizedErr)
  t.ok(oversizedErr.stderr.includes('linked evidence artifact startos-registry-evidence.json must be 2097152 bytes or smaller'))
})

test('official Umbrel PR evidence writer rejects linked artifact hash drift before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await writeLinkedArtifacts(dir, {
    'release-image-smoke-evidence.json': '{"kind":"stale-release-image-smoke"}\n'
  })

  const staleImageSmokeFile = path.join(dir, 'stale-image-smoke.json')
  let staleImageSmokeErr = null
  try {
    await runWriter(staleImageSmokeFile, env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    staleImageSmokeErr = e
  }
  t.ok(staleImageSmokeErr)
  t.ok(staleImageSmokeErr.stderr.includes('linked release image smoke evidence SHA-256 does not match release-image-smoke-evidence.json'))

  const packageDir = path.join(dir, 'stale-package')
  await writeLinkedArtifacts(packageDir, {
    'startos/blindspark.s9pk': 'stale package\n'
  })

  const stalePackageFile = path.join(packageDir, 'stale-package.json')
  let stalePackageErr = null
  try {
    await runWriter(stalePackageFile, env(), { cwd: packageDir, linkedArtifacts: false })
  } catch (e) {
    stalePackageErr = e
  }
  t.ok(stalePackageErr)
  t.ok(stalePackageErr.stderr.includes('linked StartOS package SHA-256 does not match startos/blindspark.s9pk'))
})

test('official Umbrel PR evidence writer rejects release evidence drift before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await writeLinkedArtifacts(dir, {
    'release-evidence.json': releaseEvidenceBytes({
      surfaces: {
        umbrelOfficial: {
          headOid: 'b'.repeat(40)
        }
      }
    })
  })

  const outFile = path.join(dir, 'release-pr-drift.json')
  let err = null
  try {
    await runWriter(outFile, env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence official Umbrel PR head OID'))
})

test('official Umbrel PR evidence writer requires an explicit pending closure contract', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => rm(dir, { recursive: true, force: true }))

  await writeLinkedArtifacts(dir, {
    'release-evidence.json': releaseEvidenceBytes({
      release: { closure: { status: 'verified', evidence: '' } }
    })
  })

  let err = null
  try {
    await runWriter(path.join(dir, 'bad-closure.json'), env(), { cwd: dir, linkedArtifacts: false })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release checkpoint evidence must be valid and closure-scoped'))
})

test('official Umbrel PR evidence writer rejects unsafe StartOS registry package URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'unsafe-startos-registry-package-url.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: 'http://registry.start9.com/startos/blindspark'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry package link'))
})

test('official Umbrel PR evidence writer rejects non-canonical release repositories', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
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

test('official Umbrel PR evidence writer rejects stale PR state facts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const closedFile = path.join(dir, 'closed-pr.json')
  let stateErr = null
  try {
    await runWriter(closedFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_STATE: 'CLOSED'
    }))
  } catch (e) {
    stateErr = e
  }
  t.ok(stateErr)
  t.ok(stateErr.stderr.includes('official Umbrel PR state'))

  const nonDraftFile = path.join(dir, 'non-draft-pr.json')
  let draftErr = null
  try {
    await runWriter(nonDraftFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: 'false'
    }))
  } catch (e) {
    draftErr = e
  }
  t.ok(draftErr)
  t.ok(draftErr.stderr.includes('official Umbrel PR draft'))

  const baseFile = path.join(dir, 'wrong-base-pr.json')
  let baseErr = null
  try {
    await runWriter(baseFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_BASE: 'main'
    }))
  } catch (e) {
    baseErr = e
  }
  t.ok(baseErr)
  t.ok(baseErr.stderr.includes('official Umbrel PR base'))

  const headRefFile = path.join(dir, 'wrong-head-ref-pr.json')
  let headRefErr = null
  try {
    await runWriter(headRefFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: 'wrong-branch'
    }))
  } catch (e) {
    headRefErr = e
  }
  t.ok(headRefErr)
  t.ok(headRefErr.stderr.includes('official Umbrel PR head ref matches head branch'))

  const headOwnerFile = path.join(dir, 'wrong-head-owner-pr.json')
  let headOwnerErr = null
  try {
    await runWriter(headOwnerFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: 'attacker'
    }))
  } catch (e) {
    headOwnerErr = e
  }
  t.ok(headOwnerErr)
  t.ok(headOwnerErr.stderr.includes('official Umbrel PR head owner matches head owner'))

  const headOidFile = path.join(dir, 'wrong-head-oid-pr.json')
  let headOidErr = null
  try {
    await runWriter(headOidFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: 'b'.repeat(40)
    }))
  } catch (e) {
    headOidErr = e
  }
  t.ok(headOidErr)
  t.ok(headOidErr.stderr.includes('official Umbrel PR head OID matches head SHA'))
})

test('official Umbrel PR evidence writer rejects non-upstream PR URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/example/umbrel-apps/pull/123'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR URL'))

  const zeroFile = path.join(dir, 'zero-official-pr.json')
  let zeroErr = null
  try {
    await runWriter(zeroFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/getumbrel/umbrel-apps/pull/0'
    }))
  } catch (e) {
    zeroErr = e
  }

  t.ok(zeroErr)
  t.ok(zeroErr.stderr.includes('official Umbrel PR URL'))
})

test('official Umbrel PR evidence writer rejects malformed GitHub owner names', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  for (const owner of ['bad_owner', 'bad.owner', '-bad', 'getumbrel', 'GetUmbrel']) {
    let err = null
    try {
      await runWriter(path.join(dir, `${owner}-pr.json`), env({
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: `${owner}:blindspark-v9.9.9`,
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: owner
      }))
    } catch (e) {
      err = e
    }
    t.ok(err, owner)
    t.ok(err.stderr.includes('official Umbrel PR head owner must be a normal GitHub owner name'), owner)
  }
})

test('official Umbrel PR evidence writer rejects malformed GitHub head refs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  for (const ref of ['bad..ref', '.bad-ref', 'bad/ref.lock']) {
    let err = null
    try {
      await runWriter(path.join(dir, `${ref.replace(/\//g, '-')}-pr.json`), env({
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: `bigdestiny2:${ref}`,
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: ref
      }))
    } catch (e) {
      err = e
    }
    t.ok(err, ref)
    t.ok(err.stderr.includes('official Umbrel PR head ref must be a normal GitHub branch name'), ref)
  }
})

test('official Umbrel PR evidence writer ignores release base overrides', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  await runWriter(outFile, env({
    HIVERELAY_RELEASE_BASE_URL: 'https://github.com/attacker/fake/releases/download/v9.9.9'
  }))

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.evidenceLinks.releaseEvidence, `${RELEASE_BASE}/release-evidence.json`)
  t.is(body.evidenceLinks.releaseImageManifest, `${RELEASE_BASE}/release-image-manifest-evidence.json`)
  t.is(body.evidenceLinks.releaseImageSmoke, `${RELEASE_BASE}/release-image-smoke-evidence.json`)
  t.is(body.evidenceLinks.umbrelPackageSmoke, `${RELEASE_BASE}/umbrel-package-smoke-evidence.json`)
  t.is(body.evidenceLinks.fleetRollout, `${RELEASE_BASE}/fleet-rollout-evidence.json`)
  t.is(body.evidenceLinks.startosPackage, `${RELEASE_BASE}/blindspark.s9pk`)
  t.is(body.evidenceLinks.startosRegistryPackage, STARTOS_REGISTRY_PACKAGE_URL)
  t.is(body.evidenceLinks.startosRegistry, `${RELEASE_BASE}/startos-registry-evidence.json`)
})

test('official Umbrel PR evidence writer rejects non-numeric run attempts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
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

test('official Umbrel PR evidence writer rejects whitespace-normalized metadata before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const cases = [
    ['run-id', { GITHUB_RUN_ID: ' 12345' }, 'workflow run id'],
    ['run-attempt', { GITHUB_RUN_ATTEMPT: '2 ' }, 'workflow run attempt'],
    ['server-url', { GITHUB_SERVER_URL: 'https://github.com ' }, 'workflow URL'],
    ['pr-url', { HIVERELAY_UMBREL_OFFICIAL_PR_URL: ' https://github.com/getumbrel/umbrel-apps/pull/123' }, 'official Umbrel PR URL'],
    ['head-ref', {
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: 'bigdestiny2:blindspark-v9.9.9 ',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: 'blindspark-v9.9.9 '
    }, 'official Umbrel PR head']
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

test('official Umbrel PR evidence writer rejects malformed head SHA', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: 'not-a-sha'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR head SHA'))
})

test('official Umbrel PR evidence writer rejects secret-looking public values before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
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

test('official Umbrel PR evidence writer rejects control-character public values before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'official-umbrel-pr-evidence.json')
  let err = null
  try {
    await runWriter(outFile, env({
      GITHUB_RUN_ATTEMPT: '2\n3'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR evidence must not contain control characters'))
})
