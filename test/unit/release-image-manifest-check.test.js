import test from 'brittle'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const AMD64_DIGEST = 'sha256:' + 'a'.repeat(64)
const ARM64_DIGEST = 'sha256:' + 'c'.repeat(64)
const DUPLICATE_AMD64_DIGEST = 'sha256:' + 'd'.repeat(64)
const AMD64_ATTESTATION_DIGEST = 'sha256:' + 'e'.repeat(64)
const ARM64_ATTESTATION_DIGEST = 'sha256:' + 'f'.repeat(64)

function runCheck (argv, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['scripts/check-release-image-manifest.mjs', ...argv], {
      cwd: process.cwd(),
      timeout: 10000,
      env: options.env || process.env
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

test('release image manifest checker writes platform evidence for multi-arch indexes', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const outFile = path.join(dir, 'release-image-manifest-evidence.json')
  const manifest = indexManifest()
  manifest.manifests.push(
    attestationManifest(AMD64_DIGEST, AMD64_ATTESTATION_DIGEST),
    attestationManifest(ARM64_DIGEST, ARM64_ATTESTATION_DIGEST)
  )
  const raw = JSON.stringify(manifest, null, 2) + '\n'
  const imageRef = imageRefFor(raw)
  await writeFile(rawFile, raw)

  await runCheck(['--image', imageRef, '--raw', rawFile, '--out', outFile])

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.is(body.kind, 'release-image-manifest')
  t.is(body.status, 'verified')
  t.is(body.image.name, 'ghcr.io/bigdestiny2/p2p-hiverelay')
  t.is(body.image.tag, '9.9.9')
  t.is(body.image.digest, digestFor(raw))
  t.alike(body.requiredPlatforms, ['linux/amd64', 'linux/arm64'])
  t.alike(body.platforms.map((platform) => `${platform.os}/${platform.architecture}`), ['linux/amd64', 'linux/arm64'])
  t.is(body.manifest.manifestCount, 4)
})

test('release image manifest checker rejects missing required platforms', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const outFile = path.join(dir, 'release-image-manifest-evidence.json')
  const manifest = indexManifest()
  manifest.manifests = manifest.manifests.filter((entry) => entry.platform.architecture !== 'arm64')
  const raw = JSON.stringify(manifest)
  await writeFile(rawFile, raw)

  let err = null
  try {
    await runCheck(['--image', imageRefFor(raw), '--raw', rawFile, '--out', outFile])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('missing required platform linux/arm64'))
})

test('release image manifest checker rejects duplicate platform entries', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const outFile = path.join(dir, 'release-image-manifest-evidence.json')
  const manifest = indexManifest()
  manifest.manifests.push({
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    digest: DUPLICATE_AMD64_DIGEST,
    platform: { os: 'linux', architecture: 'amd64' }
  })
  const raw = JSON.stringify(manifest)
  await writeFile(rawFile, raw)

  let err = null
  try {
    await runCheck(['--image', imageRefFor(raw), '--raw', rawFile, '--out', outFile])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest has duplicate platform linux/amd64'))
})

test('release image manifest checker rejects mutable or wrong-repository image refs', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const raw = JSON.stringify(indexManifest())
  await writeFile(rawFile, raw)
  const digest = digestFor(raw)

  for (const [image, message] of [
    ['ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9', 'requires a GHCR semver tag plus sha256 digest image ref'],
    [`ghcr.io/attacker/p2p-hiverelay:9.9.9@${digest}`, 'release image name must be ghcr.io/bigdestiny2/p2p-hiverelay']
  ]) {
    let err = null
    try {
      await runCheck(['--image', image, '--raw', rawFile, '--out', path.join(dir, 'out.json')])
    } catch (e) {
      err = e
    }

    t.ok(err, image)
    t.ok(err.stderr.includes(message), image)
  }
})

test('release image manifest checker rejects symlinked raw fixtures and unsafe raw values', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const symlinkFile = path.join(dir, 'link.json')
  const raw = JSON.stringify(indexManifest())
  await writeFile(rawFile, raw)
  await symlink(rawFile, symlinkFile)

  let symlinkErr = null
  try {
    await runCheck(['--image', imageRefFor(raw), '--raw', symlinkFile, '--out', path.join(dir, 'out.json')])
  } catch (e) {
    symlinkErr = e
  }

  t.ok(symlinkErr)
  t.ok(symlinkErr.stderr.includes('raw manifest file must not be a symlink'))

  const unsafeFile = path.join(dir, 'unsafe.json')
  const unsafeRaw = JSON.stringify(indexManifest()).replace(AMD64_DIGEST, 'Bearer abcdefghijklmnopqrstuvwxyz')
  await writeFile(unsafeFile, unsafeRaw)

  let unsafeErr = null
  try {
    await runCheck(['--image', imageRefFor(unsafeRaw), '--raw', unsafeFile, '--out', path.join(dir, 'unsafe-out.json')])
  } catch (e) {
    unsafeErr = e
  }

  t.ok(unsafeErr)
  t.ok(unsafeErr.stderr.includes('bearer token'))
})

test('release image manifest checker rejects raw bytes that do not match the claimed index digest', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const raw = JSON.stringify(indexManifest())
  await writeFile(rawFile, raw)

  let err = null
  try {
    await runCheck([
      '--image', `ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@sha256:${'b'.repeat(64)}`,
      '--raw', rawFile,
      '--out', path.join(dir, 'out.json')
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('does not match the exact raw index bytes'))
  t.ok(err.stderr.includes(`computed ${digestFor(raw)}`))
})

test('release image manifest checker redacts Buffer stderr from docker inspection failures', async (t) => {
  const dir = await fixtureDir(t)
  const docker = path.join(dir, 'docker')
  const secret = 'Bearer abcdefghijklmnopqrstuvwxyz'
  await writeFile(docker, `#!/bin/sh\nprintf '%s\\n' '${secret}' >&2\nexit 1\n`, { mode: 0o755 })

  let err = null
  try {
    await runCheck([
      '--image', `ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@sha256:${'b'.repeat(64)}`,
      '--out', path.join(dir, 'out.json')
    ], {
      env: { ...process.env, PATH: `${dir}:${process.env.PATH || ''}` }
    })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('[redacted bearer token]'))
  t.absent(err.stderr.includes(secret))
})

async function fixtureDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-image-manifest-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

function indexManifest () {
  return {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: AMD64_DIGEST,
        platform: { os: 'linux', architecture: 'amd64' }
      },
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ARM64_DIGEST,
        platform: { os: 'linux', architecture: 'arm64', variant: 'v8' }
      }
    ]
  }
}

function attestationManifest (imageDigest, attestationDigest) {
  return {
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    digest: attestationDigest,
    size: 565,
    annotations: {
      'vnd.docker.reference.digest': imageDigest,
      'vnd.docker.reference.type': 'attestation-manifest'
    },
    platform: { os: 'unknown', architecture: 'unknown' }
  }
}

function digestFor (raw) {
  return `sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`
}

function imageRefFor (raw) {
  return `ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@${digestFor(raw)}`
}
