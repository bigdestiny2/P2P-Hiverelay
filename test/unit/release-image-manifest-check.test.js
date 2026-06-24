import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const IMAGE_DIGEST = 'sha256:' + 'b'.repeat(64)
const AMD64_DIGEST = 'sha256:' + 'a'.repeat(64)
const ARM64_DIGEST = 'sha256:' + 'c'.repeat(64)
const DUPLICATE_AMD64_DIGEST = 'sha256:' + 'd'.repeat(64)
const AMD64_ATTESTATION_DIGEST = 'sha256:' + 'e'.repeat(64)
const ARM64_ATTESTATION_DIGEST = 'sha256:' + 'f'.repeat(64)
const IMAGE_REF = `ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@${IMAGE_DIGEST}`

function runCheck (argv) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['scripts/check-release-image-manifest.mjs', ...argv], {
      cwd: process.cwd(),
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

test('release image manifest checker writes platform evidence for multi-arch indexes', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  const outFile = path.join(dir, 'release-image-manifest-evidence.json')
  const manifest = indexManifest()
  manifest.manifests.push(
    attestationManifest(AMD64_DIGEST, AMD64_ATTESTATION_DIGEST),
    attestationManifest(ARM64_DIGEST, ARM64_ATTESTATION_DIGEST)
  )
  await writeFile(rawFile, JSON.stringify(manifest, null, 2) + '\n')

  await runCheck(['--image', IMAGE_REF, '--raw', rawFile, '--out', outFile])

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.is(body.kind, 'release-image-manifest')
  t.is(body.status, 'verified')
  t.is(body.image.name, 'ghcr.io/bigdestiny2/p2p-hiverelay')
  t.is(body.image.tag, '9.9.9')
  t.is(body.image.digest, IMAGE_DIGEST)
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
  await writeFile(rawFile, JSON.stringify(manifest))

  let err = null
  try {
    await runCheck(['--image', IMAGE_REF, '--raw', rawFile, '--out', outFile])
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
  await writeFile(rawFile, JSON.stringify(manifest))

  let err = null
  try {
    await runCheck(['--image', IMAGE_REF, '--raw', rawFile, '--out', outFile])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest has duplicate platform linux/amd64'))
})

test('release image manifest checker rejects mutable or wrong-repository image refs', async (t) => {
  const dir = await fixtureDir(t)
  const rawFile = path.join(dir, 'raw.json')
  await writeFile(rawFile, JSON.stringify(indexManifest()))

  for (const [image, message] of [
    ['ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9', 'requires a GHCR semver tag plus sha256 digest image ref'],
    [`ghcr.io/attacker/p2p-hiverelay:9.9.9@${IMAGE_DIGEST}`, 'release image name must be ghcr.io/bigdestiny2/p2p-hiverelay']
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
  await writeFile(rawFile, JSON.stringify(indexManifest()))
  await symlink(rawFile, symlinkFile)

  let symlinkErr = null
  try {
    await runCheck(['--image', IMAGE_REF, '--raw', symlinkFile, '--out', path.join(dir, 'out.json')])
  } catch (e) {
    symlinkErr = e
  }

  t.ok(symlinkErr)
  t.ok(symlinkErr.stderr.includes('raw manifest file must not be a symlink'))

  const unsafeFile = path.join(dir, 'unsafe.json')
  await writeFile(unsafeFile, JSON.stringify(indexManifest()).replace(AMD64_DIGEST, 'Bearer abcdefghijklmnopqrstuvwxyz'))

  let unsafeErr = null
  try {
    await runCheck(['--image', IMAGE_REF, '--raw', unsafeFile, '--out', path.join(dir, 'unsafe-out.json')])
  } catch (e) {
    unsafeErr = e
  }

  t.ok(unsafeErr)
  t.ok(unsafeErr.stderr.includes('bearer token'))
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
