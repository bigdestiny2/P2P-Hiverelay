import test from 'brittle'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  resolveStartos04ReleaseBinding
} from '../../scripts/lib/startos-04-release-evidence.mjs'

const ROOT = process.cwd()
const VERSION = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8')).version
const PACKAGE_VERSION = /version:\s*'([^']+)'/.exec(await readFile(path.join(ROOT, 'startos-0.4/startos/versions/current.ts'), 'utf8'))[1]
const TAG = `v${VERSION}`
const TAG_SHA = 'a'.repeat(40)
const IMAGE_DIGEST = `sha256:${'b'.repeat(64)}`
const AMD64_DIGEST = `sha256:${'c'.repeat(64)}`
const ARM64_DIGEST = `sha256:${'d'.repeat(64)}`
const IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const IMAGE_REF = `${IMAGE_NAME}:${VERSION}@${IMAGE_DIGEST}`
const PACKAGE_NAME = 'blindspark-startos-0.4.s9pk'
const SETUP_ACTION_SHA = '21507e89e717a303cb1064ac4c853d28b96d323b'
const START_CLI_SHA256 = '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'

test('StartOS 0.4 release resolver binds exact tag, source run, digest, and child manifests', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '12345' })
  const githubEnv = path.join(fixture.dir, 'github-env')
  const result = await run('scripts/resolve-startos-04-release.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', '12345',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', githubEnv
  ])

  t.is(result.status, 0, result.stderr)
  const env = Object.fromEntries((await readFile(githubEnv, 'utf8')).trim().split('\n').map(line => line.split('=')))
  t.is(env.HIVERELAY_RELEASE_SURFACES_RUN_ID, '12345')
  t.is(env.HIVERELAY_IMAGE_NAME, IMAGE_NAME)
  t.is(env.HIVERELAY_IMAGE_DIGEST, IMAGE_DIGEST)
  t.is(env.HIVERELAY_STARTOS_04_IMAGE_REF, IMAGE_REF)
  t.is(env.HIVERELAY_STARTOS_04_PACKAGE_VERSION, PACKAGE_VERSION)
  t.is(env.HIVERELAY_IMAGE_AMD64_DIGEST, AMD64_DIGEST)
  t.is(env.HIVERELAY_IMAGE_ARM64_DIGEST, ARM64_DIGEST)
})

test('reusable release-image resolver accepts only internally successful exact-tag evidence', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '54321' })
  const githubEnv = path.join(fixture.dir, 'reusable-github-env')
  const accepted = await run('scripts/resolve-reusable-release-image.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', githubEnv
  ])
  t.is(accepted.status, 0, accepted.stderr)
  t.ok((await readFile(githubEnv, 'utf8')).includes(`HIVERELAY_IMAGE_DIGEST=${IMAGE_DIGEST}`))

  const release = JSON.parse(await readFile(fixture.releaseEvidence, 'utf8'))
  release.release.workflow.status = 'failed'
  await writeFile(fixture.releaseEvidence, JSON.stringify(release, null, 2) + '\n')
  const rejected = await run('scripts/resolve-reusable-release-image.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', githubEnv
  ])
  t.is(rejected.status, 1)
  t.ok(rejected.stderr.includes('release evidence workflow status'))
})

test('StartOS 0.4 release resolver binds evidence toolchain claims to the source lockfile', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '54322' })
  const repoRoot = await sdkContractRepoFixture(t)
  const args = {
    repoRoot,
    tag: TAG,
    tagSha: TAG_SHA,
    releaseSurfacesRunId: '54322',
    releaseEvidencePath: fixture.releaseEvidence,
    imageManifestEvidencePath: fixture.imageManifestEvidence
  }
  t.is(resolveStartos04ReleaseBinding(args).packageVersion, PACKAGE_VERSION)

  const packagePath = path.join(repoRoot, 'startos-0.4/package.json')
  await writeFile(packagePath, JSON.stringify({ dependencies: { '@start9labs/start-sdk': '^2.0.1' } }, null, 2) + '\n')
  t.exception(() => resolveStartos04ReleaseBinding(args), /source SDK dependency/)

  await writeFile(
    packagePath,
    JSON.stringify({ name: 'blindspark-startos', dependencies: { '@start9labs/start-sdk': '2.0.1' } }, null, 2) + '\n'
  )
  const lockPath = path.join(repoRoot, 'startos-0.4/package-lock.json')
  const lock = JSON.parse(await readFile(lockPath, 'utf8'))
  lock.packages[''].dependencies['@start9labs/start-sdk'] = '^2.0.1'
  await writeFile(lockPath, JSON.stringify(lock, null, 2) + '\n')
  t.exception(() => resolveStartos04ReleaseBinding(args), /lockfile root SDK dependency/)

  lock.packages[''].dependencies['@start9labs/start-sdk'] = '2.0.1'
  lock.packages['node_modules/@start9labs/start-sdk'].integrity = `sha512-${'x'.repeat(32)}`
  await writeFile(lockPath, JSON.stringify(lock, null, 2) + '\n')
  t.exception(() => resolveStartos04ReleaseBinding(args), /locked SDK integrity/)
})

test('StartOS 0.4 release evidence is deterministic across equivalent source workflow reruns', async (t) => {
  const first = await evidenceFixture(t, { runId: '111' })
  const second = await evidenceFixture(t, { runId: '222', generatedAt: '2026-08-22T00:00:00.000Z' })
  const firstOut = path.join(first.dir, 'startos-0.4-release-evidence.json')
  const secondOut = path.join(second.dir, 'startos-0.4-release-evidence.json')

  const firstResult = await writeEvidence(first, '111', ['--out', firstOut])
  const secondResult = await writeEvidence(second, '222', ['--out', secondOut])
  t.is(firstResult.status, 0, firstResult.stderr)
  t.is(secondResult.status, 0, secondResult.stderr)
  t.is(await readFile(firstOut, 'utf8'), await readFile(secondOut, 'utf8'))

  const body = JSON.parse(await readFile(firstOut, 'utf8'))
  t.alike(body.release, { version: TAG, tagSha: TAG_SHA })
  t.is(body.image.ref, IMAGE_REF)
  t.alike(body.image.platforms, [
    { os: 'linux', architecture: 'amd64', digest: AMD64_DIGEST, revision: TAG_SHA },
    { os: 'linux', architecture: 'arm64', digest: ARM64_DIGEST, revision: TAG_SHA }
  ])
  t.is(body.toolchain.evidenceSemantics, 'declared-source-build-contract-and-current-inspection-runtime')
  t.alike(body.toolchain.artifactBuildProvenance, {
    status: 'not-embedded-or-verifiable-from-s9pk',
    claim: 'source-and-workflow-contract-only'
  })
  t.is(body.toolchain.setupAction.commit, SETUP_ACTION_SHA)
  t.is(body.toolchain.setupAction.evidenceRole, 'workflow-build-and-inspection-contract')
  t.is(body.toolchain.startCli.version, '1.1.0')
  t.is(body.toolchain.startCli.sha256, START_CLI_SHA256)
  t.is(body.toolchain.startCli.evidenceRole, 'workflow-build-and-current-inspection-contract')
  t.is(body.toolchain.startSdk.version, '2.0.1')
  t.is(body.toolchain.startSdk.evidenceRole, 'source-lockfile-build-contract')
  t.alike(body.artifact.manifest, {
    id: 'blindspark',
    version: PACKAGE_VERSION,
    runtimeImage: {
      id: 'blindspark',
      ref: IMAGE_REF,
      architectures: ['aarch64', 'x86_64']
    }
  })
  t.is(body.artifact.signerIdentity.status, 'not-exposed-by-start-cli-1.1.0')
  t.ok(body.artifact.commitment.output.includes('Root Sighash'))
  t.ok(/^[a-f0-9]{64}$/.test(body.artifact.commitment.sha256))
})

test('StartOS 0.4 release evidence verification fails closed on artifact drift', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '333' })
  const out = path.join(fixture.dir, 'startos-0.4-release-evidence.json')
  const written = await writeEvidence(fixture, '333', ['--out', out])
  t.is(written.status, 0, written.stderr)

  await writeFile(fixture.package, 'tampered package bytes')
  const verified = await writeEvidence(fixture, '333', ['--verify', out])
  t.is(verified.status, 1)
  t.ok(verified.stderr.includes('does not match the exact tag, image, toolchain, manifest identity, commitment, and package bytes'))
})

test('published StartOS 0.4 closure verifier binds source evidence and immutable assets', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '334' })
  const out = path.join(fixture.dir, 'startos-0.4-release-evidence.json')
  const written = await writeEvidence(fixture, '334', ['--out', out])
  t.is(written.status, 0, written.stderr)

  const args = [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', '334',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--package', fixture.package,
    '--startos-0.4-evidence', out
  ]
  const accepted = await run('scripts/verify-published-startos-04-release.mjs', args)
  t.is(accepted.status, 0, accepted.stderr)

  const evidence = JSON.parse(await readFile(out, 'utf8'))
  evidence.artifact.manifest.runtimeImage.ref = `${IMAGE_NAME}:${VERSION}`
  await writeFile(out, JSON.stringify(evidence, null, 2) + '\n')
  const rejected = await run('scripts/verify-published-startos-04-release.mjs', args)
  t.is(rejected.status, 1)
  t.ok(rejected.stderr.includes('Published StartOS 0.4 assets do not match'))
})

test('StartOS 0.4 release resolver rejects source and manifest drift', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '444' })
  const githubEnv = path.join(fixture.dir, 'github-env')
  const wrongSha = await run('scripts/resolve-startos-04-release.mjs', [
    '--tag', TAG,
    '--tag-sha', 'e'.repeat(40),
    '--release-surfaces-run-id', '444',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', githubEnv
  ])
  t.is(wrongSha.status, 1)
  t.ok(wrongSha.stderr.includes('release evidence tag SHA'))

  const manifest = JSON.parse(await readFile(fixture.imageManifestEvidence, 'utf8'))
  manifest.platforms = manifest.platforms.filter(platform => platform.architecture !== 'arm64')
  await writeFile(fixture.imageManifestEvidence, JSON.stringify(manifest, null, 2) + '\n')
  const release = JSON.parse(await readFile(fixture.releaseEvidence, 'utf8'))
  release.gates.imageManifestEvidence.sha256 = sha256(await readFile(fixture.imageManifestEvidence))
  await writeFile(fixture.releaseEvidence, JSON.stringify(release, null, 2) + '\n')
  const missingPlatform = await run('scripts/resolve-startos-04-release.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', '444',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', githubEnv
  ])
  t.is(missingPlatform.status, 1)
  t.ok(missingPlatform.stderr.includes('missing required platform linux/arm64'))
})

test('StartOS 0.4 child image verifier requires the exact source revision label', async (t) => {
  const good = childImage(TAG_SHA)
  const accepted = await runWithInput('scripts/verify-startos-04-image-revision.mjs', [
    '--os', 'linux',
    '--architecture', 'amd64',
    '--revision', TAG_SHA
  ], JSON.stringify(good))
  t.is(accepted.status, 0, accepted.stderr)

  const drifted = childImage('f'.repeat(40))
  const rejected = await runWithInput('scripts/verify-startos-04-image-revision.mjs', [
    '--os', 'linux',
    '--architecture', 'amd64',
    '--revision', TAG_SHA
  ], JSON.stringify(drifted))
  t.is(rejected.status, 1)
  t.ok(rejected.stderr.includes('org.opencontainers.image.revision label'))
})

test('StartOS 0.4 package manifest verifier rejects unrelated digest text and wrong identity', async (t) => {
  const wrongRuntime = packageManifest({
    id: 'blindspark',
    version: PACKAGE_VERSION,
    imageRef: `${IMAGE_NAME}:${VERSION}`,
    description: `decoy ${IMAGE_REF}`
  })
  const wrongImage = await runWithInput('scripts/verify-startos-04-package-manifest.mjs', [
    '--tag', TAG,
    '--package-version', PACKAGE_VERSION,
    '--image-ref', IMAGE_REF
  ], JSON.stringify(wrongRuntime))
  t.is(wrongImage.status, 1)
  t.ok(wrongImage.stderr.includes('runtime image ref'))

  const staleVersion = packageManifest({ id: 'blindspark', version: `${VERSION}:999`, imageRef: IMAGE_REF })
  const wrongVersion = await runWithInput('scripts/verify-startos-04-package-manifest.mjs', [
    '--tag', TAG,
    '--package-version', PACKAGE_VERSION,
    '--image-ref', IMAGE_REF
  ], JSON.stringify(staleVersion))
  t.is(wrongVersion.status, 1)
  t.ok(wrongVersion.stderr.includes('package version'))

  const duplicateImage = packageManifest({ id: 'blindspark', version: PACKAGE_VERSION, imageRef: IMAGE_REF })
  duplicateImage.images.decoy = duplicateImage.images.blindspark
  const wrongShape = await runWithInput('scripts/verify-startos-04-package-manifest.mjs', [
    '--tag', TAG,
    '--package-version', PACKAGE_VERSION,
    '--image-ref', IMAGE_REF
  ], JSON.stringify(duplicateImage))
  t.is(wrongShape.status, 1)
  t.ok(wrongShape.stderr.includes('image ids'))
})

async function evidenceFixture (t, { runId, generatedAt = '2026-08-21T00:00:00.000Z' }) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-evidence-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const imageManifestEvidence = path.join(dir, 'release-image-manifest-evidence.json')
  const releaseEvidence = path.join(dir, 'release-evidence.json')
  const packageFile = path.join(dir, PACKAGE_NAME)
  const commitment = path.join(dir, 'commitment.txt')
  const manifest = path.join(dir, 'manifest.json')
  const imageManifest = {
    schemaVersion: 1,
    generatedAt,
    kind: 'release-image-manifest',
    status: 'verified',
    image: { name: IMAGE_NAME, tag: VERSION, digest: IMAGE_DIGEST, ref: IMAGE_REF },
    requiredPlatforms: ['linux/amd64', 'linux/arm64'],
    platforms: [
      { os: 'linux', architecture: 'amd64', variant: '', digest: AMD64_DIGEST },
      { os: 'linux', architecture: 'arm64', variant: 'v8', digest: ARM64_DIGEST }
    ],
    manifest: { mediaType: 'application/vnd.oci.image.index.v1+json', manifestCount: 4 }
  }
  const imageManifestRaw = JSON.stringify(imageManifest, null, 2) + '\n'
  await writeFile(imageManifestEvidence, imageManifestRaw)
  const release = {
    schemaVersion: 1,
    generatedAt,
    release: {
      version: TAG,
      semver: VERSION,
      candidate: false,
      tagSha: TAG_SHA,
      workflow: {
        status: 'success',
        repository: 'bigdestiny2/P2P-Hiverelay',
        runId,
        runUrl: `https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/${runId}`
      }
    },
    image: { name: IMAGE_NAME, digest: IMAGE_DIGEST, ref: IMAGE_REF },
    gates: {
      imageManifest: 'passed',
      imageManifestEvidence: {
        path: 'release-image-manifest-evidence.json',
        sha256: sha256(Buffer.from(imageManifestRaw))
      },
      pushedImageSmoke: 'passed',
      startosVerify: 'passed'
    },
    surfaces: { startosReleaseAsset: 'uploaded' }
  }
  await Promise.all([
    writeFile(releaseEvidence, JSON.stringify(release, null, 2) + '\n'),
    writeFile(packageFile, 'stable package bytes'),
    writeFile(commitment, `Root Sighash: ${'1'.repeat(64)}\nMax Size: 1048576\n`),
    writeFile(manifest, JSON.stringify(packageManifest({
      id: 'blindspark',
      version: PACKAGE_VERSION,
      imageRef: IMAGE_REF
    }), null, 2) + '\n')
  ])
  return { commitment, dir, imageManifestEvidence, manifest, package: packageFile, releaseEvidence }
}

function writeEvidence (fixture, runId, tail) {
  return run('scripts/write-startos-04-release-evidence.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', runId,
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--package', fixture.package,
    '--commitment', fixture.commitment,
    '--manifest', fixture.manifest,
    ...tail
  ])
}

function packageManifest ({ id, version, imageRef, description = '' }) {
  return {
    id,
    version,
    description,
    images: {
      blindspark: {
        source: { dockerTag: imageRef },
        arch: ['aarch64', 'x86_64']
      }
    }
  }
}

async function sdkContractRepoFixture (t) {
  const repoRoot = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-sdk-contract-'))
  t.teardown(() => rm(repoRoot, { recursive: true, force: true }))
  await mkdir(path.join(repoRoot, 'startos-0.4/startos/versions'), { recursive: true })
  await Promise.all([
    writeFile(path.join(repoRoot, 'package.json'), JSON.stringify({ version: VERSION }, null, 2) + '\n'),
    writeFile(
      path.join(repoRoot, 'startos-0.4/package.json'),
      JSON.stringify({ name: 'blindspark-startos', dependencies: { '@start9labs/start-sdk': '2.0.1' } }, null, 2) + '\n'
    ),
    writeFile(
      path.join(repoRoot, 'startos-0.4/package-lock.json'),
      JSON.stringify({
        packages: {
          '': {
            name: 'blindspark-startos',
            dependencies: { '@start9labs/start-sdk': '2.0.1' }
          },
          'node_modules/@start9labs/start-sdk': {
            version: '2.0.1',
            resolved: 'https://registry.npmjs.org/@start9labs/start-sdk/-/start-sdk-2.0.1.tgz',
            integrity: 'sha512-h0CBfS501KpQ0FX3GoYhxyt1mZYRYgvIYBygWek1kZ7Yl1LHi2uUMzp00Jln38HhB9cJWya3AM9zlGqR91uRdw=='
          }
        }
      }, null, 2) + '\n'
    ),
    writeFile(
      path.join(repoRoot, 'startos-0.4/startos/versions/current.ts'),
      `export const current = { version: '${PACKAGE_VERSION}' }\n`
    )
  ])
  return repoRoot
}

function childImage (revision) {
  return {
    architecture: 'amd64',
    os: 'linux',
    config: { Labels: { 'org.opencontainers.image.revision': revision } }
  }
}

function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function run (script, args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [path.join(ROOT, script), ...args], { cwd: ROOT }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
  })
}

function runWithInput (script, args, input) {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [path.join(ROOT, script), ...args], { cwd: ROOT }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
    child.stdin.end(input)
  })
}
