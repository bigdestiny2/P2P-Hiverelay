import test from 'brittle'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  resolveStartos04ReleaseBinding,
  selectReusableReleaseImageArtifact
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
const CHECKOUT_ACTION_SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1'
const START_CLI_URL = 'https://github.com/Start9Labs/start-technologies/releases/download/start-cli%2Fv1.1.0/start-cli_x86_64-linux'
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
  t.is(env.HIVERELAY_RELEASE_SURFACES_RUN_ATTEMPT, '3')
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
  const env = Object.fromEntries((await readFile(githubEnv, 'utf8')).trim().split('\n').map(line => line.split('=')))
  t.is(env.HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ID, '54321')
  t.is(env.HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ATTEMPT, '3')
  t.is(env.HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_URL, 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/54321')
  t.is(env.HIVERELAY_IMAGE_NAME, IMAGE_NAME)
  t.is(env.HIVERELAY_IMAGE_DIGEST, IMAGE_DIGEST)
  t.is(env.HIVERELAY_IMAGE_AMD64_DIGEST, AMD64_DIGEST)
  t.is(env.HIVERELAY_IMAGE_ARM64_DIGEST, ARM64_DIGEST)

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

test('reusable image authority selector binds one immutable exact-source artifact', async (t) => {
  const valid = reusableImageAuthorityArtifact({ id: 901, runId: 701 })
  const older = reusableImageAuthorityArtifact({ id: 900, runId: 700 })
  const response = { total_count: 3, artifacts: [older, valid, reusableImageAuthorityArtifact({ id: 902, runId: 702, headSha: 'f'.repeat(40) })] }
  const selected = selectReusableReleaseImageArtifact({ response, expectedTag: TAG, expectedTagSha: TAG_SHA })
  t.is(selected.id, '901')
  t.is(selected.sourceRunId, '701')
  t.is(selected.digest, valid.digest)

  const absent = selectReusableReleaseImageArtifact({
    response: { total_count: 1, artifacts: [reusableImageAuthorityArtifact({ id: 902, runId: 702, expired: true })] },
    expectedTag: TAG,
    expectedTagSha: TAG_SHA
  })
  t.is(absent.found, false)

  const adversarial = [
    [{ total_count: 2, artifacts: [valid] }, 'response is incomplete'],
    [{ total_count: 1, artifacts: [{ ...valid, size_in_bytes: 0 }] }, 'artifact size'],
    [{ total_count: 1, artifacts: [{ ...valid, digest: 'sha256:bad' }] }, 'artifact digest'],
    [{ total_count: 1, artifacts: [{ ...valid, archive_download_url: 'https://example.com/authority.zip' }] }, 'archive URL']
  ]
  for (const [badResponse, message] of adversarial) {
    t.exception(() => selectReusableReleaseImageArtifact({
      response: badResponse,
      expectedTag: TAG,
      expectedTagSha: TAG_SHA
    }), new RegExp(message), message)
  }
})

test('reusable release run verifier binds id, attempt, source, event, and completed checkpoint authority', async (t) => {
  const runId = '54321'
  const runUrl = `https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/${runId}`
  const args = [
    '--run-id', runId,
    '--run-attempt', '2',
    '--run-url', runUrl,
    '--tag', TAG,
    '--tag-sha', TAG_SHA
  ]
  const accepted = await runWithInput(
    'scripts/verify-reusable-release-run.mjs',
    args,
    JSON.stringify(reusableReleaseRun({ databaseId: Number(runId), url: runUrl }))
  )
  t.is(accepted.status, 0, accepted.stderr)

  for (const event of ['release', 'workflow_dispatch']) {
    const acceptedEvent = await runWithInput(
      'scripts/verify-reusable-release-run.mjs',
      args,
      JSON.stringify(reusableReleaseRun({ databaseId: Number(runId), url: runUrl, event }))
    )
    t.is(acceptedEvent.status, 0, `${event}: ${acceptedEvent.stderr}`)
  }

  const acceptedLateFailure = await runWithInput(
    'scripts/verify-reusable-release-run.mjs',
    args,
    JSON.stringify(reusableReleaseRun({
      databaseId: Number(runId),
      url: runUrl,
      conclusion: 'failure',
      jobs: [successfulSyncJob({ conclusion: 'failure' })]
    }))
  )
  t.is(acceptedLateFailure.status, 0, acceptedLateFailure.stderr)

  const adversarial = [
    [{ databaseId: 99999, url: runUrl }, 'database id'],
    [{ databaseId: Number(runId), url: runUrl, attempt: 3 }, 'run attempt'],
    [{ databaseId: Number(runId), url: `${runUrl}/attempts/2` }, 'run URL'],
    [{ databaseId: Number(runId), url: runUrl, workflowName: 'Release StartOS 0.4 package' }, 'workflow name'],
    [{ databaseId: Number(runId), url: runUrl, workflowPath: '.github/workflows/not-release-surfaces.yml' }, 'workflow path'],
    [{ databaseId: Number(runId), url: runUrl, status: 'in_progress' }, 'run status'],
    [{ databaseId: Number(runId), url: runUrl, headSha: 'f'.repeat(40) }, 'head SHA'],
    [{ databaseId: Number(runId), url: runUrl, headBranch: `${TAG}-other` }, 'head ref'],
    [{ databaseId: Number(runId), url: runUrl, event: 'schedule' }, 'run event'],
    [{
      databaseId: Number(runId),
      url: runUrl,
      jobs: [successfulSyncJob(), successfulSyncJob()]
    }, 'sync job count'],
    [{
      databaseId: Number(runId),
      url: runUrl,
      jobs: [successfulSyncJob({
        steps: successfulCheckpointSteps().map((step, index) => index === 3
          ? { ...step, conclusion: 'failure' }
          : step)
      })]
    }, 'checkpoint step Write release evidence conclusion']
  ]
  for (const [override, message] of adversarial) {
    const rejected = await runWithInput(
      'scripts/verify-reusable-release-run.mjs',
      args,
      JSON.stringify(reusableReleaseRun(override))
    )
    t.is(rejected.status, 1, message)
    t.ok(rejected.stderr.includes(message), rejected.stderr)
  }
})

test('signed release image index verifier binds exact raw bytes and platform children', async (t) => {
  const index = {
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: AMD64_DIGEST,
        size: 100,
        platform: { os: 'linux', architecture: 'amd64' }
      },
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ARM64_DIGEST,
        size: 100,
        platform: { os: 'linux', architecture: 'arm64' }
      },
      {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: `sha256:${'e'.repeat(64)}`,
        size: 100,
        platform: { os: 'unknown', architecture: 'unknown' },
        annotations: { 'vnd.docker.reference.type': 'attestation-manifest' }
      }
    ]
  }
  const raw = Buffer.from(JSON.stringify(index))
  const args = [
    '--index-digest', `sha256:${sha256(raw)}`,
    '--amd64-digest', AMD64_DIGEST,
    '--arm64-digest', ARM64_DIGEST
  ]
  const accepted = await runWithInput('scripts/verify-startos-04-image-index.mjs', args, raw)
  t.is(accepted.status, 0, accepted.stderr)

  const wrongIndex = structuredClone(index)
  wrongIndex.manifests[1].digest = `sha256:${'f'.repeat(64)}`
  const wrongRaw = Buffer.from(JSON.stringify(wrongIndex))
  const wrongChild = await runWithInput('scripts/verify-startos-04-image-index.mjs', [
    '--index-digest', `sha256:${sha256(wrongRaw)}`,
    '--amd64-digest', AMD64_DIGEST,
    '--arm64-digest', ARM64_DIGEST
  ], wrongRaw)
  t.is(wrongChild.status, 1)
  t.ok(wrongChild.stderr.includes('linux/arm64 child digest'))

  const substitutedRaw = await runWithInput('scripts/verify-startos-04-image-index.mjs', [
    '--index-digest', `sha256:${'0'.repeat(64)}`,
    '--amd64-digest', AMD64_DIGEST,
    '--arm64-digest', ARM64_DIGEST
  ], raw)
  t.is(substitutedRaw.status, 1)
  t.ok(substitutedRaw.stderr.includes('raw index digest'))
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
  t.is(body.toolchain.sourceCheckoutAction.commit, CHECKOUT_ACTION_SHA)
  t.is(body.toolchain.sourceCheckoutAction.evidenceRole, 'workflow-source-checkout-contract')
  t.is(body.toolchain.startCli.version, '1.1.0')
  t.is(body.toolchain.startCli.sourceUrl, START_CLI_URL)
  t.is(body.toolchain.startCli.sha256, START_CLI_SHA256)
  t.is(body.toolchain.startCli.evidenceRole, 'fixed-url-hash-verified-workflow-build-and-current-inspection-contract')
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

test('final release closure binds exact child artifact, independent inspection, and current release bytes', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '700' })
  const startosEvidence = path.join(fixture.dir, 'startos-0.4-release-evidence.json')
  const writtenStartos = await writeEvidence(fixture, '700', ['--out', startosEvidence])
  t.is(writtenStartos.status, 0, writtenStartos.stderr)

  const artifactDir = path.join(fixture.dir, 'child-artifact')
  const releaseDir = path.join(fixture.dir, 'release-assets')
  const bundleDir = path.join(fixture.dir, 'bundle')
  await Promise.all([mkdir(artifactDir), mkdir(releaseDir), mkdir(bundleDir)])
  const copies = {
    artifactPackage: path.join(artifactDir, PACKAGE_NAME),
    artifactStartosEvidence: path.join(artifactDir, 'startos-0.4-release-evidence.json'),
    releasePackage: path.join(releaseDir, PACKAGE_NAME),
    releaseStartosEvidence: path.join(releaseDir, 'startos-0.4-release-evidence.json')
  }
  await Promise.all([
    copyFile(fixture.package, copies.artifactPackage),
    copyFile(startosEvidence, copies.artifactStartosEvidence),
    copyFile(fixture.package, copies.releasePackage),
    copyFile(startosEvidence, copies.releaseStartosEvidence)
  ])
  const childRun = path.join(fixture.dir, 'child-run.json')
  const artifactMetadata = path.join(fixture.dir, 'child-artifact.json')
  await writeFile(childRun, JSON.stringify(successfulStartosChildRun(), null, 2) + '\n')
  await writeFile(artifactMetadata, JSON.stringify(successfulChildArtifact(), null, 2) + '\n')
  const closure = path.join(fixture.dir, 'release-closure-evidence.json')
  const args = closureArgs(fixture, copies, childRun, artifactMetadata)
  const written = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', closure])
  t.is(written.status, 0, written.stderr)
  const verified = await run('scripts/write-release-closure-evidence.mjs', [...args, '--verify', closure])
  t.is(verified.status, 0, verified.stderr)

  const body = JSON.parse(await readFile(closure, 'utf8'))
  t.is(body.status, 'verified-startos-0.4-closure')
  t.is(body.sourceCheckpointEvidence.workflowStatus, 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure')
  t.is(body.sourceCheckpointEvidence.runAttempt, '3')
  t.is(body.startos04.childWorkflow.runId, '900')
  t.is(body.startos04.immutableArtifact.sourceRunAttempt, '2')
  t.ok(/^[a-f0-9]{64}$/.test(body.startos04.inspectedPackage.commitmentSha256))
  t.is(body.startos04.inspectedPackage.signerIdentity.status, 'not-exposed-by-start-cli-1.1.0')
  t.is(body.publication.atomicity, 'non-atomic')
  t.ok(body.publication.surfacesThatMayPrecedeClosure.includes('startos-0.4-release-package-and-evidence-pair'))
  t.is(body.publication.stableGaPolicy, 'stable-and-ga-closure-requires-this-verified-certificate')

  await Promise.all([
    copyFile(fixture.releaseEvidence, path.join(bundleDir, 'release-evidence.json')),
    copyFile(fixture.imageManifestEvidence, path.join(bundleDir, 'release-image-manifest-evidence.json')),
    copyFile(copies.releasePackage, path.join(bundleDir, PACKAGE_NAME)),
    copyFile(copies.releaseStartosEvidence, path.join(bundleDir, 'startos-0.4-release-evidence.json')),
    copyFile(closure, path.join(bundleDir, 'release-closure-evidence.json'))
  ])
  const offline = await run('scripts/verify-release-closure-evidence.mjs', ['--bundle-dir', bundleDir])
  t.is(offline.status, 0, offline.stderr)

  const bundledClosure = path.join(bundleDir, 'release-closure-evidence.json')
  const wrongAttemptBody = JSON.parse(await readFile(bundledClosure, 'utf8'))
  wrongAttemptBody.startos04.immutableArtifact.sourceRunAttempt = '999'
  await writeFile(bundledClosure, JSON.stringify(wrongAttemptBody, null, 2) + '\n')
  const wrongAttempt = await run('scripts/verify-release-closure-evidence.mjs', ['--bundle-dir', bundleDir])
  t.is(wrongAttempt.status, 1)
  t.ok(wrongAttempt.stderr.includes('artifact source run attempt'))
  await copyFile(closure, bundledClosure)

  const bundledPackage = path.join(bundleDir, PACKAGE_NAME)
  await writeFile(bundledPackage, '')
  const emptyPackage = await run('scripts/verify-release-closure-evidence.mjs', ['--bundle-dir', bundleDir])
  t.is(emptyPackage.status, 1)
  t.ok(emptyPackage.stderr.includes('package size must be between 1'))
  await copyFile(copies.releasePackage, bundledPackage)

  const bundledReleaseEvidence = path.join(bundleDir, 'release-evidence.json')
  await unlink(bundledReleaseEvidence)
  await symlink(fixture.releaseEvidence, bundledReleaseEvidence)
  const symlinked = await run('scripts/verify-release-closure-evidence.mjs', ['--bundle-dir', bundleDir])
  t.is(symlinked.status, 1)
  t.ok(symlinked.stderr.includes('regular JSON file'))

  const wrongArtifactSource = successfulChildArtifact()
  wrongArtifactSource.workflow_run.id = 999
  await writeFile(artifactMetadata, JSON.stringify(wrongArtifactSource, null, 2) + '\n')
  const wrongArtifact = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', path.join(fixture.dir, 'wrong-artifact.json')])
  t.is(wrongArtifact.status, 1)
  t.ok(wrongArtifact.stderr.includes('artifact source run id'))
  await writeFile(artifactMetadata, JSON.stringify(successfulChildArtifact(), null, 2) + '\n')

  await writeFile(copies.releasePackage, 'substituted mutable release package')
  const substituted = await run('scripts/write-release-closure-evidence.mjs', [...args, '--verify', closure])
  t.is(substituted.status, 1)
  t.ok(substituted.stderr.includes('published sidecar') || substituted.stderr.includes('package bytes'))

  const wrongWorkflow = successfulStartosChildRun()
  wrongWorkflow.path = '.github/workflows/release-surfaces.yml'
  await writeFile(childRun, JSON.stringify(wrongWorkflow, null, 2) + '\n')
  const wrongPath = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', path.join(fixture.dir, 'wrong-workflow.json')])
  t.is(wrongPath.status, 1)
  t.ok(wrongPath.stderr.includes('child workflow path'))

  const wrongRun = successfulStartosChildRun()
  wrongRun.head_sha = 'f'.repeat(40)
  await writeFile(childRun, JSON.stringify(wrongRun, null, 2) + '\n')
  const wrongChild = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', path.join(fixture.dir, 'wrong-child.json')])
  t.is(wrongChild.status, 1)
  t.ok(wrongChild.stderr.includes('child head SHA'))
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
        scope: 'release-surfaces/pre-handoff-checkpoint',
        status: 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure',
        repository: 'bigdestiny2/P2P-Hiverelay',
        runId,
        runAttempt: '3',
        runUrl: `https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/${runId}`
      },
      closure: {
        status: 'pending-startos-0.4',
        evidence: 'release-closure-evidence.json'
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

function reusableReleaseRun (override = {}) {
  return {
    databaseId: 54321,
    attempt: 2,
    url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/54321',
    workflowName: 'Release surfaces',
    workflowPath: '.github/workflows/release-surfaces.yml',
    headSha: TAG_SHA,
    headBranch: TAG,
    event: 'push',
    status: 'completed',
    conclusion: 'failure',
    jobs: [successfulSyncJob()],
    ...override
  }
}

function successfulSyncJob (override = {}) {
  return {
    name: 'sync',
    status: 'completed',
    conclusion: 'success',
    steps: successfulCheckpointSteps(),
    ...override
  }
}

function successfulCheckpointSteps () {
  return [
    'Sign release image (cosign keyless)',
    'Verify release image manifest platforms',
    'Smoke pushed release image',
    'Write release evidence',
    'Verify release evidence'
  ].map(name => ({ name, status: 'completed', conclusion: 'success' }))
}

function reusableImageAuthorityArtifact ({
  id,
  runId,
  headSha = TAG_SHA,
  headRef = TAG,
  expired = false
}) {
  return {
    id,
    name: `release-image-authority-${TAG}`,
    size_in_bytes: 4096,
    digest: `sha256:${String(id).padStart(64, '0')}`,
    archive_download_url: `https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/actions/artifacts/${id}/zip`,
    expired,
    workflow_run: {
      id: runId,
      head_sha: headSha,
      head_branch: headRef
    }
  }
}

function successfulStartosChildRun () {
  return {
    id: 900,
    run_attempt: 2,
    html_url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/900',
    name: 'Release StartOS 0.4 package',
    path: '.github/workflows/release-startos-0.4.yml',
    display_title: `StartOS 0.4 ${TAG} from release-surfaces 700`,
    head_sha: TAG_SHA,
    head_branch: TAG,
    event: 'workflow_dispatch',
    status: 'completed',
    conclusion: 'success'
  }
}

function successfulChildArtifact () {
  return {
    id: 901,
    name: 'startos-0.4-closure-900-2',
    size_in_bytes: 4096,
    digest: `sha256:${'e'.repeat(64)}`,
    archive_download_url: 'https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/actions/artifacts/901/zip',
    expired: false,
    workflow_run: {
      id: 900,
      head_sha: TAG_SHA,
      head_branch: TAG
    }
  }
}

function closureArgs (fixture, copies, childRun, artifactMetadata) {
  return [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', '700',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--artifact-package', copies.artifactPackage,
    '--artifact-startos-evidence', copies.artifactStartosEvidence,
    '--release-package', copies.releasePackage,
    '--release-startos-evidence', copies.releaseStartosEvidence,
    '--commitment', fixture.commitment,
    '--manifest', fixture.manifest,
    '--child-run', childRun,
    '--child-run-id', '900',
    '--artifact-metadata', artifactMetadata
  ]
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
