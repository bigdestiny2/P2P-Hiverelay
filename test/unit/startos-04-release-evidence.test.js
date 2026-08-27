import test from 'brittle'
import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  resolveStartos04ReleaseBinding,
  selectReusableReleaseImageArtifact,
  selectStartos04ReleaseImageAuthorityArtifact,
  verifyStartos04ParentRunAuthority
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
    '--release-surfaces-run-attempt', '3',
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

  const wrongAttempt = await run('scripts/resolve-startos-04-release.mjs', [
    '--tag', TAG,
    '--tag-sha', TAG_SHA,
    '--release-surfaces-run-id', '12345',
    '--release-surfaces-run-attempt', '4',
    '--release-evidence', fixture.releaseEvidence,
    '--image-manifest-evidence', fixture.imageManifestEvidence,
    '--github-env', path.join(fixture.dir, 'wrong-attempt-env')
  ])
  t.is(wrongAttempt.status, 1)
  t.ok(wrongAttempt.stderr.includes('source run attempt'))
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

test('StartOS image authority selector binds the dispatched run-attempt artifact id and source', async (t) => {
  const valid = startosImageAuthorityArtifact()
  const args = {
    response: { total_count: 1, artifacts: [valid] },
    expectedTag: TAG,
    expectedTagSha: TAG_SHA,
    expectedRunId: '777',
    expectedRunAttempt: '3',
    expectedArtifactId: '990'
  }
  const selected = selectStartos04ReleaseImageAuthorityArtifact(args)
  t.is(selected.id, '990')
  t.is(selected.sourceRunId, '777')
  t.is(selected.sourceRunAttempt, '3')
  t.is(selected.digest, valid.digest)
  const normalized = selectStartos04ReleaseImageAuthorityArtifact({
    ...args,
    response: { total_count: 1, artifacts: [selected] }
  })
  t.alike(normalized, selected)

  const adversarial = [
    [{ total_count: 0, artifacts: [] }, 'artifact count'],
    [{ total_count: 2, artifacts: [valid] }, 'response is incomplete'],
    [{ total_count: 2, artifacts: [valid, valid] }, 'artifact count'],
    [{ total_count: 1, artifacts: [{ ...valid, id: 991 }] }, 'artifact id'],
    [{ total_count: 1, artifacts: [{ ...valid, name: `${valid.name}-decoy` }] }, 'artifact name'],
    [{ total_count: 1, artifacts: [{ ...valid, expired: true }] }, 'artifact expired'],
    [{ total_count: 1, artifacts: [{ ...valid, size_in_bytes: 0 }] }, 'artifact size'],
    [{ total_count: 1, artifacts: [{ ...valid, size_in_bytes: 16 * 1024 * 1024 + 1 }] }, 'artifact size'],
    [{ total_count: 1, artifacts: [{ ...valid, digest: 'sha256:bad' }] }, 'artifact digest'],
    [{ total_count: 1, artifacts: [{ ...valid, archive_download_url: 'https://example.com/authority.zip' }] }, 'archive URL'],
    [{ total_count: 1, artifacts: [{ ...valid, workflow_run: { ...valid.workflow_run, id: 778 } }] }, 'source run id'],
    [{ total_count: 1, artifacts: [{ ...valid, workflow_run: { ...valid.workflow_run, head_sha: 'f'.repeat(40) } }] }, 'source head SHA'],
    [{ total_count: 1, artifacts: [{ ...valid, workflow_run: { ...valid.workflow_run, head_branch: `${TAG}-wrong` } }] }, 'source head ref']
  ]
  for (const [response, message] of adversarial) {
    t.exception(
      () => selectStartos04ReleaseImageAuthorityArtifact({ ...args, response }),
      new RegExp(message),
      message
    )
  }
  t.exception(() => selectStartos04ReleaseImageAuthorityArtifact({
    ...args,
    response: {
      total_count: 1,
      artifacts: [{ ...selected, sourceRunAttempt: '4' }]
    }
  }), /source run attempt/)
  t.exception(() => selectStartos04ReleaseImageAuthorityArtifact({
    ...args,
    response: {
      total_count: 1,
      artifacts: [{ ...valid, sourceRunId: '777' }]
    }
  }), /exactly one complete raw REST or normalized shape/)
})

test('StartOS parent authority allows an in-progress parent but binds exact successful sync checkpoints', async (t) => {
  const args = {
    run: startosParentRun(),
    expectedRunId: '777',
    expectedRunAttempt: '3',
    expectedRunUrl: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/777',
    expectedTag: TAG,
    expectedTagSha: TAG_SHA
  }
  const accepted = verifyStartos04ParentRunAuthority(args)
  t.is(accepted.syncConclusion, 'success')
  t.exception(
    () => verifyStartos04ParentRunAuthority({ ...args, requireTerminalSuccess: true }),
    /terminal run status/
  )
  const terminal = verifyStartos04ParentRunAuthority({
    ...args,
    run: startosParentRun({ status: 'completed', conclusion: 'success' }),
    requireTerminalSuccess: true
  })
  t.is(terminal.runConclusion, 'success')
  t.exception(
    () => verifyStartos04ParentRunAuthority({
      ...args,
      run: startosParentRun({ status: 'completed', conclusion: 'failure' })
    }),
    /completed run conclusion/
  )

  for (const event of ['release', 'workflow_dispatch']) {
    t.is(verifyStartos04ParentRunAuthority({ ...args, run: startosParentRun({ event }) }).event, event)
  }

  const adversarial = [
    [{ databaseId: 778 }, 'database id'],
    [{ attempt: 4 }, 'run attempt'],
    [{ url: `${args.expectedRunUrl}/wrong` }, 'run URL'],
    [{ workflowName: 'Decoy release' }, 'workflow name'],
    [{ workflowPath: `.github/workflows/decoy.yml@refs/tags/${TAG}` }, 'workflow path'],
    [{ workflowPath: '.github/workflows/release-surfaces.yml@refs/heads/main' }, 'workflow path'],
    [{ workflowPath: `.github/workflows/release-surfaces.yml@refs/tags/${TAG}-wrong` }, 'workflow path'],
    [{ status: 'queued' }, 'run status'],
    [{ headSha: 'f'.repeat(40) }, 'head SHA'],
    [{ headBranch: `${TAG}-wrong` }, 'head ref'],
    [{ event: 'schedule' }, 'run event'],
    [{ jobs: [] }, 'sync job count'],
    [{ jobs: [startosParentSyncJob(), startosParentSyncJob()] }, 'sync job count'],
    [{ jobs: [startosParentSyncJob({ conclusion: 'failure' })] }, 'sync job conclusion'],
    [{ jobs: [startosParentSyncJob({ steps: startosParentCheckpointSteps().filter(step => step.name !== 'Upload exact StartOS image authority') })] }, 'checkpoint step Upload exact StartOS image authority count'],
    [{ jobs: [startosParentSyncJob({ steps: startosParentCheckpointSteps().map(step => step.name === 'Upload immutable reusable image authority' ? { ...step, conclusion: 'failure' } : step) })] }, 'checkpoint step Upload immutable reusable image authority conclusion']
  ]
  for (const [override, message] of adversarial) {
    t.exception(
      () => verifyStartos04ParentRunAuthority({ ...args, run: startosParentRun(override) }),
      new RegExp(message),
      message
    )
  }
})

test('StartOS child rejects image-authority ZIP and mutable public checkpoint drift before env export', async (t) => {
  const fixture = await evidenceFixture(t, { runId: '777' })
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-image-authority-step-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  const runnerTemp = path.join(root, 'runner-temp')
  await Promise.all([mkdir(bin), mkdir(runnerTemp)])
  const archive = path.join(root, 'authority.zip')
  const zipped = await exec('zip', ['-q', '-j', archive, fixture.releaseEvidence, fixture.imageManifestEvidence])
  t.is(zipped.status, 0, zipped.stderr)
  const archiveStat = await stat(archive)
  const metadata = startosImageAuthorityArtifact({
    size_in_bytes: archiveStat.size,
    digest: `sha256:${sha256(await readFile(archive))}`
  })
  const metadataFile = path.join(root, 'artifact.json')
  const artifactsFile = path.join(root, 'artifacts.json')
  const parentRun = path.join(root, 'parent-run.json')
  const parentRest = path.join(root, 'parent-rest.json')
  const publicRelease = path.join(root, 'public-release-evidence.json')
  const publicManifest = path.join(root, 'public-image-manifest-evidence.json')
  const drifted = JSON.parse(await readFile(fixture.releaseEvidence, 'utf8'))
  drifted.generatedAt = '2099-01-01T00:00:00.000Z'
  await Promise.all([
    writeFile(metadataFile, JSON.stringify(metadata) + '\n'),
    writeFile(artifactsFile, JSON.stringify({ total_count: 1, artifacts: [metadata] }) + '\n'),
    writeFile(parentRun, JSON.stringify(startosParentRun()) + '\n'),
    writeFile(parentRest, JSON.stringify({ path: `.github/workflows/release-surfaces.yml@refs/tags/${TAG}` }) + '\n'),
    writeFile(publicRelease, JSON.stringify(drifted, null, 2) + '\n'),
    copyFile(fixture.imageManifestEvidence, publicManifest)
  ])
  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
if [ "$1" = run ] && [ "$2" = view ]; then
  cat "$GH_PARENT_RUN"
elif [ "$1" = api ]; then
  case "$2" in
    *actions/runs/777/attempts/3) cat "$GH_PARENT_REST" ;;
    *actions/runs/777/artifacts*) cat "$GH_ARTIFACTS" ;;
    *actions/artifacts/990/zip) cat "$GH_AUTHORITY_ZIP" ;;
    *actions/artifacts/990) cat "$GH_AUTHORITY_METADATA" ;;
    *) exit 97 ;;
  esac
elif [ "$1" = release ] && [ "$2" = download ]; then
  out=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --dir ]; then out="$2"; shift 2; continue; fi
    shift
  done
  cp "$GH_PUBLIC_RELEASE" "$out/release-evidence.json"
  cp "$GH_PUBLIC_MANIFEST" "$out/release-image-manifest-evidence.json"
else
  exit 98
fi
`)
  await chmod(gh, 0o755)
  const githubEnv = path.join(root, 'github-env')
  const baseEnv = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH || ''}`,
    GH_TOKEN: 'test',
    GITHUB_ENV: githubEnv,
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    HIVERELAY_RELEASE_TAG: TAG,
    HIVERELAY_RELEASE_SHA: TAG_SHA,
    EXPECTED_RELEASE_SURFACES_RUN_ID: '777',
    EXPECTED_RELEASE_SURFACES_RUN_ATTEMPT: '3',
    EXPECTED_IMAGE_AUTHORITY_ARTIFACT_ID: '990',
    RUNNER_TEMP: runnerTemp,
    GH_PARENT_RUN: parentRun,
    GH_PARENT_REST: parentRest,
    GH_ARTIFACTS: artifactsFile,
    GH_AUTHORITY_METADATA: metadataFile,
    GH_AUTHORITY_ZIP: archive,
    GH_PUBLIC_RELEASE: publicRelease,
    GH_PUBLIC_MANIFEST: publicManifest
  }
  const script = await workflowRunBlock('.github/workflows/release-startos-0.4.yml', 'Resolve immutable release image authority')
  const publicDrift = await execShellScript(script, baseEnv)
  t.is(publicDrift.status, 1)
  t.ok(publicDrift.stderr.includes('Public release-evidence.json differs from immutable image authority'), publicDrift.stderr)
  t.is(await fileExists(githubEnv), false, 'binding is not exported before public comparison')

  const wrongArchive = path.join(root, 'wrong-inventory.zip')
  const extra = path.join(root, 'extra.txt')
  await writeFile(extra, 'decoy')
  const zippedWrong = await exec('zip', [
    '-q', '-j', wrongArchive, fixture.releaseEvidence, fixture.imageManifestEvidence, extra
  ])
  t.is(zippedWrong.status, 0, zippedWrong.stderr)
  const wrongStat = await stat(wrongArchive)
  const wrongMetadata = startosImageAuthorityArtifact({
    size_in_bytes: wrongStat.size,
    digest: `sha256:${sha256(await readFile(wrongArchive))}`
  })
  await Promise.all([
    writeFile(metadataFile, JSON.stringify(wrongMetadata) + '\n'),
    writeFile(artifactsFile, JSON.stringify({ total_count: 1, artifacts: [wrongMetadata] }) + '\n')
  ])
  const secondRunnerTemp = path.join(root, 'runner-temp-2')
  await mkdir(secondRunnerTemp)
  const wrongInventory = await execShellScript(script, {
    ...baseEnv,
    GH_AUTHORITY_ZIP: wrongArchive,
    RUNNER_TEMP: secondRunnerTemp
  })
  t.is(wrongInventory.status, 1)
  t.ok(wrongInventory.stderr.includes('must contain exactly the two flat evidence files'), wrongInventory.stderr)

  const badDigestMetadata = { ...metadata, digest: `sha256:${'0'.repeat(64)}` }
  await Promise.all([
    writeFile(metadataFile, JSON.stringify(badDigestMetadata) + '\n'),
    writeFile(artifactsFile, JSON.stringify({ total_count: 1, artifacts: [badDigestMetadata] }) + '\n')
  ])
  const thirdRunnerTemp = path.join(root, 'runner-temp-3')
  await mkdir(thirdRunnerTemp)
  const wrongDigest = await execShellScript(script, { ...baseEnv, RUNNER_TEMP: thirdRunnerTemp })
  t.is(wrongDigest.status, 1)
  t.ok(wrongDigest.stderr.includes('does not match its exact REST size/digest'), wrongDigest.stderr)
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
        annotations: {
          'vnd.docker.reference.type': 'attestation-manifest',
          'vnd.docker.reference.digest': AMD64_DIGEST
        }
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

  const platformDecoy = structuredClone(index)
  platformDecoy.manifests.push({
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    digest: `sha256:${'d'.repeat(64)}`,
    size: 100,
    platform: { os: 'linux', architecture: 'amd64' },
    annotations: {
      'vnd.docker.reference.type': 'attestation-manifest',
      'vnd.docker.reference.digest': AMD64_DIGEST
    }
  })
  const decoyRaw = Buffer.from(JSON.stringify(platformDecoy))
  const annotatedDecoy = await runWithInput('scripts/verify-startos-04-image-index.mjs', [
    '--index-digest', `sha256:${sha256(decoyRaw)}`,
    '--amd64-digest', AMD64_DIGEST,
    '--arm64-digest', ARM64_DIGEST
  ], decoyRaw)
  t.is(annotatedDecoy.status, 1)
  t.ok(annotatedDecoy.stderr.includes('attestation platform'))

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
  const artifactArchive = path.join(fixture.dir, 'child-artifact.zip')
  const imageAuthorityMetadata = path.join(fixture.dir, 'image-authority-artifact.json')
  const imageAuthorityArchive = path.join(fixture.dir, 'image-authority-artifact.zip')
  const zipped = await exec('zip', ['-q', '-j', artifactArchive, copies.artifactPackage, copies.artifactStartosEvidence])
  t.is(zipped.status, 0, zipped.stderr)
  const archiveStat = await stat(artifactArchive)
  const liveArtifact = successfulChildArtifact({
    size_in_bytes: archiveStat.size,
    digest: `sha256:${sha256(await readFile(artifactArchive))}`
  })
  await writeFile(childRun, JSON.stringify(successfulStartosChildRun(), null, 2) + '\n')
  await writeFile(artifactMetadata, JSON.stringify(liveArtifact, null, 2) + '\n')
  const zippedAuthority = await exec('zip', [
    '-q', '-j', imageAuthorityArchive, fixture.releaseEvidence, fixture.imageManifestEvidence
  ])
  t.is(zippedAuthority.status, 0, zippedAuthority.stderr)
  const authorityStat = await stat(imageAuthorityArchive)
  const imageAuthority = startosImageAuthorityArtifact({
    name: `release-image-authority-${TAG}-700-3`,
    size_in_bytes: authorityStat.size,
    digest: `sha256:${sha256(await readFile(imageAuthorityArchive))}`,
    workflow_run: { id: 700, head_sha: TAG_SHA, head_branch: TAG }
  })
  await writeFile(imageAuthorityMetadata, JSON.stringify(imageAuthority, null, 2) + '\n')
  const closure = path.join(fixture.dir, 'release-closure-evidence.json')
  const args = closureArgs(fixture, copies, childRun, artifactMetadata, imageAuthorityMetadata)
  const written = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', closure])
  t.is(written.status, 0, written.stderr)
  const verified = await run('scripts/write-release-closure-evidence.mjs', [...args, '--verify', closure])
  t.is(verified.status, 0, verified.stderr)

  const body = JSON.parse(await readFile(closure, 'utf8'))
  t.is(body.status, 'verified-startos-0.4-closure')
  t.is(body.sourceCheckpointEvidence.workflowStatus, 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure')
  t.is(body.sourceCheckpointEvidence.runAttempt, '3')
  t.is(body.image.authority.id, '990')
  t.is(body.image.authority.sourceRunAttempt, '3')
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
  t.is(offline.status, 1)
  t.ok(offline.stderr.includes('Offline JSON-only release closure verification is non-authoritative'))

  const live = await liveClosureFixture(t, {
    bundleDir,
    closure,
    startosEvidence,
    artifactArchive,
    artifactMetadata,
    childRun,
    imageAuthorityArchive,
    imageAuthorityMetadata
  })
  t.is(live.status, 0, live.stderr)
  t.ok(live.stdout.includes('Live GitHub release closure verified'))

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
  t.ok(symlinked.stderr.includes('must be a regular file'))

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

  const wrongWorkflowRef = successfulStartosChildRun()
  wrongWorkflowRef.path = '.github/workflows/release-startos-0.4.yml@refs/heads/main'
  await writeFile(childRun, JSON.stringify(wrongWorkflowRef, null, 2) + '\n')
  const wrongRef = await run('scripts/write-release-closure-evidence.mjs', [...args, '--out', path.join(fixture.dir, 'wrong-workflow-ref.json')])
  t.is(wrongRef.status, 1)
  t.ok(wrongRef.stderr.includes('child workflow path'))

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
    '--release-surfaces-run-attempt', '3',
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
    '--release-surfaces-run-attempt', '3',
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
      prerelease: true,
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
    workflowPath: `.github/workflows/release-surfaces.yml@refs/tags/${TAG}`,
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

function startosParentCheckpointSteps () {
  return [
    ...successfulCheckpointSteps(),
    { name: 'Upload immutable reusable image authority', status: 'completed', conclusion: 'success' },
    { name: 'Upload exact StartOS image authority', status: 'completed', conclusion: 'success' }
  ]
}

function startosParentSyncJob (override = {}) {
  return {
    name: 'sync',
    status: 'completed',
    conclusion: 'success',
    steps: startosParentCheckpointSteps(),
    ...override
  }
}

function startosParentRun (override = {}) {
  return {
    databaseId: 777,
    attempt: 3,
    url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/777',
    workflowName: 'Release surfaces',
    workflowPath: `.github/workflows/release-surfaces.yml@refs/tags/${TAG}`,
    headSha: TAG_SHA,
    headBranch: TAG,
    event: 'push',
    status: 'in_progress',
    conclusion: '',
    jobs: [startosParentSyncJob()],
    ...override
  }
}

function startosImageAuthorityArtifact (override = {}) {
  return {
    id: 990,
    name: `release-image-authority-${TAG}-777-3`,
    size_in_bytes: 4096,
    digest: `sha256:${'9'.repeat(64)}`,
    archive_download_url: 'https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/actions/artifacts/990/zip',
    expired: false,
    workflow_run: {
      id: 777,
      head_sha: TAG_SHA,
      head_branch: TAG
    },
    ...override
  }
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
    path: `.github/workflows/release-startos-0.4.yml@refs/tags/${TAG}`,
    display_title: `StartOS 0.4 ${TAG} from release-surfaces 700 attempt 3`,
    head_sha: TAG_SHA,
    head_branch: TAG,
    event: 'workflow_dispatch',
    status: 'completed',
    conclusion: 'success'
  }
}

function successfulChildArtifact (override = {}) {
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
    },
    ...override
  }
}

function closureArgs (fixture, copies, childRun, artifactMetadata, imageAuthorityMetadata) {
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
    '--artifact-metadata', artifactMetadata,
    '--image-authority-metadata', imageAuthorityMetadata,
    '--image-authority-artifact-id', '990'
  ]
}

async function liveClosureFixture (t, {
  bundleDir,
  artifactArchive,
  artifactMetadata,
  childRun,
  imageAuthorityArchive,
  imageAuthorityMetadata
}) {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-live-closure-api-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  await mkdir(bin)
  const release = path.join(root, 'release.json')
  const tagRef = path.join(root, 'tag-ref.json')
  const tagObject = path.join(root, 'tag-object.json')
  const assets = path.join(root, 'assets.json')
  const parentRunView = path.join(root, 'parent-run-view.json')
  const parentRunRest = path.join(root, 'parent-run-rest.json')
  const assetSources = {
    1001: path.join(bundleDir, 'release-evidence.json'),
    1002: path.join(bundleDir, 'release-image-manifest-evidence.json'),
    1003: path.join(bundleDir, PACKAGE_NAME),
    1004: path.join(bundleDir, 'startos-0.4-release-evidence.json'),
    1005: path.join(bundleDir, 'release-closure-evidence.json')
  }
  const records = []
  for (const [id, file] of Object.entries(assetSources)) {
    const name = path.basename(file)
    const body = await readFile(file)
    records.push({
      id: Number(id),
      name,
      state: 'uploaded',
      size: body.length,
      digest: `sha256:${sha256(body)}`,
      url: `https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/releases/assets/${id}`
    })
  }
  await Promise.all([
    writeFile(release, JSON.stringify({
      id: 777,
      tag_name: TAG,
      draft: false,
      prerelease: true,
      url: 'https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/releases/777',
      html_url: `https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/${TAG}`
    }) + '\n'),
    writeFile(tagRef, JSON.stringify({
      ref: `refs/tags/${TAG}`,
      object: { type: 'tag', sha: 'c'.repeat(40) }
    }) + '\n'),
    writeFile(tagObject, JSON.stringify({
      object: { type: 'commit', sha: TAG_SHA }
    }) + '\n'),
    writeFile(assets, JSON.stringify([records]) + '\n'),
    writeFile(parentRunView, JSON.stringify(startosParentRun({
      databaseId: 700,
      url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/700',
      status: 'completed',
      conclusion: 'success'
    })) + '\n'),
    writeFile(parentRunRest, JSON.stringify({ path: `.github/workflows/release-surfaces.yml@refs/tags/${TAG}` }) + '\n')
  ])

  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
if [ "\${GH_TEST_HANG:-0}" = 1 ]; then
  exec sleep 2
fi
if [ "$1" = run ] && [ "$2" = view ] && [ "$3" = 700 ]; then
  cat "$GH_PARENT_RUN_VIEW"
  exit 0
fi
case "$*" in
  *actions/runs/700/attempts/3*) cat "$GH_PARENT_RUN_REST" ;;
  *actions/artifacts/990/zip*) cat "$GH_IMAGE_AUTHORITY_ARCHIVE" ;;
  *actions/artifacts/990*)
    if [ -n "\${GH_IMAGE_AUTHORITY_METADATA_AFTER:-}" ]; then
      if [ -e "$GH_IMAGE_AUTHORITY_METADATA_MARKER" ]; then
        cat "$GH_IMAGE_AUTHORITY_METADATA_AFTER"
      else
        : > "$GH_IMAGE_AUTHORITY_METADATA_MARKER"
        cat "$GH_IMAGE_AUTHORITY_METADATA"
      fi
    else
      cat "$GH_IMAGE_AUTHORITY_METADATA"
    fi
    ;;
  *actions/runs/900/attempts/2*) cat "$GH_CHILD_RUN" ;;
  *actions/artifacts/901/zip*) cat "$GH_ARTIFACT_ARCHIVE" ;;
  *actions/artifacts/901*)
    if [ -n "\${GH_ARTIFACT_METADATA_AFTER:-}" ]; then
      if [ -e "$GH_ARTIFACT_METADATA_MARKER" ]; then
        cat "$GH_ARTIFACT_METADATA_AFTER"
      else
        : > "$GH_ARTIFACT_METADATA_MARKER"
        cat "$GH_ARTIFACT_METADATA"
      fi
    else
      cat "$GH_ARTIFACT_METADATA"
    fi
    ;;
  *releases/tags/${TAG}*) cat "$GH_RELEASE_JSON" ;;
  *git/ref/tags/${TAG}*) cat "$GH_TAG_REF" ;;
  *git/tags/cccccccccccccccccccccccccccccccccccccccc*) cat "$GH_TAG_OBJECT" ;;
  *releases/777/assets*)
    if [ -n "\${GH_RELEASE_ASSETS_AFTER:-}" ]; then
      if [ -e "$GH_RELEASE_ASSETS_MARKER" ]; then
        cat "$GH_RELEASE_ASSETS_AFTER"
      else
        : > "$GH_RELEASE_ASSETS_MARKER"
        cat "$GH_RELEASE_ASSETS"
      fi
    else
      cat "$GH_RELEASE_ASSETS"
    fi
    ;;
  *releases/assets/1001*) cat "$GH_RELEASE_EVIDENCE" ;;
  *releases/assets/1002*) cat "$GH_IMAGE_EVIDENCE" ;;
  *releases/assets/1003*) cat "$GH_STARTOS_PACKAGE" ;;
  *releases/assets/1004*) cat "$GH_STARTOS_EVIDENCE" ;;
  *releases/assets/1005*) cat "$GH_CLOSURE_EVIDENCE" ;;
  *) echo "unexpected fake gh invocation: $*" >&2; exit 97 ;;
esac
`)
  await chmod(gh, 0o755)
  const env = {
    GH_TOKEN: 'test-live-token',
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    PATH: `${bin}:${process.env.PATH || ''}`,
    GH_CHILD_RUN: childRun,
    GH_PARENT_RUN_VIEW: parentRunView,
    GH_PARENT_RUN_REST: parentRunRest,
    GH_IMAGE_AUTHORITY_ARCHIVE: imageAuthorityArchive,
    GH_IMAGE_AUTHORITY_METADATA: imageAuthorityMetadata,
    GH_ARTIFACT_ARCHIVE: artifactArchive,
    GH_ARTIFACT_METADATA: artifactMetadata,
    GH_RELEASE_JSON: release,
    GH_TAG_REF: tagRef,
    GH_TAG_OBJECT: tagObject,
    GH_RELEASE_ASSETS: assets,
    GH_RELEASE_EVIDENCE: assetSources[1001],
    GH_IMAGE_EVIDENCE: assetSources[1002],
    GH_STARTOS_PACKAGE: assetSources[1003],
    GH_STARTOS_EVIDENCE: assetSources[1004],
    GH_CLOSURE_EVIDENCE: assetSources[1005]
  }
  const accepted = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    env
  )

  const inProgressParent = path.join(root, 'in-progress-parent.json')
  await writeFile(inProgressParent, JSON.stringify(startosParentRun({
    databaseId: 700,
    url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/700'
  })) + '\n')
  const unboundedInProgress = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github', '--allow-in-progress-parent'],
    { ...env, GH_PARENT_RUN_VIEW: inProgressParent }
  )
  t.is(unboundedInProgress.status, 1)
  t.ok(unboundedInProgress.stderr.includes('restricted to the exact in-parent closure job'))
  const boundedInProgress = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github', '--allow-in-progress-parent'],
    {
      ...env,
      GH_PARENT_RUN_VIEW: inProgressParent,
      GITHUB_ACTIONS: 'true',
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
      GITHUB_WORKFLOW: 'Release surfaces',
      GITHUB_WORKFLOW_REF: `bigdestiny2/P2P-Hiverelay/.github/workflows/release-surfaces.yml@refs/tags/${TAG}`,
      GITHUB_JOB: 'publish-startos-04-closure',
      GITHUB_RUN_ID: '700',
      GITHUB_RUN_ATTEMPT: '3',
      GITHUB_REF: `refs/tags/${TAG}`,
      GITHUB_SHA: TAG_SHA
    }
  )
  t.is(boundedInProgress.status, 0, boundedInProgress.stderr)

  const stablePolicy = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github', '--expected-prerelease', 'false'],
    env
  )
  t.is(stablePolicy.status, 1)
  t.ok(stablePolicy.stderr.includes('does not match requested closure policy prerelease=false'))

  const wrongPrereleaseRelease = path.join(root, 'wrong-prerelease-release.json')
  await writeFile(wrongPrereleaseRelease, JSON.stringify({
    id: 777,
    tag_name: TAG,
    draft: false,
    prerelease: false,
    url: 'https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/releases/777',
    html_url: `https://github.com/bigdestiny2/P2P-Hiverelay/releases/tag/${TAG}`
  }) + '\n')
  const wrongPrerelease = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_RELEASE_JSON: wrongPrereleaseRelease }
  )
  t.is(wrongPrerelease.status, 1)
  t.ok(wrongPrerelease.stderr.includes('prerelease=true policy'))

  const timedOut = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    {
      ...env,
      GH_TEST_HANG: '1',
      HIVERELAY_LIVE_VERIFY_COMMAND_TIMEOUT_MS: '50'
    }
  )
  t.is(timedOut.status, 1)
  t.ok(timedOut.stderr.includes('ETIMEDOUT'))

  const substitutedArchive = path.join(root, 'substituted-artifact.zip')
  await writeFile(substitutedArchive, 'not the REST digest-bound child artifact')
  const substituted = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_ARTIFACT_ARCHIVE: substitutedArchive }
  )
  t.is(substituted.status, 1)
  t.ok(substituted.stderr.includes('artifact ZIP size') || substituted.stderr.includes('artifact ZIP digest'))

  const substitutedAuthorityArchive = path.join(root, 'substituted-image-authority.zip')
  await writeFile(substitutedAuthorityArchive, 'not the parent REST digest-bound image authority')
  const substitutedAuthority = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_IMAGE_AUTHORITY_ARCHIVE: substitutedAuthorityArchive }
  )
  t.is(substitutedAuthority.status, 1)
  t.ok(substitutedAuthority.stderr.includes('image-authority ZIP size') || substitutedAuthority.stderr.includes('image-authority ZIP digest'))

  const failedParent = path.join(root, 'failed-parent.json')
  await writeFile(failedParent, JSON.stringify(startosParentRun({
    databaseId: 700,
    url: 'https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/700',
    status: 'completed',
    conclusion: 'failure'
  })) + '\n')
  const terminalFailure = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_PARENT_RUN_VIEW: failedParent }
  )
  t.is(terminalFailure.status, 1)
  t.ok(terminalFailure.stderr.includes('completed run conclusion'))

  const wrongRun = path.join(root, 'wrong-run.json')
  await writeFile(wrongRun, JSON.stringify({ ...successfulStartosChildRun(), head_sha: 'f'.repeat(40) }) + '\n')
  const replayed = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_CHILD_RUN: wrongRun }
  )
  t.is(replayed.status, 1)
  t.ok(replayed.stderr.includes('child head SHA'))

  const movedTag = path.join(root, 'moved-tag-ref.json')
  await writeFile(movedTag, JSON.stringify({
    ref: `refs/tags/${TAG}`,
    object: { type: 'commit', sha: 'f'.repeat(40) }
  }) + '\n')
  const moved = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    { ...env, GH_TAG_REF: movedTag }
  )
  t.is(moved.status, 1)
  t.ok(moved.stderr.includes('not release source'))

  const swappedAssets = path.join(root, 'swapped-assets.json')
  const swappedRecords = records.map(record => record.name === PACKAGE_NAME
    ? {
        ...record,
        id: 2003,
        url: 'https://api.github.com/repos/bigdestiny2/P2P-Hiverelay/releases/assets/2003'
      }
    : record)
  await writeFile(swappedAssets, JSON.stringify([swappedRecords]) + '\n')
  const changedInventory = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    {
      ...env,
      GH_RELEASE_ASSETS_AFTER: swappedAssets,
      GH_RELEASE_ASSETS_MARKER: path.join(root, 'inventory-swapped')
    }
  )
  t.is(changedInventory.status, 1)
  t.ok(changedInventory.stderr.includes('asset inventory changed during live closure verification'))

  const expiredArtifact = path.join(root, 'expired-artifact.json')
  const currentArtifact = JSON.parse(await readFile(artifactMetadata, 'utf8'))
  await writeFile(expiredArtifact, JSON.stringify({ ...currentArtifact, expired: true }) + '\n')
  const changedArtifact = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    {
      ...env,
      GH_ARTIFACT_METADATA_AFTER: expiredArtifact,
      GH_ARTIFACT_METADATA_MARKER: path.join(root, 'artifact-expired')
    }
  )
  t.is(changedArtifact.status, 1)
  t.ok(changedArtifact.stderr.includes('not be expired'))

  const expiredImageAuthority = path.join(root, 'expired-image-authority.json')
  const currentImageAuthority = JSON.parse(await readFile(imageAuthorityMetadata, 'utf8'))
  await writeFile(expiredImageAuthority, JSON.stringify({ ...currentImageAuthority, expired: true }) + '\n')
  const changedImageAuthority = await run(
    'scripts/verify-release-closure-evidence.mjs',
    ['--bundle-dir', bundleDir, '--live-github'],
    {
      ...env,
      GH_IMAGE_AUTHORITY_METADATA_AFTER: expiredImageAuthority,
      GH_IMAGE_AUTHORITY_METADATA_MARKER: path.join(root, 'image-authority-expired')
    }
  )
  t.is(changedImageAuthority.status, 1)
  t.ok(changedImageAuthority.stderr.includes('artifact expired'))

  return accepted
}

function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function run (script, args, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [path.join(ROOT, script), ...args], {
      cwd: ROOT,
      env: { ...process.env, ...env }
    }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
  })
}

function exec (command, args, env = {}) {
  return new Promise((resolve) => {
    execFile(command, args, { cwd: ROOT, env: { ...process.env, ...env } }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
  })
}

function execShellScript (script, env) {
  return new Promise((resolve) => {
    execFile('/bin/bash', ['-c', script], { cwd: ROOT, env, timeout: 10000 }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
  })
}

async function workflowRunBlock (workflowFile, stepName) {
  const workflow = await readFile(path.join(ROOT, workflowFile), 'utf8')
  const start = workflow.indexOf(`      - name: ${stepName}`)
  const next = workflow.indexOf('\n      - name:', start + 1)
  const step = workflow.slice(start, next)
  const marker = '        run: |\n'
  const runStart = step.indexOf(marker)
  if (start < 0 || next < 0 || runStart < 0) throw new Error(`${stepName} run block is missing`)
  const lines = step.slice(runStart + marker.length).split('\n')
  const boundary = lines.findIndex(line => line !== '' && !line.startsWith('          '))
  return lines.slice(0, boundary < 0 ? undefined : boundary).join('\n').replace(/^ {10}/gm, '') + '\n'
}

async function fileExists (file) {
  try {
    await stat(file)
    return true
  } catch {
    return false
  }
}

function runWithInput (script, args, input) {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [path.join(ROOT, script), ...args], { cwd: ROOT }, (err, stdout, stderr) => {
      resolve({ status: err && typeof err.code === 'number' ? err.code : 0, stdout, stderr })
    })
    child.stdin.end(input)
  })
}
