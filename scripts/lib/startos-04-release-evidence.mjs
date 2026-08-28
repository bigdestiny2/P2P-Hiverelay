import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import {
  RELEASE_CLOSURE_EVIDENCE,
  RELEASE_CLOSURE_PENDING,
  RELEASE_SYNC_SUCCESS_PENDING_CLOSURE,
  RELEASE_SYNC_WORKFLOW_SCOPE
} from './release-evidence-contract.mjs'

export const STARTOS_04_RELEASE_ASSET = 'blindspark-startos-0.4.s9pk'
export const STARTOS_04_RELEASE_EVIDENCE = 'startos-0.4-release-evidence.json'
export const STARTOS_04_AUTHORING_MANIFEST_ARTIFACT = 'startos-0.4-authoring-manifest.json'
export const STARTOS_04_JAVASCRIPT_BUNDLE_ARTIFACT = 'startos-0.4-javascript-index.js'
export const STARTOS_04_PACKAGE_ID = 'blindspark'
export const STARTOS_04_CHECKOUT_ACTION_SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1'
export const STARTOS_04_START_CLI_VERSION = '1.1.0'
export const STARTOS_04_START_CLI_URL = 'https://github.com/Start9Labs/start-technologies/releases/download/start-cli%2Fv1.1.0/start-cli_x86_64-linux'
export const STARTOS_04_START_CLI_SHA256 = '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'
export const STARTOS_04_START_SDK_VERSION = '2.0.1'
export const STARTOS_04_START_SDK_INTEGRITY = 'sha512-h0CBfS501KpQ0FX3GoYhxyt1mZYRYgvIYBygWek1kZ7Yl1LHi2uUMzp00Jln38HhB9cJWya3AM9zlGqR91uRdw=='
export const STARTOS_04_OS_VERSION = '0.4.0-beta.10'
export const STARTOS_04_CHILD_ARTIFACT_ACTION_SHA = '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'

const EXPECTED_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const REQUIRED_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])
const IMAGE_INDEX_MEDIA_TYPES = new Set([
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.index.v1+json'
])
const IMAGE_MANIFEST_MEDIA_TYPES = new Set([
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.oci.image.manifest.v1+json'
])
const TAG_PATTERN = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const SHA_PATTERN = /^[a-f0-9]{40}$/
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const RUN_ID_PATTERN = /^[1-9][0-9]*$/
const ACCEPTED_RELEASE_EVENTS = new Set(['push', 'release', 'workflow_dispatch'])
const REUSABLE_RELEASE_CHECKPOINT_STEPS = Object.freeze([
  'Sign release image (cosign keyless)',
  'Verify release image manifest platforms',
  'Smoke pushed release image',
  'Write release evidence',
  'Verify release evidence'
])
const STARTOS_04_PARENT_CHECKPOINT_STEPS = Object.freeze([
  ...REUSABLE_RELEASE_CHECKPOINT_STEPS,
  'Upload immutable reusable image authority',
  'Upload exact StartOS image authority'
])
const MAX_JSON_BYTES = 2 * 1024 * 1024
const MAX_REUSABLE_IMAGE_ARTIFACT_BYTES = 16 * 1024 * 1024
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
const MAX_JAVASCRIPT_BUNDLE_BYTES = 64 * 1024 * 1024
const MAX_COMMITMENT_BYTES = 4096
const MAX_PACKAGE_MANIFEST_BYTES = 2 * 1024 * 1024
const MAX_ACTIONS_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
const STARTOS_04_MANIFEST_SET_PATHS = Object.freeze([
  'hardwareRequirements.arch',
  'hardwareRequirements.device.*.capabilities',
  'images.*.arch',
  'plugins',
  'satisfies',
  'volumes'
])

export function resolveStartos04ReleaseBinding ({
  repoRoot,
  tag,
  tagSha,
  releaseSurfacesRunId,
  expectedReleaseSurfacesRunAttempt,
  releaseEvidencePath,
  imageManifestEvidencePath
}) {
  requirePattern('release tag', tag, TAG_PATTERN)
  requirePattern('release tag SHA', tagSha, SHA_PATTERN)
  requirePattern('release-surfaces run id', releaseSurfacesRunId, RUN_ID_PATTERN)

  const rootPackage = readJson(path.join(repoRoot, 'package.json'), 'root package manifest')
  requireEqual('release tag matches package.json version', tag, `v${rootPackage.version}`)
  const startosPackage = readJson(
    path.join(repoRoot, 'startos-0.4', 'package.json'),
    'StartOS 0.4 package manifest'
  )
  requireEqual(
    'StartOS 0.4 source SDK dependency',
    startosPackage.dependencies?.['@start9labs/start-sdk'],
    STARTOS_04_START_SDK_VERSION
  )
  const startosLock = readJson(
    path.join(repoRoot, 'startos-0.4', 'package-lock.json'),
    'StartOS 0.4 package lock'
  )
  requireEqual('StartOS 0.4 lockfile root name', startosLock.packages?.['']?.name, startosPackage.name)
  requireEqual(
    'StartOS 0.4 lockfile root SDK dependency',
    startosLock.packages?.['']?.dependencies?.['@start9labs/start-sdk'],
    STARTOS_04_START_SDK_VERSION
  )
  const lockedSdk = startosLock.packages?.['node_modules/@start9labs/start-sdk']
  requireEqual('StartOS 0.4 locked SDK version', lockedSdk?.version, STARTOS_04_START_SDK_VERSION)
  requireEqual(
    'StartOS 0.4 locked SDK source',
    lockedSdk?.resolved,
    `https://registry.npmjs.org/@start9labs/start-sdk/-/start-sdk-${STARTOS_04_START_SDK_VERSION}.tgz`
  )
  requireEqual('StartOS 0.4 locked SDK integrity', lockedSdk?.integrity, STARTOS_04_START_SDK_INTEGRITY)
  const packageVersionSource = readRegularFile(
    path.join(repoRoot, 'startos-0.4', 'startos', 'versions', 'current.ts'),
    'StartOS 0.4 authored version',
    MAX_JSON_BYTES
  ).toString('utf8')
  const packageVersion = /version:\s*'([^']+)'/.exec(packageVersionSource)?.[1]
  const escapedSemver = tag.slice(1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  requirePattern('StartOS 0.4 authored package version', packageVersion, new RegExp(`^${escapedSemver}:[0-9]+$`))

  const releaseEvidence = readJson(releaseEvidencePath, 'release evidence')
  requireEqual('release evidence schemaVersion', releaseEvidence.schemaVersion, 1)
  requireEqual('release evidence version', releaseEvidence.release?.version, tag)
  requireEqual('release evidence semver', releaseEvidence.release?.semver, tag.slice(1))
  requireEqual('release evidence candidate status', releaseEvidence.release?.candidate, false)
  requireEqual('release evidence tag SHA', releaseEvidence.release?.tagSha, tagSha)
  requireEqual('release evidence workflow scope', releaseEvidence.release?.workflow?.scope, RELEASE_SYNC_WORKFLOW_SCOPE)
  requireEqual('release evidence workflow status', releaseEvidence.release?.workflow?.status, RELEASE_SYNC_SUCCESS_PENDING_CLOSURE)
  requireEqual('release evidence closure status', releaseEvidence.release?.closure?.status, RELEASE_CLOSURE_PENDING)
  requireEqual('release evidence closure path', releaseEvidence.release?.closure?.evidence, RELEASE_CLOSURE_EVIDENCE)
  requireEqual('release evidence repository', releaseEvidence.release?.workflow?.repository, EXPECTED_REPOSITORY)
  requireEqual('release evidence source run id', String(releaseEvidence.release?.workflow?.runId || ''), releaseSurfacesRunId)
  const releaseSurfacesRunAttempt = String(releaseEvidence.release?.workflow?.runAttempt || '')
  requirePattern('release evidence source run attempt', releaseSurfacesRunAttempt, RUN_ID_PATTERN)
  if (expectedReleaseSurfacesRunAttempt !== undefined) {
    requirePattern('expected release-surfaces run attempt', expectedReleaseSurfacesRunAttempt, RUN_ID_PATTERN)
    requireEqual(
      'release evidence source run attempt',
      releaseSurfacesRunAttempt,
      expectedReleaseSurfacesRunAttempt
    )
  }
  requireEqual(
    'release evidence source run URL',
    releaseEvidence.release?.workflow?.runUrl,
    `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${releaseSurfacesRunId}`
  )
  requireEqual('release image name', releaseEvidence.image?.name, EXPECTED_IMAGE_NAME)
  requirePattern('release image digest', releaseEvidence.image?.digest, DIGEST_PATTERN)
  const imageRef = `${EXPECTED_IMAGE_NAME}:${tag.slice(1)}@${releaseEvidence.image.digest}`
  requireEqual('release image ref', releaseEvidence.image?.ref, imageRef)
  requireEqual('release image manifest gate', releaseEvidence.gates?.imageManifest, 'passed')
  requireEqual('release image smoke gate', releaseEvidence.gates?.pushedImageSmoke, 'passed')
  requireEqual('legacy StartOS verification gate', releaseEvidence.gates?.startosVerify, 'passed')
  requireEqual('legacy StartOS release asset status', releaseEvidence.surfaces?.startosReleaseAsset, 'uploaded')
  requireEqual(
    'release image manifest evidence path',
    releaseEvidence.gates?.imageManifestEvidence?.path,
    'release-image-manifest-evidence.json'
  )
  requirePattern(
    'release image manifest evidence SHA-256',
    releaseEvidence.gates?.imageManifestEvidence?.sha256,
    SHA256_PATTERN
  )
  requireEqual(
    'release image manifest evidence SHA-256',
    sha256File(imageManifestEvidencePath, 'release image manifest evidence', MAX_JSON_BYTES),
    releaseEvidence.gates.imageManifestEvidence.sha256
  )

  const imageManifest = readJson(imageManifestEvidencePath, 'release image manifest evidence')
  requireEqual('image manifest schemaVersion', imageManifest.schemaVersion, 1)
  requireEqual('image manifest kind', imageManifest.kind, 'release-image-manifest')
  requireEqual('image manifest status', imageManifest.status, 'verified')
  requireEqual('image manifest image name', imageManifest.image?.name, EXPECTED_IMAGE_NAME)
  requireEqual('image manifest image tag', imageManifest.image?.tag, tag.slice(1))
  requireEqual('image manifest image digest', imageManifest.image?.digest, releaseEvidence.image.digest)
  requireEqual('image manifest image ref', imageManifest.image?.ref, imageRef)
  requireArrayEqual('image manifest required platforms', imageManifest.requiredPlatforms, REQUIRED_PLATFORMS)
  if (!IMAGE_INDEX_MEDIA_TYPES.has(imageManifest.manifest?.mediaType)) {
    fail(`image manifest media type must be a multi-arch index; got ${JSON.stringify(imageManifest.manifest?.mediaType)}`)
  }
  const platforms = Array.isArray(imageManifest.platforms) ? imageManifest.platforms : []
  const labels = new Set()
  const requiredPlatformEntries = new Map()
  for (const platform of platforms) {
    const label = `${platform?.os || ''}/${platform?.architecture || ''}`
    if (labels.has(label)) fail(`image manifest has duplicate platform ${label}`)
    labels.add(label)
    requirePattern(`image manifest platform ${label} digest`, platform?.digest, DIGEST_PATTERN)
    if (REQUIRED_PLATFORMS.includes(label)) {
      requiredPlatformEntries.set(label, {
        os: platform.os,
        architecture: platform.architecture,
        digest: platform.digest,
        revision: tagSha
      })
    }
  }
  for (const required of REQUIRED_PLATFORMS) {
    if (!labels.has(required)) fail(`image manifest is missing required platform ${required}`)
  }

  return {
    repository: EXPECTED_REPOSITORY,
    tag,
    tagSha,
    semver: tag.slice(1),
    packageVersion,
    releaseSurfacesRunId,
    releaseSurfacesRunAttempt,
    releaseSurfacesRunUrl: releaseEvidence.release.workflow.runUrl,
    imageName: EXPECTED_IMAGE_NAME,
    imageDigest: releaseEvidence.image.digest,
    imageRef,
    requiredPlatforms: [...REQUIRED_PLATFORMS],
    platforms: REQUIRED_PLATFORMS.map(label => requiredPlatformEntries.get(label))
  }
}

// The StartOS child is awaited by the parent workflow. Authenticate the exact
// completed sync job and its immutable image-authority checkpoint while
// deliberately allowing the overall parent run to remain in progress.
export function verifyStartos04ParentRunAuthority ({
  run,
  expectedRunId,
  expectedRunAttempt,
  expectedRunUrl,
  expectedTag,
  expectedTagSha,
  requireTerminalSuccess = false
}) {
  requirePattern('StartOS parent run id', expectedRunId, RUN_ID_PATTERN)
  requirePattern('StartOS parent run attempt', expectedRunAttempt, RUN_ID_PATTERN)
  requireEqual(
    'StartOS parent run URL',
    expectedRunUrl,
    `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${expectedRunId}`
  )
  requirePattern('StartOS parent release tag', expectedTag, TAG_PATTERN)
  requirePattern('StartOS parent release tag SHA', expectedTagSha, SHA_PATTERN)
  requireEqual('StartOS parent run database id', String(run?.databaseId || ''), expectedRunId)
  requireEqual(
    'StartOS parent run attempt',
    String(run?.attempt ?? run?.run_attempt ?? run?.runAttempt ?? ''),
    expectedRunAttempt
  )
  requireExactRunUrl('StartOS parent run URL', run?.url, expectedRunUrl, expectedRunAttempt)
  requireEqual('StartOS parent workflow name', run?.workflowName, 'Release surfaces')
  requireTaggedWorkflowPath(
    'StartOS parent workflow path',
    run?.workflowPath ?? run?.path,
    '.github/workflows/release-surfaces.yml',
    expectedTag
  )
  if (!['in_progress', 'completed'].includes(run?.status)) {
    fail(`StartOS parent run status must be in_progress or completed; got ${JSON.stringify(run?.status)}`)
  }
  if (run.status === 'completed') {
    requireEqual('StartOS parent completed run conclusion', run?.conclusion, 'success')
  }
  if (requireTerminalSuccess) {
    requireEqual('StartOS parent terminal run status', run?.status, 'completed')
  }
  requireEqual('StartOS parent run head SHA', run?.headSha, expectedTagSha)
  requireEqual('StartOS parent run head ref', run?.headBranch, expectedTag)
  if (!ACCEPTED_RELEASE_EVENTS.has(run?.event)) {
    fail(`StartOS parent run event must be one of ${JSON.stringify([...ACCEPTED_RELEASE_EVENTS])}; got ${JSON.stringify(run?.event)}`)
  }
  const jobs = Array.isArray(run?.jobs) ? run.jobs : []
  const syncJobs = jobs.filter(job => job?.name === 'sync')
  requireEqual('StartOS parent sync job count', syncJobs.length, 1)
  const sync = syncJobs[0]
  requireEqual('StartOS parent sync job status', sync?.status, 'completed')
  requireEqual('StartOS parent sync job conclusion', sync?.conclusion, 'success')
  const steps = Array.isArray(sync?.steps) ? sync.steps : []
  for (const expectedStep of STARTOS_04_PARENT_CHECKPOINT_STEPS) {
    const matches = steps.filter(step => step?.name === expectedStep)
    requireEqual(`StartOS parent checkpoint step ${expectedStep} count`, matches.length, 1)
    requireEqual(`StartOS parent checkpoint step ${expectedStep} status`, matches[0]?.status, 'completed')
    requireEqual(`StartOS parent checkpoint step ${expectedStep} conclusion`, matches[0]?.conclusion, 'success')
  }
  return {
    runId: expectedRunId,
    runAttempt: expectedRunAttempt,
    runUrl: expectedRunUrl,
    tag: expectedTag,
    tagSha: expectedTagSha,
    event: run.event,
    runStatus: run.status,
    runConclusion: run.conclusion ?? '',
    syncConclusion: sync.conclusion
  }
}

export function selectStartos04ReleaseImageAuthorityArtifact ({
  response,
  expectedTag,
  expectedTagSha,
  expectedRunId,
  expectedRunAttempt,
  expectedArtifactId
}) {
  requirePattern('StartOS image authority tag', expectedTag, TAG_PATTERN)
  requirePattern('StartOS image authority tag SHA', expectedTagSha, SHA_PATTERN)
  requirePattern('StartOS image authority run id', expectedRunId, RUN_ID_PATTERN)
  requirePattern('StartOS image authority run attempt', expectedRunAttempt, RUN_ID_PATTERN)
  requirePattern('StartOS image authority expected artifact id', expectedArtifactId, RUN_ID_PATTERN)
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    fail('StartOS image authority artifact response must be an object')
  }
  const artifacts = response.artifacts
  const totalCount = response.total_count
  if (!Array.isArray(artifacts) || !Number.isSafeInteger(totalCount) || totalCount < 0) {
    fail('StartOS image authority artifact response has malformed artifacts or total_count')
  }
  if (totalCount !== artifacts.length) {
    fail(`StartOS image authority artifact response is incomplete: total_count=${totalCount}, returned=${artifacts.length}`)
  }
  const expectedName = `release-image-authority-${expectedTag}-${expectedRunId}-${expectedRunAttempt}`
  requireEqual('StartOS image authority artifact count', artifacts.length, 1)
  const artifact = artifacts[0]
  const hasRawShape = ['workflow_run', 'size_in_bytes', 'archive_download_url'].some(key => Object.hasOwn(artifact || {}, key))
  const hasNormalizedShape = [
    'sourceRunId',
    'sourceRunAttempt',
    'sourceHeadSha',
    'sourceHeadRef',
    'sizeInBytes',
    'archiveUrl'
  ].some(key => Object.hasOwn(artifact || {}, key))
  if (hasRawShape === hasNormalizedShape) {
    fail('StartOS image authority artifact must use exactly one complete raw REST or normalized shape')
  }
  const id = String(artifact?.id || '')
  const sourceRunId = String(hasRawShape ? artifact?.workflow_run?.id ?? '' : artifact?.sourceRunId ?? '')
  const sourceHeadSha = hasRawShape ? artifact?.workflow_run?.head_sha : artifact?.sourceHeadSha
  const sourceHeadRef = hasRawShape ? artifact?.workflow_run?.head_branch : artifact?.sourceHeadRef
  const sourceRunAttempt = String(hasRawShape ? expectedRunAttempt : artifact?.sourceRunAttempt ?? '')
  const size = hasRawShape ? artifact?.size_in_bytes : artifact?.sizeInBytes
  const archiveUrl = hasRawShape ? artifact?.archive_download_url : artifact?.archiveUrl
  requirePattern('StartOS image authority artifact id', id, RUN_ID_PATTERN)
  requireEqual('StartOS image authority artifact id', id, expectedArtifactId)
  requireEqual('StartOS image authority artifact name', artifact?.name, expectedName)
  requireEqual('StartOS image authority artifact expired', artifact?.expired, false)
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_REUSABLE_IMAGE_ARTIFACT_BYTES) {
    fail(`StartOS image authority artifact size must be between 1 and ${MAX_REUSABLE_IMAGE_ARTIFACT_BYTES} bytes`)
  }
  requirePattern('StartOS image authority artifact digest', artifact?.digest, DIGEST_PATTERN)
  requireEqual(
    'StartOS image authority artifact archive URL',
    archiveUrl,
    `https://api.github.com/repos/${EXPECTED_REPOSITORY}/actions/artifacts/${id}/zip`
  )
  requireEqual('StartOS image authority artifact source run id', sourceRunId, expectedRunId)
  requireEqual('StartOS image authority artifact source run attempt', sourceRunAttempt, expectedRunAttempt)
  requireEqual('StartOS image authority artifact source head SHA', sourceHeadSha, expectedTagSha)
  requireEqual('StartOS image authority artifact source head ref', sourceHeadRef, expectedTag)
  return {
    id,
    name: expectedName,
    digest: artifact.digest,
    sizeInBytes: size,
    archiveUrl,
    sourceRunId,
    sourceRunAttempt,
    sourceHeadRef,
    sourceHeadSha,
    expired: false
  }
}

export function verifyReusableReleaseRunAuthority ({
  run,
  expectedRunId,
  expectedRunAttempt,
  expectedRunUrl,
  expectedTag,
  expectedTagSha
}) {
  requirePattern('reusable release run id', expectedRunId, RUN_ID_PATTERN)
  requirePattern('reusable release run attempt', expectedRunAttempt, RUN_ID_PATTERN)
  requireEqual(
    'reusable release run URL',
    expectedRunUrl,
    `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${expectedRunId}`
  )
  requirePattern('reusable release tag', expectedTag, TAG_PATTERN)
  requirePattern('reusable release tag SHA', expectedTagSha, SHA_PATTERN)
  requireEqual('reusable release run database id', String(run?.databaseId || ''), expectedRunId)
  requireEqual(
    'reusable release run attempt',
    String(run?.attempt ?? run?.run_attempt ?? run?.runAttempt ?? ''),
    expectedRunAttempt
  )
  requireExactRunUrl('reusable release run URL', run?.url, expectedRunUrl, expectedRunAttempt)
  requireEqual('reusable release workflow name', run?.workflowName, 'Release surfaces')
  requireTaggedWorkflowPath(
    'reusable release workflow path',
    run?.workflowPath ?? run?.path,
    '.github/workflows/release-surfaces.yml',
    expectedTag
  )
  requireEqual('reusable release run status', run?.status, 'completed')
  requireEqual('reusable release run head SHA', run?.headSha, expectedTagSha)
  requireEqual('reusable release run head ref', run?.headBranch, expectedTag)
  if (!ACCEPTED_RELEASE_EVENTS.has(run?.event)) {
    fail(`reusable release run event must be one of ${JSON.stringify([...ACCEPTED_RELEASE_EVENTS])}; got ${JSON.stringify(run?.event)}`)
  }
  const jobs = Array.isArray(run?.jobs) ? run.jobs : []
  const syncJobs = jobs.filter(job => job?.name === 'sync')
  requireEqual('reusable release sync job count', syncJobs.length, 1)
  requireEqual('reusable release sync job status', syncJobs[0]?.status, 'completed')
  const steps = Array.isArray(syncJobs[0]?.steps) ? syncJobs[0].steps : []
  for (const expectedStep of REUSABLE_RELEASE_CHECKPOINT_STEPS) {
    const matches = steps.filter(step => step?.name === expectedStep)
    requireEqual(`reusable release checkpoint step ${expectedStep} count`, matches.length, 1)
    requireEqual(`reusable release checkpoint step ${expectedStep} status`, matches[0]?.status, 'completed')
    requireEqual(`reusable release checkpoint step ${expectedStep} conclusion`, matches[0]?.conclusion, 'success')
  }
  return {
    runId: expectedRunId,
    runAttempt: expectedRunAttempt,
    runUrl: expectedRunUrl,
    tag: expectedTag,
    tagSha: expectedTagSha,
    event: run.event,
    syncConclusion: syncJobs[0]?.conclusion
  }
}

export function selectReusableReleaseImageArtifact ({ response, expectedTag, expectedTagSha }) {
  requirePattern('reusable release artifact tag', expectedTag, TAG_PATTERN)
  requirePattern('reusable release artifact tag SHA', expectedTagSha, SHA_PATTERN)
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    fail('reusable release artifact response must be an object')
  }
  const artifacts = response.artifacts
  const totalCount = response.total_count
  if (!Array.isArray(artifacts) || !Number.isSafeInteger(totalCount) || totalCount < 0) {
    fail('reusable release artifact response has malformed artifacts or total_count')
  }
  if (totalCount !== artifacts.length) {
    fail(`reusable release artifact response is incomplete: total_count=${totalCount}, returned=${artifacts.length}`)
  }

  const expectedName = `release-image-authority-${expectedTag}`
  const eligible = artifacts.filter(artifact => {
    const workflowRun = artifact?.workflow_run
    return artifact?.name === expectedName &&
      artifact?.expired === false &&
      workflowRun?.head_sha === expectedTagSha &&
      workflowRun?.head_branch === expectedTag
  })
  if (eligible.length === 0) return { found: false, name: expectedName }

  const validated = eligible.map(artifact => {
    const id = String(artifact?.id || '')
    const sourceRunId = String(artifact?.workflow_run?.id || '')
    const size = artifact?.size_in_bytes
    requirePattern('reusable release artifact id', id, RUN_ID_PATTERN)
    requirePattern('reusable release artifact source run id', sourceRunId, RUN_ID_PATTERN)
    if (!Number.isSafeInteger(size) || size < 1 || size > MAX_REUSABLE_IMAGE_ARTIFACT_BYTES) {
      fail(`reusable release artifact size must be between 1 and ${MAX_REUSABLE_IMAGE_ARTIFACT_BYTES} bytes`)
    }
    requirePattern('reusable release artifact digest', artifact?.digest, DIGEST_PATTERN)
    requireEqual(
      'reusable release artifact archive URL',
      artifact?.archive_download_url,
      `https://api.github.com/repos/${EXPECTED_REPOSITORY}/actions/artifacts/${id}/zip`
    )
    return {
      found: true,
      id,
      name: expectedName,
      digest: artifact.digest,
      sizeInBytes: size,
      archiveUrl: artifact.archive_download_url,
      sourceRunId,
      sourceHeadRef: artifact.workflow_run.head_branch,
      sourceHeadSha: artifact.workflow_run.head_sha
    }
  })
  validated.sort((a, b) => {
    const left = BigInt(a.id)
    const right = BigInt(b.id)
    return left < right ? 1 : left > right ? -1 : 0
  })
  return validated[0]
}

export function resolveReusableStartos04ReleaseBinding ({
  repoRoot,
  tag,
  tagSha,
  releaseEvidencePath,
  imageManifestEvidencePath
}) {
  const releaseEvidence = readJson(releaseEvidencePath, 'reusable release evidence')
  const releaseSurfacesRunId = String(releaseEvidence.release?.workflow?.runId || '')
  requirePattern('reusable release-surfaces run id', releaseSurfacesRunId, RUN_ID_PATTERN)
  return resolveStartos04ReleaseBinding({
    repoRoot,
    tag,
    tagSha,
    releaseSurfacesRunId,
    releaseEvidencePath,
    imageManifestEvidencePath
  })
}

export function readPackageCommitment (commitmentPath) {
  const value = readRegularFile(commitmentPath, 'StartOS package commitment', MAX_COMMITMENT_BYTES).toString('utf8').trim()
  return normalizePackageCommitment(value)
}

export function verifyStartos04ImageIndex ({ raw, expectedDigest, expectedAmd64Digest, expectedArm64Digest }) {
  requirePattern('release image index digest', expectedDigest, DIGEST_PATTERN)
  requirePattern('release image amd64 child digest', expectedAmd64Digest, DIGEST_PATTERN)
  requirePattern('release image arm64 child digest', expectedArm64Digest, DIGEST_PATTERN)
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > MAX_JSON_BYTES) {
    fail(`release image raw index must be between 1 and ${MAX_JSON_BYTES} bytes`)
  }
  requireEqual('release image raw index digest', `sha256:${sha256(raw)}`, expectedDigest)
  let index
  try {
    index = JSON.parse(raw.toString('utf8'))
  } catch (err) {
    fail(`release image raw index must be JSON: ${err.message}`)
  }
  if (!IMAGE_INDEX_MEDIA_TYPES.has(index?.mediaType)) {
    fail(`release image raw index media type must be multi-arch; got ${JSON.stringify(index?.mediaType)}`)
  }
  if (!Array.isArray(index.manifests) || index.manifests.length === 0) {
    fail('release image raw index must include manifests')
  }
  const required = new Map([
    ['linux/amd64', expectedAmd64Digest],
    ['linux/arm64', expectedArm64Digest]
  ])
  const observed = new Map()
  for (const entry of index.manifests) {
    if (entry?.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest') {
      const label = `${entry?.platform?.os || ''}/${entry?.platform?.architecture || ''}`
      requireEqual('release image attestation platform', label, 'unknown/unknown')
      if (!IMAGE_MANIFEST_MEDIA_TYPES.has(entry?.mediaType)) {
        fail(`release image attestation media type is unsupported: ${JSON.stringify(entry?.mediaType)}`)
      }
      requirePattern('release image attestation digest', entry?.digest, DIGEST_PATTERN)
      const subject = entry?.annotations?.['vnd.docker.reference.digest']
      requirePattern('release image attestation subject digest', subject, DIGEST_PATTERN)
      if (![expectedAmd64Digest, expectedArm64Digest].includes(subject)) {
        fail(`release image attestation subject digest is not a required platform child: ${JSON.stringify(subject)}`)
      }
      continue
    }
    const label = `${entry?.platform?.os || ''}/${entry?.platform?.architecture || ''}`
    if (!required.has(label)) fail(`release image raw index has unexpected runnable platform ${label}`)
    if (observed.has(label)) fail(`release image raw index has duplicate platform ${label}`)
    if (!IMAGE_MANIFEST_MEDIA_TYPES.has(entry?.mediaType)) {
      fail(`release image raw index ${label} media type is unsupported: ${JSON.stringify(entry?.mediaType)}`)
    }
    requirePattern(`release image raw index ${label} digest`, entry?.digest, DIGEST_PATTERN)
    observed.set(label, entry.digest)
  }
  for (const [label, expected] of required) {
    requireEqual(`release image raw index ${label} child digest`, observed.get(label), expected)
  }
  return {
    digest: expectedDigest,
    platforms: Object.fromEntries(observed)
  }
}

function normalizePackageCommitment (value) {
  if (typeof value !== 'string') {
    fail(`StartOS package commitment must be a string no larger than ${MAX_COMMITMENT_BYTES} bytes`)
  }
  if (!value) fail('StartOS package commitment must not be empty')
  if (Buffer.byteLength(value, 'utf8') > MAX_COMMITMENT_BYTES) {
    fail(`StartOS package commitment must be a string no larger than ${MAX_COMMITMENT_BYTES} bytes`)
  }
  if (value.includes('\r') || value.includes(String.fromCharCode(27)) || value.includes(String.fromCharCode(0))) {
    fail('StartOS package commitment contains unsupported control bytes')
  }
  return {
    output: value,
    sha256: sha256(Buffer.from(`${value}\n`))
  }
}

export function verifyStartos04ImageRevision ({ image, expectedOs, expectedArchitecture, expectedRevision }) {
  requirePattern('expected image OS', expectedOs, /^[a-z0-9._-]{1,32}$/)
  requirePattern('expected image architecture', expectedArchitecture, /^[a-z0-9._-]{1,32}$/)
  requirePattern('expected image revision', expectedRevision, SHA_PATTERN)
  requireEqual('release image child OS', image?.os, expectedOs)
  requireEqual('release image child architecture', image?.architecture, expectedArchitecture)
  requireEqual(
    'release image child org.opencontainers.image.revision label',
    image?.config?.Labels?.['org.opencontainers.image.revision'],
    expectedRevision
  )
}

export function verifyStartos04AuthoringManifest ({
  manifest,
  expectedTag,
  expectedReleaseSha,
  expectedPackageVersion,
  expectedImageRef
}) {
  const { image, architectures } = verifyStartos04ManifestIdentity({
    manifest,
    expectedTag,
    expectedReleaseSha,
    expectedPackageVersion
  })
  requireEqual('StartOS 0.4 authoring manifest gitHash', manifest.gitHash, null)
  const source = image?.source
  if (!isPlainObject(source)) fail('StartOS 0.4 authoring runtime image source must be an object')
  requireArrayEqual('StartOS 0.4 authoring runtime image source fields', Object.keys(source).sort(), ['dockerTag'])
  requireEqual('StartOS 0.4 authoring runtime image ref', source.dockerTag, expectedImageRef)
  return {
    id: manifest.id,
    version: manifest.version,
    gitHash: null,
    osVersion: STARTOS_04_OS_VERSION,
    sdkVersion: STARTOS_04_START_SDK_VERSION,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      source: 'dockerTag',
      ref: expectedImageRef,
      architectures,
      emulateMissingAs: 'x86_64',
      nvidiaContainer: false
    }
  }
}

export function verifyStartos04PackedManifest ({ manifest, expectedTag, expectedReleaseSha, expectedPackageVersion }) {
  const { image, architectures } = verifyStartos04ManifestIdentity({
    manifest,
    expectedTag,
    expectedReleaseSha,
    expectedPackageVersion
  })
  requireEqual('StartOS 0.4 packed manifest gitHash', manifest.gitHash, expectedReleaseSha)
  requireEqual('StartOS 0.4 packed runtime image source', image?.source, 'packed')
  return {
    id: manifest.id,
    version: manifest.version,
    gitHash: expectedReleaseSha,
    osVersion: STARTOS_04_OS_VERSION,
    sdkVersion: STARTOS_04_START_SDK_VERSION,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      source: 'packed',
      architectures,
      emulateMissingAs: 'x86_64',
      nvidiaContainer: false
    }
  }
}

export function verifyStartos04ManifestTransition ({
  authoringManifest,
  packedManifest,
  expectedTag,
  expectedReleaseSha,
  expectedPackageVersion,
  expectedImageRef
}) {
  const authoringIdentity = verifyStartos04AuthoringManifest({
    manifest: authoringManifest,
    expectedTag,
    expectedReleaseSha,
    expectedPackageVersion,
    expectedImageRef
  })
  const packedIdentity = verifyStartos04PackedManifest({
    manifest: packedManifest,
    expectedTag,
    expectedReleaseSha,
    expectedPackageVersion
  })
  const canonicalAuthoring = canonicalizeStartos04Manifest(
    authoringManifest,
    'StartOS 0.4 authoring manifest'
  )
  const canonicalPacked = canonicalizeStartos04Manifest(
    packedManifest,
    'StartOS 0.4 packed manifest'
  )
  const expectedPacked = canonicalizeJsonValue(
    canonicalAuthoring,
    'StartOS 0.4 expected packed manifest'
  )
  expectedPacked.gitHash = expectedReleaseSha
  for (const image of Object.values(expectedPacked.images)) image.source = 'packed'
  if (!isDeepStrictEqual(canonicalPacked, expectedPacked)) {
    fail(
      'StartOS 0.4 packed manifest differs from the full canonical authoring manifest outside the permitted gitHash and images.*.source transition'
    )
  }
  return {
    authoringIdentity,
    packedIdentity,
    manifestTransition: buildStartos04ManifestTransitionEvidence({
      authoringCanonicalSha256: sha256(Buffer.from(JSON.stringify(canonicalAuthoring))),
      packedCanonicalSha256: sha256(Buffer.from(JSON.stringify(canonicalPacked)))
    })
  }
}

function canonicalizeStartos04Manifest (manifest, label) {
  const canonical = canonicalizeJsonValue(manifest, label)
  if (!isPlainObject(canonical)) fail(`${label} must be an object`)
  canonical.volumes = canonicalizeStringSet(canonical.volumes, `${label} volumes`)
  canonical.plugins = canonicalizeStringSet(canonical.plugins, `${label} plugins`)
  canonical.satisfies = canonicalizeStringSet(canonical.satisfies, `${label} satisfies`)
  if (!isPlainObject(canonical.images)) fail(`${label} images must be an object`)
  for (const [imageId, image] of Object.entries(canonical.images)) {
    if (!isPlainObject(image)) fail(`${label} image ${JSON.stringify(imageId)} must be an object`)
    image.arch = canonicalizeStringSet(image.arch, `${label} image ${JSON.stringify(imageId)} arch`)
  }
  if (!isPlainObject(canonical.hardwareRequirements)) {
    fail(`${label} hardwareRequirements must be an object`)
  }
  const hardware = canonical.hardwareRequirements
  if (hardware.arch !== null) {
    hardware.arch = canonicalizeStringSet(hardware.arch, `${label} hardwareRequirements arch`)
  }
  if (!Array.isArray(hardware.device)) fail(`${label} hardwareRequirements device must be an array`)
  for (const [index, device] of hardware.device.entries()) {
    if (!isPlainObject(device)) {
      fail(`${label} hardwareRequirements device ${index} must be an object`)
    }
    if (device.capabilities !== undefined && device.capabilities !== null) {
      device.capabilities = canonicalizeStringSet(
        device.capabilities,
        `${label} hardwareRequirements device ${index} capabilities`
      )
    }
  }
  return canonical
}

function canonicalizeStringSet (value, label) {
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) {
    fail(`${label} must be an array of strings`)
  }
  return [...new Set(value)].sort()
}

function canonicalizeJsonValue (value, label) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(`${label} contains a non-finite number`)
    return value
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => canonicalizeJsonValue(item, `${label}[${index}]`))
  }
  if (!isPlainObject(value)) fail(`${label} contains a non-JSON value`)
  return Object.fromEntries(
    Object.keys(value).sort().map(key => [key, canonicalizeJsonValue(value[key], `${label}.${key}`)])
  )
}

function buildStartos04ManifestTransitionEvidence ({
  authoringCanonicalSha256,
  packedCanonicalSha256
}) {
  requirePattern(
    'StartOS 0.4 canonical authoring manifest SHA-256',
    authoringCanonicalSha256,
    SHA256_PATTERN
  )
  requirePattern(
    'StartOS 0.4 canonical packed manifest SHA-256',
    packedCanonicalSha256,
    SHA256_PATTERN
  )
  return {
    evidenceSemantics: 'exact-full-canonical-authoring-to-packed-transition',
    canonicalization: {
      jsonObjectKeys: 'lexicographically-sorted',
      setValuedArrays: STARTOS_04_MANIFEST_SET_PATHS
    },
    permittedMutations: [
      'gitHash:null-to-release-tag-sha',
      'images.*.source:digest-bound-dockerTag-to-packed'
    ],
    architectureFilter: 'none-direct-pack',
    authoringCanonicalSha256,
    packedCanonicalSha256
  }
}

function verifyStartos04ManifestIdentity ({ manifest, expectedTag, expectedReleaseSha, expectedPackageVersion }) {
  requirePattern('expected StartOS 0.4 release tag', expectedTag, TAG_PATTERN)
  requirePattern('expected StartOS 0.4 release SHA', expectedReleaseSha, SHA_PATTERN)
  requireEqual('StartOS 0.4 package id', manifest?.id, STARTOS_04_PACKAGE_ID)
  const semver = expectedTag.slice(1)
  const escapedSemver = semver.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  requirePattern('expected StartOS 0.4 package version', expectedPackageVersion, new RegExp(`^${escapedSemver}:[0-9]+$`))
  requireEqual('StartOS 0.4 package version', manifest?.version, expectedPackageVersion)
  requireEqual('StartOS 0.4 package OS version', manifest?.osVersion, STARTOS_04_OS_VERSION)
  requireEqual('StartOS 0.4 package SDK version', manifest?.sdkVersion, STARTOS_04_START_SDK_VERSION)
  const images = manifest?.images
  if (!isPlainObject(images)) fail('StartOS 0.4 package images must be an object')
  requireArrayEqual('StartOS 0.4 package image ids', Object.keys(images).sort(), [STARTOS_04_PACKAGE_ID])
  const image = images[STARTOS_04_PACKAGE_ID]
  if (!isPlainObject(image)) fail('StartOS 0.4 package runtime image config must be an object')
  requireArrayEqual(
    'StartOS 0.4 package runtime image config fields',
    Object.keys(image).sort(),
    ['arch', 'emulateMissingAs', 'nvidiaContainer', 'source']
  )
  const architectures = Array.isArray(image?.arch) ? [...image.arch].sort() : image?.arch
  requireArrayEqual('StartOS 0.4 package runtime image architectures', architectures, ['aarch64', 'x86_64'])
  requireEqual('StartOS 0.4 package runtime image emulation architecture', image?.emulateMissingAs, 'x86_64')
  requireEqual('StartOS 0.4 package runtime image NVIDIA container flag', image?.nvidiaContainer, false)
  return { image, architectures }
}

export function readStartos04AuthoringManifest ({
  manifestPath,
  expectedTag,
  expectedReleaseSha,
  expectedPackageVersion,
  expectedImageRef
}) {
  const manifest = readJson(manifestPath, 'StartOS 0.4 built authoring manifest', MAX_PACKAGE_MANIFEST_BYTES)
  return verifyStartos04AuthoringManifest({
    manifest,
    expectedTag,
    expectedReleaseSha,
    expectedPackageVersion,
    expectedImageRef
  })
}

export function readStartos04PackedManifest ({ manifestPath, expectedTag, expectedReleaseSha, expectedPackageVersion }) {
  const manifest = readJson(manifestPath, 'StartOS 0.4 inspected packed manifest', MAX_PACKAGE_MANIFEST_BYTES)
  return verifyStartos04PackedManifest({ manifest, expectedTag, expectedReleaseSha, expectedPackageVersion })
}

export function buildStartos04ReleaseEvidence ({
  binding,
  packagePath,
  commitmentPath,
  javascriptBundlePath,
  expectedJavascriptBundleSha256,
  authoringManifestPath,
  packedManifestPath
}) {
  const packageStat = regularFileStat(packagePath, 'StartOS 0.4 package')
  if (packageStat.size === 0 || packageStat.size > MAX_PACKAGE_BYTES) {
    fail(`StartOS 0.4 package size must be between 1 and ${MAX_PACKAGE_BYTES} bytes`)
  }
  if (path.basename(packagePath) !== STARTOS_04_RELEASE_ASSET) {
    fail(`StartOS 0.4 package filename must be ${STARTOS_04_RELEASE_ASSET}`)
  }
  const commitment = readPackageCommitment(commitmentPath)
  const javascriptBundleStat = regularFileStat(javascriptBundlePath, 'StartOS 0.4 built javascript bundle')
  if (javascriptBundleStat.size === 0 || javascriptBundleStat.size > MAX_JAVASCRIPT_BUNDLE_BYTES) {
    fail(`StartOS 0.4 built javascript bundle size must be between 1 and ${MAX_JAVASCRIPT_BUNDLE_BYTES} bytes`)
  }
  requirePattern(
    'expected verified StartOS 0.4 javascript bundle SHA-256',
    expectedJavascriptBundleSha256,
    SHA256_PATTERN
  )
  const javascriptBundleSha256 = sha256File(
    javascriptBundlePath,
    'StartOS 0.4 built javascript bundle',
    MAX_JAVASCRIPT_BUNDLE_BYTES
  )
  requireEqual(
    'StartOS 0.4 built javascript bundle SHA-256',
    javascriptBundleSha256,
    expectedJavascriptBundleSha256
  )
  const authoringManifestDocument = readJson(
    authoringManifestPath,
    'StartOS 0.4 built authoring manifest',
    MAX_PACKAGE_MANIFEST_BYTES
  )
  const packedManifestDocument = readJson(
    packedManifestPath,
    'StartOS 0.4 inspected packed manifest',
    MAX_PACKAGE_MANIFEST_BYTES
  )
  const transition = verifyStartos04ManifestTransition({
    authoringManifest: authoringManifestDocument,
    packedManifest: packedManifestDocument,
    expectedTag: binding.tag,
    expectedReleaseSha: binding.tagSha,
    expectedPackageVersion: binding.packageVersion,
    expectedImageRef: binding.imageRef
  })
  return buildStartos04ReleaseEvidenceBody({
    binding,
    packagePath,
    commitment,
    javascriptBundleSha256,
    authoringManifest: transition.authoringIdentity,
    packedManifest: transition.packedIdentity,
    manifestTransition: transition.manifestTransition
  })
}

function buildStartos04ReleaseEvidenceBody ({
  binding,
  packagePath,
  commitment,
  javascriptBundleSha256,
  authoringManifest,
  packedManifest,
  manifestTransition
}) {
  const releaseBase = `https://github.com/${binding.repository}/releases/download/${binding.tag}`
  return {
    schemaVersion: 2,
    kind: 'startos-0.4-release',
    status: 'verified',
    release: {
      version: binding.tag,
      tagSha: binding.tagSha
    },
    image: {
      name: binding.imageName,
      digest: binding.imageDigest,
      ref: binding.imageRef,
      requiredPlatforms: binding.requiredPlatforms,
      platforms: binding.platforms
    },
    toolchain: {
      evidenceSemantics: 'digest-bound-authoring-manifest-and-current-packed-inspection',
      artifactBuildProvenance: {
        status: 'build-input-ref-verified-but-not-embedded-in-packed-manifest',
        claim: 'the exact built javascript authoring manifest is checked under the release environment; start-cli intentionally replaces its registry source with packed after embedding image files'
      },
      buildContract: {
        javascriptBundle: {
          path: 'startos-0.4/javascript/index.js',
          artifactName: STARTOS_04_JAVASCRIPT_BUNDLE_ARTIFACT,
          sha256: javascriptBundleSha256
        },
        invariant: 'verified-identical-before-and-after-start-cli-pack'
      },
      sourceCheckoutAction: {
        ref: `actions/checkout@${STARTOS_04_CHECKOUT_ACTION_SHA}`,
        commit: STARTOS_04_CHECKOUT_ACTION_SHA,
        evidenceRole: 'workflow-source-checkout-contract'
      },
      startCli: {
        version: STARTOS_04_START_CLI_VERSION,
        sourceUrl: STARTOS_04_START_CLI_URL,
        sha256: STARTOS_04_START_CLI_SHA256,
        evidenceRole: 'fixed-url-hash-verified-workflow-build-and-current-inspection-contract'
      },
      startSdk: {
        version: STARTOS_04_START_SDK_VERSION,
        integrity: STARTOS_04_START_SDK_INTEGRITY,
        evidenceRole: 'source-lockfile-build-contract'
      }
    },
    artifact: {
      name: STARTOS_04_RELEASE_ASSET,
      format: 'startos-0.4',
      sha256: sha256File(packagePath, 'StartOS 0.4 package', MAX_PACKAGE_BYTES),
      commitment,
      manifests: {
        transition: manifestTransition,
        authoring: {
          artifactName: STARTOS_04_AUTHORING_MANIFEST_ARTIFACT,
          evidenceSemantics: 'same-built-javascript-module-under-digest-bound-release-environment',
          identity: authoringManifest
        },
        packed: {
          evidenceSemantics: 'post-pack-start-cli-1.1.0-inspection-with-embedded-image-source',
          identity: packedManifest
        }
      },
      signerIdentity: {
        status: 'not-exposed-by-start-cli-1.1.0',
        value: ''
      },
      url: `${releaseBase}/${STARTOS_04_RELEASE_ASSET}`
    },
    evidenceLinks: {
      release: `${releaseBase}/release-evidence.json`,
      imageManifest: `${releaseBase}/release-image-manifest-evidence.json`
    }
  }
}

export function verifyPublishedStartos04ReleaseAssets ({ evidencePath, binding, packagePath }) {
  const packageStat = regularFileStat(packagePath, 'published StartOS 0.4 package')
  if (packageStat.size === 0 || packageStat.size > MAX_PACKAGE_BYTES) {
    fail(`Published StartOS 0.4 package size must be between 1 and ${MAX_PACKAGE_BYTES} bytes`)
  }
  if (path.basename(packagePath) !== STARTOS_04_RELEASE_ASSET) {
    fail(`Published StartOS 0.4 package filename must be ${STARTOS_04_RELEASE_ASSET}`)
  }
  const actual = readJson(evidencePath, 'published StartOS 0.4 release evidence')
  const commitment = normalizePackageCommitment(actual?.artifact?.commitment?.output)
  requireEqual('published StartOS 0.4 commitment SHA-256', actual?.artifact?.commitment?.sha256, commitment.sha256)
  const javascriptBundleSha256 = actual?.toolchain?.buildContract?.javascriptBundle?.sha256
  requirePattern('published StartOS 0.4 javascript bundle SHA-256', javascriptBundleSha256, SHA256_PATTERN)
  const manifestTransition = buildStartos04ManifestTransitionEvidence({
    authoringCanonicalSha256: actual?.artifact?.manifests?.transition?.authoringCanonicalSha256,
    packedCanonicalSha256: actual?.artifact?.manifests?.transition?.packedCanonicalSha256
  })
  const authoringManifest = {
    id: STARTOS_04_PACKAGE_ID,
    version: binding.packageVersion,
    gitHash: null,
    osVersion: STARTOS_04_OS_VERSION,
    sdkVersion: STARTOS_04_START_SDK_VERSION,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      source: 'dockerTag',
      ref: binding.imageRef,
      architectures: ['aarch64', 'x86_64'],
      emulateMissingAs: 'x86_64',
      nvidiaContainer: false
    }
  }
  const packedManifest = {
    id: STARTOS_04_PACKAGE_ID,
    version: binding.packageVersion,
    gitHash: binding.tagSha,
    osVersion: STARTOS_04_OS_VERSION,
    sdkVersion: STARTOS_04_START_SDK_VERSION,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      source: 'packed',
      architectures: ['aarch64', 'x86_64'],
      emulateMissingAs: 'x86_64',
      nvidiaContainer: false
    }
  }
  const expected = buildStartos04ReleaseEvidenceBody({
    binding,
    packagePath,
    commitment,
    javascriptBundleSha256,
    authoringManifest,
    packedManifest,
    manifestTransition
  })
  if (!isDeepStrictEqual(actual, expected)) {
    fail('Published StartOS 0.4 assets do not match the exact source run, image, toolchain, manifest identity, commitment, and package bytes')
  }
  return actual
}

export function verifyStartos04ReleaseEvidence ({
  evidencePath,
  binding,
  packagePath,
  commitmentPath,
  javascriptBundlePath,
  expectedJavascriptBundleSha256,
  authoringManifestPath,
  packedManifestPath
}) {
  const actual = readJson(evidencePath, 'StartOS 0.4 release evidence')
  const expected = buildStartos04ReleaseEvidence({
    binding,
    packagePath,
    commitmentPath,
    javascriptBundlePath,
    expectedJavascriptBundleSha256,
    authoringManifestPath,
    packedManifestPath
  })
  if (!isDeepStrictEqual(actual, expected)) {
    fail('StartOS 0.4 release evidence does not match the exact tag, image, toolchain, manifest identity, commitment, and package bytes')
  }
  return actual
}

export function verifyStartos04ArtifactBuildInputs ({
  evidencePath,
  binding,
  packagePath,
  javascriptBundlePath,
  authoringManifestPath
}) {
  const evidence = verifyPublishedStartos04ReleaseAssets({ evidencePath, binding, packagePath })
  const javascriptBundleStat = regularFileStat(
    javascriptBundlePath,
    'immutable child StartOS 0.4 javascript bundle'
  )
  if (javascriptBundleStat.size === 0 || javascriptBundleStat.size > MAX_JAVASCRIPT_BUNDLE_BYTES) {
    fail(
      `Immutable child StartOS 0.4 javascript bundle size must be between 1 and ${MAX_JAVASCRIPT_BUNDLE_BYTES} bytes`
    )
  }
  const javascriptBundleSha256 = sha256File(
    javascriptBundlePath,
    'immutable child StartOS 0.4 javascript bundle',
    MAX_JAVASCRIPT_BUNDLE_BYTES
  )
  requireEqual(
    'immutable child StartOS 0.4 javascript bundle SHA-256',
    javascriptBundleSha256,
    evidence.toolchain.buildContract.javascriptBundle.sha256
  )
  const authoringManifestDocument = readJson(
    authoringManifestPath,
    'immutable child StartOS 0.4 authoring manifest',
    MAX_PACKAGE_MANIFEST_BYTES
  )
  const authoringManifest = verifyStartos04AuthoringManifest({
    manifest: authoringManifestDocument,
    expectedTag: binding.tag,
    expectedReleaseSha: binding.tagSha,
    expectedPackageVersion: binding.packageVersion,
    expectedImageRef: binding.imageRef
  })
  if (!isDeepStrictEqual(evidence.artifact.manifests?.authoring?.identity, authoringManifest)) {
    fail('Immutable child StartOS 0.4 authoring manifest does not match the published sidecar')
  }
  const authoringManifestCanonicalSha256 = sha256(Buffer.from(JSON.stringify(
    canonicalizeStartos04Manifest(
      authoringManifestDocument,
      'immutable child StartOS 0.4 authoring manifest'
    )
  )))
  requireEqual(
    'immutable child StartOS 0.4 canonical authoring manifest SHA-256',
    authoringManifestCanonicalSha256,
    evidence.artifact.manifests.transition.authoringCanonicalSha256
  )
  return {
    evidence,
    javascriptBundleSha256,
    authoringManifest,
    authoringManifestCanonicalSha256,
    authoringManifestDocument
  }
}

export function verifyInspectedStartos04ReleaseAssets ({
  evidencePath,
  binding,
  packagePath,
  commitmentPath,
  javascriptBundlePath,
  authoringManifestPath,
  packedManifestPath
}) {
  const buildInputs = verifyStartos04ArtifactBuildInputs({
    evidencePath,
    binding,
    packagePath,
    javascriptBundlePath,
    authoringManifestPath
  })
  const { evidence } = buildInputs
  const commitment = readPackageCommitment(commitmentPath)
  if (!isDeepStrictEqual(evidence.artifact.commitment, commitment)) {
    fail('Inspected StartOS 0.4 package commitment does not match the published sidecar')
  }
  const packedManifestDocument = readJson(
    packedManifestPath,
    'independently inspected StartOS 0.4 packed manifest',
    MAX_PACKAGE_MANIFEST_BYTES
  )
  const transition = verifyStartos04ManifestTransition({
    authoringManifest: buildInputs.authoringManifestDocument,
    packedManifest: packedManifestDocument,
    expectedTag: binding.tag,
    expectedReleaseSha: binding.tagSha,
    expectedPackageVersion: binding.packageVersion,
    expectedImageRef: binding.imageRef
  })
  if (!isDeepStrictEqual(evidence.artifact.manifests?.packed?.identity, transition.packedIdentity)) {
    fail('Inspected StartOS 0.4 packed manifest does not match the published sidecar')
  }
  if (!isDeepStrictEqual(evidence.artifact.manifests?.transition, transition.manifestTransition)) {
    fail('Inspected StartOS 0.4 full manifest transition does not match the published sidecar')
  }
  return {
    evidence,
    javascriptBundleSha256: buildInputs.javascriptBundleSha256,
    authoringManifest: buildInputs.authoringManifest,
    commitment,
    packedManifest: transition.packedIdentity,
    manifestTransition: transition.manifestTransition
  }
}

export function verifyStartos04ClosureChildRun ({ run, expectedChildRunId, binding }) {
  requirePattern('StartOS 0.4 child run id', expectedChildRunId, RUN_ID_PATTERN)
  const runId = String(run?.id ?? run?.runId ?? '')
  const runAttempt = String(run?.run_attempt ?? run?.runAttempt ?? '')
  const runUrl = run?.html_url ?? run?.runUrl
  const workflowName = run?.name ?? run?.workflowName
  const workflowPath = run?.path ?? run?.workflowPath
  const displayTitle = run?.display_title ?? run?.displayTitle
  const headSha = run?.head_sha ?? run?.headSha
  const headRef = run?.head_branch ?? run?.headRef
  requireEqual('StartOS 0.4 child run id', runId, expectedChildRunId)
  requirePattern('StartOS 0.4 child run attempt', runAttempt, RUN_ID_PATTERN)
  requireEqual(
    'StartOS 0.4 child run URL',
    runUrl,
    `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${expectedChildRunId}`
  )
  requireEqual('StartOS 0.4 child workflow name', workflowName, 'Release StartOS 0.4 package')
  const canonicalWorkflowPath = requireTaggedWorkflowPath(
    'StartOS 0.4 child workflow path',
    workflowPath,
    '.github/workflows/release-startos-0.4.yml',
    binding.tag
  )
  requireEqual(
    'StartOS 0.4 child display title',
    displayTitle,
    `StartOS 0.4 ${binding.tag} from release-surfaces ${binding.releaseSurfacesRunId} attempt ${binding.releaseSurfacesRunAttempt}`
  )
  requireEqual('StartOS 0.4 child head SHA', headSha, binding.tagSha)
  requireEqual('StartOS 0.4 child head ref', headRef, binding.tag)
  requireEqual('StartOS 0.4 child event', run?.event, 'workflow_dispatch')
  requireEqual('StartOS 0.4 child status', run?.status, 'completed')
  requireEqual('StartOS 0.4 child conclusion', run?.conclusion, 'success')
  return {
    workflowName: 'Release StartOS 0.4 package',
    workflowPath: canonicalWorkflowPath,
    displayTitle,
    runId,
    runAttempt,
    runUrl,
    event: 'workflow_dispatch',
    headRef,
    headSha,
    status: 'completed',
    conclusion: 'success'
  }
}

export function verifyStartos04ClosureArtifact ({ artifact, childRun }) {
  const id = String(artifact?.id || '')
  const size = Number(artifact?.size_in_bytes ?? artifact?.sizeInBytes)
  const archiveUrl = artifact?.archive_download_url ?? artifact?.archiveUrl
  const workflowRun = artifact?.workflow_run ?? artifact?.workflowRun
  const sourceRunId = String(workflowRun?.id ?? artifact?.sourceRunId ?? '')
  const sourceHeadSha = workflowRun?.head_sha ?? workflowRun?.headSha ?? artifact?.sourceHeadSha
  const sourceHeadRef = workflowRun?.head_branch ?? workflowRun?.headRef ?? artifact?.sourceHeadRef
  const sourceRunAttempt = String(artifact?.sourceRunAttempt ?? childRun.runAttempt)
  const expectedName = `startos-0.4-closure-${childRun.runId}-${childRun.runAttempt}`
  requirePattern('StartOS 0.4 child artifact id', id, RUN_ID_PATTERN)
  requireEqual('StartOS 0.4 child artifact name', artifact?.name, expectedName)
  if (artifact?.expired !== false) fail('StartOS 0.4 child artifact must exist and not be expired')
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_ACTIONS_ARTIFACT_BYTES) {
    fail(`StartOS 0.4 child artifact size must be between 1 and ${MAX_ACTIONS_ARTIFACT_BYTES} bytes`)
  }
  requirePattern('StartOS 0.4 child artifact digest', artifact?.digest, DIGEST_PATTERN)
  requireEqual(
    'StartOS 0.4 child artifact archive URL',
    archiveUrl,
    `https://api.github.com/repos/${EXPECTED_REPOSITORY}/actions/artifacts/${id}/zip`
  )
  requireEqual('StartOS 0.4 child artifact source run id', sourceRunId, childRun.runId)
  requireEqual('StartOS 0.4 child artifact source run attempt', sourceRunAttempt, childRun.runAttempt)
  requireEqual('StartOS 0.4 child artifact source head SHA', sourceHeadSha, childRun.headSha)
  requireEqual('StartOS 0.4 child artifact source head ref', sourceHeadRef, childRun.headRef)
  return {
    id,
    name: expectedName,
    digest: artifact.digest,
    sizeInBytes: size,
    archiveUrl,
    sourceRunId,
    sourceRunAttempt,
    sourceHeadRef,
    sourceHeadSha,
    expired: false,
    uploadAction: `actions/upload-artifact@${STARTOS_04_CHILD_ARTIFACT_ACTION_SHA}`
  }
}

export function buildReleaseClosureEvidence ({
  binding,
  sourceReleaseEvidencePath,
  imageManifestEvidencePath,
  artifactPackagePath,
  artifactStartosEvidencePath,
  releasePackagePath,
  releaseStartosEvidencePath,
  commitmentPath,
  artifactJavascriptBundlePath,
  artifactAuthoringManifestPath,
  packedManifestPath,
  childRun,
  childRunId,
  artifact,
  imageAuthorityArtifact,
  imageAuthorityArtifactId
}) {
  const inspection = verifyInspectedStartos04ReleaseAssets({
    evidencePath: artifactStartosEvidencePath,
    binding,
    packagePath: artifactPackagePath,
    commitmentPath,
    javascriptBundlePath: artifactJavascriptBundlePath,
    authoringManifestPath: artifactAuthoringManifestPath,
    packedManifestPath
  })
  const imageAuthority = selectStartos04ReleaseImageAuthorityArtifact({
    response: { total_count: 1, artifacts: [imageAuthorityArtifact] },
    expectedTag: binding.tag,
    expectedTagSha: binding.tagSha,
    expectedRunId: binding.releaseSurfacesRunId,
    expectedRunAttempt: binding.releaseSurfacesRunAttempt,
    expectedArtifactId: imageAuthorityArtifactId
  })
  return buildReleaseClosureEvidenceBody({
    binding,
    sourceReleaseEvidencePath,
    imageManifestEvidencePath,
    artifactPackagePath,
    artifactStartosEvidencePath,
    releasePackagePath,
    releaseStartosEvidencePath,
    inspection,
    childRun: verifyStartos04ClosureChildRun({ run: childRun, expectedChildRunId: childRunId, binding }),
    artifact,
    imageAuthority
  })
}

function buildReleaseClosureEvidenceBody ({
  binding,
  sourceReleaseEvidencePath,
  imageManifestEvidencePath,
  artifactPackagePath,
  artifactStartosEvidencePath,
  releasePackagePath,
  releaseStartosEvidencePath,
  inspection,
  childRun,
  artifact,
  imageAuthority
}) {
  const immutableArtifact = verifyStartos04ClosureArtifact({ artifact, childRun })
  const releaseEvidence = verifyPublishedStartos04ReleaseAssets({
    evidencePath: releaseStartosEvidencePath,
    binding,
    packagePath: releasePackagePath
  })
  if (!isDeepStrictEqual(releaseEvidence, inspection.evidence)) {
    fail('GitHub Release StartOS 0.4 evidence differs from the exact child artifact evidence')
  }
  const packageSha = sha256File(artifactPackagePath, 'child artifact StartOS 0.4 package', MAX_PACKAGE_BYTES)
  requireEqual(
    'GitHub Release StartOS 0.4 package hash matches child artifact',
    sha256File(releasePackagePath, 'GitHub Release StartOS 0.4 package', MAX_PACKAGE_BYTES),
    packageSha
  )
  const startosEvidenceSha = sha256File(
    artifactStartosEvidencePath,
    'child artifact StartOS 0.4 evidence',
    MAX_JSON_BYTES
  )
  requireEqual(
    'GitHub Release StartOS 0.4 evidence hash matches child artifact',
    sha256File(releaseStartosEvidencePath, 'GitHub Release StartOS 0.4 evidence', MAX_JSON_BYTES),
    startosEvidenceSha
  )
  const releaseBase = `https://github.com/${binding.repository}/releases/download/${binding.tag}`
  return {
    schemaVersion: 2,
    kind: 'hiverelay-release-closure',
    status: 'verified-startos-0.4-closure',
    release: {
      version: binding.tag,
      tagSha: binding.tagSha,
      semver: binding.semver
    },
    sourceCheckpointEvidence: {
      name: 'release-evidence.json',
      sha256: sha256File(sourceReleaseEvidencePath, 'release pre-handoff checkpoint evidence', MAX_JSON_BYTES),
      workflowScope: RELEASE_SYNC_WORKFLOW_SCOPE,
      workflowStatus: RELEASE_SYNC_SUCCESS_PENDING_CLOSURE,
      runId: binding.releaseSurfacesRunId,
      runAttempt: binding.releaseSurfacesRunAttempt,
      runUrl: binding.releaseSurfacesRunUrl
    },
    image: {
      ref: binding.imageRef,
      digest: binding.imageDigest,
      authority: imageAuthority,
      manifestEvidence: {
        name: 'release-image-manifest-evidence.json',
        sha256: sha256File(imageManifestEvidencePath, 'release image manifest evidence', MAX_JSON_BYTES)
      }
    },
    startos04: {
      childWorkflow: childRun,
      immutableArtifact,
      releaseAssets: {
        package: {
          name: STARTOS_04_RELEASE_ASSET,
          sha256: packageSha,
          url: `${releaseBase}/${STARTOS_04_RELEASE_ASSET}`
        },
        evidence: {
          name: STARTOS_04_RELEASE_EVIDENCE,
          sha256: startosEvidenceSha,
          url: `${releaseBase}/${STARTOS_04_RELEASE_EVIDENCE}`
        }
      },
      inspectedPackage: {
        commitmentSha256: inspection.commitment.sha256,
        javascriptBundleSha256: inspection.javascriptBundleSha256,
        authoringManifest: inspection.authoringManifest,
        packedManifest: inspection.packedManifest,
        manifestTransition: inspection.manifestTransition,
        signerIdentity: {
          status: 'not-exposed-by-start-cli-1.1.0',
          policy: 'closure-binds-inspected-package-bytes-and-commitment-for-github-sideload-only; registry-signer-identity-remains-unverified'
        }
      }
    },
    publication: {
      atomicity: 'non-atomic',
      surfacesThatMayPrecedeClosure: [
        'ghcr-image-and-keyless-signature',
        'npm-packages-and-dist-tags',
        'legacy-startos-release-asset-and-registry',
        'startos-0.4-release-package-and-evidence-pair',
        'github-release-and-pre-handoff-evidence-assets',
        'fleet-channel-rollout',
        'umbrel-and-ecosystem-metadata'
      ],
      stableGaPolicy: 'stable-and-ga-closure-requires-this-verified-certificate'
    }
  }
}

export function verifyReleaseClosureEvidence (args) {
  const actual = readJson(args.evidencePath, 'release closure evidence')
  const expected = buildReleaseClosureEvidence(args)
  if (!isDeepStrictEqual(actual, expected)) {
    fail('Release closure evidence does not match the exact source checkpoint, child run/artifact, inspected package, and published bytes')
  }
  return actual
}

export function verifyPublishedReleaseClosureEvidence ({
  evidencePath,
  binding,
  sourceReleaseEvidencePath,
  imageManifestEvidencePath,
  releasePackagePath,
  releaseStartosEvidencePath
}) {
  const actual = readJson(evidencePath, 'published release closure evidence')
  const startosEvidence = verifyPublishedStartos04ReleaseAssets({
    evidencePath: releaseStartosEvidencePath,
    binding,
    packagePath: releasePackagePath
  })
  const expected = buildReleaseClosureEvidenceBody({
    binding,
    sourceReleaseEvidencePath,
    imageManifestEvidencePath,
    artifactPackagePath: releasePackagePath,
    artifactStartosEvidencePath: releaseStartosEvidencePath,
    releasePackagePath,
    releaseStartosEvidencePath,
    inspection: {
      evidence: startosEvidence,
      commitment: startosEvidence.artifact.commitment,
      javascriptBundleSha256: startosEvidence.toolchain.buildContract.javascriptBundle.sha256,
      authoringManifest: startosEvidence.artifact.manifests.authoring.identity,
      packedManifest: startosEvidence.artifact.manifests.packed.identity,
      manifestTransition: startosEvidence.artifact.manifests.transition
    },
    childRun: verifyStartos04ClosureChildRun({
      run: actual?.startos04?.childWorkflow,
      expectedChildRunId: String(actual?.startos04?.childWorkflow?.runId || ''),
      binding
    }),
    artifact: actual?.startos04?.immutableArtifact,
    imageAuthority: selectStartos04ReleaseImageAuthorityArtifact({
      response: { total_count: 1, artifacts: [actual?.image?.authority] },
      expectedTag: binding.tag,
      expectedTagSha: binding.tagSha,
      expectedRunId: binding.releaseSurfacesRunId,
      expectedRunAttempt: binding.releaseSurfacesRunAttempt,
      expectedArtifactId: String(actual?.image?.authority?.id || '')
    })
  })
  if (!isDeepStrictEqual(actual, expected)) {
    fail('Published release closure evidence does not match the source checkpoint, current release assets, and recorded immutable child artifact')
  }
  return actual
}

export function writeJsonAtomic (file, body) {
  const resolved = path.resolve(file)
  fs.mkdirSync(path.dirname(resolved), { recursive: true })
  const tmp = `${resolved}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 })
  fs.renameSync(tmp, resolved)
}

export function appendGitHubEnv (file, values) {
  const lines = []
  for (const [name, value] of Object.entries(values)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) fail(`invalid GitHub environment variable name: ${name}`)
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) fail(`invalid GitHub environment value for ${name}`)
    lines.push(`${name}=${value}`)
  }
  fs.appendFileSync(path.resolve(file), `${lines.join('\n')}\n`)
}

function readJson (file, label, maxBytes = MAX_JSON_BYTES) {
  const raw = readRegularFile(file, label, maxBytes)
  try {
    return JSON.parse(raw.toString('utf8'))
  } catch (err) {
    fail(`${label} must be JSON: ${err.message}`)
  }
}

function readRegularFile (file, label, maxBytes) {
  const stat = regularFileStat(file, label)
  if (stat.size > maxBytes) fail(`${label} must be ${maxBytes} bytes or smaller`)
  return fs.readFileSync(path.resolve(file))
}

function regularFileStat (file, label) {
  const resolved = path.resolve(file)
  let stat
  try {
    stat = fs.lstatSync(resolved)
  } catch (err) {
    fail(`${label} is not readable: ${err.message}`)
  }
  if (stat.isSymbolicLink() || !stat.isFile()) fail(`${label} must be a regular non-symlink file`)
  return stat
}

function sha256File (file, label, maxBytes) {
  const resolved = path.resolve(file)
  const stat = regularFileStat(resolved, label)
  if (stat.size > maxBytes) fail(`${label} must be ${maxBytes} bytes or smaller`)
  const hash = crypto.createHash('sha256')
  const buffer = Buffer.allocUnsafe(1024 * 1024)
  const fd = fs.openSync(resolved, 'r')
  try {
    let bytesRead
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null)
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead))
    } while (bytesRead > 0)
  } finally {
    fs.closeSync(fd)
  }
  return hash.digest('hex')
}

function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
  fail(`${label} is required and malformed; got ${JSON.stringify(value)}`)
}

function requireTaggedWorkflowPath (label, actual, expectedPath, expectedTag) {
  requirePattern(`${label} release tag`, expectedTag, TAG_PATTERN)
  const canonical = `${expectedPath}@refs/tags/${expectedTag}`
  if (
    actual === expectedPath ||
    actual === `${expectedPath}@${expectedTag}` ||
    actual === canonical
  ) return canonical
  fail(
    `${label} must be ${JSON.stringify(expectedPath)} at exact tag ${JSON.stringify(expectedTag)}; ` +
    `got ${JSON.stringify(actual)}`
  )
}

// `gh run view --attempt` reports the selected attempt using an
// attempt-qualified URL, while release evidence intentionally stores the
// canonical run URL. Both identify the same already-bound run and exact
// attempt; reject every other URL shape.
function requireExactRunUrl (label, actual, expectedRunUrl, expectedRunAttempt) {
  const attemptUrl = `${expectedRunUrl}/attempts/${expectedRunAttempt}`
  if (actual === expectedRunUrl || actual === attemptUrl) return expectedRunUrl
  fail(
    `${label} must be ${JSON.stringify(expectedRunUrl)} or ` +
    `${JSON.stringify(attemptUrl)}; got ${JSON.stringify(actual)}`
  )
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  fail(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireArrayEqual (label, actual, expected) {
  if (Array.isArray(actual) && actual.length === expected.length && actual.every((item, index) => item === expected[index])) return
  fail(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function fail (message) {
  throw new Error(message)
}
