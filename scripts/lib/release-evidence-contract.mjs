export const RELEASE_SYNC_WORKFLOW_SCOPE = 'release-surfaces/pre-handoff-checkpoint'
export const RELEASE_SYNC_SUCCESS_PENDING_CLOSURE = 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure'
export const RELEASE_CANDIDATE_SYNC_SUCCESS = 'checkpoint-passed-branch-candidate'
export const RELEASE_CLOSURE_EVIDENCE = 'release-closure-evidence.json'
export const RELEASE_CLOSURE_PENDING = 'pending-startos-0.4'
export const RELEASE_CLOSURE_NOT_REQUIRED = 'not-required-branch-candidate'
export const RELEASE_CLOSURE_NOT_REACHED = 'not-reached'
export const RELEASE_ARTIFACT_STAGE = 'artifact-v1'
export const RELEASE_STABLE_STAGE = 'stable-v1'
export const RELEASE_PROMOTION_EVIDENCE = 'release-stable-promotion-evidence.json'
export const RELEASE_DEFERRED_STATUS = 'deferred-stable-promotion'
export const RELEASE_NPM_STAGING_TAG = 'next'
export const RELEASE_NPM_PACKAGES = Object.freeze([
  'p2p-hiverelay', 'p2p-hiverelay-client', 'p2p-hiverelay-verifier', 'p2p-hiveservices'
])
export const RELEASE_DEFERRED_SURFACES = Object.freeze([
  'npm-latest', 'oci-latest', 'github-latest', 'fleet', 'metadata',
  'ecosystem-consumers', 'umbrel-community', 'umbrel-official', 'startos-registry'
])

export function isArtifactRelease (body) {
  return body?.release?.stage?.name === RELEASE_ARTIFACT_STAGE
}

export function assertArtifactChannel (channel) {
  if (channel !== 'none') throw new Error('Artifact publication requires channel=none; fleet publication uses the signed channels-only publisher')
}

export function validateReleaseStage (body) {
  const stage = body?.release?.stage
  if (stage == null) return false // Immutable historical checkpoints retain their original contract.
  exactKeys(stage, ['schemaVersion', 'name', 'npmDistTag', 'packages', 'githubLatest', 'metadataBranch', 'deferredSurfaces', 'promotionEvidence'], 'release.stage')
  if (stage.schemaVersion !== 1 || stage.name !== RELEASE_ARTIFACT_STAGE ||
      stage.npmDistTag !== RELEASE_NPM_STAGING_TAG || stage.githubLatest !== false ||
      stage.promotionEvidence !== RELEASE_PROMOTION_EVIDENCE ||
      JSON.stringify(stage.deferredSurfaces) !== JSON.stringify(RELEASE_DEFERRED_SURFACES)) {
    throw new Error('Unknown or inconsistent versioned artifact stage')
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(stage.metadataBranch || '') || stage.metadataBranch.includes('..') || stage.metadataBranch.endsWith('/')) throw new Error('Artifact metadata publication branch is invalid')
  assertArtifactChannel(body.release.channel)
  if (!Array.isArray(stage.packages) || stage.packages.length !== RELEASE_NPM_PACKAGES.length) {
    throw new Error('Artifact stage requires exactly four immutable npm packages')
  }
  for (const [index, pkg] of stage.packages.entries()) {
    exactKeys(pkg, ['name', 'version', 'integrity', 'shasum'], 'artifact npm package')
    if (pkg.name !== RELEASE_NPM_PACKAGES[index] || pkg.version !== body.release.semver ||
        !/^sha512-[A-Za-z0-9+/]{86}==$/.test(pkg.integrity) ||
        !/^[a-f0-9]{40}$/.test(pkg.shasum)) throw new Error('Artifact npm package identity or integrity is invalid')
  }
  return true
}

export function assertArtifactSurfaceState (body) {
  if (!validateReleaseStage(body)) throw new Error('Versioned artifact stage is required')
  const s = body.surfaces
  if (!['published-next', 'current-next'].includes(s.npmPackages) || body.gates.distributionPreflight !== 'passed-artifact') {
    throw new Error('Artifact stage requires verified staging npm publication and artifact credential preflight')
  }
  if (s.metadataCommit !== RELEASE_DEFERRED_STATUS || s.fleetRollout !== RELEASE_DEFERRED_STATUS ||
      s.startosRegistry !== RELEASE_DEFERRED_STATUS || s.umbrelOfficial.status !== RELEASE_DEFERRED_STATUS ||
      s.umbrelCommunityStore.validation !== RELEASE_DEFERRED_STATUS || s.umbrelCommunityStore.publish !== RELEASE_DEFERRED_STATUS) {
    throw new Error('Artifact stage must defer every stable distribution and fleet surface')
  }
  for (const value of [s.fleetRolloutChannel, s.fleetRolloutEvidence.path, s.fleetRolloutEvidence.sha256,
    s.fleetChannelConfig.path, s.fleetChannelConfig.sha256, s.startosRegistryUrl, s.startosRegistryPackageUrl,
    s.startosRegistryEvidence.path, s.startosRegistryEvidence.sha256, s.umbrelCommunityStore.commit,
    s.umbrelCommunityStore.commitUrl, ...Object.entries(s.umbrelOfficial).filter(([key]) => key !== 'status').map(([, value]) => value)]) {
    if (value !== '' && value !== null) throw new Error('Deferred artifact surface carries a publication or fleet claim')
  }
}

function exactKeys (value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} has unknown or missing fields`)
  }
}

export function releaseSyncEvidenceStatus ({ jobStatus, candidate }) {
  if (jobStatus !== 'success') return jobStatus
  return candidate ? RELEASE_CANDIDATE_SYNC_SUCCESS : RELEASE_SYNC_SUCCESS_PENDING_CLOSURE
}

export function releaseClosureStatus ({ jobStatus, candidate }) {
  if (candidate) return RELEASE_CLOSURE_NOT_REQUIRED
  return jobStatus === 'success' ? RELEASE_CLOSURE_PENDING : RELEASE_CLOSURE_NOT_REACHED
}

export function isSuccessfulReleaseSyncEvidence (release) {
  const expected = release?.candidate === true
    ? RELEASE_CANDIDATE_SYNC_SUCCESS
    : RELEASE_SYNC_SUCCESS_PENDING_CLOSURE
  const expectedClosure = release?.candidate === true
    ? RELEASE_CLOSURE_NOT_REQUIRED
    : RELEASE_CLOSURE_PENDING
  const expectedEvidence = release?.candidate === true ? '' : RELEASE_CLOSURE_EVIDENCE
  return release?.workflow?.scope === RELEASE_SYNC_WORKFLOW_SCOPE &&
    release?.workflow?.status === expected &&
    release?.closure?.status === expectedClosure &&
    release?.closure?.evidence === expectedEvidence
}

export function expectedReleaseClosureStatus (release) {
  return release?.candidate === true ? RELEASE_CLOSURE_NOT_REQUIRED : RELEASE_CLOSURE_PENDING
}

export function promotionAssetNames (workflow) {
  if (!/^[1-9][0-9]*$/.test(workflow?.runId || '') || !/^[1-9][0-9]*$/.test(workflow?.runAttempt || '')) throw new Error('Exact promotion run and attempt required for immutable asset names')
  const suffix = `${workflow.runId}-${workflow.runAttempt}.json`
  return {
    'release-stable-promotion-evidence.json': `release-stable-promotion-${suffix}`,
    'stable-promotion-fleet-evidence.json': `stable-promotion-fleet-${suffix}`
  }
}
