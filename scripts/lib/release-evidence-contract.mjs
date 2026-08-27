export const RELEASE_SYNC_WORKFLOW_SCOPE = 'release-surfaces/pre-handoff-checkpoint'
export const RELEASE_SYNC_SUCCESS_PENDING_CLOSURE = 'checkpoint-passed-pending-sync-completion-and-startos-0.4-closure'
export const RELEASE_CANDIDATE_SYNC_SUCCESS = 'checkpoint-passed-branch-candidate'
export const RELEASE_CLOSURE_EVIDENCE = 'release-closure-evidence.json'
export const RELEASE_CLOSURE_PENDING = 'pending-startos-0.4'
export const RELEASE_CLOSURE_NOT_REQUIRED = 'not-required-branch-candidate'
export const RELEASE_CLOSURE_NOT_REACHED = 'not-reached'

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
