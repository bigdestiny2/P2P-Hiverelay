import { verifyForkProof } from '../fork-proof-signing.js'
import { verifySeedingManifest } from '../seeding-manifest.js'
import { formatErr } from '../error-prefixes.js'

function errorPayload (code, message) {
  return { error: formatErr(code, message) }
}

export function runAuthorManifestFetchAction ({ manifestStore, pubkey }) {
  if (!manifestStore) {
    return { ok: false, status: 503, payload: errorPayload('UNSUPPORTED', 'manifest store not initialized') }
  }
  const manifest = manifestStore.get(pubkey)
  if (!manifest) {
    return { ok: false, status: 404, payload: errorPayload('NOT_FOUND', 'no seeding manifest for this author') }
  }
  return {
    ok: true,
    status: 200,
    headers: { 'Cache-Control': 'public, max-age=30' },
    payload: manifest
  }
}

export async function runAuthorManifestPublishAction ({ body, manifestStore }) {
  if (!manifestStore) {
    return { ok: false, status: 503, payload: errorPayload('UNSUPPORTED', 'manifest store not initialized') }
  }
  if (!body || typeof body !== 'object') {
    return { ok: false, status: 400, payload: errorPayload('BAD_REQUEST', 'manifest required') }
  }

  const check = verifySeedingManifest(body)
  if (!check.valid) {
    return { ok: false, status: 400, payload: errorPayload('BAD_REQUEST', 'invalid manifest: ' + check.reason) }
  }

  const snapshot = typeof manifestStore.snapshot === 'function'
    ? manifestStore.snapshot()
    : null
  const result = manifestStore.put(body)
  if (!result.ok) {
    const status = /stale/.test(result.reason) ? 409 : 400
    return { ok: false, status, payload: errorPayload('BAD_REQUEST', result.reason) }
  }

  try {
    await manifestStore.save()
  } catch (err) {
    if (snapshot && typeof manifestStore.restoreSnapshot === 'function') {
      manifestStore.restoreSnapshot(snapshot)
    }
    return { ok: false, kind: 'manifest-persist', error: err }
  }

  return {
    ok: true,
    status: 200,
    payload: { ok: true, pubkey: check.pubkey, replaced: result.replaced }
  }
}

export async function runForkProofPublishAction ({ body, forkDetector }) {
  if (!forkDetector) {
    return { ok: false, status: 503, payload: errorPayload('UNSUPPORTED', 'fork detector not initialized') }
  }
  if (!body || typeof body !== 'object') {
    return { ok: false, status: 400, payload: errorPayload('BAD_REQUEST', 'fork proof body required') }
  }

  const verify = verifyForkProof(body)
  if (!verify.valid) {
    return { ok: false, status: 400, payload: errorPayload('BAD_REQUEST', 'invalid signed proof: ' + verify.reason) }
  }

  const snapshot = typeof forkDetector.snapshot === 'function'
    ? forkDetector.snapshot()
    : null
  const result = forkDetector.report({
    hypercoreKey: body.proof.hypercoreKey,
    blockIndex: body.proof.blockIndex,
    evidenceA: body.proof.evidence[0],
    evidenceB: body.proof.evidence[1]
  })
  if (!result.ok) {
    return { ok: false, status: 400, payload: errorPayload('BAD_REQUEST', result.reason) }
  }

  try {
    await forkDetector.save()
  } catch (err) {
    if (snapshot && typeof forkDetector.restoreSnapshot === 'function') {
      forkDetector.restoreSnapshot(snapshot)
    }
    return { ok: false, kind: 'fork-persist', error: err }
  }

  return {
    ok: true,
    status: 200,
    payload: { ok: true, recordExists: result.recordExists, observer: verify.observer }
  }
}
