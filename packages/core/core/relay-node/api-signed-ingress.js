import { verifyForkProof } from '../fork-proof-signing.js'
import { verifySeedingManifest } from '../seeding-manifest.js'
import { formatErr } from '../error-prefixes.js'

const AUTHOR_MANIFEST_ROUTE = /^\/api\/authors\/([0-9a-f]{64})\/seeding\.json$/i
const MANIFEST_PERSIST_FAILED_MESSAGE = 'failed to persist seeding manifest; check storage permissions and disk space'
const FORK_PERSIST_FAILED_MESSAGE = 'failed to persist fork proof; check storage permissions and disk space'

const SIGNED_INGRESS_PERSIST_FAILURES = Object.freeze({
  'manifest-persist': Object.freeze({
    event: 'manifest-persist-error',
    message: MANIFEST_PERSIST_FAILED_MESSAGE
  }),
  'fork-persist': Object.freeze({
    event: 'fork-persist-error',
    message: FORK_PERSIST_FAILED_MESSAGE
  })
})

function errorPayload (code, message) {
  return { error: formatErr(code, message) }
}

function errorMessage (err) {
  return err && err.message ? err.message : String(err || 'unknown error')
}

export function signedIngressPersistFailureResult ({
  kind,
  error,
  emit = null
}) {
  const spec = SIGNED_INGRESS_PERSIST_FAILURES[kind]
  if (!spec) return null

  if (typeof emit === 'function') {
    emit(spec.event, {
      message: errorMessage(error),
      error
    })
  }

  return {
    ok: false,
    kind,
    status: 500,
    payload: {
      error: formatErr('PERSIST_FAILED', spec.message),
      errorCode: 'persist-failed'
    }
  }
}

export function resolveSignedIngressRoute (method, path) {
  if (method !== 'POST') return null
  if (path === '/api/authors/seeding.json') return { kind: 'author-manifest-publish' }
  if (path === '/api/forks/proof') return { kind: 'fork-proof-publish' }
  return null
}

export function authorManifestPubkeyFromPath (path) {
  if (typeof path !== 'string') return null
  const match = path.match(AUTHOR_MANIFEST_ROUTE)
  return match ? match[1] : null
}

export function buildAuthorManifestFetchRoutePayload ({
  manifestStore,
  path
}) {
  return runAuthorManifestFetchAction({
    manifestStore,
    pubkey: authorManifestPubkeyFromPath(path)
  })
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

export async function runAuthorManifestPublishAction ({ body, manifestStore, emit = null }) {
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
    return signedIngressPersistFailureResult({ kind: 'manifest-persist', error: err, emit })
  }

  return {
    ok: true,
    status: 200,
    payload: { ok: true, pubkey: check.pubkey, replaced: result.replaced }
  }
}

export async function runForkProofPublishAction ({ body, forkDetector, emit = null }) {
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
    return signedIngressPersistFailureResult({ kind: 'fork-persist', error: err, emit })
  }

  return {
    ok: true,
    status: 200,
    payload: { ok: true, recordExists: result.recordExists, observer: verify.observer }
  }
}
