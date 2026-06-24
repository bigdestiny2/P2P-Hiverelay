import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'

/**
 * Build a minimal mock RelayNode with appRegistry containing the given entries.
 * Each entry in `apps` is [appKeyHex, { publisherPubkey, ... }].
 */
function mockNode (apps = []) {
  const map = new Map(apps)
  const node = {
    appRegistry: {
      get (key) { return map.get(key) },
      has (key) { return map.has(key) }
    },
    seededApps: map,
    config: {}
  }
  return node
}

/**
 * Generate an Ed25519 key pair.
 */
function keygen () {
  const pk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(pk, sk)
  return { pk, sk }
}

/**
 * Sign an unseed payload: (appKey + 'unseed' + uint64 timestamp).
 */
function signUnseed (appKeyHex, timestamp, sk) {
  const appKeyBuf = b4a.from(appKeyHex, 'hex')
  const tsBuf = b4a.alloc(8)
  const view = new DataView(tsBuf.buffer, tsBuf.byteOffset)
  view.setBigUint64(0, BigInt(timestamp))
  const payload = b4a.concat([appKeyBuf, b4a.from('unseed'), tsBuf])

  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, payload, sk)
  return b4a.toString(sig, 'hex')
}

/**
 * Import verifyUnseedRequest by dynamically loading the RelayNode class
 * and calling the method on a crafted instance (avoiding full node startup).
 */
async function loadVerify () {
  // verifyUnseedRequest now lives on AppLifecycle (extracted from RelayNode
  // during the god-object refactor). Call it directly against the mock node.
  const mod = await import('p2p-hiverelay/core/relay-node/app-lifecycle.js')
  const AppLifecycleClass = mod.AppLifecycle
  return function verifyUnseedRequest (node, appKeyHex, publisherPubkeyHex, signatureHex, timestamp) {
    const lifecycle = new AppLifecycleClass(node)
    return lifecycle.verifyUnseedRequest(appKeyHex, publisherPubkeyHex, signatureHex, timestamp)
  }
}

let verify

test('unseed-verify: setup', async (t) => {
  verify = await loadVerify()
  t.ok(verify, 'verifyUnseedRequest loaded')
})

test('unseed-verify: valid unseed with matching publisher key and fresh timestamp', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0xab), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now()
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.ok(result.ok, 'result.ok is true')
  t.is(result.error, undefined, 'no error')
})

test('unseed-verify: wrong publisher key returns PUBLISHER_MISMATCH', async (t) => {
  const { pk, sk } = keygen()
  const { pk: otherPk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0xcd), 'hex')
  const realPublisherHex = b4a.toString(pk, 'hex')
  const wrongPublisherHex = b4a.toString(otherPk, 'hex')
  const timestamp = Date.now()
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  const node = mockNode([[appKeyHex, { publisherPubkey: realPublisherHex }]])
  const result = verify(node, appKeyHex, wrongPublisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'PUBLISHER_MISMATCH', 'error is PUBLISHER_MISMATCH')
})

test('unseed-verify: stale timestamp (> 5 min old) returns STALE_TIMESTAMP', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x11), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now() - (6 * 60 * 1000) // 6 minutes ago
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'STALE_TIMESTAMP', 'error is STALE_TIMESTAMP')
})

test('unseed-verify: future timestamp (> 60s ahead) returns STALE_TIMESTAMP', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x22), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now() + (90 * 1000) // 90 seconds in the future
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'STALE_TIMESTAMP', 'error is STALE_TIMESTAMP')
})

test('unseed-verify: app not found returns APP_NOT_FOUND', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x33), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now()
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  const node = mockNode([]) // empty registry
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'APP_NOT_FOUND', 'error is APP_NOT_FOUND')
})

test('unseed-verify: no publisher key on record returns NO_PUBLISHER_KEY', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x44), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now()
  const sigHex = signUnseed(appKeyHex, timestamp, sk)

  // Entry exists but has no publisherPubkey (legacy app)
  const node = mockNode([[appKeyHex, { publisherPubkey: null }]])
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.ok(result.error.startsWith('NO_PUBLISHER_KEY'), 'error starts with NO_PUBLISHER_KEY')
})

test('unseed-verify: invalid signature returns INVALID_SIGNATURE', async (t) => {
  const { pk } = keygen()
  const { sk: wrongSk } = keygen() // sign with a different key
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x55), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const timestamp = Date.now()
  const sigHex = signUnseed(appKeyHex, timestamp, wrongSk)

  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const result = verify(node, appKeyHex, publisherHex, sigHex, timestamp)

  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'INVALID_SIGNATURE', 'error is INVALID_SIGNATURE')
})

// ─── adversarial / malformed input robustness ───────────────────────────────
// The verifier must be total: a malformed unseed request (garbage hex, wrong
// length, non-string, non-finite timestamp) must be rejected cleanly with
// { ok:false, error:'MALFORMED_REQUEST' } and must never throw. Without the
// input guard, sodium asserts on a wrong-length signature and BigInt() throws
// on a non-integer timestamp — turning a bad request into an exception that a
// P2P/direct caller would have to catch. These cases lock in graceful rejection.

test('unseed-verify: non-hex signature returns MALFORMED_REQUEST (no throw)', async (t) => {
  const { pk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x61), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])

  let result
  t.execution(() => { result = verify(node, appKeyHex, publisherHex, 'z'.repeat(128), Date.now()) }, 'does not throw')
  t.is(result.ok, false, 'result.ok is false')
  t.is(result.error, 'MALFORMED_REQUEST', 'error is MALFORMED_REQUEST')
})

test('unseed-verify: wrong-length signature returns MALFORMED_REQUEST (no throw)', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x62), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const ts = Date.now()
  // a valid signature truncated to the wrong byte length
  const shortSig = signUnseed(appKeyHex, ts, sk).slice(0, 40)

  let result
  t.execution(() => { result = verify(node, appKeyHex, publisherHex, shortSig, ts) }, 'does not throw')
  t.is(result.error, 'MALFORMED_REQUEST', 'error is MALFORMED_REQUEST')
})

test('unseed-verify: empty / null signature returns MALFORMED_REQUEST (no throw)', async (t) => {
  const { pk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x63), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const ts = Date.now()

  for (const badSig of ['', null, undefined]) {
    let result
    t.execution(() => { result = verify(node, appKeyHex, publisherHex, badSig, ts) }, `does not throw for ${String(badSig)}`)
    t.is(result.error, 'MALFORMED_REQUEST', `${String(badSig)} signature is MALFORMED_REQUEST`)
  }
})

test('unseed-verify: malformed timestamp returns MALFORMED_REQUEST (no throw)', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x64), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const sigHex = signUnseed(appKeyHex, Date.now(), sk)

  for (const badTs of [NaN, Infinity, 'not-a-number', null, Date.now() + 0.5, -1]) {
    let result
    t.execution(() => { result = verify(node, appKeyHex, publisherHex, sigHex, badTs) }, `does not throw for ${String(badTs)}`)
    t.is(result.error, 'MALFORMED_REQUEST', `${String(badTs)} timestamp is MALFORMED_REQUEST`)
  }
})

test('unseed-verify: non-string / wrong-length appKey returns MALFORMED_REQUEST (no throw)', async (t) => {
  const { pk, sk } = keygen()
  const appKeyHex = b4a.toString(b4a.alloc(32, 0x65), 'hex')
  const publisherHex = b4a.toString(pk, 'hex')
  const node = mockNode([[appKeyHex, { publisherPubkey: publisherHex }]])
  const ts = Date.now()
  const sigHex = signUnseed(appKeyHex, ts, sk)

  for (const badKey of [{}, 'abcd', 'z'.repeat(64), 12345, null]) {
    let result
    t.execution(() => { result = verify(node, badKey, publisherHex, sigHex, ts) }, `does not throw for ${JSON.stringify(badKey)}`)
    t.is(result.error, 'MALFORMED_REQUEST', `${JSON.stringify(badKey)} appKey is MALFORMED_REQUEST`)
  }
})
