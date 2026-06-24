import test from 'brittle'
import http from 'http'

// Guards the public custody-status redaction contract that the dealer-side
// orchestration (client splitForCustody → _awaitVerifiedReceipts) depends on:
// the UNAUTHENTICATED GET /api/custody/<id>/status must expose a per-receipt
// `receipts[]` array carrying the PUBLIC attestation fields (relayPubkey,
// shareIndex, shareVerified, anchored) so publicly-verifiable custody can be
// confirmed without an API key — while the secret-ish receipt fields
// (addressKey, ciphertextRoot, signature, …) and the full intent stay behind
// ?detailed=1 + Bearer auth.
//
// Regression: _redactCustodyStatus previously dropped receipts[] entirely, so
// _awaitVerifiedReceipts polled an array that never arrived and every live
// splitForCustody timed out with CUSTODY_QUORUM_TIMEOUT.

const API_KEY = 'redaction-test-key-abcdef'
const INTENT_ID = 'a'.repeat(64)
const RELAY_PUBKEY = 'b'.repeat(64)

function fullStatus () {
  return {
    intentId: INTENT_ID,
    blindContentId: 'c'.repeat(64),
    custodyMode: 'blind',
    requiredReplicas: 1,
    receiptCount: 1,
    quorumReached: true,
    receiptRoot: 'd'.repeat(64),
    relayQuorum: [RELAY_PUBKEY],
    committed: false,
    sourceRetired: false,
    proofCount: 0,
    passingProofs: 0,
    nonServingProofCount: 0,
    nonServingRelays: [],
    expiryWitnessCount: 0,
    validExpiryWitnessCount: 0,
    expiryWitnessRelays: [],
    pvss: {
      shareScheme: 'pvss-secp256k1-v1',
      shareThreshold: 1,
      commitmentRoot: 'e'.repeat(64),
      shareIndices: [1]
    },
    // Sensitive: full signed intent (names shareBundleKey, commitments, …).
    intent: { intentId: INTENT_ID, shareBundleKey: 'f'.repeat(64), version: 2 },
    // Each receipt mixes PUBLIC attestation fields with sensitive ones.
    receipts: [
      {
        relayPubkey: RELAY_PUBKEY,
        shareIndex: 1,
        shareVerified: true,
        anchored: true,
        // sensitive / must NOT leak via the public redacted view:
        addressKey: '9'.repeat(64),
        blindContentId: 'c'.repeat(64),
        ciphertextRoot: '8'.repeat(64),
        relayRegion: 'us-test',
        signature: '7'.repeat(128)
      }
    ],
    commit: null,
    proofs: [],
    nonServingProofs: [],
    expiryWitnesses: []
  }
}

function mockRelayNode () {
  return {
    running: true,
    config: { storage: null, registryAutoAccept: false },
    metrics: { getSummary () { return { uptime: 100 } } },
    appRegistry: {
      get () { return null },
      has () { return false },
      apps: new Map(),
      catalog () { return [] },
      catalogForBroadcast () { return [] }
    },
    getStats () { return { running: true, seededApps: 0, connections: 0 } },
    getHealthStatus () { return { healthy: true } },
    async stop () {},
    seedingRegistry: {
      getCustodyStatus () { return fullStatus() }
    },
    serviceRegistry: null,
    reputation: null,
    networkDiscovery: null,
    relay: null,
    seeder: null,
    swarm: null,
    on () {},
    emit () {}
  }
}

function request (port, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path, headers }, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch (_) { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

let api = null
let port = 0

test('custody-redaction: setup server', async (t) => {
  const { RelayAPI } = await import('p2p-hiverelay/core/relay-node/api.js')
  api = new RelayAPI(mockRelayNode(), { apiPort: 0, apiKey: API_KEY, apiHost: '127.0.0.1' })
  await api.start()
  port = api.server.address().port
  t.ok(port > 0, 'server started on port ' + port)
})

test('custody-redaction: public status exposes minimal per-receipt attestation', async (t) => {
  const res = await request(port, 'GET', `/api/custody/${INTENT_ID}/status`)
  t.is(res.statusCode, 200, 'public status returns 200 (no auth)')
  t.ok(Array.isArray(res.body.receipts), 'receipts[] present in redacted status')
  t.is(res.body.receipts.length, 1, 'one receipt surfaced')

  const r = res.body.receipts[0]
  t.is(r.relayPubkey, RELAY_PUBKEY, 'relayPubkey exposed (already public via relayQuorum)')
  t.is(r.shareIndex, 1, 'shareIndex exposed (already public via pvss.shareIndices)')
  t.is(r.shareVerified, true, 'shareVerified exposed — required by _awaitVerifiedReceipts')
  t.is(r.anchored, true, 'anchored exposed — required by _awaitVerifiedReceipts')

  // Only the 4 public attestation fields — nothing sensitive.
  t.alike(Object.keys(r).sort(), ['anchored', 'relayPubkey', 'shareIndex', 'shareVerified'],
    'redacted receipt carries only the 4 public fields')
  t.absent(r.addressKey, 'addressKey not leaked')
  t.absent(r.ciphertextRoot, 'ciphertextRoot not leaked')
  t.absent(r.signature, 'receipt signature not leaked')
  t.absent(r.relayRegion, 'relayRegion not leaked')

  // The full intent must never appear in the public view.
  t.absent(res.body.intent, 'full intent absent from public status')
  t.absent(res.body.commit, 'commit absent from public status')
  t.absent(res.body.proofs, 'proofs absent from public status')
})

test('custody-redaction: ?detailed=1 without auth is 401', async (t) => {
  const res = await request(port, 'GET', `/api/custody/${INTENT_ID}/status?detailed=1`)
  t.is(res.statusCode, 401, 'detailed view requires auth')
})

test('custody-redaction: ?detailed=1 with Bearer returns shaped diagnostics', async (t) => {
  const res = await request(port, 'GET', `/api/custody/${INTENT_ID}/status?detailed=1`, {
    Authorization: 'Bearer ' + API_KEY
  })
  t.is(res.statusCode, 200, 'authed detailed status returns 200')
  t.alike(res.body.pvss, {
    shareScheme: 'pvss-secp256k1-v1',
    shareThreshold: 1,
    commitmentRoot: 'e'.repeat(64),
    shareIndices: [1]
  })
  t.alike(res.body.receipts[0], {
    relayPubkey: RELAY_PUBKEY,
    shareIndex: 1,
    shareVerified: true,
    anchored: true,
    relayRegion: 'us-test',
    receivedAt: null,
    attestedAt: null
  })
  t.absent(res.body.intent, 'full intent absent even under detailed API status')
  t.absent(res.body.commit, 'raw commit absent from detailed API status')
  t.absent(res.body.proofs, 'raw proofs absent from detailed API status')
  t.absent(res.body.nonServingProofs, 'raw non-serving proofs absent from detailed API status')
  t.absent(res.body.expiryWitnesses, 'raw expiry witnesses absent from detailed API status')
  const json = JSON.stringify(res.body)
  t.absent(json.includes('shareBundleKey'), 'shareBundleKey omitted under auth')
  t.absent(json.includes('7'.repeat(128)), 'receipt signature omitted under auth')
  t.absent(json.includes('9'.repeat(64)), 'addressKey omitted under auth')
  t.absent(json.includes('8'.repeat(64)), 'ciphertextRoot omitted under auth')
})

test('custody-redaction: teardown server', async (t) => {
  if (api && api.server) {
    api.server.close()
    if (api._rateLimitCleanup) clearInterval(api._rateLimitCleanup)
    if (api._dashboardFeed) {
      try { api._dashboardFeed.stop() } catch (_) {}
    }
  }
  t.pass('server closed')
})
