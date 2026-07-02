import test from 'brittle'
import http from 'http'
import Hypercore from 'hypercore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import os from 'os'
import path from 'path'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import {
  PROOF_KIND_RETRIEVABILITY,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  verifyStorageProof
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'
import {
  resolveRetrievabilityProofRoute
} from 'p2p-hiverelay/core/relay-node/retrievability-proof.js'

let seq = 0
function tmp () {
  return path.join(os.tmpdir(), 'hr-proof-api-' + process.pid + '-' + (seq++))
}

function keyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function nonce () {
  const out = b4a.alloc(32)
  sodium.randombytes_buf(out)
  return out
}

async function seededCore (blocks) {
  const core = new Hypercore(tmp())
  await core.ready()
  await core.append(blocks)
  return core
}

function mockNode (core, kp, opts = {}) {
  const keyHex = b4a.toString(core.key, 'hex')
  const entry = {
    drive: { core, db: { core }, closed: false, closing: false },
    blind: opts.blind === true,
    privacyTier: opts.privacyTier || 'public'
  }
  return {
    running: true,
    config: {
      storage: null,
      acceptMode: 'review',
      enableRelay: true,
      enableSeeding: true,
      enableAPI: true
    },
    metrics: { getSummary () { return {} }, toPrometheus () { return '' } },
    appRegistry: {
      apps: new Map(),
      has: (key) => !opts.notSeeded && key === keyHex,
      get: (key) => key === keyHex ? entry : null,
      catalog () { return [] },
      catalogForBroadcast () { return [] },
      _shouldRedactEntry (e, o = {}) {
        return e.blind === true ||
          (o.redactPrivate === true && String(e.privacyTier || 'public').toLowerCase() !== 'public')
      }
    },
    seededApps: new Map(),
    getStats () { return { running: true } },
    getHealthStatus () { return { healthy: true } },
    swarm: { keyPair: kp },
    keyPair: kp,
    relay: null,
    seeder: null,
    router: null,
    serviceRegistry: null,
    seedingRegistry: null,
    reputation: null,
    networkDiscovery: null,
    store: { close: async () => {}, replicate: () => {} },
    on () {},
    removeListener () {},
    emit () {}
  }
}

async function setupApi (t, node) {
  const api = new RelayAPI(node, { apiPort: 0, apiHost: '127.0.0.1', apiKey: 'proof-test' })
  await api.start()
  t.teardown(async () => {
    try { await api.stop() } catch {}
  })
  return api.server.address().port
}

function request (port, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: 'POST',
      path: '/api/proof/retrievability',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        let parsed
        try { parsed = JSON.parse(data) } catch { parsed = data }
        resolve({ statusCode: res.statusCode, body: parsed, headers: res.headers })
      })
    })
    req.on('error', reject)
    req.write(JSON.stringify(body))
    req.end()
  })
}

test('api retrievability proof: route helper maps exact public proof route', (t) => {
  t.alike(resolveRetrievabilityProofRoute('POST', '/api/proof/retrievability'), {
    kind: 'retrievability-proof'
  })

  t.is(resolveRetrievabilityProofRoute('GET', '/api/proof/retrievability'), null)
  t.is(resolveRetrievabilityProofRoute('POST', '/api/proof/retrievability/extra'), null)
  t.is(resolveRetrievabilityProofRoute('POST', '/api/proofs/retrievability'), null)
})

test('api retrievability proof: public HTTP proof verifies against drive key', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('bb'), b4a.from('ccc')])
  const relay = keyPair()
  const port = await setupApi(t, mockNode(core, relay))
  const challenge = nonce()

  const res = await request(port, {
    coreKey: b4a.toString(core.key, 'hex'),
    index: 2,
    nonce: b4a.toString(challenge, 'hex')
  })

  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.proofKind, PROOF_KIND_RETRIEVABILITY)
  t.is(res.body.relayPubkey, b4a.toString(relay.publicKey, 'hex'))

  const verifierCore = new Hypercore(tmp(), core.key)
  await verifierCore.ready()
  const verdict = await verifyStorageProof({
    verifierCore,
    response: res.body,
    expect: {
      driveKey: core.key,
      index: 2,
      nonce: challenge,
      relayPubkey: relay.publicKey,
      minLength: core.length
    }
  })

  t.ok(verdict.valid, 'HTTP proof verifies')
  await verifierCore.close()
  await core.close()
})

test('api retrievability proof: opt-in domain signature profile verifies', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('bb'), b4a.from('ccc')])
  const relay = keyPair()
  const port = await setupApi(t, mockNode(core, relay))
  const challenge = nonce()

  const res = await request(port, {
    coreKey: b4a.toString(core.key, 'hex'),
    index: 1,
    nonce: b4a.toString(challenge, 'hex'),
    signatureProfile: RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
  })

  t.is(res.statusCode, 200)
  t.is(res.body.ok, true)
  t.is(res.body.signatureProfile, RETRIEVABILITY_PROOF_SIGNATURE_PROFILE)

  const verifierCore = new Hypercore(tmp(), core.key)
  await verifierCore.ready()
  const verdict = await verifyStorageProof({
    verifierCore,
    response: res.body,
    expect: {
      driveKey: core.key,
      index: 1,
      nonce: challenge,
      relayPubkey: relay.publicKey,
      minLength: core.length
    }
  })

  t.ok(verdict.valid, 'domain-profile HTTP proof verifies')
  t.is(verdict.signatureProfile, RETRIEVABILITY_PROOF_SIGNATURE_PROFILE)
  await verifierCore.close()
  await core.close()
})

test('api retrievability proof: unsupported signature profile is a cheap 400', async (t) => {
  const core = await seededCore([b4a.from('a')])
  const relay = keyPair()
  const port = await setupApi(t, mockNode(core, relay))

  const res = await request(port, {
    coreKey: b4a.toString(core.key, 'hex'),
    index: 0,
    nonce: b4a.toString(nonce(), 'hex'),
    signatureProfile: 'unknown-proof-profile'
  })

  t.is(res.statusCode, 400)
  t.alike(res.body, { error: 'UNSUPPORTED_SIGNATURE_PROFILE' })
  await core.close()
})

test('api retrievability proof: oversized index is a cheap 400', async (t) => {
  const core = await seededCore([b4a.from('a')])
  const relay = keyPair()
  const port = await setupApi(t, mockNode(core, relay))

  const res = await request(port, {
    coreKey: b4a.toString(core.key, 'hex'),
    index: 2 ** 32,
    nonce: b4a.toString(nonce(), 'hex')
  })

  t.is(res.statusCode, 400)
  t.alike(res.body, { error: 'BAD_INDEX' })
  await core.close()
})

test('api retrievability proof: blind and private drives are indistinguishable from not-seeded', async (t) => {
  const blindCore = await seededCore([b4a.from('secret')])
  const blindPort = await setupApi(t, mockNode(blindCore, keyPair(), { blind: true }))
  const blind = await request(blindPort, {
    coreKey: b4a.toString(blindCore.key, 'hex'),
    index: 0,
    nonce: b4a.toString(nonce(), 'hex')
  })
  t.is(blind.statusCode, 404)
  t.alike(blind.body, { error: 'NOT_SEEDED' })

  const privateCore = await seededCore([b4a.from('private')])
  const privatePort = await setupApi(t, mockNode(privateCore, keyPair(), { privacyTier: 'private' }))
  const privateRes = await request(privatePort, {
    coreKey: b4a.toString(privateCore.key, 'hex'),
    index: 0,
    nonce: b4a.toString(nonce(), 'hex')
  })
  t.is(privateRes.statusCode, 404)
  t.alike(privateRes.body, { error: 'NOT_SEEDED' })

  await blindCore.close()
  await privateCore.close()
})
