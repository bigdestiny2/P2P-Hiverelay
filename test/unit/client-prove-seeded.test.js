/**
 * client.proveSeeded (Tier-2 client side) — RPC roundtrip + verdict aggregation.
 *
 * The crypto is already covered by proof-of-storage.test.js; here the real
 * StorageProofService.prove runs in-process over a shared real temp-dir core,
 * callService is stubbed to route into it, and proveSeeded's own verifier
 * sandbox (a real temp Corestore) verifies each response end-to-end. We assert
 * the happy path is ok, and that a tampered/short/failed relay flips ok=false.
 */
import test from 'brittle'
import Hypercore from 'hypercore'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import os from 'os'
import path from 'path'
import { readFile } from 'fs/promises'
import { HiveRelayClient } from 'p2p-hiverelay-client'
import { StorageProofService } from 'p2p-hiveservices/builtin/storage-proof-service.js'
import {
  PROOF_KIND_RETRIEVABILITY,
  RETRIEVABILITY_PROOF_LIMITATION,
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'

let _n = 0
const tmp = () => path.join(os.tmpdir(), 'hr-ps-' + process.pid + '-' + (_n++))
function relayKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

async function harness () {
  const core = new Hypercore(tmp())
  await core.ready()
  await core.append([b4a.from('a'), b4a.from('bb'), b4a.from('ccc'), b4a.from('dddd'), b4a.from('eeeee')])
  const keyHex = b4a.toString(core.key, 'hex')
  const relay = relayKeyPair()
  const relayHex = b4a.toString(relay.publicKey, 'hex')

  const svc = new StorageProofService()
  await svc.start({
    node: {
      keyPair: relay,
      appRegistry: {
        has: (k) => k === keyHex,
        get: (k) => (k === keyHex ? { drive: { core, db: { core }, closed: false, closing: false } } : null)
      }
    }
  })

  const client = Object.create(HiveRelayClient.prototype)
  client._started = true
  client._ensureStarted = () => {}
  client._serviceRequestId = 0
  client.relays = new Map([[relayHex, {}]])
  client._capabilityCache = new Map()
  client.open = async () => ({ core, ready: async () => {} })
  let routeSeen = null
  client.callService = async (service, method, params) => {
    routeSeen = service + '.' + method
    return svc.prove(params, { remotePubkey: 'cl'.repeat(32) })
  }
  client._routeSeen = () => routeSeen
  return { client, core, keyHex, relayHex, relay, svc }
}

test('proveSeeded: every sample verifies => ok true', async (t) => {
  const { client, keyHex, relayHex } = await harness()
  const r = await client.proveSeeded(keyHex, { relay: relayHex, samples: 4 })
  t.is(client._routeSeen(), 'storage-proof.prove', 'calls the storage-proof.prove route')
  t.ok(r.ok, 'overall ok')
  t.is(r.proofTransport, 'service')
  t.is(r.proofKind, PROOF_KIND_RETRIEVABILITY)
  t.is(r.proofLimit, RETRIEVABILITY_PROOF_LIMITATION)
  t.is(r.passed, r.total, 'all samples passed')
  t.is(r.total, 4)
  t.is(r.head, 5)
  t.ok(r.samples.every((sample) => sample.transport === 'service'), 'samples record service transport')
  t.ok(r.samples.every((sample) => sample.proofKind === PROOF_KIND_RETRIEVABILITY), 'samples carry proof kind')
})

test('proveSeeded: capability-advertised HTTP proof route is preferred over service RPC', async (t) => {
  const { client, keyHex, relayHex, svc } = await harness()
  client._capabilityCache.set('http://relay.test', {
    fetchedAt: Date.now(),
    relayInfo: {
      pubkey: relayHex,
      features: ['retrievability-proof-http']
    }
  })

  let httpCalls = 0
  let serviceCalls = 0
  client.callService = async () => {
    serviceCalls++
    throw new Error('service should not be called')
  }

  const fetchBefore = globalThis.fetch
  globalThis.fetch = async (url, opts = {}) => {
    httpCalls++
    t.is(url, 'http://relay.test/api/proof/retrievability')
    t.is(opts.method, 'POST')
    const params = JSON.parse(opts.body)
    const proof = await svc.prove(params, { caller: 'http-test' })
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, ...proof })
    }
  }
  t.teardown(() => { globalThis.fetch = fetchBefore })

  const r = await client.proveSeeded(keyHex, { relay: relayHex, samples: 2 })
  t.ok(r.ok, 'overall ok')
  t.is(r.proofTransport, 'http')
  t.is(httpCalls, 2, 'one HTTP proof call per sample')
  t.is(serviceCalls, 0, 'service route was not used')
  t.ok(r.samples.every((sample) => sample.transport === 'http'), 'samples record HTTP transport')
})

test('proveSeeded: opt-in proofSignatureProfile is sent through HTTP proofs', async (t) => {
  const { client, keyHex, relayHex, svc } = await harness()
  client._capabilityCache.set('http://relay.test', {
    fetchedAt: Date.now(),
    relayInfo: {
      pubkey: relayHex,
      features: ['retrievability-proof-http', 'retrievability-proof-domain-v1']
    }
  })

  const profiles = []
  const fetchBefore = globalThis.fetch
  globalThis.fetch = async (url, opts = {}) => {
    t.is(url, 'http://relay.test/api/proof/retrievability')
    const params = JSON.parse(opts.body)
    profiles.push(params.signatureProfile)
    const proof = await svc.prove(params, { caller: 'http-profile-test' })
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ok: true, ...proof })
    }
  }
  t.teardown(() => { globalThis.fetch = fetchBefore })

  const r = await client.proveSeeded(keyHex, {
    relay: relayHex,
    samples: 2,
    proofSignatureProfile: RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
  })
  t.ok(r.ok, 'overall ok')
  t.is(r.proofTransport, 'http')
  t.is(profiles.length, 2, 'one profiled HTTP proof request per sample')
  t.ok(profiles.every((profile) => profile === RETRIEVABILITY_PROOF_SIGNATURE_PROFILE), 'HTTP requests carry the requested profile')
  t.ok(r.samples.every((sample) => sample.signatureProfile === RETRIEVABILITY_PROOF_SIGNATURE_PROFILE), 'sample verdicts expose the verified profile')
})

test('proveSeeded: tampered relay signature => ok false, all samples invalid', async (t) => {
  const { client, keyHex, relayHex } = await harness()
  const orig = client.callService
  client.callService = async (s, m, p) => {
    const resp = await orig(s, m, p)
    // Corrupt the last hex nibble of the signature.
    resp.signature = resp.signature.replace(/.$/, (ch) => (ch === '0' ? '1' : '0'))
    return resp
  }
  const r = await client.proveSeeded(keyHex, { relay: relayHex, samples: 3 })
  t.absent(r.ok, 'overall not ok')
  t.ok(r.samples.every((s) => !s.valid), 'every sample rejected')
})

test('proveSeeded: relay errors on every prove => ok false (CALL_FAILED)', async (t) => {
  const { client, keyHex, relayHex } = await harness()
  client.callService = async () => { throw new Error('SERVICE_TIMEOUT') }
  const r = await client.proveSeeded(keyHex, { relay: relayHex, samples: 2 })
  t.absent(r.ok)
  t.ok(r.samples.every((s) => /CALL_FAILED/.test(s.reason)), 'samples report CALL_FAILED')
})

test('proveSeeded: NO_RELAY when not connected to the named relay', async (t) => {
  const { client, keyHex } = await harness()
  await t.exception(client.proveSeeded(keyHex, { relay: 'de'.repeat(32) }), /NO_RELAY/)
})

test('proveSeeded: unsupported proofSignatureProfile is rejected locally', async (t) => {
  const { client, keyHex, relayHex } = await harness()
  await t.exception(
    client.proveSeeded(keyHex, { relay: relayHex, proofSignatureProfile: 'unknown-proof-profile' }),
    /proofSignatureProfile/
  )
})

test('proveSeeded: requires opts.relay', async (t) => {
  const { client, keyHex } = await harness()
  await t.exception(client.proveSeeded(keyHex, {}), /opts\.relay/)
})

test('proveSeeded: empty drive (head 0) => ok false, EMPTY_DRIVE', async (t) => {
  const { client, relayHex } = await harness()
  const empty = new Hypercore(tmp())
  await empty.ready()
  client.open = async () => ({ core: empty, ready: async () => {} })
  const r = await client.proveSeeded(b4a.toString(empty.key, 'hex'), { relay: relayHex, samples: 3 })
  t.absent(r.ok); t.is(r.reason, 'EMPTY_DRIVE'); t.is(r.total, 0)
  t.is(r.proofKind, PROOF_KIND_RETRIEVABILITY)
  t.is(r.proofTransport, 'service')
  await empty.close()
})

test('proveSeeded: sample indices are sodium-backed, distinct, and clamped to head', (t) => {
  const client = Object.create(HiveRelayClient.prototype)
  const originalRandom = Math.random
  Math.random = () => { throw new Error('Math.random should not be used for proof sampling') }
  t.teardown(() => { Math.random = originalRandom })

  const all = client._sampleIndices(5, 16)
  t.is(all.length, 5, 'sampling more than the head clamps to every block')
  t.alike([...all].sort((a, b) => a - b), [0, 1, 2, 3, 4], 'all indices are distinct and in range')

  const partial = client._sampleIndices(64, 8)
  t.is(partial.length, 8, 'requested sample count is preserved below the head')
  t.is(new Set(partial).size, partial.length, 'partial sample has no duplicates')
  t.ok(partial.every(index => Number.isInteger(index) && index >= 0 && index < 64), 'partial sample stays in range')

  t.alike(client._sampleIndices(0, 3), [], 'empty head samples nothing')
})

test('proveSeeded: client source does not import Node os builtin', async (t) => {
  const source = await readFile(new URL('../../packages/client/index.js', import.meta.url), 'utf8')
  t.absent(source.includes("import os from 'os'"), 'client source avoids Node os import')
  t.absent(source.includes('os.tmpdir()'), 'client source avoids os.tmpdir')
  t.ok(source.includes('function portableTmpdir'), 'client source has portable temp-dir helper')
  t.absent(source.includes('Math.random'), 'client source avoids predictable Math.random identifiers')
  t.ok(source.includes('function randomNameSuffix'), 'client source has sodium-backed name suffix helper')
})
