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
  client.open = async () => ({ core, ready: async () => {} })
  let routeSeen = null
  client.callService = async (service, method, params) => {
    routeSeen = service + '.' + method
    return svc.prove(params, { remotePubkey: 'cl'.repeat(32) })
  }
  client._routeSeen = () => routeSeen
  return { client, core, keyHex, relayHex, relay }
}

test('proveSeeded: every sample verifies => ok true', async (t) => {
  const { client, keyHex, relayHex } = await harness()
  const r = await client.proveSeeded(keyHex, { relay: relayHex, samples: 4 })
  t.is(client._routeSeen(), 'storage-proof.prove', 'calls the storage-proof.prove route')
  t.ok(r.ok, 'overall ok')
  t.is(r.passed, r.total, 'all samples passed')
  t.is(r.total, 4)
  t.is(r.head, 5)
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
  await empty.close()
})

test('proveSeeded: client source does not import Node os builtin', async (t) => {
  const source = await readFile(new URL('../../packages/client/index.js', import.meta.url), 'utf8')
  t.absent(source.includes("import os from 'os'"), 'client source avoids Node os import')
  t.absent(source.includes('os.tmpdir()'), 'client source avoids os.tmpdir')
  t.ok(source.includes('function portableTmpdir'), 'client source has portable temp-dir helper')
})
