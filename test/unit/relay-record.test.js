/**
 * Relay record — DHT-resolvable relay self-description (iroh adoption Phase 1).
 * Covers the codec, resolveRelayRecord over a fake hyperdht, and
 * RelayNode.publishRelayRecord wiring (mutablePut on the relay's keyPair).
 */

import test from 'brittle'
import b4a from 'b4a'
import z32 from 'z32'
import {
  encodeRelayRecord, decodeRelayRecord, relayRecordHasContent, resolveRelayRecord, MAX_RECORD_BYTES
} from 'p2p-hiverelay/core/relay-node/relay-record.js'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

const ROOM = z32.encode(b4a.alloc(32, 7)) // valid 52-char z32
const GW = 'https://relay.example:9100'

test('encode/decode round-trips gatewayUrl + indexRoom', (t) => {
  const buf = encodeRelayRecord({ gatewayUrl: GW + '/', indexRoom: ROOM })
  t.ok(b4a.isBuffer(buf))
  const rec = decodeRelayRecord(buf)
  t.is(rec.gatewayUrl, GW, 'trailing slash stripped')
  t.is(rec.indexRoom, ROOM)
})

test('encode drops invalid fields (non-http gateway, non-z32 room)', (t) => {
  t.is(decodeRelayRecord(encodeRelayRecord({ gatewayUrl: 'ftp://x', indexRoom: 'nope' })).gatewayUrl, null)
  t.is(decodeRelayRecord(encodeRelayRecord({ gatewayUrl: 'ftp://x', indexRoom: 'nope' })).indexRoom, null)
  const onlyGw = decodeRelayRecord(encodeRelayRecord({ gatewayUrl: GW }))
  t.is(onlyGw.gatewayUrl, GW)
  t.is(onlyGw.indexRoom, null)
})

test('encode throws over the size cap', (t) => {
  t.exception(() => encodeRelayRecord({ gatewayUrl: 'https://' + 'a'.repeat(MAX_RECORD_BYTES) + '.example' }))
})

test('decode returns null on garbage / wrong version / null', (t) => {
  t.is(decodeRelayRecord(null), null)
  t.is(decodeRelayRecord(b4a.from('not json', 'utf8')), null)
  t.is(decodeRelayRecord(b4a.from(JSON.stringify({ v: 99, g: GW }), 'utf8')), null)
})

test('relayRecordHasContent gates empty records', (t) => {
  t.ok(relayRecordHasContent({ gatewayUrl: GW }))
  t.ok(relayRecordHasContent({ indexRoom: ROOM }))
  t.absent(relayRecordHasContent({}))
  t.absent(relayRecordHasContent({ gatewayUrl: 'ftp://x', indexRoom: 'nope' }))
})

test('resolveRelayRecord verifies via hyperdht mutableGet + decodes', async (t) => {
  const pub = b4a.alloc(32, 3)
  const fakeDht = {
    async mutableGet (key) {
      t.ok(b4a.equals(key, pub), 'resolves by the relay pubkey')
      return { value: encodeRelayRecord({ gatewayUrl: GW, indexRoom: ROOM }), seq: 1 }
    }
  }
  const rec = await resolveRelayRecord(fakeDht, pub)
  t.is(rec.gatewayUrl, GW)
  t.is(rec.indexRoom, ROOM)
  // hex pubkey accepted too
  t.is((await resolveRelayRecord(fakeDht, b4a.toString(pub, 'hex'))).indexRoom, ROOM)
})

test('resolveRelayRecord returns null on not-found / bad key / no dht', async (t) => {
  t.is(await resolveRelayRecord(null, b4a.alloc(32, 1)), null)
  t.is(await resolveRelayRecord({ async mutableGet () { return null } }, b4a.alloc(32, 1)), null)
  t.is(await resolveRelayRecord({ async mutableGet () { throw new Error('dht down') } }, b4a.alloc(32, 1)), null)
  t.is(await resolveRelayRecord({ mutableGet () {} }, b4a.alloc(8, 1)), null, 'rejects non-32-byte key')
})

// ── publishRelayRecord wiring (stub node, no full RelayNode construction) ──
function stubNode ({ gatewayUrl = GW, indexRoom = ROOM, dht = true } = {}) {
  const puts = []
  const keyPair = { publicKey: b4a.alloc(32, 5), secretKey: b4a.alloc(64, 6) }
  return {
    puts,
    keyPair,
    indexRoom,
    config: { gatewayUrl },
    swarm: dht ? { dht: { async mutablePut (kp, value) { puts.push({ kp, value }) } } } : null,
    emit () {}
  }
}

test('publishRelayRecord mutablePuts the encoded record on the relay keyPair', async (t) => {
  const node = stubNode()
  const ok = await RelayNode.prototype.publishRelayRecord.call(node)
  t.is(ok, true)
  t.is(node.puts.length, 1)
  t.is(node.puts[0].kp, node.keyPair, 'signed with the relay identity keyPair')
  const decoded = decodeRelayRecord(node.puts[0].value)
  t.is(decoded.gatewayUrl, GW)
  t.is(decoded.indexRoom, ROOM)
})

test('publishRelayRecord no-ops when there is nothing to advertise or no dht', async (t) => {
  const empty = stubNode({ gatewayUrl: null, indexRoom: null })
  t.is(await RelayNode.prototype.publishRelayRecord.call(empty), false)
  t.is(empty.puts.length, 0)
  const noDht = stubNode({ dht: false })
  t.is(await RelayNode.prototype.publishRelayRecord.call(noDht), false)
})
