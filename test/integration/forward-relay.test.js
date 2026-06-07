import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import DHT from 'hyperdht'
import Protomux from 'protomux'
import c from 'compact-encoding'
import b4a from 'b4a'
import { ForwardRelay } from '../../packages/core/core/protocol/forward-relay.js'

// Encodings must match packages/core/core/protocol/forward-relay.js, and the
// addMessage ORDER must match the server (status, data, close, open).
const statusEnc = { preencode (s, m) { c.uint.preencode(s, m.code); c.string.preencode(s, m.message || '') }, encode (s, m) { c.uint.encode(s, m.code); c.string.encode(s, m.message || '') }, decode (s) { return { code: c.uint.decode(s), message: c.string.decode(s) } } }
const dataEnc = { preencode (s, m) { c.buffer.preencode(s, m.data) }, encode (s, m) { c.buffer.encode(s, m.data) }, decode (s) { return { data: c.buffer.decode(s) } } }
const closeEnc = { preencode (s, m) { c.uint.preencode(s, m.reason || 0) }, encode (s, m) { c.uint.encode(s, m.reason || 0) }, decode (s) { return { reason: c.uint.decode(s) } } }
const openEnc = { preencode (s, m) { c.fixed32.preencode(s, m.target) }, encode (s, m) { c.fixed32.encode(s, m.target) }, decode (s) { return { target: c.fixed32.decode(s) } } }

const waitUntil = (fn, ms = 5000) => new Promise((resolve, reject) => {
  const t0 = Date.now()
  const iv = setInterval(() => { if (fn()) { clearInterval(iv); resolve() } else if (Date.now() - t0 > ms) { clearInterval(iv); reject(new Error('timeout')) } }, 25)
})

// Spin a relay host running ForwardRelay + an echo target, connect a raw
// forward-protocol client, return its channel handles.
async function harness (t, { enabled = true } = {}) {
  const testnet = await createTestnet(4, t)
  const boot = testnet.bootstrap

  const tDht = new DHT({ bootstrap: boot }); const tKp = DHT.keyPair()
  const tServer = tDht.createServer((conn) => { conn.on('error', () => {}); conn.on('data', (d) => { try { conn.write(b4a.concat([b4a.from('echo:'), d])) } catch (_) {} }) })
  await tServer.listen(tKp)

  const rDht = new DHT({ bootstrap: boot }); const rKp = DHT.keyPair()
  const fr = new ForwardRelay({ dht: rDht }, { enabled })
  const rServer = rDht.createServer((conn) => { try { fr.attach(conn) } catch (_) {} ; conn.on('error', () => {}) })
  await rServer.listen(rKp)

  const cDht = new DHT({ bootstrap: boot })
  const conn = cDht.connect(rKp.publicKey)
  await new Promise((res, rej) => { conn.on('open', res); conn.on('error', rej) })
  const mux = Protomux.from(conn)
  const ch = mux.createChannel({ protocol: 'hiverelay-forward', id: null })
  const state = { got: '', status: null }
  const statusMsg = ch.addMessage({ encoding: statusEnc, onmessage: (m) => { state.status = m } })
  const dataMsg = ch.addMessage({ encoding: dataEnc, onmessage: (m) => { state.got += b4a.toString(m.data) } })
  const closeMsg = ch.addMessage({ encoding: closeEnc })
  const openMsg = ch.addMessage({ encoding: openEnc })
  ch.open()

  t.teardown(async () => { try { fr.destroy() } catch (_) {} ; for (const d of [cDht, rDht, tDht]) { try { await d.destroy() } catch (_) {} } })
  return { tKp, openMsg, dataMsg, state }
}

test('forward-relay byte-bridges to a demand-dialled target', async (t) => {
  const { tKp, openMsg, dataMsg, state } = await harness(t)
  openMsg.send({ target: tKp.publicKey })
  await waitUntil(() => state.status !== null)
  t.is(state.status.code, 0, 'forward open accepted (STATUS=ok)')
  dataMsg.send({ data: b4a.from('ping') })
  await waitUntil(() => state.got.includes('echo:ping'))
  t.ok(state.got.includes('echo:ping'), 'bytes round-tripped buyer→relay→target→relay→buyer')
})

test('forward-relay refuses when disabled (fail-closed)', async (t) => {
  const { tKp, openMsg, state } = await harness(t, { enabled: false })
  openMsg.send({ target: tKp.publicKey })
  await waitUntil(() => state.status !== null)
  t.not(state.status.code, 0, 'disabled relay rejects the forward')
})
