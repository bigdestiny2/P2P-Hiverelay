import test from 'brittle'
import createTestnet from '@hyperswarm/testnet'
import DHT from 'hyperdht'
import Protomux from 'protomux'
import b4a from 'b4a'
import {
  ForwardRelay,
  forwardStatusEncoding,
  forwardDataEncoding,
  forwardCloseEncoding,
  forwardOpenEncoding
} from '../../packages/core/core/protocol/forward-relay.js'

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
  await new Promise((resolve, reject) => { conn.on('open', resolve); conn.on('error', reject) })
  const mux = Protomux.from(conn)
  const ch = mux.createChannel({ protocol: 'hiverelay-forward', id: null })
  const state = { got: '', status: null }
  ch.addMessage({ encoding: forwardStatusEncoding, onmessage: (m) => { state.status = m } })
  const dataMsg = ch.addMessage({ encoding: forwardDataEncoding, onmessage: (m) => { state.got += b4a.toString(m.data) } })
  ch.addMessage({ encoding: forwardCloseEncoding })
  const openMsg = ch.addMessage({ encoding: forwardOpenEncoding })
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
