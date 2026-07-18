import test from 'brittle'
import net from 'net'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { EventEmitter } from 'events'
import NoiseSecretStream from '@hyperswarm/secret-stream'
import Protomux from 'protomux'
import c from 'compact-encoding'
import { OnionPeerListener, DEFAULT_PEER_VPORT } from 'p2p-hiverelay/transports/tor/peer-listener.js'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'

const SERVICE_ID = 'a'.repeat(56)
const KEY_BLOB = 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64')
const ALICE_PUB = 'a'.repeat(52)

/** Daemon-free control-port fake (same shape as tor-transport.test.js). */
class FakeControl extends EventEmitter {
  constructor () {
    super()
    this.commands = []
    this.destroyed = false
  }

  async connect () {}

  cmd (command, _timeout) {
    this.commands.push(command)
    const head = command.split(' ')[0]
    if (head === 'AUTHENTICATE') return Promise.resolve('250 OK')
    if (head === 'GETINFO') return Promise.resolve('250-version=0.4.9.6\n250 OK')
    if (head === 'ADD_ONION') {
      const lines = ['250-ServiceID=' + SERVICE_ID]
      if (command.startsWith('ADD_ONION NEW:')) lines.push('250-PrivateKey=' + KEY_BLOB)
      lines.push('250 OK')
      return Promise.resolve(lines.join('\n'))
    }
    return Promise.resolve('250 OK')
  }

  destroy () { this.destroyed = true }
}

/** Dummy TCP listener so _checkTorRunning succeeds without a real daemon. */
async function fakeSocks (t) {
  const server = net.createServer((s) => s.destroy())
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  t.teardown(() => { try { server.close() } catch {} })
  return server.address().port
}

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tor-peer-listener-test-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

/** Stubbed peer listener — binding behavior without real sockets. */
class StubPeerListener extends EventEmitter {
  constructor ({ host = '127.0.0.1', port = DEFAULT_PEER_VPORT } = {}) {
    super()
    this.host = host
    this.port = port
    this.running = false
    this.started = 0
    this.stopped = 0
  }

  async start () { this.started++; this.running = true }

  async stop () { this.stopped++; this.running = false }
}

function addOnionCmds (control) {
  return control.commands.filter((cmd) => cmd.startsWith('ADD_ONION'))
}

test('listener upgrades inbound TCP to a Noise XK peer stream — protomux rides it', async (t) => {
  const relayKP = NoiseSecretStream.keyPair()
  const clientKP = NoiseSecretStream.keyPair()
  const listener = new OnionPeerListener({ keyPair: relayKP, port: 0 })
  t.teardown(async () => { await listener.stop() })
  await listener.start()
  t.is(listener.running, true)
  t.ok(listener.port > 0)

  const connPromise = new Promise((resolve) => listener.once('connection', (stream, info) => resolve({ stream, info })))

  const socket = net.createConnection(listener.port, '127.0.0.1')
  const client = new NoiseSecretStream(true, socket, {
    keyPair: clientKP,
    remotePublicKey: relayKP.publicKey,
    pattern: 'XK'
  })
  t.teardown(() => { try { client.destroy() } catch {} })
  await new Promise((resolve) => client.on('handshake', resolve))

  const { stream, info } = await connPromise
  t.is(info.type, 'tor')
  t.is(info.isOnion, true)
  // Noise XK: the responder learns the initiator's identity from the handshake
  t.alike([...stream.remotePublicKey], [...clientKP.publicKey])
  t.alike([...client.remotePublicKey], [...relayKP.publicKey])

  // The peer protocol (Protomux channels) runs over the stream unchanged
  const serverMux = Protomux.from(stream)
  const clientMux = Protomux.from(client)
  const serverChannel = serverMux.createChannel({ protocol: 'hr-peer-test', id: null })
  const serverMsg = serverChannel.addMessage({
    encoding: c.string,
    onmessage: (text) => serverMsg.send('echo:' + text)
  })
  serverChannel.open()

  const clientChannel = clientMux.createChannel({ protocol: 'hr-peer-test', id: null })
  const gotEcho = new Promise((resolve) => {
    const clientMsg = clientChannel.addMessage({ encoding: c.string, onmessage: resolve })
    clientChannel.open()
    clientMsg.send('custody.ping')
  })

  t.is(await gotEcho, 'echo:custody.ping')
  await listener.stop()
  t.is(listener.running, false)
})

test('listener rejects a handshake aimed at a different relay identity', async (t) => {
  const relayKP = NoiseSecretStream.keyPair()
  const otherKP = NoiseSecretStream.keyPair()
  const clientKP = NoiseSecretStream.keyPair()
  const listener = new OnionPeerListener({ keyPair: relayKP, port: 0 })
  t.teardown(async () => { await listener.stop() })
  await listener.start()

  let connections = 0
  listener.on('connection', () => connections++)

  const socket = net.createConnection(listener.port, '127.0.0.1')
  const client = new NoiseSecretStream(true, socket, {
    keyPair: clientKP,
    remotePublicKey: otherKP.publicKey, // wrong expected responder key
    pattern: 'XK'
  })
  client.on('error', () => {})
  t.teardown(() => { try { client.destroy() } catch {} })

  await Promise.race([
    new Promise((resolve) => client.on('close', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000))
  ])
  await new Promise((resolve) => setTimeout(resolve, 100))
  t.is(connections, 0, 'failed handshake never surfaces as a peer connection')
})

test('listener enforces maxConnections at the socket layer', async (t) => {
  const relayKP = NoiseSecretStream.keyPair()
  const listener = new OnionPeerListener({ keyPair: relayKP, port: 0, maxConnections: 1 })
  t.teardown(async () => { await listener.stop() })
  await listener.start()

  const first = net.createConnection(listener.port, '127.0.0.1')
  first.on('error', () => {})
  t.teardown(() => { try { first.destroy() } catch {} })
  await new Promise((resolve) => first.on('connect', resolve))
  // let the accept land so the stream registers against the cap
  await new Promise((resolve) => setTimeout(resolve, 100))

  const second = net.createConnection(listener.port, '127.0.0.1')
  second.on('error', () => {})
  t.teardown(() => { try { second.destroy() } catch {} })
  await Promise.race([
    new Promise((resolve) => second.on('close', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000))
  ])
  t.is(second.destroyed, true, 'over-cap socket is refused')
  t.is(first.destroyed, false, 'first connection survives')
})

test('peer vport binding — stubbed listener is started, mapped, and stopped with the transport', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const control = new FakeControl()
  const stub = new StubPeerListener()
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    peerListener: stub,
    _controlFactory: () => control
  })
  await tt.start()
  t.is(stub.started, 1, 'listener bound before the hidden service')

  const add = addOnionCmds(control).pop()
  t.ok(add.includes('Port=80,127.0.0.1:9100'), 'read plane forwarded')
  t.ok(add.includes('Port=19737,127.0.0.1:19737'), 'peer vport forwarded to the listener')
  t.alike(tt.getInfo().vports, [80, 19737])

  // roster rebuilds keep the peer vport mapping
  await tt.addAuthClient(ALICE_PUB)
  const rebuild = addOnionCmds(control).pop()
  t.ok(rebuild.includes('Port=19737,127.0.0.1:19737'))
  t.ok(rebuild.includes('ClientAuthV3=' + ALICE_PUB))

  // inbound peer connections re-emit through the transport's connection event
  const seen = new Promise((resolve) => tt.once('connection', (stream, info) => resolve({ stream, info })))
  const fakeStream = { fake: true }
  stub.emit('connection', fakeStream, { type: 'tor', isOnion: true })
  const { stream, info } = await seen
  t.is(stream, fakeStream)
  t.is(info.isOnion, true)

  await tt.stop()
  t.is(stub.stopped, 1, 'listener stopped with the transport')
})

test('explicit vports config wins over the automatic peer mapping', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const control = new FakeControl()
  const stub = new StubPeerListener()
  const tt = new TorTransport({
    socksPort,
    keyFile: path.join(dir, 'hs-key.blob'),
    vports: [
      { vport: 80, targetHost: '127.0.0.1', targetPort: 9100 },
      { vport: 19737, targetHost: '127.0.0.1', targetPort: 29999 }
    ],
    peerListener: stub,
    _controlFactory: () => control
  })
  await tt.start()
  const add = addOnionCmds(control).pop()
  t.ok(add.includes('Port=19737,127.0.0.1:29999'), 'operator mapping kept')
  t.is(add.split('Port=19737').length - 1, 1, 'no duplicate peer vport entry')
  await tt.stop()
})

test('peer-vport config mapping — _effectiveVports shapes', async (t) => {
  // legacy single-port shape unchanged without a listener
  const legacy = new TorTransport({ localPort: 9100 })
  t.alike(legacy._effectiveVports(), [{ vport: 80, targetHost: '127.0.0.1', targetPort: 9100 }])

  // listener attached → peer vport appended after the read plane
  const withPeer = new TorTransport({ localPort: 9100, peerListener: new StubPeerListener() })
  t.alike(withPeer._effectiveVports(), [
    { vport: 80, targetHost: '127.0.0.1', targetPort: 9100 },
    { vport: 19737, targetHost: '127.0.0.1', targetPort: 19737 }
  ])

  // peer vport overridable; listener-only service (no read plane) works
  const peerOnly = new TorTransport({ peerListener: new StubPeerListener(), peerVport: 19738 })
  t.alike(peerOnly._effectiveVports(), [
    { vport: 19738, targetHost: '127.0.0.1', targetPort: 19737 }
  ])
})

test('peer-only hidden service — no read plane vport required', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const control = new FakeControl()
  const stub = new StubPeerListener({ port: 19737 })
  const tt = new TorTransport({
    socksPort,
    keyFile: path.join(dir, 'hs-key.blob'),
    peerListener: stub,
    _controlFactory: () => control
  })
  await tt.start()
  t.is(tt.onionAddress, SERVICE_ID + '.onion')
  const add = addOnionCmds(control).pop()
  t.ok(add.includes('Port=19737,127.0.0.1:19737'))
  t.absent(add.includes('Port=80,'), 'no read plane exposed')
  await tt.stop()
})
