import test from 'brittle'
import net from 'net'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { EventEmitter } from 'events'
import { TorTransport, TorControl, TorHealth, parseTorVersion, versionAtLeast } from 'p2p-hiverelay/transports/tor/index.js'

const SERVICE_ID = 'a'.repeat(56)
const KEY_BLOB = 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64')
const ALICE_PUB = 'a'.repeat(52)
const BOB_PUB = 'b'.repeat(52)

/** Daemon-free control-port fake. Records commands, answers the subset we use. */
class FakeControl extends EventEmitter {
  constructor ({ version = '0.4.9.6', failSetConf = false, failAddOnionAt = [] } = {}) {
    super()
    this.version = version
    this.failSetConf = failSetConf
    this.failAddOnionAt = new Set(failAddOnionAt)
    this.addOnionCount = 0
    this.commands = []
    this.destroyed = false
  }

  async connect () {}

  cmd (command, _timeout) {
    this.commands.push(command)
    const head = command.split(' ')[0]
    if (head === 'AUTHENTICATE') return Promise.resolve('250 OK')
    if (head === 'GETINFO') return Promise.resolve('250-version=' + this.version + '\n250 OK')
    if (head === 'SETCONF') {
      return this.failSetConf
        ? Promise.reject(new Error('513 Unacceptable option value: Failed to configure rendezvous options'))
        : Promise.resolve('250 OK')
    }
    if (head === 'SETEVENTS') return Promise.resolve('250 OK')
    if (head === 'DEL_ONION') return Promise.resolve('250 OK')
    if (head === 'ADD_ONION') {
      this.addOnionCount++
      if (this.failAddOnionAt.has(this.addOnionCount)) {
        return Promise.reject(new Error('injected ADD_ONION failure'))
      }
      const lines = ['250-ServiceID=' + SERVICE_ID]
      if (command.startsWith('ADD_ONION NEW:')) lines.push('250-PrivateKey=' + KEY_BLOB)
      lines.push('250 OK')
      return Promise.resolve(lines.join('\n'))
    }
    return Promise.resolve('250 OK')
  }

  destroy () { this.destroyed = true }
}

function fakeFactory (opts) {
  const control = new FakeControl(opts)
  return { control, factory: () => control }
}

/** Dummy TCP listener so _checkTorRunning succeeds without a real daemon. */
async function fakeSocks (t) {
  const server = net.createServer((s) => s.destroy())
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  t.teardown(() => { try { server.close() } catch {} })
  return server.address().port
}

function tmpdir (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tor-transport-test-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  return dir
}

test('constructor defaults — legacy v1 shape', async (t) => {
  const tt = new TorTransport()
  t.is(tt.socksPort, 9050)
  t.is(tt.controlPort, 9051)
  t.is(tt.keyFile, null)
  t.is(tt.vports, null)
  t.is(tt.minDaemonVersion, null)
  t.is(tt.health, TorHealth.DISABLED)
  t.is(tt.running, false)
  t.alike(tt.clientAuthKeys, [])
})

test('parseTorVersion + versionAtLeast', async (t) => {
  t.alike(parseTorVersion('0.4.9.6'), [0, 4, 9, 6])
  t.alike(parseTorVersion('0.4.9.5-alpha-dev'), [0, 4, 9, 5])
  t.is(parseTorVersion('garbage'), null)
  t.is(versionAtLeast('0.4.9.6', '0.4.9.5'), true)
  t.is(versionAtLeast('0.4.9.5', '0.4.9.5'), true)
  t.is(versionAtLeast('0.4.8.12', '0.4.9.5'), false)
  t.is(versionAtLeast('0.5.0.1', '0.4.9.5'), true)
})

test('version floor fails closed', async (t) => {
  const socksPort = await fakeSocks(t)
  const { control, factory } = fakeFactory({ version: '0.4.8.2' })
  const tt = new TorTransport({ socksPort, minDaemonVersion: '0.4.9.5', _controlFactory: factory })
  await t.exception(tt.start(), /below floor 0\.4\.9\.5/)
  t.is(tt.running, false)
  t.ok(control.commands.some((c) => c === 'GETINFO version'))
})

test('legacy ephemeral mode — ADD_ONION NEW:BEST, no key written', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, localPort: 9100, _controlFactory: factory })
  await tt.start()
  t.is(tt.onionAddress, SERVICE_ID + '.onion')
  t.is(tt.running, true)
  const add = control.commands.find((c) => c.startsWith('ADD_ONION'))
  t.ok(add.startsWith('ADD_ONION NEW:BEST'))
  t.ok(add.includes('Port=80,127.0.0.1:9100'))
  t.is(fs.existsSync(path.join(dir, 'hs-key.blob')), false)
  await tt.stop()
})

test('persistent key custody — mint, store 0600, restore with same blob', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const keyFile = path.join(dir, 'tor', 'hs-key.blob')

  const { control: c1, factory: f1 } = fakeFactory({})
  const tt1 = new TorTransport({ socksPort, localPort: 9100, keyFile, _controlFactory: f1 })
  await tt1.start()
  t.is(fs.readFileSync(keyFile, 'utf8').trim(), KEY_BLOB)
  t.is(fs.statSync(keyFile).mode & 0o777, 0o600)
  t.ok(c1.commands.find((c) => c.startsWith('ADD_ONION')).startsWith('ADD_ONION NEW:ED25519-V3'))
  await tt1.stop()

  const { control: c2, factory: f2 } = fakeFactory({})
  const tt2 = new TorTransport({ socksPort, localPort: 9100, keyFile, _controlFactory: f2 })
  await tt2.start()
  t.ok(c2.commands.find((c) => c.startsWith('ADD_ONION')).startsWith('ADD_ONION ' + KEY_BLOB))
  t.is(tt2.onionAddress, SERVICE_ID + '.onion')
  await tt2.stop()
})

test('corrupt key file fails closed — no silent re-identity', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const keyFile = path.join(dir, 'hs-key.blob')
  fs.writeFileSync(keyFile, 'garbage-not-a-key\n')
  const { factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, localPort: 9100, keyFile, _controlFactory: factory })
  await t.exception(tt.start(), /corrupt tor key file/)
  t.is(tt.running, false)
})

test('multi-vport + client auth command shape (Flags=V3Auth required)', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    keyFile: path.join(dir, 'hs-key.blob'),
    vports: [
      { vport: 80, targetHost: '127.0.0.1', targetPort: 9100 },
      { vport: 19737, targetHost: '127.0.0.1', targetPort: 19737 }
    ],
    clientAuthKeys: [ALICE_PUB],
    maxStreams: 64,
    _controlFactory: factory
  })
  await tt.start()
  const add = control.commands.find((c) => c.startsWith('ADD_ONION'))
  t.ok(add.includes('Flags=V3Auth'))
  t.ok(add.includes('Port=80,127.0.0.1:9100'))
  t.ok(add.includes('Port=19737,127.0.0.1:19737'))
  t.ok(add.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(add.includes('MaxStreams=64'))
  await tt.stop()
})

test('roster add/remove rebuilds service with same address and updated ClientAuthV3 set', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, localPort: 9100, keyFile: path.join(dir, 'hs-key.blob'), _controlFactory: factory })
  await tt.start()

  await tt.addAuthClient(ALICE_PUB)
  const del = control.commands.filter((c) => c.startsWith('DEL_ONION'))
  t.is(del.length, 1)
  const rebuild = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(rebuild.includes('ClientAuthV3=' + ALICE_PUB))
  t.is(tt.onionAddress, SERVICE_ID + '.onion')
  t.alike(tt.listAuthClients(), [ALICE_PUB])

  await tt.addAuthClient(BOB_PUB)
  const rebuild2 = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(rebuild2.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(rebuild2.includes('ClientAuthV3=' + BOB_PUB))

  await tt.removeAuthClient(ALICE_PUB)
  const rebuild3 = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.absent(rebuild3.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(rebuild3.includes('ClientAuthV3=' + BOB_PUB))
  t.alike(tt.listAuthClients(), [BOB_PUB])

  await t.exception(tt.addAuthClient('not-a-key'), /invalid x25519/)
  await tt.stop()
})

test('restricted discovery stays fail-closed with an empty roster', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile: path.join(dir, 'auth-roster.json'),
    _controlFactory: factory
  })
  await tt.start()

  const initial = control.commands.find((c) => c.startsWith('ADD_ONION'))
  t.ok(initial.includes('Flags=V3Auth'), 'empty persisted roster never creates a public descriptor')
  const guard = initial.match(/ClientAuthV3=([a-z2-7]{52})/)
  t.ok(guard, 'an unreachable guard credential closes the empty roster')
  t.alike(tt.listAuthClients(), [], 'guard is not exposed as an enrolled client')
  t.is(tt.isRestrictedDiscoveryActive(), true)

  await tt.addAuthClient(ALICE_PUB)
  const enrolled = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(enrolled.includes('ClientAuthV3=' + ALICE_PUB))
  t.absent(enrolled.includes('ClientAuthV3=' + guard[1]), 'guard leaves the live roster once a real client exists')

  await tt.removeAuthClient(ALICE_PUB)
  const emptied = control.commands.filter((c) => c.startsWith('ADD_ONION')).pop()
  t.ok(emptied.includes('Flags=V3Auth'), 'removing the final client remains closed')
  t.absent(emptied.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(emptied.includes('ClientAuthV3=' + guard[1]))
  t.alike(tt.listAuthClients(), [])

  const info = tt.getInfo()
  t.is(info.restrictedDiscovery, true)
  t.is(info.authClients, 0)
  await tt.stop()
})

test('roster rebuild failure restores the live and persisted previous roster', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const rosterFile = path.join(dir, 'auth-roster.json')
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile,
    _controlFactory: factory
  })
  await tt.start()
  await tt.addAuthClient(ALICE_PUB)

  control.failAddOnionAt.add(control.addOnionCount + 1)
  await t.exception(tt.addAuthClient(BOB_PUB), /injected ADD_ONION failure/)

  t.alike(tt.listAuthClients(), [ALICE_PUB], 'failed mutation does not commit in memory')
  const persisted = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.alike(persisted.keys.filter((entry) => !entry.revokedAtMs).map((entry) => entry.pub), [ALICE_PUB])
  const restored = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.ok(restored.includes('ClientAuthV3=' + ALICE_PUB), 'previous service roster is recreated')
  t.absent(restored.includes('ClientAuthV3=' + BOB_PUB))
  t.is(tt.health, TorHealth.KEY_LOADED, 'rebuilt endpoint must re-qualify before advertisement')
  await tt.stop()
})

test('restricted discovery activation failure leaves a running public service honest', async (t) => {
  const socksPort = await fakeSocks(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    _controlFactory: factory
  })
  await tt.start()
  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' first')
  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' second')
  t.is(tt.health, TorHealth.READY)

  await t.exception(tt.addAuthClient(ALICE_PUB), /requires persistent keyFile mode/)
  t.is(tt.isRestrictedDiscoveryActive(), false)
  t.alike(tt.listAuthClients(), [])
  t.is(tt.health, TorHealth.READY, 'unchanged public service keeps its established health')
  const live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.absent(live.includes('Flags=V3Auth'))
  await tt.stop()
})

test('static client auth keys survive file-roster mutations', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile: path.join(dir, 'auth-roster.json'),
    clientAuthKeys: [ALICE_PUB],
    _controlFactory: factory
  })
  await tt.start()

  await tt.addAuthClient(BOB_PUB)
  let live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.ok(live.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(live.includes('ClientAuthV3=' + BOB_PUB))
  t.alike(tt.listAuthClients(), [ALICE_PUB, BOB_PUB])

  await tt.removeAuthClient(BOB_PUB)
  live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.ok(live.includes('ClientAuthV3=' + ALICE_PUB))
  t.absent(live.includes('ClientAuthV3=' + BOB_PUB))
  t.alike(tt.listAuthClients(), [ALICE_PUB])

  const rebuildsBeforeStaticRemoval = control.addOnionCount
  t.alike(await tt.removeAuthClient(ALICE_PUB), [ALICE_PUB])
  t.is(control.addOnionCount, rebuildsBeforeStaticRemoval, 'runtime roster cannot revoke a configured key')
  await tt.stop()
})

test('roster save failure rolls the live service back and the queue continues', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const rosterFile = path.join(dir, 'auth-roster.json')
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile,
    _controlFactory: factory
  })
  await tt.start()
  await tt.addAuthClient(ALICE_PUB)

  const realSave = tt._roster.save.bind(tt._roster)
  tt._roster.save = async () => { throw new Error('injected roster save failure') }
  await t.exception(tt.addAuthClient(BOB_PUB), /injected roster save failure/)
  t.alike(tt.listAuthClients(), [ALICE_PUB])
  let persisted = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.alike(persisted.keys.filter((entry) => !entry.revokedAtMs).map((entry) => entry.pub), [ALICE_PUB])
  const live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.ok(live.includes('ClientAuthV3=' + ALICE_PUB))
  t.absent(live.includes('ClientAuthV3=' + BOB_PUB))

  tt._roster.save = realSave
  await tt.addAuthClient(BOB_PUB)
  persisted = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.alike(persisted.keys.filter((entry) => !entry.revokedAtMs).map((entry) => entry.pub), [ALICE_PUB, BOB_PUB])
  await tt.stop()
})

test('failed roster removal restores the previous live authorization set', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile: path.join(dir, 'auth-roster.json'),
    _controlFactory: factory
  })
  await tt.start()
  await tt.addAuthClient(ALICE_PUB)
  await tt.addAuthClient(BOB_PUB)

  control.failAddOnionAt.add(control.addOnionCount + 1)
  await t.exception(tt.removeAuthClient(ALICE_PUB), /injected ADD_ONION failure/)
  t.alike(tt.listAuthClients(), [ALICE_PUB, BOB_PUB])
  const live = control.commands.filter((command) => command.startsWith('ADD_ONION')).pop()
  t.ok(live.includes('ClientAuthV3=' + ALICE_PUB))
  t.ok(live.includes('ClientAuthV3=' + BOB_PUB))
  await tt.stop()
})

test('throwing roster observers cannot roll back an already committed mutation', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { factory } = fakeFactory({})
  const rosterFile = path.join(dir, 'auth-roster.json')
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    rosterFile,
    _controlFactory: factory
  })
  await tt.start()
  tt.on('roster-changed', () => { throw new Error('injected observer failure') })

  await t.exception(tt.addAuthClient(ALICE_PUB), /injected observer failure/)
  t.alike(tt.listAuthClients(), [ALICE_PUB], 'observer runs after the commit boundary')
  const persisted = JSON.parse(fs.readFileSync(rosterFile, 'utf8'))
  t.alike(persisted.keys.filter((entry) => !entry.revokedAtMs).map((entry) => entry.pub), [ALICE_PUB])

  tt.removeAllListeners('roster-changed')
  await tt.addAuthClient(BOB_PUB)
  t.alike(tt.listAuthClients(), [ALICE_PUB, BOB_PUB], 'queue continues after observer rejection')
  await tt.stop()
})

test('concurrent roster mutations are serialized as complete rebuild transactions', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    _controlFactory: factory
  })
  await tt.start()

  await Promise.all([
    tt.addAuthClient(ALICE_PUB),
    tt.addAuthClient(BOB_PUB)
  ])

  const rebuildCommands = control.commands
    .filter((command) => command.startsWith('ADD_ONION') || command.startsWith('DEL_ONION'))
    .slice(1)
    .map((command) => command.split(' ')[0])
  t.alike(rebuildCommands, ['DEL_ONION', 'ADD_ONION', 'DEL_ONION', 'ADD_ONION'])
  t.alike(tt.listAuthClients(), [ALICE_PUB, BOB_PUB])
  await tt.stop()
})

test('health probe cannot bypass descriptor uploads after a roster rebuild', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  let probeConnections = 0
  const tt = new TorTransport({
    socksPort,
    localPort: 9100,
    keyFile: path.join(dir, 'hs-key.blob'),
    health: {
      probeVport: 80,
      minDescriptorUploads: 2,
      probeIntervalMs: 60_000
    },
    _controlFactory: factory,
    _probeConnectionFactory: async () => {
      probeConnections++
      return { socket: { destroy () {} } }
    }
  })
  await tt.start()

  await tt._probeNow()
  t.is(probeConnections, 0)
  t.is(tt.health, TorHealth.KEY_LOADED)
  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' first')
  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' second')
  await new Promise((resolve) => setTimeout(resolve, 0))
  t.is(probeConnections, 1)
  t.is(tt.health, TorHealth.READY)

  await tt.addAuthClient(ALICE_PUB)
  t.is(tt.health, TorHealth.KEY_LOADED)
  await tt._probeNow()
  t.is(probeConnections, 1, 'old descriptor reachability cannot re-qualify the rebuilt roster')
  t.is(tt.health, TorHealth.KEY_LOADED)
  await tt.stop()
})

test('health — descriptor uploads drive readiness without probe vport', async (t) => {
  const socksPort = await fakeSocks(t)
  const dir = tmpdir(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, localPort: 9100, keyFile: path.join(dir, 'hs-key.blob'), _controlFactory: factory })
  const states = []
  tt.on('health', (s) => states.push(s))
  await tt.start()
  t.is(tt.health, TorHealth.KEY_LOADED)

  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' xyz')
  t.is(tt.health, TorHealth.KEY_LOADED) // minDescriptorUploads = 2
  control.emit('event', 'HS_DESC UPLOADED ' + SERVICE_ID + ' abc')
  t.is(tt.health, TorHealth.READY) // no probeVport → uploads are the signal
  t.ok(states.includes(TorHealth.DESCRIPTOR_UPLOADED))

  const info = tt.getInfo()
  t.is(info.health, TorHealth.READY)
  t.is(info.persistent, true)
  t.is(info.authClients, 0)
  t.is(info.descriptorUploads, 2)
  await tt.stop()
  t.is(tt.getInfo().health, TorHealth.DISABLED)
})

test('PoW — SETCONF applied; failure surfaces with HiddenServiceDir guidance', async (t) => {
  const socksPort = await fakeSocks(t)
  const { control, factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, minDaemonVersion: '0.4.9.5', pow: { enabled: true, queueRate: 250, queueBurst: 1000 }, _controlFactory: factory })
  await tt.start()
  const setconf = control.commands.find((c) => c.startsWith('SETCONF'))
  t.ok(setconf.includes('HiddenServicePoWDefensesEnabled=1'))
  t.ok(setconf.includes('HiddenServicePoWQueueRate=250'))
  t.ok(setconf.includes('HiddenServicePoWQueueBurst=1000'))
  await tt.stop()

  const { factory: factory2 } = fakeFactory({ failSetConf: true })
  const tt2 = new TorTransport({ socksPort, minDaemonVersion: '0.4.9.5', pow: { enabled: true }, _controlFactory: factory2 })
  await t.exception(tt2.start(), /requires a HiddenServiceDir/)
})

test('getInfo legacy shape preserved', async (t) => {
  const socksPort = await fakeSocks(t)
  const { factory } = fakeFactory({})
  const tt = new TorTransport({ socksPort, localPort: 9100, _controlFactory: factory })
  await tt.start()
  const info = tt.getInfo()
  t.is(info.running, true)
  t.is(info.socksProxy, '127.0.0.1:' + socksPort)
  t.is(info.onionAddress, SERVICE_ID + '.onion')
  t.is(info.activeConnections, 0)
  t.is(info.persistent, false)
  await tt.stop()
})

test('TorControl real parser — events dispatch immediately, replies route, errors reject', async (t) => {
  // Fake control-protocol server: answers commands, pushes events spontaneously
  const received = []
  let conn = null
  const server = net.createServer((sock) => {
    conn = sock
    let buf = ''
    sock.on('data', (d) => {
      buf += d.toString()
      for (;;) {
        const idx = buf.indexOf('\r\n')
        if (idx === -1) break
        const line = buf.slice(0, idx)
        buf = buf.slice(idx + 2)
        received.push(line)
        if (line.startsWith('AUTHENTICATE')) {
          sock.write('250 OK\r\n')
          // spontaneous event AFTER the command completed — must be dispatched
          // immediately, not buffered until the next command
          setTimeout(() => sock.write('650 HS_DESC UPLOADED abc123\r\n'), 20)
        } else if (line.startsWith('GETINFO')) {
          // interleave an event inside the reply window
          sock.write('650 HS_DESC UPLOADED during\r\n')
          sock.write('250-version=0.4.9.6\r\n250 OK\r\n')
        } else if (line.startsWith('BADCMD')) {
          sock.write('512 syntax error\r\n')
        }
      }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const port = server.address().port
  t.teardown(() => { try { conn && conn.destroy() } catch {} try { server.close() } catch {} })

  const ctl = new TorControl({ host: '127.0.0.1', port })
  const events = []
  ctl.on('event', (line) => events.push(line))
  await ctl.connect()

  const auth = await ctl.cmd('AUTHENTICATE deadbeef')
  t.is(auth, '250 OK')

  // event pushed after AUTHENTICATE completed — arrives without another command
  await new Promise((resolve) => {
    const iv = setInterval(() => { if (events.length) { clearInterval(iv); resolve() } }, 10)
    setTimeout(() => { clearInterval(iv); resolve() }, 2000)
  })
  t.is(events[0], 'HS_DESC UPLOADED abc123')

  const info = await ctl.cmd('GETINFO version')
  t.ok(info.includes('version=0.4.9.6'))
  t.ok(events.includes('HS_DESC UPLOADED during'))

  await t.exception(ctl.cmd('BADCMD now'), /512/)

  // serialization: concurrent commands resolve in order
  const [r1, r2] = await Promise.all([ctl.cmd('AUTHENTICATE one'), ctl.cmd('AUTHENTICATE two')])
  t.is(r1, '250 OK')
  t.is(r2, '250 OK')
  t.alike(received.filter((l) => l.startsWith('AUTHENTICATE')), ['AUTHENTICATE deadbeef', 'AUTHENTICATE one', 'AUTHENTICATE two'])

  ctl.destroy()
})
