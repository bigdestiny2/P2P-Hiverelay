/**
 * Headless fake tor daemon for the cross-feature journey tests.
 *
 * The unit suites stub the control plane in-process via `_controlFactory`
 * (see test/unit/tor-transport.test.js). That injection point is not
 * reachable through RelayNode — the node constructs its own TorTransport
 * from operator config — so the journeys use the next-best seam: a REAL
 * loopback TCP fake that speaks the two daemon protocols the transport
 * code actually talks to:
 *
 *   1. Control port — the subset of the tor control protocol TorTransport
 *      issues (AUTHENTICATE / GETINFO / SETCONF / SETEVENTS / ADD_ONION /
 *      DEL_ONION), same reply shapes as the unit FakeControl. After
 *      SETEVENTS the fake pushes the async `650 HS_DESC UPLOADED` events
 *      the health machine needs to reach `ready` (no probe vport), which
 *      is what ungates the capability-doc privacyTransports advertisement.
 *
 *   2. SOCKS5 port — a minimal no-auth CONNECT server that emulates the
 *      daemon's hidden-service forwarding: a CONNECT to
 *      `<serviceId>.onion:<vport>` is piped to the `127.0.0.1` target the
 *      most recent ADD_ONION `Port=` mapping declared. This lets a client
 *      TorTransport (or any SOCKS client) push REAL BYTES through the same
 *      code path a tor daemon would feed — the read plane (HTTP gateway)
 *      and the peer plane (OnionPeerListener Noise XK) both included.
 *
 * Nothing here grants authority: the fake supplies reachability only, the
 * application-layer Noise handshake + per-service authorization run
 * unmodified (ONION-INV-006).
 */

import net from 'net'

const DEFAULT_SERVICE_ID = 'a'.repeat(56)
const DEFAULT_KEY_BLOB = 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64')
const DEFAULT_VERSION = '0.4.9.6'

export async function startFakeTorDaemon (t, opts = {}) {
  const serviceId = opts.serviceId || DEFAULT_SERVICE_ID
  const keyBlob = opts.keyBlob || DEFAULT_KEY_BLOB
  const version = opts.version || DEFAULT_VERSION

  const commands = []
  // vport → { host, targetPort } from the most recent ADD_ONION.
  const portMap = new Map()
  // Every socket the daemon touches, so close() never blocks on open
  // connections (server.close() alone waits for them).
  const sockets = new Set()
  let controlSock = null
  let serviceLive = false

  function track (sock) {
    sockets.add(sock)
    sock.on('close', () => sockets.delete(sock))
    sock.on('error', () => {})
    return sock
  }

  function emitDescriptorUploads (n = 2) {
    // Mirror the daemon's async 650 events: with minDescriptorUploads = 2
    // and no probe vport these drive TorTransport health KEY_LOADED →
    // DESCRIPTOR_UPLOADED → READY (the privacyTransports gate).
    let sent = 0
    const tick = () => {
      if (!controlSock || controlSock.destroyed || !serviceLive) return
      try { controlSock.write('650 HS_DESC UPLOADED ' + serviceId + ' fakeupload' + sent + '\r\n') } catch { return }
      sent++
      if (sent < n) setTimeout(tick, 15)
    }
    setTimeout(tick, 15)
  }

  function handleControlLine (sock, line) {
    commands.push(line)
    const head = line.split(' ')[0]
    if (head === 'AUTHENTICATE') return sock.write('250 OK\r\n')
    if (head === 'GETINFO') return sock.write('250-version=' + version + '\r\n250 OK\r\n')
    if (head === 'SETCONF') return sock.write('250 OK\r\n')
    if (head === 'SETEVENTS') {
      sock.write('250 OK\r\n')
      emitDescriptorUploads(2)
      return
    }
    if (head === 'DEL_ONION') {
      serviceLive = false
      return sock.write('250 OK\r\n')
    }
    if (head === 'ADD_ONION') {
      portMap.clear()
      for (const token of line.split(' ')) {
        if (!token.startsWith('Port=')) continue
        const [vport, target] = token.slice('Port='.length).split(',')
        const split = target.lastIndexOf(':')
        portMap.set(Number(vport), {
          host: target.slice(0, split),
          targetPort: Number(target.slice(split + 1))
        })
      }
      serviceLive = true
      const lines = ['250-ServiceID=' + serviceId]
      if (line.startsWith('ADD_ONION NEW:')) lines.push('250-PrivateKey=' + keyBlob)
      lines.push('250 OK')
      return sock.write(lines.join('\r\n') + '\r\n')
    }
    sock.write('250 OK\r\n')
  }

  const controlServer = net.createServer((sock) => {
    track(sock)
    controlSock = sock
    let buf = ''
    sock.on('data', (chunk) => {
      buf += chunk.toString()
      for (;;) {
        const idx = buf.indexOf('\r\n')
        if (idx === -1) break
        const line = buf.slice(0, idx)
        buf = buf.slice(idx + 2)
        try {
          handleControlLine(sock, line)
        } catch {
          try { sock.write('513 fake control error\r\n') } catch {}
        }
      }
    })
  })

  // ─── SOCKS5 (no-auth CONNECT) with .onion → vport-target routing ─────
  const socksServer = net.createServer((sock) => {
    track(sock)
    let buf = Buffer.alloc(0)
    let phase = 'greeting'
    sock.on('data', (chunk) => {
      if (phase === 'piped') return // stray data after piping starts is forwarded by pipe()
      buf = Buffer.concat([buf, chunk])
      try {
        if (phase === 'greeting') {
          if (buf.length < 2) return
          const nmethods = buf[1]
          if (buf.length < 2 + nmethods) return
          buf = buf.subarray(2 + nmethods)
          phase = 'request'
          sock.write(Buffer.from([0x05, 0x00])) // select no-auth
        }
        if (phase !== 'request') return
        if (buf.length < 4) return
        if (buf[0] !== 0x05 || buf[1] !== 0x01) { // CONNECT only
          sock.write(socksReply(0x07)) // command not supported
          sock.end()
          return
        }
        const atyp = buf[3]
        let host = null
        let addrEnd = -1
        if (atyp === 0x01) { // IPv4
          if (buf.length < 4 + 4 + 2) return
          host = [...buf.subarray(4, 8)].join('.')
          addrEnd = 8
        } else if (atyp === 0x03) { // domain
          const len = buf[4]
          if (buf.length < 5 + len + 2) return
          host = buf.subarray(5, 5 + len).toString('ascii')
          addrEnd = 5 + len
        } else {
          sock.write(socksReply(0x08)) // address type not supported
          sock.end()
          return
        }
        const port = buf.readUInt16BE(addrEnd)
        phase = 'piped'

        // The hidden-service forwarding model: only our service's .onion
        // resolves, and only on vports the latest ADD_ONION declared.
        const route = host === serviceId + '.onion' ? portMap.get(port) || null : null
        if (!route) {
          sock.write(socksReply(0x04)) // host unreachable
          sock.end()
          return
        }
        const upstream = track(net.createConnection(route.targetPort, route.host))
        upstream.on('error', () => { try { sock.destroy() } catch {} })
        upstream.on('connect', () => {
          sock.write(socksReply(0x00))
          sock.pipe(upstream)
          upstream.pipe(sock)
        })
      } catch {
        try { sock.destroy() } catch {}
      }
    })
  })

  await Promise.all([
    new Promise((resolve, reject) => {
      controlServer.once('error', reject)
      controlServer.listen(0, '127.0.0.1', resolve)
    }),
    new Promise((resolve, reject) => {
      socksServer.once('error', reject)
      socksServer.listen(0, '127.0.0.1', resolve)
    })
  ])

  const daemon = {
    serviceId,
    onionAddress: serviceId + '.onion',
    keyBlob,
    version,
    controlPort: controlServer.address().port,
    socksPort: socksServer.address().port,
    commands,
    portMap,
    addOnionCommands: () => commands.filter((c) => c.startsWith('ADD_ONION')),
    emitDescriptorUploads,
    close: async () => {
      // Destroy every live connection first — server.close() waits for them.
      for (const sock of [...sockets]) { try { sock.destroy() } catch {} }
      for (const server of [controlServer, socksServer]) {
        try { await new Promise((resolve) => server.close(resolve)) } catch {}
      }
    }
  }
  t.teardown(() => daemon.close())
  return daemon
}

function socksReply (code) {
  return Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}
