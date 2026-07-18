/**
 * RA-05 — bulk-over-onion validation against a LIVE tor daemon.
 *
 * Verifies that the TorTransport v2 (persistent key, onion service) can carry
 * real bulk bytes end-to-end with integrity, and measures throughput to
 * calibrate the RA-05 gate (100 MB median <= 10 min on a 10 Mbps uplink).
 *
 * NOT part of the default suite — requires a tor binary and network access:
 *   HIVERELAY_TOR_TEST=1   enable the 5 MB integrity+throughput test
 *   HIVERELAY_TOR_BULK=1   additionally run the 100 MB measurement
 *   HIVERELAY_TOR_ASSERT_GATE=1  make the 100 MB timing a hard gate (<= 10 min)
 *   TOR_BIN=/path/to/tor   override tor binary resolution
 */
import test from 'brittle'
import { spawn, execSync } from 'child_process'
import http from 'http'
import fs from 'fs'
import os from 'os'
import path from 'path'
import crypto from 'crypto'
import { TorTransport } from 'p2p-hiverelay/transports/tor/index.js'

const ENABLED = !!process.env.HIVERELAY_TOR_TEST
const BULK = !!process.env.HIVERELAY_TOR_BULK
const ASSERT_GATE = !!process.env.HIVERELAY_TOR_ASSERT_GATE
const SOCKS_PORT = 19150
const CONTROL_PORT = 19151
const GATE_MS = 10 * 60 * 1000

function resolveTorBin () {
  if (process.env.TOR_BIN) return process.env.TOR_BIN
  try { return execSync('which tor', { encoding: 'utf8' }).trim() } catch { return null }
}

function startTor (dataDir) {
  fs.mkdirSync(dataDir, { recursive: true })
  fs.writeFileSync(path.join(dataDir, 'torrc'), [
    'DataDirectory ' + dataDir,
    'SocksPort ' + SOCKS_PORT,
    'ControlPort ' + CONTROL_PORT,
    'CookieAuthentication 1',
    'Log notice file ' + path.join(dataDir, 'tor.log')
  ].join('\n'))
  return spawn(resolveTorBin(), ['-f', path.join(dataDir, 'torrc')], { stdio: 'ignore' })
}

async function waitBootstrap (dataDir, timeoutMs = 360000) {
  const logFile = path.join(dataDir, 'tor.log')
  const t0 = Date.now()
  for (;;) {
    try { if (fs.readFileSync(logFile, 'utf8').includes('Bootstrapped 100%')) return Date.now() - t0 } catch {}
    if (Date.now() - t0 > timeoutMs) throw new Error('tor bootstrap timeout')
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
}

function blobServer (t, blobs) {
  const server = http.createServer((req, res) => {
    const blob = blobs[req.url.slice(1)]
    if (!blob) { res.writeHead(404); res.end(); return }
    res.writeHead(200, { 'content-length': blob.length, 'content-type': 'application/octet-stream' })
    res.end(blob)
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      t.teardown(() => { try { server.close() } catch {} })
      resolve(server.address().port)
    })
  })
}

function httpGetStream (stream, host, pathOut) {
  return new Promise((resolve, reject) => {
    const chunks = []
    stream.on('data', (d) => chunks.push(d))
    stream.on('end', () => resolve(Buffer.concat(chunks)))
    stream.on('error', reject)
    stream.write(`GET ${pathOut} HTTP/1.0\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)
  })
}

function stripHttp (buf) {
  const idx = buf.indexOf('\r\n\r\n')
  return buf.subarray(idx + 4)
}

async function onionFetch (t, sizeBytes, { keyFile, cookieFile }) {
  const blob = crypto.randomBytes(sizeBytes)
  const expected = crypto.createHash('sha256').update(blob).digest('hex')
  const port = await blobServer(t, { blob })
  const transport = new TorTransport({
    socksPort: SOCKS_PORT,
    controlPort: CONTROL_PORT,
    cookieAuthFile: cookieFile,
    keyFile,
    localPort: port,
    minDaemonVersion: '0.4.9.5'
  })
  t.teardown(async () => { try { await transport.stop() } catch {} })
  await transport.start()
  t.ok(transport.onionAddress, 'onion service created')
  t.ok(transport.onionAddress.endsWith('.onion'))

  // address must persist across restart (persistent custody, ONION-INV-001)
  const firstAddress = transport.onionAddress
  await transport.stop()
  const transport2 = new TorTransport({
    socksPort: SOCKS_PORT,
    controlPort: CONTROL_PORT,
    cookieAuthFile: cookieFile,
    keyFile,
    localPort: port
  })
  t.teardown(async () => { try { await transport2.stop() } catch {} })
  await transport2.start()
  t.is(transport2.onionAddress, firstAddress, 'persistent address survives restart')

  const t0 = Date.now()
  const stream = await transport2.connect(firstAddress, 80)
  const raw = await httpGetStream(stream, firstAddress, '/blob')
  const ms = Date.now() - t0
  const body = stripHttp(raw)
  const got = crypto.createHash('sha256').update(body).digest('hex')
  t.is(got, expected, 'byte integrity through onion')
  const mbps = +(body.length * 8 / 1e6 / (ms / 1000)).toFixed(2)
  return { ms, bytes: body.length, mbps }
}

const it = ENABLED ? test : test.skip
const itBulk = ENABLED && BULK ? test : test.skip

it('onion bulk fetch — 5 MB integrity + throughput (live tor)', { timeout: 900000 }, async (t) => {
  if (!resolveTorBin()) { t.comment('no tor binary found — skipping'); return }
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-tor-bulk-'))
  t.teardown(() => { try { fs.rmSync(dataDir, { recursive: true, force: true }) } catch {} })
  const proc = startTor(dataDir)
  t.teardown(() => { proc.kill('SIGTERM') })
  await waitBootstrap(dataDir)
  const keyFile = path.join(dataDir, 'hs-key.blob')
  const cookieFile = path.join(dataDir, 'control_auth_cookie')

  const r = await onionFetch(t, 5 * 1024 * 1024, { keyFile, cookieFile })
  t.comment(`5MB over onion: ${r.ms}ms (${r.mbps} Mbps)`)
  t.ok(r.bytes === 5 * 1024 * 1024)
})

itBulk('onion bulk fetch — 100 MB gate measurement (live tor)', { timeout: 1500000 }, async (t) => {
  if (!resolveTorBin()) { t.comment('no tor binary found — skipping'); return }
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-tor-bulk100-'))
  t.teardown(() => { try { fs.rmSync(dataDir, { recursive: true, force: true }) } catch {} })
  const proc = startTor(dataDir)
  t.teardown(() => { proc.kill('SIGTERM') })
  await waitBootstrap(dataDir)
  const keyFile = path.join(dataDir, 'hs-key.blob')
  const cookieFile = path.join(dataDir, 'control_auth_cookie')

  const r = await onionFetch(t, 100 * 1024 * 1024, { keyFile, cookieFile })
  t.comment(`100MB over onion: ${r.ms}ms (${r.mbps} Mbps) — RA-05 gate is ${GATE_MS}ms`)
  t.ok(r.bytes === 100 * 1024 * 1024)
  if (ASSERT_GATE) {
    t.ok(r.ms <= GATE_MS, `RA-05 gate: 100MB ${r.ms}ms <= ${GATE_MS}ms`)
  }
})
