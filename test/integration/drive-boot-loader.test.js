// drive-boot M2 acceptance: the loader verifies → mirrors → spawns → health-gates a
// signed code drive, hot-swaps v1→v2, ROLLS BACK a deliberately-broken v3, and REJECTS a
// wrong-key v4 without disrupting the running app — all while the public /health shim
// stays up and the /data identity survives every swap. Hermetic (one Corestore, a tiny
// fake app; no swarm/fleet).
import test from 'brittle'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import net from 'node:net'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { writeCodeDrive } from '../../scripts/drive-boot/publish-code-drive.mjs'
import { pubKeyFromSeedHex } from '../../scripts/drive-boot/release-manifest.mjs'
import { DriveBootLoader } from '../../scripts/drive-boot/loader.mjs'

// A tiny "app": binds $PORT, persists an identity under $DRIVE_BOOT_DATA_DIR (the /data
// equivalent), and serves /health {running, version, identity}. meta.healthy:false makes
// a version that never gates green (→ rollback); meta.crash exits immediately.
const FAKE_APP = `
const http = require('http'), fs = require('fs'), path = require('path')
const meta = JSON.parse(fs.readFileSync(path.join(__dirname, 'appmeta.json'), 'utf8'))
if (meta.crash) process.exit(1)
const dataDir = process.env.DRIVE_BOOT_DATA_DIR
let identity = 'no-data'
if (dataDir) {
  const idf = path.join(dataDir, 'identity')
  try { identity = fs.readFileSync(idf, 'utf8') }
  catch { identity = 'id-' + Math.random().toString(36).slice(2, 10); fs.mkdirSync(dataDir, { recursive: true }); fs.writeFileSync(idf, identity) }
}
http.createServer((req, res) => {
  if ((req.url || '').startsWith('/health')) {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ running: meta.healthy !== false, version: String(meta.version), identity }))
  } else { res.writeHead(200); res.end('fake v' + meta.version) }
}).listen(process.env.PORT, '127.0.0.1')
`

function freePort () {
  return new Promise((resolve, reject) => {
    const s = net.createServer()
    s.on('error', reject)
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)) })
  })
}

function shimHealth (port) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 4000 }, (res) => {
      let b = ''; res.on('data', d => { b += d }); res.on('end', () => { try { resolve(JSON.parse(b)) } catch { resolve(null) } })
    })
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

// Publish one version of the fake app to the writable drive; return its drive version.
async function publishVersion (drive, { version, healthy = true, crash = false, seedHex }) {
  const files = [
    { path: '/server.js', content: Buffer.from(FAKE_APP) },
    { path: '/appmeta.json', content: Buffer.from(JSON.stringify({ version, healthy, crash })) }
  ]
  await writeCodeDrive(drive, { files, version: String(version), seedHex, runtime: { nodeMajor: '22', packagesOnly: true } })
  return drive.version
}

test('drive-boot M2: hot-swap, rollback a broken release, reject a wrong-key release; /data survives', async (t) => {
  const goodSeed = randomBytes(32).toString('hex')
  const { pubHex } = pubKeyFromSeedHex(goodSeed)
  const evilSeed = randomBytes(32).toString('hex')

  const storeDirA = await mkdtemp(join(tmpdir(), 'db-loader-storeA-'))
  const storeDirB = await mkdtemp(join(tmpdir(), 'db-loader-storeB-'))
  const mirrorRoot = await mkdtemp(join(tmpdir(), 'db-loader-app-'))
  const dataDir = await mkdtemp(join(tmpdir(), 'db-loader-data-'))
  // storeA = the publisher (writer); storeB = the appliance's store, replicating the drive
  // in like a real box that DOESN'T author it. The loader reads from storeB.
  const storeA = new Corestore(storeDirA)
  const drive = new Hyperdrive(storeA)
  await drive.ready()

  // publish v1, v2 (healthy), v3 (broken), v4 (valid app but signed by the WRONG key)
  const dv1 = await publishVersion(drive, { version: 1, seedHex: goodSeed })
  const dv2 = await publishVersion(drive, { version: 2, seedHex: goodSeed })
  const dv3 = await publishVersion(drive, { version: 3, healthy: false, seedHex: goodSeed })
  const dv4 = await publishVersion(drive, { version: 4, seedHex: evilSeed })

  const storeB = new Corestore(storeDirB)
  const s1 = storeA.replicate(true)
  const s2 = storeB.replicate(false)
  s1.pipe(s2).pipe(s1)

  const appPort = await freePort()
  const loader = new DriveBootLoader({
    store: storeB,
    driveKey: drive.key.toString('hex'),
    expectedReleaseKey: pubHex,
    mirrorRoot,
    dataDir,
    entry: 'server.js',
    appPort,
    publicPort: 0,
    healthPath: '/health',
    healthTimeoutMs: 6000
  })
  const publicPort = await loader.startShim()

  // ── boot v1 ──────────────────────────────────────────────────────────────
  const a = await loader.activate(dv1)
  t.is(a.appVersion, '1', 'activated v1')
  let h = await shimHealth(publicPort)
  t.ok(h && h.running === true && h.version === '1', 'shim reports running v1')
  const id = h.identity
  t.ok(id && id.startsWith('id-'), 'app minted a /data identity')

  // ── hot-swap v1 → v2 ─────────────────────────────────────────────────────
  const sw2 = await loader.swapTo(dv2)
  t.ok(sw2.swapped && !sw2.rolledBack, 'swapped to v2')
  h = await shimHealth(publicPort)
  t.ok(h && h.running === true && h.version === '2', 'shim reports running v2 after swap')
  t.is(h.identity, id, '/data identity preserved across the v1→v2 swap')

  // ── swap to a BROKEN v3 → rollback to v2 ─────────────────────────────────
  const sw3 = await loader.swapTo(dv3)
  t.ok(!sw3.swapped && sw3.rolledBack, 'broken v3 rolled back')
  t.ok(sw3.rollbackHealthy, 'rollback restored a healthy app')
  h = await shimHealth(publicPort)
  t.ok(h && h.running === true && h.version === '2', 'shim back on running v2 after rollback')
  t.is(h.identity, id, '/data identity preserved across the failed v3 + rollback')

  // ── swap to a WRONG-KEY v4 → rejected, running app untouched ──────────────
  const childBefore = loader.current.child
  const sw4 = await loader.swapTo(dv4)
  t.ok(!sw4.swapped && !sw4.rolledBack && sw4.reason === 'verify-failed', 'wrong-key v4 rejected at verify (no rollback needed)')
  t.is(loader.current.child, childBefore, 'the running v2 child was never restarted for an untrusted release')
  h = await shimHealth(publicPort)
  t.ok(h && h.running === true && h.version === '2', 'shim still on running v2 after rejecting v4')

  // cleanup
  await loader.stop()
  s1.destroy(); s2.destroy()
  await drive.close(); await storeA.close(); await storeB.close()
  await rm(storeDirA, { recursive: true, force: true })
  await rm(storeDirB, { recursive: true, force: true })
  await rm(mirrorRoot, { recursive: true, force: true })
  await rm(dataDir, { recursive: true, force: true })
})
