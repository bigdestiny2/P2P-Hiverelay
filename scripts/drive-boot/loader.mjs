// loader.mjs — the drive-boot loader (docs/DRIVE-BOOT-APPLIANCE.md, milestone M2).
//
// The loader is the thin, stable entrypoint baked into the appliance image. It fetches
// the signed code drive (M1), verifies it FAIL-CLOSED before running a byte, materializes
// the checkout to disk, spawns the app, health-gates it, and hot-swaps to new versions
// with rollback to last-good. It ports the fleet updater's invariants (fleet/updater.sh)
// with hyperdrive.checkout() in place of git checkout:
//
//   • verify-before-run  — a bad/forged release never reaches a spawn (like verify_tag
//     running before git checkout).
//   • health gate        — running:true AND version==target within a timeout, else roll back
//     (the /health "version"==expected check).
//   • rollback           — always try to leave the box on the version it started from.
//   • /health shim       — the PUBLIC health endpoint stays up (running:true) through sync
//     and swap so the platform health check (StartOS's 30s grace) never reads the app as
//     down while a drive syncs or an update swaps.
//   • /data untouched     — only the app-code checkout is swapped; identity/config/corestore
//     live on the data volume and survive every update.
//
// This module is decoupled from the fleet and the real Node CLI (that wiring is M4/M5):
// it takes a store, a pinned driveKey + release key, an app entry path, and ports.

import Hyperdrive from 'hyperdrive'
import { spawn } from 'node:child_process'
import http from 'node:http'
import { mkdir, writeFile, rm, rename } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { verifyDriveManifest, verifyDriveContents } from './release-manifest.mjs'

const MANIFEST_PATH = '/release-manifest.json'
const MANIFEST_SIG_PATH = '/release-manifest.sig'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function onExit (child, ms) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve()
    const t = setTimeout(() => { try { child.kill('SIGKILL') } catch {} resolve() }, ms)
    child.once('exit', () => { clearTimeout(t); resolve() })
  })
}

function getJson (port, path, timeoutMs) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path, timeout: timeoutMs }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (d) => { body += d })
      res.on('end', () => { try { resolve(JSON.parse(body)) } catch { resolve(null) } })
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

// Verify the signed manifest of an ALREADY-OPEN drive (a checkout at driveVersion, or its
// head) against the pinned release key + reconstruct/hash-check every file, then materialize
// to mirrorRoot/v-<driveVersion>/. Fail-closed: throws BEFORE writing the final dir if
// anything fails to verify. Opening the drive is the caller's job (the loader opens it once
// and reuses it — reopening a drive by key repeatedly, especially on a store that owns the
// key, deadlocks in corestore).
export async function verifyAndMirror ({ drive, driveVersion, expectedReleaseKey, mirrorRoot }) {
  const head = (driveVersion != null) ? driveVersion : drive.version
  const snap = (driveVersion != null) ? drive.checkout(driveVersion) : drive

  try {
    const manifestBuf = await snap.get(MANIFEST_PATH)
    const sigBuf = await snap.get(MANIFEST_SIG_PATH)
    if (!manifestBuf || !sigBuf) throw new Error('drive-boot loader: drive is missing its release manifest/signature')
    const manifest = JSON.parse(manifestBuf.toString())
    const signature = JSON.parse(sigBuf.toString())

    // 1. signature over {files, driveKey, version, runtime} by the PINNED key
    verifyDriveManifest({ manifest, signature, expectedKey: expectedReleaseKey })
    // 2. the manifest must be for THIS drive (block a valid manifest transplanted from another drive)
    if (String(manifest.driveKey).toLowerCase() !== drive.key.toString('hex')) {
      throw new Error('drive-boot loader: manifest driveKey does not match the opened drive')
    }
    // 3. reconstruct + hash-check every file the manifest pins
    const files = new Map()
    for (const path of Object.keys(manifest.files || {})) {
      const buf = await snap.get(path)
      if (!buf) throw new Error('drive-boot loader: file missing from drive: ' + path)
      files.set(path, buf)
    }
    verifyDriveContents(manifest, files)

    // 4. materialize to disk atomically (temp dir → rename → never a half-written checkout)
    const finalDir = join(mirrorRoot, 'v-' + head)
    const tmpDir = finalDir + '.tmp-' + process.pid
    await rm(tmpDir, { recursive: true, force: true })
    for (const [path, buf] of files) {
      const abs = join(tmpDir, path)
      await mkdir(dirname(abs), { recursive: true })
      await writeFile(abs, buf)
    }
    await rm(finalDir, { recursive: true, force: true })
    await rename(tmpDir, finalDir)
    return { dir: finalDir, manifest, appVersion: String(manifest.version), driveVersion: head }
  } finally {
    if (snap !== drive) await snap.close()
  }
}

export function spawnApp ({ dir, entry, port, dataDir, env = {} }) {
  const child = spawn(process.execPath, [join(dir, entry)], {
    env: { ...process.env, ...env, PORT: String(port), DRIVE_BOOT_DATA_DIR: dataDir || '' },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const logs = []
  const cap = (d) => { logs.push(d.toString()); if (logs.length > 200) logs.shift() }
  child.stdout.on('data', cap)
  child.stderr.on('data', cap)
  child._logs = logs
  return child
}

// Poll the child's /health until running:true AND version==expected, or timeout.
export async function healthGate ({ port, healthPath = '/health', expectedVersion, timeoutMs = 120000, intervalMs = 400 }) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const h = await getJson(port, healthPath, 4000)
    if (h && h.running === true && (expectedVersion == null || String(h.version) === String(expectedVersion))) return true
    await sleep(intervalMs)
  }
  return false
}

export class DriveBootLoader {
  constructor (opts) {
    const {
      store, driveKey, expectedReleaseKey, mirrorRoot, dataDir,
      entry, appPort, publicPort, healthPath = '/health', healthTimeoutMs = 120000, env = {}
    } = opts
    Object.assign(this, { store, driveKey, expectedReleaseKey, mirrorRoot, dataDir, entry, appPort, publicPort, healthPath, healthTimeoutMs, env })
    this.state = { phase: 'sync', appVersion: null, driveVersion: null }
    this.current = null // { child, dir, appVersion, driveVersion }
    this.lastGood = null // { dir, appVersion, driveVersion }
    this.shim = null
    this.drive = null
  }

  // Open the code drive ONCE and keep it; all version reads go through checkout() on this
  // handle. (Reopening a drive by key repeatedly — especially on a store that owns the key —
  // deadlocks in corestore.) In production the store replicates the drive from the fleet.
  async open () {
    if (this.drive) return this.drive
    const keyBuf = typeof this.driveKey === 'string' ? Buffer.from(this.driveKey, 'hex') : this.driveKey
    this.drive = new Hyperdrive(this.store, keyBuf)
    await this.drive.ready()
    return this.drive
  }

  // Pull the latest drive state (bounded — never block the boot forever waiting for a peer),
  // then verify + mirror the requested version.
  async _mirror (driveVersion) {
    await Promise.race([this.drive.update().catch(() => {}), sleep(3000)])
    return verifyAndMirror({ drive: this.drive, driveVersion, expectedReleaseKey: this.expectedReleaseKey, mirrorRoot: this.mirrorRoot })
  }

  // The PUBLIC health/reverse-proxy shim. /health answers from loader STATE so it stays
  // up (running:true) through sync/swap; everything else proxies to the running child.
  startShim () {
    this.shim = http.createServer((req, res) => {
      const path = (req.url || '/').split('?')[0]
      const childUp = this.current && this.current.child && this.current.child.exitCode === null
      if (childUp) {
        // App is up → proxy everything (incl. /health, so the real version + app state
        // surface) straight to the child.
        const up = http.request({ host: '127.0.0.1', port: this.appPort, path: req.url, method: req.method, headers: req.headers }, (r) => {
          res.writeHead(r.statusCode || 502, r.headers); r.pipe(res)
        })
        up.on('error', () => { if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' }); res.end('{"error":"upstream unavailable"}') })
        req.pipe(up)
        return
      }
      // No child yet (first sync) or a swap window (old killed, new not gated): keep the
      // PUBLIC health endpoint GREEN so the platform health check (StartOS 30s grace)
      // doesn't read the app as down while a drive syncs or an update swaps.
      if (path === this.healthPath) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ running: true, version: this.state.appVersion || 'starting', phase: this.state.phase }))
        return
      }
      res.writeHead(503, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ running: true, phase: this.state.phase, note: 'app starting' }))
    })
    return new Promise((resolve) => this.shim.listen(this.publicPort, '127.0.0.1', () => resolve(this.shim.address().port)))
  }

  async _bringUp (driveVersion, phase) {
    this.state = { ...this.state, phase }
    const m = await this._mirror(driveVersion)
    const child = spawnApp({ dir: m.dir, entry: this.entry, port: this.appPort, dataDir: this.dataDir, env: this.env })
    const ok = await healthGate({ port: this.appPort, healthPath: this.healthPath, expectedVersion: m.appVersion, timeoutMs: this.healthTimeoutMs })
    if (!ok) { child.kill('SIGKILL'); await onExit(child, 3000); throw Object.assign(new Error('drive-boot: health gate failed for ' + m.appVersion), { logs: child._logs.join('') }) }
    return { child, dir: m.dir, appVersion: m.appVersion, driveVersion: m.driveVersion }
  }

  // First boot: verify → mirror → spawn → gate. Throws if the first release won't come up.
  async activate (driveVersion) {
    await this.open()
    const up = await this._bringUp(driveVersion, 'sync')
    this.current = up
    this.lastGood = { dir: up.dir, appVersion: up.appVersion, driveVersion: up.driveVersion }
    this.state = { phase: 'running', appVersion: up.appVersion, driveVersion: up.driveVersion }
    return { appVersion: up.appVersion, driveVersion: up.driveVersion }
  }

  // Update to a new version with rollback. Returns {swapped, rolledBack, appVersion, reason}.
  async swapTo (driveVersion) {
    if (!this.current) return this.activate(driveVersion)
    const prev = this.current
    this.state = { ...this.state, phase: 'swapping' }

    // 1. verify + mirror the NEW version FIRST — a verify failure aborts without touching
    //    the running app (never kill a healthy version for a release we can't even trust).
    let mirrored
    try {
      mirrored = await this._mirror(driveVersion)
    } catch (err) {
      this.state = { phase: 'running', appVersion: prev.appVersion, driveVersion: prev.driveVersion }
      return { swapped: false, rolledBack: false, reason: 'verify-failed', error: err.message, appVersion: prev.appVersion }
    }

    // 2. stop current, start the new version on the same port, health-gate it
    prev.child.kill('SIGTERM'); await onExit(prev.child, 5000)
    const child = spawnApp({ dir: mirrored.dir, entry: this.entry, port: this.appPort, dataDir: this.dataDir, env: this.env })
    const ok = await healthGate({ port: this.appPort, healthPath: this.healthPath, expectedVersion: mirrored.appVersion, timeoutMs: this.healthTimeoutMs })
    if (ok) {
      this.current = { child, dir: mirrored.dir, appVersion: mirrored.appVersion, driveVersion: mirrored.driveVersion }
      this.lastGood = { dir: mirrored.dir, appVersion: mirrored.appVersion, driveVersion: mirrored.driveVersion }
      this.state = { phase: 'running', appVersion: mirrored.appVersion, driveVersion: mirrored.driveVersion }
      return { swapped: true, rolledBack: false, appVersion: mirrored.appVersion }
    }

    // 3. new version unhealthy → roll back to prev (last-good) and re-gate
    child.kill('SIGKILL'); await onExit(child, 3000)
    const rb = spawnApp({ dir: prev.dir, entry: this.entry, port: this.appPort, dataDir: this.dataDir, env: this.env })
    const rbok = await healthGate({ port: this.appPort, healthPath: this.healthPath, expectedVersion: prev.appVersion, timeoutMs: this.healthTimeoutMs })
    this.current = { child: rb, dir: prev.dir, appVersion: prev.appVersion, driveVersion: prev.driveVersion }
    this.state = { phase: rbok ? 'running' : 'failed', appVersion: prev.appVersion, driveVersion: prev.driveVersion }
    return { swapped: false, rolledBack: true, appVersion: prev.appVersion, rollbackHealthy: rbok, reason: 'health-gate-failed' }
  }

  async stop () {
    if (this.current && this.current.child) { this.current.child.kill('SIGKILL'); await onExit(this.current.child, 3000) }
    if (this.shim) await new Promise((resolve) => this.shim.close(resolve))
    if (this.drive) { await this.drive.close().catch(() => {}); this.drive = null }
  }
}
