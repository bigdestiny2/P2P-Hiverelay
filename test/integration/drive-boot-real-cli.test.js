// drive-boot M4-lite acceptance: the loader boots the REAL Blindspark Node CLI off a signed
// code drive (not a stand-in), gates on the relay's real /health, and self-updates to a
// version whose bumped packages/core/package.json ONLY the new drive content reports — proving
// the swap actually put fresh code live — while the /data relay identity survives the restart.
//
// Exercises the real dependency wiring: the drive ships pure-JS packages/, and the loader links
// node_modules so external deps resolve to the image's baked copy while the 4 workspace packages
// resolve to the mirror's fresh packages/. Boots two full relays, so it runs longer than a unit
// test (explicit timeout). /health running:true is not DHT-gated, so it stays robust.
import test from 'brittle'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import net from 'node:net'
import http from 'node:http'
import { readFileSync, existsSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import { collectCodeFiles, writeCodeDrive } from '../../scripts/drive-boot/publish-code-drive.mjs'
import { pubKeyFromSeedHex } from '../../scripts/drive-boot/release-manifest.mjs'
import { DriveBootLoader } from '../../scripts/drive-boot/loader.mjs'

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url))

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
      let b = ''
      res.on('data', (d) => { b += d })
      res.on('end', () => { try { resolve(JSON.parse(b)) } catch { resolve(null) } })
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

test('drive-boot M4-lite: loader boots the REAL Blindspark CLI + self-updates; /data identity survives',
  { timeout: 180000 }, async (t) => {
    const realVersion = JSON.parse(readFileSync(join(REPO_ROOT, 'packages/core/package.json'), 'utf8')).version
    const bumped = realVersion + '-driveboot-e2e'
    const seed = randomBytes(32).toString('hex')
    const { pubHex } = pubKeyFromSeedHex(seed)
    const runtime = { nodeMajor: String(process.versions.node.split('.')[0]), packagesOnly: true }

    // v1 = the real packages/ tree; v2 = same tree with packages/core/package.json version bumped
    // (the relay's /health reports packages/core/package.json version via _relayVersion()).
    const v1 = await collectCodeFiles(REPO_ROOT)
    t.ok(v1.length > 100, 'collected the real app tree (' + v1.length + ' files)')
    const v2 = v1.map((f) => {
      if (f.path !== '/packages/core/package.json') return f
      const pkg = JSON.parse(f.content.toString()); pkg.version = bumped
      return { path: f.path, content: Buffer.from(JSON.stringify(pkg, null, 2)) }
    })

    const storeDirA = await mkdtemp(join(tmpdir(), 'db-cli-storeA-'))
    const storeDirB = await mkdtemp(join(tmpdir(), 'db-cli-storeB-'))
    const mirrorRoot = await mkdtemp(join(tmpdir(), 'db-cli-app-'))
    const dataDir = await mkdtemp(join(tmpdir(), 'db-cli-data-'))
    const storeA = new Corestore(storeDirA)
    const drive = new Hyperdrive(storeA)
    await drive.ready()
    await writeCodeDrive(drive, { files: v1, version: realVersion, seedHex: seed, runtime }); const dv1 = drive.version
    await writeCodeDrive(drive, { files: v2, version: bumped, seedHex: seed, runtime }); const dv2 = drive.version

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
      entry: 'packages/core/cli/index.js',
      appArgs: ['start'],
      portFlag: '--port',
      nodeModules: join(REPO_ROOT, 'node_modules'),
      env: { HOME: dataDir, HIVERELAY_STORAGE: dataDir },
      appPort,
      publicPort: 0,
      healthPath: '/health',
      healthTimeoutMs: 40000
    })
    const publicPort = await loader.startShim()

    try {
      // ── boot the real relay at v1 ──────────────────────────────────────────
      const a = await loader.activate(dv1)
      t.is(a.appVersion, realVersion, 'real CLI activated at ' + realVersion)
      const h1 = await shimHealth(publicPort)
      t.ok(h1 && h1.running === true, 'real relay reports running:true through the shim')
      t.is(String(h1.version), realVersion, 'shim surfaces the real relay version')
      const idPath = join(dataDir, 'relay-identity.json')
      t.ok(existsSync(idPath), 'relay minted its identity on /data')
      const identityV1 = readFileSync(idPath, 'utf8')

      // ── self-update to the bumped v2: the gate on `bumped` only passes if the NEW drive
      //    content (bumped package.json) is what the relay is now running ──────────
      const sw = await loader.swapTo(dv2)
      t.ok(sw.swapped && !sw.rolledBack, 'swapped the real relay to v2')
      const h2 = await shimHealth(publicPort)
      t.ok(h2 && h2.running === true, 'relay running:true after the self-update')
      t.is(String(h2.version), bumped, 'relay now reports the bumped version — fresh drive code is live')

      // ── /data identity survived the real relay restart ─────────────────────
      t.is(readFileSync(idPath, 'utf8'), identityV1, '/data relay identity preserved across the self-update')
    } finally {
      await loader.stop()
      s1.destroy(); s2.destroy()
      await drive.close(); await storeA.close(); await storeB.close()
      await rm(storeDirA, { recursive: true, force: true })
      await rm(storeDirB, { recursive: true, force: true })
      await rm(mirrorRoot, { recursive: true, force: true })
      await rm(dataDir, { recursive: true, force: true })
    }
  })
