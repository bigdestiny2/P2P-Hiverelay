// drive-boot M1 acceptance: a published code drive reconstructs BYTE-IDENTICAL on a
// fresh peer, and its offline-signed release manifest verifies against the pinned key.
// Hermetic: two Corestores replicated in-process (no swarm/DHT/fleet) — proves the
// content-addressing + signing mechanism the loader (M2) will depend on.
import test from 'brittle'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { collectCodeFiles, writeCodeDrive } from '../../scripts/drive-boot/publish-code-drive.mjs'
import {
  verifyDriveManifest,
  verifyDriveContents,
  pubKeyFromSeedHex,
  driveReleaseSigningMessage
} from '../../scripts/drive-boot/release-manifest.mjs'

async function tmp (p) { return mkdtemp(join(tmpdir(), p)) }

test('drive-boot M1: publish -> reconstruct byte-identical -> verify signed manifest', async (t) => {
  // ── 1. a tiny app-code fixture, incl. files the collector MUST exclude ──────────
  const src = await tmp('db-src-')
  await mkdir(join(src, 'packages/core'), { recursive: true })
  await writeFile(join(src, 'packages/core/index.js'), 'export const V = 1\n')
  await writeFile(join(src, 'packages/core/util.js'), 'export const add = (a, b) => a + b\n')
  await mkdir(join(src, 'packages/core/prebuilds/linux-x64'), { recursive: true })
  await writeFile(join(src, 'packages/core/prebuilds/linux-x64/sodium.node'), randomBytes(64)) // .node → excluded
  await mkdir(join(src, 'packages/core/test'), { recursive: true })
  await writeFile(join(src, 'packages/core/test/x.test.js'), 'test junk\n') // test/ → excluded
  await mkdir(join(src, 'packages/core/node_modules/dep'), { recursive: true })
  await writeFile(join(src, 'packages/core/node_modules/dep/i.js'), 'dep\n') // node_modules → excluded

  const files = await collectCodeFiles(src, { include: ['packages/core'] })
  t.is(files.length, 2, 'collector keeps only the 2 pure-JS app files (drops .node, test/, node_modules)')
  t.alike(files.map(f => f.path), ['/packages/core/index.js', '/packages/core/util.js'], 'sorted posix drive paths')

  // ── 2. publish: write app files + signed manifest into a drive in store A ────────
  const dirA = await tmp('db-a-')
  const storeA = new Corestore(dirA)
  const driveA = new Hyperdrive(storeA)
  await driveA.ready()
  const seed = randomBytes(32).toString('hex')
  const { pubHex } = pubKeyFromSeedHex(seed)
  const runtime = { nodeMajor: '22', packagesOnly: true }
  const { manifest, signature, driveKey } = await writeCodeDrive(driveA, { files, version: '0.24.2', seedHex: seed, runtime })
  t.is(driveKey, driveA.key.toString('hex'), 'manifest pins this drive key')
  t.is(signature.key, pubHex, 'signed by the offline release key')

  // ── 3. fresh peer: store B opens by key and replicates from A ────────────────────
  const dirB = await tmp('db-b-')
  const storeB = new Corestore(dirB)
  const driveB = new Hyperdrive(storeB, driveA.key)
  await driveB.ready()
  const s1 = storeA.replicate(true)
  const s2 = storeB.replicate(false)
  s1.pipe(s2).pipe(s1)
  await driveB.update({ wait: true })

  // ── 4. reconstruct every app file, byte-identical ───────────────────────────────
  const actual = new Map()
  for (const f of files) {
    const got = await driveB.get(f.path)
    t.ok(got && Buffer.compare(got, f.content) === 0, 'byte-identical on fresh peer: ' + f.path)
    actual.set(f.path, got)
  }

  // ── 5. verify the signed manifest + contents on the reader (pinned key) ──────────
  const rmJson = JSON.parse((await driveB.get('/release-manifest.json')).toString())
  const rmSig = JSON.parse((await driveB.get('/release-manifest.sig')).toString())
  t.alike(rmJson, manifest, 'manifest reconstructs intact')
  const v = verifyDriveManifest({ manifest: rmJson, signature: rmSig, expectedKey: pubHex })
  t.ok(v.ok && v.key === pubHex, 'signature verifies against the pinned release key')
  t.is(verifyDriveContents(rmJson, actual).count, 2, 'every manifest file matches its pinned sha256')

  // ── 6. adversarial: fail-closed on wrong key, bad sig, tampered content ──────────
  t.exception(() => verifyDriveManifest({ manifest: rmJson, signature: rmSig, expectedKey: 'ab'.repeat(32) }),
    /unexpected key/, 'a different pinned key is rejected')
  t.exception(() => verifyDriveManifest({ manifest: rmJson, signature: { ...rmSig, sig: 'cd'.repeat(64) }, expectedKey: pubHex }),
    /did not verify/, 'a forged signature is rejected')
  const tampered = new Map(actual)
  tampered.set(files[0].path, Buffer.from('/* injected */\n'))
  t.exception(() => verifyDriveContents(rmJson, tampered), /hash mismatch/, 'tampered file content is rejected')

  // ── 7. determinism: the signed message is reproducible from the file set ─────────
  t.is(driveReleaseSigningMessage(rmJson), driveReleaseSigningMessage(manifest), 'signing message is deterministic')

  // cleanup
  s1.destroy(); s2.destroy()
  await driveA.close(); await driveB.close()
  await storeA.close(); await storeB.close()
  await rm(src, { recursive: true, force: true })
  await rm(dirA, { recursive: true, force: true })
  await rm(dirB, { recursive: true, force: true })
})

test('drive-boot M1: the real packages/ tree collects clean (no node_modules/.node/test)', async (t) => {
  // Sanity-check the collector against the actual repo tree — no publish, just the
  // file set, so it's fast. Guards against the drive ever carrying forbidden payloads.
  const root = new URL('../../', import.meta.url).pathname
  const files = await collectCodeFiles(root)
  t.ok(files.length > 50, 'collects a substantial app tree (' + files.length + ' files)')
  const bad = files.filter(f => /\/node_modules\/|\/test\/|\.node$|\.bare$/.test(f.path))
  t.is(bad.length, 0, 'no node_modules / test / native payloads leak onto the drive')
  const total = files.reduce((n, f) => n + f.content.length, 0)
  t.ok(total < 20 * 1024 * 1024, 'pure-JS payload is drive-sized (' + (total / 1024 / 1024).toFixed(1) + ' MB)')
})
