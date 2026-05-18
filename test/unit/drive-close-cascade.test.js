/**
 * Regression test: drive.close() must NOT close the shared root corestore.
 *
 * Root cause (confirmed 2026-05-18, debug/CAPTURED-TRACE-2026-05-18.md):
 * app-lifecycle.js was constructing Hyperdrive instances with the root
 * node.store directly: `new Hyperdrive(node.store, appKey)`. Hyperdrive's
 * _close() unconditionally calls `this.corestore.close()` unless the drive is
 * a checkout/batch. This made ANY unseed path (custody expiry, eviction,
 * manual unseed) close the shared root corestore, wedging the entire relay
 * until systemd restarted the process.
 *
 * Fix: construct drives with `node.store.session()`, a lightweight
 * ref-counted view that shares the same key-addressed hypercore objects but
 * whose close() only tears down the session's own refs — not the root store.
 *
 * These tests verify all four required properties of the fix:
 *   a) root store stays open after one drive's session is closed
 *   b) other seeded drives remain operational
 *   c) fresh drives can still be opened after an unseed
 *   d) the closed drive's session actually released its resources (no leak)
 */

import test from 'brittle'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import crypto from 'hypercore-crypto'

function tmpDir () {
  const d = mkdtempSync(join(tmpdir(), 'drive-close-cascade-'))
  return { dir: d, cleanup: () => rmSync(d, { recursive: true, force: true }) }
}

function freshKey () {
  return crypto.keyPair().publicKey
}

// ---------------------------------------------------------------------------
// Core invariant: store.session().close() does NOT close root store
// ---------------------------------------------------------------------------

test('corestore.session().close() leaves root store open', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const session = store.session()
  await session.close()

  t.is(store.closed, false, 'root store is NOT closed after session.close()')
  t.ok(!store.closing, 'root store is NOT closing after session.close()')

  await store.close()
})

// ---------------------------------------------------------------------------
// Fix property (a): unseeding one drive does not close the root store
// ---------------------------------------------------------------------------

test('(a) drive.close() on session-backed drive leaves root store open', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const key1 = freshKey()
  const drive = new Hyperdrive(store.session(), key1)
  await drive.ready()

  // Simulate unseedApp
  await drive.close()

  t.is(store.closed, false, 'root store.closed === false after drive.close()')
  t.ok(!store.closing, 'root store.closing is falsy after drive.close()')

  await store.close()
})

// ---------------------------------------------------------------------------
// Fix property (b): other drives stay operational after an unseed
// ---------------------------------------------------------------------------

test('(b) sibling drive is unaffected after a different drive unseeds', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const key1 = freshKey()
  const key2 = freshKey()
  const drive1 = new Hyperdrive(store.session(), key1)
  const drive2 = new Hyperdrive(store.session(), key2)
  await Promise.all([drive1.ready(), drive2.ready()])

  // Unseed drive1
  await drive1.close()

  t.is(drive2.closed, false, 'drive2 is NOT closed after drive1.close()')
  t.is(drive2.opened, true, 'drive2 is still opened after drive1.close()')

  await drive2.close()
  await store.close()
})

// ---------------------------------------------------------------------------
// Fix property (c): fresh drives can still be opened after an unseed
// ---------------------------------------------------------------------------

test('(c) fresh drive opens successfully after an unseed', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const key1 = freshKey()
  const drive1 = new Hyperdrive(store.session(), key1)
  await drive1.ready()
  await drive1.close()

  t.is(store.closed, false, 'store still open (precondition for fresh drive)')

  const key3 = freshKey()
  const drive3 = new Hyperdrive(store.session(), key3)
  await drive3.ready()

  t.is(drive3.opened, true, 'fresh drive opens successfully after an unseed')

  await drive3.close()
  await store.close()
})

// ---------------------------------------------------------------------------
// Fix property (d): the unseeded drive's session resources are released
// ---------------------------------------------------------------------------

test('(d) unseeded drive session is actually closed (no leak)', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const key1 = freshKey()
  const drive = new Hyperdrive(store.session(), key1)
  await drive.ready()

  await drive.close()

  t.is(drive.closed, true, 'drive itself is closed')
  // The session-backed corestore held by this drive should also be closed
  t.is(drive.corestore.closed, true, "drive.corestore (the session) is closed — drive's own resources freed")

  await store.close()
})

// ---------------------------------------------------------------------------
// Regression: confirm the OLD pattern (root store directly) does break things.
// This documents the exact bug and ensures the above tests are meaningful.
// ---------------------------------------------------------------------------

test('regression: new Hyperdrive(root-store, key).close() closes root store (old broken pattern)', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  // OLD (broken) pattern: pass root store directly
  const key1 = freshKey()
  const drive = new Hyperdrive(store, key1)
  await drive.ready()

  await drive.close()

  // The root store is now closed — this is the bug we fixed
  t.is(store.closed, true, 'OLD pattern: root store IS closed after drive.close() (documents the pre-fix bug)')
  // No store.close() needed: it is already closed
})

// ---------------------------------------------------------------------------
// Multi-unseed stress: 5 drives, unseed all, root store stays open throughout
// ---------------------------------------------------------------------------

test('multi-unseed: 5 successive unseeds leave root store open each time', async (t) => {
  const { dir, cleanup } = tmpDir()
  t.teardown(cleanup)

  const store = new Corestore(dir)
  await store.ready()

  const drives = []
  for (let i = 0; i < 5; i++) {
    const key = freshKey()
    const drive = new Hyperdrive(store.session(), key)
    await drive.ready()
    drives.push(drive)
  }

  // Unseed all drives one by one (simulates repeated _runCustodyExpiryPass calls)
  for (let i = 0; i < drives.length; i++) {
    await drives[i].close()
    t.is(store.closed, false, `store open after unseeding drive ${i + 1} of ${drives.length}`)
  }

  // Verify the relay can still serve a fresh seed after all unseeds
  const keyFinal = freshKey()
  const driveFinal = new Hyperdrive(store.session(), keyFinal)
  await driveFinal.ready()
  t.is(driveFinal.opened, true, 'fresh seed drive opens after all 5 unseeds')

  await driveFinal.close()
  await store.close()
})
