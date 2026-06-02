#!/usr/bin/env node

/**
 * test-seeding-manifest-lifetime.js
 *
 * Validates the optional `lifetime` field on drive entries in the seeding
 * manifest. Specifically:
 *
 *   1. Valid lifetimes ('persistent' | 'session' | 'ephemeral') are accepted.
 *   2. Unknown lifetimes are rejected at sign time (loud failure, not silent).
 *   3. Default 'persistent' is byte-stripped from the canonical payload, so
 *      a manifest signed with explicit `lifetime: 'persistent'` produces the
 *      exact same signature as one signed without the field at all.
 *   4. A new manifest with `lifetime: 'session'` round-trips through verify
 *      — same lifetime survives sign+verify.
 *   5. Old-shaped manifests (no `lifetime` anywhere) still verify cleanly.
 *   6. `defaultLifetimeTtlMs()` returns the expected ms values, including
 *      Infinity for persistent and the persistent default for unknown values.
 *   7. `driveLifetime()` returns the effective lifetime, including the
 *      default when absent and the default when set to an unknown value.
 */

import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  createSeedingManifest,
  verifySeedingManifest,
  defaultLifetimeTtlMs,
  driveLifetime,
  LIFETIME_VALUES,
  LIFETIME_TTL_MS
} from '../packages/core/core/seeding-manifest.js'

let passed = 0
let failed = 0

function assert (condition, label) {
  if (condition) {
    console.log(`  PASS  ${label}`)
    passed++
  } else {
    console.log(`  FAIL  ${label}`)
    failed++
  }
}

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const FAKE_DRIVE_KEY = 'a'.repeat(64)
const ANOTHER_DRIVE_KEY = 'b'.repeat(64)

// ── 1. Valid lifetimes are accepted ─────────────────────────────────────────
function testValidLifetimes () {
  console.log('\n── 1. Valid lifetimes accepted ──')
  const kp = makeKeyPair()
  for (const lifetime of LIFETIME_VALUES) {
    let ok = false
    try {
      createSeedingManifest({
        keyPair: kp,
        relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
        drives: [{ driveKey: FAKE_DRIVE_KEY, lifetime }]
      })
      ok = true
    } catch (err) {
      console.log('    threw:', err.message)
    }
    assert(ok, `lifetime='${lifetime}' accepted at sign time`)
  }
}

// ── 2. Unknown lifetimes are rejected ───────────────────────────────────────
function testUnknownLifetimeRejected () {
  console.log('\n── 2. Unknown lifetime rejected ──')
  const kp = makeKeyPair()
  let threw = false
  let msg = null
  try {
    createSeedingManifest({
      keyPair: kp,
      relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
      drives: [{ driveKey: FAKE_DRIVE_KEY, lifetime: 'sesion' /* typo */ }]
    })
  } catch (err) {
    threw = true
    msg = err.message
  }
  assert(threw, 'unknown lifetime throws')
  assert(msg && msg.includes('lifetime'), 'error message mentions lifetime')
}

// ── 3. Default 'persistent' is stripped from canonical payload ──────────────
function testPersistentByteEqual () {
  console.log('\n── 3. Explicit persistent === absent (byte equal) ──')
  const kp = makeKeyPair()
  const ts = 1700000000000
  const a = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
    drives: [{ driveKey: FAKE_DRIVE_KEY }],
    timestamp: ts
  })
  const b = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
    drives: [{ driveKey: FAKE_DRIVE_KEY, lifetime: 'persistent' }],
    timestamp: ts
  })
  assert(a.signature === b.signature, 'signatures byte-identical for absent vs explicit persistent')
  // Neither manifest's normalized drive entries should contain a lifetime key,
  // since persistent is the default and gets dropped on the way out.
  assert(!('lifetime' in a.drives[0]), 'absent: no lifetime key in normalized drive')
  assert(!('lifetime' in b.drives[0]), 'explicit persistent: no lifetime key in normalized drive')
}

// ── 4. Session lifetime round-trips ─────────────────────────────────────────
function testSessionRoundTrip () {
  console.log('\n── 4. lifetime: "session" round-trips ──')
  const kp = makeKeyPair()
  const m = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
    drives: [
      { driveKey: FAKE_DRIVE_KEY, lifetime: 'session' },
      { driveKey: ANOTHER_DRIVE_KEY, lifetime: 'ephemeral', channel: 'hand-42' }
    ]
  })
  assert(m.drives[0].lifetime === 'session', 'session preserved')
  assert(m.drives[1].lifetime === 'ephemeral', 'ephemeral preserved')
  assert(m.drives[1].channel === 'hand-42', 'channel coexists with lifetime')
  const v = verifySeedingManifest(m)
  assert(v.valid, 'manifest with lifetimes verifies (' + (v.reason || 'ok') + ')')
}

// ── 5. Old-shape manifests still verify ─────────────────────────────────────
function testOldShape () {
  console.log('\n── 5. Old-shape (no lifetime) manifest verifies ──')
  const kp = makeKeyPair()
  const m = createSeedingManifest({
    keyPair: kp,
    relays: [{ url: 'hyperswarm://abc', role: 'primary' }],
    drives: [{ driveKey: FAKE_DRIVE_KEY, channel: 'prod' }]
  })
  const v = verifySeedingManifest(m)
  assert(v.valid, 'old-shape manifest verifies')
}

// ── 6. defaultLifetimeTtlMs() ───────────────────────────────────────────────
function testDefaultTtl () {
  console.log('\n── 6. defaultLifetimeTtlMs() ──')
  assert(defaultLifetimeTtlMs('persistent') === Infinity, 'persistent → Infinity')
  assert(defaultLifetimeTtlMs('session') === LIFETIME_TTL_MS.session, 'session → 24h-ish')
  assert(defaultLifetimeTtlMs('ephemeral') === LIFETIME_TTL_MS.ephemeral, 'ephemeral → 1h-ish')
  assert(defaultLifetimeTtlMs(undefined) === Infinity, 'undefined → persistent default (Infinity)')
  assert(defaultLifetimeTtlMs('bogus') === Infinity, 'unknown → persistent default (safer)')
}

// ── 7. driveLifetime() ──────────────────────────────────────────────────────
function testDriveLifetimeHelper () {
  console.log('\n── 7. driveLifetime() ──')
  assert(driveLifetime({ driveKey: FAKE_DRIVE_KEY }) === 'persistent', 'absent → persistent')
  assert(driveLifetime({ lifetime: 'session' }) === 'session', 'explicit → that value')
  assert(driveLifetime({ lifetime: 'bogus' }) === 'persistent', 'unknown → persistent default')
  assert(driveLifetime(null) === 'persistent', 'null → persistent')
}

async function main () {
  testValidLifetimes()
  testUnknownLifetimeRejected()
  testPersistentByteEqual()
  testSessionRoundTrip()
  testOldShape()
  testDefaultTtl()
  testDriveLifetimeHelper()
  console.log(`\n── done: ${passed} passed, ${failed} failed ──`)
  process.exit(failed === 0 ? 0 : 1)
}

main().catch((err) => {
  console.error('fatal:', err)
  process.exit(2)
})
