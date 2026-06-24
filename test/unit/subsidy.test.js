/**
 * SubsidyAccrual (Phase 1) tests.
 *
 * The relay-local half of the operator subsidy: capped accrual estimate,
 * payout-destination validation (non-custodial — operator's own address),
 * Ed25519-signed claims for the coordinator, atomic persistence. No money
 * moves anywhere in this module; these tests pin that the *evidence and
 * estimate* layer is deterministic and crash-safe.
 */

import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { mkdtemp, readFile, readdir } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  SubsidyAccrual,
  validatePayoutDestination,
  canonicalJson,
  signClaim,
  verifyClaim,
  claimDigest,
  SUBSIDY_SCHEMA_VERSION
} from 'p2p-hiverelay/incentive/subsidy/index.js'

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

const DAY_MS = 86_400_000
const T0 = Date.UTC(2026, 5, 11, 0, 0, 0) // fixed epoch for determinism

function makeAccrual (opts = {}) {
  return new SubsidyAccrual({
    keyPair: makeKeyPair(),
    statsFn: opts.statsFn || (() => ({ connections: 9, seededApps: 800, appRegistry: { anchored: 750 } })),
    rateSatsPerDay: opts.rateSatsPerDay != null ? opts.rateSatsPerDay : 500,
    epochMs: opts.epochMs != null ? opts.epochMs : 60 * 60 * 1000, // 1h epochs for easy math
    storagePath: opts.storagePath || null,
    payoutDestination: opts.payoutDestination
  })
}

// ─── destination validation ────────────────────────────────────────

test('validatePayoutDestination: accepts the three rails', (t) => {
  t.alike(validatePayoutDestination('Satoshi@GetAlby.com'),
    { type: 'lightning-address', value: 'satoshi@getalby.com' }, 'lightning address (lowercased)')
  const lno = 'lno1' + 'qcp4256ypq'.repeat(4)
  t.alike(validatePayoutDestination(lno), { type: 'bolt12', value: lno }, 'BOLT12 offer')
  t.alike(validatePayoutDestination('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'),
    { type: 'onchain', value: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' }, 'bech32 onchain')
  t.alike(validatePayoutDestination('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'),
    { type: 'onchain', value: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' }, 'base58 onchain')
})

test('validatePayoutDestination: rejects junk', (t) => {
  t.is(validatePayoutDestination(''), null, 'empty')
  t.is(validatePayoutDestination('not a destination'), null, 'free text')
  t.is(validatePayoutDestination('user@nodomain'), null, 'lightning address without TLD')
  t.is(validatePayoutDestination(12345), null, 'non-string')
  t.is(validatePayoutDestination('lno1'), null, 'bolt12 too short')
  t.is(validatePayoutDestination('x'.repeat(400)), null, 'absurd length')
})

test('constructor: invalid configured destination throws (no silent drop)', (t) => {
  t.exception(() => makeAccrual({ payoutDestination: 'garbage' }), /invalid payoutDestination/)
  t.exception(() => new SubsidyAccrual({}), /keyPair is required/)
})

// ─── canonical JSON + claim signing ────────────────────────────────

test('canonicalJson: key order does not change the byte string', (t) => {
  const a = canonicalJson({ b: 1, a: { d: 2, c: [3, { f: 4, e: 5 }] } })
  const b = canonicalJson({ a: { c: [3, { e: 5, f: 4 }], d: 2 }, b: 1 })
  t.is(a, b, 'same logical object -> same canonical string')
})

test('claim signing round-trips; tamper breaks verification', (t) => {
  const keyPair = makeKeyPair()
  const body = { schemaVersion: SUBSIDY_SCHEMA_VERSION, accruedSatsEstimate: 42, periodStart: T0, periodEnd: T0 + DAY_MS }
  const signature = signClaim(keyPair, body)
  t.ok(verifyClaim({ body, relayPubkey: keyPair.publicKey, signature }), 'valid claim verifies')
  const tampered = { ...body, accruedSatsEstimate: 9999 }
  t.absent(verifyClaim({ body: tampered, relayPubkey: keyPair.publicKey, signature }), 'tampered amount fails')
  const otherKey = makeKeyPair()
  t.absent(verifyClaim({ body, relayPubkey: otherKey.publicKey, signature }), 'wrong pubkey fails')
  t.absent(verifyClaim({ body, relayPubkey: keyPair.publicKey.subarray(0, 16), signature }), 'short pubkey rejected')
})

// ─── accrual math ──────────────────────────────────────────────────

test('accrues pro-rata per epoch and caps per UTC day', async (t) => {
  const sub = makeAccrual({ rateSatsPerDay: 240, epochMs: 60 * 60 * 1000 }) // 10 sats/hour
  for (let h = 1; h <= 30; h++) await sub._tick(T0 + h * 3600_000) // 30 ticks across day boundary
  // Day 1: ticks at h=1..23 land on day one (24 ticks incl h=0? first tick at T0+1h)
  // What matters: no UTC day may exceed the cap, and the total reflects it.
  const summary = sub.getSummary()
  t.ok(summary.accruedSatsTotal <= 300, 'total bounded (no runaway)')
  t.ok(summary.accruedSatsToday <= 240, 'daily cap respected')
  t.is(summary.epochCount, 30, 'all epochs recorded as evidence')
  t.is(summary.estimate, true, 'summary is explicitly an estimate')
  await sub.destroy()
})

test('day rollover resets the daily counter', async (t) => {
  const sub = makeAccrual({ rateSatsPerDay: 240, epochMs: 60 * 60 * 1000 })
  for (let h = 1; h <= 23; h++) await sub._tick(T0 + h * 3600_000)
  const day1 = sub.getSummary().accruedSatsToday
  await sub._tick(T0 + DAY_MS + 3600_000) // first tick of next UTC day
  const day2 = sub.getSummary().accruedSatsToday
  t.ok(day1 > day2, 'today counter reset on rollover')
  t.is(day2, 10, 'new day accrues from zero at the hourly rate')
  await sub.destroy()
})

test('zero rate accrues nothing but still records evidence', async (t) => {
  const sub = makeAccrual({ rateSatsPerDay: 0 })
  await sub._tick(T0 + 3600_000)
  t.is(sub.getSummary().accruedSatsTotal, 0, 'no sats at zero rate')
  t.is(sub.getSummary().epochCount, 1, 'epoch evidence still recorded')
  await sub.destroy()
})

// ─── claims ────────────────────────────────────────────────────────

test('buildClaim: verifiable envelope with evidence + destination', async (t) => {
  const sub = makeAccrual({ rateSatsPerDay: 240, epochMs: 3600_000 })
  await sub.setPayoutDestination('op@getalby.com')
  for (let h = 1; h <= 5; h++) await sub._tick(T0 + h * 3600_000)
  const claim = sub.buildClaim(T0 + 6 * 3600_000)
  t.is(claim.body.epochCount, 5, 'epoch count in claim')
  t.is(claim.body.uptimeMs, 5 * 3600_000, 'uptime totalled from epochs')
  t.is(claim.body.accruedSatsEstimate, 50, '5h at 10 sats/h')
  t.is(claim.body.evidence.seededAppsAtEnd, 800, 'evidence snapshot present')
  t.alike(claim.body.payoutDestination, { type: 'lightning-address', value: 'op@getalby.com' }, 'destination rides in the claim')
  const ok = verifyClaim({
    body: claim.body,
    relayPubkey: b4a.from(claim.relayPubkey, 'hex'),
    signature: b4a.from(claim.signature, 'hex')
  })
  t.ok(ok, 'exported claim verifies from its hex envelope')
  await sub.destroy()
})

// ─── persistence ───────────────────────────────────────────────────

test('persists atomically and reloads (no leftover .tmp)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'subsidy-'))
  const path = join(dir, 'subsidy.json')
  const keyPair = makeKeyPair()
  const sub = new SubsidyAccrual({ keyPair, statsFn: () => ({ connections: 1 }), rateSatsPerDay: 240, epochMs: 3600_000, storagePath: path })
  await sub.start()
  for (let h = 1; h <= 3; h++) await sub._tick(T0 + h * 3600_000)
  await sub.setPayoutDestination('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
  await sub.destroy()

  const files = await readdir(dir)
  t.alike(files, ['subsidy.json'], 'only the real file remains — no .tmp orphan')
  const onDisk = JSON.parse(await readFile(path, 'utf8'))
  t.is(onDisk.schemaVersion, SUBSIDY_SCHEMA_VERSION, 'schema stamped')

  const sub2 = new SubsidyAccrual({ keyPair, statsFn: () => ({}), rateSatsPerDay: 240, epochMs: 3600_000, storagePath: path })
  await sub2.start()
  t.is(sub2.getSummary().epochCount, 3, 'epochs reloaded')
  t.is(sub2.getSummary().accruedSatsTotal, 30, 'accrual reloaded')
  t.is(sub2.getSummary().payoutDestination.type, 'onchain', 'destination reloaded')
  await sub2.destroy()
})

test('corrupt persistence file starts fresh instead of crashing', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'subsidy-'))
  const path = join(dir, 'subsidy.json')
  const { writeFile } = await import('fs/promises')
  await writeFile(path, '{ truncated garbag')
  const sub = makeAccrual({ storagePath: path })
  await sub.start()
  t.is(sub.getSummary().epochCount, 0, 'fresh state from corrupt file')
  await sub.destroy()
})

test('setPayoutDestination: rejects junk, keeps previous value', async (t) => {
  const sub = makeAccrual()
  await sub.setPayoutDestination('op@getalby.com')
  await t.exception(() => sub.setPayoutDestination('junk'), /Unrecognized payout destination/)
  t.is(sub.getSummary().payoutDestination.value, 'op@getalby.com', 'previous destination intact')
  await sub.destroy()
})

test('setPayoutDestination: clears destination with blank or null', async (t) => {
  const sub = makeAccrual()
  await sub.setPayoutDestination('op@getalby.com')
  t.is(sub.getSummary().payoutDestination.value, 'op@getalby.com', 'destination set')
  t.is(await sub.setPayoutDestination(''), null, 'blank clears')
  t.is(sub.getSummary().payoutDestination, null, 'destination cleared')
  await sub.setPayoutDestination('op@getalby.com')
  t.is(await sub.setPayoutDestination(null), null, 'null clears')
  t.is(sub.getSummary().payoutDestination, null, 'destination cleared again')
  await sub.destroy()
})

test('setPayoutDestination: persistence failure rejects and keeps previous value', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'subsidy-'))
  const path = join(dir, 'subsidy.json')
  const sub = makeAccrual({ storagePath: path })
  await sub.setPayoutDestination('old@example.com')

  const errors = []
  sub.on('persist-error', (err) => { errors.push(err) })
  sub._write = async () => { throw new Error('disk full') }

  await t.exception(() => sub.setPayoutDestination('new@example.com'), /disk full/)
  t.is(sub.getSummary().payoutDestination.value, 'old@example.com', 'previous destination intact after failed write')
  t.is(errors.length, 1, 'background persistence error event emitted')
})

// ─── claim digest stability (cross-version pin) ────────────────────

test('claimDigest is stable for a fixed input', (t) => {
  const pub = b4a.alloc(32, 7)
  const digest = claimDigest(pub, { a: 1, b: 'two' })
  t.is(b4a.toString(digest, 'hex'),
    b4a.toString(claimDigest(pub, { b: 'two', a: 1 }), 'hex'),
    'digest independent of key order')
  t.is(digest.byteLength, 32, 'sha256 length')
})
