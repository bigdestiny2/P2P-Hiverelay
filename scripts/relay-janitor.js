#!/usr/bin/env node
// scripts/relay-janitor.js
//
// Fleet garbage collector. Classifies every catalog entry on each relay
// and (with --apply) unseeds the junk. DRY-RUN BY DEFAULT.
//
// Safe to run only on v0.8.14+ relays: pre-v0.8.14, unseedApp() →
// drive.close() → corestore.close() tore down the shared root store, so
// a janitor would have wedged the relay. v0.8.14's per-drive
// node.store.session() removes that cascade. This script refuses to
// --apply unless every targeted relay reports version >= 0.8.14.
//
// Classification reads each relay's REAL app-registry.json over SSH
// (the public /catalog.json is a lossy projection — its `seededAt`
// defaults to now() for entries with no persisted timestamp, and
// startedAt/anchoredAt reset on every reseed, so AGE IS NOT A USABLE
// SIGNAL here). We classify on identity + commitment + serve-count,
// which are age-independent and reseed-stable:
//
//   KEEP        durability>=1 (AutoHeal-managed durable tier) OR
//               revocable===false (permanent publisher commitment) OR
//               bytesServed>0 (the relay is actually serving it) OR
//               an unexpired future retainUntil (active custody window).
//   TEST-JUNK   appId/name matches ^(test-|custody-) OR author in
//               {observatory-test-runner, custody-e2e-runner}. Our own
//               synthetic artifacts. High confidence — Tier 1c.
//   FED-JUNK    NO manifest identity at all (appId, name, author all
//               null/empty) AND durability not>=1 AND revocable!==false
//               AND no bytesServed AND no active retainUntil. A drive
//               the relay blind-accumulated via catalog-sync that has
//               zero identity, zero commitment, and has served nobody —
//               Tier 2. (durability:0 is "best-effort, no guarantee" by
//               spec; dropping it is in-spec. If it's still wanted it
//               re-federates via catalog-sync.)
//   REVIEW     has identity but isn't obviously valued (named but
//               anonymous + never served) → KEEP, list for a human.
//
// The operator API key is only needed to ACT; it's read per-relay from
// that relay's own systemd unit over SSH, never stored locally.
//
// Usage:
//   node scripts/relay-janitor.js                         # dry-run, all relays, classify only
//   node scripts/relay-janitor.js --relay utah            # one relay
//   node scripts/relay-janitor.js --tier1 --apply         # sweep our test-junk
//   node scripts/relay-janitor.js --sweep-keys keys.txt --apply  # explicit reviewed keys
//   node scripts/relay-janitor.js --cap 100               # per-relay sweep cap (default 50)
//
// --apply with no tier flag is rejected (you must opt into what to sweep).

import { execFile } from 'child_process'
import { promisify } from 'util'

const exec = promisify(execFile)

const CLOUDZY_KEY = ['-i', `${process.env.HOME}/.ssh/cloudzy_hiverelay`]
const RELAYS = {
  utah: { host: '144.172.101.215' },
  'utah-us': { host: '144.172.91.26' },
  'singapore-1': { host: '104.194.153.179' },
  'singapore-2': { host: '104.194.152.121', ssh: CLOUDZY_KEY },
  bern: { host: '45.59.123.112', ssh: CLOUDZY_KEY }
}

const args = parseArgs(process.argv.slice(2))
const APPLY = !!args.apply
const TIER1 = !!args.tier1
const ONLY_RELAY = args.relay || null
const PER_RELAY_CAP = Number(args.cap || 50)
const SWEEP_DELAY_MS = 250 // rate-limit unseed calls
// Tier-2 (fed-junk) is NOT auto-sweepable. The PearBrowser production
// drive (appKey 8b21b577…) is byte-identical to fed-junk in a relay's
// registry — appId/name/author/publisherPubkey/durability/revocable
// all null — because that relay mirrors it via catalog-sync without
// ever indexing its (blind) manifest. A relay CANNOT locally tell
// "important federated content" from "accidental accumulation". So
// fed-junk is report-only; to actually drop specific keys you pass an
// explicit, human-reviewed file: --sweep-keys <file> (one appKey/line).
const SWEEP_KEYS_FILE = args['sweep-keys'] || null

const TEST_APPID = /^(test-|custody-)/
const TEST_AUTHORS = new Set(['observatory-test-runner', 'custody-e2e-runner'])

if (APPLY && !TIER1 && !SWEEP_KEYS_FILE) {
  console.error('✗ --apply needs --tier1 (sweep our own test-junk) and/or --sweep-keys <file> (explicit reviewed appKeys).')
  console.error('  There is intentionally no "sweep all fed-junk" mode — see header comment (PearBrowser indistinguishability).')
  process.exit(1)
}

let explicitSweepKeys = new Set()
if (SWEEP_KEYS_FILE) {
  const fs = await import('fs')
  explicitSweepKeys = new Set(
    fs.readFileSync(SWEEP_KEYS_FILE, 'utf8')
      .split('\n').map(s => s.trim()).filter(s => /^[0-9a-f]{64}$/.test(s))
  )
}

const targets = ONLY_RELAY
  ? (RELAYS[ONLY_RELAY] ? [ONLY_RELAY] : die(`unknown --relay ${ONLY_RELAY}`))
  : Object.keys(RELAYS)

console.log(`▸ relay-janitor — ${APPLY ? 'APPLY' : 'DRY-RUN'}${APPLY ? ` (tier1=${TIER1} explicit-keys=${explicitSweepKeys.size} cap=${PER_RELAY_CAP}/relay)` : ''}`)
console.log('  classify by identity+commitment+serve-count (age-independent)\n')

main().catch(e => { console.error('FATAL:', e.message); process.exit(1) })

async function main () {
  const totals = { kept: 0, testJunk: 0, fedJunk: 0, review: 0, swept: 0, sweepErr: 0 }

  for (const id of targets) {
    const r = RELAYS[id]
    const sshBase = ['-o', 'ConnectTimeout=10', ...(r.ssh || []), `root@${r.host}`]

    // version gate — refuse to --apply on a pre-v0.8.14 relay
    let version = '?'
    try {
      const cap = await sshJson(sshBase, 'curl -s --max-time 6 http://127.0.0.1:9100/.well-known/hiverelay.json')
      version = cap.version || '?'
    } catch (_) { /* fall through; classify-only still works off catalog */ }

    // Read the REAL registry (not the lossy public catalog). It's a
    // JSON array (or object map) of full entries with the fields we
    // actually need: appKey, appId, name, author, durability, revocable,
    // bytesServed, retainUntil, anchored, blind, storageClass.
    let apps
    try {
      const raw = await sshText(sshBase, 'cat /root/.hiverelay/storage/app-registry.json 2>/dev/null')
      const parsed = JSON.parse(raw)
      apps = Array.isArray(parsed) ? parsed : Object.values(parsed)
    } catch (e) {
      console.log(`  ${id}: registry read failed (${e.message}) — skipping`)
      continue
    }
    const now = Date.now()

    const buckets = { keep: [], test: [], fed: [], review: [] }
    for (const a of apps) {
      buckets[classify(a, now)].push(a)
    }
    totals.kept += buckets.keep.length
    totals.testJunk += buckets.test.length
    totals.fedJunk += buckets.fed.length
    totals.review += buckets.review.length

    const applicable = (TIER1 ? buckets.test.length : 0) +
      (explicitSweepKeys.size ? apps.filter(a => explicitSweepKeys.has(a.appKey)).length : 0)
    console.log(`  ${id}  v${version}  total=${apps.length}  keep=${buckets.keep.length}  test-junk=${buckets.test.length}  fed-junk=${buckets.fed.length}  review=${buckets.review.length}` +
      (APPLY ? `  → will sweep ${Math.min(applicable, PER_RELAY_CAP)}${applicable > PER_RELAY_CAP ? ` (capped from ${applicable})` : ''}` : ''))

    // sample what fed-junk looks like so the operator can sanity-check the rule
    if (!APPLY && buckets.fed.length) {
      for (const a of buckets.fed.slice(0, 3)) {
        console.log(`      fed-junk e.g. ${(a.appKey || '').slice(0, 12)} dur=${a.durability} rev=${a.revocable} author=${a.author} served=${a.bytesServed}`)
      }
    }
    if (!APPLY && buckets.review.length) {
      for (const a of buckets.review.slice(0, 3)) {
        console.log(`      review   e.g. ${(a.appKey || '').slice(0, 12)} appId=${a.appId} name=${a.name} author=${a.author} dur=${a.durability} served=${a.bytesServed}`)
      }
    }

    if (APPLY) {
      const key = await readApiKey(sshBase).catch(() => null)
      if (!key) { console.log(`      ✗ could not read API key for ${id} — skipping sweep`); continue }
      if (!versionGE(version, '0.8.14')) {
        console.log(`      ✗ ${id} is v${version} (<0.8.14) — refusing to sweep (pre-fix unseed cascades). Deploy v0.8.14 first.`)
        continue
      }
      // Auto-sweepable = our own test-junk only. Explicit reviewed
      // keys may name anything (incl. fed-junk you've eyeballed).
      const explicit = explicitSweepKeys.size
        ? [...buckets.test, ...buckets.fed, ...buckets.review, ...buckets.keep]
            .filter(a => explicitSweepKeys.has(a.appKey))
        : []
      const toSweep = [
        ...(TIER1 ? buckets.test : []),
        ...explicit
      ].slice(0, PER_RELAY_CAP)
      for (const a of toSweep) {
        const ak = a.appKey
        if (!ak || ak.length !== 64) continue
        try {
          const out = await sshText(sshBase, `curl -s --max-time 8 -X POST http://127.0.0.1:9100/unseed -H 'authorization: Bearer ${key}' -H 'content-type: application/json' -d '{"appKey":"${ak}"}'`)
          if (out.includes('"ok":true')) {
            totals.swept++; process.stdout.write('.')
          } else {
            totals.sweepErr++; process.stdout.write('x')
          }
        } catch (_) { totals.sweepErr++; process.stdout.write('x') }
        await sleep(SWEEP_DELAY_MS)
      }
      if (toSweep.length) process.stdout.write('\n')
    }
  }

  console.log('\n  ── totals ──')
  console.log(`  keep=${totals.kept}  test-junk=${totals.testJunk}  fed-junk=${totals.fedJunk}  review=${totals.review}`)
  if (APPLY) {
    console.log(`  swept=${totals.swept}  errors=${totals.sweepErr}`)
  } else {
    console.log('\n  DRY-RUN. Safe action:')
    console.log(`    --tier1 --apply   → sweep ${totals.testJunk} test-junk (our own synthetic artifacts)`)
    console.log(`\n  fed-junk (${totals.fedJunk}) is REPORT-ONLY and intentionally not auto-sweepable:`)
    console.log('    a relay cannot distinguish important mirrored content (e.g. the')
    console.log('    PearBrowser drive 8b21b577…) from accidental catalog-sync accretion —')
    console.log('    both are identity-less in the local registry. To drop specific keys,')
    console.log('    review them by hand and pass --sweep-keys <file> (one 64-hex appKey/line).')
    console.log(`  (per-relay cap ${PER_RELAY_CAP}; raise with --cap. Re-run dry-run after to confirm.)`)
  }
}

// ── classification ──────────────────────────────────────────────────────

function classify (a, now) {
  const durable = Number(a.durability) >= 1
  const served = Number(a.bytesServed) > 0
  const activeRetain = Number.isFinite(Number(a.retainUntil)) &&
    Number(a.retainUntil) > now

  // ── hard KEEP guards (commitment / value signals) ──
  if (durable) return 'keep' // AutoHeal-managed durable tier
  if (a.revocable === false) return 'keep' // permanent publisher commitment
  if (served) return 'keep' // relay is actually serving it
  if (activeRetain && a.blind === true) return 'keep' // live custody window

  const appId = String(a.appId || '').trim()
  const name = String(a.name || '').trim()
  const author = String(a.author || '').trim()

  // ── TEST-JUNK — our own synthetic artifacts (identity-bearing) ──
  if (TEST_APPID.test(appId) || TEST_APPID.test(name) || TEST_AUTHORS.has(author)) {
    return 'test'
  }

  // ── FED-JUNK — zero manifest identity, zero commitment, served
  // nobody. The relay blind-accumulated it via catalog-sync. Age is
  // deliberately NOT a factor (startedAt/anchoredAt reset on reseed and
  // the public seededAt defaults to now — all unreliable). The
  // signature itself is sufficient and age-independent: a drive with no
  // appId AND no name AND no author has never had a manifest, so it's
  // not a real published app; durability<1 + revocable≠false means no
  // one asked us to keep it; bytesServed falsy means it serves nobody.
  const noIdentity = appId === '' && name === '' &&
    (author === '' || author === 'anonymous')
  if (noIdentity && !durable && a.revocable !== false && !served && !activeRetain) {
    return 'fed'
  }

  // ── REVIEW — has some identity but isn't obviously valued. KEEP it,
  // but surface for a human (don't auto-sweep identity-bearing content).
  return 'review'
}

// ── ssh / api helpers ───────────────────────────────────────────────────

async function sshText (sshBase, remoteCmd) {
  const { stdout } = await exec('ssh', [...sshBase, remoteCmd], { maxBuffer: 64 * 1024 * 1024 })
  return stdout
}
async function sshJson (sshBase, remoteCmd) {
  const out = await sshText(sshBase, remoteCmd)
  return JSON.parse(out)
}
async function readApiKey (sshBase) {
  // Read HIVERELAY_API_KEY from the relay's own systemd unit. Never
  // printed, never stored locally.
  const out = await sshText(sshBase, "grep -oE 'HIVERELAY_API_KEY=[A-Za-z0-9._-]+' /etc/systemd/system/hiverelay.service | head -1 | cut -d= -f2")
  const key = out.trim()
  if (!key) throw new Error('no API key in systemd unit')
  return key
}

function versionGE (v, min) {
  const pa = String(v).split('.').map(Number)
  const pb = String(min).split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true
    if ((pa[i] || 0) < (pb[i] || 0)) return false
  }
  return true
}

function parseArgs (argv) {
  const o = {}
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i]
    if (x.startsWith('--')) {
      const k = x.slice(2)
      const n = argv[i + 1]
      if (n && !n.startsWith('--')) { o[k] = n; i++ } else o[k] = true
    }
  }
  return o
}
function sleep (ms) { return new Promise(resolve => setTimeout(resolve, ms)) }
function die (m) { console.error('✗', m); process.exit(1) }
