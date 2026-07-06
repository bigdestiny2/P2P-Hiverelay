/**
 * Regression tests for audit HR-SVC-004 — unauthenticated fork-proof
 * quarantine.
 *
 * The vulnerability: ForkDetector.report() never cryptographically
 * verified fork evidence, and Federation._pullForkProofs accepted
 * unsigned 'unverified-observer' proofs with no pubkey allow-list. Any
 * followed relay could quarantine ANY drive network-wide (censorship /
 * DoS).
 *
 * These tests prove:
 *   1. A forged / unsigned fork proof does NOT quarantine a drive on the
 *      network path.
 *   2. A genuine signed conflicting-heads proof (two different blocks
 *      each signed by the hypercore key) STILL quarantines.
 *   3. Federation._pullForkProofs gates pulled proofs on (a) a signed
 *      observer envelope, (b) a trusted-observer allow-list, and (c)
 *      cryptographic verification of the underlying fork evidence.
 *
 * They are deliberately brittle — they assert the exact security
 * behavior so a regression that re-opens the censorship hole fails loudly.
 */

import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ForkDetector } from 'p2p-hiverelay/core/fork-detector.js'
import { Federation } from 'p2p-hiverelay/core/federation.js'
import {
  verifyForkEvidence,
  signForkProof
} from 'p2p-hiverelay/core/fork-proof-signing.js'

// ─── Test crypto helpers ──────────────────────────────────────────

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// Build a GENUINE hypercore fork proof: two different block payloads,
// each carrying a valid Ed25519 signature by the hypercore's OWN key.
// This is what real equivocation looks like — the core key signed two
// conflicting heads at the same index.
function genuineForkProof () {
  const coreKeyPair = makeKeyPair() // the hypercore's keypair
  const hypercoreKey = b4a.toString(coreKeyPair.publicKey, 'hex')

  const blockA = b4a.from('head-A@index-7', 'utf8')
  const blockB = b4a.from('head-B@index-7-conflicting', 'utf8')

  const sigA = b4a.alloc(64)
  const sigB = b4a.alloc(64)
  sodium.crypto_sign_detached(sigA, blockA, coreKeyPair.secretKey)
  sodium.crypto_sign_detached(sigB, blockB, coreKeyPair.secretKey)

  return {
    hypercoreKey,
    coreKeyPair,
    blockIndex: 7,
    evidenceA: {
      fromRelay: 'r1',
      block: b4a.toString(blockA, 'hex'),
      signature: b4a.toString(sigA, 'hex')
    },
    evidenceB: {
      fromRelay: 'r2',
      block: b4a.toString(blockB, 'hex'),
      signature: b4a.toString(sigB, 'hex')
    }
  }
}

// A forged "proof": well-formed shape, but the signatures are junk that
// no hypercore key signed. This is what an attacker POSTs / gossips to
// try to quarantine an arbitrary drive.
function forgedForkProof (hypercoreKey = 'a'.repeat(64)) {
  return {
    hypercoreKey,
    blockIndex: 3,
    evidenceA: { fromRelay: 'attacker-1', block: 'ab'.repeat(16), signature: 'cd'.repeat(64) },
    evidenceB: { fromRelay: 'attacker-2', block: 'ef'.repeat(16), signature: 'ba'.repeat(64) }
  }
}

// ─── verifyForkEvidence primitive ─────────────────────────────────

test('verifyForkEvidence accepts genuine conflicting signed heads', async (t) => {
  const p = genuineForkProof()
  const r = verifyForkEvidence({ hypercoreKey: p.hypercoreKey, evidenceA: p.evidenceA, evidenceB: p.evidenceB })
  t.ok(r.valid, 'two blocks signed by the hypercore key = real fork')
})

test('verifyForkEvidence rejects forged (unsigned) evidence', async (t) => {
  const f = forgedForkProof()
  const r = verifyForkEvidence({ hypercoreKey: f.hypercoreKey, evidenceA: f.evidenceA, evidenceB: f.evidenceB })
  t.absent(r.valid, 'junk signatures do not verify under the hypercore key')
})

test('verifyForkEvidence rejects evidence signed by a DIFFERENT key', async (t) => {
  // Signatures are valid Ed25519 sigs, but by an attacker key — NOT the
  // hypercore key. This is the subtle attack: a well-formed signature
  // that isn't the core equivocating.
  const attacker = makeKeyPair()
  const victimHypercoreKey = b4a.toString(makeKeyPair().publicKey, 'hex')
  const blockA = b4a.from('x', 'utf8')
  const blockB = b4a.from('y', 'utf8')
  const sigA = b4a.alloc(64); sodium.crypto_sign_detached(sigA, blockA, attacker.secretKey)
  const sigB = b4a.alloc(64); sodium.crypto_sign_detached(sigB, blockB, attacker.secretKey)
  const r = verifyForkEvidence({
    hypercoreKey: victimHypercoreKey,
    evidenceA: { block: b4a.toString(blockA, 'hex'), signature: b4a.toString(sigA, 'hex') },
    evidenceB: { block: b4a.toString(blockB, 'hex'), signature: b4a.toString(sigB, 'hex') }
  })
  t.absent(r.valid, 'sigs by an attacker key are not the hypercore equivocating')
})

test('verifyForkEvidence rejects identical blocks (not a fork)', async (t) => {
  const kp = makeKeyPair()
  const hypercoreKey = b4a.toString(kp.publicKey, 'hex')
  const block = b4a.from('same', 'utf8')
  const sig = b4a.alloc(64); sodium.crypto_sign_detached(sig, block, kp.secretKey)
  const ev = { block: b4a.toString(block, 'hex'), signature: b4a.toString(sig, 'hex') }
  const r = verifyForkEvidence({ hypercoreKey, evidenceA: ev, evidenceB: { ...ev } })
  t.absent(r.valid, 'two copies of the same signed block is not equivocation')
})

// ─── ForkDetector.report() network provenance gate ────────────────

test('report(provenance:network) REFUSES forged evidence — no quarantine', async (t) => {
  const fd = new ForkDetector({})
  const f = forgedForkProof()
  let rejected = null
  fd.on('fork-report-rejected', (e) => { rejected = e })
  const r = fd.report({
    hypercoreKey: f.hypercoreKey,
    blockIndex: f.blockIndex,
    evidenceA: f.evidenceA,
    evidenceB: f.evidenceB,
    provenance: 'network'
  })
  t.absent(r.ok, 'forged network report is refused')
  t.ok(r.reason.includes('unverified fork evidence'), 'reason names the missing proof')
  t.ok(rejected, 'fork-report-rejected emitted')
  t.absent(fd.isQuarantined(f.hypercoreKey), 'drive is NOT quarantined by forged evidence')
})

test('report(provenance:network) ACCEPTS a genuine signed conflicting-heads proof', async (t) => {
  const fd = new ForkDetector({})
  const p = genuineForkProof()
  const r = fd.report({
    hypercoreKey: p.hypercoreKey,
    blockIndex: p.blockIndex,
    evidenceA: p.evidenceA,
    evidenceB: p.evidenceB,
    provenance: 'network'
  })
  t.ok(r.ok, 'genuine cryptographic fork proof is accepted')
  t.ok(fd.isQuarantined(p.hypercoreKey), 'genuine fork quarantines the drive')
})

test('report() local provenance still accepts lightweight self-detected evidence', async (t) => {
  // Preserve legitimate LOCAL fork handling: the client observed its own
  // core truncate / its own quorum diverge. That path uses non-crypto
  // placeholder evidence and must keep working.
  const fd = new ForkDetector({})
  const key = 'a'.repeat(64)
  const r = fd.report({
    hypercoreKey: key,
    blockIndex: 0,
    evidenceA: { fromRelay: 'local', block: 'truncate-pre', signature: 'auto-pre' },
    evidenceB: { fromRelay: 'replication', block: 'truncate-post', signature: 'auto-post' }
    // provenance defaults to 'local'
  })
  t.ok(r.ok, 'local self-detection is internally trusted')
  t.ok(fd.isQuarantined(key), 'local fork still quarantines')
})

// ─── Federation._pullForkProofs authentication gates ──────────────

// Minimal node stub carrying a real ForkDetector, so we can drive
// _pullForkProofs without spinning a RelayNode. We override _fetchJson
// to return a canned /api/forks/proofs payload.
function fedWith (proofs, { trustedForkObservers = [] } = {}) {
  const forkDetector = new ForkDetector({})
  const fed = new Federation({ node: { forkDetector }, trustedForkObservers })
  fed._fetchJson = async () => ({ proofs })
  return { fed, forkDetector }
}

test('_pullForkProofs REJECTS bare unsigned proofs (no unverified-observer path)', async (t) => {
  const f = forgedForkProof()
  const bare = { hypercoreKey: f.hypercoreKey, blockIndex: f.blockIndex, evidence: [f.evidenceA, f.evidenceB] }
  const { fed, forkDetector } = fedWith([bare], { trustedForkObservers: [] })
  await fed._pullForkProofs('http://peer.test')
  t.absent(forkDetector.isQuarantined(f.hypercoreKey), 'unsigned proof cannot quarantine')
})

test('_pullForkProofs REJECTS signed proof from an observer NOT on the allow-list', async (t) => {
  const p = genuineForkProof()
  const observer = makeKeyPair()
  const signed = signForkProof(
    { hypercoreKey: p.hypercoreKey, blockIndex: p.blockIndex, evidence: [p.evidenceA, p.evidenceB] },
    observer
  )
  // Allow-list is EMPTY → even a genuine, validly-signed proof is refused.
  const { fed, forkDetector } = fedWith([signed], { trustedForkObservers: [] })
  await fed._pullForkProofs('http://peer.test')
  t.absent(forkDetector.isQuarantined(p.hypercoreKey), 'untrusted observer cannot quarantine (fail closed)')
})

test('_pullForkProofs REJECTS trusted observer whose evidence is forged', async (t) => {
  // Observer is trusted, envelope signature is valid — but the underlying
  // fork evidence is junk. Must NOT quarantine: a trusted observer still
  // cannot censor a drive it has no cryptographic proof against.
  const f = forgedForkProof()
  const observer = makeKeyPair()
  const observerHex = b4a.toString(observer.publicKey, 'hex')
  const signed = signForkProof(
    { hypercoreKey: f.hypercoreKey, blockIndex: f.blockIndex, evidence: [f.evidenceA, f.evidenceB] },
    observer
  )
  const { fed, forkDetector } = fedWith([signed], { trustedForkObservers: [observerHex] })
  let rejected = null
  fed.on('fork-proof-rejected', (e) => { rejected = e })
  await fed._pullForkProofs('http://peer.test')
  t.absent(forkDetector.isQuarantined(f.hypercoreKey), 'trusted observer + forged evidence = no quarantine')
  t.ok(rejected, 'rejection surfaced')
})

test('_pullForkProofs QUARANTINES on a trusted observer + genuine signed conflicting-heads proof', async (t) => {
  const p = genuineForkProof()
  const observer = makeKeyPair()
  const observerHex = b4a.toString(observer.publicKey, 'hex')
  const signed = signForkProof(
    { hypercoreKey: p.hypercoreKey, blockIndex: p.blockIndex, evidence: [p.evidenceA, p.evidenceB] },
    observer
  )
  const { fed, forkDetector } = fedWith([signed], { trustedForkObservers: [observerHex] })
  let merged = null
  fed.on('fork-proofs-merged', (e) => { merged = e })
  await fed._pullForkProofs('http://peer.test')
  t.ok(forkDetector.isQuarantined(p.hypercoreKey), 'legitimate proven fork DOES quarantine')
  t.ok(merged && merged.count === 1, 'merged exactly one proof')
})

test('trustedForkObservers config drops malformed entries (no silent trust widening)', async (t) => {
  const fed = new Federation({
    node: { forkDetector: new ForkDetector({}) },
    trustedForkObservers: ['not-hex', 'AB'.repeat(32), 42, null, 'zz'.repeat(32)]
  })
  // Only the valid 64-hex entry survives (lowercased).
  t.is(fed.trustedForkObservers.size, 1)
  t.ok(fed.trustedForkObservers.has('ab'.repeat(32)))
})
