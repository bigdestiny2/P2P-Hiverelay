// secret-sharing-service: Phase-1 spike for verifiable encrypted-share
// custody (the "B + D" design). Exercises the PVSS primitive end-to-end:
// a client-side dealer splits a secret t-of-n, relays publicly verify the
// encrypted shares they custody WITHOUT any secret key, shareholders
// decrypt with a correctness proof, and a client reconstructs via
// Lagrange-in-exponent. The malicious-dealer and malicious-relay paths are
// pinned, plus the blindness invariant (the published bundle leaks no
// secret, and public-only data cannot recover the key).

import test from 'brittle'
import { keygen, split, verifyShares, decryptShare, verifyDecryptedShare, reconstruct, deriveKey } from 'p2p-hiverelay-client/secret-sharing.js'

async function shareholders (n) {
  const keys = []
  for (let i = 0; i < n; i++) keys.push(await keygen())
  return keys
}

// Decrypt a chosen subset of encrypted shares using the matching
// shareholder secret keys (share index i ↔ shareholders[i - 1]).
async function decryptSubset (pub, keys, indices) {
  const out = []
  for (const idx of indices) {
    const enc = pub.encryptedShares.find(s => s.index === idx)
    const dec = await decryptShare({ encryptedShare: enc, secretKey: keys[idx - 1].secretKey })
    out.push(dec)
  }
  return out
}

test('PVSS round-trip: any t-of-n subset reconstructs the same secret', async (t) => {
  const keys = await shareholders(5)
  const res = await split({ threshold: 3, shareholders: keys.map(k => k.publicKey) })

  t.is(res.public.threshold, 3, 'threshold echoed')
  t.is(res.public.encryptedShares.length, 5, 'one encrypted share per shareholder')
  t.is(res.public.commitments.length, 3, 't Feldman commitments (degree t-1)')

  const a = await decryptSubset(res.public, keys, [1, 2, 3])
  const recA = await reconstruct({ shares: a, threshold: 3 })
  t.is(recA.secretPoint, res.secretPoint, 'subset {1,2,3} recovers the secret point')
  t.is(recA.key, res.key, 'subset {1,2,3} recovers the key')

  const b = await decryptSubset(res.public, keys, [2, 4, 5])
  const recB = await reconstruct({ shares: b, threshold: 3 })
  t.is(recB.key, res.key, 'a different subset {2,4,5} recovers the same key')

  const all = await decryptSubset(res.public, keys, [1, 2, 3, 4, 5])
  const recAll = await reconstruct({ shares: all })
  t.is(recAll.key, res.key, 'the full set recovers the same key')
})

test('split: accepts an explicit secret scalar and round-trips it', async (t) => {
  const keys = await shareholders(3)
  const secret = '5b'.repeat(32) // fixed, valid, < N
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey), secret })
  const dec = await decryptSubset(res.public, keys, [1, 3])
  const rec = await reconstruct({ shares: dec, threshold: 2 })
  t.is(rec.secretPoint, res.secretPoint, 'explicit secret reconstructs to the same point')
  t.is(rec.key, res.key, 'explicit secret reconstructs to the same key')
})

test('verify-shares: an honest bundle passes public verification (no secret keys)', async (t) => {
  const keys = await shareholders(4)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })

  const all = await verifyShares({ commitments: res.public.commitments, encryptedShares: res.public.encryptedShares })
  t.is(all.valid, true, 'every share is consistent with the commitments')
  t.is(all.verified, 4, 'all four verified')
  t.alike(all.badIndices, [], 'no bad indices')

  // A relay verifies ONLY the single share it custodies.
  const one = await verifyShares({ commitments: res.public.commitments, encryptedShares: res.public.encryptedShares, index: 3 })
  t.is(one.valid, true, 'single-index verification passes')
  t.is(one.verified, 1, 'verified exactly one')
})

test('verify-shares: a tampered encrypted share is flagged (malicious dealer / corruption)', async (t) => {
  const keys = await shareholders(4)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })

  const tampered = res.public.encryptedShares.map(s => ({ ...s }))
  tampered[1].encryptedShare = (await keygen()).publicKey // swap for an unrelated valid point

  const v = await verifyShares({ commitments: res.public.commitments, encryptedShares: tampered })
  t.is(v.valid, false, 'tamper detected')
  t.ok(v.badIndices.includes(2), 'flags the tampered share index')
  t.is(v.verified, 3, 'the other three still verify')
})

test('verify-shares: a tampered DLEQ proof is flagged', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })

  const tampered = res.public.encryptedShares.map(s => ({ ...s, proof: { ...s.proof } }))
  tampered[0].proof.s = 'f'.repeat(64) // corrupt the response scalar

  const v = await verifyShares({ commitments: res.public.commitments, encryptedShares: tampered })
  t.is(v.valid, false, 'tampered proof rejected')
  t.ok(v.badIndices.includes(1), 'flags the index with the bad proof')
})

test('decrypted shares: honest verifies, forged is caught at verify + reconstruct (malicious relay)', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  const good = await decryptSubset(res.public, keys, [1, 2])

  const okCheck = await verifyDecryptedShare(good[0])
  t.is(okCheck.valid, true, 'an honest decrypted share verifies')

  // A relay returns a wrong share value but keeps the (now-inconsistent) proof.
  const forged = { ...good[0], share: (await keygen()).publicKey }
  const badCheck = await verifyDecryptedShare(forged)
  t.is(badCheck.valid, false, 'forged share value fails its decryption DLEQ')

  await t.exception(
    reconstruct({ shares: [forged, good[1]], threshold: 2 }),
    /SS_INVALID_SHARE_PROOF/,
    'reconstruct refuses a share that fails verification'
  )
})

test('threshold: fewer than t shares do not recover the secret', async (t) => {
  const keys = await shareholders(5)
  const res = await split({ threshold: 3, shareholders: keys.map(k => k.publicKey) })

  const two = await decryptSubset(res.public, keys, [1, 2]) // t = 3, only 2 shares
  const rec = await reconstruct({ shares: two }) // unguarded → interpolates the wrong value
  t.not(rec.key, res.key, 't-1 shares interpolate to the wrong secret')

  await t.exception(
    reconstruct({ shares: two, threshold: 3 }),
    /SS_INSUFFICIENT_SHARES/,
    'the threshold guard rejects an under-threshold set'
  )
})

test('blindness: the published bundle leaks no secret, and public data cannot recover the key', async (t) => {
  const keys = await shareholders(4)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })

  const published = JSON.stringify(res.public)
  t.is(res.public.scheme, 'pvss-secp256k1-v1', 'scheme tag present')
  t.absent(published.includes(res.key), 'published bundle does not contain the key')
  t.absent(published.includes(res.secretPoint), 'published bundle does not contain the secret point')

  // What a relay holds is the ENCRYPTED share. Feeding the encrypted shares
  // straight into reconstruct (as if they were decrypted) yields a wrong key —
  // recovery genuinely requires the shareholder secret keys.
  const asIfDecrypted = res.public.encryptedShares.slice(0, 2).map(s => ({ index: s.index, share: s.encryptedShare }))
  const wrong = await reconstruct({ shares: asIfDecrypted })
  t.not(wrong.key, res.key, 'encrypted shares cannot stand in for decrypted shares')
})

test('derive-key: matches the key derived during split and reconstruct', async (t) => {
  const keys = await shareholders(3)
  const res = await split({ threshold: 2, shareholders: keys.map(k => k.publicKey) })
  const dk = await deriveKey({ secretPoint: res.secretPoint })
  t.is(dk.key, res.key, 'derive-key over the secret point reproduces the key')
})

test('split: input validation', async (t) => {
  const keys = await shareholders(2)
  await t.exception(
    split({ threshold: 3, shareholders: keys.map(k => k.publicKey) }),
    /SS_THRESHOLD_EXCEEDS_SHAREHOLDERS/,
    'threshold cannot exceed shareholder count'
  )
  await t.exception(
    split({ threshold: 0, shareholders: keys.map(k => k.publicKey) }),
    /SS_INVALID_THRESHOLD/,
    'threshold must be >= 1'
  )
  await t.exception(
    split({ threshold: 2, shareholders: ['not-a-point', keys[0].publicKey] }),
    /SS_BAD_SHAREHOLDER_PUBKEY/,
    'shareholder pubkeys must be valid curve points'
  )
})
