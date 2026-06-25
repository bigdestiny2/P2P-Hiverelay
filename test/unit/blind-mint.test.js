import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { BlindMint, blind, unblind, newSecret, hashToPoint } from 'p2p-hiverelay/incentive/payment/blind-mint.js'

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

test('BDHKE: full blind → sign → unblind → verify round-trip', (t) => {
  const mint = new BlindMint({ keyPair: makeKeyPair() })
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const blindSig = mint.blindSign(blinded)
  const C = unblind(blindSig, blindingFactor, mint.publicKey)
  t.ok(mint.verifyToken(secret, C), 'unblinded token verifies against the mint')
})

test('BDHKE: a token from a different mint does not verify', (t) => {
  const mintA = new BlindMint({ keyPair: makeKeyPair() })
  const mintB = new BlindMint({ keyPair: makeKeyPair() })
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(mintA.blindSign(blinded), blindingFactor, mintA.publicKey)
  t.ok(mintA.verifyToken(secret, C))
  t.absent(mintB.verifyToken(secret, C), 'cross-mint forgery rejected')
})

test('BDHKE: wrong secret does not verify against a valid signature', (t) => {
  const mint = new BlindMint({ keyPair: makeKeyPair() })
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(mint.blindSign(blinded), blindingFactor, mint.publicKey)
  t.absent(mint.verifyToken(newSecret(), C), 'C is bound to its own secret')
})

test('BDHKE: mint rejects an invalid / non-prime-order blinded message', (t) => {
  const mint = new BlindMint({ keyPair: makeKeyPair() })
  // All-zero point is the identity (low order) — must be rejected.
  t.exception(() => mint.blindSign('00'.repeat(32)), /BLIND_INVALID_POINT|BLIND_BAD_INPUT/)
  t.exception(() => mint.blindSign('zz'), /BLIND_BAD_INPUT/)
})

test('BDHKE: deterministic mint key from keyPair is stable (survives restart)', (t) => {
  const kp = makeKeyPair()
  const a = new BlindMint({ keyPair: kp })
  const b = new BlindMint({ keyPair: kp })
  t.is(a.publicKey, b.publicKey, 'same keyPair → same mint key, no persistence needed')
  // And a token minted by instance A verifies on instance B (restart safety).
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(a.blindSign(blinded), blindingFactor, a.publicKey)
  t.ok(b.verifyToken(secret, C))
})

test('BDHKE: unlinkability — blinding the same secret twice yields distinct points', (t) => {
  const secret = newSecret()
  const b1 = blind(secret)
  const b2 = blind(secret)
  t.not(b1.blinded, b2.blinded, 'blinded messages differ (random r) → mint cannot link by B_')
  // Hash-to-point is deterministic though (that is what redeem checks against).
  t.is(b4a.toString(hashToPoint(secret), 'hex'), b4a.toString(hashToPoint(secret), 'hex'))
})
