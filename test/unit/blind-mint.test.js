import test from 'brittle'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { BlindMint, blind, unblind, newSecret, hashToCurve } from 'p2p-hiverelay/incentive/payment/blind-mint.js'

const Point = secp256k1.Point

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// ─── Official Cashu NUT-00 test vectors — proof of interoperability ──

test('NUT-00 vector: hash_to_curve', (t) => {
  const vectors = [
    ['0000000000000000000000000000000000000000000000000000000000000000', '024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725'],
    ['0000000000000000000000000000000000000000000000000000000000000001', '022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf'],
    ['0000000000000000000000000000000000000000000000000000000000000002', '026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f']
  ]
  for (const [msg, expected] of vectors) {
    t.is(hashToCurve(msg).toHex(true), expected, 'hash_to_curve(' + msg.slice(0, 4) + '…) matches spec')
  }
})

test('NUT-00 vector: blinded message B_ = Y + rG', (t) => {
  const vectors = [
    ['d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6', '99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a', '033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d'],
    ['f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60', 'f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50', '029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763']
  ]
  for (const [x, r, expectedB] of vectors) {
    const Y = hashToCurve(x)
    const B_ = Y.add(Point.BASE.multiply(BigInt('0x' + r)))
    t.is(B_.toHex(true), expectedB, 'B_ matches spec')
  }
})

test('NUT-00 vector: blind signature C_ = k·B_', (t) => {
  // Mint key = 0x7f..7f, B_ from the spec, expected C_ from the spec.
  const mint = new BlindMint({ secret: '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f' })
  const C_ = mint.blindSign('02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2')
  t.is(C_, '0398bc70ce8184d27ba89834d19f5199c84443c31131e48d3c1214db24247d005d', 'C_ matches spec')
})

// ─── Behaviour ──────────────────────────────────────────────────────

test('BDHKE: full blind → sign → unblind → verify round-trip', (t) => {
  const mint = new BlindMint({ keyPair: makeKeyPair() })
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(mint.blindSign(blinded), blindingFactor, mint.publicKey)
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

test('BDHKE: mint rejects an invalid blinded message', (t) => {
  const mint = new BlindMint({ keyPair: makeKeyPair() })
  t.exception(() => mint.blindSign('00'.repeat(33)), /BLIND_INVALID_POINT/)
  t.exception(() => mint.blindSign('zz'), /BLIND_INVALID_POINT/)
})

test('BDHKE: deterministic mint key from keyPair is stable (survives restart)', (t) => {
  const kp = makeKeyPair()
  const a = new BlindMint({ keyPair: kp })
  const b = new BlindMint({ keyPair: kp })
  t.is(a.publicKey, b.publicKey, 'same keyPair → same mint key, no persistence needed')
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(a.blindSign(blinded), blindingFactor, a.publicKey)
  t.ok(b.verifyToken(secret, C))
})

test('BDHKE: unlinkability — blinding the same secret twice yields distinct points', (t) => {
  const secret = newSecret()
  t.not(blind(secret).blinded, blind(secret).blinded, 'blinded messages differ (random r) → mint cannot link by B_')
  t.is(hashToCurve(secret).toHex(true), hashToCurve(secret).toHex(true), 'hash_to_curve is deterministic')
})
