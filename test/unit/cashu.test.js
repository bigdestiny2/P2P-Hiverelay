import test from 'brittle'
import { BlindMint, newSecret, blind, unblind } from 'p2p-hiverelay/incentive/payment/blind-mint.js'
import { deriveKeysetId, buildKeyset, makeProof, encodeToken, decodeToken } from 'p2p-hiverelay/incentive/payment/cashu.js'

test('NUT-02 keyset id: stable, 16-hex, version byte 00', (t) => {
  const keys = { 1: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }
  const id = deriveKeysetId(keys)
  t.ok(/^00[0-9a-f]{14}$/.test(id), 'id is 00 + 14 hex chars')
  t.is(deriveKeysetId(keys), id, 'deterministic')
})

test('buildKeyset wraps a mint as a NUT-01/02 keyset', (t) => {
  const mint = new BlindMint({ secret: '01'.repeat(32) })
  const ks = buildKeyset(mint, 100, 'sat')
  t.is(ks.unit, 'sat')
  t.is(ks.keys[100], mint.publicKey, 'amount maps to the mint pubkey')
  t.ok(/^00[0-9a-f]{14}$/.test(ks.id))
})

test('cashuA token: encode → decode round-trip carries the proof', (t) => {
  const mint = new BlindMint({ keyPair: { secretKey: new Uint8Array(64).fill(7), publicKey: new Uint8Array(32) } })
  const ks = buildKeyset(mint, 100, 'sat')
  // Full mint/redeem cycle to get a real proof.
  const secret = newSecret()
  const { blinded, blindingFactor } = blind(secret)
  const C = unblind(mint.blindSign(blinded), blindingFactor, mint.publicKey)
  t.ok(mint.verifyToken(secret, C), 'proof verifies before serialization')

  const proof = makeProof(100, ks.id, secret, C)
  const token = encodeToken({ mint: 'https://relay.example', proofs: [proof], unit: 'sat', memo: 'lease' })
  t.ok(token.startsWith('cashuA'), 'is a cashuA token')

  const decoded = decodeToken(token)
  t.is(decoded.unit, 'sat')
  t.is(decoded.memo, 'lease')
  t.alike(decoded.proofs[0], proof, 'proof survives the round-trip')
  t.ok(mint.verifyToken(decoded.proofs[0].secret, decoded.proofs[0].C), 'decoded proof still verifies')
})

test('decodeToken rejects non-cashuA input', (t) => {
  t.exception(() => decodeToken('not-a-token'), /not a cashuA token/)
})
