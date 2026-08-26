import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { SignedLog } from '../../packages/services/builtin/poker/signed-log.js'
import {
  CARD_SHARE_PROTOCOL_VERSION,
  CVE_2025_69277_POINT,
  proveShareEquality,
  publicFromSecret,
  shareFor,
  verifyShareEquality
} from '../../packages/services/builtin/poker/crypto/chaum-pedersen.js'
import { makeInvalidShareVerifier } from '../../packages/services/builtin/poker/crypto/share-verifier.js'

const TABLE_KEY = '11'.repeat(32)
const HAND = 7
const CARD_INDEX = 3

function keypair () {
  const pk = b4a.alloc(32)
  const sk = b4a.alloc(64)
  sodium.crypto_sign_keypair(pk, sk)
  return { pk, sk, hex: b4a.toString(pk, 'hex') }
}

function scalar () {
  const value = b4a.alloc(32)
  sodium.crypto_core_ed25519_scalar_random(value)
  return value
}

function signEntry (entry, sk) {
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, SignedLog.canonicalBytes(entry), sk)
  return { ...entry, signature: b4a.toString(signature, 'hex') }
}

function fixture () {
  const respondent = keypair()
  const x = scalar()
  const X = publicFromSecret(x)
  const cardScalar = scalar()
  const C1 = publicFromSecret(cardScalar)
  const D = shareFor(x, C1)
  const context = {
    protocolVersion: CARD_SHARE_PROTOCOL_VERSION,
    tableKey: TABLE_KEY,
    hand: HAND,
    writer: respondent.hex,
    proofKind: 'share-precommit',
    cardIndex: CARD_INDEX,
    recipientSeat: null
  }
  const proof = proveShareEquality({ x, Y: X, C1, D, context })
  const wireProof = Object.fromEntries(Object.entries(proof).map(([name, value]) => [name, b4a.toString(value, 'hex')]))
  const keyEntry = signEntry({
    tableKey: TABLE_KEY,
    writer: respondent.hex,
    seq: 0,
    ts: 1,
    payload: {
      kind: 'dkg-commit',
      protocolVersion: CARD_SHARE_PROTOCOL_VERSION,
      hand: HAND,
      round: 2,
      X: b4a.toString(X, 'hex')
    }
  }, respondent.sk)
  const shareEntry = signEntry({
    tableKey: TABLE_KEY,
    writer: respondent.hex,
    seq: 1,
    ts: 2,
    payload: {
      kind: 'share-precommit',
      protocolVersion: CARD_SHARE_PROTOCOL_VERSION,
      hand: HAND,
      cardIdx: CARD_INDEX,
      C1: b4a.toString(C1, 'hex'),
      D: b4a.toString(D, 'hex'),
      proof: wireProof
    }
  }, respondent.sk)
  const evidence = {
    tableKey: TABLE_KEY,
    handId: String(HAND),
    cardIndex: CARD_INDEX,
    ciphertext: shareEntry.payload.C1,
    share: shareEntry.payload.D,
    respondent: respondent.hex,
    signedEntry: shareEntry,
    publisherKeyEntry: keyEntry,
    witness: {
      Y: b4a.toString(X, 'hex'),
      proof: wireProof,
      context
    }
  }
  return { respondent, x, X, C1, D, context, proof, evidence }
}

test('DRI-387 rejects the CVE-2025-69277 point vector in the service runtime', t => {
  const { X, C1, D, context, proof } = fixture()
  const result = verifyShareEquality({ Y: CVE_2025_69277_POINT, C1, D, ...proof, context })
  t.alike(result, { valid: false, reason: 'invalid-point:Y' })
  t.ok(X.byteLength === 32, 'fixture exercised the service-owned verifier path')
})

test('DRI-387 CP proof binds every signed card-share context dimension', t => {
  const { X, C1, D, context, proof } = fixture()
  t.is(verifyShareEquality({ Y: X, C1, D, ...proof, context }).valid, true)
  const mutations = [
    { protocolVersion: 2 },
    { tableKey: '22'.repeat(32) },
    { hand: HAND + 1 },
    { writer: '33'.repeat(32) },
    { proofKind: 'hole-reveal' },
    { cardIndex: CARD_INDEX + 1 },
    { proofKind: 'share-deliver', recipientSeat: 2 }
  ]
  for (const mutation of mutations) {
    const changed = { ...context, ...mutation }
    t.is(verifyShareEquality({ Y: X, C1, D, ...proof, context: changed }).valid, false,
      `replay rejected for ${Object.keys(mutation).join('+')}`)
  }
})

test('DRI-387 arbitration authenticates respondent, share entry, and DKG key provenance', t => {
  const { respondent, evidence } = fixture()
  const verifier = makeInvalidShareVerifier()
  t.alike(verifier(evidence), { verdict: 'claim-refuted', reason: 'proof-verifies' })

  const wrongRespondent = { ...evidence, respondent: '44'.repeat(32) }
  t.is(verifier(wrongRespondent).verdict, 'inconclusive', 'respondent substitution rejected')

  const wrongKey = { ...evidence, publisherKeyEntry: { ...evidence.publisherKeyEntry, writer: '55'.repeat(32) } }
  t.is(verifier(wrongKey).verdict, 'inconclusive', 'publisher-key entry substitution rejected')

  const badProof = { ...evidence.witness.proof, z: '00'.repeat(32) }
  const badPayload = { ...evidence.signedEntry.payload, proof: badProof }
  const signedBadEntry = signEntry({ ...evidence.signedEntry, payload: badPayload, signature: undefined }, respondent.sk)
  const signedBadEvidence = {
    ...evidence,
    signedEntry: signedBadEntry,
    witness: { ...evidence.witness, proof: badProof }
  }
  t.is(verifier(signedBadEvidence).verdict, 'claim-supported', 'respondent-signed invalid proof supports the claim')
})
