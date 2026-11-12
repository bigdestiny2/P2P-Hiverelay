import test from 'brittle'
import { paymentClaimId, X402ClaimStore } from '../../packages/core/incentive/x402/claim-store.js'

const PAYER = '0x' + 'ab'.repeat(20)
const OTHER = '0x' + 'cd'.repeat(20)
const ASSET = '0x' + '11'.repeat(20)
const PAY_TO = '0x' + '22'.repeat(20)
const NONCE = '0x' + 'ef'.repeat(32)
const requirements = { scheme: 'exact', network: 'eip155:84532', asset: ASSET, payTo: PAY_TO, amount: '1000' }

function payment (overrides = {}) {
  return {
    x402Version: 2,
    payload: {
      signature: '0x1234',
      authorization: { from: PAYER, to: PAY_TO, value: '1000', validAfter: '0', validBefore: '200', nonce: NONCE, ...overrides }
    }
  }
}

function permit2 (overrides = {}) {
  return {
    x402Version: 2,
    payload: {
      signature: '0x1234',
      permit2Authorization: {
        from: PAYER,
        spender: OTHER,
        permitted: { token: ASSET, amount: '1000' },
        witness: { to: PAY_TO, validAfter: '0' },
        deadline: '200',
        nonce: '42',
        ...overrides
      }
    }
  }
}

test('x402 claims identify EIP-3009 nonce domains independently of representation', (t) => {
  const id = paymentClaimId(payment(), requirements)
  const variant = payment({ from: PAYER.toUpperCase(), nonce: NONCE.slice(2).toUpperCase(), value: '01000', validBefore: '300' })
  variant.payload.signature = '0x5678'
  variant.resource = { description: 'different unsigned metadata' }
  variant.payload.ignored = true
  t.is(paymentClaimId(variant, requirements), id)
  t.not(paymentClaimId(payment({ from: OTHER }), requirements), id, 'different payer')
  t.not(paymentClaimId(payment({ nonce: '0x' + '1'.repeat(64) }), requirements), id, 'different nonce')
  t.not(paymentClaimId(payment(), { ...requirements, asset: OTHER }), id, 'different token nonce domain')
  t.not(paymentClaimId(payment(), { ...requirements, network: 'eip155:1' }), id, 'different chain')
  t.is(paymentClaimId(payment({ value: '2000', to: OTHER }), { ...requirements, amount: '2000', payTo: OTHER }), id, 'changed signed terms cannot reopen one nonce')
})

test('x402 claims identify the owner-wide Permit2 nonce across tokens and spenders', (t) => {
  const id = paymentClaimId(permit2(), requirements)
  t.is(paymentClaimId(permit2({ nonce: '00042', from: PAYER.toUpperCase(), spender: PAY_TO }), requirements), id)
  t.is(paymentClaimId(permit2({ permitted: { token: OTHER, amount: '1000' } }), { ...requirements, asset: OTHER }), id)
  t.not(paymentClaimId(permit2({ nonce: '43' }), requirements), id)
  t.not(paymentClaimId(permit2({ from: OTHER }), requirements), id)
  t.not(paymentClaimId(permit2(), { ...requirements, network: 'eip155:1' }), id)
  t.not(paymentClaimId(payment(), requirements), id)
})

test('x402 claim identity rejects malformed, mismatched, ambiguous, and unbounded authorizations', (t) => {
  for (const invalid of [
    null,
    { x402Version: 2, payload: [] },
    payment({ from: 'invalid' }),
    payment({ nonce: '0x12' }),
    payment({ value: '-1' }),
    payment({ value: '999' }),
    payment({ to: OTHER }),
    payment({ validBefore: '0' }),
    payment({ validBefore: (1n << 256n).toString() }),
    payment({ validBefore: '99999999999999999999' }),
    payment({ validBefore: 200 }),
    permit2({ nonce: '-1' }),
    permit2({ witness: null }),
    permit2({ permitted: { token: OTHER, amount: '1000' } }),
    { ...payment(), payload: { ...payment().payload, ...permit2().payload } }
  ]) t.exception(() => paymentClaimId(invalid, requirements), /X402_PAYMENT_AUTHORIZATION/)
  t.exception(() => paymentClaimId(payment(), { ...requirements, scheme: 'upto' }), /X402_PAYMENT_AUTHORIZATION/)
  t.exception(() => paymentClaimId(payment(), { ...requirements, network: 'eip155:01' }), /X402_PAYMENT_AUTHORIZATION/)
})

test('x402 pending claims survive TTL and completed claims survive authorization validity', (t) => {
  let now = 1000
  const store = new X402ClaimStore({ now: () => now, ttlMs: 10, maxClaims: 1 })
  const first = store.claim(payment(), requirements, 'POST /one')
  now = 2000
  store.sweep()
  t.is(store.claims.size, 1, 'in-flight claims cannot be swept')
  t.is(store.claim(payment(), requirements, 'POST /two').ok, false)
  t.is(store.claim(payment({ nonce: '0x' + '1'.repeat(64) }), requirements, 'POST /one').full, true, 'capacity remains bounded')
  t.is(store.retain(first.claim), true)
  now = 3000
  store.sweep()
  t.is(store.claim(payment(), requirements, 'POST /one').ok, false, 'TTL does not reopen a still-valid authorization')
  now = 200001
  store.sweep()
  t.is(store.claims.size, 0)
  t.exception(() => store.claim(payment(), requirements, 'POST /one'), /EXPIRED/)
})

test('x402 stale claim owners cannot release or retain a replacement reservation', (t) => {
  const store = new X402ClaimStore({ now: () => 1000 })
  const first = store.claim(payment(), requirements, 'POST /one')
  t.is(store.release(first.claim), true)
  const second = store.claim(payment(), requirements, 'POST /one')
  t.is(second.ok, true, 'failure before execution allows retry')
  t.is(store.release(first.claim), false)
  t.is(store.retain(first.claim), false)
  t.is(store.claims.get(second.id), second.claim)
})
