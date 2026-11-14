import test from 'brittle'
import { X402ServiceFacade } from '../../packages/core/incentive/x402/service-facade.js'

const FACILITATOR = 'https://facilitator.invalid'
const PAY_TO = '0x1111111111111111111111111111111111111111'
const ASSET = '0x2222222222222222222222222222222222222222'

test('x402 official SDK preserves challenge, verification, settlement, and replay boundaries', async (t) => {
  const calls = []
  let verificationAllowed = false
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, options) => {
    const url = new URL(input)
    if (url.origin !== FACILITATOR) throw new Error('unexpected external request')
    calls.push(url.pathname)
    if (url.pathname === '/supported') {
      return Response.json({
        kinds: [{ x402Version: 2, scheme: 'exact', network: 'eip155:84532' }],
        extensions: [],
        signers: {}
      })
    }
    const body = JSON.parse(options.body)
    t.is(body.x402Version, 2)
    t.is(body.paymentRequirements.amount, '1000')
    if (url.pathname === '/verify') {
      // Exercise the real SDK boundary; the local facilitator stub is not an onchain verification.
      return Response.json(verificationAllowed
        ? { isValid: true, payer: PAY_TO }
        : { isValid: false, invalidReason: 'invalid_exact_evm_signature', payer: PAY_TO })
    }
    if (url.pathname === '/settle') {
      return Response.json({
        success: true,
        payer: PAY_TO,
        transaction: '0x' + 'a'.repeat(64),
        network: 'eip155:84532'
      })
    }
    throw new Error('unexpected facilitator endpoint')
  }
  t.teardown(() => { globalThis.fetch = originalFetch })

  const facade = new X402ServiceFacade({
    config: {
      enabled: true,
      facilitatorUrl: FACILITATOR,
      publicBaseUrl: 'https://relay.example',
      routes: {
        'POST /svc/vrf/prove': {
          serviceRoute: 'vrf.prove',
          sideEffects: 'read-only',
          accepts: [{
            scheme: 'exact',
            network: 'eip155:84532',
            payTo: PAY_TO,
            price: { asset: ASSET, amount: '1000' }
          }]
        }
      }
    }
  })
  let reads = 0
  let executions = 0
  const handle = payment => facade.handle({
    req: {
      method: 'POST',
      headers: payment ? { 'payment-signature': payment } : {},
      rawHeaders: payment ? ['PAYMENT-SIGNATURE', payment] : []
    },
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => { reads++; return {} },
    execute: async () => { executions++; return { proof: 'local-stub-result' } }
  })

  const unpaid = await handle()
  t.is(unpaid.status, 402)
  const required = JSON.parse(Buffer.from(unpaid.headers['PAYMENT-REQUIRED'], 'base64').toString())
  t.is(required.x402Version, 2)
  t.is(required.accepts[0].amount, '1000')
  t.is(reads, 0)
  t.is(executions, 0)
  t.alike(calls, ['/supported'])

  const malformed = await handle(Buffer.from('null').toString('base64'))
  t.is(malformed.status, 402)
  t.alike(calls, ['/supported'], 'non-object headers never reach the facilitator')

  const payment = Buffer.from(JSON.stringify({
    x402Version: 2,
    resource: required.resource,
    accepted: required.accepts[0],
    payload: {
      signature: '0x' + '1'.repeat(130),
      authorization: {
        from: PAY_TO,
        to: PAY_TO,
        value: '1000',
        validAfter: '0',
        validBefore: '9999999999',
        nonce: '0x' + '2'.repeat(64)
      }
    }
  })).toString('base64')
  const rejected = await handle(payment)
  t.is(rejected.status, 402)
  t.is(reads, 0, 'rejected payment does not read a body')
  t.is(executions, 0, 'rejected payment does not execute a service')

  verificationAllowed = true
  const paid = await handle(payment)
  t.is(paid.status, 200)
  t.is(reads, 1)
  t.is(executions, 1)
  const receipt = JSON.parse(Buffer.from(paid.headers['PAYMENT-RESPONSE'], 'base64').toString())
  t.is(receipt.success, true)
  t.is(receipt.network, 'eip155:84532')

  const replay = await handle(payment)
  t.is(replay.status, 402)
  t.is(reads, 1, 'replay does not read the request again')
  t.is(executions, 1, 'replay never executes twice')
  t.alike(calls, ['/supported', '/verify', '/verify', '/settle', '/verify'])

  const sameAuthorization = JSON.parse(Buffer.from(payment, 'base64').toString())
  sameAuthorization.payload.authorization.nonce = '0x' + '3'.repeat(64)
  const reordered = {
    payload: {
      authorization: Object.fromEntries(Object.entries(sameAuthorization.payload.authorization).reverse()),
      signature: sameAuthorization.payload.signature
    },
    accepted: sameAuthorization.accepted,
    resource: sameAuthorization.resource,
    x402Version: 2
  }
  const concurrent = await Promise.all([
    handle(Buffer.from(JSON.stringify(sameAuthorization)).toString('base64')),
    handle(Buffer.from(JSON.stringify(reordered, null, 2)).toString('base64'))
  ])
  t.alike(concurrent.map(result => result.status).sort(), [200, 402], 'formatting and key order share one concurrent claim')
  t.is(executions, 2, 'one new authorization executes only once')
  t.is(reads, 2, 'the duplicate is rejected before body reading')

  const distinct = await Promise.all(['4', '5'].map(nonce => {
    const payload = structuredClone(sameAuthorization)
    payload.payload.authorization.nonce = '0x' + nonce.repeat(64)
    return handle(Buffer.from(JSON.stringify(payload)).toString('base64'))
  }))
  t.alike(distinct.map(result => result.status), [200, 200], 'distinct authorizations remain independent')
  t.is(executions, 4)
})
