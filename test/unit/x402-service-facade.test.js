import test from 'brittle'
import { X402ServiceFacade } from '../../packages/core/incentive/x402/service-facade.js'

const PAY_TO = '0x1111111111111111111111111111111111111111'
const ASSET = '0x2222222222222222222222222222222222222222'

function config (route = {}) {
  return {
    enabled: true,
    facilitatorUrl: 'https://x402.org/facilitator',
    publicBaseUrl: 'https://relay.example',
    routes: {
      'POST /svc/vrf/prove': {
        serviceRoute: 'vrf.prove',
        sideEffects: 'read-only',
        unit: 'proof',
        proofType: 'ecvrf-proof-v1',
        accepts: [{
          scheme: 'exact',
          network: 'eip155:84532',
          payTo: PAY_TO,
          price: { asset: ASSET, amount: '1000' }
        }],
        ...route
      }
    }
  }
}

function request (payment, rawHeaders, method = 'POST') {
  return {
    method,
    headers: {
      'content-type': 'application/json',
      ...(payment ? { 'payment-signature': payment } : {})
    },
    rawHeaders: rawHeaders || (payment
      ? ['Content-Type', 'application/json', 'PAYMENT-SIGNATURE', payment]
      : ['Content-Type', 'application/json'])
  }
}

function fakeServer () {
  const cancellations = []
  const server = {
    cancellations,
    async processHTTPRequest (context) {
      const header = context.adapter.getHeader('payment-signature')
      if (!header) {
        return {
          type: 'payment-error',
          response: {
            status: 402,
            headers: { 'PAYMENT-REQUIRED': 'challenge' },
            body: { error: 'payment required' }
          }
        }
      }
      return {
        type: 'payment-verified',
        paymentPayload: { x402Version: 2, payload: { authorization: header } },
        paymentRequirements: {
          scheme: 'exact',
          network: 'eip155:84532',
          asset: ASSET,
          amount: '1000',
          payTo: PAY_TO,
          maxTimeoutSeconds: 60,
          extra: {}
        },
        cancellationDispatcher: {
          async cancel (value) {
            cancellations.push(value)
          }
        }
      }
    },
    async processSettlement () {
      return {
        success: true,
        headers: { 'PAYMENT-RESPONSE': 'settled' }
      }
    }
  }
  return server
}

test('x402 facade challenges before reading the request body or executing a service', async (t) => {
  const server = fakeServer()
  let reads = 0
  let calls = 0
  const facade = new X402ServiceFacade({
    config: config(),
    serverFactory: async () => server
  })

  const result = await facade.handle({
    req: request(),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => { reads++; return {} },
    execute: async () => { calls++ }
  })

  t.is(result.status, 402)
  t.is(result.headers['PAYMENT-REQUIRED'], 'challenge')
  t.is(result.headers['Cache-Control'], 'no-store, private, max-age=0')
  t.is(reads, 0)
  t.is(calls, 0)
})

test('x402 facade executes once, settles, and rejects a replay with a fresh 402 challenge', async (t) => {
  const server = fakeServer()
  const calls = []
  const facade = new X402ServiceFacade({
    config: config(),
    serverFactory: async () => server
  })
  const args = {
    req: request('signed-payment'),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => ({ alpha: '01' }),
    execute: async (route, body, context) => {
      calls.push({ route, body, context })
      return { proof: 'ok' }
    }
  }

  const paid = await facade.handle(args)
  t.is(paid.status, 200)
  t.is(paid.headers['PAYMENT-RESPONSE'], 'settled')
  t.alike(paid.payload, { ok: true, result: { proof: 'ok' } })
  t.is(calls.length, 1)
  t.is(calls[0].route.serviceRoute, 'vrf.prove')
  t.is(calls[0].context.x402.version, 2)

  const replay = await facade.handle(args)
  t.is(replay.status, 402)
  t.is(replay.headers['PAYMENT-REQUIRED'], 'challenge')
  t.is(calls.length, 1, 'replay never executes the service twice')
  t.is(server.cancellations.length, 1)
})

test('x402 facade requires an idempotency key before an enabled write route executes', async (t) => {
  const server = fakeServer()
  let calls = 0
  const facade = new X402ServiceFacade({
    config: config({
      serviceRoute: 'notify.send',
      sideEffects: 'idempotent-write',
      requireIdempotencyKey: true
    }),
    serverFactory: async () => server
  })

  const result = await facade.handle({
    req: request('signed-write-payment'),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => ({ ciphertext: 'opaque' }),
    execute: async () => { calls++ }
  })

  t.is(result.status, 400)
  t.is(result.payload.errorCode, 'x402-idempotency-key-required')
  t.is(calls, 0)
})

test('x402 facade forwards repeated query parameters to paid GET services', async (t) => {
  const server = fakeServer()
  const getConfig = config()
  const postRoute = getConfig.routes['POST /svc/vrf/prove']
  delete getConfig.routes['POST /svc/vrf/prove']
  getConfig.routes['GET /svc/vrf/beacon-range'] = {
    ...postRoute,
    serviceRoute: 'vrf.beacon-range'
  }
  const facade = new X402ServiceFacade({
    config: getConfig,
    serverFactory: async () => server
  })
  let received

  const result = await facade.handle({
    req: request('signed-get-payment', null, 'GET'),
    url: new URL('https://relay.example/svc/vrf/beacon-range?from=10&tag=a&tag=b'),
    readBody: async () => {
      throw new Error('GET must not read a body')
    },
    execute: async (_route, params) => {
      received = params
      return { entries: [] }
    }
  })

  t.is(result.status, 200)
  t.alike(received, { from: '10', tag: ['a', 'b'] })
})
