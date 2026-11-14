import test from 'brittle'
import { createHash } from 'node:crypto'
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
        paymentPayload: {
          x402Version: 2,
          payload: {
            signature: header,
            authorization: {
              from: PAY_TO,
              to: PAY_TO,
              value: '1000',
              validAfter: '0',
              validBefore: '9999999999',
              nonce: '0x' + createHash('sha256').update(header).digest('hex')
            }
          }
        },
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

test('x402 facade releases a pre-execution failure only after cancellation completes', async (t) => {
  const server = fakeServer()
  const process = server.processHTTPRequest.bind(server)
  let cancelStarted
  let finishCancel
  const started = new Promise(resolve => { cancelStarted = resolve })
  const finish = new Promise(resolve => { finishCancel = resolve })
  let cancellations = 0
  server.processHTTPRequest = async context => {
    const result = await process(context)
    if (result.cancellationDispatcher) {
      result.cancellationDispatcher.cancel = async () => {
        if (++cancellations === 1) {
          cancelStarted()
          await finish
        }
      }
    }
    return result
  }
  const facade = new X402ServiceFacade({ config: config(), serverFactory: async () => server })
  let executions = 0
  const args = {
    req: request('retry-payment'),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => ({}),
    execute: async () => { executions++; return {} }
  }
  const first = facade.handle({ ...args, readBody: async () => { throw new Error('invalid body') } })
  await started
  t.is((await facade.handle(args)).status, 402, 'pending cancellation retains ownership')
  t.is(executions, 0)
  finishCancel()
  t.is((await first).status, 400)
  t.is((await facade.handle(args)).status, 200, 'pre-execution failure can retry after cancellation')
  t.is(executions, 1)
})

test('x402 facade retains an authorization when the handler throws after starting work', async (t) => {
  const server = fakeServer()
  const facade = new X402ServiceFacade({ config: config(), serverFactory: async () => server })
  let executions = 0
  const args = {
    req: request('handler-failure'),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => ({}),
    execute: async () => { executions++; throw new Error('side effect may already have happened') }
  }
  t.is((await facade.handle(args)).status, 400)
  t.is((await facade.handle(args)).status, 402)
  t.is(executions, 1, 'a handler exception never reopens its payment')
  t.is((await facade.handle({ ...args, req: request('distinct-payment'), execute: async () => ({}) })).status, 200)
})

test('x402 facade retains executed claims after thrown and rejected settlements', async (t) => {
  for (const throws of [true, false]) {
    const server = fakeServer()
    server.processSettlement = async () => {
      if (throws) throw new Error('facilitator unavailable')
      return { success: false, response: { status: 402, headers: {}, body: { error: 'settlement rejected' } } }
    }
    const facade = new X402ServiceFacade({ config: config(), serverFactory: async () => server })
    let executions = 0
    const args = {
      req: request('settlement-failure'),
      url: new URL('https://relay.example/svc/vrf/prove'),
      readBody: async () => ({}),
      execute: async () => { executions++; return {} }
    }
    t.is((await facade.handle(args)).status, throws ? 503 : 402)
    t.is((await facade.handle(args)).status, 402)
    t.is(executions, 1)
  }
})

test('x402 facade fails closed on a malformed verified authorization', async (t) => {
  const server = fakeServer()
  const process = server.processHTTPRequest.bind(server)
  server.processHTTPRequest = async context => {
    const result = await process(context)
    if (result.paymentPayload) result.paymentPayload.payload.authorization.nonce = 'invalid'
    return result
  }
  const facade = new X402ServiceFacade({ config: config(), serverFactory: async () => server })
  let reads = 0
  let executions = 0
  const result = await facade.handle({
    req: request('malformed-payment'),
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => { reads++; return {} },
    execute: async () => { executions++; return {} }
  })
  t.is(result.status, 402)
  t.is(reads, 0)
  t.is(executions, 0)
  t.is(facade.claims.claims.size, 0)
  t.is(server.cancellations.length, 1)
})
