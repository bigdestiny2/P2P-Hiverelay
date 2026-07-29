import test from 'brittle'
import { RelayAPI } from 'p2p-hiverelay/core/relay-node/api.js'
import {
  resolveX402PriceManifestRoute,
  runX402ServiceRequest
} from '../../packages/core/core/relay-node/api-x402.js'

function makeApi (x402Facade = null) {
  const node = {
    emit () {},
    config: {},
    router: null,
    serviceRegistry: null
  }
  const api = new RelayAPI(node, {
    apiPort: 0,
    apiHost: '127.0.0.1',
    corsOrigins: [],
    ...(x402Facade ? { x402Facade } : {})
  })
  api.trustProxy = false
  return api
}

function mockRes () {
  const cap = { statusCode: null, headers: {}, body: null }
  const res = {
    setHeader (key, value) {
      cap.headers[String(key).toLowerCase()] = value
    },
    getHeader (key) {
      return cap.headers[String(key).toLowerCase()]
    },
    writeHead (status) {
      cap.statusCode = status
      return res
    },
    end (body) {
      cap.body = body == null ? null : String(body)
    }
  }
  return { res, cap }
}

test('x402 API exposes only the exact price-manifest route', (t) => {
  t.alike(resolveX402PriceManifestRoute('GET', '/.well-known/x402-prices'), {
    kind: 'x402-price-manifest'
  })
  t.is(resolveX402PriceManifestRoute('POST', '/.well-known/x402-prices'), null)
  t.is(resolveX402PriceManifestRoute('GET', '/.well-known/x402-prices/extra'), null)
})

test('x402 API preflight is public and exposes only payment facade headers', async (t) => {
  const api = makeApi()
  const req = {
    method: 'OPTIONS',
    url: '/svc/vrf/prove',
    headers: { origin: 'https://agent.example' },
    socket: { remoteAddress: '203.0.113.9' }
  }
  const { res, cap } = mockRes()

  await api._handle(req, res)

  t.is(cap.statusCode, 204)
  t.is(cap.headers['access-control-allow-origin'], '*')
  t.is(
    cap.headers['access-control-allow-headers'],
    'Content-Type, PAYMENT-SIGNATURE, X-HiveRelay-Idempotency-Key'
  )
  t.is(
    cap.headers['access-control-expose-headers'],
    'PAYMENT-REQUIRED, PAYMENT-RESPONSE, Retry-After'
  )
})

test('x402 API hands the configured service route to the relay router', async (t) => {
  const calls = []
  const facade = {
    async handle ({ execute }) {
      const result = await execute(
        { serviceRoute: 'vrf.prove' },
        { alpha: '01' },
        { transport: 'x402-http' }
      )
      return { handled: true, status: 200, payload: result }
    }
  }
  const router = {
    async dispatch (...args) {
      calls.push(args)
      return { proof: 'ok' }
    }
  }

  const result = await runX402ServiceRequest({
    facade,
    req: { method: 'POST' },
    url: new URL('https://relay.example/svc/vrf/prove'),
    readBody: async () => ({}),
    router
  })

  t.is(result.status, 200)
  t.alike(result.payload, { proof: 'ok' })
  t.alike(calls, [[
    'vrf.prove',
    { alpha: '01' },
    { transport: 'x402-http' }
  ]])
})
