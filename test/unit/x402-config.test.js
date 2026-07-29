import test from 'brittle'
import {
  isX402ServicePath,
  normalizeX402Config,
  x402SdkRoutes
} from '../../packages/core/incentive/x402/config.js'

const PAY_TO = '0x1111111111111111111111111111111111111111'
const ASSET = '0x2222222222222222222222222222222222222222'

function route (amount = '1000') {
  return {
    serviceRoute: 'vrf.prove',
    sideEffects: 'read-only',
    description: 'Create a verifiable randomness proof',
    unit: 'proof',
    proofType: 'ecvrf-proof-v1',
    accepts: [{
      scheme: 'exact',
      network: 'eip155:84532',
      payTo: PAY_TO,
      price: { asset: ASSET, amount }
    }]
  }
}

test('x402 config is disabled and route-empty by default', (t) => {
  const config = normalizeX402Config()
  t.absent(config.enabled)
  t.alike(config.routes, {})
  t.alike(x402SdkRoutes(config), {})
  t.ok(isX402ServicePath('/svc/vrf/prove'))
  t.absent(isX402ServicePath('/api/v1/vrf/prove'))
})

test('x402 config compiles an explicit atomic-amount service route for the official SDK', (t) => {
  const config = normalizeX402Config({
    enabled: true,
    facilitatorUrl: 'https://x402.org/facilitator',
    publicBaseUrl: 'https://relay.example',
    routes: {
      'POST /svc/vrf/prove': route()
    }
  })
  const sdk = x402SdkRoutes(config)

  t.is(config.routes['POST /svc/vrf/prove'].serviceRoute, 'vrf.prove')
  t.is(sdk['POST /svc/vrf/prove'].resource, 'https://relay.example/svc/vrf/prove')
  t.alike(sdk['POST /svc/vrf/prove'].accepts[0].price, {
    asset: ASSET,
    amount: '1000'
  })
})

test('x402 config rejects unsafe writes, dollar strings, and duplicate cross-route payment tuples', (t) => {
  t.exception(() => normalizeX402Config({
    enabled: true,
    publicBaseUrl: 'https://relay.example',
    routes: {
      'POST /svc/notify/send': {
        ...route(),
        serviceRoute: 'notify.send',
        sideEffects: 'idempotent-write'
      }
    }
  }), /requireIdempotencyKey:true/)

  t.exception(() => normalizeX402Config({
    enabled: true,
    publicBaseUrl: 'https://relay.example',
    routes: {
      'POST /svc/vrf/prove': {
        ...route(),
        accepts: [{
          scheme: 'exact',
          network: 'eip155:84532',
          payTo: PAY_TO,
          price: '$0.01'
        }]
      }
    }
  }), /price.asset/)

  t.exception(() => normalizeX402Config({
    enabled: true,
    publicBaseUrl: 'https://relay.example',
    routes: {
      'POST /svc/vrf/prove': route(),
      'GET /svc/vrf/beacon-range': {
        ...route(),
        serviceRoute: 'vrf.beacon-range'
      }
    }
  }), /reuse the same payment tuple/)
})
