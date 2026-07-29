import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { buildCapabilityDoc } from '../../packages/core/core/capability-doc.js'
import {
  buildX402PriceManifest,
  verifyX402PriceManifest
} from '../../packages/core/incentive/x402/price-manifest.js'

const PAY_TO = '0x1111111111111111111111111111111111111111'
const ASSET = '0x2222222222222222222222222222222222222222'

function keyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function enabledConfig () {
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
        }]
      }
    }
  }
}

test('x402 price manifest is relay-signed and exposes atomic terms', (t) => {
  const keys = keyPair()
  const manifest = buildX402PriceManifest({
    config: enabledConfig(),
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
    attestedAt: 123456
  })

  t.is(manifest.x402Version, 2)
  t.is(manifest.services['vrf.prove'].path, '/svc/vrf/prove')
  t.alike(manifest.services['vrf.prove'].accepts[0], {
    scheme: 'exact',
    network: 'eip155:84532',
    asset: ASSET,
    amount: '1000',
    payTo: PAY_TO
  })
  t.alike(verifyX402PriceManifest(manifest), { valid: true })

  manifest.services['vrf.prove'].accepts[0].amount = '1'
  t.absent(verifyX402PriceManifest(manifest).valid, 'tampering invalidates the signature')
})

test('capability doc advertises the x402 v2 facade only when enabled on Node', (t) => {
  const enabled = buildCapabilityDoc({
    runtime: 'node',
    relay: { config: { x402: enabledConfig() } }
  })
  t.ok(enabled.features.includes('x402-v2'))
  t.is(enabled.x402.prices, '/.well-known/x402-prices')
  t.ok(enabled.protocol_profile.app_surfaces.includes('x402'))

  const bare = buildCapabilityDoc({
    runtime: 'bare',
    relay: { config: { x402: enabledConfig() } }
  })
  t.absent(bare.features.includes('x402-v2'))
  t.absent('x402' in bare)
})
