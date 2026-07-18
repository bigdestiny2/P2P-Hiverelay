import test from 'brittle'
import {
  assertSafeOnionVports,
  classifyOnionVports,
  selectOnionReadPort
} from 'p2p-hiverelay/transports/tor/vport-policy.js'

test('tor vport policy classifies reordered and peer-only mappings by role', (t) => {
  const reordered = classifyOnionVports([
    { vport: 19737, targetPort: 19737 },
    { vport: 8080, targetPort: 9200 }
  ], { peerTargetPort: 19737, readTargetPort: 9200 })
  t.alike(reordered, { readPlane: 8080, peer: 19737 })

  const peerOnly = classifyOnionVports([
    { vport: 19737, targetPort: 19737 }
  ], { peerVport: 19737 })
  t.alike(peerOnly, { readPlane: null, peer: 19737 })

  const explicitRead = classifyOnionVports([
    { vport: 8080, targetPort: 9300 },
    { vport: 80, targetPort: 9200 }
  ], { readVport: 80 })
  t.alike(explicitRead, { readPlane: 80, peer: null })

  const externallyRemappedPeer = classifyOnionVports([
    { vport: 443, targetPort: 19737 },
    { vport: 80, targetPort: 9200 }
  ], { peerVport: 19737, peerTargetPort: 19737, readTargetPort: 9200 })
  t.alike(externallyRemappedPeer, { readPlane: 80, peer: 443 })

  const overriddenConventionalPeerPort = classifyOnionVports([
    { vport: 19737, targetPort: 9200 }
  ], { peerVport: 19737, peerTargetPort: 19738, readTargetPort: 9200 })
  t.alike(overriddenConventionalPeerPort, { readPlane: 19737, peer: null })

  const arbitraryTcp = classifyOnionVports([
    { vport: 9001, targetPort: 9001 }
  ])
  t.alike(arbitraryTcp, { readPlane: null, peer: null })
})

test('tor vport policy rejects loopback-trusting listeners unconditionally', (t) => {
  const apiMapping = [
    { vport: 80, targetHost: '127.0.0.1', targetPort: 9100 }
  ]
  t.exception(
    () => assertSafeOnionVports(apiMapping, { apiPort: 9100 }),
    /cannot expose RelayAPI/
  )
  t.exception(
    () => assertSafeOnionVports(apiMapping, { apiPort: 9100, apiKey: 'operator-secret' }),
    /cannot expose RelayAPI/
  )
  t.exception(
    () => assertSafeOnionVports([
      { vport: 80, targetHost: '127.0.0.1', targetPort: 9200 }
    ], { trustedProxyGatewayPort: 9200 }),
    /cannot expose a trustProxy gateway/
  )
  t.execution(() => assertSafeOnionVports([
    { vport: 80, targetHost: '127.0.0.1', targetPort: 9200 }
  ], { apiPort: 9100 }))
  t.execution(() => assertSafeOnionVports(apiMapping, { apiPort: null }))
})

test('tor default read selection excludes proxy-trusting gateways', (t) => {
  t.is(selectOnionReadPort({ port: 9200, trustProxy: false }), 9200)
  t.is(selectOnionReadPort({ port: 9200, trustProxy: true }), null)
  t.is(selectOnionReadPort(null), null)
})
