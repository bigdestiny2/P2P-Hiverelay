import test from 'brittle'
import {
  LOCAL_RUNTIME_SERVICE_PERMISSION,
  assertLocalRuntimeBridgeCall,
  checkLocalRuntimeBridgeCall,
  hasLocalRuntimePermission,
  isLoopbackEndpoint,
  isPrivateRuntimeEndpoint
} from 'p2p-hiverelay/core/app-runtime-policy.js'

function privateAiManifest (overrides = {}) {
  return {
    permissions: [LOCAL_RUNTIME_SERVICE_PERMISSION],
    privacy: {
      storesPrompts: false,
      remoteHttpInference: 'forbidden'
    },
    ...overrides
  }
}

test('AppRuntimePolicy - detects loopback endpoints only', (t) => {
  t.ok(isLoopbackEndpoint('http://127.0.0.1:19311'))
  t.ok(isLoopbackEndpoint('http://localhost:19311'))
  t.ok(isLoopbackEndpoint('http://[::1]:19311'))
  t.absent(isLoopbackEndpoint('http://192.0.2.10:19311'))
  t.absent(isLoopbackEndpoint('https://example.com'))
})

test('AppRuntimePolicy - detects private runtime endpoints', (t) => {
  t.ok(isPrivateRuntimeEndpoint('hiverelay-runtime://services'))
  t.ok(isPrivateRuntimeEndpoint('pear-runtime://anongpt'))
  t.absent(isPrivateRuntimeEndpoint('http://127.0.0.1:19311'))
})

test('AppRuntimePolicy - requires declared local runtime permission', (t) => {
  t.ok(hasLocalRuntimePermission({ permissions: [LOCAL_RUNTIME_SERVICE_PERMISSION] }))
  t.ok(hasLocalRuntimePermission({ hiverelay: { runtime: { permissions: [LOCAL_RUNTIME_SERVICE_PERMISSION] } } }))
  t.absent(hasLocalRuntimePermission({ permissions: ['storage.read'] }))
})

test('AppRuntimePolicy - allows private ai.infer over direct P2P with receipt verification', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'hyperswarm',
    endpoint: 'hiverelay-runtime://services',
    receiptVerification: true
  })
  t.ok(result.allowed)
})

test('AppRuntimePolicy - allows circuit relay as opaque transport', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'circuit-relay',
    receiptVerification: true
  })
  t.ok(result.allowed)
})

test('AppRuntimePolicy - denies remote HTTP inference routes', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'https',
    endpoint: 'https://relay.example/infer',
    receiptVerification: true
  })
  t.is(result.allowed, false)
  t.is(result.code, 'REMOTE_TERMINATING_ROUTE')
})

test('AppRuntimePolicy - denies non-local endpoints', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'local-runtime',
    endpoint: 'http://192.0.2.10:19311',
    receiptVerification: true
  }, { allowDevLoopbackHttp: true })
  t.is(result.allowed, false)
  t.is(result.code, 'NON_LOCAL_ENDPOINT')
})

test('AppRuntimePolicy - loopback HTTP requires dev opt-in', (t) => {
  const req = {
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'local-runtime',
    endpoint: 'http://127.0.0.1:19311',
    receiptVerification: true
  }
  t.is(checkLocalRuntimeBridgeCall(req).allowed, false)
  t.ok(checkLocalRuntimeBridgeCall(req, { allowDevLoopbackHttp: true }).allowed)
})

test('AppRuntimePolicy - ai.infer requires no prompt persistence declaration', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest({ privacy: { remoteHttpInference: 'forbidden' } }),
    service: 'ai',
    method: 'infer',
    route: 'hyperswarm',
    receiptVerification: true
  })
  t.is(result.allowed, false)
  t.is(result.code, 'PROMPT_PERSISTENCE_UNDECLARED')
})

test('AppRuntimePolicy - ai.infer requires remote HTTP to be forbidden', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest({ privacy: { storesPrompts: false, remoteHttpInference: 'disabled-by-default' } }),
    service: 'ai',
    method: 'infer',
    route: 'hyperswarm',
    receiptVerification: true
  })
  t.is(result.allowed, false)
  t.is(result.code, 'REMOTE_HTTP_NOT_FORBIDDEN')
})

test('AppRuntimePolicy - ai.infer requires local receipt verification', (t) => {
  const result = checkLocalRuntimeBridgeCall({
    manifest: privateAiManifest(),
    service: 'ai',
    method: 'infer',
    route: 'hyperswarm'
  })
  t.is(result.allowed, false)
  t.is(result.code, 'RECEIPT_VERIFICATION_REQUIRED')
})

test('AppRuntimePolicy - assert throws structured codes', (t) => {
  try {
    assertLocalRuntimeBridgeCall({
      manifest: privateAiManifest(),
      service: 'ai',
      method: 'infer',
      route: 'remote-http',
      receiptVerification: true
    })
    t.fail('expected assertion to throw')
  } catch (err) {
    t.is(err.code, 'REMOTE_TERMINATING_ROUTE')
  }
})
