import test from 'brittle'

test('core and split client package entrypoints resolve independently', async (t) => {
  const core = await import('../../packages/core/core/index.js')
  const client = await import('../../packages/client/index.js')
  const installedCore = await import('p2p-hiverelay')
  const installedClient = await import('p2p-hiverelay-client')

  t.is(typeof core.RelayNode, 'function')
  t.is(typeof core.ServiceRegistry, 'undefined', 'services stay on their explicit subpath')
  t.is(typeof client.HiveRelayClient, 'function')
  t.is(typeof installedCore.RelayNode, 'function')
  t.is(typeof installedCore.HiveRelayClient, 'undefined', 'core package does not re-export the split client SDK')
  t.is(typeof installedClient.HiveRelayClient, 'function')
})

test('customer-used core service and relay subpaths resolve', async (t) => {
  const services = await import('../../packages/core/core/services/index.js')
  const forward = await import('../../packages/core/core/protocol/forward-relay.js')
  const directory = await import('../../packages/core/core/services/signed-directory.js')
  const installedServices = await import('p2p-hiverelay/core/services/index.js')
  const installedForward = await import('p2p-hiverelay/core/protocol/forward-relay.js')
  const installedDirectory = await import('p2p-hiverelay/core/services/signed-directory.js')

  t.is(typeof services.ServiceRegistry, 'function')
  t.is(typeof services.ServiceProtocol, 'function')
  t.is(typeof forward.ForwardRelay, 'function')
  t.is(typeof directory.SignedDirectory, 'function')
  t.is(typeof installedServices.ServiceRegistry, 'function')
  t.is(typeof installedServices.ServiceProtocol, 'function')
  t.is(typeof installedForward.ForwardRelay, 'function')
  t.is(typeof installedDirectory.SignedDirectory, 'function')
})

test('legacy bundled client subpath is not part of the 0.20 package contract', async (t) => {
  try {
    await import('p2p-hiverelay/client')
    t.fail('legacy client subpath unexpectedly resolved')
  } catch (err) {
    t.ok(err && (err.code === 'ERR_MODULE_NOT_FOUND' || err.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED'))
  }
})
