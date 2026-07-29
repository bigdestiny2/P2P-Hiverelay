import b4a from 'b4a'
import test from 'brittle'
import {
  loadDaemonBootstrapConfig,
  requiredEndpointIds,
  requiredTopologyHash
} from '../bootstrap-config.js'

function validEnvironment (overrides = {}) {
  return {
    HIVERELAY_BLIND_UNARY_SOCKET: '/private/tmp/hiverelay-blind/unary.sock',
    HIVERELAY_BLIND_STREAM_SOCKET: '/private/tmp/hiverelay-blind/stream.sock',
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: 'ab'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1,7,255',
    HIVERELAY_BLIND_EDGE_UID: '998',
    HIVERELAY_BLIND_DAEMON_UID: '999',
    HIVERELAY_BLIND_DAEMON_GID: '997',
    HIVERELAY_BLIND_SHARED_GID: '997',
    ...overrides
  }
}

const identity = { getuid: () => 999, getgid: () => 997 }

test('daemon bootstrap config binds every signed topology input exactly', t => {
  const config = loadDaemonBootstrapConfig(validEnvironment(), identity)
  t.is(config.unarySocketPath, '/private/tmp/hiverelay-blind/unary.sock')
  t.is(config.streamSocketPath, '/private/tmp/hiverelay-blind/stream.sock')
  t.is(config.expectedPeerUid, 998)
  t.is(config.expectedPeerGid, 997)
  t.is(config.socketGroupGid, 997)
  t.alike(config.endpointIds, [1, 7, 255])
  t.alike(config.launchTopologyHash, b4a.alloc(32, 0xab))
  t.is(Object.isFrozen(config.endpointIds), true)
})

test('daemon endpoint set encoding is canonical, ordered and duplicate-free', async t => {
  for (const value of ['', '0', '01', '256', '2,1', '1,1', '1, 2', '1,2,', ',1', '1'.repeat(1020)]) {
    await t.exception(() => requiredEndpointIds(validEnvironment({ HIVERELAY_BLIND_ENDPOINT_IDS: value })), 'rejects malformed endpoint set')
  }
  t.alike(requiredEndpointIds(validEnvironment({ HIVERELAY_BLIND_ENDPOINT_IDS: '1,2,255' })), [1, 2, 255])
})

test('daemon bootstrap rejects incomplete, aliased and wrong-identity topology', async t => {
  const cases = [
    { HIVERELAY_BLIND_UNARY_SOCKET: undefined },
    { HIVERELAY_BLIND_STREAM_SOCKET: 'relative.sock' },
    { HIVERELAY_BLIND_STREAM_SOCKET: '/private/tmp/hiverelay-blind/unary.sock' },
    { HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '00' },
    { HIVERELAY_BLIND_ENDPOINT_IDS: undefined },
    { HIVERELAY_BLIND_EDGE_UID: '999' },
    { HIVERELAY_BLIND_DAEMON_UID: '0999' },
    { HIVERELAY_BLIND_DAEMON_GID: '996' }
  ]
  for (const overrides of cases) await t.exception(() => loadDaemonBootstrapConfig(validEnvironment(overrides), identity))
  await t.exception(() => loadDaemonBootstrapConfig(validEnvironment(), { getuid: () => 1000, getgid: () => 997 }))
  await t.exception(() => loadDaemonBootstrapConfig(validEnvironment(), { getuid: () => 999, getgid: () => 996 }))
  await t.exception(() => loadDaemonBootstrapConfig(validEnvironment(), {}))
})

test('daemon topology hash accepts exact hex bytes and rejects shape drift', async t => {
  t.alike(requiredTopologyHash(validEnvironment({
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: 'CD'.repeat(32)
  })), b4a.alloc(32, 0xcd))
  for (const value of ['', '0'.repeat(63), '0'.repeat(65), 'zz'.repeat(32), ` ${'00'.repeat(32)}`]) {
    await t.exception(() => requiredTopologyHash(validEnvironment({ HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: value })))
  }
})
