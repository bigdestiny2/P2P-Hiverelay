/**
 * getStats() must redact transport credentials / infra identifiers for
 * unauthenticated callers. The unauthenticated HTTP /status and
 * /api/overview handlers pass includeSecrets:false; trusted in-process
 * callers (CLI, metrics, auth-gated WS feed) keep the default (true).
 *
 * Leaking the holesail connectionKey from an unauthenticated /status is a
 * privilege escalation: a remote attacker can use it to tunnel to the API
 * (the tunnel lands on 127.0.0.1) and ride the localhost auth fallback.
 */

import test from 'brittle'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'
import { mkdtemp, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

async function makeNode () {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-redact-'))
  const node = new RelayNode({ storage: dir, enableAPI: false })
  // Stub the transports / infra that expose secrets. getStats reads these
  // via getInfo()/.key without needing the node to be started.
  node.holesailTransport = { getInfo: () => ({ running: true, connectionKey: 'HOLESAIL_SECRET', apiPort: 9100 }) }
  node.torTransport = { getInfo: () => ({ running: true, socksProxy: '127.0.0.1:9050', onionAddress: 'secret.onion', activeConnections: 0 }) }
  node.diskMonitor = { getInfo: () => ({ usedPct: 12, mountPath: '/var/lib/hiverelay' }) }
  node.seedingRegistry = { running: true, key: Buffer.alloc(32, 7) }
  return { node, dir }
}

test('getStats() redacts transport secrets when includeSecrets is false', async (t) => {
  const { node, dir } = await makeNode()
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const redacted = node.getStats({ includeSecrets: false })
  t.is(redacted.holesail.connectionKey, null, 'holesail connectionKey redacted')
  t.is(redacted.tor.onionAddress, null, 'tor onionAddress redacted')
  t.is(redacted.disk.mountPath, null, 'disk mountPath redacted')
  t.is(redacted.registry.key, null, 'registry key redacted')
  // Non-secret state is preserved so the dashboard still shows transport status.
  t.is(redacted.holesail.running, true, 'holesail running flag preserved')
  t.is(redacted.tor.running, true, 'tor running flag preserved')
})

test('getStats() includes secrets by default and when includeSecrets is true', async (t) => {
  const { node, dir } = await makeNode()
  t.teardown(() => rm(dir, { recursive: true, force: true }))

  const full = node.getStats()
  t.is(full.holesail.connectionKey, 'HOLESAIL_SECRET', 'default includes connectionKey')
  t.is(full.tor.onionAddress, 'secret.onion', 'default includes onionAddress')

  const explicit = node.getStats({ includeSecrets: true })
  t.is(explicit.holesail.connectionKey, 'HOLESAIL_SECRET', 'explicit true includes connectionKey')
  t.is(explicit.disk.mountPath, '/var/lib/hiverelay', 'explicit true includes mountPath')
  t.is(explicit.registry.key, Buffer.alloc(32, 7).toString('hex'), 'explicit true includes registry key')
})
