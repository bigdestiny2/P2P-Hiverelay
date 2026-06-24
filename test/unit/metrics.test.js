import { EventEmitter } from 'events'
import test from 'brittle'
import { Metrics, prometheusNumber } from '../../packages/core/core/relay-node/metrics.js'

test('metrics: Prometheus exporter uses redacted stats and clamps sample values', (t) => {
  const calls = []
  const node = new EventEmitter()
  node.getStats = function (opts) {
    calls.push(opts)
    return {
      seededApps: '5\nhiverelay_injected 1',
      connections: Infinity,
      seeder: {
        coresSeeded: '12.5',
        totalBytesStored: -7,
        totalBytesServed: 'nope'
      },
      served: {
        totalBytesServed: 42,
        totalBlocksServed: NaN
      },
      appRegistry: {
        entries: 3,
        anchored: '2',
        unanchored: 'bad',
        cores: 6
      },
      relay: {
        activeCircuits: -1,
        totalCircuitsServed: 4,
        totalBytesRelayed: '5e2'
      },
      tor: { onionAddress: 'secret.onion' },
      holesail: { connectionKey: 'secret-key' }
    }
  }
  const metrics = new Metrics(node)
  t.teardown(() => metrics.stop())

  const out = metrics.toPrometheus()

  t.alike(calls[0], { includeSecrets: false })
  t.absent(out.includes('secret.onion'))
  t.absent(out.includes('secret-key'))
  t.absent(out.includes('hiverelay_injected 1'))
  t.absent(out.includes('Infinity'))
  t.absent(out.includes('NaN'))
  t.ok(out.includes('hiverelay_seeded_apps 0'))
  t.ok(out.includes('hiverelay_connections 0'))
  t.ok(out.includes('hiverelay_cores_seeded 12.5'))
  t.ok(out.includes('hiverelay_bytes_stored 0'))
  t.ok(out.includes('hiverelay_bytes_served 0'))
  t.ok(out.includes('hiverelay_blocks_served_measured 0'))
  t.ok(out.includes('hiverelay_active_circuits 0'))
  t.ok(out.includes('hiverelay_bytes_relayed 500'))
})

test('metrics: snapshots and summaries request public-redacted stats', (t) => {
  const calls = []
  const node = new EventEmitter()
  node.getStats = function (opts) {
    calls.push(opts)
    if (opts && opts.includeSecrets === false) {
      return {
        seededApps: 1,
        tor: { enabled: true, onionAddress: null },
        holesail: { enabled: true, connectionKey: null }
      }
    }
    return {
      seededApps: 1,
      tor: { enabled: true, onionAddress: 'secret.onion' },
      holesail: { enabled: true, connectionKey: 'secret-key' }
    }
  }
  const metrics = new Metrics(node)
  t.teardown(() => metrics.stop())

  const snapshot = metrics._snapshot()
  const summary = metrics.getSummary()

  t.alike(calls, [{ includeSecrets: false }, { includeSecrets: false }])
  t.is(snapshot.tor.onionAddress, null)
  t.is(snapshot.holesail.connectionKey, null)
  t.is(summary.current.tor.onionAddress, null)
  t.is(summary.current.holesail.connectionKey, null)
})

test('metrics: Prometheus sample sanitizer emits finite non-negative numbers', (t) => {
  t.is(prometheusNumber('3.25'), 3.25)
  t.is(prometheusNumber(-1), 0)
  t.is(prometheusNumber(Infinity), 0)
  t.is(prometheusNumber('bad\n1'), 0)
  t.is(prometheusNumber(Number.MAX_SAFE_INTEGER + 1000), Number.MAX_SAFE_INTEGER)
})
