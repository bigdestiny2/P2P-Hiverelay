import test from 'brittle'
import {
  buildAutoHealPayload,
  buildHealthDetailPayload,
  buildMetricsHistoryPayload,
  buildStorageTopPayload,
  MAX_OPERATOR_AUTO_HEAL_DRIVES,
  MAX_OPERATOR_HEALTH_ACTIONS,
  MAX_METRICS_HISTORY_SNAPSHOTS
} from 'p2p-hiverelay/core/relay-node/api-operator-telemetry.js'

test('api operator telemetry: health detail caps and sanitizes health and self-heal actions', (t) => {
  const out = buildHealthDetailPayload({
    node: {
      getHealthStatus () {
        return {
          healthy: true,
          lastCheck: 1234,
          consecutiveFailures: 2,
          unsafe: 'should-not-leak',
          checks: {
            memory: {
              ok: false,
              critical: true,
              heapPct: 99.5,
              rssMB: 700,
              secret: 'should-not-leak'
            },
            connections: {
              ok: true,
              staleCount: 1,
              totalConns: 3,
              suggestion: 'DHT re-announce'
            },
            disk: {
              ok: false,
              usedPct: 91.2,
              freeGB: 1.5,
              totalGB: 20,
              error: 'disk almost full',
              mountPath: '/should/not/leak'
            },
            unknown: { ok: false, secret: 'should-not-leak' }
          }
        }
      },
      selfHeal: {
        getActions () {
          return [
            { type: 'bad\ncontrol', timestamp: 1, secret: 'should-not-leak' },
            ...Array.from({ length: MAX_OPERATOR_HEALTH_ACTIONS + 1 }, (_, i) => ({
              type: 'repair',
              check: 'memory',
              appKey: 'a'.repeat(64),
              timestamp: 1000 + i,
              reason: 'bounded action',
              error: i === MAX_OPERATOR_HEALTH_ACTIONS ? 'last error' : null,
              destroyed: i,
              details: {
                ok: false,
                heapPct: 99,
                secret: 'should-not-leak'
              },
              secret: 'should-not-leak'
            }))
          ]
        }
      }
    }
  })

  t.is(out.status, 200)
  t.alike(out.payload.checks.memory, {
    ok: false,
    critical: true,
    heapPct: 99.5,
    rssMB: 700
  })
  t.alike(out.payload.checks.connections, {
    ok: true,
    staleCount: 1,
    totalConns: 3,
    suggestion: 'DHT re-announce'
  })
  t.alike(out.payload.checks.disk, {
    ok: false,
    usedPct: 91.2,
    freeGB: 1.5,
    totalGB: 20,
    error: 'disk almost full'
  })
  t.is(out.payload.actions.length, MAX_OPERATOR_HEALTH_ACTIONS, 'action history is capped')
  t.is(out.payload.actions[0].timestamp, 1001, 'cap keeps newest self-heal actions')
  t.is(out.payload.actions[out.payload.actions.length - 1].error, 'last error')
  t.absent(JSON.stringify(out.payload).includes('should-not-leak'), 'raw health/action fields are dropped')

  t.alike(buildHealthDetailPayload({ node: {} }).payload, { actions: [] })
})

test('api operator telemetry: storage top sanitizes summary and measured rows', (t) => {
  const calls = []
  const out = buildStorageTopPayload({
    n: 7,
    storageAccounting: {
      getSummary () {
        return { totalBytes: 1234, measuredEntries: 2, privatePath: '/should/not/leak' }
      },
      getTop (n) {
        calls.push(n)
        return [
          { appKey: 'b'.repeat(64), bytes: 512, measuredAt: 1000, privatePath: '/should/not/leak' },
          { appKey: 'not-hex', bytes: 1 },
          { appKey: 'c'.repeat(64), bytes: -1 }
        ]
      }
    }
  })

  t.is(out.status, 200)
  t.alike(calls, [7])
  t.alike(out.payload, {
    totalBytes: 1234,
    measuredEntries: 2,
    entries: [{ appKey: 'b'.repeat(64), bytes: 512, measuredAt: 1000 }]
  })
  t.absent(JSON.stringify(out.payload).includes('should-not-leak'), 'raw storage fields are dropped')
  t.alike(buildStorageTopPayload().payload, { entries: [] })
})

test('api operator telemetry: auto-heal payload distinguishes disabled and sanitizes running state', (t) => {
  t.alike(buildAutoHealPayload().payload, {
    enabled: false,
    reason: 'AutoHeal not enabled in config'
  })

  const out = buildAutoHealPayload({
    autoHeal: {
      snapshot () {
        return {
          enabled: true,
          running: true,
          tickMs: 5000,
          thresholds: {
            minReplicas: 7,
            minRegions: 4,
            minOperators: 5,
            replicaBuffer: 2,
            secret: 'should-not-leak'
          },
          tracked: MAX_OPERATOR_AUTO_HEAL_DRIVES + 3,
          below: 1,
          verifyProofs: true,
          proofCacheSize: 9,
          privateCache: 'should-not-leak',
          drives: [
            { appKey: 'bad-key', replicas: 1, secret: 'should-not-leak' },
            ...Array.from({ length: MAX_OPERATOR_AUTO_HEAL_DRIVES + 2 }, (_, i) => ({
              appKey: (i % 2 === 0 ? 'c' : 'd').repeat(64),
              replicas: i,
              regions: ['eu', 'us', 'bad\nregion'],
              operators: ['alice', 'bob', 'bad\noperator'],
              meetsThreshold: i > 0,
              haveLocally: i === 1,
              backoff: { failures: i, retryInMs: 1000 + i, reason: 'should-not-leak' },
              raw: [{ secret: 'should-not-leak' }]
            }))
          ]
        }
      }
    }
  })

  t.is(out.status, 200)
  t.is(out.payload.enabled, true)
  t.is(out.payload.running, true)
  t.alike(out.payload.thresholds, {
    minReplicas: 7,
    minRegions: 4,
    minOperators: 5,
    replicaBuffer: 2
  })
  t.is(out.payload.drives.length, MAX_OPERATOR_AUTO_HEAL_DRIVES, 'auto-heal drives are capped')
  t.alike(out.payload.drives[0], {
    appKey: 'c'.repeat(64),
    replicas: 0,
    regions: ['eu', 'us'],
    operators: ['alice', 'bob'],
    meetsThreshold: false,
    haveLocally: false,
    backoff: { failures: 0, retryInMs: 1000 }
  })
  t.absent(JSON.stringify(out.payload).includes('should-not-leak'), 'raw auto-heal fields are dropped')
})

test('api operator telemetry: metrics history is retention-bounded, capped, and sanitized', (t) => {
  const now = 1_000_000
  const out = buildMetricsHistoryPayload({
    now,
    minutes: 10,
    metrics: {
      snapshots: [
        {
          timestamp: now - 5 * 60_000,
          running: true,
          mode: 'public',
          seededApps: 7,
          connections: 4,
          marker: 'recent',
          credential: 'should-not-leak',
          holesail: { connectionKey: 'should-not-leak' },
          registry: { key: 'should-not-leak' },
          seeder: {
            coresSeeded: 1,
            totalBytesStored: 2,
            totalBytesServed: 3,
            capacityUsedPct: 4.5,
            secret: 'should-not-leak'
          },
          served: {
            totalBytesServed: 5,
            totalBlocksServed: 6,
            trackedCores: 2
          },
          relay: {
            activeCircuits: 1,
            totalCircuitsServed: 2,
            totalBytesRelayed: 3,
            capacityUsedPct: 50,
            peersWithCircuits: 1
          },
          appRegistry: {
            entries: 2,
            anchored: 1,
            unanchored: 1,
            cores: 4
          },
          storage: {
            totalBytes: 9,
            measuredEntries: 2,
            fullSweeps: 1,
            lastFullSweepAt: now - 1000
          },
          disk: {
            totalBytes: 100,
            usedBytes: 40,
            availableBytes: 60,
            usedPct: 40,
            checkedAt: now - 500,
            status: 'warn',
            mountPath: '/should/not/leak',
            error: 'should-not-leak'
          }
        },
        { timestamp: now - 20 * 60_000, marker: 'old' },
        { timestamp: 'not-a-number', marker: 'malformed' },
        null
      ]
    }
  })

  t.is(out.status, 200)
  t.alike(out.payload, [{
    timestamp: now - 5 * 60_000,
    running: true,
    mode: 'public',
    seededApps: 7,
    connections: 4,
    relay: {
      activeCircuits: 1,
      totalCircuitsServed: 2,
      totalBytesRelayed: 3,
      capacityUsedPct: 50,
      peersWithCircuits: 1
    },
    seeder: {
      coresSeeded: 1,
      totalBytesStored: 2,
      totalBytesServed: 3,
      capacityUsedPct: 4.5
    },
    served: {
      totalBytesServed: 5,
      totalBlocksServed: 6,
      trackedCores: 2
    },
    storage: {
      totalBytes: 9,
      measuredEntries: 2,
      fullSweeps: 1,
      lastFullSweepAt: now - 1000
    },
    appRegistry: {
      entries: 2,
      anchored: 1,
      unanchored: 1,
      cores: 4
    },
    disk: {
      totalBytes: 100,
      usedBytes: 40,
      availableBytes: 60,
      usedPct: 40,
      checkedAt: now - 500,
      status: 'warn'
    }
  }])
  t.absent(JSON.stringify(out.payload).includes('should-not-leak'), 'raw internal fields are dropped')

  const missing = buildMetricsHistoryPayload({ metrics: null })
  t.is(missing.status, 503)
  t.alike(missing.payload, { error: 'Metrics not enabled' })

  const malformedStore = buildMetricsHistoryPayload({
    now,
    minutes: 10,
    metrics: { snapshots: null }
  })
  t.is(malformedStore.status, 200)
  t.alike(malformedStore.payload, [])

  const capped = buildMetricsHistoryPayload({
    now,
    minutes: 10,
    metrics: {
      snapshots: Array.from({ length: MAX_METRICS_HISTORY_SNAPSHOTS + 5 }, (_, i) => ({
        timestamp: now - (MAX_METRICS_HISTORY_SNAPSHOTS + 5 - i),
        connections: i,
        marker: `row-${i}`
      }))
    }
  })
  t.is(capped.status, 200)
  t.is(capped.payload.length, MAX_METRICS_HISTORY_SNAPSHOTS, 'history response is capped')
  t.is(capped.payload[0].connections, 5, 'cap keeps newest rows in chronological order')
  t.absent(JSON.stringify(capped.payload).includes('row-'), 'cap output keeps the shaped metric surface')
})
