import test from 'brittle'
import {
  buildHealthResponse,
  diskHealthSummary,
  MAX_HEALTH_DISK_ERROR_BYTES,
  resolveHealthRoute
} from '../../packages/core/core/relay-node/api-health.js'

const RESOURCE_DIAGNOSTICS = Object.freeze({
  kind: 'HiveRelayResourceDiagnosticsV1',
  version: 1,
  process: { uptimeMs: 1234 },
  sample: { available: true }
})

function nodeFixture (overrides = {}) {
  return {
    running: true,
    config: {},
    metrics: { getSummary () { throw new Error('health must not call metrics summary') } },
    getResourceDiagnostics () { return RESOURCE_DIAGNOSTICS },
    ...overrides
  }
}

test('api health: route resolver maps only the exact public health route', (t) => {
  t.alike(resolveHealthRoute('GET', '/health'), { kind: 'health' })
  t.is(resolveHealthRoute('POST', '/health'), null, 'wrong method falls through')
  t.is(resolveHealthRoute('GET', '/health/extra'), null, 'subpath falls through')
  t.is(resolveHealthRoute('GET', '/status'), null, 'adjacent status route falls through')
  t.is(resolveHealthRoute('GET', '/api/health-detail'), null, 'operator health detail route falls through')
})

test('api health: summarizes missing, error, and ordinary disk state', (t) => {
  t.is(diskHealthSummary(null), null)
  t.alike(diskHealthSummary({ error: 'df failed', status: 'critical', usedPct: 99 }), {
    error: 'df failed'
  })
  t.alike(diskHealthSummary({
    usedPct: 72.5,
    status: 'warn',
    mountPath: '/data',
    extra: 'not public'
  }), {
    usedPct: 72.5,
    status: 'warn'
  })
})

test('api health: disk summary omits filesystem topology and caps unsafe errors', (t) => {
  t.alike(diskHealthSummary({
    usedPct: -1,
    status: 'weird',
    mountPath: '/private/data'
  }), {
    usedPct: 0,
    status: null
  })

  t.alike(diskHealthSummary({
    error: 'df failed\n/private/data',
    mountPath: '/private/data'
  }), {
    usedPct: 0,
    status: null
  })

  const out = diskHealthSummary({ error: 'x'.repeat(MAX_HEALTH_DISK_ERROR_BYTES + 10) })
  t.is(out.error.length, MAX_HEALTH_DISK_ERROR_BYTES)
})

test('api health: healthy response includes version uptime running and disk facts', (t) => {
  const out = buildHealthResponse({
    version: '9.9.9',
    node: nodeFixture({
      diskMonitor: {
        getInfo () {
          return { usedPct: 42, status: 'ok', mountPath: '/relay' }
        }
      }
    })
  })

  t.is(out.status, 200)
  t.alike(out.payload, {
    ok: true,
    version: '9.9.9',
    uptime: { ms: 1234, hours: 0, human: '0m' },
    running: true,
    disk: { usedPct: 42, status: 'ok' },
    storageGeneration: null,
    resourceDiagnostics: RESOURCE_DIAGNOSTICS
  })
})

test('api health: critical disk stays 200 unless diskHealthGate is enabled', (t) => {
  const out = buildHealthResponse({
    version: '1.2.3',
    node: nodeFixture({
      config: { diskHealthGate: false },
      diskMonitor: {
        getInfo () {
          return { usedPct: 99, status: 'critical', mountPath: '/data' }
        }
      }
    })
  })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.is(out.payload.disk.status, 'critical')
})

test('api health: diskHealthGate drains critical relays with stable fleet payload', (t) => {
  const out = buildHealthResponse({
    version: '2.0.0',
    node: nodeFixture({
      running: false,
      config: { diskHealthGate: true },
      diskMonitor: {
        getInfo () {
          return { usedPct: 98.2, status: 'critical', mountPath: '/data' }
        }
      }
    })
  })

  t.is(out.status, 503)
  t.alike(out.payload, {
    ok: false,
    reason: 'disk-critical',
    reasons: [{ code: 'disk-critical', status: 'critical' }],
    version: '2.0.0',
    uptime: { ms: 1234, hours: 0, human: '0m' },
    running: false,
    disk: { usedPct: 98.2, status: 'critical' },
    storageGeneration: null,
    resourceDiagnostics: RESOURCE_DIAGNOSTICS
  })
})

test('api health: fail-closed storage authority reports 503 before the disk gate', (t) => {
  // A fail-closed storage authority is terminal and restart-proof, so it must
  // win over the (restartable) disk drain even when diskHealthGate is on.
  const out = buildHealthResponse({
    version: '3.0.0',
    node: nodeFixture({
      config: { diskHealthGate: true },
      storageAdmission: { fatalReason: 'journal invariant violated' },
      diskMonitor: {
        getInfo () {
          return { usedPct: 99, status: 'critical', mountPath: '/data' }
        }
      }
    })
  })

  t.is(out.status, 503)
  t.alike(out.payload, {
    ok: false,
    reason: 'storage-fail-closed',
    reasons: [{ code: 'storage-fail-closed', detail: 'journal invariant violated' }],
    storageFatalReason: 'journal invariant violated',
    version: '3.0.0',
    uptime: { ms: 1234, hours: 0, human: '0m' },
    running: true,
    disk: { usedPct: 99, status: 'critical' },
    storageGeneration: null,
    resourceDiagnostics: RESOURCE_DIAGNOSTICS
  })
})

test('api health: healthy storage authority does not perturb the 200 payload', (t) => {
  const out = buildHealthResponse({
    version: '3.0.1',
    node: nodeFixture({
      storageAdmission: { fatalReason: null }
    })
  })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.absent(out.payload.reason)
})

test('api health: missing metrics and disk monitor remain stable', (t) => {
  const out = buildHealthResponse({
    version: null,
    node: nodeFixture({ metrics: null, diskMonitor: null, getResourceDiagnostics: () => null })
  })

  t.is(out.status, 200)
  t.alike(out.payload, {
    ok: true,
    version: null,
    uptime: null,
    running: true,
    disk: null,
    storageGeneration: null,
    resourceDiagnostics: null
  })
})

test('api health: request path never walks stats, registries, storage, or unresolved drives', (t) => {
  const forbidden = () => { throw new Error('forbidden health walk') }
  const out = buildHealthResponse({
    version: '4.0.0',
    node: nodeFixture({
      getStats: forbidden,
      metrics: { startedAt: Date.now() - 1000, getSummary: forbidden },
      appRegistry: { catalog: forbidden, snapshot: forbidden },
      storageAccounting: { getSummary: forbidden, measureDisk: forbidden },
      getResourceDiagnostics () { return RESOURCE_DIAGNOSTICS }
    })
  })

  t.is(out.status, 200)
  t.is(out.payload.ok, true)
  t.is(out.payload.resourceDiagnostics, RESOURCE_DIAGNOSTICS)
})
