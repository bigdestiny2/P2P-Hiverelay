import test from 'brittle'
import {
  MAX_STATUS_ERROR_BYTES,
  buildStatusPayload,
  buildStatusRoutePayload,
  resolveStatusRoute,
  sanitizeCapacitySummary,
  statusString
} from 'p2p-hiverelay/core/relay-node/api-status-read.js'

test('api status: route resolver maps only the exact public status route', (t) => {
  t.alike(resolveStatusRoute('GET', '/status'), { kind: 'status' })
  t.is(resolveStatusRoute('POST', '/status'), null, 'wrong method falls through')
  t.is(resolveStatusRoute('GET', '/status/extra'), null, 'subpath falls through')
  t.is(resolveStatusRoute('GET', '/health'), null, 'adjacent health route falls through')
  t.is(resolveStatusRoute('GET', '/metrics'), null, 'adjacent metrics route falls through')
})

test('api status: route payload helper dispatches bounded public status', (t) => {
  const calls = []
  const result = buildStatusRoutePayload({
    route: { kind: 'status' },
    now: 15_000,
    node: {
      config: { regions: ['NA'] },
      metrics: { startedAt: 10_000 },
      getStats (opts) {
        calls.push(opts)
        return {
          running: true,
          mode: 'relay-core',
          publicKey: 'B'.repeat(64),
          seededApps: 4,
          connections: 7,
          holesail: {
            running: true,
            connectionKey: 'do-not-leak'
          }
        }
      }
    }
  })
  const unknown = buildStatusRoutePayload({
    route: { kind: 'unknown' },
    node: {
      getStats () {
        throw new Error('should not be called')
      }
    }
  })

  t.alike(calls, [{ includeSecrets: false }])
  t.is(result.status, 200)
  t.is(result.payload.running, true)
  t.is(result.payload.publicKey, 'b'.repeat(64))
  t.is(result.payload.uptimeMs, 5000)
  t.alike(result.payload.transports.holesail, { running: true })
  t.absent(JSON.stringify(result.payload).includes('do-not-leak'))
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown status route')
})

test('api status: build payload shapes public counters and omits raw secret fields', (t) => {
  const calls = []
  const longError = 'x'.repeat(MAX_STATUS_ERROR_BYTES + 32)
  const node = {
    config: { regions: ['EU'] },
    metrics: { startedAt: 9000 },
    getHealthStatus () {
      return { healthy: true, reason: 'ok', internal: 'drop-me' }
    },
    getStats (opts) {
      calls.push(opts)
      return {
        running: true,
        mode: 'relay-core',
        publicKey: 'A'.repeat(64),
        seededApps: 2.9,
        connections: 4,
        relay: {
          activeCircuits: 1,
          totalCircuitsServed: 2,
          totalBytesRelayed: 3,
          capacityUsedPct: 4.5,
          peersWithCircuits: 5,
          secretPeerMap: { a: true }
        },
        seeder: {
          coresSeeded: 6,
          totalBytesStored: 7,
          totalBytesServed: 8,
          capacityUsedPct: 9
        },
        storage: {
          totalBytes: 10,
          measuredEntries: 11,
          fullSweeps: 12,
          lastFullSweepAt: 13
        },
        served: {
          totalBytesServed: 14,
          totalBlocksServed: 15,
          trackedCores: 16
        },
        disk: {
          totalBytes: 17,
          usedBytes: 18,
          availableBytes: 19,
          usedPct: 20,
          status: 'warn',
          checkedAt: 21,
          mountPath: '/var/lib/hiverelay',
          error: longError
        },
        registry: {
          running: true,
          key: 'registry-secret'
        },
        replication: {
          trackedApps: 22,
          underReplicated: 23,
          lastCheckedAt: 24,
          repairEnabled: true
        },
        payment: {
          enabled: true,
          active: true,
          experimental: true,
          settlementIntervalMs: 25,
          payoutDestination: 'wallet-secret'
        },
        tor: {
          running: true,
          socksProxy: '127.0.0.1:9050',
          onionAddress: 'secret.onion',
          activeConnections: 26
        },
        holesail: {
          running: true,
          connectionKey: 'HOLESAIL_SECRET',
          apiPort: 9100
        },
        dhtRelayWs: {
          running: true,
          host: '0.0.0.0',
          port: 8766,
          activeConnections: 27,
          totalConnectionsServed: 28,
          totalRateLimited: 29,
          maxConnections: 30,
          rateLimit: {
            connectionsPerMinutePerIp: 31,
            maxConcurrentPerIp: 32
          }
        },
        reputation: {
          trackedRelays: 33,
          rawScores: { a: 1 }
        },
        appRegistry: {
          entries: 34,
          anchored: 35,
          unanchored: 36,
          cores: 37
        },
        distributedDrive: {
          enabled: true,
          running: false,
          moduleAvailable: true,
          registeredDrives: 38,
          peers: 39,
          lastError: longError,
          peerMap: { secret: true }
        },
        signedDirectory: {
          enabled: true,
          entries: 40,
          maxTotalEntries: 41,
          attachedChannels: 42,
          ttlSeconds: 43,
          totalPublished: 44,
          totalRejected: 45,
          totalReplicated: 46,
          totalEvicted: 47,
          rejectedReasons: { secret: 1 }
        },
        accessControl: { pairedDevices: 1 },
        subsidy: { payoutDestination: 'wallet-secret' },
        arbitrary: 'drop-me'
      }
    },
    serviceRegistry: {
      catalog () {
        return [
          { name: 'identity', version: '1.0.0', capabilities: ['sign'], description: 'ids', provider: { secret: true } },
          { name: 'bad\nname', version: '1.0.0', capabilities: ['drop'] }
        ]
      }
    }
  }

  const result = buildStatusPayload({ node, now: 12_000 })
  t.is(result.status, 200)
  t.alike(calls, [{ includeSecrets: false }])
  t.is(result.payload.publicKey, 'a'.repeat(64))
  t.is(result.payload.uptimeMs, 3000)
  t.is(result.payload.seededApps, 2, 'fractional counters are floored')
  t.alike(result.payload.transports.holesail, { running: true })
  t.alike(result.payload.transports.tor, { running: true, activeConnections: 26 })
  t.alike(result.payload.services, {
    count: 1,
    total: 2,
    truncated: true,
    services: [
      { name: 'identity', version: '1.0.0', capabilities: ['sign'], description: 'ids' }
    ]
  })
  t.is(result.payload.disk.error.length, MAX_STATUS_ERROR_BYTES, 'disk error is byte-capped')
  t.is(result.payload.distributedDrive.lastError.length, MAX_STATUS_ERROR_BYTES, 'bridge error is byte-capped')

  const json = JSON.stringify(result.payload)
  for (const secret of [
    'HOLESAIL_SECRET',
    'secret.onion',
    '/var/lib/hiverelay',
    'registry-secret',
    'wallet-secret',
    'socksProxy',
    'apiPort',
    'secretPeerMap',
    'rawScores',
    'rejectedReasons',
    'accessControl',
    'arbitrary'
  ]) {
    t.absent(json.includes(secret), secret + ' omitted from public status')
  }
})

test('api status: malformed public fields become stable null or zero values', (t) => {
  const result = buildStatusPayload({
    node: {
      config: { regions: ['bad\nregion'] },
      getHealthStatus () {
        return { healthy: 'yes', reason: 'bad\nreason' }
      },
      getStats () {
        return {
          running: 'true',
          mode: 'bad\nmode',
          publicKey: 'not-a-key',
          seededApps: -1,
          connections: { active: 1 },
          relay: { activeCircuits: -1, capacityUsedPct: Number.NaN },
          disk: { status: 'unknown', error: 'bad\nerror' },
          replication: { repairEnabled: 'yes' },
          payment: { settlementIntervalMs: -1 },
          tor: { running: 'yes', activeConnections: -1 },
          holesail: { running: 'yes' }
        }
      }
    },
    now: 1
  })

  t.is(result.payload.running, false)
  t.is(result.payload.mode, null)
  t.is(result.payload.publicKey, null)
  t.is(result.payload.region, null)
  t.is(result.payload.seededApps, 0)
  t.is(result.payload.connections, 0)
  t.alike(result.payload.health, { healthy: null, reason: null })
  t.alike(result.payload.relay, {
    activeCircuits: 0,
    totalCircuitsServed: 0,
    totalBytesRelayed: 0,
    capacityUsedPct: 0,
    peersWithCircuits: 0
  })
  t.alike(result.payload.disk, {
    totalBytes: 0,
    usedBytes: 0,
    availableBytes: 0,
    usedPct: 0,
    status: null,
    checkedAt: null,
    error: null
  })
  t.alike(result.payload.transports.tor, { running: false, activeConnections: 0 })
  t.alike(result.payload.transports.holesail, { running: false })
})

test('api status: statusString truncates by UTF-8 bytes and rejects controls', (t) => {
  t.is(statusString(' abc '), 'abc')
  t.is(statusString('a\nb'), null)
  t.is(statusString('üüü', { maxBytes: 5, truncate: true }), 'üü')
})

test('api status: capacity summary is planning-only and field allowlisted', (t) => {
  const summary = sanitizeCapacitySummary({
    schemaVersion: 1,
    mode: 'planning-only',
    profileId: 'services-s2',
    operatorDeclared: true,
    plan: {
      schemaVersion: 1,
      mode: 'planning-only',
      profileId: 'services-s2',
      observedUsableBytes: 1000,
      observedFreeBytes: 600,
      observedFreeAssumed: false,
      reservePolicy: { basisPoints: 1500, floorBytes: 32 },
      physicalReserveBytes: 150,
      postReserveBytes: 850,
      operatorCapBytes: 800,
      operatorCapApplied: true,
      managedCapacityBytes: 800,
      physicalHeadroomBytes: 450,
      poolBytes: { durable: 500, serviceControl: 0, repair: 100, cache: 100, burst: 100, leak: 1 },
      usage: {
        actualUsageBytes: 10,
        committedBytes: 20,
        pendingBytes: 30,
        untrackedDebtBytes: 0,
        futureDebtBytes: 50,
        conservativeDemandBytes: 60,
        leak: 1
      },
      logicalAvailableBytes: 740,
      availableBytes: 450,
      advertisableBytes: 440,
      overcommittedBytes: 0,
      atCapacity: false,
      advertisingBlocked: false,
      secret: 'drop-me'
    },
    measurements: {
      complete: true,
      fresh: true,
      maxAgeMs: 300000,
      diskCheckedAt: 100,
      storageMeasuredAt: 99,
      rawSample: 'drop-me'
    },
    enforcement: {
      logicalAdmissionActive: true,
      recoveryReady: true,
      acceptingMutations: true,
      fatal: false,
      committedBytes: 20,
      pendingBytes: 30,
      unknownCommitments: 0,
      physicalEnforcementActive: true,
      records: ['drop-me']
    },
    advertisement: {
      eligible: true,
      bytes: 440,
      blockReasons: [],
      signedDocument: 'drop-me'
    },
    secret: 'drop-me'
  })

  t.is(summary.profileId, 'services-s2')
  t.is(summary.plan.poolBytes.durable, 500)
  t.is(summary.plan.physicalHeadroomBytes, 450)
  t.ok(summary.measurements.complete)
  t.ok(summary.measurements.fresh)
  t.ok(summary.advertisement.eligible)
  t.is(summary.advertisement.bytes, 440)
  t.absent(JSON.stringify(summary).includes('drop-me'))
  t.is(sanitizeCapacitySummary({ mode: 'enforced' }), null, 'an enforcement claim is never accepted here')
})
