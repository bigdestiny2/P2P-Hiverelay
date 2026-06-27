import test from 'brittle'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import {
  buildLeaseStatusPayload,
  parseLeaseRateUpdate,
  runLeaseConfigAction
} from 'p2p-hiverelay/core/relay-node/api-lease.js'
import { LeaseManager } from 'p2p-hiverelay/incentive/lease/index.js'
import { MockProvider } from 'p2p-hiverelay/incentive/payment/mock-provider.js'

const NOW = Date.UTC(2026, 5, 26, 12, 0, 0)

function makeKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

test('api lease: status payload shapes summary and counts active paid leases', (t) => {
  const appRegistry = {
    apps: new Map([
      ['active', { leaseManaged: true, retainUntil: NOW + 1000 }],
      ['expired', { leaseManaged: true, retainUntil: NOW - 1000 }],
      ['free', { leaseManaged: false, retainUntil: NOW + 1000 }],
      ['malformed', { leaseManaged: true, retainUntil: Infinity }]
    ])
  }

  const result = buildLeaseStatusPayload({
    appRegistry,
    now: NOW,
    leaseManager: {
      getSummary () {
        return {
          enabled: false,
          satsPerGiBDay: 12.9,
          minDays: 1.2,
          maxDays: 30.8,
          payTo: 'operator@example.com',
          totalLeasedSats: -1,
          leaseCount: 2.7,
          provider: 'MockProvider',
          providerConnected: true,
          unexpectedSecret: 'do-not-leak'
        }
      }
    }
  })

  t.is(result.status, 200)
  t.alike(result.payload, {
    enabled: true,
    satsPerGiBDay: 12,
    minDays: 1,
    maxDays: 30,
    payTo: 'operator@example.com',
    totalLeasedSats: 0,
    leaseCount: 2,
    provider: 'MockProvider',
    providerConnected: true,
    activeLeases: 1
  })
})

test('api lease: disabled and malformed runtime states stay stable', (t) => {
  t.alike(buildLeaseStatusPayload().payload, { enabled: false })

  const result = buildLeaseStatusPayload({
    appRegistry: { apps: null },
    leaseManager: {
      getSummary () {
        return {
          satsPerGiBDay: Infinity,
          minDays: -1,
          maxDays: NaN,
          payTo: { value: 'object' },
          totalLeasedSats: '100',
          leaseCount: -2,
          provider: 'bad\u001bprovider',
          providerConnected: 'yes'
        }
      }
    }
  })

  t.alike(result.payload, {
    enabled: true,
    satsPerGiBDay: 0,
    minDays: 0,
    maxDays: 0,
    payTo: null,
    totalLeasedSats: 0,
    leaseCount: 0,
    provider: null,
    providerConnected: false,
    activeLeases: 0
  })
})

test('api lease: rate parser requires a finite non-negative number', (t) => {
  t.alike(parseLeaseRateUpdate({}), {
    ok: false,
    kind: 'bad-request',
    message: 'satsPerGiBDay (number) required'
  })
  t.alike(parseLeaseRateUpdate({ satsPerGiBDay: '10' }), {
    ok: false,
    kind: 'bad-request',
    message: 'satsPerGiBDay (number) required'
  })
  t.alike(parseLeaseRateUpdate({ satsPerGiBDay: -1 }), {
    ok: false,
    kind: 'bad-request',
    message: 'satsPerGiBDay must be a non-negative number'
  })
  t.alike(parseLeaseRateUpdate({ satsPerGiBDay: 42.8 }), {
    ok: true,
    satsPerGiBDay: 42.8
  })
})

test('api lease: config update uses durable setter before returning success', async (t) => {
  const calls = []
  const result = await runLeaseConfigAction({
    body: { satsPerGiBDay: 25.9 },
    leaseManager: {
      async setRateDurable (rate) {
        calls.push(rate)
        return Math.floor(rate)
      },
      setRate () {
        throw new Error('setRate fallback should not run')
      }
    }
  })

  t.is(result.status, 200)
  t.alike(calls, [25.9])
  t.alike(result.payload, { ok: true, satsPerGiBDay: 25 })
})

test('api lease: config update reports persistence failure without pretending success', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-lease-api-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })

  const lm = new LeaseManager({
    keyPair: makeKeyPair(),
    provider: new MockProvider(),
    storagePath: repo,
    satsPerGiBDay: 10
  })
  await lm.start()
  const events = []
  lm.on('persist-error', err => events.push(err && err.code))

  const result = await runLeaseConfigAction({
    body: { satsPerGiBDay: 50 },
    leaseManager: lm
  })

  t.is(result.status, 503)
  t.ok(result.payload.error.startsWith('persist-failed: '))
  t.is(lm.satsPerGiBDay, 10, 'rate rolled back after failed persistence')
  t.ok(events.length >= 1, 'persistence failure was observable')

  lm.storagePath = null
  await lm.destroy()
})

test('api lease: config update keeps disabled and validation failures stable', async (t) => {
  const disabled = await runLeaseConfigAction({
    body: { satsPerGiBDay: 1 },
    leaseManager: null
  })
  t.is(disabled.status, 409)
  t.ok(disabled.payload.error.startsWith('not-enabled: '))

  const malformed = await runLeaseConfigAction({
    body: { satsPerGiBDay: Infinity },
    leaseManager: {
      async setRateDurable () {
        throw new Error('should not be called')
      }
    }
  })
  t.is(malformed.status, 400)
  t.ok(malformed.payload.error.startsWith('bad-request: '))

  const rejected = await runLeaseConfigAction({
    body: { satsPerGiBDay: 2_000_000 },
    leaseManager: {
      async setRateDurable () {
        throw new Error('satsPerGiBDay exceeds maximum (1000000)')
      }
    }
  })
  t.is(rejected.status, 400)
  t.ok(rejected.payload.error.includes('exceeds maximum'))

  const internal = await runLeaseConfigAction({
    body: { satsPerGiBDay: 2 },
    leaseManager: {
      async setRateDurable () {
        throw new Error('/data/hiverelay/lease.json: permission denied')
      }
    }
  })
  t.is(internal.status, 400)
  t.is(internal.payload.error, 'bad-request: invalid lease config')
})
