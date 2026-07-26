/**
 * Prove NotifyService.status() exposes the operator-dashboard shape:
 * deliveryAttempts/successes/failures + egress, and that the flat fields
 * match the nested counts/limits the manage route returns.
 *
 * Also asserts the dashboard HTML fetches /api/manage/notify (not the
 * signature-gated public status / empty capabilities fallback).
 */
import test from 'brittle'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import {
  NotifyService,
  createMemoryPushProvider
} from '../../packages/services/builtin/notify-service.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const DASHBOARD = join(HERE, '../../dashboard/index.html')

test('NotifyService.status() exposes delivery aggregates + egress for the manage panel', async (t) => {
  const service = new NotifyService({
    provider: createMemoryPushProvider(),
    persistence: false
  })
  await service.start({ config: {} })
  t.teardown(async () => { await service.stop() })

  // Inject a few delivery events with known statuses (bypass send path).
  const now = Date.now()
  service._recordDeliveryEvent({
    intent: { intentId: 'a'.repeat(64), app: 'b'.repeat(64), receiver: 'c'.repeat(64) },
    status: 'accepted_by_provider',
    reason: 'accepted_by_provider',
    providerStatus: 'memory-accepted',
    binding: { provider: 'runtime' },
    billable: true,
    attempts: 1,
    payloadBytes: 0,
    now
  })
  service._recordDeliveryEvent({
    intent: { intentId: 'd'.repeat(64), app: 'b'.repeat(64), receiver: 'c'.repeat(64) },
    status: 'rejected_by_relay',
    reason: 'cap_missing',
    providerStatus: null,
    binding: null,
    billable: false,
    attempts: 0,
    payloadBytes: 0,
    now: now + 1
  })
  service._recordDeliveryEvent({
    intent: { intentId: 'e'.repeat(64), app: 'b'.repeat(64), receiver: 'c'.repeat(64) },
    status: 'accepted_by_provider',
    reason: 'accepted_by_provider',
    providerStatus: 'memory-accepted',
    binding: { provider: 'runtime' },
    billable: true,
    attempts: 1,
    payloadBytes: 0,
    now: now + 2
  })

  const status = await service.status({})
  t.is(status.ok, true)
  t.is(status.ready, true)
  t.is(status.service, 'notify')
  t.is(status.deliveryAttempts, 3)
  t.is(status.deliverySuccesses, 2)
  t.is(status.deliveryFailures, 1)
  t.is(status.counts.deliveryEvents, 3)
  t.is(status.counts.deliverySuccesses, 2)
  t.is(status.counts.deliveryFailures, 1)
  // Memory provider is live:false by design
  t.ok(status.egress)
  t.is(status.egress.kind, 'memory')
  t.is(status.egress.live, false)
  t.alike(status.limits.egress, status.egress)
})

test('dashboard notify panel fetches /api/manage/notify and maps real status fields', (t) => {
  const html = readFileSync(DASHBOARD, 'utf8')

  // Must use the management status route (API-key / UI-token shim).
  t.ok(html.includes("fetchWithTimeout('/api/manage/notify')"), 'fetches manage notify')
  t.ok(html.includes('id="notifyPanel"'), 'notify panel element present')

  // Must NOT rely on the signature-gated public status or capabilities fallback
  // for delivery stats (those cannot populate attempts/successes/failures).
  const fetchFn = html.slice(html.indexOf('async function fetchNotifyPanel'))
  const end = fetchFn.indexOf('async function fetchVrfPanel')
  const body = end > 0 ? fetchFn.slice(0, end) : fetchFn
  t.absent(body.includes("/api/v1/notify/status"), 'does not GET public status')
  t.absent(body.includes("/api/v1/notify/capabilities"), 'does not fall back to capabilities')

  // applyNotifyPanel maps counts.deliveryEvents / limits.egress / flat fields.
  t.ok(html.includes('counts.deliveryEvents') || html.includes('status.deliveryAttempts') || html.includes('deliveryAttempts'),
    'maps deliveryAttempts or counts.deliveryEvents')
  t.ok(html.includes('limits.egress') || html.includes('status.egress'),
    'maps limits.egress / status.egress')
  t.ok(html.includes('function applyNotifyPanel'), 'applyNotifyPanel present')
})
