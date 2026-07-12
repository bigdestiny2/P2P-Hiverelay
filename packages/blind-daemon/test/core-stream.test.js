import test from 'brittle'
import b4a from 'b4a'
import { TRANSPORT_ID } from '@hiverelay/blind-protocol'
import { CoreReplicationStreamService } from '../core-stream.js'
import { StreamSessionPlane } from '../stream-session.js'
import {
  fixtureBytes,
  fixtureCoreOpen,
  fixtureCoreResult,
  fixtureReadiness
} from './stream-fixtures.js'

const noTimer = {
  schedule: () => ({}),
  cancelSchedule: () => {}
}

function createHarness (overrides = {}) {
  let now = 100n
  let nextStreamId = 40n
  let admissions = 0
  let upstreamOpens = 0
  const events = []
  const upstreamWrites = []
  const callerWrites = []
  const persistentRecords = []
  const relayPublicKey = fixtureBytes(32, 0x11)
  const wireProfileHash = fixtureBytes(32, 0x12)
  const parentSessionId = fixtureBytes(16, 0x13)
  const readiness = fixtureReadiness()
  const plane = new StreamSessionPlane({
    monotonicMillis: () => now,
    randomBytes: length => fixtureBytes(length, Number(nextStreamId & 0xffn)),
    ...noTimer,
    ...(overrides.plane || {})
  })
  const upstream = {
    async write (chunk) {
      upstreamWrites.push(b4a.from(chunk))
    },
    async end () { events.push('upstream-end') },
    async abort (reason) { events.push(`upstream-abort:${reason}`) }
  }
  const caller = {
    async write (chunk) {
      callerWrites.push(b4a.from(chunk))
    },
    async end () { events.push('caller-end') },
    async abort (reason) { events.push(`caller-abort:${reason}`) }
  }
  const service = new CoreReplicationStreamService({
    plane,
    relayPublicKey,
    wireProfileHash,
    authenticateParent: overrides.authenticateParent || (async ({ request }) => ({
      verified: true,
      authenticatedExporter: true,
      computedParentChannelBinding: b4a.from(request.parentChannelBinding),
      controlChannelId: request.controlChannelId,
      parentSessionId,
      readiness
    })),
    authorizeAdmission: overrides.authorizeAdmission || (async () => {
      admissions++
      return { accepted: true, spendTag: fixtureBytes(16, 0x21) }
    }),
    allocateStreamId: overrides.allocateStreamId || (async () => nextStreamId++),
    nowEpoch: async () => 100,
    buildResult: fields => fixtureCoreResult(relayPublicKey, fields),
    openUpstream: overrides.openUpstream || (async () => {
      upstreamOpens++
      events.push('upstream-open')
      return upstream
    }),
    persistence: {
      async reserve (record) { persistentRecords.push(record); events.push(`persist:${record.state}`) },
      async activate (record) { persistentRecords.push(record); events.push(`persist:${record.state}`) },
      async terminal (record) { persistentRecords.push(record); events.push(`persist:${record.state}:${record.terminalReason}`) },
      ...(overrides.persistence || {})
    }
  })
  return {
    plane,
    service,
    relayPublicKey,
    wireProfileHash,
    parentSessionId,
    readiness,
    upstream,
    caller,
    events,
    upstreamWrites,
    callerWrites,
    persistentRecords,
    admissions: () => admissions,
    upstreamOpens: () => upstreamOpens,
    setNow: value => { now = value }
  }
}

function context () {
  return { transportId: TRANSPORT_ID.DIRECT_PROTOMUX_NOISE }
}

function attachment (opened, harness) {
  return {
    streamId: opened.result.streamId,
    parentSessionId: harness.parentSessionId,
    descriptorSequence: harness.readiness.descriptorSequence,
    descriptorHash: harness.readiness.descriptorHash,
    caller: harness.caller
  }
}

test('CORE open persists before upstream allocation and hands opaque bytes through unchanged', async t => {
  const harness = createHarness()
  t.teardown(async () => {
    await harness.service.close()
    await harness.plane.close()
  })
  const request = fixtureCoreOpen(harness.wireProfileHash)
  const opened = await harness.service.open(request, context())
  t.alike(harness.events.slice(0, 3), ['persist:RESERVED', 'upstream-open', 'persist:LIVE'])
  t.is(opened.result.streamId, 40n)
  t.is(opened.result.maxSessionBytes, 16n * 1024n * 1024n)
  t.is(opened.ticket.byteLength, 32)
  t.is(harness.admissions(), 1)
  t.is(harness.upstreamOpens(), 1)
  t.alike(harness.persistentRecords[0].wireProfileHash, request.wireProfileHash)
  t.is(harness.persistentRecords[0].sessionClass, request.sessionClass)
  t.alike(harness.persistentRecords[0].clientNonce, request.clientNonce)
  t.is(harness.persistentRecords[0].openedAtEpoch, 100)

  const lostResultRetry = await harness.service.open(request, context())
  t.is(lostResultRetry.retried, true)
  t.alike(lostResultRetry.ticket, opened.ticket)
  t.is(harness.admissions(), 1)
  t.is(harness.upstreamOpens(), 1)

  const child = harness.service.attach(opened.ticket, attachment(opened, harness))
  t.exception(() => harness.service.attach(opened.ticket, attachment(opened, harness)), /already consumed/)
  const callerBytes = fixtureBytes(97, 0x61)
  const upstreamBytes = fixtureBytes(113, 0x62)
  await child.fromCaller(callerBytes)
  await child.fromUpstream(upstreamBytes)
  t.alike(harness.upstreamWrites, [callerBytes])
  t.alike(harness.callerWrites, [upstreamBytes])

  const attachedRetry = await harness.service.open(request, context())
  t.is(attachedRetry.attached, true)
  t.is(attachedRetry.ticket, null)
  await child.callerFin()
  t.is(child.scope.closed, false)
  await child.upstreamFin()
  t.is(child.scope.closed, true)
  t.ok(harness.events.includes('upstream-end'))
  t.ok(harness.events.includes('caller-end'))
  t.ok(harness.events.some(event => event.startsWith('persist:TERMINAL:clean-fin')))
  await t.exception(harness.service.open(request, context()), /no longer live/)
})

test('CORE verifies profile, native exporter and channel binding before admission or allocation', async t => {
  let authCalls = 0
  const harness = createHarness({
    authenticateParent: async ({ request }) => {
      authCalls++
      return {
        verified: true,
        authenticatedExporter: true,
        computedParentChannelBinding: fixtureBytes(32, 0x99),
        controlChannelId: request.controlChannelId,
        parentSessionId: fixtureBytes(16, 0x13),
        readiness: fixtureReadiness()
      }
    }
  })
  t.teardown(async () => {
    await harness.service.close()
    await harness.plane.close()
  })
  await t.exception(harness.service.open(fixtureCoreOpen(harness.wireProfileHash), context()), /binding does not match/)
  t.is(authCalls, 1)
  t.is(harness.admissions(), 0)
  t.is(harness.upstreamOpens(), 0)
  t.alike(harness.events, [])

  await t.exception(harness.service.open(fixtureCoreOpen(fixtureBytes(32, 0x98)), context()), /wire profile/)
  t.is(authCalls, 1)
  await t.exception(harness.service.open(fixtureCoreOpen(harness.wireProfileHash), {
    transportId: TRANSPORT_ID.HTTPS_DIRECT
  }), /native authenticated/)
  t.is(authCalls, 1)
})

test('CORE exact retry is same-parent only and spend/control replay stays terminal', async t => {
  const harness = createHarness()
  t.teardown(async () => {
    await harness.service.close()
    await harness.plane.close()
  })
  const request = fixtureCoreOpen(harness.wireProfileHash)
  await harness.service.open(request, context())
  const movedChannel = fixtureCoreOpen(harness.wireProfileHash, {
    controlChannelId: 18n,
    parentChannelBinding: fixtureBytes(32, 0x36),
    clientNonce: b4a.from(request.clientNonce)
  })
  await t.exception(harness.service.open(movedChannel, context()), /another authenticated channel/)
  t.is(harness.admissions(), 1)

  const changedLogical = fixtureCoreOpen(harness.wireProfileHash, {
    controlChannelId: 19n,
    parentChannelBinding: fixtureBytes(32, 0x37),
    clientNonce: fixtureBytes(32, 0x38)
  })
  await t.exception(harness.service.open(changedLogical, context()), /spend tag was already used/)
  t.is(harness.admissions(), 2)
  t.is(harness.upstreamOpens(), 1)

  const reusedControl = fixtureCoreOpen(harness.wireProfileHash, {
    controlChannelId: request.controlChannelId,
    parentChannelBinding: b4a.from(request.parentChannelBinding),
    clientNonce: fixtureBytes(32, 0x39)
  })
  await t.exception(harness.service.open(reusedControl, context()), /controlChannelId was already used/)
  t.is(harness.admissions(), 2)
})

test('CORE post-reservation upstream failure is terminal and never allocates a replacement', async t => {
  let opens = 0
  const harness = createHarness({
    openUpstream: async () => {
      opens++
      throw new Error('injected upstream unavailable')
    }
  })
  t.teardown(async () => {
    await harness.service.close()
    await harness.plane.close()
  })
  const request = fixtureCoreOpen(harness.wireProfileHash)
  await t.exception(harness.service.open(request, context()), /allocation failed terminally/)
  t.is(opens, 1)
  t.is(harness.events[0], 'persist:RESERVED')
  t.ok(harness.events.some(event => event.startsWith('persist:TERMINAL:core-open-failed')))
  await t.exception(harness.service.open(request, context()), /no longer live/)
  t.is(opens, 1)
})

test('CORE readiness expiry aborts both opaque ports and makes retries terminal', async t => {
  const harness = createHarness()
  t.teardown(async () => {
    await harness.service.close()
    await harness.plane.close()
  })
  const request = fixtureCoreOpen(harness.wireProfileHash)
  const opened = await harness.service.open(request, context())
  harness.service.attach(opened.ticket, attachment(opened, harness))
  await harness.plane.fence({
    descriptorSequence: harness.readiness.descriptorSequence,
    descriptorHash: harness.readiness.descriptorHash,
    reason: 'expired'
  })
  t.ok(harness.events.includes('upstream-abort:readiness-expired'))
  t.ok(harness.events.includes('caller-abort:readiness-expired'))
  t.is(harness.plane.activeStreams, 0)
  await t.exception(harness.service.open(request, context()), /no longer live/)
})
