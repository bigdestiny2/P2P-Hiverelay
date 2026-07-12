import test from 'brittle'
import b4a from 'b4a'
import { FAMILY } from '@hiverelay/blind-protocol'
import {
  OneUseStreamTickets,
  StreamSessionPlane,
  streamTicketBinding
} from '../stream-session.js'

const bytes = (length, value) => b4a.alloc(length, value)
const noTimer = {
  schedule: () => ({}),
  cancelSchedule: () => {}
}

function readiness (overrides = {}) {
  return {
    descriptorSequence: 7n,
    descriptorHash: bytes(32, 0x31),
    expiresMonotonicMillis: 10_000n,
    ...overrides
  }
}

function session (plane, overrides = {}) {
  return plane.createSession({
    family: FAMILY.CORE,
    streamId: 1n,
    maxBytes: 1024n,
    maxBufferedBytes: 128,
    idleMillis: 1000,
    lifetimeMillis: 5000,
    readiness: readiness(),
    ...overrides
  })
}

test('private stream tickets are one-use, parent/descriptor bound and wrong use burns them', async t => {
  let now = 100n
  let random = 1
  const plane = new StreamSessionPlane({
    monotonicMillis: () => now,
    randomBytes: length => bytes(length, random++),
    ticketTtlMillis: 2000,
    ...noTimer
  })
  t.teardown(() => plane.close())
  const scope = session(plane)
  const parent = bytes(16, 0x41)
  const expected = {
    family: FAMILY.CORE,
    streamId: 1n,
    descriptorSequence: 7n,
    descriptorHash: bytes(32, 0x31),
    parentSessionId: parent
  }
  const first = plane.issueTicket(scope, parent)
  t.is(first.byteLength, 32)
  t.is(plane.tickets.size, 1)
  t.exception(() => plane.consumeTicket(first, {
    ...expected,
    parentSessionId: bytes(16, 0x42)
  }), /binding does not match/)
  t.is(plane.tickets.size, 0)
  t.exception(() => plane.consumeTicket(first, expected), /unknown or already consumed/)

  const second = plane.issueTicket(scope, parent)
  t.is(plane.consumeTicket(second, expected), scope)
  t.exception(() => plane.consumeTicket(second, expected), /unknown or already consumed/)

  const third = plane.issueTicket(scope, parent)
  now += 2000n
  t.exception(() => plane.consumeTicket(third, expected), /expired/)

  const binding = streamTicketBinding(expected)
  t.is(binding.byteLength, 32)
  t.exception(() => streamTicketBinding({ ...expected, streamId: 0n }), /nonzero/)
})

test('ticket capacity is bounded and scope close revokes every unconsumed token', async t => {
  const tickets = new OneUseStreamTickets({
    monotonicMillis: () => 10n,
    randomBytes: length => bytes(length, 0x51),
    maxTickets: 1
  })
  const binding = bytes(32, 0x52)
  tickets.issue({ binding, scopeId: 'a', payload: 1, expiresMonotonicMillis: 100n })
  t.exception(() => tickets.issue({ binding, scopeId: 'b', payload: 2, expiresMonotonicMillis: 100n }), /capacity/)
  tickets.revokeScope('a')
  t.is(tickets.size, 0)

  const plane = new StreamSessionPlane({ monotonicMillis: () => 10n, ...noTimer })
  t.teardown(() => plane.close())
  const scope = session(plane)
  plane.issueTicket(scope, bytes(8, 0x53))
  plane.issueTicket(scope, bytes(8, 0x53))
  t.is(plane.tickets.size, 2)
  await scope.close('test-close')
  t.is(plane.tickets.size, 0)
})

test('stream plane enforces stream, aggregate-byte and memory caps without leaks', async t => {
  let closes = 0
  const plane = new StreamSessionPlane({
    monotonicMillis: () => 100n,
    maxStreams: 2,
    maxBufferedBytes: 150,
    maxPerStreamBufferedBytes: 100,
    ...noTimer
  })
  t.teardown(() => plane.close())
  const first = session(plane, { maxBufferedBytes: 100, onClose: () => { closes++ } })
  const second = session(plane, {
    family: FAMILY.FORWARD,
    streamId: 2n,
    maxBufferedBytes: 100,
    onClose: () => { closes++ }
  })
  t.is(plane.activeStreams, 2)
  t.exception(() => session(plane, { streamId: 3n }), /capacity/)

  first.countBytes(1024)
  t.is(first.totalBytes, 1024n)
  t.exception(() => first.countBytes(1), /byte cap/)
  await first.close()
  t.is(closes, 1)
  t.is(plane.activeStreams, 1)

  const release = second.reserveBuffer(100)
  t.is(plane.bufferedBytes, 100)
  t.exception(() => second.reserveBuffer(1), /buffer cap/)
  await second.close()
  release()
  t.is(plane.bufferedBytes, 0)
  t.is(closes, 2)
})

test('idle, lifetime, readiness expiry and injected descriptor fences tear down once', async t => {
  let now = 100n
  let fence
  let unsubscribed = 0
  const reasons = []
  let ready = true
  const plane = new StreamSessionPlane({
    monotonicMillis: () => now,
    isReady: () => ready,
    subscribeReadinessFence: callback => {
      fence = callback
      return () => { unsubscribed++ }
    },
    ...noTimer
  })
  t.teardown(() => plane.close())

  const idle = session(plane, { streamId: 1n, idleMillis: 50, onClose: reason => reasons.push(reason) })
  now = 150n
  t.is(idle.poll(), false)
  await idle.close()
  t.alike(reasons, ['idle-expired'])

  now = 200n
  const lifetime = session(plane, {
    streamId: 2n,
    idleMillis: 1000,
    lifetimeMillis: 100,
    onClose: reason => reasons.push(reason)
  })
  now = 300n
  t.is(lifetime.poll(), false)
  await lifetime.close()
  t.alike(reasons, ['idle-expired', 'lifetime-expired'])

  now = 400n
  const unhealthy = session(plane, { streamId: 3n, onClose: reason => reasons.push(reason) })
  ready = false
  t.is(unhealthy.poll(), false)
  await unhealthy.close()
  t.alike(reasons, ['idle-expired', 'lifetime-expired', 'readiness-expired'])

  ready = true
  const fenced = session(plane, {
    streamId: 4n,
    readiness: readiness({ descriptorSequence: 9n, descriptorHash: bytes(32, 0x61) }),
    onClose: reason => reasons.push(reason)
  })
  await fence({ descriptorSequence: 9n, descriptorHash: bytes(32, 0x61), reason: 'descriptor-expired' })
  t.is(fenced.closed, true)
  t.is(reasons.at(-1), 'readiness-descriptor-expired')
  await plane.close()
  t.is(unsubscribed, 1)
})
