import test from 'brittle'
import { ServiceProtocol } from 'p2p-hiverelay/core/services/protocol.js'

function registry () {
  return {
    catalog () { return [{ name: 'storage', version: '1.0.0' }] },
    addRemoteServices () {},
    handleRequest: async () => ({ ok: true })
  }
}

function addChannel (proto, remotePubkey, sent, lifecycle = {}) {
  const channel = {
    cork () { lifecycle.corked = (lifecycle.corked || 0) + 1 },
    uncork () { lifecycle.uncorked = (lifecycle.uncorked || 0) + 1 },
    close () { lifecycle.closed = (lifecycle.closed || 0) + 1 }
  }
  proto.channels.set(remotePubkey, {
    channel,
    msgHandler: { send: (message) => sent.push(message) }
  })
  return channel
}

test('ServiceProtocol app catalog: open schedules once without eager full or delta materialization', (t) => {
  const sent = []
  let schedules = 0
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog ({ remotePubkey, send }) {
      schedules++
      t.is(remotePubkey, 'peer')
      t.is(typeof send, 'function')
    }
  })
  proto._getCatalogEnvelope = () => t.fail('must not build an eager catalog envelope')
  proto._getSeededApps = () => t.fail('must not materialize the app population')
  const channel = addChannel(proto, 'peer', sent)

  proto._onOpen('peer', channel)
  proto._onOpen('peer', channel)

  t.is(schedules, 1, 'one hook invocation for this channel ownership')
  t.is(sent.length, 2, 'only the independently bounded service catalog is sent')
  t.ok(sent.every(message => message.type === 0))
  t.is(proto.broadcastAppCatalog(), false, 'registry churn has no legacy sender path')
  t.is(sent.length, 2, 'no full or delta app catalog was sent')
})

test('ServiceProtocol app catalog: hook send passes through controller envelope and result', (t) => {
  const sent = []
  const lifecycle = {}
  let sendLegacy = null
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog ({ send }) { sendLegacy = send }
  })
  const channel = addChannel(proto, 'peer', sent, lifecycle)
  proto._onOpen('peer', channel)

  const envelope = Object.freeze({
    type: 7,
    apps: Object.freeze([]),
    relayPubkey: 'a'.repeat(64),
    catalogTimestamp: 123456,
    signature: 'b'.repeat(128)
  })
  const prepared = Object.freeze({ envelope, reason: 'CATALOG_LEGACY_OVERBOUND' })

  t.is(sendLegacy(prepared), prepared, 'diagnostic result is returned untouched to the controller')
  t.is(sendLegacy(prepared), false, 'the terminal fallback cannot be sent twice')
  t.is(sent.length, 2)
  t.is(sent[1], envelope, 'the exact signed envelope object is sent without rebuilding')
  t.is(lifecycle.corked, 2, 'service and app catalog sends are independently corked')
  t.is(lifecycle.uncorked, 2)
})

test('ServiceProtocol app catalog: a failed terminal send cannot be retried', (t) => {
  let sendLegacy = null
  let sends = 0
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog ({ send }) { sendLegacy = send }
  })
  proto.channels.set('peer', {
    channel: { cork () {}, uncork () {} },
    msgHandler: {
      send (message) {
        if (message.type === 7) {
          sends++
          throw new Error('injected send failure')
        }
      }
    }
  })
  proto._onOpen('peer', proto.channels.get('peer').channel)
  const prepared = {
    envelope: { type: 7, apps: [], relayPubkey: 'a'.repeat(64), catalogTimestamp: 1, signature: 'b'.repeat(128) },
    reason: null
  }

  t.exception(() => sendLegacy(prepared), /injected send failure/)
  t.is(sendLegacy(prepared), false, 'a send error still consumes the terminal attempt')
  t.is(sends, 1)
})

test('ServiceProtocol app catalog: no public sender bypasses the scheduled channel token', (t) => {
  const proto = new ServiceProtocol(registry())
  addChannel(proto, 'peer', [])

  t.is(typeof proto.sendAppCatalog, 'undefined')
  t.is(proto._sendScheduledAppCatalog({}, { type: 7, apps: [] }), false)
})

test('ServiceProtocol app catalog: scheduled sender enforces exact signed 128-entry and 65536-byte bounds', (t) => {
  const attempts = []
  const make = (apps, overrides = {}) => ({
    envelope: {
      type: 7,
      apps,
      relayPubkey: 'a'.repeat(64),
      catalogTimestamp: 1,
      signature: 'b'.repeat(128),
      ...overrides
    },
    reason: null
  })
  const schedule = () => {
    const proto = new ServiceProtocol(registry(), {
      scheduleLegacyAppCatalog ({ send }) { attempts.push(send) }
    })
    const channel = addChannel(proto, `peer-${attempts.length}`, [])
    proto._onOpen(`peer-${attempts.length}`, channel)
    return attempts.at(-1)
  }

  t.exception(() => schedule()(make(new Array(129).fill({}))), /LEGACY_APP_CATALOG_ENVELOPE_REQUIRED/)
  t.exception(() => schedule()(make([{ value: 'x'.repeat(89_000) }])), /LEGACY_APP_CATALOG_ENVELOPE_REQUIRED/)
  const unsigned = make([])
  delete unsigned.envelope.signature
  t.exception(() => schedule()(unsigned), /LEGACY_APP_CATALOG_ENVELOPE_REQUIRED/)
  t.exception(() => schedule()(make([], { signature: null })), /LEGACY_APP_CATALOG_ENVELOPE_REQUIRED/)
})

test('ServiceProtocol app catalog: channel close cancels once and fences a late fallback', (t) => {
  const sent = []
  let sendLegacy = null
  let cancellations = 0
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog ({ send }) {
      sendLegacy = send
      return () => { cancellations++ }
    }
  })
  const channel = addChannel(proto, 'peer', sent)
  proto._onOpen('peer', channel)

  proto._onClose('peer')
  proto._onClose('peer')
  proto.destroy()

  t.is(cancellations, 1, 'cancel hook is idempotent across close and destroy')
  t.is(sendLegacy({ type: 7, apps: [] }), false, 'a late controller timer cannot send after close')
  t.is(sent.length, 1, 'only the service catalog was sent before close')
})

test('ServiceProtocol app catalog: stale same-peer close cannot revoke replacement ownership', (t) => {
  const firstSent = []
  const secondSent = []
  const sends = []
  let schedules = 0
  let cancellations = 0
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog ({ send }) {
      schedules++
      sends.push(send)
      return () => { cancellations++ }
    }
  })
  const first = addChannel(proto, 'peer', firstSent)
  proto._onOpen('peer', first)

  const second = addChannel(proto, 'peer', secondSent)
  proto._onOpen('peer', second)
  t.is(schedules, 2, 'replacement cancels the old token and owns a fresh fallback')
  t.is(cancellations, 1, 'replacement immediately cancels the old controller timer')

  t.is(proto._onClose('peer', first), false, 'stale close is ignored')
  t.is(proto.channels.get('peer').channel, second, 'replacement remains the exact owner')
  t.is(cancellations, 1, 'stale close does not cancel the replacement fallback')

  const prepared = {
    envelope: { type: 7, apps: [], relayPubkey: 'a'.repeat(64), catalogTimestamp: 1, signature: 'b'.repeat(128) },
    reason: null
  }
  t.is(sends[0](prepared), false, 'stale callback is bound to the old exact channel token')
  t.is(sends[1](prepared), prepared)
  t.is(sends[1](prepared), false, 'replacement still has one terminal send total')
  t.is(firstSent.filter(message => message.type === 7).length, 0)
  t.is(secondSent.filter(message => message.type === 7).length, 1)

  t.is(proto._onClose('peer', second), true, 'current owner closes normally')
  t.is(cancellations, 2, 'current close cancels its replacement timer once')
  t.absent(proto.channels.has('peer'))
  t.is(proto._onClose('peer', second), false)
  t.is(cancellations, 2, 'duplicate current close remains idempotent')
})

test('ServiceProtocol app catalog: destroy cancels a still-open scheduled fallback once', (t) => {
  const sent = []
  const lifecycle = {}
  let cancellations = 0
  const proto = new ServiceProtocol(registry(), {
    scheduleLegacyAppCatalog () {
      return { cancel () { cancellations++ } }
    }
  })
  const channel = addChannel(proto, 'peer', sent, lifecycle)
  proto._onOpen('peer', channel)

  proto.destroy()
  proto.destroy()

  t.is(cancellations, 1)
  t.is(lifecycle.closed, 1)
})

test('ServiceProtocol app catalog: legacy type-8 remains receive-only compatible', async (t) => {
  const sent = []
  const deltas = []
  const additions = []
  const proto = new ServiceProtocol(registry())
  proto.on('app-catalog-delta', (event) => deltas.push(event))
  proto.on('app-catalog', (event) => additions.push(event))
  addChannel(proto, 'peer', sent)

  await proto._onMessage('peer', {
    type: 8,
    apps: [{ appKey: 'c'.repeat(64), version: '1.0.0' }],
    removed: ['d'.repeat(64)],
    relayPubkey: 'a'.repeat(64),
    catalogTimestamp: 123,
    signature: 'b'.repeat(128)
  })
  proto.broadcastAppCatalog()

  t.is(deltas.length, 1)
  t.alike(deltas[0].removed, ['d'.repeat(64)])
  t.is(additions.length, 1)
  t.is(additions[0].delta, true)
  t.ok(sent.every(message => message.type !== 8), 'ServiceProtocol never emits a type-8 delta')
})
