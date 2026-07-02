import test from 'brittle'
import {
  DEVICE_NAME_MAX_LENGTH,
  MAX_DEVICE_LIST_ENTRIES,
  devicePersistFailureResult,
  normalizeDeviceName,
  resolveDevicePairingManagementRoute,
  runDeviceManagementAction,
  runDevicePairingManagementRouteAction,
  runPairingManagementAction,
  sanitizeDeviceList
} from '../../packages/core/core/relay-node/api-device-pairing.js'

test('api device pairing: route helper maps exact device and pairing mutation routes', (t) => {
  t.alike(resolveDevicePairingManagementRoute('POST', '/api/manage/devices'), {
    kind: 'device-management'
  })
  t.alike(resolveDevicePairingManagementRoute('POST', '/api/manage/pairing'), {
    kind: 'pairing-management'
  })

  t.is(resolveDevicePairingManagementRoute('GET', '/api/manage/devices'), null)
  t.is(resolveDevicePairingManagementRoute('POST', '/api/manage/device'), null)
  t.is(resolveDevicePairingManagementRoute('POST', '/api/manage/pairing/start'), null)
})

test('api device pairing: route action helper dispatches device and pairing mutations', async (t) => {
  const node = {
    mode: 'private',
    accessControl: {
      isPairing: true,
      _pairingState: { expiresAt: 123 }
    },
    listDevices: () => [{
      pubkey: 'A'.repeat(64),
      name: '  Operator phone  ',
      pairedAt: 1,
      lastSeen: 2,
      secretToken: 'do-not-leak'
    }]
  }

  let result = await runDevicePairingManagementRouteAction({
    route: resolveDevicePairingManagementRoute('POST', '/api/manage/devices'),
    body: { action: 'list' },
    node
  })
  t.is(result.ok, true)
  t.is(result.payload.count, 1)
  t.is(result.payload.devices[0].pubkey, 'a'.repeat(64))
  t.absent(result.payload.devices[0].secretToken)

  result = await runDevicePairingManagementRouteAction({
    route: resolveDevicePairingManagementRoute('POST', '/api/manage/pairing'),
    body: { action: 'status' },
    node
  })
  t.is(result.ok, true)
  t.alike(result.payload, { ok: true, active: true, expiresAt: 123 })

  const unknown = await runDevicePairingManagementRouteAction({
    route: { kind: 'unknown' },
    body: {},
    node
  })
  t.is(unknown.status, 404)
  t.alike(unknown.payload, { error: 'unknown device/pairing management route' })
})

test('api device pairing: rejects unavailable access-control modes', async (t) => {
  const node = { mode: 'public' }

  const devices = await runDeviceManagementAction({ body: { action: 'list' }, node })
  t.is(devices.status, 400)
  t.alike(devices.payload, {
    error: 'Access control is not active in current mode',
    mode: 'public'
  })

  const pairing = runPairingManagementAction({ body: { action: 'status' }, node })
  t.is(pairing.status, 400)
  t.alike(pairing.payload, {
    error: 'Pairing is not available in current mode',
    mode: 'public'
  })
})

test('api device pairing: normalizes device names and canonicalizes pubkeys', async (t) => {
  t.is(DEVICE_NAME_MAX_LENGTH, 80)
  t.alike(normalizeDeviceName('  Phone  '), { ok: true, value: 'Phone' })
  t.alike(normalizeDeviceName(''), { ok: true, value: 'manual' })
  t.alike(normalizeDeviceName({ label: 'Phone' }), { ok: false, error: 'name must be a string' })
  t.alike(normalizeDeviceName('bad\nname'), { ok: false, error: 'name must not contain control characters' })
  t.alike(normalizeDeviceName('x'.repeat(81)), {
    ok: false,
    error: 'name exceeds max length (80)'
  })

  const devices = new Map()
  const node = {
    mode: 'private',
    accessControl: {},
    listDevices: () => Array.from(devices.values()),
    async addDevice (pubkey, name) {
      devices.set(pubkey, { pubkey, name, pairedAt: 1, lastSeen: null })
    },
    async removeDevice (pubkey) {
      if (!devices.has(pubkey)) throw new Error('Device not in allowlist')
      devices.delete(pubkey)
    }
  }

  const added = await runDeviceManagementAction({
    body: { action: 'add', pubkey: 'A'.repeat(64), name: '  Operator phone  ' },
    node
  })
  t.is(added.ok, true)
  t.is(added.payload.pubkey, 'a'.repeat(64))
  t.is(added.payload.name, 'Operator phone')
  t.is(devices.get('a'.repeat(64)).name, 'Operator phone')

  const listed = await runDeviceManagementAction({ body: { action: 'list' }, node })
  t.is(listed.payload.count, 1)
  t.is(listed.payload.total, 1)
  t.absent(listed.payload.truncated)
  t.is(listed.payload.devices[0].pubkey, 'a'.repeat(64))

  const removed = await runDeviceManagementAction({
    body: { action: 'remove', pubkey: 'A'.repeat(64) },
    node
  })
  t.is(removed.ok, true)
  t.is(removed.payload.pubkey, 'a'.repeat(64))
  t.is(devices.size, 0)
})

test('api device pairing: list action sanitizes persisted device rows', async (t) => {
  const devices = [
    {
      pubkey: 'A'.repeat(64),
      name: '  Operator phone  ',
      pairedAt: 1,
      lastSeen: 2,
      token: 'do-not-leak'
    },
    {
      pubkey: 'B'.repeat(64),
      name: 'bad\nname',
      pairedAt: -1,
      lastSeen: Infinity,
      privateKey: 'hidden'
    },
    {
      pubkey: 'not-a-key',
      name: 'ignored'
    }
  ]
  for (let i = 0; i < MAX_DEVICE_LIST_ENTRIES + 4; i++) {
    devices.push({
      pubkey: (i % 16).toString(16).repeat(64),
      name: 'device-' + i,
      pairedAt: i,
      lastSeen: i + 1
    })
  }
  const node = {
    mode: 'private',
    accessControl: {},
    listDevices: () => devices
  }

  const clean = sanitizeDeviceList(devices)
  t.is(clean.length, MAX_DEVICE_LIST_ENTRIES)
  t.alike(clean[0], {
    pubkey: 'a'.repeat(64),
    name: 'Operator phone',
    pairedAt: 1,
    lastSeen: 2
  })
  t.alike(clean[1], {
    pubkey: 'b'.repeat(64),
    name: 'manual',
    pairedAt: null,
    lastSeen: null
  })
  t.absent(JSON.stringify(clean).includes('do-not-leak'))
  t.absent(JSON.stringify(clean).includes('privateKey'))

  const listed = await runDeviceManagementAction({ body: { action: 'list' }, node })
  t.is(listed.payload.count, MAX_DEVICE_LIST_ENTRIES)
  t.is(listed.payload.total, MAX_DEVICE_LIST_ENTRIES + 7)
  t.ok(listed.payload.truncated)
  t.absent(JSON.stringify(listed.payload).includes('do-not-leak'))
})

test('api device pairing: separates validation, operator, and persistence errors', async (t) => {
  const node = {
    mode: 'private',
    accessControl: {},
    listDevices: () => [],
    async addDevice () {},
    async removeDevice () {}
  }

  const malformed = await runDeviceManagementAction({
    body: { action: 'add', pubkey: 'xyz' },
    node
  })
  t.is(malformed.status, 400)
  t.alike(malformed.payload, { error: 'pubkey must be 64 hex characters' })

  node.addDevice = async () => { throw new Error('Maximum devices reached (50)') }
  const maxDevices = await runDeviceManagementAction({
    body: { action: 'add', pubkey: 'a'.repeat(64), name: 'phone' },
    node
  })
  t.is(maxDevices.status, 400)
  t.alike(maxDevices.payload, { error: 'Maximum devices reached (50)' })

  node.removeDevice = async () => { throw new Error('Device not in allowlist') }
  const missing = await runDeviceManagementAction({
    body: { action: 'remove', pubkey: 'b'.repeat(64) },
    node
  })
  t.is(missing.status, 400)
  t.alike(missing.payload, { error: 'Device not in allowlist' })

  const diskError = new Error('disk full')
  node.addDevice = async () => { throw diskError }
  const events = []
  const persist = await runDeviceManagementAction({
    body: { action: 'add', pubkey: 'c'.repeat(64), name: 'phone' },
    node,
    emit: (event, payload) => events.push({ event, payload })
  })
  t.is(persist.ok, false)
  t.is(persist.kind, 'device-persist')
  t.is(persist.status, 500)
  t.is(persist.payload.errorCode, 'persist-failed')
  t.ok(persist.payload.error.startsWith('persist-failed: '), 'public payload is stable and prefixed')
  t.absent(persist.payload.error.includes('disk full'), 'public payload does not leak local storage error')
  t.is(events.length, 1)
  t.is(events[0].event, 'device-persist-error')
  t.is(events[0].payload.message, 'disk full')
  t.is(events[0].payload.error, diskError)
})

test('api device pairing: device persist failure mapper emits internal diagnostics', (t) => {
  const err = new Error('readonly allowlist')
  const events = []
  const out = devicePersistFailureResult({
    error: err,
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'device-persist')
  t.is(out.status, 500)
  t.is(out.payload.errorCode, 'persist-failed')
  t.ok(out.payload.error.startsWith('persist-failed: '))
  t.absent(out.payload.error.includes('readonly allowlist'))
  t.alike(events, [{
    event: 'device-persist-error',
    payload: {
      message: 'readonly allowlist',
      error: err
    }
  }])
})

test('api device pairing: validates pairing actions before state changes', async (t) => {
  let enabled = 0
  let disabled = 0
  const node = {
    mode: 'private',
    accessControl: {
      isPairing: false,
      _pairingState: null,
      disablePairing () {
        disabled++
      }
    },
    enablePairing (opts = {}) {
      enabled++
      this.accessControl.isPairing = true
      this.accessControl._pairingState = { expiresAt: 12345 }
      return { token: 'a'.repeat(32), expiresAt: 12345, timeoutMs: opts.timeoutMs }
    }
  }

  const malformed = runPairingManagementAction({
    body: { action: 'start', timeoutMs: '1e3' },
    node
  })
  t.is(malformed.status, 400)
  t.alike(malformed.payload, { error: 'timeoutMs must be a valid integer' })
  t.is(enabled, 0)

  const outOfRange = runPairingManagementAction({
    body: { action: 'start', timeoutMs: 0 },
    node
  })
  t.is(outOfRange.status, 400)
  t.alike(outOfRange.payload, { error: 'timeoutMs must be between 10000 and 1800000' })
  t.is(enabled, 0)

  const started = runPairingManagementAction({
    body: { action: 'start', timeoutMs: '10000' },
    node
  })
  t.is(started.ok, true)
  t.is(started.payload.timeoutMs, 10000)
  t.is(started.payload.active, true)
  t.is(enabled, 1)

  const status = runPairingManagementAction({ body: { action: 'status' }, node })
  t.is(status.payload.active, true)
  t.is(status.payload.expiresAt, 12345)

  const stopped = runPairingManagementAction({ body: { action: 'stop' }, node })
  t.is(stopped.payload.active, false)
  t.is(disabled, 1)
})
