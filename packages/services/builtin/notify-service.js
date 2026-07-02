import b4a from 'b4a'
import sodium from 'sodium-universal'
import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'

export const NOTIFY_SERVICE_VERSION = '0.1.0'
export const NOTIFY_FEATURE = 'notify-v1'

export const NOTIFY_DOMAINS = Object.freeze({
  providerBinding: 'hiverelay.notify.v1.provider-binding',
  deviceRegistration: 'hiverelay.notify.v1.device-registration',
  receiveCap: 'hiverelay.notify.v1.receive-cap',
  sendCap: 'hiverelay.notify.v1.send-cap',
  intent: 'hiverelay.notify.v1.intent',
  watch: 'hiverelay.notify.v1.watch',
  status: 'hiverelay.notify.v1.status',
  revoke: 'hiverelay.notify.v1.revoke',
  deliveryEvent: 'hiverelay.notify.v1.delivery-event'
})

export const NOTIFY_PRIVACY_PROFILES = Object.freeze([
  'generic',
  'local-template'
])

export const NOTIFY_PROVIDERS = Object.freeze([
  'runtime',
  'apns',
  'fcm',
  'webpush'
])

const HEX_32 = /^[0-9a-f]{64}$/i
const HEX_16 = /^[0-9a-f]{32}$/i
const HEX_SIG = /^[0-9a-f]{128}$/i
const DEFAULT_MAX_PAYLOAD_BYTES = 3072
const DEFAULT_MAX_TTL_SECONDS = 7 * 24 * 60 * 60
const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000
const DEFAULT_EVENT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000
const DEFAULT_MAX_EVENTS = 10000
const DEFAULT_MAX_WATCHES = 128
const NOTIFY_STATE_VERSION = 1
const URGENCY_RANK = Object.freeze({
  silent: 0,
  normal: 1,
  high: 2
})

export class NotifyService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.provider = opts.provider || createMemoryPushProvider(opts.providerResult)
    this.keyPair = opts.keyPair || null
    this.clock = typeof opts.clock === 'function' ? opts.clock : () => Date.now()
    this.maxPayloadBytes = positiveInteger(opts.maxPayloadBytes, DEFAULT_MAX_PAYLOAD_BYTES)
    this.maxTtlSeconds = positiveInteger(opts.maxTtlSeconds, DEFAULT_MAX_TTL_SECONDS)
    this.clockSkewMs = positiveInteger(opts.clockSkewMs, DEFAULT_CLOCK_SKEW_MS)
    this.eventRetentionMs = positiveInteger(opts.eventRetentionMs, DEFAULT_EVENT_RETENTION_MS)
    this.maxEvents = positiveInteger(opts.maxEvents, DEFAULT_MAX_EVENTS)
    this.maxWatchesPerReceiveCap = positiveInteger(opts.maxWatchesPerReceiveCap, DEFAULT_MAX_WATCHES)
    this.persistence = normalizePersistence(opts.persistence || null)
    this.persistencePath = stringOr(opts.persistencePath, null)
    this.persistenceDisabled = opts.persistence === false

    this.providerBindings = new Map()
    this.devices = new Map()
    this.receiveCaps = new Map()
    this.sendCaps = new Map()
    this.revocations = new Map()
    this.deliveryEvents = new Map()
    this.eventsByIntent = new Map()
    this.replay = new Map()
    this.dedupe = new Map()
    this.buckets = new Map()
    this.watches = new Map()
    this._eventSeq = 0
    this._persistChain = Promise.resolve()
    this.node = null
    this.store = null
  }

  manifest () {
    return {
      name: 'notify',
      version: NOTIFY_SERVICE_VERSION,
      description: 'Encrypted P2P wakeup notification service',
      capabilities: [
        'bind-provider',
        'register-device',
        'install-receive-cap',
        'install-send-cap',
        'revoke',
        'send',
        'watch',
        'unwatch',
        'status',
        'delivery-event',
        'production-gates'
      ]
    }
  }

  async start (context = {}) {
    this.node = context.node || null
    this.store = context.store || null
    if (!this.keyPair) this.keyPair = extractRelayKeyPair(this.node)
    if (!this.persistence) this.persistence = await this._createDefaultPersistence(context)
    await this._loadState()
  }

  async stop () {
    await this._saveState()
    this.node = null
    this.store = null
  }

  async 'bind-provider' (params = {}) {
    const now = this.clock()
    requireObject(params, 'provider binding required')
    requireHex(params.bindingId, 'bindingId')
    requireHex(params.app, 'app')
    requireHex(params.device, 'device')
    requireHex(params.tokenHash, 'tokenHash')
    if (params.audience) this._requireAudience(params.audience)
    if (!NOTIFY_PROVIDERS.includes(params.provider)) throw fail('PROVIDER_UNSUPPORTED', 'unsupported provider')
    if (params.mode !== 'runtimePush' && params.mode !== 'standalonePush') throw fail('MODE_UNSUPPORTED', 'unsupported provider binding mode')
    if (params.credentialMode !== 'runtime-owned' && params.credentialMode !== 'app-owned') throw fail('CREDENTIAL_MODE_UNSUPPORTED', 'unsupported credential mode')
    if (!Number.isSafeInteger(params.generation) || params.generation < 0) throw fail('BAD_GENERATION', 'generation must be a non-negative integer')
    if (!isFuture(params.expiresAt, now)) throw fail('EXPIRED', 'provider binding expired')
    verifySigned(params, NOTIFY_DOMAINS.providerBinding, params.signatureKey || params.device)

    const previous = this.providerBindings.get(params.bindingId)
    if (previous && params.generation <= previous.generation) throw fail('STALE_GENERATION', 'provider binding generation is stale')

    const binding = freezeClone({
      type: params.type || 'hiverelay.notify.provider-binding.v1',
      bindingId: params.bindingId,
      audience: params.audience || this._relayKeyHex(),
      app: params.app,
      device: params.device,
      mode: params.mode,
      provider: params.provider,
      platform: stringOr(params.platform, null),
      scope: objectOr(params.scope, {}),
      credentialMode: params.credentialMode,
      tokenHash: params.tokenHash.toLowerCase(),
      tokenCiphertext: boundedString(params.tokenCiphertext, 8192) || '',
      generation: params.generation,
      createdAt: safeTime(params.createdAt, now),
      expiresAt: params.expiresAt,
      nonce: validHex(params.nonce, 16) ? params.nonce.toLowerCase() : null,
      signature: params.signature,
      signatureKey: params.signatureKey || params.device,
      stale: false
    })

    this.providerBindings.set(binding.bindingId, binding)
    await this._saveState()
    return { ok: true, bindingId: binding.bindingId, generation: binding.generation, expiresAt: binding.expiresAt }
  }

  async 'register-device' (params = {}) {
    const now = this.clock()
    requireObject(params, 'device registration required')
    requireHex(params.app, 'app')
    requireHex(params.user, 'user')
    requireHex(params.device, 'device')
    requireHex(params.encryptionKey, 'encryptionKey')
    requireHex(params.bindingId, 'bindingId')
    if (params.audience) this._requireAudience(params.audience)
    verifySigned(params, NOTIFY_DOMAINS.deviceRegistration, params.device)
    if (!isFuture(params.expiresAt, now)) throw fail('EXPIRED', 'device registration expired')

    const binding = this._requireBinding(params.bindingId, params.app, params.device)
    const device = freezeClone({
      type: params.type || 'hiverelay.notify.device-registration.v1',
      audience: params.audience || this._relayKeyHex(),
      app: params.app,
      user: params.user,
      device: params.device,
      encryptionKey: params.encryptionKey,
      bindingId: params.bindingId,
      provider: binding.provider,
      createdAt: safeTime(params.createdAt, now),
      expiresAt: params.expiresAt,
      nonce: validHex(params.nonce, 16) ? params.nonce.toLowerCase() : null,
      signature: params.signature
    })

    this.devices.set(deviceKey(device.app, device.user, device.device), device)
    await this._saveState()
    return { ok: true, device: device.device, relay: this._relayKeyHex(), bindingId: device.bindingId, expiresAt: device.expiresAt }
  }

  async 'install-receive-cap' (params = {}) {
    const now = this.clock()
    requireObject(params, 'receive capability required')
    requireHex(params.capId, 'capId')
    requireHex(params.user, 'user')
    requireHex(params.app, 'app')
    requireHex(params.device, 'device')
    requireHex(params.bindingId, 'bindingId')
    requireHex(params.tokenHash, 'tokenHash')
    if (params.audience) this._requireAudience(params.audience)
    if (!Array.isArray(params.channels) || params.channels.length === 0) throw fail('CHANNEL_DENIED', 'channels required')
    if (!isFuture(params.expiresAt, now)) throw fail('EXPIRED', 'receive capability expired')
    verifySignedAny(params, NOTIFY_DOMAINS.receiveCap, [params.signatureKey, params.user, params.device])

    const binding = this._requireBinding(params.bindingId, params.app, params.device)
    if (binding.tokenHash !== params.tokenHash.toLowerCase()) throw fail('TOKEN_MISMATCH', 'receive capability tokenHash does not match provider binding')
    const registered = this._findDevice(params.app, params.user, params.device)
    if (!registered) throw fail('DEVICE_NOT_REGISTERED', 'device is not registered')

    const receiveCap = freezeClone({
      type: params.type || 'hiverelay.notify.receive-cap.v1',
      capId: params.capId,
      audience: params.audience || this._relayKeyHex(),
      user: params.user,
      app: params.app,
      device: params.device,
      bindingId: params.bindingId,
      tokenHash: params.tokenHash.toLowerCase(),
      channels: normalizeStringList(params.channels, 64, 32),
      modes: normalizeStringList(params.modes || ['direct'], 64, 8),
      quota: normalizeQuota(params.quota, { perHour: 30, burst: 5, maxTtlSeconds: 86400, maxUrgency: 'normal' }),
      createdAt: safeTime(params.createdAt, now),
      expiresAt: params.expiresAt,
      nonce: validHex(params.nonce, 16) ? params.nonce.toLowerCase() : null,
      signature: params.signature,
      signatureKey: params.signatureKey || params.user
    })
    if (receiveCap.channels.length === 0) throw fail('CHANNEL_DENIED', 'no valid channels')

    this.receiveCaps.set(receiveCap.capId, receiveCap)
    await this._saveState()
    return { ok: true, capId: receiveCap.capId, limits: receiveCap.quota }
  }

  async 'install-send-cap' (params = {}) {
    const now = this.clock()
    requireObject(params, 'send capability required')
    requireHex(params.capId, 'capId')
    requireHex(params.receiveCap, 'receiveCap')
    requireHex(params.app, 'app')
    requireHex(params.device, 'device')
    requireHex(params.sender, 'sender')
    if (params.audience) this._requireAudience(params.audience)
    if (!isFuture(params.expiresAt, now)) throw fail('EXPIRED', 'send capability expired')
    const receiveCap = this._requireReceiveCap(params.receiveCap)
    if (receiveCap.app !== params.app || receiveCap.device !== params.device) throw fail('CAP_MISMATCH', 'send capability does not match receive capability')
    if (!receiveCap.channels.includes(params.channel)) throw fail('CHANNEL_DENIED', 'channel outside receive capability')
    verifySignedAny(params, NOTIFY_DOMAINS.sendCap, [params.signatureKey, receiveCap.user])

    const sendCap = freezeClone({
      type: params.type || 'hiverelay.notify.send-cap.v1',
      capId: params.capId,
      receiveCap: params.receiveCap,
      audience: params.audience || this._relayKeyHex(),
      app: params.app,
      device: params.device,
      sender: params.sender,
      channel: params.channel,
      quota: normalizeQuota(params.quota, { perHour: 10, burst: 3, maxTtlSeconds: 3600, maxUrgency: 'normal' }),
      createdAt: safeTime(params.createdAt, now),
      expiresAt: params.expiresAt,
      nonce: validHex(params.nonce, 16) ? params.nonce.toLowerCase() : null,
      signature: params.signature,
      signatureKey: params.signatureKey || receiveCap.user
    })

    this.sendCaps.set(sendCap.capId, sendCap)
    await this._saveState()
    return { ok: true, capId: sendCap.capId, receiveCap: sendCap.receiveCap }
  }

  async revoke (params = {}) {
    const now = this.clock()
    requireObject(params, 'revocation required')
    requireHex(params.app, 'app')
    if (params.audience) this._requireAudience(params.audience)
    const scope = boundedString(params.scope, 64)
    if (!scope) throw fail('BAD_SCOPE', 'revocation scope required')
    const target = boundedString(params.target, 256) || ''
    const candidates = [params.signatureKey, params.user, params.device].filter(Boolean)
    if (candidates.length === 0) throw fail('BAD_SIGNATURE', 'revocation signer required')
    verifySignedAny(params, NOTIFY_DOMAINS.revoke, candidates)

    const revocation = freezeClone({
      type: params.type || 'hiverelay.notify.revocation.v1',
      target,
      user: stringOr(params.user, null),
      device: stringOr(params.device, null),
      app: params.app,
      audience: params.audience || this._relayKeyHex(),
      scope,
      createdAt: safeTime(params.createdAt, now),
      nonce: validHex(params.nonce, 16) ? params.nonce.toLowerCase() : null,
      signature: params.signature,
      signatureKey: params.signatureKey || params.user || params.device
    })

    this.revocations.set(revocationKey(scope, target, params.app), revocation)
    if (scope === 'binding') {
      const binding = this.providerBindings.get(target)
      if (binding) this.providerBindings.set(target, freezeClone({ ...binding, stale: true }))
    }
    await this._saveState()
    return { ok: true, revoked: true, scope, target }
  }

  async send (params = {}) {
    requireObject(params, 'notification intent required')
    const verdict = this._validateIntent(params)
    if (!verdict.ok) return this._finalizeRejectedIntentAndPersist(params, verdict)

    const { receiveCap, sendCap, binding, now } = verdict
    const quota = this._consumeIntentQuota(params, receiveCap, sendCap, now)
    if (!quota.ok) return this._finalizeRejectedIntentAndPersist(params, { status: 'rate_limited', reason: quota.reason, receiveCap, sendCap, binding, now })

    if (params.dedupeKey) {
      const dedupeUntil = this.dedupe.get(params.dedupeKey)
      if (dedupeUntil && dedupeUntil > now) {
        return this._finalizeRejectedIntentAndPersist(params, { status: 'rate_limited', reason: 'duplicate', receiveCap, sendCap, binding, now })
      }
      this.dedupe.set(params.dedupeKey, now + Math.min(params.ttlSeconds * 1000, 24 * 60 * 60 * 1000))
    }

    this.replay.set(params.intentId, now + params.ttlSeconds * 1000)
    this._sweepExpiringMaps(now)

    const providerResult = await this.provider.send({
      provider: binding.provider,
      credentialMode: binding.credentialMode,
      providerTokenCiphertext: binding.tokenCiphertext,
      app: params.app,
      device: params.receiver,
      channel: params.channel,
      urgency: params.urgency,
      ttlSeconds: params.ttlSeconds,
      collapseKey: params.collapseKey || null,
      payloadCiphertext: params.payloadCiphertext,
      genericDisplay: true,
      intent: params
    })
    const normalized = normalizeProviderResult(providerResult)
    if (normalized.status === 'token_invalid') {
      this.providerBindings.set(binding.bindingId, freezeClone({ ...binding, stale: true }))
    }
    const event = this._recordDeliveryEvent({
      intent: params,
      status: normalized.status,
      reason: normalized.reason,
      providerStatus: normalized.providerStatus,
      binding,
      billable: normalized.billable !== false,
      attempts: 1,
      payloadBytes: payloadBytes(params.payloadCiphertext),
      now
    })
    await this._saveState()
    return { ok: normalized.status === 'accepted_by_provider' || normalized.status === 'provider_attempted', intentId: params.intentId, status: event.status, reason: event.reason, eventId: event.eventId, event }
  }

  async watch (params = {}) {
    const now = this.clock()
    requireObject(params, 'watch required')
    requireHex(params.watchId, 'watchId')
    requireHex(params.receiveCap, 'receiveCap')
    requireHex(params.sendCap, 'sendCap')
    if (params.audience) this._requireAudience(params.audience)
    const receiveCap = this._requireReceiveCap(params.receiveCap)
    const sendCap = this._requireSendCap(params.sendCap)
    if (sendCap.receiveCap !== receiveCap.capId) throw fail('CAP_MISMATCH', 'watch send capability does not match receive capability')
    if (!receiveCap.modes.includes('watch')) throw fail('MODE_DENIED', 'receive capability does not allow watch mode')
    if (!receiveCap.channels.includes(params.channel) || sendCap.channel !== params.channel) throw fail('CHANNEL_DENIED', 'watch channel denied')
    if (!isFuture(params.expiresAt, now)) throw fail('EXPIRED', 'watch expired')
    verifySignedAny(params, NOTIFY_DOMAINS.watch, [params.signatureKey, receiveCap.user, receiveCap.device])

    const source = objectOr(params.source, null)
    if (!source || (source.kind !== 'hypercore-head' && source.kind !== 'notify-feed-head')) throw fail('SOURCE_DENIED', 'unsupported watch source')
    requireHex(source.key, 'source.key')
    const existingForCap = [...this.watches.values()].filter(w => w.receiveCap === receiveCap.capId).length
    if (existingForCap >= this.maxWatchesPerReceiveCap) throw fail('WATCH_LIMIT', 'receive capability watch limit reached')

    const watch = freezeClone({
      type: params.type || 'hiverelay.notify.watch.v1',
      watchId: params.watchId,
      receiveCap: receiveCap.capId,
      sendCap: sendCap.capId,
      app: receiveCap.app,
      user: receiveCap.user,
      device: receiveCap.device,
      audience: params.audience || this._relayKeyHex(),
      source: {
        kind: source.kind,
        key: source.key,
        start: Number.isSafeInteger(source.start) && source.start >= 0 ? source.start : 0
      },
      channel: params.channel,
      policy: objectOr(params.policy, {}),
      createdAt: safeTime(params.createdAt, now),
      expiresAt: params.expiresAt,
      signature: params.signature,
      signatureKey: params.signatureKey || receiveCap.user,
      lastSeq: Number.isSafeInteger(source.start) && source.start >= 0 ? source.start : 0
    })
    this.watches.set(watch.watchId, watch)
    await this._saveState()
    return { ok: true, watchId: watch.watchId, source: watch.source }
  }

  async unwatch (params = {}) {
    requireObject(params, 'unwatch request required')
    requireHex(params.watchId, 'watchId')
    const watch = this.watches.get(params.watchId)
    if (!watch) return { ok: true, removed: false }
    const receiveCap = this._requireReceiveCap(watch.receiveCap)
    verifySignedAny(params, NOTIFY_DOMAINS.watch, [params.signatureKey, receiveCap.user, receiveCap.device])
    this.watches.delete(params.watchId)
    await this._saveState()
    return { ok: true, removed: true }
  }

  async status (params = {}) {
    if (params && params.signature) {
      const candidates = [params.signatureKey, params.user, params.device].filter(Boolean)
      if (candidates.length === 0) throw fail('BAD_SIGNATURE', 'status signer required')
      verifySignedAny(params, NOTIFY_DOMAINS.status, candidates)
    }
    const app = params && typeof params.app === 'string' ? params.app : null
    const device = params && typeof params.device === 'string' ? params.device : null
    const matches = (entry) => {
      if (app && entry.app !== app) return false
      if (device && entry.device !== device) return false
      return true
    }
    return {
      ok: true,
      service: 'notify',
      version: NOTIFY_SERVICE_VERSION,
      privacy: {
        plaintextAllowed: false,
        profiles: NOTIFY_PRIVACY_PROFILES
      },
      limits: this.limits(),
      counts: {
        providerBindings: countMap(this.providerBindings, matches),
        devices: countMap(this.devices, matches),
        receiveCaps: countMap(this.receiveCaps, matches),
        sendCaps: countMap(this.sendCaps, matches),
        watches: countMap(this.watches, matches),
        deliveryEvents: this.deliveryEvents.size,
        revocations: this.revocations.size
      }
    }
  }

  async 'delivery-event' (params = {}) {
    const events = []
    if (params && params.eventId) {
      const event = this.deliveryEvents.get(params.eventId)
      if (event) events.push(redactDeliveryEvent(event))
    } else if (params && params.intentId) {
      const ids = this.eventsByIntent.get(params.intentId) || []
      for (const id of ids) {
        const event = this.deliveryEvents.get(id)
        if (event) events.push(redactDeliveryEvent(event))
      }
    }
    return { ok: true, events, count: events.length }
  }

  async 'production-gates' (params = {}) {
    const app = params && typeof params.app === 'string' ? params.app : null
    const bindings = [...this.providerBindings.values()].filter(b => !app || b.app === app)
    const receiveCaps = [...this.receiveCaps.values()].filter(c => !app || c.app === app)
    const sendCaps = [...this.sendCaps.values()].filter(c => !app || c.app === app)
    const hasRuntimeBinding = bindings.some(b => b.mode === 'runtimePush' && b.credentialMode === 'runtime-owned' && !b.stale)
    const hasStandalone = bindings.some(b => b.mode === 'standalonePush')
    return {
      ok: true,
      app,
      gates: [
        { id: 'provider-binding', ok: bindings.some(b => !b.stale), detail: 'valid non-stale provider binding present' },
        { id: 'runtime-push-preferred', ok: hasRuntimeBinding || !hasStandalone, detail: 'runtime-owned provider path preferred for v1' },
        { id: 'receive-cap', ok: receiveCaps.length > 0, detail: 'at least one receive capability installed' },
        { id: 'send-cap', ok: sendCaps.length > 0, detail: 'at least one sender capability installed' },
        { id: 'generic-privacy', ok: true, detail: 'v1 service only exposes generic provider display' },
        { id: 'delivery-events-redacted', ok: true, detail: 'delivery events omit provider tokens and plaintext' }
      ]
    }
  }

  limits () {
    return {
      maxPayloadBytes: this.maxPayloadBytes,
      maxTtlSeconds: this.maxTtlSeconds,
      maxWatchesPerReceiveCap: this.maxWatchesPerReceiveCap,
      privacyProfiles: NOTIFY_PRIVACY_PROFILES,
      providers: NOTIFY_PROVIDERS
    }
  }

  _validateIntent (intent) {
    const now = this.clock()
    requireHex(intent.intentId, 'intentId')
    requireHex(intent.receiveCap, 'receiveCap')
    requireHex(intent.sendCap, 'sendCap')
    requireHex(intent.app, 'app')
    requireHex(intent.receiver, 'receiver')
    requireHex(intent.sender, 'sender')
    if (this.replay.get(intent.intentId) > now) return { ok: false, status: 'rejected_by_relay', reason: 'replay', now }
    const receiveCap = this.receiveCaps.get(intent.receiveCap)
    if (!receiveCap) return { ok: false, status: 'rejected_by_relay', reason: 'receive_cap_missing', now }
    const sendCap = this.sendCaps.get(intent.sendCap)
    if (!sendCap) return { ok: false, status: 'rejected_by_relay', reason: 'send_cap_missing', receiveCap, now }
    const binding = this.providerBindings.get(receiveCap.bindingId)
    if (!binding || binding.stale) return { ok: false, status: 'rejected_by_relay', reason: 'provider_token_invalid', receiveCap, sendCap, now }
    if (!isFuture(receiveCap.expiresAt, now) || !isFuture(sendCap.expiresAt, now)) return { ok: false, status: 'rejected_by_relay', reason: 'cap_expired', receiveCap, sendCap, binding, now }
    if (this._revokedForIntent(intent, receiveCap, sendCap, binding)) return { ok: false, status: 'rejected_by_relay', reason: 'cap_revoked', receiveCap, sendCap, binding, now }
    if (intent.app !== receiveCap.app || intent.app !== sendCap.app) return { ok: false, status: 'rejected_by_relay', reason: 'cap_mismatch', receiveCap, sendCap, binding, now }
    if (intent.receiver !== receiveCap.device || intent.receiver !== sendCap.device) return { ok: false, status: 'rejected_by_relay', reason: 'cap_mismatch', receiveCap, sendCap, binding, now }
    if (intent.sender !== sendCap.sender) return { ok: false, status: 'rejected_by_relay', reason: 'send_cap_missing', receiveCap, sendCap, binding, now }
    if (!receiveCap.channels.includes(intent.channel) || sendCap.channel !== intent.channel) return { ok: false, status: 'rejected_by_relay', reason: 'channel_denied', receiveCap, sendCap, binding, now }
    if (!receiveCap.modes.includes('direct') && !receiveCap.modes.includes('presence-fallback')) return { ok: false, status: 'rejected_by_relay', reason: 'mode_denied', receiveCap, sendCap, binding, now }
    if (!withinClockSkew(intent.createdAt, now, this.clockSkewMs)) return { ok: false, status: 'expired', reason: 'intent_clock_skew', receiveCap, sendCap, binding, now }
    const ttl = positiveInteger(intent.ttlSeconds, 0)
    if (!ttl || ttl > this.maxTtlSeconds || ttl > receiveCap.quota.maxTtlSeconds || ttl > sendCap.quota.maxTtlSeconds) return { ok: false, status: 'expired', reason: 'ttl_denied', receiveCap, sendCap, binding, now }
    if (!urgencyAllowed(intent.urgency, receiveCap.quota.maxUrgency) || !urgencyAllowed(intent.urgency, sendCap.quota.maxUrgency)) return { ok: false, status: 'rejected_by_relay', reason: 'urgency_denied', receiveCap, sendCap, binding, now }
    if (payloadBytes(intent.payloadCiphertext) > this.maxPayloadBytes) return { ok: false, status: 'rejected_by_relay', reason: 'payload_too_large', receiveCap, sendCap, binding, now }
    if (intent.payloadHash && intent.payloadHash !== hashHex(String(intent.payloadCiphertext || ''))) return { ok: false, status: 'rejected_by_relay', reason: 'payload_hash_mismatch', receiveCap, sendCap, binding, now }
    if (intent.privacyProfile && !NOTIFY_PRIVACY_PROFILES.includes(intent.privacyProfile)) return { ok: false, status: 'rejected_by_relay', reason: 'privacy_profile_denied', receiveCap, sendCap, binding, now }
    try {
      verifySigned(intent, NOTIFY_DOMAINS.intent, intent.sender)
    } catch (_) {
      return { ok: false, status: 'rejected_by_relay', reason: 'bad_signature', receiveCap, sendCap, binding, now }
    }
    return { ok: true, receiveCap, sendCap, binding, now }
  }

  _consumeIntentQuota (intent, receiveCap, sendCap, now) {
    for (const check of [
      consumeBucket(this.buckets, 'receive:' + receiveCap.capId, receiveCap.quota, now),
      consumeBucket(this.buckets, 'send:' + sendCap.capId, sendCap.quota, now),
      consumeBucket(this.buckets, 'app:' + intent.app, { perHour: 10000, burst: 1000 }, now),
      consumeBucket(this.buckets, 'sender:' + intent.sender, { perHour: 1000, burst: 100 }, now),
      consumeBucket(this.buckets, 'device:' + intent.receiver, { perHour: 120, burst: 10 }, now),
      consumeBucket(this.buckets, 'channel:' + intent.app + ':' + intent.channel, { perHour: 1000, burst: 100 }, now)
    ]) {
      if (!check.ok) return check
    }
    return { ok: true }
  }

  _finalizeRejectedIntent (intent, verdict) {
    const now = verdict.now || this.clock()
    const event = this._recordDeliveryEvent({
      intent,
      status: verdict.status || 'rejected_by_relay',
      reason: verdict.reason || 'rejected_by_relay',
      providerStatus: null,
      binding: verdict.binding || null,
      billable: false,
      attempts: 0,
      payloadBytes: payloadBytes(intent && intent.payloadCiphertext),
      now
    })
    return { ok: false, intentId: intent && intent.intentId, status: event.status, reason: event.reason, eventId: event.eventId, event }
  }

  async _finalizeRejectedIntentAndPersist (intent, verdict) {
    const result = this._finalizeRejectedIntent(intent, verdict)
    await this._saveState()
    return result
  }

  _recordDeliveryEvent ({ intent, status, reason, providerStatus, binding, billable, attempts, payloadBytes, now }) {
    const event = {
      type: 'hiverelay.notify.delivery-event.v1',
      eventId: '',
      intentId: stringOr(intent && intent.intentId, null),
      relay: this._relayKeyHex(),
      app: stringOr(intent && intent.app, null),
      device: stringOr(intent && intent.receiver, null),
      provider: binding ? binding.provider : null,
      status,
      reason,
      providerStatus: providerStatus || null,
      attemptedAt: now,
      expiresAt: now + this.eventRetentionMs,
      metering: {
        billable: billable === true,
        attempts: attempts || 0,
        payloadBytes: payloadBytes || 0
      }
    }
    event.eventId = hashHex(JSON.stringify([event.intentId, event.status, event.reason, event.attemptedAt, ++this._eventSeq]))
    event.signature = this._signObject(event, NOTIFY_DOMAINS.deliveryEvent)
    const frozen = freezeClone(event)
    this.deliveryEvents.set(frozen.eventId, frozen)
    if (frozen.intentId) {
      const ids = this.eventsByIntent.get(frozen.intentId) || []
      ids.push(frozen.eventId)
      this.eventsByIntent.set(frozen.intentId, ids)
    }
    this._trimEvents(now)
    return frozen
  }

  _revokedForIntent (intent, receiveCap, sendCap, binding) {
    return !!(
      this._hasRevocation('receive-cap', receiveCap.capId, intent.app) ||
      this._hasRevocation('send-cap', sendCap.capId, intent.app) ||
      this._hasRevocation('device', intent.receiver, intent.app) ||
      this._hasRevocation('binding', binding.bindingId, intent.app) ||
      this._hasRevocation('app', intent.app, intent.app) ||
      this._hasRevocation('channel', intent.channel, intent.app) ||
      this._hasRevocation('relay', this._relayKeyHex(), intent.app)
    )
  }

  _hasRevocation (scope, target, app) {
    return this.revocations.has(revocationKey(scope, target, app)) ||
      this.revocations.has(revocationKey(scope, target, null))
  }

  _requireReceiveCap (capId) {
    const cap = this.receiveCaps.get(capId)
    if (!cap) throw fail('RECEIVE_CAP_MISSING', 'receive capability missing')
    return cap
  }

  _requireSendCap (capId) {
    const cap = this.sendCaps.get(capId)
    if (!cap) throw fail('SEND_CAP_MISSING', 'send capability missing')
    return cap
  }

  _requireBinding (bindingId, app, device) {
    const binding = this.providerBindings.get(bindingId)
    if (!binding) throw fail('BINDING_MISSING', 'provider binding missing')
    if (binding.stale) throw fail('PROVIDER_TOKEN_INVALID', 'provider binding is stale')
    if (binding.app !== app || binding.device !== device) throw fail('BINDING_MISMATCH', 'provider binding does not match app/device')
    if (!isFuture(binding.expiresAt, this.clock())) throw fail('EXPIRED', 'provider binding expired')
    return binding
  }

  _findDevice (app, user, device) {
    const record = this.devices.get(deviceKey(app, user, device))
    if (!record) return null
    if (!isFuture(record.expiresAt, this.clock())) return null
    return record
  }

  _requireAudience (audience) {
    requireHex(audience, 'audience')
    const relayKey = this._relayKeyHex()
    if (relayKey && audience.toLowerCase() !== relayKey) throw fail('AUDIENCE_MISMATCH', 'capability audience does not match relay')
  }

  _relayKeyHex () {
    const pk = this.keyPair && this.keyPair.publicKey
    return pk ? b4a.toString(pk, 'hex') : null
  }

  _signObject (obj, domain) {
    const secretKey = this.keyPair && this.keyPair.secretKey
    if (!secretKey) return null
    const sig = b4a.alloc(64)
    sodium.crypto_sign_detached(sig, notifySignaturePayload(domain, obj), secretKey)
    return b4a.toString(sig, 'hex')
  }

  _trimEvents (now) {
    for (const [id, event] of this.deliveryEvents) {
      if (event.expiresAt <= now || this.deliveryEvents.size > this.maxEvents) {
        this.deliveryEvents.delete(id)
        if (event.intentId) {
          const ids = (this.eventsByIntent.get(event.intentId) || []).filter(v => v !== id)
          if (ids.length) this.eventsByIntent.set(event.intentId, ids)
          else this.eventsByIntent.delete(event.intentId)
        }
      } else if (this.deliveryEvents.size <= this.maxEvents) {
        break
      }
    }
  }

  _sweepExpiringMaps (now) {
    sweepExpiryMap(this.replay, now)
    sweepExpiryMap(this.dedupe, now)
  }

  async _createDefaultPersistence (context) {
    if (this.persistenceDisabled) return null
    const config = objectOr(context && context.config, {})
    const notifyConfig = objectOr(config.notify, {})
    const path = this.persistencePath ||
      stringOr(notifyConfig.persistencePath, null) ||
      (canUseNodeFs() && typeof config.storage === 'string' && config.storage
        ? joinPath(config.storage, 'notify-service-state.json')
        : null)
    return path ? createJsonFileNotifyPersistence(path) : null
  }

  async _loadState () {
    if (!this.persistence) return
    const snapshot = await this.persistence.load()
    if (!snapshot) return
    this._applyState(snapshot)
  }

  async _saveState () {
    if (!this.persistence) return
    const snapshot = this._stateSnapshot()
    const write = this._persistChain.catch(() => {}).then(() => this.persistence.save(snapshot))
    this._persistChain = write
    await write
  }

  _stateSnapshot () {
    return {
      version: NOTIFY_STATE_VERSION,
      savedAt: this.clock(),
      eventSeq: this._eventSeq,
      providerBindings: mapEntries(this.providerBindings),
      devices: mapEntries(this.devices),
      receiveCaps: mapEntries(this.receiveCaps),
      sendCaps: mapEntries(this.sendCaps),
      revocations: mapEntries(this.revocations),
      watches: mapEntries(this.watches),
      deliveryEvents: mapEntries(this.deliveryEvents),
      replay: mapEntries(this.replay),
      dedupe: mapEntries(this.dedupe),
      buckets: mapEntries(this.buckets)
    }
  }

  _applyState (snapshot) {
    if (!snapshot || typeof snapshot !== 'object') return
    if (snapshot.version !== NOTIFY_STATE_VERSION) throw fail('BAD_STATE', 'unsupported notify state version')
    this.providerBindings = restoreObjectMap(snapshot.providerBindings)
    this.devices = restoreObjectMap(snapshot.devices)
    this.receiveCaps = restoreObjectMap(snapshot.receiveCaps)
    this.sendCaps = restoreObjectMap(snapshot.sendCaps)
    this.revocations = restoreObjectMap(snapshot.revocations)
    this.watches = restoreObjectMap(snapshot.watches)
    this.deliveryEvents = restoreObjectMap(snapshot.deliveryEvents)
    this.replay = restoreNumberMap(snapshot.replay)
    this.dedupe = restoreNumberMap(snapshot.dedupe)
    this.buckets = restoreObjectMap(snapshot.buckets)
    this._eventSeq = Number.isSafeInteger(snapshot.eventSeq) && snapshot.eventSeq >= 0 ? snapshot.eventSeq : 0
    this._rebuildEventIndex()
    const now = this.clock()
    this._trimEvents(now)
    this._sweepExpiringMaps(now)
  }

  _rebuildEventIndex () {
    this.eventsByIntent = new Map()
    for (const event of this.deliveryEvents.values()) {
      if (!event || !event.intentId) continue
      const ids = this.eventsByIntent.get(event.intentId) || []
      ids.push(event.eventId)
      this.eventsByIntent.set(event.intentId, ids)
    }
  }
}

export function createMemoryPushProvider (result = {}) {
  const attempts = []
  return {
    attempts,
    async send (delivery) {
      attempts.push({ ...delivery, providerTokenCiphertext: delivery.providerTokenCiphertext ? '[redacted]' : null })
      return {
        status: result.status || 'accepted_by_provider',
        reason: result.reason || 'accepted_by_provider',
        providerStatus: result.providerStatus || 'memory-accepted',
        billable: result.billable !== false
      }
    }
  }
}

export function createMemoryNotifyPersistence (initialSnapshot = null) {
  let state = initialSnapshot ? freezeClone(initialSnapshot) : null
  return {
    async load () {
      return state ? freezeClone(state) : null
    },
    async save (snapshot) {
      state = snapshot ? freezeClone(snapshot) : null
    },
    snapshot () {
      return state ? freezeClone(state) : null
    }
  }
}

export function createJsonFileNotifyPersistence (path) {
  if (typeof path !== 'string' || !path) throw new Error('NotifyService: persistence path required')
  return {
    async load () {
      const fs = await nodeFs()
      try {
        return JSON.parse(await fs.readFile(path, 'utf8'))
      } catch (err) {
        if (err && err.code === 'ENOENT') return null
        throw err
      }
    },
    async save (snapshot) {
      const fs = await nodeFs()
      const tmp = path + '.tmp-' + process.pid + '-' + Date.now()
      await fs.mkdir(dirnamePath(path), { recursive: true })
      await fs.writeFile(tmp, JSON.stringify(snapshot), 'utf8')
      await fs.rename(tmp, path)
    }
  }
}

export function notifySignaturePayload (domain, obj) {
  return b4a.from(domain + '\0' + stableObjectString(obj, new Set(['signature'])), 'utf8')
}

export function verifyNotifySignature (obj, domain, publicKeyHex) {
  if (!validHex(publicKeyHex, 32)) return false
  if (!obj || typeof obj.signature !== 'string' || !HEX_SIG.test(obj.signature)) return false
  const sig = b4a.from(obj.signature, 'hex')
  const pub = b4a.from(publicKeyHex, 'hex')
  return sodium.crypto_sign_verify_detached(sig, notifySignaturePayload(domain, obj), pub)
}

function verifySigned (obj, domain, publicKeyHex) {
  if (!verifyNotifySignature(obj, domain, publicKeyHex)) throw fail('BAD_SIGNATURE', 'signature verification failed')
}

function verifySignedAny (obj, domain, keys) {
  for (const key of keys) {
    if (key && verifyNotifySignature(obj, domain, key)) return true
  }
  throw fail('BAD_SIGNATURE', 'signature verification failed')
}

function normalizeProviderResult (result) {
  const status = result && typeof result.status === 'string' ? result.status : 'failed'
  if (status === 'accepted_by_provider') return { status, reason: result.reason || status, providerStatus: result.providerStatus || 'accepted', billable: result.billable }
  if (status === 'provider_attempted') return { status, reason: result.reason || status, providerStatus: result.providerStatus || 'attempted', billable: result.billable }
  if (status === 'token_invalid') return { status, reason: 'provider_token_invalid', providerStatus: result.providerStatus || 'token_invalid', billable: false }
  if (status === 'provider_rejected') return { status, reason: result.reason || 'provider_rejected', providerStatus: result.providerStatus || 'provider_rejected', billable: false }
  return { status: 'failed', reason: result && result.reason ? result.reason : 'failed', providerStatus: result && result.providerStatus ? result.providerStatus : null, billable: false }
}

function stableObjectString (value, exclude = new Set()) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value)
  if (Array.isArray(value)) return '[' + value.map(v => stableObjectString(v, exclude)).join(',') + ']'
  const keys = Object.keys(value).filter(key => !exclude.has(key)).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableObjectString(value[key], exclude)).join(',') + '}'
}

function hashHex (value) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(String(value), 'utf8'))
  return b4a.toString(out, 'hex')
}

function consumeBucket (buckets, key, quota, now) {
  const perHour = positiveInteger(quota && quota.perHour, 0)
  const burst = positiveInteger(quota && quota.burst, perHour)
  if (!perHour || !burst) return { ok: false, reason: 'quota_exhausted' }
  let bucket = buckets.get(key)
  if (!bucket || now - bucket.start >= 60 * 60 * 1000) {
    bucket = { start: now, count: 0, burstStart: now, burstCount: 0 }
  }
  if (now - bucket.burstStart >= 60 * 1000) {
    bucket.burstStart = now
    bucket.burstCount = 0
  }
  if (bucket.count >= perHour || bucket.burstCount >= burst) {
    buckets.set(key, bucket)
    return { ok: false, reason: 'rate_limited' }
  }
  bucket.count++
  bucket.burstCount++
  buckets.set(key, bucket)
  return { ok: true }
}

function normalizeQuota (quota, defaults) {
  const src = quota && typeof quota === 'object' ? quota : {}
  const maxUrgency = Object.prototype.hasOwnProperty.call(URGENCY_RANK, src.maxUrgency) ? src.maxUrgency : defaults.maxUrgency
  return {
    perHour: positiveInteger(src.perHour, defaults.perHour),
    burst: positiveInteger(src.burst, defaults.burst),
    maxTtlSeconds: positiveInteger(src.maxTtlSeconds, defaults.maxTtlSeconds),
    maxUrgency
  }
}

function urgencyAllowed (actual = 'normal', max = 'normal') {
  const a = URGENCY_RANK[actual] == null ? URGENCY_RANK.normal : URGENCY_RANK[actual]
  const m = URGENCY_RANK[max] == null ? URGENCY_RANK.normal : URGENCY_RANK[max]
  return a <= m
}

function payloadBytes (value) {
  return typeof value === 'string' ? b4a.byteLength(value) : 0
}

function countMap (map, fn) {
  let count = 0
  for (const value of map.values()) {
    if (!fn || fn(value)) count++
  }
  return count
}

function mapEntries (map) {
  const entries = []
  for (const [key, value] of map) {
    entries.push([key, freezeClone(value)])
  }
  return entries
}

function restoreObjectMap (entries) {
  const map = new Map()
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') continue
    if (!entry[1] || typeof entry[1] !== 'object' || Array.isArray(entry[1])) continue
    map.set(entry[0], freezeClone(entry[1]))
  }
  return map
}

function restoreNumberMap (entries) {
  const map = new Map()
  for (const entry of Array.isArray(entries) ? entries : []) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') continue
    if (!Number.isSafeInteger(entry[1])) continue
    map.set(entry[0], entry[1])
  }
  return map
}

function redactDeliveryEvent (event) {
  return {
    type: event.type,
    eventId: event.eventId,
    intentId: event.intentId,
    relay: event.relay,
    app: event.app,
    device: event.device,
    provider: event.provider,
    status: event.status,
    reason: event.reason,
    providerStatus: event.providerStatus,
    attemptedAt: event.attemptedAt,
    expiresAt: event.expiresAt,
    metering: event.metering,
    signature: event.signature
  }
}

function deviceKey (app, user, device) {
  return app + '/' + user + '/' + device
}

function revocationKey (scope, target, app) {
  return scope + '/' + (target || '*') + '/' + (app || '*')
}

function extractRelayKeyPair (node) {
  return (node && node.keyPair) ||
    (node && node.identityKeyPair) ||
    (node && node.swarm && node.swarm.keyPair) ||
    null
}

function freezeClone (obj) {
  return Object.freeze(JSON.parse(JSON.stringify(obj)))
}

function requireObject (value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail('BAD_REQUEST', message)
}

function requireHex (value, field) {
  if (!validHex(value, 32)) throw fail('BAD_KEY', field + ' must be 32-byte hex')
}

function validHex (value, bytes) {
  if (bytes === 32) return typeof value === 'string' && HEX_32.test(value)
  if (bytes === 16) return typeof value === 'string' && HEX_16.test(value)
  return typeof value === 'string' && new RegExp('^[0-9a-f]{' + (bytes * 2) + '}$', 'i').test(value)
}

function isFuture (value, now) {
  return Number.isSafeInteger(value) && value > now
}

function withinClockSkew (value, now, skew) {
  return Number.isSafeInteger(value) && value >= now - skew && value <= now + skew
}

function safeTime (value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

function positiveInteger (value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback
}

function stringOr (value, fallback) {
  return typeof value === 'string' ? value : fallback
}

function objectOr (value, fallback) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : fallback
}

function normalizePersistence (persistence) {
  if (!persistence) return null
  if (typeof persistence.load !== 'function' || typeof persistence.save !== 'function') {
    throw new Error('NotifyService: persistence requires load() and save(snapshot)')
  }
  return persistence
}

function canUseNodeFs () {
  return typeof process !== 'undefined' &&
    process &&
    process.versions &&
    process.versions.node &&
    typeof globalThis.Bare === 'undefined'
}

async function nodeFs () {
  if (!canUseNodeFs()) throw new Error('NotifyService: JSON file persistence requires Node.js fs')
  return import('node:fs/promises')
}

function joinPath (base, file) {
  return String(base).replace(/\/+$/, '') + '/' + file
}

function dirnamePath (path) {
  const index = path.lastIndexOf('/')
  return index > 0 ? path.slice(0, index) : '.'
}

function boundedString (value, maxBytes) {
  if (typeof value !== 'string') return null
  if (b4a.byteLength(value) > maxBytes) return null
  return value
}

function normalizeStringList (list, maxBytes, maxItems) {
  const out = []
  const seen = new Set()
  for (const value of Array.isArray(list) ? list : []) {
    const normalized = boundedString(value, maxBytes)
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
    if (out.length >= maxItems) break
  }
  return out
}

function sweepExpiryMap (map, now) {
  for (const [key, expiresAt] of map) {
    if (expiresAt <= now) map.delete(key)
  }
}

function fail (code, message) {
  const err = new Error(code + ': ' + message)
  err.code = code
  return err
}
