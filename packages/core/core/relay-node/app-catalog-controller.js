import b4a from 'b4a'
import { CompletionScheduler, strictPositiveInteger } from '../completion-scheduler.js'
import {
  APP_CATALOG_LIMITS,
  AppCatalogProtocolError,
  createAppCatalogAbort,
  createLegacyCatalogEnvelope
} from './app-catalog-paged.js'
import {
  AppCatalogInboundManager,
  AppCatalogMvccStore,
  AppCatalogOutboundManager,
  attachAppCatalogPagedChannel
} from './app-catalog-paged-runtime.js'
import {
  appRegistryCatalogSource,
  assertAppRegistryCatalogIngress,
  catalogRowToLegacyApp
} from './app-catalog-source.js'

const HEX_64 = /^[0-9a-f]{64}$/
const ZERO_SNAPSHOT_ID = '0'.repeat(64)
const DEFAULT_SOURCE_INTERVAL_MS = 60_000
const DEFAULT_SWEEP_INTERVAL_MS = 1_000
const DEFAULT_ACTION_LIMIT = 10

function peerHex (value) {
  const peer = b4a.isBuffer(value) ? b4a.toString(value, 'hex') : value
  if (typeof peer !== 'string' || !HEX_64.test(peer)) {
    throw new AppCatalogProtocolError('PROTOCOL_ERROR', 'authenticated catalog peer key must be lowercase 64-hex')
  }
  return peer
}

function errorCode (err, fallback = 'PROTOCOL_ERROR') {
  return typeof err?.code === 'string' ? err.code : fallback
}

/**
 * Owns the bounded local catalog source, completed MVCC snapshots, the
 * dedicated Protomux channel, atomic inbound staging and one finite action
 * scheduler. Node and Bare runtimes share this exact controller.
 */
export class AppCatalogController {
  constructor (opts = {}) {
    if (!opts.appRegistry || typeof opts.appRegistry.page !== 'function') {
      throw new TypeError('AppCatalogController requires a bounded AppRegistry')
    }
    if (!opts.keyPair?.publicKey || !opts.keyPair?.secretKey) {
      throw new TypeError('AppCatalogController requires the relay Ed25519 key pair')
    }
    if (!opts.stageFactory || typeof opts.stageFactory.ready !== 'function') {
      throw new TypeError('AppCatalogController requires an owned disk stage factory')
    }
    this.appRegistry = opts.appRegistry
    this.keyPair = opts.keyPair
    this.localPubkey = b4a.toString(opts.keyPair.publicKey, 'hex')
    this.stageFactory = opts.stageFactory
    this.sourceBudget = strictPositiveInteger(
      opts.sourceBudget ?? 64,
      'app catalog sourceBudget',
      64
    )
    this.digestBudget = strictPositiveInteger(
      opts.digestBudget ?? APP_CATALOG_LIMITS.maxPageEntries,
      'app catalog digestBudget',
      APP_CATALOG_LIMITS.maxPageEntries
    )
    this.sourceIntervalMs = strictPositiveInteger(
      opts.sourceIntervalMs ?? DEFAULT_SOURCE_INTERVAL_MS,
      'app catalog sourceIntervalMs'
    )
    this.sweepIntervalMs = strictPositiveInteger(
      opts.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS,
      'app catalog sweepIntervalMs',
      APP_CATALOG_LIMITS.inboundIdleTimeoutMs
    )
    this.abortDrainTimeoutMs = strictPositiveInteger(
      opts.abortDrainTimeoutMs ?? APP_CATALOG_LIMITS.ackTimeoutMs,
      'app catalog abortDrainTimeoutMs',
      APP_CATALOG_LIMITS.ackTimeoutMs
    )
    this.actionLimit = strictPositiveInteger(
      opts.actionLimit ?? DEFAULT_ACTION_LIMIT,
      'app catalog actionLimit',
      DEFAULT_ACTION_LIMIT
    )
    this.onCatalogComplete = typeof opts.onCatalogComplete === 'function' ? opts.onCatalogComplete : null
    this.onCatalogActionPage = typeof opts.onCatalogActionPage === 'function' ? opts.onCatalogActionPage : null
    this.onError = typeof opts.onError === 'function' ? opts.onError : null
    this.onLegacyFallback = typeof opts.onLegacyFallback === 'function' ? opts.onLegacyFallback : null
    this._setTimer = typeof opts.setTimeout === 'function' ? opts.setTimeout : setTimeout
    this._clearTimer = typeof opts.clearTimeout === 'function' ? opts.clearTimeout : clearTimeout

    this.store = new AppCatalogMvccStore(opts.store || {})
    this.outbound = null
    this.inbound = null
    this.channels = new Map()
    this._legacyTimers = new Map()
    this._actionQueue = new Map()
    this._nextActionGeneration = 1
    this._actionRefs = new Map()
    this._releaseFlights = new Set()
    this._notificationFlights = new Set()
    this._peerRemovalFlights = new Map()
    this._closeFlights = new Set()
    this._sourceScheduler = null
    this._digestScheduler = null
    this._inboundSweepScheduler = null
    this._actionScheduler = null
    this._digestBuild = null
    this._sourceReady = false
    this._sourceFatal = null
    this._started = false
    this._startFlight = null
    this._stopFlight = null
    this._stopProgress = Object.create(null)
    this._shutdownRequested = false
    this._stopped = false
    this._firstSnapshotSettled = false
    this._firstSnapshot = new Promise(resolve => { this._resolveFirstSnapshot = resolve })
    this._shutdownSignal = new Promise(resolve => { this._resolveShutdownSignal = resolve })
    this._onRegistryChange = change => this._registryChanged(change)
  }

  get publishedSnapshot () {
    return this.store.publishedSnapshot
  }

  get stopped () {
    return this._stopped
  }

  beginShutdown () {
    if (this._shutdownRequested) return false
    this._shutdownRequested = true
    this._settleFirstSnapshot({ available: false, stopped: true })
    this._resolveShutdownSignal()
    // CompletionScheduler.stop() installs its no-new-work fence synchronously,
    // before awaiting an already-owned pass. The terminal stop path below
    // performs the actual drain.
    this._sourceScheduler?.stop().catch(() => {})
    this._digestScheduler?.stop().catch(() => {})
    this._inboundSweepScheduler?.stop().catch(() => {})
    this._actionScheduler?.stop().catch(() => {})
    for (const fallback of this._legacyTimers.values()) {
      fallback.resolved = true
      if (fallback.timer !== null) this._clearTimer(fallback.timer)
    }
    this._legacyTimers.clear()
    return true
  }

  start () {
    if (this._stopped || this._shutdownRequested) {
      return Promise.reject(new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog controller is shutting down'))
    }
    if (this._startFlight !== null) return this._startFlight
    if (this._started) return this._firstSnapshot
    const operation = this._start()
    this._startFlight = operation
    // Retain one successful completion authority for the controller lifetime.
    // A rejected attempt releases only that authority so a fenced retry can
    // deterministically rebuild unresolved startup state.
    operation.then(() => {}, () => {
      if (this._startFlight === operation) this._startFlight = null
    })
    return operation
  }

  async _start () {
    const ready = Promise.resolve().then(() => this.stageFactory.ready()).then(
      () => ({ ready: true }),
      error => ({ ready: false, error })
    )
    const gate = await Promise.race([
      ready,
      this._shutdownSignal.then(() => ({ ready: false, shutdown: true }))
    ])
    if (gate.shutdown || this._shutdownRequested) return this._firstSnapshot
    if (gate.error) throw gate.error
    if (this._stopped) throw new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog controller stopped during start')

    this.outbound = new AppCatalogOutboundManager({
      store: this.store,
      keyPair: this.keyPair,
      sendPage: (peer, page) => this._sendOutboundPage(peer, page),
      sendAbort: (peer, abort) => this._sendOutboundAbort(peer, abort),
      onSessionReady: (peer, _session, event) => {
        if (event?.reason !== 'history-expired') return
        const state = this.channels.get(peer)
        if (state?.ready && !state.closed) this._pump(state)
      },
      stopDrainTimeoutMs: this.sweepIntervalMs
    })
    this.inbound = new AppCatalogInboundManager({
      keyPair: this.keyPair,
      stageFactory: this.stageFactory,
      onComplete: completed => this._catalogCommitted(completed),
      onActionError: err => this._report(err, 'inbound-action')
    })

    if (typeof this.appRegistry.setCatalogIngressValidator === 'function') {
      this.appRegistry.setCatalogIngressValidator(assertAppRegistryCatalogIngress)
    }
    this.appRegistry.on('change', this._onRegistryChange)

    this._sourceScheduler = new CompletionScheduler({
      name: 'app-catalog-source',
      intervalMs: this.sourceIntervalMs,
      run: () => this._advanceSource()
    })
    this._digestScheduler = new CompletionScheduler({
      name: 'app-catalog-digest',
      intervalMs: this.sourceIntervalMs,
      run: () => this._advanceDigest()
    })
    this._inboundSweepScheduler = new CompletionScheduler({
      name: 'app-catalog-inbound-expiry',
      intervalMs: this.sweepIntervalMs,
      run: async () => ({ complete: true, expired: await this.inbound.sweep() })
    })
    this._actionScheduler = new CompletionScheduler({
      name: 'app-catalog-actions',
      intervalMs: this.sourceIntervalMs,
      run: () => this._advanceAction()
    })
    if (this._shutdownRequested || this._stopped) return this._firstSnapshot
    this._started = true
    this._sourceScheduler.start()
    this._digestScheduler.start({ immediate: false })
    this._inboundSweepScheduler.start({ immediate: false })
    this._actionScheduler.start({ immediate: false })
    if (this._shutdownRequested || this._stopped) {
      this.beginShutdown()
      return this._firstSnapshot
    }
    return this._firstSnapshot
  }

  attach (connection, authenticatedRemotePubkey) {
    if (!this._started || this._shutdownRequested || this._stopped || !this.outbound || !this.inbound) return null
    const peer = peerHex(authenticatedRemotePubkey)
    // A retained pointer removal and a new stage for the same authenticated
    // peer must never race. The transport can reconnect after the bounded
    // removal flight settles.
    if (this._peerRemovalFlights.has(peer)) {
      this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog peer cleanup is still settling'), 'attach', peer)
      return null
    }
    if (this.channels.has(peer)) {
      this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'one catalog channel per authenticated peer'), 'attach', peer)
      return null
    }
    // Negotiating channels retain a nonce, timer and channel state before a
    // manager session exists, so enforce the peer cap before allocating them.
    if (this.channels.size >= APP_CATALOG_LIMITS.maxInboundPeers) {
      this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog channel peer cap reached'), 'attach', peer)
      return null
    }
    const state = {
      peer,
      api: null,
      ready: false,
      closeAfterDrain: false,
      abortCloseTimer: null,
      closed: false
    }
    const api = attachAppCatalogPagedChannel(connection, {
      keyPair: this.keyPair,
      remotePubkey: peer,
      onReady: channel => this._channelReady(state, channel),
      onPage: (page, channel) => this._receivePage(state, page, channel),
      onAck: (ack, channel) => this._receiveAck(state, ack, channel),
      onAbort: abort => this._receiveAbort(state, abort),
      onDrain: () => this._channelDrained(state),
      onProtocolError: err => this._report(err, 'channel', peer),
      onClose: () => this._channelClosed(state)
    })
    if (!api) return null
    state.api = api
    if (state.closed) return null
    this.channels.set(peer, state)
    return api
  }

  scheduleLegacyFallback (remotePubkey, send) {
    const peer = peerHex(remotePubkey)
    this.cancelLegacyFallback(peer)
    if (this._shutdownRequested || this._stopped || typeof send !== 'function') return false
    const fallback = { peer, send, timer: null, resolved: false }
    const timer = this._setTimer(() => this._resolveLegacyFallback(peer), APP_CATALOG_LIMITS.negotiationTimeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
    fallback.timer = timer
    this._legacyTimers.set(peer, fallback)
    return true
  }

  cancelLegacyFallback (remotePubkey) {
    const peer = peerHex(remotePubkey)
    const fallback = this._legacyTimers.get(peer)
    if (!fallback) return false
    this._legacyTimers.delete(peer)
    fallback.resolved = true
    if (fallback.timer !== null) this._clearTimer(fallback.timer)
    return true
  }

  _resolveLegacyFallback (remotePubkey) {
    const peer = peerHex(remotePubkey)
    const fallback = this._legacyTimers.get(peer)
    if (!fallback || fallback.resolved) return false
    this._legacyTimers.delete(peer)
    fallback.resolved = true
    if (fallback.timer !== null) this._clearTimer(fallback.timer)
    const state = this.channels.get(peer)
    if (this._shutdownRequested || this._stopped || state?.ready) return false
    try {
      const result = fallback.send()
      if (result?.reason && this.onLegacyFallback) this.onLegacyFallback({ peer, reason: result.reason })
      return true
    } catch (err) {
      this._report(err, 'legacy-fallback', peer)
      return false
    }
  }

  legacyEnvelope (catalogTimestamp = Date.now()) {
    const snapshot = this.store.publishedSnapshot
    let apps
    if (this._sourceFatal || !snapshot || snapshot.entryCount > APP_CATALOG_LIMITS.maxLegacyEntries) {
      // A fixed 129-element sentinel reaches the helper's exact overbound path
      // without materializing any live population.
      apps = new Array(APP_CATALOG_LIMITS.maxLegacyEntries + 1).fill(null)
    } else {
      try {
        const page = this.store.readSnapshotPage({
          highWater: snapshot.highWater,
          cursor: null,
          limit: APP_CATALOG_LIMITS.maxLegacyEntries
        })
        apps = page.rows.map(catalogRowToLegacyApp)
      } catch (err) {
        if (err?.code !== 'HISTORY_EXPIRED') throw err
        apps = new Array(APP_CATALOG_LIMITS.maxLegacyEntries + 1).fill(null)
      }
    }
    return createLegacyCatalogEnvelope({ apps, keyPair: this.keyPair, catalogTimestamp })
  }

  readExternalPage (opts = {}) {
    return this.store.readExternalPage({ ...opts, keyPair: this.keyPair })
  }

  status () {
    const snapshot = this.store.publishedSnapshot
    return Object.freeze({
      ready: snapshot !== null && this._sourceFatal === null,
      sourceFatal: this._sourceFatal ? { ...this._sourceFatal } : null,
      lastCatalogRevision: this.store.lastCatalogRevision,
      entries: this.store.size,
      excludedRows: this.store.excludedRows,
      publishedHighWater: snapshot?.highWater ?? null,
      snapshotId: snapshot?.snapshotId ?? null,
      outboundPeers: this.outbound?.sessions.size || 0,
      inboundPeers: this.inbound?.sessions.size || 0,
      inboundStagingBytes: this.inbound?.stagingBytes || 0,
      storageFault: this.stageFactory.storageFault === true,
      channels: this.channels.size,
      actionQueue: this._actionQueue.size,
      sourceScheduler: this._sourceScheduler?.snapshot() || null,
      digestScheduler: this._digestScheduler?.snapshot() || null,
      inboundSweepScheduler: this._inboundSweepScheduler?.snapshot() || null,
      actionScheduler: this._actionScheduler?.snapshot() || null
    })
  }

  stop () {
    if (this._stopFlight !== null) return this._stopFlight
    const operation = this._stop()
    const flight = operation.catch(err => {
      if (this._stopFlight === flight) this._stopFlight = null
      throw err
    })
    this._stopFlight = flight
    return flight
  }

  async _stop () {
    const progress = this._stopProgress
    const failures = []
    const attempt = async (key, operation) => {
      if (progress[key] === true) return null
      try {
        await operation()
        progress[key] = true
        return null
      } catch (err) {
        return err
      }
    }
    const retain = (err) => {
      if (err) failures.push(err)
    }

    retain(await attempt('fence', async () => {
      this.beginShutdown()
      this._stopped = true
    }))
    retain(await attempt('registryListener', async () => {
      this.appRegistry.removeListener('change', this._onRegistryChange)
    }))
    retain(await attempt('registryValidator', async () => {
      if (typeof this.appRegistry.setCatalogIngressValidator === 'function') {
        this.appRegistry.setCatalogIngressValidator(null)
      }
    }))
    retain(await attempt('legacyTimers', async () => {
      for (const fallback of this._legacyTimers.values()) {
        fallback.resolved = true
        if (fallback.timer !== null) this._clearTimer(fallback.timer)
      }
      this._legacyTimers.clear()
    }))

    const schedulerErrors = await Promise.all([
      attempt('sourceScheduler', () => this._sourceScheduler?.stop()),
      attempt('digestScheduler', () => this._digestScheduler?.stop()),
      attempt('inboundSweepScheduler', () => this._inboundSweepScheduler?.stop()),
      attempt('actionScheduler', () => this._actionScheduler?.stop())
    ])
    for (const err of schedulerErrors) retain(err)

    retain(await attempt('localOwners', async () => {
      if (this._digestBuild) this._digestBuild.close()
      this._digestBuild = null
      for (const action of this._actionQueue.values()) this._retireAction(action)
      this._actionQueue.clear()
    }))

    retain(await attempt('channels', async () => {
      const channelCloses = []
      for (const state of this.channels.values()) {
        this._closeChannel(state)
        if (state.api?.closed && typeof state.api.closed.then === 'function') {
          channelCloses.push(state.api.closed)
        }
      }
      // `closed` settles only after the channel's serialized message tail and
      // controller onClose have both drained. Never tear down inbound staging
      // concurrently with an append/commit still owned by that tail.
      const channelResults = await Promise.allSettled(channelCloses)
      const closeResults = await Promise.allSettled([...this._closeFlights])
      const rejected = [...channelResults, ...closeResults].find(result => result.status === 'rejected')
      if (rejected) throw rejected.reason
    }))

    // Both managers get a best-effort stop attempt even when the other one
    // rejects. A successful owner is never invoked again; only the unresolved
    // owner is retried by the next shared stop authority.
    const managerErrors = await Promise.all([
      attempt('outboundManager', () => this.outbound?.stop()),
      attempt('inboundManager', () => this.inbound?.stop())
    ])
    for (const err of managerErrors) retain(err)

    retain(await attempt('notifications', async () => {
      while (this._notificationFlights.size > 0) {
        await Promise.allSettled([...this._notificationFlights])
      }
    }))
    retain(await attempt('releases', () => this._drainCatalogReleases()))
    retain(await attempt('stageFactory', () => this.stageFactory.stop()))
    retain(await attempt('store', () => this.store.stop()))
    retain(await attempt('populationConsumer', async () => {
      if (typeof this.appRegistry.releasePopulationConsumer === 'function') {
        this.appRegistry.releasePopulationConsumer('p2p-catalog')
      }
    }))
    this._settleFirstSnapshot({ available: false, stopped: true })

    if (failures.length > 0) throw failures[0]
    this.channels.clear()
  }

  _registryChanged (change) {
    if (this._shutdownRequested || this._stopped || !change || typeof change.appKey !== 'string') return
    try {
      let result
      if (change.type === 'delete') result = { changed: this.store.delete(change.appKey) }
      else if (change.entry) result = this.store.put(change.appKey, appRegistryCatalogSource(change.appKey, change.entry))
      else return
      const recovered = this._sourceFatal?.sourceKey === change.appKey
      if (recovered) {
        // The failed page may have contained later entries we deliberately did
        // not skip. Re-register from BEGIN before allowing another digest.
        this._sourceFatal = null
        this._sourceReady = false
        if (this._digestBuild) this._digestBuild.close()
        this._digestBuild = null
        this.appRegistry.releasePopulationConsumer('p2p-catalog')
      } else if (result.changed !== false) {
        this._digestScheduler?.trigger('registry-change')
      }
      this._sourceScheduler?.trigger('registry-change')
    } catch (err) {
      this._recordSourceFatal(change.appKey, err)
    }
  }

  _advanceSource () {
    if (this._shutdownRequested || this._stopped) return { complete: true, stopped: true }
    if (this._sourceFatal) return { complete: true, fatal: this._sourceFatal.code }
    const page = this.appRegistry.page('p2p-catalog', this.sourceBudget)
    let changed = false
    for (const item of page.entries) {
      try {
        const result = this.store.put(item.key, appRegistryCatalogSource(item.key, item.value))
        if (result.changed !== false) changed = true
      } catch (err) {
        this._recordSourceFatal(item.key, err)
        return { complete: true, fatal: this._sourceFatal.code, examined: page.examined }
      }
    }
    if (page.complete) this._sourceReady = true
    if (this._sourceReady && (changed || this.store.publishedSnapshot === null)) {
      this._digestScheduler?.trigger('source')
    }
    return page
  }

  _advanceDigest () {
    if (this._shutdownRequested || this._stopped || !this._sourceReady || this._sourceFatal) return { complete: true }
    const published = this.store.publishedSnapshot
    if (!this._digestBuild && published && published.highWater === this.store.lastCatalogRevision) {
      return { complete: true, highWater: published.highWater }
    }
    if (!this._digestBuild) {
      this._digestBuild = this.store.beginDigest({ senderPubkey: this.localPubkey, budget: this.digestBudget })
    }
    let result
    try {
      result = this._digestBuild.step()
    } catch (err) {
      this._digestBuild.close()
      this._digestBuild = null
      if (err?.code === 'HISTORY_EXPIRED') return { complete: false, restarted: true }
      this._report(err, 'digest')
      throw err
    }
    if (!result.done) return { complete: false, examined: result.examined }
    const snapshot = result.snapshot
    this._digestBuild = null
    this._snapshotPublished(snapshot)
    return {
      complete: snapshot.highWater === this.store.lastCatalogRevision,
      highWater: snapshot.highWater,
      snapshot
    }
  }

  _snapshotPublished (snapshot) {
    if (this._shutdownRequested || this._stopped) return
    this._settleFirstSnapshot({ available: true, snapshot })
    for (const state of this.channels.values()) {
      if (!state.ready || state.closed) continue
      try {
        const existing = this.outbound.sessions.get(state.peer) || null
        this.outbound.open(state.peer, snapshot)
        // open() marks an active older session dirty. Its one outstanding PAGE
        // remains governed only by the ACK deadline/retry counter; publishing a
        // newer digest must never manufacture an unaccounted retransmit.
        if (!existing || existing.closed) this._pump(state)
      } catch (err) {
        this._report(err, 'snapshot-publish', state.peer)
      }
    }
  }

  _channelReady (state, api) {
    if (this._shutdownRequested || this._stopped || state.closed || this.channels.get(state.peer) !== state) return
    state.ready = true
    this.cancelLegacyFallback(state.peer)
    if (this._sourceFatal) {
      const code = this._sourceFatal.code === 'CATALOG_ENTRY_TOO_LARGE'
        ? 'CATALOG_ENTRY_TOO_LARGE'
        : 'PROTOCOL_ERROR'
      const abort = createAppCatalogAbort({
        receiverPubkey: state.peer,
        snapshotId: ZERO_SNAPSHOT_ID,
        code
      }, this.keyPair)
      this._sendAbortBeforeClose(state, abort)
      return
    }
    try {
      this.outbound.open(state.peer)
      this._pump(state)
    } catch (err) {
      this._report(err, 'channel-ready', state.peer)
      const abort = createAppCatalogAbort({
        receiverPubkey: state.peer,
        snapshotId: this.store.publishedSnapshot?.snapshotId || ZERO_SNAPSHOT_ID,
        code: errorCode(err, 'SNAPSHOT_MISMATCH') === 'CATALOG_ENTRY_TOO_LARGE'
          ? 'CATALOG_ENTRY_TOO_LARGE'
          : 'SNAPSHOT_MISMATCH'
      }, this.keyPair)
      this._sendAbortBeforeClose(state, abort)
    }
  }

  async _receivePage (state, page, api) {
    if (this._shutdownRequested || this._stopped) {
      this._sendAbortBeforeClose(state, createAppCatalogAbort({
        receiverPubkey: state.peer,
        snapshotId: page.snapshotId,
        code: 'RESOURCE_LIMIT'
      }, this.keyPair))
      return
    }
    try {
      const removal = this._peerRemovalFlights.get(state.peer)
      if (removal) await removal
      if (this._shutdownRequested || this._stopped || state.closed) return
      const ack = await this.inbound.receivePage(state.peer, page)
      api.sendAck(ack)
    } catch (err) {
      if (err?.abort) {
        this._report(err, 'inbound-page', state.peer)
        this._sendAbortBeforeClose(state, err.abort)
        return
      }
      throw err
    }
  }

  _receiveAck (state, ack) {
    if (this._shutdownRequested || this._stopped) return
    const result = this.outbound.acceptAck(state.peer, ack)
    if (result.status === 'advanced' || result.status === 'complete') this._pump(state)
  }

  async _receiveAbort (state, abort) {
    let accepted = false
    let outboundStatus = 'missing'
    if (typeof this.outbound.acceptAbort === 'function') {
      const result = this.outbound.acceptAbort(state.peer, abort)
      outboundStatus = result?.status || 'missing'
      accepted = outboundStatus === 'closed' || outboundStatus === 'duplicate'
    }
    const inbound = this.inbound.sessions.get(state.peer)
    if (inbound && (inbound.snapshot === null || inbound.snapshot.snapshotId === abort.snapshotId)) {
      await this.inbound.receiveAbort(state.peer, abort)
      accepted = true
    }
    if (!accepted) {
      if (outboundStatus === 'stopped' && (this._shutdownRequested || this._stopped)) return
      throw new AppCatalogProtocolError('SNAPSHOT_MISMATCH', 'ABORT does not own an exact verified catalog session')
    }
  }

  _pump (state) {
    if (this._shutdownRequested || this._stopped || !state.ready || state.closed || !state.api) return false
    const session = this.outbound.sessions.get(state.peer)
    if (!session || session.closed) return false
    const issued = session.issuePage()
    if (issued.abort) return true // manager sendAbort owns delivery exactly once
    state.api.sendPage(issued.page)
    return true
  }

  _sendOutboundPage (remotePubkey, page) {
    const state = this.channels.get(remotePubkey)
    if (!state?.ready || state.closed) throw new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog channel is unavailable')
    state.api.sendPage(page) // false is accepted backpressure, not failure
  }

  _sendOutboundAbort (remotePubkey, abort) {
    const state = this.channels.get(remotePubkey)
    if (!state?.ready || state.closed) throw new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog channel is unavailable')
    state.api.sendAbort(abort) // false is accepted backpressure, not failure
  }

  _sendAbortBeforeClose (state, abort) {
    if (state.closed || state.closeAfterDrain) return false
    try {
      state.closeAfterDrain = true
      state.api.sendAbort(abort)
      if (state.api.drained) Promise.resolve().then(() => this._closeChannel(state))
      else {
        const timer = this._setTimer(() => {
          if (state.abortCloseTimer === timer) state.abortCloseTimer = null
          this._closeChannel(state)
        }, this.abortDrainTimeoutMs)
        if (typeof timer?.unref === 'function') timer.unref()
        state.abortCloseTimer = timer
      }
      return true
    } catch {
      this._closeChannel(state)
      return false
    }
  }

  _channelDrained (state) {
    if (state.closeAfterDrain) this._closeChannel(state)
  }

  _closeChannel (state) {
    if (state.closed) return
    if (state.abortCloseTimer != null) {
      this._clearTimer(state.abortCloseTimer)
      state.abortCloseTimer = null
    }
    try { state.api?.close() } catch {}
  }

  async _channelClosed (state) {
    if (state.closed) return
    if (state.abortCloseTimer != null) {
      this._clearTimer(state.abortCloseTimer)
      state.abortCloseTimer = null
    }
    state.closed = true
    const operation = (async () => {
      if (state.ready) this.cancelLegacyFallback(state.peer)
      else this._resolveLegacyFallback(state.peer)
      await this.inbound.closePeer(state.peer)
      this.outbound.closePeer(state.peer)
      if (this.channels.get(state.peer) === state) this.channels.delete(state.peer)
      this._maybeRemoveCommittedPeer(state.peer)
    })()
    this._closeFlights.add(operation)
    try {
      await operation
    } finally {
      this._closeFlights.delete(operation)
    }
  }

  _catalogCommitted (completed) {
    if (this._shutdownRequested || this._stopped) return
    const peer = peerHex(completed?.snapshot?.senderPubkey)
    let actionCatalog = null
    if (this.onCatalogActionPage) {
      if (typeof completed.catalog?.acquire !== 'function') {
        this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'committed catalog handle cannot be acquired'), 'catalog-action', peer)
        return
      }
      try {
        actionCatalog = completed.catalog.acquire()
      } catch (err) {
        this._report(err, 'catalog-action-acquire', peer)
        return
      }
      if (!actionCatalog || typeof actionCatalog.readPage !== 'function' || typeof actionCatalog.release !== 'function') {
        this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'acquired catalog handle is incomplete'), 'catalog-action-acquire', peer)
        if (typeof actionCatalog?.release === 'function') {
          this._actionRefs.set(peer, (this._actionRefs.get(peer) || 0) + 1)
          this._releaseAction({ peerPubkey: peer, catalog: actionCatalog, released: false })
        }
        return
      }
      // Publish ownership before retiring a prior generation. Even a
      // synchronously-settling prior release must observe the replacement ref.
      this._actionRefs.set(peer, (this._actionRefs.get(peer) || 0) + 1)
    }
    if (this.onCatalogComplete) {
      try {
        // The inbound session owns and releases `completed.catalog` as soon as
        // this callback returns. Notifications expose immutable metadata only;
        // the action queue above owns its distinct acquired reader.
        const notification = Promise.resolve(this.onCatalogComplete(Object.freeze({
          peerPubkey: peer,
          snapshot: completed.snapshot
        })))
          .catch(err => this._report(err, 'catalog-complete', peer))
          .finally(() => this._notificationFlights.delete(notification))
        this._notificationFlights.add(notification)
      } catch (err) {
        this._report(err, 'catalog-complete', peer)
      }
    }
    if (!this.onCatalogActionPage) return
    const previous = this._actionQueue.get(peer)
    if (previous) {
      this._actionQueue.delete(peer)
      this._retireAction(previous)
    } else if (this._actionQueue.size >= APP_CATALOG_LIMITS.maxInboundPeers) {
      // Preserve the one in-flight action and evict the oldest queued peer.
      // This bounds unique completed/disconnected peer churn at 256.
      let eviction = null
      for (const candidate of this._actionQueue.values()) {
        if (!candidate.inFlight) {
          eviction = candidate
          break
        }
      }
      if (eviction === null) eviction = this._actionQueue.values().next().value || null
      if (eviction !== null) {
        if (this._actionQueue.get(eviction.peerPubkey) === eviction) {
          this._actionQueue.delete(eviction.peerPubkey)
        }
        this._retireAction(eviction)
      }
    }
    const action = {
      generation: this._nextActionGeneration,
      peerPubkey: peer,
      snapshot: completed.snapshot,
      catalog: actionCatalog,
      cursor: null,
      remainingActions: this.actionLimit,
      inFlight: false,
      retired: false,
      released: false
    }
    this._nextActionGeneration = this._nextActionGeneration === Number.MAX_SAFE_INTEGER
      ? 1
      : this._nextActionGeneration + 1
    this._actionQueue.set(peer, action)
    this._actionScheduler?.trigger('catalog-complete')
  }

  async _advanceAction () {
    if (this._shutdownRequested || this._stopped || this._actionQueue.size === 0) return { complete: true }
    const peer = this._actionQueue.keys().next().value
    const action = this._actionQueue.get(peer)
    if (!action) return { complete: this._actionQueue.size === 0 }
    action.inFlight = true
    try {
      const page = await action.catalog.readPage({
        cursor: action.cursor,
        limit: APP_CATALOG_LIMITS.maxPageEntries
      })
      if (this._shutdownRequested || this._stopped || action.retired) {
        if (this._actionQueue.get(peer) === action) this._actionQueue.delete(peer)
        this._retireAction(action)
        return { complete: this._actionQueue.size === 0, fenced: true }
      }
      const result = await this.onCatalogActionPage(Object.freeze({
        peerPubkey: peer,
        snapshot: action.snapshot,
        entries: page.entries,
        cursor: action.cursor,
        nextCursor: page.cursor,
        complete: page.complete,
        remainingActions: action.remainingActions
      }))
      if (this._shutdownRequested || this._stopped || action.retired) {
        if (this._actionQueue.get(peer) === action) this._actionQueue.delete(peer)
        this._retireAction(action)
        return { complete: this._actionQueue.size === 0, fenced: true }
      }
      const acted = Number.isSafeInteger(result?.acted) && result.acted > 0
        ? Math.min(result.acted, action.remainingActions)
        : 0
      action.remainingActions -= acted
      action.cursor = page.cursor
      if (this._actionQueue.get(peer) === action) {
        this._actionQueue.delete(peer)
        if (!page.complete && action.remainingActions > 0 && result?.stop !== true) {
          // Rotate after one bounded page so a large catalog cannot starve the
          // other at-most-255 committed peers.
          this._actionQueue.set(peer, action)
        } else {
          this._retireAction(action)
        }
      }
    } catch (err) {
      if (this._actionQueue.get(peer) === action) {
        this._actionQueue.delete(peer)
        this._retireAction(action)
      }
      this._report(err, 'catalog-action', peer)
    } finally {
      action.inFlight = false
      if (action.retired) this._releaseAction(action)
    }
    return { complete: this._actionQueue.size === 0 }
  }

  _retireAction (action) {
    if (!action || action.retired) return
    action.retired = true
    if (!action.inFlight) this._releaseAction(action)
  }

  _releaseAction (action) {
    // The disk-stage follow-up supplies an idempotent release hook for a
    // superseded committed snapshot. Keep the controller compatible with the
    // immutable baseline handle until that hook is integrated.
    if (action.released) return
    action.released = true
    const finish = removable => {
      const refs = this._actionRefs.get(action.peerPubkey) || 0
      if (refs <= 1) this._actionRefs.delete(action.peerPubkey)
      else this._actionRefs.set(action.peerPubkey, refs - 1)
      if (removable) this._maybeRemoveCommittedPeer(action.peerPubkey)
    }
    let release
    try { release = action.catalog.release() } catch (err) {
      this._report(err, 'catalog-release', action.peerPubkey)
      finish(false)
      return
    }
    let released = true
    const flight = Promise.resolve(release).then(result => {
      if (result === false) {
        released = false
        this._report(new AppCatalogProtocolError('RESOURCE_LIMIT', 'acquired catalog handle was already released'), 'catalog-release', action.peerPubkey)
      }
    }).catch(err => {
      released = false
      this._report(err, 'catalog-release', action.peerPubkey)
    }).finally(() => {
      this._releaseFlights.delete(flight)
      finish(released)
    })
    this._releaseFlights.add(flight)
  }

  _maybeRemoveCommittedPeer (peer) {
    if (this._actionRefs.has(peer) || this._peerRemovalFlights.has(peer)) return false
    const inbound = this.inbound?.sessions?.get(peer)
    if (inbound && !inbound.closed) return false
    if (typeof this.stageFactory.removeCommittedPeer !== 'function') return false
    const flight = Promise.resolve().then(() => {
      // Recheck after every release/connection callback in this turn has had
      // an opportunity to publish a replacement ref or active inbound stage.
      if (this._actionRefs.has(peer)) return false
      const currentInbound = this.inbound?.sessions?.get(peer)
      if (currentInbound && !currentInbound.closed) return false
      return this.stageFactory.removeCommittedPeer(peer)
    }).catch(err => {
      this._report(err, 'catalog-peer-remove', peer)
      return false
    }).finally(() => {
      this._peerRemovalFlights.delete(peer)
      this._releaseFlights.delete(flight)
    })
    this._peerRemovalFlights.set(peer, flight)
    this._releaseFlights.add(flight)
    return true
  }

  async _drainCatalogReleases () {
    while (this._releaseFlights.size > 0) {
      await Promise.allSettled([...this._releaseFlights])
    }
  }

  _recordSourceFatal (sourceKey, err) {
    this._sourceFatal = Object.freeze({
      sourceKey,
      code: errorCode(err),
      error: err instanceof Error ? err.message : String(err)
    })
    this._settleFirstSnapshot({ available: false, fatal: this._sourceFatal })
    this._report(err, 'source', sourceKey)
  }

  _settleFirstSnapshot (value) {
    if (this._firstSnapshotSettled) return
    this._firstSnapshotSettled = true
    this._resolveFirstSnapshot(Object.freeze(value))
  }

  _report (err, phase, peer = null) {
    if (!this.onError) return
    try { this.onError(Object.freeze({ phase, peer, error: err })) } catch {}
  }
}
