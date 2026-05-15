/**
 * Seeding Registry
 *
 * Distributed multi-log registry of seed requests.
 * Each relay has its own append-only local log; peers exchange log keys over
 * a lightweight Protomux metadata channel and replicate/index each other's logs.
 */

import b4a from 'b4a'
import sodium from 'sodium-universal'
import Protomux from 'protomux'
import { EventEmitter } from 'events'
import {
  isValidHexKey,
  normalizeAvailabilityClass,
  normalizeContentType,
  normalizePrivacyTier,
  normalizeStorageClass
} from '../constants.js'
import { isAbortError } from '../relay-node/lifecycle-scope.js'
import {
  computeReceiptRoot,
  createCustodyCommit,
  createCustodyExpiryWitness,
  createCustodyIntent,
  createCustodyNonServingProof,
  createCustodyProof,
  createCustodyReceipt,
  createSourceRetired,
  summarizeCustodyStatus,
  validateCustodyTransition,
  verifyCustodyEntry
} from '../custody-signing.js'

// Well-known topic for registry discovery
const REGISTRY_TOPIC = b4a.alloc(32)
sodium.crypto_generichash(REGISTRY_TOPIC, b4a.from('hiverelay-seeding-registry-v1'))

const MSG_ANNOUNCE_LOG = 0
const REGISTRY_META_PROTOCOL = 'hiverelay-registry-meta'
const REGISTRY_META_ID = b4a.from('registry-meta-v1')
const MAX_DISCOVERY_KEYS = 128
const MAX_REGISTRY_ENTRY_BYTES = 64 * 1024
const MAX_ENTRY_FUTURE_SKEW_MS = 10 * 60 * 1000
const MAX_ENTRY_AGE_MS = 180 * 24 * 60 * 60 * 1000

const META_ENCODING = {
  preencode (state, msg) {
    const json = JSON.stringify(msg)
    state.end += 4 + b4a.byteLength(json)
  },
  encode (state, msg) {
    const json = JSON.stringify(msg)
    const buf = b4a.from(json)
    state.buffer.writeUInt32BE(buf.length, state.start)
    buf.copy(state.buffer, state.start + 4)
    state.start += 4 + buf.length
  },
  decode (state) {
    const len = state.buffer.readUInt32BE(state.start)
    if (len > 64 * 1024) {
      state.start += 4 + len
      return { type: -1, error: 'message too large' }
    }
    const json = state.buffer.subarray(state.start + 4, state.start + 4 + len).toString()
    state.start += 4 + len
    try {
      return JSON.parse(json)
    } catch (_) {
      return { type: -1, error: 'malformed JSON' }
    }
  }
}

export class SeedingRegistry extends EventEmitter {
  constructor (store, swarm, opts = {}) {
    super()
    this.store = store
    this.swarm = swarm
    this.localLog = null
    this.peerLogs = new Map() // logKey hex -> Hypercore
    this.running = false

    // In-memory indexes rebuilt from logs
    this._requests = new Map() // appKey -> latest seed-request entry
    this._acceptances = new Map() // appKey -> [{ relayPubkey, region, timestamp }]
    this._cancellations = new Map() // appKey:publisherPubkey -> cancellation timestamp
    this._custodyIntents = new Map() // intentId -> custody-intent
    this._custodyReceipts = new Map() // intentId -> Map(relayPubkey -> custody-receipt)
    this._custodyCommits = new Map() // intentId -> custody-commit
    this._sourceRetirements = new Map() // intentId -> source-retired
    this._custodyProofs = new Map() // intentId -> custody-proof[]
    this._custodyNonServingProofs = new Map() // intentId -> custody-non-serving-proof[]
    this._custodyExpiryWitnesses = new Map() // intentId -> custody-expiry-witness[]
    this._custodyStatusCache = new Map()

    this._indexedOffsets = new Map() // logId -> indexed block count
    this._peerLogMeta = new Map() // logKeyHex -> { log, onAppend }
    this._metaChannels = new WeakMap() // conn -> { channel, msgHandler }
    this._onSwarmConnection = null
    this._onLocalAppend = null
    this._maxPeerLogs = Number.isFinite(opts.maxPeerLogs) && opts.maxPeerLogs > 0
      ? Math.floor(opts.maxPeerLogs)
      : 256
    this._maxLogsPerPeer = Number.isFinite(opts.maxLogsPerPeer) && opts.maxLogsPerPeer > 0
      ? Math.floor(opts.maxLogsPerPeer)
      : 4
    // Optional LifecycleScope from the owning RelayNode — used so
    // _indexLog can short-circuit on stop() instead of running its
    // for-loop's next `log.get(i)` against a freshly-closed core. See
    // STALE-REF-INVENTORY.md vector A3 and CANCELLATION-CONTRACT.md.
    this._scope = opts.scope || null
  }

  async start () {
    // Create local log for this node's registry entries
    this.localLog = this.store.get({ name: 'seeding-registry-local' })
    await this.localLog.ready()

    const localLogKeyHex = b4a.toString(this.localLog.key, 'hex')

    // Rebuild index from local log
    await this._indexLog(this.localLog, localLogKeyHex)
    this._onLocalAppend = () => {
      // Track in the LifecycleScope so RelayNode.stop()'s drain awaits
      // any in-flight indexing before closing the localLog. AbortError
      // is the normal exit path during stop() — swallow it silently.
      const promise = this._indexLog(this.localLog, localLogKeyHex).catch((err) => {
        if (isAbortError(err)) return
        this.emit('index-error', { context: 'local-append', error: err.message || String(err) })
      })
      if (this._scope) this._scope.tracked(promise)
    }
    this.localLog.on('append', this._onLocalAppend)

    // Join DHT topic to discover other registry peers
    this.swarm.join(REGISTRY_TOPIC, { server: true, client: true })

    // Listen for new connections to exchange registry log keys and replicate logs
    this._onSwarmConnection = (conn, info) => this._onConnection(conn, info)
    this.swarm.on('connection', this._onSwarmConnection)

    this.running = true
    this.emit('started', {
      key: localLogKeyHex
    })
  }

  _onConnection (conn, info) {
    if (!this.localLog) return

    // Always replicate our local log
    this.localLog.replicate(conn)

    // Exchange log keys so peers can replicate/index each other's logs
    this._attachMetaChannel(conn, info)
  }

  _attachMetaChannel (conn, info) {
    if (this._metaChannels.has(conn)) return

    const mux = Protomux.from(conn)
    const channel = mux.createChannel({
      protocol: REGISTRY_META_PROTOCOL,
      id: REGISTRY_META_ID,
      onopen: () => {
        if (!this.localLog) return
        const entry = this._metaChannels.get(conn)
        if (!entry) return
        const localLogKeyHex = b4a.toString(this.localLog.key, 'hex')
        entry.msgHandler.send({
          type: MSG_ANNOUNCE_LOG,
          logKey: localLogKeyHex,
          peerPubkey: this.swarm?.keyPair?.publicKey
            ? b4a.toString(this.swarm.keyPair.publicKey, 'hex')
            : null
        })
      }
    })

    if (!channel) return

    const msgHandler = channel.addMessage({
      encoding: META_ENCODING,
      onmessage: (msg) => this._onMetaMessage(conn, info, msg)
    })

    this._metaChannels.set(conn, { channel, msgHandler })
    channel.open()
  }

  _onMetaMessage (conn, info, msg) {
    if (!msg || msg.type === -1) return
    if (msg.type !== MSG_ANNOUNCE_LOG) return
    if (!msg.logKey || typeof msg.logKey !== 'string') return
    if (!isValidHexKey(msg.logKey, 64)) return

    const transportPeerPubkey = info?.publicKey ? b4a.toString(info.publicKey, 'hex') : null
    const declaredPeerPubkey = typeof msg.peerPubkey === 'string' ? msg.peerPubkey.toLowerCase() : null

    if (declaredPeerPubkey && transportPeerPubkey && declaredPeerPubkey !== transportPeerPubkey) {
      this.emit('peer-log-rejected', {
        logKey: msg.logKey,
        peerPubkey: declaredPeerPubkey,
        reason: 'declared peer pubkey mismatch'
      })
      return
    }

    const peerPubkey = transportPeerPubkey || declaredPeerPubkey
    if (!peerPubkey || !isValidHexKey(peerPubkey, 64)) {
      this.emit('peer-log-rejected', {
        logKey: msg.logKey,
        peerPubkey,
        reason: 'missing or invalid peer pubkey'
      })
      return
    }

    this._registerPeerLog(msg.logKey, peerPubkey, conn).catch((err) => {
      this.emit('peer-log-error', {
        logKey: msg.logKey,
        peerPubkey,
        error: err.message || String(err)
      })
    })
  }

  async _registerPeerLog (logKeyHex, peerPubkey, conn) {
    if (!this.localLog) return
    logKeyHex = typeof logKeyHex === 'string' ? logKeyHex.toLowerCase() : logKeyHex
    peerPubkey = typeof peerPubkey === 'string' ? peerPubkey.toLowerCase() : peerPubkey

    const localLogKeyHex = b4a.toString(this.localLog.key, 'hex')
    if (logKeyHex === localLogKeyHex) return

    // Already known: just ensure replication on this connection
    const existing = this._peerLogMeta.get(logKeyHex)
    if (existing) {
      existing.log.replicate(conn)
      return
    }

    if (this._peerLogMeta.size >= this._maxPeerLogs) {
      this.emit('peer-log-rejected', {
        logKey: logKeyHex,
        peerPubkey,
        reason: 'max peer logs reached'
      })
      return
    }

    let peerLogCount = 0
    for (const meta of this._peerLogMeta.values()) {
      if (meta.peerPubkey === peerPubkey) peerLogCount++
    }
    if (peerLogCount >= this._maxLogsPerPeer) {
      this.emit('peer-log-rejected', {
        logKey: logKeyHex,
        peerPubkey,
        reason: 'peer log quota reached'
      })
      return
    }

    const log = this.store.get(b4a.from(logKeyHex, 'hex'))
    await log.ready()
    log.replicate(conn)

    await this._indexLog(log, logKeyHex, peerPubkey)

    const onAppend = () => {
      const promise = this._indexLog(log, logKeyHex, peerPubkey).catch((err) => {
        if (isAbortError(err)) return
        this.emit('index-error', {
          context: 'peer-append',
          logKey: logKeyHex,
          peerPubkey,
          error: err.message || String(err)
        })
      })
      if (this._scope) this._scope.tracked(promise)
    }
    log.on('append', onAppend)

    this.peerLogs.set(logKeyHex, log)
    this._peerLogMeta.set(logKeyHex, { log, onAppend, peerPubkey })

    this.emit('peer-log-discovered', {
      logKey: logKeyHex,
      peerPubkey,
      blocks: log.length
    })
  }

  async _indexLog (log, logId = null, sourcePeerPubkey = null) {
    const id = logId || b4a.toString(log.key, 'hex')
    const scope = this._scope
    let offset = this._indexedOffsets.get(id) || 0
    const source = sourcePeerPubkey
      ? { peerPubkey: sourcePeerPubkey }
      : (this._peerLogMeta.get(id) || null)

    for (let i = offset; i < log.length; i++) {
      // Bail before each `log.get(i)` if stop() has begun — otherwise
      // the next get() runs against a closed core and throws (vector A3
      // in STALE-REF-INVENTORY.md). We also bail if the log itself
      // reports closing — defense in depth for the case where stop()
      // closed the log before draining the scope, e.g. shutdown
      // sequencing bug.
      if (scope && scope.aborted) {
        const err = new Error('Operation aborted')
        err.name = 'AbortError'
        err.code = 'ABORT_ERR'
        throw err
      }
      if (log.closed || log.closing) return

      try {
        const block = await log.get(i)
        if (!block) {
          offset = i + 1
          this._indexedOffsets.set(id, offset)
          continue
        }
        if (block.byteLength > MAX_REGISTRY_ENTRY_BYTES) {
          this.emit('entry-rejected', {
            reason: 'registry-entry-too-large',
            logId: id,
            index: i,
            bytes: block.byteLength
          })
          offset = i + 1
          this._indexedOffsets.set(id, offset)
          continue
        }
        const entry = JSON.parse(b4a.toString(block))
        this._applyEntry(entry, { logId: id, peerPubkey: source?.peerPubkey || null })
        offset = i + 1
        this._indexedOffsets.set(id, offset)
      } catch (err) {
        // Re-throw AbortError so callers (the listener wrappers) can
        // distinguish stop()-driven bail from a real index error.
        if (isAbortError(err)) throw err
        // Real index error — emit and continue. But check whether the
        // error is from a freshly-closed log (the symptom we're fixing):
        // if so, exit the loop instead of repeatedly hitting closed-core
        // errors on every remaining iteration.
        this.emit('index-error', { context: 'indexLog', logId: id, index: i, error: err.message || String(err) })
        if (log.closed || log.closing) return
        offset = i + 1
        this._indexedOffsets.set(id, offset)
      }
    }
  }

  _isPlausibleTimestamp (timestamp) {
    if (!Number.isFinite(timestamp) || timestamp <= 0) return false
    const now = Date.now()
    if (timestamp > (now + MAX_ENTRY_FUTURE_SKEW_MS)) return false
    if (timestamp < (now - MAX_ENTRY_AGE_MS)) return false
    return true
  }

  _normalizeIndexedEntry (entry, source = {}) {
    if (!entry || typeof entry !== 'object') return null
    if (!this._isPlausibleTimestamp(entry.timestamp)) return null

    if (
      entry.type === 'custody-intent' ||
      entry.type === 'custody-receipt' ||
      entry.type === 'custody-commit' ||
      entry.type === 'source-retired' ||
      entry.type === 'custody-proof' ||
      entry.type === 'custody-non-serving-proof' ||
      entry.type === 'custody-expiry-witness'
    ) {
      const verified = verifyCustodyEntry(entry)
      if (!verified.valid) {
        this.emit('custody-entry-rejected', {
          type: entry.type,
          intentId: entry.intentId || null,
          reason: verified.reason
        })
        return null
      }

      const custodyEntry = verified.entry
      if (source.peerPubkey) {
        const peer = source.peerPubkey.toLowerCase()
        if (custodyEntry.type === 'custody-receipt' && custodyEntry.relayPubkey !== peer) return null
        if (custodyEntry.type === 'custody-proof' && custodyEntry.observerPubkey !== peer) return null
        if (custodyEntry.type === 'custody-non-serving-proof' && custodyEntry.relayPubkey !== peer) return null
      }

      // Receipts can be validated as soon as their intent is known. Commits
      // and source-retirement checkpoints may arrive before all peer receipt
      // logs have synced, so we index their valid signatures and only mark
      // them effective inside getCustodyStatus() once quorum data is present.
      if (custodyEntry.type === 'custody-receipt') {
        const status = this.getCustodyStatus(custodyEntry.intentId)
        const transition = validateCustodyTransition(custodyEntry, status)
        if (!transition.valid) {
          this.emit('custody-entry-rejected', {
            type: custodyEntry.type,
            intentId: custodyEntry.intentId,
            reason: transition.reason
          })
          return null
        }
      }

      return custodyEntry
    }

    const appKey = typeof entry.appKey === 'string' ? entry.appKey.toLowerCase() : null
    if (!appKey || !isValidHexKey(appKey, 64)) return null

    if (entry.type === 'seed-request') {
      const publisherPubkey = typeof entry.publisherPubkey === 'string'
        ? entry.publisherPubkey.toLowerCase()
        : null
      if (!publisherPubkey || !isValidHexKey(publisherPubkey, 64)) return null

      const discoveryKeys = Array.isArray(entry.discoveryKeys)
        ? entry.discoveryKeys
          .filter(dk => typeof dk === 'string' && isValidHexKey(dk, 64))
          .slice(0, MAX_DISCOVERY_KEYS)
          .map(dk => dk.toLowerCase())
        : []

      return {
        ...entry,
        appKey,
        publisherPubkey,
        discoveryKeys,
        storageClass: normalizeStorageClass(entry.storageClass, entry.blind ? 'temporary' : 'persistent'),
        availabilityClass: normalizeAvailabilityClass(entry.availabilityClass, entry.blind ? 'atomic-handoff' : 'always-on')
      }
    }

    if (entry.type === 'seed-accept') {
      const relayPubkey = typeof entry.relayPubkey === 'string'
        ? entry.relayPubkey.toLowerCase()
        : null
      if (!relayPubkey || !isValidHexKey(relayPubkey, 64)) return null
      if (source.peerPubkey && relayPubkey !== source.peerPubkey.toLowerCase()) return null

      return {
        ...entry,
        appKey,
        relayPubkey
      }
    }

    if (entry.type === 'seed-cancel') {
      const publisherPubkey = typeof entry.publisherPubkey === 'string'
        ? entry.publisherPubkey.toLowerCase()
        : null
      if (!publisherPubkey || !isValidHexKey(publisherPubkey, 64)) return null

      return {
        ...entry,
        appKey,
        publisherPubkey
      }
    }

    return null
  }

  _applyEntry (entry, source = {}) {
    const normalized = this._normalizeIndexedEntry(entry, source)
    if (!normalized) {
      this.emit('entry-rejected', {
        reason: 'invalid-registry-entry',
        logId: source.logId || null
      })
      return
    }

    entry = normalized
    if (entry.type === 'seed-request') {
      const cancelKey = entry.appKey + ':' + entry.publisherPubkey
      const canceledAt = this._cancellations.get(cancelKey)
      if (canceledAt && canceledAt >= entry.timestamp) return

      const current = this._requests.get(entry.appKey)
      if (!current || current.timestamp <= entry.timestamp) {
        this._requests.set(entry.appKey, entry)
      }
      return
    }

    if (entry.type === 'seed-accept') {
      if (!this._acceptances.has(entry.appKey)) {
        this._acceptances.set(entry.appKey, [])
      }
      const list = this._acceptances.get(entry.appKey)
      const idx = list.findIndex(a => a.relayPubkey === entry.relayPubkey)
      if (idx === -1) {
        list.push(entry)
      } else if (list[idx].timestamp <= entry.timestamp) {
        list[idx] = entry
      }
      return
    }

    if (entry.type === 'seed-cancel') {
      const cancelKey = entry.appKey + ':' + entry.publisherPubkey
      const existingCancelTs = this._cancellations.get(cancelKey) || 0
      if (entry.timestamp > existingCancelTs) {
        this._cancellations.set(cancelKey, entry.timestamp)
      }

      const current = this._requests.get(entry.appKey)
      if (
        current &&
        current.publisherPubkey === entry.publisherPubkey &&
        current.timestamp <= entry.timestamp
      ) {
        this._requests.delete(entry.appKey)
      }
      return
    }

    if (entry.type === 'custody-intent') {
      const current = this._custodyIntents.get(entry.intentId)
      if (!current || current.timestamp <= entry.timestamp) {
        this._custodyIntents.set(entry.intentId, entry)
        this._invalidateCustodyStatus(entry.intentId)
      }
      return
    }

    if (entry.type === 'custody-receipt') {
      if (!this._custodyReceipts.has(entry.intentId)) {
        this._custodyReceipts.set(entry.intentId, new Map())
      }
      const receipts = this._custodyReceipts.get(entry.intentId)
      const current = receipts.get(entry.relayPubkey)
      if (!current || current.timestamp <= entry.timestamp) {
        receipts.set(entry.relayPubkey, entry)
        this._invalidateCustodyStatus(entry.intentId)
      }
      return
    }

    if (entry.type === 'custody-commit') {
      const current = this._custodyCommits.get(entry.intentId)
      if (!current || current.timestamp <= entry.timestamp) {
        this._custodyCommits.set(entry.intentId, entry)
        this._invalidateCustodyStatus(entry.intentId)
      }
      return
    }

    if (entry.type === 'source-retired') {
      const current = this._sourceRetirements.get(entry.intentId)
      if (!current) {
        this._sourceRetirements.set(entry.intentId, entry)
        this._invalidateCustodyStatus(entry.intentId)
      }
      return
    }

    if (entry.type === 'custody-proof') {
      if (!this._custodyProofs.has(entry.intentId)) {
        this._custodyProofs.set(entry.intentId, [])
      }
      const list = this._custodyProofs.get(entry.intentId)
      const key = `${entry.observerPubkey}:${entry.relayPubkey}:${entry.challengeNonce}`
      const idx = list.findIndex(p => `${p.observerPubkey}:${p.relayPubkey}:${p.challengeNonce}` === key)
      if (idx === -1) {
        list.push(entry)
        this._invalidateCustodyStatus(entry.intentId)
      } else if (list[idx].timestamp <= entry.timestamp) {
        list[idx] = entry
        this._invalidateCustodyStatus(entry.intentId)
      }
      return
    }

    if (entry.type === 'custody-non-serving-proof') {
      if (!this._custodyNonServingProofs.has(entry.intentId)) {
        this._custodyNonServingProofs.set(entry.intentId, [])
      }
      const list = this._custodyNonServingProofs.get(entry.intentId)
      const key = `${entry.relayPubkey}:${entry.challengeNonce}`
      const idx = list.findIndex(p => `${p.relayPubkey}:${p.challengeNonce}` === key)
      if (idx === -1) {
        list.push(entry)
        this._invalidateCustodyStatus(entry.intentId)
      } else if (list[idx].timestamp <= entry.timestamp) {
        list[idx] = entry
        this._invalidateCustodyStatus(entry.intentId)
      }
    }

    if (entry.type === 'custody-expiry-witness') {
      if (!this._custodyExpiryWitnesses.has(entry.intentId)) {
        this._custodyExpiryWitnesses.set(entry.intentId, [])
      }
      const list = this._custodyExpiryWitnesses.get(entry.intentId)
      // Dedup on (witnessPubkey, relayPubkey, challengeNonce)
      const key = `${entry.witnessPubkey}:${entry.relayPubkey}:${entry.challengeNonce}`
      const idx = list.findIndex(w => `${w.witnessPubkey}:${w.relayPubkey}:${w.challengeNonce}` === key)
      if (idx === -1) {
        list.push(entry)
        this._invalidateCustodyStatus(entry.intentId)
      } else if (list[idx].timestamp <= entry.timestamp) {
        list[idx] = entry
        this._invalidateCustodyStatus(entry.intentId)
      }
    }
  }

  /**
   * Publish a seed request to the registry
   */
  async publishRequest (request) {
    const privacyTier = normalizePrivacyTier(request.privacyTier, 'public')
    const contentType = normalizeContentType(request.contentType || request.type, 'app')
    const blind = request.blind === true
    const storageClass = normalizeStorageClass(request.storageClass, blind ? 'temporary' : 'persistent')
    const availabilityClass = normalizeAvailabilityClass(request.availabilityClass, blind ? 'atomic-handoff' : 'always-on')
    const parentKey = typeof request.parentKey === 'string' && isValidHexKey(request.parentKey, 64)
      ? request.parentKey
      : null
    const mountPath = typeof request.mountPath === 'string' && request.mountPath.trim().startsWith('/')
      ? request.mountPath.trim()
      : null
    const entry = {
      type: 'seed-request',
      timestamp: Date.now(),
      appKey: b4a.toString(request.appKey, 'hex'),
      discoveryKeys: request.discoveryKeys.map(dk => b4a.toString(dk, 'hex')),
      contentType,
      parentKey,
      mountPath,
      replicationFactor: request.replicationFactor || 3,
      geoPreference: request.geoPreference || [],
      maxStorageBytes: request.maxStorageBytes || 0,
      bountyRate: request.bountyRate || 0,
      ttlSeconds: request.ttlSeconds || 30 * 24 * 3600, // 30 days default
      privacyTier,
      blind,
      storageClass,
      availabilityClass,
      publisherPubkey: b4a.toString(request.publisherPubkey, 'hex')
    }

    await this.localLog.append(b4a.from(JSON.stringify(entry)))
    this._applyEntry(entry)
    this.emit('request-published', entry)
    return entry
  }

  /**
   * Record a seed acceptance in the registry
   */
  async recordAcceptance (appKeyHex, relayPubkeyHex, region) {
    const entry = {
      type: 'seed-accept',
      timestamp: Date.now(),
      appKey: appKeyHex,
      relayPubkey: relayPubkeyHex,
      region
    }

    await this.localLog.append(b4a.from(JSON.stringify(entry)))
    this._applyEntry(entry)
    this.emit('acceptance-recorded', entry)
    return entry
  }

  async publishCustodyIntent (intent, publisherKeyPair) {
    const entry = intent.signature
      ? this._verifiedCustodyEntry(intent)
      : createCustodyIntent(intent, publisherKeyPair)
    return this._appendCustodyEntry(entry, 'custody-intent-published')
  }

  async recordCustodyReceipt (receipt, relayKeyPair) {
    const entry = receipt.signature
      ? this._verifiedCustodyEntry(receipt)
      : createCustodyReceipt(receipt, relayKeyPair)
    return this._appendCustodyEntry(entry, 'custody-receipt-recorded')
  }

  async publishCustodyCommit (commit, publisherKeyPair) {
    const intent = this._custodyIntents.get(commit.intentId)
    const receipts = this.getCustodyReceipts(commit.intentId)
    const entry = commit.signature
      ? this._verifiedCustodyEntry(commit)
      : createCustodyCommit({
        ...commit,
        blindContentId: commit.blindContentId || intent?.blindContentId,
        ciphertextRoot: commit.ciphertextRoot || intent?.ciphertextRoot,
        contentVersion: commit.contentVersion ?? intent?.contentVersion,
        relayQuorum: commit.relayQuorum || receipts.map(r => r.relayPubkey).sort(),
        receiptRoot: commit.receiptRoot || computeReceiptRoot(receipts),
        receipts
      }, publisherKeyPair)
    return this._appendCustodyEntry(entry, 'custody-commit-published')
  }

  async publishSourceRetired (retirement, publisherKeyPair) {
    const intent = this._custodyIntents.get(retirement.intentId)
    const entry = retirement.signature
      ? this._verifiedCustodyEntry(retirement)
      : createSourceRetired({
        ...retirement,
        blindContentId: retirement.blindContentId || intent?.blindContentId,
        retiredAtVersion: retirement.retiredAtVersion ?? intent?.contentVersion
      }, publisherKeyPair)
    return this._appendCustodyEntry(entry, 'source-retired-published')
  }

  async recordCustodyProof (proof, observerKeyPair) {
    const intent = this._custodyIntents.get(proof.intentId)
    const entry = proof.signature
      ? this._verifiedCustodyEntry(proof)
      : createCustodyProof({
        ...proof,
        blindContentId: proof.blindContentId || intent?.blindContentId
      }, observerKeyPair)
    return this._appendCustodyEntry(entry, 'custody-proof-recorded')
  }

  async recordCustodyNonServingProof (proof, relayKeyPair) {
    const intent = this._custodyIntents.get(proof.intentId)
    const entry = proof.signature
      ? this._verifiedCustodyEntry(proof)
      : createCustodyNonServingProof({
        ...proof,
        addressKey: proof.addressKey || intent?.addressKey,
        blindContentId: proof.blindContentId || intent?.blindContentId,
        retainUntil: proof.retainUntil ?? intent?.retainUntil
      }, relayKeyPair)
    return this._appendCustodyEntry(entry, 'custody-non-serving-proof-recorded')
  }

  /**
   * Record a witness tombstone — an independent attestation that a relay
   * is no longer actively serving content past its `retainUntil`. The
   * witness does NOT store content; it just probes the relay's catalog,
   * gateway, and swarm and signs over what it observed.
   *
   * Pre-signed entries are accepted as-is (after verification). Otherwise
   * the registry signs with the supplied witnessKeyPair.
   */
  async recordCustodyExpiryWitness (witness, witnessKeyPair) {
    const intent = this._custodyIntents.get(witness.intentId)
    const entry = witness.signature
      ? this._verifiedCustodyEntry(witness)
      : createCustodyExpiryWitness({
        ...witness,
        blindContentId: witness.blindContentId || intent?.blindContentId
      }, witnessKeyPair)
    return this._appendCustodyEntry(entry, 'custody-expiry-witness-recorded')
  }

  _verifiedCustodyEntry (entry) {
    const verified = verifyCustodyEntry(entry)
    if (!verified.valid) throw new Error(`INVALID_CUSTODY_ENTRY: ${verified.reason}`)
    return verified.entry
  }

  async _appendCustodyEntry (entry, eventName) {
    const status = this.getCustodyStatus(entry.intentId)
    const transition = validateCustodyTransition(entry, status)
    if (!transition.valid) throw new Error(`INVALID_CUSTODY_TRANSITION: ${transition.reason}`)
    await this.localLog.append(b4a.from(JSON.stringify(entry)))
    this._applyEntry(entry)
    this.emit(eventName, entry)
    // Local-append also fires `custody-entry-appended` so the relay-node
    // (or any other consumer) can broadcast the entry over Protomux for
    // real-time push without waiting for log replication.
    this.emit('custody-entry-appended', { entry, eventName })
    return entry
  }

  /**
   * Apply a custody entry pushed to us by a peer over the Protomux custody
   * channel. Returns true if the entry was new and applied, false if it
   * was a duplicate or invalid.
   *
   * Pushed entries do NOT get appended to OUR local log — that would
   * misattribute the entry to us. They only update our in-memory indexes.
   * The actual durable record lives in the peer's log, which we'll receive
   * on the next replication cycle. This channel is the fast-path; log
   * replication is the durable transport.
   */
  _applyPushedEntry (entry, fromPeer) {
    if (!entry || typeof entry !== 'object') return false
    if (typeof entry.type !== 'string') return false
    if (!entry.type.startsWith('custody-') && entry.type !== 'source-retired') return false

    // Validate the same way the indexer does — drops invalid signatures,
    // forbidden plaintext fields, etc.
    const normalized = this._normalizeIndexedEntry(entry, { source: 'push', fromPeer })
    if (!normalized) {
      this.emit('custody-entry-rejected', { reason: 'invalid-pushed-entry', fromPeer })
      return false
    }

    // Dedup check: if we already have this exact entry (same intentId +
    // type + relayPubkey + timestamp), skip the apply.
    if (this._isDuplicateCustodyEntry(normalized)) return false

    this._applyEntry(normalized, { source: 'push', fromPeer })

    // Map type → bubbled event name so consumers see the same events
    // regardless of whether the entry came via push or log replication.
    const eventByType = {
      'custody-intent': 'custody-intent-published',
      'custody-receipt': 'custody-receipt-recorded',
      'custody-commit': 'custody-commit-published',
      'source-retired': 'source-retired-published',
      'custody-proof': 'custody-proof-recorded',
      'custody-non-serving-proof': 'custody-non-serving-proof-recorded',
      'custody-expiry-witness': 'custody-expiry-witness-recorded'
    }
    const eventName = eventByType[normalized.type]
    if (eventName) this.emit(eventName, normalized)
    return true
  }

  _isDuplicateCustodyEntry (entry) {
    if (entry.type === 'custody-intent') {
      const existing = this._custodyIntents.get(entry.intentId)
      return !!existing && existing.timestamp >= entry.timestamp
    }
    if (entry.type === 'custody-receipt') {
      const receipts = this._custodyReceipts.get(entry.intentId)
      const current = receipts?.get(entry.relayPubkey)
      return !!current && current.timestamp >= entry.timestamp
    }
    if (entry.type === 'custody-commit') {
      const existing = this._custodyCommits.get(entry.intentId)
      return !!existing && existing.timestamp >= entry.timestamp
    }
    if (entry.type === 'source-retired') {
      const existing = this._sourceRetirements.get(entry.intentId)
      return !!existing && existing.timestamp >= entry.timestamp
    }
    if (entry.type === 'custody-proof' || entry.type === 'custody-non-serving-proof') {
      // Proofs accumulate; dedup on (relayPubkey + challengeNonce + timestamp)
      const list = (entry.type === 'custody-proof'
        ? this._custodyProofs
        : this._custodyNonServingProofs).get(entry.intentId) || []
      return list.some(p =>
        p.relayPubkey === entry.relayPubkey &&
        p.challengeNonce === entry.challengeNonce &&
        p.timestamp === entry.timestamp
      )
    }
    if (entry.type === 'custody-expiry-witness') {
      const list = this._custodyExpiryWitnesses.get(entry.intentId) || []
      return list.some(w =>
        w.witnessPubkey === entry.witnessPubkey &&
        w.relayPubkey === entry.relayPubkey &&
        w.challengeNonce === entry.challengeNonce
      )
    }
    return false
  }

  /**
   * Record a seed cancellation
   */
  async cancelRequest (appKeyHex, publisherPubkeyHex) {
    const entry = {
      type: 'seed-cancel',
      timestamp: Date.now(),
      appKey: appKeyHex,
      publisherPubkey: publisherPubkeyHex
    }

    await this.localLog.append(b4a.from(JSON.stringify(entry)))
    this._applyEntry(entry)
    this.emit('request-cancelled', entry)
    return entry
  }

  /**
   * Query active seed requests, optionally filtered
   */
  async getActiveRequests (filter = {}) {
    const now = Date.now()
    const results = []

    for (const [appKey, entry] of this._requests) {
      // Check if cancelled
      const cancelKey = appKey + ':' + entry.publisherPubkey
      const canceledAt = this._cancellations.get(cancelKey)
      if (canceledAt && canceledAt >= entry.timestamp) continue

      // Check TTL
      const expiresAt = entry.timestamp + (entry.ttlSeconds * 1000)
      if (expiresAt < now) continue

      // Apply filters
      if (filter.region && entry.geoPreference.length > 0) {
        if (!entry.geoPreference.includes(filter.region)) continue
      }
      if (filter.maxStorageBytes && entry.maxStorageBytes > filter.maxStorageBytes) continue

      results.push(entry)
    }

    return results
  }

  /**
   * Get relays currently seeding an app
   */
  async getRelaysForApp (appKeyHex) {
    return this._acceptances.get(appKeyHex) || []
  }

  getCustodyIntent (intentId) {
    return this._custodyIntents.get(intentId) || null
  }

  getCustodyReceipts (intentId) {
    return Array.from(this._custodyReceipts.get(intentId)?.values() || [])
  }

  getCustodyProofs (intentId) {
    return [...(this._custodyProofs.get(intentId) || [])]
  }

  getCustodyNonServingProofs (intentId) {
    return [...(this._custodyNonServingProofs.get(intentId) || [])]
  }

  getCustodyExpiryWitnesses (intentId) {
    return [...(this._custodyExpiryWitnesses.get(intentId) || [])]
  }

  getCustodyStatus (intentId) {
    const cached = this._custodyStatusCache.get(intentId)
    if (cached) return cached
    const intent = this._custodyIntents.get(intentId) || null
    const receipts = this.getCustodyReceipts(intentId)
    const rawCommit = this._custodyCommits.get(intentId) || null
    const sourceRetired = this._sourceRetirements.get(intentId) || null
    const proofs = this.getCustodyProofs(intentId)
    const nonServingProofs = this.getCustodyNonServingProofs(intentId)
    const expiryWitnesses = this.getCustodyExpiryWitnesses(intentId)
    const commitCheck = rawCommit
      ? validateCustodyTransition(rawCommit, { intent, receipts })
      : { valid: false, reason: 'no commit' }
    const commit = commitCheck.valid ? rawCommit : null
    const retirementCheck = sourceRetired
      ? validateCustodyTransition(sourceRetired, { intent, receipts, commit })
      : { valid: false, reason: 'no source retirement' }
    const effectiveRetirement = retirementCheck.valid ? sourceRetired : null
    const status = {
      ...summarizeCustodyStatus(intent, receipts, commit, effectiveRetirement, proofs, nonServingProofs, expiryWitnesses),
      intent,
      receipts,
      commit,
      commitPendingReason: rawCommit && !commit ? commitCheck.reason : null,
      sourceRetirement: effectiveRetirement,
      sourceRetirementPendingReason: sourceRetired && !effectiveRetirement ? retirementCheck.reason : null,
      proofs,
      nonServingProofs,
      expiryWitnesses
    }
    this._custodyStatusCache.set(intentId, status)
    return status
  }

  _invalidateCustodyStatus (intentId) {
    if (intentId) this._custodyStatusCache.delete(intentId)
  }

  /**
   * Aggregate custody snapshot for dashboards and the WS feed.
   *
   * Walks every active intent and rolls up:
   *   - total intent count
   *   - how many have committed (publisher acknowledged quorum)
   *   - how many have reached receipt quorum (ready to commit)
   *   - how many have at least one validated proof
   *   - how many have an unresolved non-serving-proof outstanding
   *   - total receipts and proofs counts (for trend graphs)
   *
   * Cheap to compute on each broadcast — bounded by intent count, which is
   * already bounded by the registry's append-only log size.
   */
  custodySnapshot () {
    let intents = 0
    let withQuorum = 0
    let committed = 0
    let withProof = 0
    let withNonServingProof = 0
    let withWitnessTombstone = 0
    let totalReceipts = 0
    let totalProofs = 0
    let totalNonServingProofs = 0
    let totalWitnessTombstones = 0
    let retired = 0
    for (const intentId of this._custodyIntents.keys()) {
      intents++
      const status = this.getCustodyStatus(intentId)
      if (status.quorumReached) withQuorum++
      if (status.committed) committed++
      if (status.proofCount > 0) withProof++
      if (status.nonServingProofCount > 0) withNonServingProof++
      if (status.sourceRetired) retired++
      totalReceipts += status.receiptCount
      totalProofs += status.proofCount
      totalNonServingProofs += status.nonServingProofCount

      if (status.validExpiryWitnessCount > 0) withWitnessTombstone++
      totalWitnessTombstones += status.validExpiryWitnessCount
    }
    return {
      intents,
      withQuorum,
      committed,
      retired,
      withProof,
      withNonServingProof,
      withWitnessTombstone,
      totalReceipts,
      totalProofs,
      totalNonServingProofs,
      totalWitnessTombstones,
      // Derived health indicator: ratio of committed intents to total. A
      // healthy registry should converge to ~1.0 over time. Sustained low
      // values mean the network is failing to gather quorums.
      commitRate: intents > 0 ? committed / intents : null
    }
  }

  get key () {
    return this.localLog ? this.localLog.key : null
  }

  async stop () {
    this.running = false
    try { await this.swarm.leave(REGISTRY_TOPIC) } catch (err) {
      this.emit('stop-error', { operation: 'swarm.leave', error: err.message })
    }
    if (this._onSwarmConnection) {
      this.swarm.removeListener('connection', this._onSwarmConnection)
      this._onSwarmConnection = null
    }
    if (this.localLog && this._onLocalAppend) {
      this.localLog.removeListener('append', this._onLocalAppend)
      this._onLocalAppend = null
    }
    for (const { log, onAppend } of this._peerLogMeta.values()) {
      if (onAppend) log.removeListener('append', onAppend)
    }
    if (this.localLog) {
      try { await this.localLog.close() } catch (err) {
        this.emit('stop-error', { operation: 'localLog.close', error: err.message })
      }
    }
    for (const log of this.peerLogs.values()) {
      try { await log.close() } catch (err) {
        this.emit('stop-error', { operation: 'peerLog.close', error: err.message })
      }
    }
    this.peerLogs.clear()
    this._peerLogMeta.clear()
    this._indexedOffsets.clear()
    this._custodyStatusCache.clear()
    this.emit('stopped')
  }
}
