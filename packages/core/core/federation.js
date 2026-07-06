/**
 * Federation — explicit, opt-in cross-relay catalog sharing.
 *
 * The deprecated CatalogSync module auto-polled every discovered relay and
 * auto-seeded everything new it found. That made operators answerable for
 * content they never agreed to carry. Federation replaces that with the
 * RSS / Nostr-relay model: an operator chooses which other relays to follow
 * or mirror, and even followed catalogs go through their accept-mode gate
 * before anything actually gets seeded.
 *
 * Two relationships:
 *   follow(url)   — periodically pulls /catalog.json from that relay. Each
 *                   newly discovered app is funneled through the local
 *                   accept-mode (Review queues it; Allowlist applies the
 *                   publisher filter; Open auto-accepts; Closed drops it).
 *   mirror(url)   — used for "my own other node" or a trusted partner. Apps
 *                   discovered through this relay's *Protomux* catalog
 *                   broadcast bypass the accept queue and are seeded
 *                   immediately. Use sparingly.
 *
 * No auto-discovery. If an operator hasn't followed/mirrored a relay,
 * nothing crosses over from that relay — full stop.
 */

import { EventEmitter } from 'events'
import http from 'http'
import { readFile, writeFile, mkdir, rename, unlink } from 'fs/promises'
import { dirname, basename, join } from 'path'
import { verifyForkProof, verifyForkEvidence } from './fork-proof-signing.js'

const DEFAULT_FOLLOW_INTERVAL = 5 * 60 * 1000 // 5 minutes
const FETCH_TIMEOUT = 10_000
const MAX_URL_LENGTH = 2048
const MAX_FEDERATION_JSON_BYTES = 2 * 1024 * 1024

// Validate a federation source URL. Returns the validated URL string or throws.
// Caller-supplied URLs (follow/mirror/republish) get the throwing variant; the
// load() path uses validateUrlSafe() which returns false instead so a single
// bad entry on disk can't crash federation startup.
function validateUrl (url) {
  if (typeof url !== 'string' || url.length === 0) {
    throw new Error('Federation: URL must be a non-empty string')
  }
  if (url.length > MAX_URL_LENGTH) {
    throw new Error(`Federation: URL exceeds maximum length of ${MAX_URL_LENGTH} characters`)
  }
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    throw new Error(`Federation: invalid URL: ${url}`)
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Federation: URL scheme must be http: or https: (got ${parsed.protocol})`)
  }
  return url
}

function validateUrlSafe (url) {
  try {
    validateUrl(url)
    return true
  } catch {
    return false
  }
}

// Normalize an operator-supplied trusted-fork-observer allow-list into a
// lowercase Set of 64-hex pubkeys. Anything that isn't a valid 32-byte
// hex key is dropped, so a malformed config entry can't silently widen
// trust. Accepts an array of hex strings, or a single hex string.
function normalizeObserverAllowList (input) {
  const out = new Set()
  const items = Array.isArray(input) ? input : (input == null ? [] : [input])
  for (const item of items) {
    if (typeof item === 'string' && /^[0-9a-f]{64}$/i.test(item)) {
      out.add(item.toLowerCase())
    }
  }
  return out
}

function utf8ByteLength (text) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.byteLength === 'function') {
    return Buffer.byteLength(text, 'utf8')
  }
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(text).byteLength
  }
  return String(text).length
}

async function readBoundedFetchText (res) {
  const contentLength = Number(res.headers?.get?.('content-length'))
  if (Number.isFinite(contentLength) && contentLength > MAX_FEDERATION_JSON_BYTES) return null

  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader()
    const decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder() : null
    let body = ''
    let bytes = 0
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      const value = chunk.value
      bytes += value?.byteLength || value?.length || 0
      if (bytes > MAX_FEDERATION_JSON_BYTES) {
        if (typeof reader.cancel === 'function') {
          try { await reader.cancel() } catch (_) {}
        }
        return null
      }
      if (decoder) body += decoder.decode(value, { stream: true })
      else body += String(value)
    }
    if (decoder) body += decoder.decode()
    return body
  }

  if (typeof res.text !== 'function') return null
  const text = await res.text()
  if (utf8ByteLength(text) > MAX_FEDERATION_JSON_BYTES) return null
  return text
}

export class Federation extends EventEmitter {
  /**
   * @param {object} opts
   * @param {RelayNode} opts.node - relay node reference (for accept queue, seedApp)
   * @param {number}  [opts.followInterval] - ms between catalog pulls for followed relays
   * @param {Array}   [opts.followed] - initial followed entries: [{ url, pubkey? }]
   * @param {Array}   [opts.mirrored] - initial mirrored entries: [{ url, pubkey? }]
   * @param {string}  [opts.storagePath] - JSON file for persisting follow/mirror state
   *                                       across restarts. If omitted, state is runtime-only.
   */
  constructor (opts = {}) {
    super()
    this.node = opts.node
    this.followInterval = opts.followInterval || DEFAULT_FOLLOW_INTERVAL
    this.storagePath = opts.storagePath || null

    // Trusted fork-observer allow-list (audit HR-SVC-004). A pulled
    // fork proof may only quarantine a drive if it was attested by an
    // observer whose pubkey is on this list AND its conflicting-heads
    // proof cryptographically verifies. Empty list = pulled fork proofs
    // NEVER quarantine (fail closed) — an operator must explicitly trust
    // observers before their gossip can censor drives on this node.
    this.trustedForkObservers = normalizeObserverAllowList(opts.trustedForkObservers)
    // Keyed by URL so follow/unfollow are idempotent.
    this.followed = new Map()
    this.mirrored = new Map()
    // Republish: operator's curated channel of apps that originate on other
    // relays. Keyed by appKey. We don't (necessarily) seed them — we surface
    // them in /catalog.json with attribution so subscribers see them too.
    this.republished = new Map()
    for (const entry of opts.followed || []) this._addFollowed(entry.url, entry.pubkey, entry.addedAt)
    for (const entry of opts.mirrored || []) this._addMirrored(entry.url, entry.pubkey, entry.addedAt)
    for (const entry of opts.republished || []) this._addRepublished(entry)

    // Pubkey index for quick "is this peer mirrored?" lookups during catalog broadcasts.
    this._mirroredPubkeys = new Set()
    for (const e of this.mirrored.values()) {
      if (e.pubkey) this._mirroredPubkeys.add(e.pubkey)
    }

    this._timer = null
    this.running = false
    this._saveInFlight = null // de-dupe concurrent saves

    // Cache of the most recent successful fetch per followed peer.
    // Consumers (AutoHeal, dashboard, /api/federation) read this to see
    // who's seeding what without triggering fresh HTTP fetches. Keyed by
    // URL; entries are { url, pubkey, region, fetchedAt, apps[] }.
    // Updated on every successful _pollOne; never grows beyond the
    // followed set's cardinality.
    this._peerCatalogs = new Map()
  }

  /**
   * Load persisted follow/mirror state from disk. Safe to call when no file
   * exists (first boot) — silently no-ops in that case.
   */
  async load () {
    if (!this.storagePath) return
    let raw
    try {
      raw = await readFile(this.storagePath, 'utf8')
    } catch (err) {
      if (err.code === 'ENOENT') return
      this.emit('persistence-error', { phase: 'load', error: err })
      return
    }
    let data
    try {
      data = JSON.parse(raw)
    } catch (err) {
      this.emit('persistence-error', { phase: 'parse', error: err })
      return
    }
    if (Array.isArray(data.followed)) {
      for (const entry of data.followed) {
        if (!entry || !validateUrlSafe(entry.url)) {
          this.emit('persistence-error', { phase: 'load-skip-invalid', kind: 'followed', entry })
          continue
        }
        this._addFollowed(entry.url, entry.pubkey, entry.addedAt)
      }
    }
    if (Array.isArray(data.mirrored)) {
      for (const entry of data.mirrored) {
        if (!entry || !validateUrlSafe(entry.url)) {
          this.emit('persistence-error', { phase: 'load-skip-invalid', kind: 'mirrored', entry })
          continue
        }
        this._addMirrored(entry.url, entry.pubkey, entry.addedAt)
      }
    }
    if (Array.isArray(data.republished)) {
      for (const entry of data.republished) {
        // sourceUrl is optional on republished entries — only validate when present.
        if (entry && entry.sourceUrl != null && !validateUrlSafe(entry.sourceUrl)) {
          this.emit('persistence-error', { phase: 'load-skip-invalid', kind: 'republished', entry })
          continue
        }
        this._addRepublished(entry)
      }
    }
    this.emit('loaded', this.snapshot())
  }

  /**
   * Persist follow/mirror state. Coalesces concurrent calls so a burst of
   * follow()/unfollow() doesn't trigger overlapping writes.
   */
  async save ({ throwOnError = false } = {}) {
    if (!this.storagePath) return
    if (!this._saveInFlight) {
      // Atomic write: writeFile(.tmp) then rename — POSIX rename is atomic,
      // so SIGKILL mid-write leaves either the old file intact or the new one
      // in place, never a partial. Cleans up .tmp on any error.
      this._saveInFlight = (async () => {
        const tmpPath = join(dirname(this.storagePath), basename(this.storagePath) + '.tmp')
        await mkdir(dirname(this.storagePath), { recursive: true })
        const payload = JSON.stringify({
          followed: Array.from(this.followed.values()),
          mirrored: Array.from(this.mirrored.values()),
          republished: Array.from(this.republished.values()),
          savedAt: Date.now()
        }, null, 2)
        await writeFile(tmpPath, payload, 'utf8')
        await rename(tmpPath, this.storagePath)
      })().catch(async (err) => {
        // Best-effort cleanup of any leftover .tmp on failure.
        const tmpPath = join(dirname(this.storagePath), basename(this.storagePath) + '.tmp')
        try { await unlink(tmpPath) } catch (_) {}
        throw err
      }).finally(() => {
        this._saveInFlight = null
      })
    }
    try {
      return await this._saveInFlight
    } catch (err) {
      this.emit('persistence-error', { phase: 'save', error: err })
      if (throwOnError) throw err
    }
  }

  restoreSnapshot (snapshot = {}) {
    this.followed = new Map()
    this.mirrored = new Map()
    this.republished = new Map()
    this._mirroredPubkeys = new Set()

    for (const entry of snapshot.followed || []) this._addFollowed(entry.url, entry.pubkey, entry.addedAt)
    for (const entry of snapshot.mirrored || []) this._addMirrored(entry.url, entry.pubkey, entry.addedAt)
    for (const entry of snapshot.republished || []) this._addRepublished(entry)

    this._syncPollTimer()
  }

  _syncPollTimer () {
    if (!this.running) return
    if (this.followed.size > 0) {
      if (!this._timer) this._scheduleNextPoll()
      return
    }
    if (this._timer) {
      clearTimeout(this._timer)
      this._timer = null
    }
  }

  // Internal: add to map without emitting, used by load() so persisted state
  // doesn't trigger save() / events recursively. Bad URLs are dropped silently
  // — load() emits 'persistence-error' with phase 'load-skip-invalid' before
  // calling these so we have observability without crashing federation.
  _addFollowed (url, pubkey, addedAt) {
    if (!validateUrlSafe(url)) return
    this.followed.set(url, { url, pubkey: pubkey || null, addedAt: addedAt || Date.now() })
  }

  _addMirrored (url, pubkey, addedAt) {
    if (!validateUrlSafe(url)) return
    this.mirrored.set(url, { url, pubkey: pubkey || null, addedAt: addedAt || Date.now() })
    if (pubkey) this._mirroredPubkeys.add(pubkey)
  }

  _addRepublished (entry) {
    if (!entry || !entry.appKey) return
    if (entry.sourceUrl != null && !validateUrlSafe(entry.sourceUrl)) return
    this.republished.set(entry.appKey, {
      appKey: entry.appKey,
      sourceUrl: entry.sourceUrl || null,
      sourcePubkey: entry.sourcePubkey || null,
      channel: entry.channel || null,
      note: entry.note || null,
      addedAt: entry.addedAt || Date.now()
    })
  }

  start () {
    if (this.running) return
    this.running = true
    if (this.followed.size > 0) this._scheduleNextPoll()
    this.emit('started', this.snapshot())
  }

  async stop () {
    this.running = false
    if (this._timer) {
      clearTimeout(this._timer)
      this._timer = null
    }
    this.emit('stopped')
  }

  // ─── Subscription management ────────────────────────────────────────

  follow (url, { pubkey = null, persist = true } = {}) {
    validateUrl(url)
    this._addFollowed(url, pubkey, Date.now())
    this.emit('followed', { url, pubkey })
    if (persist) this.save() // fire-and-forget; errors emit 'persistence-error'
    this._syncPollTimer()
  }

  mirror (url, { pubkey = null, persist = true } = {}) {
    validateUrl(url)
    this._addMirrored(url, pubkey, Date.now())
    this.emit('mirrored', { url, pubkey })
    if (persist) this.save()
  }

  unfollow (url, { persist = true } = {}) {
    const removedFollow = this.followed.delete(url)
    const mirrorEntry = this.mirrored.get(url)
    const removedMirror = this.mirrored.delete(url)
    if (mirrorEntry?.pubkey) this._mirroredPubkeys.delete(mirrorEntry.pubkey)
    if (removedFollow || removedMirror) {
      this.emit('unfollowed', { url })
      if (persist) this.save()
      this._syncPollTimer()
    }
    return removedFollow || removedMirror
  }

  /**
   * Republish a single app from another relay's catalog with attribution.
   * The app appears in this relay's /catalog.json under federation.republished
   * with the source relay credited. Republishing does NOT auto-seed — if the
   * operator also wants to seed the app locally, they accept it via the
   * normal seed-request queue.
   */
  republish (appKey, { sourceUrl = null, sourcePubkey = null, channel = null, note = null, persist = true } = {}) {
    if (!appKey || typeof appKey !== 'string') throw new Error('Federation: republish(appKey) requires a string appKey')
    if (sourceUrl != null) validateUrl(sourceUrl)
    this._addRepublished({ appKey, sourceUrl, sourcePubkey, channel, note, addedAt: Date.now() })
    this.emit('republished', { appKey, sourceUrl, channel })
    if (persist) this.save()
  }

  unrepublish (appKey, { persist = true } = {}) {
    const removed = this.republished.delete(appKey)
    if (removed) {
      this.emit('unrepublished', { appKey })
      if (persist) this.save()
    }
    return removed
  }

  /**
   * Is this remote relay pubkey on the operator's mirror list?
   * Called by the Protomux app-catalog handler in RelayNode to decide
   * whether to bypass the accept queue.
   */
  isMirroredPubkey (pubkey) {
    return !!pubkey && this._mirroredPubkeys.has(pubkey)
  }

  snapshot () {
    return {
      followed: Array.from(this.followed.values()),
      mirrored: Array.from(this.mirrored.values()),
      republished: Array.from(this.republished.values()),
      followIntervalMs: this.followInterval,
      running: this.running,
      // Peer catalogs as of the last poll. Consumers (AutoHeal, dashboard)
      // shouldn't mutate these — treat as read-only.
      peerCatalogs: Array.from(this._peerCatalogs.values())
    }
  }

  // ─── Polling followed catalogs ──────────────────────────────────────

  _scheduleNextPoll () {
    if (!this.running) return
    if (this._timer) clearTimeout(this._timer)
    this._timer = setTimeout(() => {
      this._pollAll().catch(err => this.emit('poll-error', err)).finally(() => {
        if (this.running && this.followed.size > 0) this._scheduleNextPoll()
      })
    }, this.followInterval)
    if (this._timer.unref) this._timer.unref()
  }

  async _pollAll () {
    const entries = Array.from(this.followed.values())
    if (entries.length === 0) return
    const results = await Promise.allSettled(entries.map(e => this._pollOne(e)))
    let totalQueued = 0
    for (const r of results) {
      if (r.status === 'fulfilled') totalQueued += r.value || 0
    }
    this.emit('poll-complete', { polled: entries.length, queued: totalQueued })
  }

  async _pollOne (entry) {
    const data = await this._fetchCatalog(entry.url)
    if (!data || !Array.isArray(data.apps)) return 0

    // Cache the peer catalog so AutoHeal and the dashboard can read who's
    // seeding what without re-fetching. Stored as the latest snapshot;
    // updated on every successful poll.
    this._peerCatalogs.set(entry.url, {
      url: entry.url,
      pubkey: entry.pubkey || data.pubkey || null,
      region: data.region || null,
      // Operator: optional self-declared identity of the relay's deployment
      // owner (e.g. "acme-corp"). Used by AutoHeal for operator-diversity
      // scoring + sybil-cluster detection. Older catalogs without operator
      // get treated as their own pubkey-as-operator (no diversity boost).
      operator: data.operator || null,
      fetchedAt: Date.now(),
      apps: data.apps
    })

    let queued = 0
    for (const app of data.apps) {
      const appKey = app.appKey || app.driveKey || app.key
      if (!appKey) continue
      // Skip apps we already seed or have already queued.
      if (this.node?.seededApps?.has?.(appKey)) continue
      if (this.node?.appRegistry?.has?.(appKey)) continue
      if (this.node?._pendingRequests?.has?.(appKey)) continue

      // Funnel through the same accept-mode used for registry seed requests.
      const synthRequest = {
        appKey,
        publisherPubkey: app.publisherPubkey || app.author || null,
        contentType: app.type || 'app',
        privacyTier: app.privacyTier || 'public',
        blind: app.blind === true,
        storageClass: app.storageClass || null,
        availabilityClass: app.availabilityClass || null,
        replicationFactor: app.replicationFactor || 1,
        parentKey: app.parentKey || null,
        mountPath: app.mountPath || null,
        source: 'federation',
        sourceRelay: entry.url
      }

      const mode = this.node._resolveAcceptMode()
      const decision = this.node._decideAcceptance(synthRequest, mode)

      if (decision === 'reject') {
        this.emit('federation-rejected', { appKey, source: entry.url, mode })
        continue
      }

      if (decision === 'accept') {
        try {
          await this.node.seedApp(appKey, {
            publisherPubkey: synthRequest.publisherPubkey,
            type: synthRequest.contentType,
            parentKey: synthRequest.parentKey,
            mountPath: synthRequest.mountPath,
            privacyTier: synthRequest.privacyTier,
            blind: synthRequest.blind,
            storageClass: synthRequest.storageClass,
            availabilityClass: synthRequest.availabilityClass
          })
          this.emit('federation-seeded', { appKey, source: entry.url, mode })
        } catch (err) {
          this.emit('federation-error', { appKey, source: entry.url, error: err.message })
        }
        continue
      }

      // 'review' — queue for operator approval.
      const pendingEntry = {
        ...synthRequest,
        discoveredAt: Date.now(),
        mode
      }
      const inserted = typeof this.node._addPendingRequest === 'function'
        ? this.node._addPendingRequest(appKey, pendingEntry)
        : this._addPendingRequestFallback(appKey, pendingEntry)
      if (inserted) {
        this.node.emit('registry-pending', { appKey, publisher: synthRequest.publisherPubkey, source: 'federation' })
        this.emit('federation-queued', { appKey, source: entry.url })
        queued++
      }
    }

    // Pull fork-proof gossip from this followed peer too. Bounded
    // poll — fork-proof gossip latency = followInterval (5 min by
    // default). Best-effort: if the remote has no /api/forks/proofs
    // endpoint or it errors, we silently move on.
    try { await this._pullForkProofs(entry.url) } catch (_) { /* non-fatal */ }

    return queued
  }

  _addPendingRequestFallback (appKey, entry) {
    if (!this.node?._pendingRequests || typeof this.node._pendingRequests.has !== 'function' || typeof this.node._pendingRequests.set !== 'function') return false
    if (this.node._pendingRequests.has(appKey)) return false
    this.node._pendingRequests.set(appKey, entry)
    return true
  }

  /**
   * Pull a remote relay's published fork-proof list and merge into our
   * local fork detector. This is how equivocation evidence propagates
   * across federation peers — without active gossip there's no way for
   * client-A's fork detection to reach client-B.
   *
   * Best-effort: missing endpoint or malformed payload silently skipped.
   * Per-call timeout enforced via FETCH_TIMEOUT.
   */
  async _pullForkProofs (entryUrl) {
    if (!this.node?.forkDetector) return
    const data = await this._fetchJson(entryUrl, '/api/forks/proofs')
    if (!data || !Array.isArray(data.proofs)) return
    let merged = 0
    let rejected = 0
    for (const proof of data.proofs) {
      if (!proof) continue

      // SECURITY (audit HR-SVC-004): a pulled fork proof quarantines a
      // drive network-wide — an unauthenticated-censorship primitive if
      // left ungated. Three cumulative gates before we let a remote
      // party quarantine anything:
      //
      //   1. It MUST be a signed observer envelope. Bare unsigned
      //      records ('unverified-observer') are rejected outright — no
      //      more accept-anything transition path.
      //   2. The observer envelope signature must verify.
      //   3. The observer pubkey must be on our trusted-observer
      //      allow-list. Empty list = fail closed (nothing quarantines).
      //   4. The underlying conflicting-heads evidence must be a
      //      cryptographically valid fork proof (both blocks signed by
      //      the hypercore key, and different). Enforced again inside
      //      forkDetector.report({ provenance: 'network' }).
      if (!(proof.version && proof.proof && proof.observer)) {
        rejected++
        this.emit('fork-proof-rejected', { source: entryUrl, reason: 'unsigned proof (signed envelope required)' })
        continue
      }
      const verify = verifyForkProof(proof)
      if (!verify.valid) {
        rejected++
        this.emit('fork-proof-rejected', { source: entryUrl, reason: 'observer signature invalid: ' + verify.reason })
        continue
      }
      const observerPubkey = typeof verify.observer === 'string' ? verify.observer.toLowerCase() : null
      if (!observerPubkey || !this.trustedForkObservers.has(observerPubkey)) {
        rejected++
        this.emit('fork-proof-rejected', {
          source: entryUrl,
          observer: observerPubkey,
          reason: 'observer not on trusted allow-list'
        })
        continue
      }

      const coreProof = proof.proof
      if (!coreProof || !Array.isArray(coreProof.evidence) || coreProof.evidence.length < 2) {
        rejected++
        continue
      }

      // Final cryptographic gate: prove the actual fork before quarantine.
      const evidenceValid = verifyForkEvidence({
        hypercoreKey: coreProof.hypercoreKey,
        evidenceA: coreProof.evidence[0],
        evidenceB: coreProof.evidence[1]
      })
      if (!evidenceValid.valid) {
        rejected++
        this.emit('fork-proof-rejected', {
          source: entryUrl,
          observer: observerPubkey,
          reason: 'fork evidence does not verify: ' + evidenceValid.reason
        })
        continue
      }

      const result = this.node.forkDetector.report({
        hypercoreKey: coreProof.hypercoreKey,
        blockIndex: coreProof.blockIndex || 0,
        evidenceA: coreProof.evidence[0],
        evidenceB: coreProof.evidence[1],
        provenance: 'network'
      })
      if (result.ok && !result.recordExists) merged++
      else if (!result.ok) rejected++
    }
    if (merged > 0 || rejected > 0) {
      this.emit('fork-proofs-merged', { source: entryUrl, count: merged, rejected })
    }
  }

  _fetchCatalog (url) {
    const target = url.endsWith('/catalog.json') ? url : url.replace(/\/+$/, '') + '/catalog.json'
    return this._fetchJsonTarget(target)
  }

  async _fetchJsonTarget (target) {
    let parsed
    try {
      parsed = new URL(target)
    } catch {
      return null
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null

    if (typeof globalThis.fetch === 'function') return this._fetchJsonTargetWithFetch(parsed)
    if (parsed.protocol === 'http:') return this._fetchJsonTargetWithHttp(parsed)
    return null
  }

  async _fetchJsonTargetWithFetch (parsed) {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null
    const timeout = controller ? setTimeout(() => controller.abort(), FETCH_TIMEOUT) : null
    if (timeout && typeof timeout.unref === 'function') timeout.unref()
    try {
      const res = await globalThis.fetch(parsed.href, controller ? { signal: controller.signal } : {})
      if (!res || res.status !== 200) return null
      const body = await readBoundedFetchText(res)
      if (body == null) return null
      try { return JSON.parse(body) } catch { return null }
    } catch {
      return null
    } finally {
      if (timeout) clearTimeout(timeout)
    }
  }

  _fetchJsonTargetWithHttp (parsed) {
    return new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (settled) return
        settled = true
        resolve(value)
      }

      const req = http.get(parsed, { timeout: FETCH_TIMEOUT }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return finish(null) }
        const contentLength = Number(res.headers['content-length'])
        if (Number.isFinite(contentLength) && contentLength > MAX_FEDERATION_JSON_BYTES) {
          res.resume()
          return finish(null)
        }
        let body = ''
        let bytes = 0
        res.setEncoding('utf8')
        res.on('data', (chunk) => {
          bytes += utf8ByteLength(chunk)
          if (bytes > MAX_FEDERATION_JSON_BYTES) {
            res.destroy()
            req.destroy()
            return finish(null)
          }
          body += chunk
        })
        res.on('end', () => {
          if (settled) return
          try { finish(JSON.parse(body)) } catch { finish(null) }
        })
      })
      req.on('error', () => finish(null))
      req.on('timeout', () => { req.destroy(); finish(null) })
    })
  }

  /**
   * Generic JSON fetch helper for federation pulls. Reuses the same
   * timeout + error tolerance as _fetchCatalog. Returns null on any
   * failure so callers can short-circuit cleanly.
   */
  _fetchJson (baseUrl, path) {
    const target = baseUrl.replace(/\/+$/, '') + path
    return this._fetchJsonTarget(target)
  }
}
