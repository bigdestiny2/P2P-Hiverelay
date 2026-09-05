import b4a from 'b4a'
import sodium from 'sodium-universal'
import Protomux from 'protomux'
import {
  APP_CATALOG_LIMITS,
  APP_CATALOG_MESSAGE,
  APP_CATALOG_PAGED_ID,
  APP_CATALOG_PAGED_PROTOCOL,
  AppCatalogDigestBuilder,
  AppCatalogProtocolError,
  appCatalogPageRetransmitEquals,
  appCatalogPagedJsonEncoding,
  appCatalogSnapshotId,
  assertCatalogRowFitsPage,
  capabilityProofSignable,
  compareCatalogAppWinners,
  createAppCatalogAbort,
  createAppCatalogAck,
  createAppCatalogExternalCursor,
  createAppCatalogPage,
  projectAppCatalogSource,
  validateAppCatalogAbort,
  validateAppCatalogAck,
  validateAppCatalogPage,
  validateCapabilityChallenge,
  validateCapabilityProof,
  verifyAppCatalogAbort,
  verifyAppCatalogAck,
  verifyAppCatalogExternalCursor,
  verifyAppCatalogPage
} from './app-catalog-paged.js'

const HEX_64 = /^[0-9a-f]{64}$/
export const APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES = 2_048
const APP_CATALOG_STAGE_ROW_INDEX_BYTES = 72

// Reserve the largest legal frame, including the raw frame remembered by the
// decoder, before retaining any decoded input. Counts also bound object and
// promise overhead; these are payload reservations, not measured heap bytes.
// The shared budget covers this runtime's channels, including closing channels
// whose active storage callback has not settled yet.
const CATALOG_RECEIVE_FRAME_BYTES = APP_CATALOG_LIMITS.maxPayloadBytes + 4
const CATALOG_RECEIVE_PEER_MESSAGES = 8
const CATALOG_RECEIVE_RUNTIME_MESSAGES = 64
const CATALOG_RECEIVE_PEER_BYTES = CATALOG_RECEIVE_PEER_MESSAGES * CATALOG_RECEIVE_FRAME_BYTES
const CATALOG_RECEIVE_RUNTIME_BYTES = CATALOG_RECEIVE_RUNTIME_MESSAGES * CATALOG_RECEIVE_FRAME_BYTES
let catalogReceiveMessages = 0
let catalogReceiveBytes = 0

function fail (code, message) {
  throw new AppCatalogProtocolError(code, message)
}

function safeInteger (value, field, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max || Object.is(value, -0)) {
    fail('RESOURCE_LIMIT', `${field} must be a safe integer within ${min}..${max}`)
  }
  return value
}

function boundedOption (value, fallback, hardMax, field) {
  if (value === undefined) return fallback
  return safeInteger(value, field, 1, hardMax)
}

function hex64 (value, field) {
  if (typeof value !== 'string' || !HEX_64.test(value)) fail('PROTOCOL_ERROR', `${field} must be lowercase 64-hex`)
  return value
}

function pubkeyHex (value, field = 'public key') {
  if (typeof value === 'string') return hex64(value, field)
  if (!value || value.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) fail('PROTOCOL_ERROR', `${field} must be 32 bytes`)
  return b4a.toString(value, 'hex')
}

function validKeyPair (keyPair) {
  if (!keyPair || !keyPair.publicKey || keyPair.publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES ||
      !keyPair.secretKey || keyPair.secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    fail('PROTOCOL_ERROR', 'catalog Ed25519 key pair is unavailable')
  }
  return keyPair
}

function sign (bytes, secretKey) {
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, bytes, secretKey)
  return b4a.toString(signature, 'hex')
}

function sameJson (left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function cloneJson (value) {
  return JSON.parse(JSON.stringify(value))
}

function sourceEntriesEqual (left, right) {
  return left.eligible === right.eligible &&
    left.identity === right.identity &&
    left.reason === right.reason &&
    sameJson(left.row, right.row)
}

async function settleWithin (promise, timeoutMs) {
  let timer = null
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve(false), timeoutMs)
  })
  try {
    return await Promise.race([
      Promise.resolve(promise).then(() => true, () => true),
      timeout
    ])
  } finally {
    if (timer !== null) clearTimeout(timer)
  }
}

function rowIdentity (row) {
  if (row[13]) return `redacted:${row[15]}`
  if (row[3] === 'app' && row[2] !== null) return `public-app:${row[2]}`
  return `public-key:${row[1]}`
}

function avlHeight (node) {
  return node === null ? 0 : node.height
}

function updateAvlHeight (node) {
  node.height = Math.max(avlHeight(node.left), avlHeight(node.right)) + 1
  return node
}

function rotateAvlLeft (node) {
  const root = node.right
  node.right = root.left
  root.left = updateAvlHeight(node)
  return updateAvlHeight(root)
}

function rotateAvlRight (node) {
  const root = node.left
  node.left = root.right
  root.right = updateAvlHeight(node)
  return updateAvlHeight(root)
}

function balanceAvl (node) {
  updateAvlHeight(node)
  const balance = avlHeight(node.left) - avlHeight(node.right)
  if (balance > 1) {
    if (avlHeight(node.left.left) < avlHeight(node.left.right)) node.left = rotateAvlLeft(node.left)
    return rotateAvlRight(node)
  }
  if (balance < -1) {
    if (avlHeight(node.right.right) < avlHeight(node.right.left)) node.right = rotateAvlRight(node.right)
    return rotateAvlLeft(node)
  }
  return node
}

class OrderedIndex {
  constructor (compare, onCompare = null) {
    this.root = null
    this.length = 0
    this.compare = compare
    this.onCompare = onCompare
  }

  get size () {
    return this.length
  }

  first () {
    let node = this.root
    if (node === null) return null
    while (node.left !== null) node = node.left
    return node.key
  }

  successor (key) {
    let node = this.root
    let successor = null
    while (node !== null) {
      const compared = this._compare(key, node.key)
      if (compared < 0) {
        successor = node
        node = node.left
      } else {
        node = node.right
      }
    }
    return successor === null ? null : successor.key
  }

  iteratorAfter (key = null) {
    const stack = []
    let node = this.root
    while (node !== null) {
      if (key === null || this._compare(key, node.key) < 0) {
        stack.push(node)
        node = node.left
      } else {
        node = node.right
      }
    }
    return {
      next: () => {
        if (stack.length === 0) return null
        const current = stack.pop()
        node = current.right
        while (node !== null) {
          stack.push(node)
          node = node.left
        }
        return current.key
      }
    }
  }

  set (key, value = key) {
    const result = { inserted: false }
    this.root = this._set(this.root, key, value, result)
    if (result.inserted) this.length++
    return result.inserted
  }

  delete (key) {
    const result = { deleted: false }
    this.root = this._delete(this.root, key, result)
    if (result.deleted) this.length--
    return result.deleted
  }

  _set (node, key, value, result) {
    if (node === null) {
      result.inserted = true
      return { key, value, left: null, right: null, height: 1 }
    }
    const compared = this._compare(key, node.key)
    if (compared < 0) node.left = this._set(node.left, key, value, result)
    else if (compared > 0) node.right = this._set(node.right, key, value, result)
    else {
      node.key = key
      node.value = value
      return node
    }
    return balanceAvl(node)
  }

  _delete (node, key, result) {
    if (node === null) return null
    const compared = this._compare(key, node.key)
    if (compared < 0) node.left = this._delete(node.left, key, result)
    else if (compared > 0) node.right = this._delete(node.right, key, result)
    else {
      result.deleted = true
      if (node.left === null) return node.right
      if (node.right === null) return node.left
      let successor = node.right
      while (successor.left !== null) successor = successor.left
      node.key = successor.key
      node.value = successor.value
      node.right = this._deleteMinimum(node.right)
    }
    return balanceAvl(node)
  }

  _deleteMinimum (node) {
    if (node.left === null) return node.right
    node.left = this._deleteMinimum(node.left)
    return balanceAvl(node)
  }

  _compare (left, right) {
    if (this.onCompare !== null) this.onCompare()
    return this.compare(left, right)
  }
}

function compareText (left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

function compareGroupKeys (identity, left, right) {
  if (identity.startsWith('public-app:')) {
    const winner = compareCatalogAppWinners(left.row, right.row)
    if (winner !== 0) return winner > 0 ? -1 : 1
  }
  return compareText(left.sourceKey, right.sourceKey)
}

function firstGroupKeyExcluding (group, excluded) {
  if (group === null) return null
  const first = group.index.first()
  if (first !== excluded) return first
  return group.index.successor(first)
}

function prospectiveGroupWinner (group, removeKey, addKey, compare) {
  let winner = firstGroupKeyExcluding(group, removeKey)
  if (addKey !== null && (winner === null || compare(addKey, winner) < 0)) winner = addKey
  return winner
}

export class AppCatalogCapabilitySession {
  constructor (opts) {
    this.keyPair = validKeyPair(opts.keyPair)
    this.localPubkey = pubkeyHex(this.keyPair.publicKey, 'local public key')
    this.remotePubkey = pubkeyHex(opts.remotePubkey, 'remote public key')
    this.now = typeof opts.now === 'function' ? opts.now : Date.now
    this.startedAt = safeInteger(this.now(), 'capability startedAt')
    this.expiresAt = this.startedAt + APP_CATALOG_LIMITS.negotiationTimeoutMs
    if (!Number.isSafeInteger(this.expiresAt)) fail('PROTOCOL_ERROR', 'capability deadline overflow')
    this.closed = false
    this.sentProof = false
    this.verifiedPeerProof = false
    this._issuedNonce = b4a.alloc(32)
    if (typeof opts.randomBytes === 'function') {
      const generated = opts.randomBytes(32)
      if (!generated || generated.byteLength !== 32) fail('PROTOCOL_ERROR', 'capability nonce source returned the wrong size')
      b4a.from(generated).copy(this._issuedNonce)
    } else {
      sodium.randombytes_buf(this._issuedNonce)
    }
    this._challenge = Object.freeze({ type: 0, nonce: b4a.toString(this._issuedNonce, 'hex') })
    this._peerChallenge = null
    this._localProof = null
  }

  get ready () {
    return !this.closed && this.sentProof && this.verifiedPeerProof
  }

  challenge () {
    this._assertNegotiating()
    return this._challenge
  }

  createProof (input, issuedAt = this.now()) {
    this._assertNegotiating()
    const challenge = validateCapabilityChallenge(input)
    safeInteger(issuedAt, 'issuedAt')
    if (this._peerChallenge !== null && challenge.nonce !== this._peerChallenge) {
      fail('PROTOCOL_ERROR', 'peer changed its channel-fresh challenge')
    }
    if (this._localProof !== null) return this._localProof
    this._peerChallenge = challenge.nonce
    const proof = {
      type: 1,
      nonce: challenge.nonce,
      senderPubkey: this.localPubkey,
      protocolMajor: 1,
      protocolMinor: 1,
      features: ['app-catalog-paged-v1'],
      issuedAt,
      signature: ''
    }
    proof.signature = sign(capabilityProofSignable(proof), this.keyPair.secretKey)
    this._localProof = validateCapabilityProof(proof)
    return this._localProof
  }

  markProofSent (proof) {
    this._assertNegotiating()
    if (this._localProof === null || !sameJson(proof, this._localProof)) fail('PROTOCOL_ERROR', 'sent capability proof was not the channel proof')
    this.sentProof = true
    return this.ready
  }

  verifyPeerProof (input, verifierNow = this.now()) {
    this._assertNegotiating()
    if (this.verifiedPeerProof || this._issuedNonce === null) fail('PROTOCOL_ERROR', 'capability nonce was already accepted')
    const proof = validateCapabilityProof(input)
    safeInteger(verifierNow, 'verifierNow')
    if (proof.nonce !== b4a.toString(this._issuedNonce, 'hex')) fail('PROTOCOL_ERROR', 'capability proof nonce mismatch')
    if (proof.senderPubkey !== this.remotePubkey) fail('PROTOCOL_ERROR', 'capability proof authenticated key mismatch')
    if (Math.abs(verifierNow - proof.issuedAt) > APP_CATALOG_LIMITS.capabilityClockSkewMs) {
      fail('PROTOCOL_ERROR', 'capability proof time is outside the accepted window')
    }
    const signature = b4a.from(proof.signature, 'hex')
    const valid = sodium.crypto_sign_verify_detached(
      signature,
      capabilityProofSignable(proof),
      b4a.from(this.remotePubkey, 'hex')
    )
    if (!valid) fail('PROTOCOL_ERROR', 'capability proof signature is invalid')
    this._issuedNonce.fill(0)
    this._issuedNonce = null
    this.verifiedPeerProof = true
    return this.ready
  }

  assertReady () {
    this._assertOpen()
    if (!this.ready) fail('PROTOCOL_ERROR', 'paged catalog capability is incomplete')
  }

  close () {
    if (this.closed) return
    this.closed = true
    if (this._issuedNonce !== null) this._issuedNonce.fill(0)
    this._issuedNonce = null
  }

  _assertOpen () {
    if (this.closed) fail('PROTOCOL_ERROR', 'catalog capability channel is closed')
  }

  _assertNegotiating () {
    this._assertOpen()
    if (this.now() > this.expiresAt && !this.ready) {
      this.close()
      fail('PROTOCOL_ERROR', 'catalog capability negotiation expired')
    }
  }
}

export class AppCatalogMvccStore {
  constructor (opts = {}) {
    this.maxHistoryRecords = boundedOption(
      opts.maxHistoryRecords,
      APP_CATALOG_LIMITS.maxMvccRecords,
      APP_CATALOG_LIMITS.maxMvccRecords,
      'maxHistoryRecords'
    )
    this.maxHistoryBytes = boundedOption(
      opts.maxHistoryBytes,
      APP_CATALOG_LIMITS.maxMvccBytes,
      APP_CATALOG_LIMITS.maxMvccBytes,
      'maxHistoryBytes'
    )
    this.maxReaders = boundedOption(
      opts.maxReaders,
      APP_CATALOG_LIMITS.maxOutboundPeers,
      APP_CATALOG_LIMITS.maxOutboundPeers,
      'maxReaders'
    )
    this.maxSources = boundedOption(
      opts.maxSources,
      APP_CATALOG_LIMITS.maxSnapshotEntries,
      APP_CATALOG_LIMITS.maxSnapshotEntries,
      'maxSources'
    )
    this.lastCatalogRevision = 0
    this.excludedRows = 0
    this._sources = new Map()
    this._groups = new Map()
    this._rows = new Map()
    this._rowOwners = new Map()
    this._indexMetrics = { rowComparisons: 0, groupComparisons: 0 }
    this._rowIndex = new OrderedIndex(compareText, () => { this._indexMetrics.rowComparisons++ })
    this._history = []
    this._historyBytes = 0
    this._readers = new Set()
    this._digestReaders = 0
    this._sessionReaders = 0
    this._snapshots = new Map()
    this._publishedSnapshot = null
    this.stopped = false
  }

  get size () {
    return this._rows.size
  }

  get historyRecords () {
    return this._history.length
  }

  get historyBytes () {
    return this._historyBytes
  }

  get historyFloor () {
    if (this._history.length === 0) return this.lastCatalogRevision
    return this._history[0].revision - 1
  }

  get publishedSnapshot () {
    return this._publishedSnapshot
  }

  get indexMetrics () {
    return Object.freeze({ ...this._indexMetrics })
  }

  put (sourceKey, source) {
    this._assertMutable()
    this._validateSourceKey(sourceKey)
    if (!this._sources.has(sourceKey) && this._sources.size >= this.maxSources) {
      fail('RESOURCE_LIMIT', 'catalog source cap reached')
    }
    const projection = projectAppCatalogSource(source)
    if (projection.eligible) assertCatalogRowFitsPage(projection.row)
    const nextEntry = {
      eligible: projection.eligible,
      row: projection.row,
      identity: projection.eligible ? rowIdentity(projection.row) : null,
      reason: projection.reason,
      indexKey: null
    }
    const previous = this._sources.get(sourceKey) || null
    if (previous !== null && sourceEntriesEqual(previous, nextEntry)) {
      return Object.freeze({
        revision: this.lastCatalogRevision,
        eligible: nextEntry.eligible,
        reason: nextEntry.reason,
        changed: false
      })
    }
    if (nextEntry.identity !== null) nextEntry.indexKey = { sourceKey, row: nextEntry.row }
    return this._mutate(sourceKey, nextEntry)
  }

  delete (sourceKey) {
    this._assertMutable()
    this._validateSourceKey(sourceKey)
    if (!this._sources.has(sourceKey)) return false
    this._mutate(sourceKey, null)
    return true
  }

  isHighWaterRetained (highWater) {
    if (!Number.isSafeInteger(highWater) || highWater < 0 || highWater > this.lastCatalogRevision) return false
    if (highWater === this.lastCatalogRevision) return true
    return this._history.length > 0 && highWater >= this.historyFloor
  }

  readSnapshotPage ({ highWater, cursor = null, limit = APP_CATALOG_LIMITS.maxPageEntries }) {
    safeInteger(highWater, 'highWater')
    if (cursor !== null) hex64(cursor, 'cursor')
    safeInteger(limit, 'limit', 1, APP_CATALOG_LIMITS.externalApiMaxPageEntries)
    if (!this.isHighWaterRetained(highWater)) fail('HISTORY_EXPIRED', 'catalog snapshot history expired')

    const historicalKeys = new Set()
    for (let i = this._history.length - 1; i >= 0; i--) {
      const entry = this._history[i]
      if (entry.revision <= highWater) break
      for (const change of entry.changes) {
        if (cursor === null || change.rowKey > cursor) historicalKeys.add(change.rowKey)
      }
    }
    const changedKeys = [...historicalKeys].sort()
    const currentRows = this._rowIndex.iteratorAfter(cursor)
    let currentKey = currentRows.next()
    let changedIndex = 0
    const rows = []
    let lastCandidate = null
    let hasMore = false

    while (true) {
      const changedKey = changedKeys[changedIndex] ?? null
      let key
      if (currentKey === null && changedKey === null) break
      if (changedKey === null || (currentKey !== null && currentKey < changedKey)) {
        key = currentKey
        currentKey = currentRows.next()
      } else if (currentKey === null || changedKey < currentKey) {
        key = changedKey
        changedIndex++
      } else {
        key = currentKey
        currentKey = currentRows.next()
        changedIndex++
      }
      if (key === lastCandidate) continue
      lastCandidate = key
      const row = this._rowAt(key, highWater)
      if (row === null) continue
      if (rows.length === limit) {
        hasMore = true
        break
      }
      rows.push(row)
    }

    return Object.freeze({
      highWater,
      cursor,
      rows: Object.freeze(rows.slice()),
      complete: !hasMore,
      lastRowKey: rows.length === 0 ? cursor : rows[rows.length - 1][0]
    })
  }

  beginDigest (opts) {
    this._assertOpen()
    return new AppCatalogSnapshotBuild(this, {
      senderPubkey: pubkeyHex(opts.senderPubkey, 'senderPubkey'),
      highWater: this.lastCatalogRevision,
      entryCount: this._rows.size,
      budget: opts.budget
    })
  }

  openReader (highWater, onExpire, kind = 'outbound') {
    this._assertOpen()
    safeInteger(highWater, 'reader highWater')
    if (!this.isHighWaterRetained(highWater)) fail('HISTORY_EXPIRED', 'catalog snapshot history expired')
    const digestReader = kind === 'digest'
    if (digestReader ? this._digestReaders >= 1 : this._sessionReaders >= this.maxReaders) {
      fail('RESOURCE_LIMIT', digestReader ? 'catalog digest reader slot is occupied' : 'catalog MVCC session reader cap reached')
    }
    const reader = {
      highWater,
      kind,
      expired: false,
      closed: false,
      onExpire: typeof onExpire === 'function' ? onExpire : null,
      close: () => {
        this._closeReader(reader)
      }
    }
    this._readers.add(reader)
    if (digestReader) this._digestReaders++
    else this._sessionReaders++
    return reader
  }

  publishSnapshot (snapshot) {
    this._assertOpen()
    this._validateSnapshotIdentity(snapshot)
    if (!this.isHighWaterRetained(snapshot.highWater)) fail('HISTORY_EXPIRED', 'completed snapshot history expired before publish')
    this._publishedSnapshot = Object.freeze({ ...snapshot })
    this._snapshots.set(snapshot.highWater, this._publishedSnapshot)
    this._pruneSnapshots()
    return this._publishedSnapshot
  }

  readExternalPage ({ cursor, limit = APP_CATALOG_LIMITS.externalApiMaxPageEntries, status = false, keyPair }) {
    this._assertOpen()
    const hardLimit = status
      ? APP_CATALOG_LIMITS.externalStatusMaxPageEntries
      : APP_CATALOG_LIMITS.externalApiMaxPageEntries
    safeInteger(limit, 'external catalog limit', 1, hardLimit)
    if (this._publishedSnapshot === null) fail('CURSOR_EXPIRED', 'no completed catalog snapshot is available')

    let snapshot = this._publishedSnapshot
    let lastRowKey = null
    if (cursor !== null && cursor !== undefined) {
      const verified = verifyAppCatalogExternalCursor(cursor, pubkeyHex(keyPair.publicKey, 'cursor signer'))
      snapshot = this._snapshots.get(verified.highWater) || null
      if (snapshot === null || verified.rootDigest !== snapshot.rootDigest) {
        fail('CURSOR_EXPIRED', 'external cursor snapshot tuple expired')
      }
      lastRowKey = verified.lastRowKey
    }
    if (!this.isHighWaterRetained(snapshot.highWater)) fail('CURSOR_EXPIRED', 'external cursor history expired')
    const page = this.readSnapshotPage({
      highWater: snapshot.highWater,
      cursor: lastRowKey,
      limit
    })
    const nextCursor = page.complete
      ? null
      : createAppCatalogExternalCursor({
        highWater: snapshot.highWater,
        rootDigest: snapshot.rootDigest,
        lastRowKey: page.lastRowKey
      }, keyPair)
    return Object.freeze({
      snapshot,
      entries: page.rows,
      complete: page.complete,
      cursor: nextCursor
    })
  }

  stop () {
    if (this.stopped) return
    this.stopped = true
    for (const reader of [...this._readers]) this._expireReader(reader, 'HISTORY_EXPIRED')
    this._readers.clear()
  }

  _mutate (sourceKey, nextEntry) {
    if (this.lastCatalogRevision === Number.MAX_SAFE_INTEGER) {
      fail('RESOURCE_LIMIT', 'catalog revision exhausted; operator rebuild required')
    }
    const previous = this._sources.get(sourceKey) || null
    const identities = new Set()
    if (previous && previous.identity !== null) identities.add(previous.identity)
    if (nextEntry && nextEntry.identity !== null) identities.add(nextEntry.identity)

    const plans = new Map()
    const changes = []
    for (const identity of identities) {
      const group = this._groups.get(identity) || null
      const compare = group === null ? (left, right) => compareGroupKeys(identity, left, right) : group.compare
      const removeKey = previous && previous.identity === identity ? previous.indexKey : null
      const addKey = nextEntry && nextEntry.identity === identity ? nextEntry.indexKey : null
      const beforeKey = group === null ? null : group.index.first()
      const remainingKey = firstGroupKeyExcluding(group, removeKey)
      if (!identity.startsWith('public-app:') && addKey !== null && remainingKey !== null &&
          !sameJson(addKey.row, remainingKey.row)) {
        fail('SNAPSHOT_MISMATCH', 'catalog row-key collision')
      }
      const afterKey = prospectiveGroupWinner(group, removeKey, addKey, compare)
      const before = beforeKey === null ? null : beforeKey.row
      const after = afterKey === null ? null : afterKey.row
      plans.set(identity, { identity, group, compare, removeKey, addKey, afterKey })
      if (!sameJson(before, after)) {
        const rowKey = before ? before[0] : after[0]
        changes.push({ rowKey, before, after })
      }
    }
    changes.sort((a, b) => a.rowKey.localeCompare(b.rowKey))
    const revision = this.lastCatalogRevision + 1
    const history = { revision, changes }
    const bytes = b4a.byteLength(JSON.stringify(history))
    if (bytes > this.maxHistoryBytes) fail('RESOURCE_LIMIT', 'single catalog MVCC record exceeds history byte cap')

    const removingOwners = new Set(changes.filter(change => change.after === null).map(change => change.rowKey))
    for (const [identity, plan] of plans) {
      if (plan.afterKey === null) continue
      const owner = this._rowOwners.get(plan.afterKey.row[0])
      if (owner !== undefined && owner !== identity && !removingOwners.has(plan.afterKey.row[0])) {
        fail('SNAPSHOT_MISMATCH', 'terminal catalog row-key collision')
      }
    }

    for (const [identity, plan] of plans) {
      let group = plan.group
      if (group === null) {
        group = {
          compare: plan.compare,
          index: new OrderedIndex(plan.compare, () => { this._indexMetrics.groupComparisons++ })
        }
      }
      if (plan.removeKey !== null && !group.index.delete(plan.removeKey)) {
        fail('SNAPSHOT_MISMATCH', 'catalog winner index lost its source')
      }
      if (plan.addKey !== null) group.index.set(plan.addKey)
      if (group.index.size === 0) this._groups.delete(identity)
      else this._groups.set(identity, group)
    }
    if (previous && !previous.eligible) this.excludedRows--
    if (nextEntry === null) this._sources.delete(sourceKey)
    else {
      this._sources.set(sourceKey, nextEntry)
      if (!nextEntry.eligible) this.excludedRows++
    }
    for (const change of changes) {
      if (change.after === null) {
        this._rows.delete(change.rowKey)
        this._rowOwners.delete(change.rowKey)
        this._rowIndex.delete(change.rowKey)
      } else {
        if (!this._rows.has(change.rowKey)) this._rowIndex.set(change.rowKey)
        this._rows.set(change.rowKey, change.after)
        this._rowOwners.set(change.rowKey, rowIdentity(change.after))
      }
    }
    this.lastCatalogRevision = revision
    this._history.push({ ...history, bytes })
    this._historyBytes += bytes
    this._evictHistory()
    return Object.freeze({
      revision,
      eligible: nextEntry ? nextEntry.eligible : false,
      reason: nextEntry ? nextEntry.reason : null,
      changed: true
    })
  }

  _evictHistory () {
    while (this._history.length > this.maxHistoryRecords || this._historyBytes > this.maxHistoryBytes) {
      const oldest = this._history[0]
      for (const reader of [...this._readers]) {
        if (reader.highWater < oldest.revision) this._expireReader(reader, 'HISTORY_EXPIRED')
      }
      this._history.shift()
      this._historyBytes -= oldest.bytes
      this._pruneSnapshots()
    }
  }

  _expireReader (reader, code) {
    if (reader.closed) return
    reader.expired = true
    this._closeReader(reader)
    if (reader.onExpire) {
      try { reader.onExpire(code) } catch {}
    }
  }

  _closeReader (reader) {
    if (reader.closed) return
    reader.closed = true
    this._readers.delete(reader)
    if (reader.kind === 'digest') this._digestReaders--
    else this._sessionReaders--
  }

  _pruneSnapshots () {
    for (const highWater of this._snapshots.keys()) {
      if (highWater < this.historyFloor) this._snapshots.delete(highWater)
    }
    const hardCap = this.maxHistoryRecords + 1
    while (this._snapshots.size > hardCap) {
      const oldest = this._snapshots.keys().next().value
      this._snapshots.delete(oldest)
    }
    if (this._publishedSnapshot !== null && !this._snapshots.has(this._publishedSnapshot.highWater)) {
      this._publishedSnapshot = null
    }
  }

  _rowAt (rowKey, highWater) {
    let row = this._rows.get(rowKey) || null
    for (let i = this._history.length - 1; i >= 0; i--) {
      const history = this._history[i]
      if (history.revision <= highWater) break
      for (const change of history.changes) {
        if (change.rowKey === rowKey) {
          row = change.before
          break
        }
      }
    }
    return row
  }

  _validateSnapshotIdentity (snapshot) {
    if (!snapshot || typeof snapshot !== 'object') fail('PROTOCOL_ERROR', 'snapshot identity is required')
    hex64(snapshot.snapshotId, 'snapshotId')
    safeInteger(snapshot.highWater, 'highWater')
    hex64(snapshot.rootDigest, 'rootDigest')
    safeInteger(snapshot.entryCount, 'entryCount', 0, APP_CATALOG_LIMITS.maxSnapshotEntries)
    if (snapshot.snapshotId !== appCatalogSnapshotId(snapshot)) fail('SNAPSHOT_MISMATCH', 'snapshot identity is not canonical')
  }

  _validateSourceKey (sourceKey) {
    if (typeof sourceKey !== 'string' || b4a.byteLength(sourceKey) < 1 || b4a.byteLength(sourceKey) > 1_024) {
      fail('PROTOCOL_ERROR', 'catalog source key must be 1..1,024 UTF-8 bytes')
    }
  }

  _assertOpen () {
    if (this.stopped) fail('RESOURCE_LIMIT', 'catalog MVCC store is stopped')
  }

  _assertMutable () {
    this._assertOpen()
  }
}

export class AppCatalogSnapshotBuild {
  constructor (store, opts) {
    this.store = store
    this.senderPubkey = opts.senderPubkey
    this.highWater = opts.highWater
    this.entryCount = opts.entryCount
    this.budget = boundedOption(opts.budget, APP_CATALOG_LIMITS.maxPageEntries, APP_CATALOG_LIMITS.maxPageEntries, 'digest budget')
    this.cursor = null
    this.builder = new AppCatalogDigestBuilder(this.highWater, this.entryCount)
    this.done = false
    this.invalidated = false
    this.snapshot = null
    this.reader = store.openReader(this.highWater, () => {
      this.invalidated = true
    }, 'digest')
  }

  step () {
    if (this.done) return Object.freeze({ done: true, snapshot: this.snapshot })
    if (this.invalidated || this.reader.expired) fail('HISTORY_EXPIRED', 'catalog digest history expired')
    const page = this.store.readSnapshotPage({ highWater: this.highWater, cursor: this.cursor, limit: this.budget })
    for (const row of page.rows) this.builder.update(row)
    if (!page.complete) {
      this.cursor = page.lastRowKey
      return Object.freeze({ done: false, examined: page.rows.length, cursor: this.cursor })
    }
    const rootDigest = this.builder.final()
    const snapshot = Object.freeze({
      snapshotId: appCatalogSnapshotId({
        senderPubkey: this.senderPubkey,
        highWater: this.highWater,
        rootDigest,
        entryCount: this.entryCount
      }),
      senderPubkey: this.senderPubkey,
      highWater: this.highWater,
      rootDigest,
      entryCount: this.entryCount
    })
    this.reader.close()
    this.snapshot = this.store.publishSnapshot(snapshot)
    this.done = true
    return Object.freeze({ done: true, examined: page.rows.length, snapshot: this.snapshot })
  }

  close () {
    this.reader.close()
  }
}

function snapshotTupleMatches (message, snapshot) {
  return message.snapshotId === snapshot.snapshotId &&
    message.highWater === snapshot.highWater &&
    message.rootDigest === snapshot.rootDigest
}

export class AppCatalogOutboundSession {
  constructor (opts) {
    this.store = opts.store
    this.snapshot = opts.snapshot
    this.keyPair = validKeyPair(opts.keyPair)
    this.localPubkey = pubkeyHex(this.keyPair.publicKey, 'local public key')
    this.remotePubkey = pubkeyHex(opts.remotePubkey, 'remote public key')
    this.now = typeof opts.now === 'function' ? opts.now : Date.now
    this.sequence = 0
    this.cursor = null
    this.outstanding = null
    this.outstandingBytes = null
    this.lastAck = null
    this.retryCount = 0
    this.deadline = null
    this.dirty = false
    this.closed = false
    this.completed = false
    this.abort = null
    this.abortPending = false
    this.abortDelivery = null
    this._sendAbort = typeof opts.sendAbort === 'function' ? opts.sendAbort : null
    this._onClose = typeof opts.onClose === 'function' ? opts.onClose : null
    this.store._validateSnapshotIdentity(this.snapshot)
    if (this.snapshot.senderPubkey !== undefined && this.snapshot.senderPubkey !== this.localPubkey) {
      fail('SNAPSHOT_MISMATCH', 'outbound snapshot sender mismatch')
    }
    this.reader = this.store.openReader(this.snapshot.highWater, () => {
      this._prepareAbort('HISTORY_EXPIRED')
    }, 'outbound')
  }

  trigger () {
    if (this.closed) return false
    this.dirty = true
    return true
  }

  issuePage () {
    if (this.abort !== null) return Object.freeze({ abort: this.abort, pending: this.abortPending })
    this._assertOpen()
    if (this.outstanding !== null) return Object.freeze({ page: this.outstanding, retransmit: false, outstanding: true })
    if (this.reader.expired || !this.store.isHighWaterRetained(this.snapshot.highWater)) {
      return Object.freeze({ abort: this._prepareAbort('HISTORY_EXPIRED'), pending: true })
    }
    const sourcePage = this.store.readSnapshotPage({
      highWater: this.snapshot.highWater,
      cursor: this.cursor,
      limit: APP_CATALOG_LIMITS.maxPageEntries
    })
    if (sourcePage.rows.length === 0 && this.snapshot.entryCount !== 0) {
      return Object.freeze({ abort: this._prepareAbort('SNAPSHOT_MISMATCH'), pending: true })
    }
    const entries = sourcePage.rows.slice()
    let page = null
    while (page === null) {
      const complete = sourcePage.complete && entries.length === sourcePage.rows.length
      const nextCursor = complete ? null : entries[entries.length - 1][0]
      try {
        page = createAppCatalogPage({
          receiverPubkey: this.remotePubkey,
          snapshotId: this.snapshot.snapshotId,
          highWater: this.snapshot.highWater,
          rootDigest: this.snapshot.rootDigest,
          entryCount: this.snapshot.entryCount,
          sequence: this.sequence,
          cursor: this.cursor,
          nextCursor,
          complete,
          entries
        }, this.keyPair)
      } catch (err) {
        if (!(err instanceof AppCatalogProtocolError) || err.code !== 'CATALOG_ENTRY_TOO_LARGE') throw err
        if (entries.length <= 1) return Object.freeze({ abort: this._prepareAbort('CATALOG_ENTRY_TOO_LARGE'), pending: true })
        entries.pop()
      }
    }
    this.outstanding = page
    this.outstandingBytes = b4a.from(JSON.stringify(page), 'utf8')
    this.retryCount = 0
    this.deadline = this.now() + APP_CATALOG_LIMITS.ackTimeoutMs
    return Object.freeze({ page, bytes: this.outstandingBytes, retransmit: false, outstanding: true })
  }

  acceptAck (input) {
    let ack
    try {
      ack = verifyAppCatalogAck(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
    } catch {
      return Object.freeze({ status: 'aborted', abort: this._prepareAbort('PROTOCOL_ERROR') })
    }
    if (this.closed) {
      if (this.completed && this.lastAck !== null && sameJson(ack, this.lastAck)) {
        return Object.freeze({ status: 'duplicate', complete: true })
      }
      const abort = this.abort || createAppCatalogAbort({
        receiverPubkey: this.remotePubkey,
        snapshotId: this.snapshot.snapshotId,
        code: 'PROTOCOL_ERROR'
      }, this.keyPair)
      return Object.freeze({ status: 'aborted', abort })
    }
    if (this.abort !== null) return Object.freeze({ status: 'aborted', abort: this.abort })
    if (this.lastAck !== null && sameJson(ack, this.lastAck)) {
      return Object.freeze({ status: 'duplicate', complete: this.completed })
    }
    if (this.outstanding === null) {
      return Object.freeze({ status: 'aborted', abort: this._prepareAbort('PROTOCOL_ERROR') })
    }
    const page = this.outstanding
    const exact = snapshotTupleMatches(ack, this.snapshot) &&
      ack.sequence === page.sequence &&
      ack.pageDigest === page.pageDigest &&
      ack.nextCursor === page.nextCursor
    if (!exact) return Object.freeze({ status: 'aborted', abort: this._prepareAbort('PROTOCOL_ERROR') })

    this.lastAck = ack
    this.outstanding = null
    this.outstandingBytes = null
    this.deadline = null
    this.retryCount = 0
    if (page.complete) {
      this.completed = true
      this._close()
      return Object.freeze({ status: 'complete', complete: true })
    }
    this.cursor = page.nextCursor
    this.sequence++
    return Object.freeze({ status: 'advanced', complete: false })
  }

  acceptAbort (input) {
    let abort
    try {
      abort = verifyAppCatalogAbort(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
    } catch {
      return Object.freeze({ status: 'mismatch' })
    }
    if (abort.snapshotId !== this.snapshot.snapshotId) return Object.freeze({ status: 'mismatch' })
    if (this.closed) {
      return Object.freeze({ status: this.abort !== null && sameJson(abort, this.abort) ? 'duplicate' : 'mismatch' })
    }
    this.abort = abort
    this.abortPending = false
    this.outstanding = null
    this.outstandingBytes = null
    this.deadline = null
    this._close()
    return Object.freeze({ status: 'closed', abort })
  }

  onAckDeadline (now = this.now()) {
    if (this.closed || this.outstanding === null || this.deadline === null || now < this.deadline) return null
    if (this.retryCount >= APP_CATALOG_LIMITS.maxPageRetransmits) {
      return Object.freeze({ abort: this._prepareAbort('RESOURCE_LIMIT'), exhausted: true })
    }
    this.retryCount++
    this.deadline = now + APP_CATALOG_LIMITS.ackTimeoutMs
    return Object.freeze({
      page: this.outstanding,
      bytes: this.outstandingBytes,
      retransmit: true,
      retry: this.retryCount
    })
  }

  stop () {
    if (this.closed) return
    this._prepareAbort('RESOURCE_LIMIT')
    this._close()
  }

  confirmAbortSent () {
    if (this.abort === null) return false
    this.abortPending = false
    this._close()
    return true
  }

  _prepareAbort (code) {
    if (this.abort !== null) return this.abort
    this.abort = createAppCatalogAbort({
      receiverPubkey: this.remotePubkey,
      snapshotId: this.snapshot.snapshotId,
      code
    }, this.keyPair)
    this.abortPending = true
    this.outstanding = null
    this.outstandingBytes = null
    this.deadline = null
    if (this._sendAbort !== null) {
      try {
        const delivery = this._sendAbort(this.abort)
        if (delivery && typeof delivery.then === 'function') {
          this.abortDelivery = Promise.resolve(delivery).then(
            () => this.confirmAbortSent(),
            () => false
          )
        } else {
          this.confirmAbortSent()
        }
      } catch {}
    }
    return this.abort
  }

  _close () {
    if (this.closed) return
    this.closed = true
    this.reader.close()
    if (this._onClose) this._onClose(this)
  }

  _assertOpen () {
    if (this.closed) fail('RESOURCE_LIMIT', 'outbound catalog session is closed')
  }
}

export class AppCatalogOutboundManager {
  constructor (opts) {
    this.store = opts.store
    this.keyPair = validKeyPair(opts.keyPair)
    this.localPubkey = pubkeyHex(this.keyPair.publicKey, 'local public key')
    this.now = typeof opts.now === 'function' ? opts.now : Date.now
    this.maxPeers = boundedOption(opts.maxPeers, APP_CATALOG_LIMITS.maxOutboundPeers, APP_CATALOG_LIMITS.maxOutboundPeers, 'max outbound peers')
    this.sendAbort = typeof opts.sendAbort === 'function' ? opts.sendAbort : null
    this.sendPage = typeof opts.sendPage === 'function' ? opts.sendPage : null
    this.onDeadlineAction = typeof opts.onDeadlineAction === 'function' ? opts.onDeadlineAction : null
    this.onSessionReady = typeof opts.onSessionReady === 'function' ? opts.onSessionReady : null
    this.deadlineSweepMs = boundedOption(
      opts.deadlineSweepMs,
      1_000,
      APP_CATALOG_LIMITS.ackTimeoutMs,
      'deadlineSweepMs'
    )
    this.stopDrainTimeoutMs = boundedOption(
      opts.stopDrainTimeoutMs,
      1_000,
      APP_CATALOG_LIMITS.ackTimeoutMs,
      'stopDrainTimeoutMs'
    )
    this.sessions = new Map()
    this.terminalAckReceipts = new Map()
    this.terminalAbortReceipts = new Map()
    this.stopped = false
    this._deadlineTimer = null
    this._deadlineFlight = null
    this._deadlineEpoch = 0
    this._autoDeadlineSweep = opts.autoDeadlineSweep !== false
    if (this._autoDeadlineSweep) {
      if (this.sendPage === null && this.onDeadlineAction === null) {
        fail('PROTOCOL_ERROR', 'automatic ACK deadline sweep requires sendPage or onDeadlineAction')
      }
      this._armDeadlineSweep()
    }
  }

  open (remotePubkey, snapshot = this.store.publishedSnapshot) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'outbound catalog manager is stopped')
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const existing = this.sessions.get(peer)
    if (existing) {
      if (!existing.closed) {
        existing.trigger()
        return existing
      }
      if (existing.completed && snapshot && snapshot.snapshotId === existing.snapshot.snapshotId) {
        existing.dirty = true
        return existing
      }
      this.sessions.delete(peer)
    }
    const knownPeer = this.terminalAckReceipts.has(peer) || this.terminalAbortReceipts.has(peer)
    if (!knownPeer && this._peerStateCount() >= this.maxPeers) fail('RESOURCE_LIMIT', 'outbound catalog peer cap reached')
    if (!snapshot) fail('SNAPSHOT_MISMATCH', 'no completed catalog snapshot is available')
    const session = new AppCatalogOutboundSession({
      store: this.store,
      snapshot,
      keyPair: this.keyPair,
      remotePubkey: peer,
      now: this.now,
      sendAbort: this.sendAbort === null ? null : abort => this.sendAbort(peer, abort),
      onClose: closed => this._onSessionClosed(peer, closed)
    })
    this.sessions.set(peer, session)
    return session
  }

  async runTurn (remotePubkey, send) {
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const epoch = this._deadlineEpoch
    if (this.stopped) return Object.freeze({ pages: 0, status: 'stopped' })
    const session = this.sessions.get(peer)
    if (!session) return Object.freeze({ pages: 0, status: 'missing' })
    let pages = 0
    let status = 'waiting'
    while (pages < APP_CATALOG_LIMITS.maxPagesPerTurn && !session.closed && !this.stopped && epoch === this._deadlineEpoch) {
      const issued = session.issuePage()
      if (issued.abort) {
        await this._deliverAbort(peer, session, issued.abort, send, epoch)
        status = 'aborted'
        break
      }
      pages++
      const response = await send(issued.page)
      if (this.stopped || epoch !== this._deadlineEpoch) {
        status = 'stopped'
        break
      }
      if (!response || typeof response !== 'object' || Array.isArray(response)) {
        status = response === false ? 'backpressure' : 'sent'
        break
      }
      const accepted = session.acceptAck(response)
      status = accepted.status
      if (accepted.abort) {
        await this._deliverAbort(peer, session, accepted.abort, send, epoch)
        break
      }
      if (accepted.complete) break
    }
    return Object.freeze({ pages, status })
  }

  acceptAck (remotePubkey, ack) {
    if (this.stopped) return Object.freeze({ status: 'stopped' })
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const receipt = this.terminalAckReceipts.get(peer)
    if (receipt && sameJson(ack, receipt.ack)) {
      return Object.freeze({ status: 'duplicate', complete: true })
    }
    const session = this.sessions.get(peer)
    if (!session) {
      if (receipt) return receipt.session.acceptAck(ack)
      return Object.freeze({ status: 'missing' })
    }
    return session.acceptAck(ack)
  }

  acceptAbort (remotePubkey, abort) {
    if (this.stopped) return Object.freeze({ status: 'stopped' })
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    let verified
    try {
      verified = verifyAppCatalogAbort(abort, { localPubkey: this.localPubkey, remotePubkey: peer })
    } catch {
      return Object.freeze({ status: 'mismatch' })
    }
    const receipt = this.terminalAbortReceipts.get(peer)
    if (receipt && sameJson(verified, receipt)) return Object.freeze({ status: 'duplicate', closed: true })
    const session = this.sessions.get(peer)
    if (!session) return Object.freeze({ status: receipt ? 'mismatch' : 'missing' })
    const accepted = session.acceptAbort(verified)
    if (accepted.status !== 'closed') return accepted
    this.sessions.delete(peer)
    this.terminalAbortReceipts.set(peer, verified)
    return accepted
  }

  async sweepDeadlines (now = this.now(), epoch = this._deadlineEpoch) {
    const actions = []
    if (this.stopped || epoch !== this._deadlineEpoch) return Object.freeze(actions)
    for (const [peer, session] of [...this.sessions]) {
      if (this.stopped || epoch !== this._deadlineEpoch) break
      if (session.closed) continue
      const action = session.onAckDeadline(now)
      if (action === null) continue
      actions.push(Object.freeze({ peer, ...action }))
      if (action.page) {
        if (this.sendPage !== null) await this.sendPage(peer, action.page, { retransmit: true, retry: action.retry })
        else await this.onDeadlineAction(peer, action)
        if (this.stopped || epoch !== this._deadlineEpoch) break
      } else if (action.abort) {
        await this._deliverAbort(peer, session, action.abort, null, epoch)
        if (this.stopped || epoch !== this._deadlineEpoch) break
      }
    }
    return Object.freeze(actions)
  }

  closePeer (remotePubkey) {
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const session = this.sessions.get(peer)
    const receipt = this.terminalAckReceipts.delete(peer)
    const abortReceipt = this.terminalAbortReceipts.delete(peer)
    if (!session) return receipt || abortReceipt || false
    this.sessions.delete(peer)
    if (!session.closed) session.stop()
    return true
  }

  async stop () {
    if (this.stopped) return
    this.stopped = true
    this._deadlineEpoch++
    const drainDeadline = Date.now() + this.stopDrainTimeoutMs
    if (this._deadlineTimer !== null) clearTimeout(this._deadlineTimer)
    this._deadlineTimer = null
    if (this._deadlineFlight !== null) {
      const flight = this._deadlineFlight
      const remaining = Math.max(0, drainDeadline - Date.now())
      if (!(remaining > 0 && await settleWithin(flight, remaining)) && this._deadlineFlight === flight) {
        this._deadlineFlight = null
      }
    }
    const sessions = [...this.sessions.values()]
    for (const session of sessions) session.stop()
    const abortDeliveries = sessions.map(session => session.abortDelivery).filter(Boolean)
    const remaining = Math.max(0, drainDeadline - Date.now())
    if (abortDeliveries.length > 0 && remaining > 0) {
      await settleWithin(Promise.allSettled(abortDeliveries), remaining)
    }
    this.sessions.clear()
    this.terminalAckReceipts.clear()
    this.terminalAbortReceipts.clear()
  }

  _onSessionClosed (peer, session) {
    if (this.sessions.get(peer) !== session) return
    const newest = this.store.publishedSnapshot
    if (!session.completed) {
      this.sessions.delete(peer)
      const restart = !this.stopped && !session.abortPending && session.dirty && newest !== null &&
        newest.snapshotId !== session.snapshot.snapshotId && session.abort?.senderPubkey === session.localPubkey &&
        session.abort.code === 'HISTORY_EXPIRED'
      if (restart) this._notifySessionReady(peer, this.open(peer, newest), 'history-expired')
      return
    }
    this.terminalAckReceipts.set(peer, Object.freeze({ ack: session.lastAck, session }))
    if (!session.dirty || !newest || newest.snapshotId === session.snapshot.snapshotId || this.stopped) return
    this.sessions.delete(peer)
    this.open(peer, newest)
  }

  _notifySessionReady (peer, session, reason) {
    if (this.onSessionReady === null) return
    try {
      const notified = this.onSessionReady(peer, session, Object.freeze({ reason }))
      if (notified && typeof notified.then === 'function') Promise.resolve(notified).catch(() => {})
    } catch {}
  }

  _peerStateCount () {
    const peers = new Set(this.sessions.keys())
    for (const peer of this.terminalAckReceipts.keys()) peers.add(peer)
    for (const peer of this.terminalAbortReceipts.keys()) peers.add(peer)
    return peers.size
  }

  async _deliverAbort (peer, session, abort, fallbackSend, epoch = null) {
    const active = () => epoch === null || (!this.stopped && epoch === this._deadlineEpoch)
    if (!active()) return
    if (session.abortDelivery !== null) {
      await session.abortDelivery
      if (!active()) return
      session.abortDelivery = null
      if (!session.abortPending) return
    }
    if (!session.abortPending) return
    if (this.sendAbort !== null) {
      // A synchronous injected send already ran inside _prepareAbort(). If it
      // threw, abortPending remains true and this retry owns the send.
      await this.sendAbort(peer, abort)
    } else if (fallbackSend !== null) {
      await fallbackSend(abort)
    } else if (this.onDeadlineAction !== null) {
      await this.onDeadlineAction(peer, { abort })
    } else {
      return
    }
    if (!active()) return
    session.confirmAbortSent()
  }

  _armDeadlineSweep () {
    if (this.stopped || !this._autoDeadlineSweep || this._deadlineTimer !== null || this._deadlineFlight !== null) return
    const epoch = this._deadlineEpoch
    this._deadlineTimer = setTimeout(() => {
      this._deadlineTimer = null
      if (this.stopped || epoch !== this._deadlineEpoch) return
      const flight = this.sweepDeadlines(this.now(), epoch)
      this._deadlineFlight = flight
      Promise.resolve(flight).catch(() => {}).finally(() => {
        if (this._deadlineFlight === flight) this._deadlineFlight = null
        this._armDeadlineSweep()
      })
    }, this.deadlineSweepMs)
    if (this._deadlineTimer && typeof this._deadlineTimer.unref === 'function') this._deadlineTimer.unref()
  }
}

export class AppCatalogInboundSession {
  constructor (opts) {
    this.manager = opts.manager
    this.keyPair = validKeyPair(opts.keyPair)
    this.localPubkey = pubkeyHex(this.keyPair.publicKey, 'local public key')
    this.remotePubkey = pubkeyHex(opts.remotePubkey, 'remote public key')
    this.stageFactory = opts.stageFactory
    if (!this.stageFactory || typeof this.stageFactory.open !== 'function') {
      fail('RESOURCE_LIMIT', 'owned no-follow catalog stage factory is required')
    }
    this.now = typeof opts.now === 'function' ? opts.now : Date.now
    this.maxEntries = opts.maxEntries
    this.maxSessionBytes = opts.maxSessionBytes
    this.startedAt = safeInteger(this.now(), 'inbound startedAt')
    this.lastActivityAt = this.startedAt
    this.stage = null
    this.snapshot = null
    this.digest = null
    this.sequence = 0
    this.cursor = null
    this.entryCount = 0
    this.stagedBytes = 0
    this.lastPageDigest = null
    this.lastPage = null
    this.lastAck = null
    this.closed = false
    this.completed = false
    this.stopped = false
    this._stopEpoch = 0
    this._stop = null
    this._receiveFlights = new Set()
    this.committedCatalog = null
    this.abort = null
    this._onComplete = typeof opts.onComplete === 'function' ? opts.onComplete : null
    this._onActionError = typeof opts.onActionError === 'function' ? opts.onActionError : null
  }

  receivePage (input, managerEpoch = this.manager._receiveEpoch) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'inbound catalog session is stopped')
    const stopEpoch = this._stopEpoch
    const flight = this._receivePage(input, stopEpoch, managerEpoch)
    this._receiveFlights.add(flight)
    Promise.resolve(flight).then(
      () => this._receiveFlights.delete(flight),
      () => this._receiveFlights.delete(flight)
    )
    return flight
  }

  async _receivePage (input, stopEpoch, managerEpoch) {
    this._assertReceiveActive(stopEpoch, managerEpoch)
    if (this.closed) {
      let page
      try {
        page = verifyAppCatalogPage(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
      } catch {
        fail('PROTOCOL_ERROR', 'closed inbound session received an invalid PAGE')
      }
      if (this.completed && this.lastAck !== null && this.lastPage !== null && appCatalogPageRetransmitEquals(page, this.lastPage)) return this.lastAck
      fail('PROTOCOL_ERROR', 'closed inbound session PAGE is not a byte-exact retransmit')
    }
    if (this.completed) {
      const page = verifyAppCatalogPage(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
      if (this.lastAck === null || this.lastPage === null || !appCatalogPageRetransmitEquals(page, this.lastPage)) {
        fail('PROTOCOL_ERROR', 'finalizing inbound session PAGE is not a byte-exact retransmit')
      }
      await this._releaseCommittedCatalog()
      this._assertReceiveActive(stopEpoch, managerEpoch)
      this._close(false)
      return this.lastAck
    }
    const receivedAt = this.now()
    if ((receivedAt - this.lastActivityAt) >= APP_CATALOG_LIMITS.inboundIdleTimeoutMs ||
        (receivedAt - this.startedAt) >= APP_CATALOG_LIMITS.inboundHardTimeoutMs) {
      return this._abortAndThrow('RESOURCE_LIMIT', 'inbound catalog session expired')
    }
    const page = verifyAppCatalogPage(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
    if (this.lastPageDigest !== null && page.sequence === this.sequence - 1) {
      if (!appCatalogPageRetransmitEquals(page, this.lastPage)) return this._abortAndThrow('PROTOCOL_ERROR', 'inbound PAGE retransmit is not byte-exact')
      this.lastActivityAt = this.now()
      return this.lastAck
    }
    if (this.snapshot === null) {
      if (page.sequence !== 0 || page.cursor !== null) return this._abortAndThrow('SNAPSHOT_MISMATCH', 'inbound PAGE did not start at sequence 0')
      this.snapshot = Object.freeze({
        snapshotId: page.snapshotId,
        highWater: page.highWater,
        rootDigest: page.rootDigest,
        entryCount: page.entryCount,
        senderPubkey: page.senderPubkey
      })
      this.digest = new AppCatalogDigestBuilder(page.highWater, page.entryCount)
      if (APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES > this.maxSessionBytes ||
          !this.manager._reserveStagingBytes(APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES)) {
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog staging fixed overhead exceeds its cap')
      }
      this.stagedBytes = APP_CATALOG_STAGE_FIXED_OVERHEAD_BYTES
      try {
        const stage = await this.stageFactory.open({
          peerPubkey: this.remotePubkey,
          snapshotId: page.snapshotId,
          highWater: page.highWater,
          rootDigest: page.rootDigest,
          entryCount: page.entryCount
        })
        if (!this._receiveActive(stopEpoch, managerEpoch)) {
          this.stage = stage
          if (stage && typeof stage.discard === 'function') await stage.discard()
          this._throwStopped()
        }
        this.stage = stage
      } catch {
        if (!this._receiveActive(stopEpoch, managerEpoch)) this._throwStopped()
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog staging store could not be opened')
      }
      if (!this.stage || typeof this.stage.append !== 'function' || typeof this.stage.commit !== 'function' || typeof this.stage.discard !== 'function') {
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog staging store has an invalid ownership interface')
      }
    } else if (!snapshotTupleMatches(page, this.snapshot) || page.entryCount !== this.snapshot.entryCount) {
      return this._abortAndThrow('SNAPSHOT_MISMATCH', 'inbound PAGE changed its snapshot tuple')
    }
    if (page.sequence !== this.sequence || page.cursor !== this.cursor) {
      return this._abortAndThrow('PROTOCOL_ERROR', 'inbound PAGE sequence/cursor is stale or out of order')
    }

    for (const row of page.entries) {
      const bytes = b4a.from(JSON.stringify(row), 'utf8')
      const stagedBytes = 4 + APP_CATALOG_STAGE_ROW_INDEX_BYTES + bytes.byteLength
      if (this.entryCount + 1 > this.maxEntries ||
          this.entryCount + 1 > this.snapshot.entryCount ||
          this.stagedBytes + stagedBytes > this.maxSessionBytes) {
        return this._abortAndThrow('RESOURCE_LIMIT', 'inbound catalog session cap reached')
      }
      if (!this.manager._reserveStagingBytes(stagedBytes)) {
        return this._abortAndThrow('RESOURCE_LIMIT', 'process-wide inbound catalog staging cap reached')
      }
      // Once append owns the filesystem boundary, retain the full reservation
      // until discard succeeds. A rejected/partial append can still leave
      // exact on-disk ownership that a later terminal retry must account for.
      this.stagedBytes += stagedBytes
      try {
        await this.stage.append(row, bytes)
      } catch {
        if (!this._receiveActive(stopEpoch, managerEpoch)) this._throwStopped()
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog staging append failed')
      }
      if (!this._receiveActive(stopEpoch, managerEpoch)) this._throwStopped()
      this.entryCount++
      try {
        this.digest.update(row)
      } catch {
        return this._abortAndThrow('SNAPSHOT_MISMATCH', 'catalog staging digest rejected a row')
      }
    }

    if (page.complete) {
      if (this.entryCount !== this.snapshot.entryCount) return this._abortAndThrow('SNAPSHOT_MISMATCH', 'terminal PAGE entry count mismatch')
      let digest
      try {
        digest = this.digest.final()
      } catch {
        return this._abortAndThrow('SNAPSHOT_MISMATCH', 'terminal PAGE digest could not finalize')
      }
      if (digest !== this.snapshot.rootDigest) return this._abortAndThrow('SNAPSHOT_MISMATCH', 'terminal PAGE root digest mismatch')
    }

    this._assertReceiveActive(stopEpoch, managerEpoch)

    const ack = createAppCatalogAck(page, this.keyPair)
    this.lastPageDigest = page.pageDigest
    this.lastPage = page
    this.lastAck = ack
    this.sequence++
    this.cursor = page.nextCursor
    this.lastActivityAt = this.now()

    if (page.complete) {
      let committedCatalog
      try {
        this._assertReceiveActive(stopEpoch, managerEpoch)
        committedCatalog = await this.stage.commit(this.snapshot)
      } catch {
        if (!this._receiveActive(stopEpoch, managerEpoch)) this._throwStopped()
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog pointer transaction failed')
      }
      if (committedCatalog && typeof committedCatalog.release === 'function') {
        this.committedCatalog = committedCatalog
      }
      if (!this._receiveActive(stopEpoch, managerEpoch)) {
        await this._releaseCommittedCatalog()
        this._throwStopped()
      }
      if (!committedCatalog || typeof committedCatalog.readPage !== 'function') {
        return this._abortAndThrow('RESOURCE_LIMIT', 'catalog pointer transaction returned no bounded reader')
      }
      this.completed = true
      let actionError = null
      if (this._onComplete && this._receiveActive(stopEpoch, managerEpoch)) {
        try {
          await this._onComplete(Object.freeze({ snapshot: this.snapshot, catalog: committedCatalog }))
        } catch (err) {
          actionError = err
        }
      }
      const callbackActive = this._receiveActive(stopEpoch, managerEpoch)
      if (callbackActive && actionError !== null && this._onActionError) this._onActionError(actionError)
      let releaseError = null
      try {
        await this._releaseCommittedCatalog()
      } catch (err) {
        releaseError = err
      }
      this._assertReceiveActive(stopEpoch, managerEpoch)
      if (releaseError !== null) {
        if (this.committedCatalog !== null) throw releaseError
        if (this._onActionError) this._onActionError(releaseError)
      }
      this._close(false)
    }
    this._assertReceiveActive(stopEpoch, managerEpoch)
    return ack
  }

  async receiveAbort (input) {
    if (this.closed) return null
    const abort = verifyAppCatalogAbort(input, { localPubkey: this.localPubkey, remotePubkey: this.remotePubkey })
    if (this.snapshot !== null && abort.snapshotId !== this.snapshot.snapshotId) {
      return this._abortAndThrow('SNAPSHOT_MISMATCH', 'inbound ABORT snapshot mismatch')
    }
    this.abort = abort
    await this._terminate()
    return abort
  }

  async expire (now = this.now()) {
    if (this.closed) return false
    if ((now - this.lastActivityAt) < APP_CATALOG_LIMITS.inboundIdleTimeoutMs &&
        (now - this.startedAt) < APP_CATALOG_LIMITS.inboundHardTimeoutMs) return false
    this.abort = createAppCatalogAbort({
      receiverPubkey: this.remotePubkey,
      snapshotId: this.snapshot ? this.snapshot.snapshotId : '0'.repeat(64),
      code: 'RESOURCE_LIMIT'
    }, this.keyPair)
    await this._terminate()
    return true
  }

  stop () {
    return this._terminate()
  }

  _terminate () {
    if (this._stop !== null) return this._stop
    if (!this.stopped) {
      this.stopped = true
      this._stopEpoch++
    }
    const stop = this._stopAfterReceiveDrain()
    this._stop = stop
    stop.catch(() => {
      if (this._stop === stop) this._stop = null
    })
    return stop
  }

  async _stopAfterReceiveDrain () {
    await Promise.allSettled([...this._receiveFlights])
    if (!this.closed) {
      if (this.committedCatalog !== null) await this._releaseCommittedCatalog()
      if (this.completed) {
        this._close(false)
      } else {
        await this._discard()
        this._close(true)
      }
    }
  }

  async _abortAndThrow (code, message) {
    if (this.abort === null) {
      this.abort = createAppCatalogAbort({
        receiverPubkey: this.remotePubkey,
        snapshotId: this.snapshot ? this.snapshot.snapshotId : '0'.repeat(64),
        code
      }, this.keyPair)
    }
    const error = new AppCatalogProtocolError(code, message)
    error.abort = this.abort
    try {
      await this._discard()
    } catch (cleanupError) {
      if (!this.stopped) {
        this.stopped = true
        this._stopEpoch++
      }
      throw cleanupError
    }
    this._close(true)
    throw error
  }

  async _discard () {
    if (this.stage && typeof this.stage.discard === 'function') {
      await this.stage.discard()
    }
  }

  async _releaseCommittedCatalog () {
    const catalog = this.committedCatalog
    if (catalog === null) return false
    try {
      if (typeof catalog.release === 'function') await catalog.release()
      this.committedCatalog = null
      return true
    } catch (err) {
      // Disk handles mark themselves released only after lease ownership has
      // synchronously transferred to the factory's retained reclaim record.
      // A handle that did not make that handoff remains session-owned/retryable.
      if (catalog.released === true) this.committedCatalog = null
      throw err
    }
  }

  _close (discarded) {
    if (this.closed) return
    this.closed = true
    this.manager._releaseStagingBytes(this.stagedBytes)
    this.stagedBytes = 0
    this.manager._closeSession(this.remotePubkey, this)
    if (discarded) this.completed = false
  }

  _receiveActive (stopEpoch, managerEpoch) {
    return !this.stopped && !this.manager.stopped &&
      stopEpoch === this._stopEpoch && managerEpoch === this.manager._receiveEpoch
  }

  _assertReceiveActive (stopEpoch, managerEpoch) {
    if (!this._receiveActive(stopEpoch, managerEpoch)) this._throwStopped()
  }

  _throwStopped () {
    fail('RESOURCE_LIMIT', 'inbound catalog session is stopped')
  }
}

export class AppCatalogInboundManager {
  constructor (opts) {
    this.keyPair = validKeyPair(opts.keyPair)
    this.localPubkey = pubkeyHex(this.keyPair.publicKey, 'local public key')
    this.stageFactory = opts.stageFactory
    this.now = typeof opts.now === 'function' ? opts.now : Date.now
    this.maxPeers = boundedOption(opts.maxPeers, APP_CATALOG_LIMITS.maxInboundPeers, APP_CATALOG_LIMITS.maxInboundPeers, 'max inbound peers')
    this.maxStagingBytes = boundedOption(
      opts.maxStagingBytes,
      APP_CATALOG_LIMITS.maxInboundStagingBytes,
      APP_CATALOG_LIMITS.maxInboundStagingBytes,
      'max inbound staging bytes'
    )
    this.maxEntries = boundedOption(
      opts.maxEntries,
      APP_CATALOG_LIMITS.maxSnapshotEntries,
      APP_CATALOG_LIMITS.maxSnapshotEntries,
      'max inbound entries'
    )
    this.maxSessionBytes = boundedOption(
      opts.maxSessionBytes,
      APP_CATALOG_LIMITS.maxInboundSessionBytes,
      APP_CATALOG_LIMITS.maxInboundSessionBytes,
      'max inbound session bytes'
    )
    this.onComplete = opts.onComplete
    this.onActionError = opts.onActionError
    this.sessions = new Map()
    this.stagingBytes = 0
    this.stopped = false
    this._receiveEpoch = 0
    this._receiveFlights = new Set()
    this._stop = null
  }

  open (remotePubkey) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'inbound catalog manager is stopped')
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const existing = this.sessions.get(peer)
    if (existing) return existing
    if (this.sessions.size >= this.maxPeers) fail('RESOURCE_LIMIT', 'inbound catalog peer cap reached')
    const session = new AppCatalogInboundSession({
      manager: this,
      keyPair: this.keyPair,
      remotePubkey: peer,
      stageFactory: this.stageFactory,
      now: this.now,
      maxEntries: this.maxEntries,
      maxSessionBytes: this.maxSessionBytes,
      onComplete: this.onComplete,
      onActionError: this.onActionError
    })
    this.sessions.set(peer, session)
    return session
  }

  async receivePage (remotePubkey, page) {
    if (this.stopped) fail('RESOURCE_LIMIT', 'inbound catalog manager is stopped')
    const epoch = this._receiveEpoch
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const verifiedPage = verifyAppCatalogPage(page, { localPubkey: this.localPubkey, remotePubkey: peer })
    let session = this.sessions.get(peer)
    if (session && session.closed && session.completed && session.snapshot &&
        verifiedPage.snapshotId !== session.snapshot.snapshotId && verifiedPage.sequence === 0 && verifiedPage.cursor === null) {
      this.sessions.delete(peer)
      session = null
    }
    if (!session) session = this.open(peer)
    const flight = session.receivePage(verifiedPage, epoch)
    this._receiveFlights.add(flight)
    try {
      const ack = await flight
      if (this.stopped || epoch !== this._receiveEpoch || session.stopped) {
        fail('RESOURCE_LIMIT', 'inbound catalog manager is stopped')
      }
      return ack
    } finally {
      this._receiveFlights.delete(flight)
    }
  }

  async receiveAbort (remotePubkey, abort) {
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const session = this.sessions.get(peer)
    if (!session) return null
    return session.receiveAbort(abort)
  }

  async closePeer (remotePubkey) {
    const peer = pubkeyHex(remotePubkey, 'remote public key')
    const session = this.sessions.get(peer)
    if (!session) return false
    await session.stop()
    if (this.sessions.get(peer) === session) this.sessions.delete(peer)
    return true
  }

  async sweep (now = this.now()) {
    let expired = 0
    for (const session of [...this.sessions.values()]) {
      if (await session.expire(now)) expired++
    }
    return expired
  }

  stop () {
    if (this._stop !== null) return this._stop
    if (!this.stopped) {
      this.stopped = true
      this._receiveEpoch++
    }
    const sessions = [...this.sessions.values()]
    const stops = sessions.map(session => session.stop())
    const stop = this._stopAfterReceiveDrain(stops)
    this._stop = stop
    stop.catch(() => {
      if (this._stop === stop) this._stop = null
    })
    return stop
  }

  async _stopAfterReceiveDrain (stops) {
    const stopResults = await Promise.allSettled(stops)
    await Promise.allSettled([...this._receiveFlights])
    const failed = stopResults.find(result => result.status === 'rejected')
    if (failed) throw failed.reason
    this.sessions.clear()
    this.stagingBytes = 0
  }

  _reserveStagingBytes (bytes) {
    safeInteger(bytes, 'staging bytes')
    if (this.stopped) return false
    if (this.stagingBytes + bytes > this.maxStagingBytes) return false
    this.stagingBytes += bytes
    return true
  }

  _releaseStagingBytes (bytes) {
    this.stagingBytes = Math.max(0, this.stagingBytes - bytes)
  }

  _closeSession (peer, session) {
    if (this.sessions.get(peer) !== session) return
    if (!session.completed) this.sessions.delete(peer)
  }
}

export function guardAppCatalogMessageIds (channel, onProtocolError = null) {
  if (!channel || typeof channel._recv !== 'function' || typeof channel.close !== 'function') {
    fail('PROTOCOL_ERROR', 'catalog channel cannot enforce message ids')
  }
  const receive = channel._recv.bind(channel)
  channel._recv = function guardedCatalogReceive (type, state) {
    if (!Number.isSafeInteger(type) || type < 0 || type > APP_CATALOG_MESSAGE.ABORT) {
      if (state && Number.isSafeInteger(state.end)) state.start = state.end
      const error = new AppCatalogProtocolError('PROTOCOL_ERROR', 'unknown paged catalog message id')
      if (onProtocolError) {
        try { onProtocolError(error) } catch {}
      }
      channel.close()
      return null
    }
    return receive(type, state)
  }
  return channel
}

export function attachAppCatalogPagedChannel (connection, opts) {
  const keyPair = validKeyPair(opts.keyPair)
  const localPubkey = pubkeyHex(keyPair.publicKey, 'local public key')
  const remotePubkey = pubkeyHex(opts.remotePubkey, 'Noise-authenticated remote public key')
  const capability = new AppCatalogCapabilitySession({
    keyPair,
    remotePubkey,
    now: opts.now,
    randomBytes: opts.randomBytes
  })
  const mux = opts.mux || Protomux.from(connection)
  let closed = false
  let negotiationTimer = null
  let readyNotified = false
  let messageTail = Promise.resolve()
  let draining = false
  let pendingMessages = 0
  let pendingBytes = 0
  const pending = []
  let resolveClosed = null
  const closedPromise = new Promise(resolve => { resolveClosed = resolve })

  const releaseMessage = entry => {
    if (entry.released) return
    entry.released = true
    entry.input = null
    pendingMessages--
    pendingBytes -= CATALOG_RECEIVE_FRAME_BYTES
    catalogReceiveMessages--
    catalogReceiveBytes -= CATALOG_RECEIVE_FRAME_BYTES
    entry.resolve()
  }

  const discardPending = () => {
    for (const entry of pending) releaseMessage(entry)
    pending.length = 0
  }

  const protocolError = (error) => {
    if (closed) return closedPromise
    closed = true
    discardPending()
    if (typeof opts.onProtocolError === 'function') {
      try { opts.onProtocolError(error) } catch {}
    }
    capability.close()
    if (negotiationTimer !== null) clearTimeout(negotiationTimer)
    negotiationTimer = null
    if (channel && !channel.closed) channel.close()
    else resolveClosed()
    return closedPromise
  }

  const onMessage = async (id, input) => {
    if (closed) return
    try {
      if (input && input.catalogProtocolError) fail(input.code || 'PROTOCOL_ERROR', input.error || 'catalog decode failure')
      if (!input || input.type !== id) fail('PROTOCOL_ERROR', 'catalog inner type does not match its message id')
      if (id === APP_CATALOG_MESSAGE.CAPABILITY_CHALLENGE) {
        const proof = capability.createProof(input)
        messages[1].send(proof)
        capability.markProofSent(proof)
      } else if (id === APP_CATALOG_MESSAGE.CAPABILITY_PROOF) {
        capability.verifyPeerProof(input)
      } else {
        capability.assertReady()
        if (id === APP_CATALOG_MESSAGE.PAGE) {
          const page = verifyAppCatalogPage(input, { localPubkey, remotePubkey })
          if (typeof opts.onPage === 'function') await opts.onPage(page, api)
        } else if (id === APP_CATALOG_MESSAGE.ACK) {
          const ack = verifyAppCatalogAck(input, { localPubkey, remotePubkey })
          if (typeof opts.onAck === 'function') await opts.onAck(ack, api)
        } else {
          const abort = verifyAppCatalogAbort(input, { localPubkey, remotePubkey })
          if (typeof opts.onAbort === 'function') await opts.onAbort(abort, api)
        }
      }
      if (capability.ready && !readyNotified) {
        readyNotified = true
        if (negotiationTimer !== null) clearTimeout(negotiationTimer)
        negotiationTimer = null
        if (typeof opts.onReady === 'function') await opts.onReady(api)
      }
    } catch (err) {
      protocolError(err instanceof Error ? err : new AppCatalogProtocolError('PROTOCOL_ERROR'))
    }
  }

  const startDrain = () => {
    if (draining || closed || pending.length === 0) return
    draining = true
    // Publish the exact cleanup owner before invoking a callback, which may
    // synchronously close this channel itself.
    messageTail = Promise.resolve().then(async () => {
      try {
        while (pending.length) {
          if (closed) break
          const entry = pending.shift()
          try {
            await onMessage(entry.id, entry.input)
          } catch (err) {
            entry.reject(err)
          } finally {
            releaseMessage(entry)
          }
        }
      } finally {
        draining = false
        if (!closed && pending.length) startDrain()
      }
    }).catch(() => {})
  }

  const enqueueMessage = (id, input) => {
    // Do not return a shared pending close promise on rejection: Protomux
    // would retain a new reaction to it for every further received message.
    if (closed) return
    if (pendingMessages >= CATALOG_RECEIVE_PEER_MESSAGES ||
        pendingBytes + CATALOG_RECEIVE_FRAME_BYTES > CATALOG_RECEIVE_PEER_BYTES ||
        catalogReceiveMessages >= CATALOG_RECEIVE_RUNTIME_MESSAGES ||
        catalogReceiveBytes + CATALOG_RECEIVE_FRAME_BYTES > CATALOG_RECEIVE_RUNTIME_BYTES) {
      protocolError(new AppCatalogProtocolError('RESOURCE_LIMIT', 'catalog receive admission exhausted'))
      return
    }
    pendingMessages++
    pendingBytes += CATALOG_RECEIVE_FRAME_BYTES
    catalogReceiveMessages++
    catalogReceiveBytes += CATALOG_RECEIVE_FRAME_BYTES
    let resolveOperation
    let rejectOperation
    const operation = new Promise((resolve, reject) => {
      resolveOperation = resolve
      rejectOperation = reject
    })
    pending.push({ id, input, resolve: resolveOperation, reject: rejectOperation, released: false })
    startDrain()
    return operation
  }

  const channel = mux.createChannel({
    protocol: APP_CATALOG_PAGED_PROTOCOL,
    id: APP_CATALOG_PAGED_ID,
    onopen: () => {
      try {
        messages[0].send(capability.challenge())
        negotiationTimer = setTimeout(() => {
          if (!capability.ready) protocolError(new AppCatalogProtocolError('PROTOCOL_ERROR', 'catalog capability negotiation expired'))
        }, APP_CATALOG_LIMITS.negotiationTimeoutMs)
        if (negotiationTimer && typeof negotiationTimer.unref === 'function') negotiationTimer.unref()
      } catch (err) {
        protocolError(err)
      }
    },
    onclose: async () => {
      closed = true
      discardPending()
      capability.close()
      if (negotiationTimer !== null) clearTimeout(negotiationTimer)
      negotiationTimer = null
      try {
        await messageTail
        if (typeof opts.onClose === 'function') await opts.onClose(api)
      } finally {
        resolveClosed()
      }
    },
    ondrain: () => {
      if (typeof opts.onDrain === 'function') opts.onDrain(api)
    }
  })
  if (!channel) return null
  guardAppCatalogMessageIds(channel, protocolError)

  const messages = []
  for (let id = 0; id <= APP_CATALOG_MESSAGE.ABORT; id++) {
    messages.push(channel.addMessage({
      encoding: appCatalogPagedJsonEncoding,
      onmessage: message => enqueueMessage(id, message)
    }))
  }

  const send = (id, message) => {
    if (closed || !messages[id]) return false
    if (id > APP_CATALOG_MESSAGE.CAPABILITY_PROOF) capability.assertReady()
    return messages[id].send(message)
  }
  const api = Object.freeze({
    channel,
    capability,
    localPubkey,
    remotePubkey,
    get ready () { return capability.ready },
    get drained () { return channel.drained },
    closed: closedPromise,
    sendPage: page => send(APP_CATALOG_MESSAGE.PAGE, validateAppCatalogPage(page)),
    sendAck: ack => send(APP_CATALOG_MESSAGE.ACK, validateAppCatalogAck(ack)),
    sendAbort: abort => send(APP_CATALOG_MESSAGE.ABORT, validateAppCatalogAbort(abort)),
    close: () => protocolError(new AppCatalogProtocolError('PROTOCOL_ERROR', 'catalog channel closed locally'))
  })
  channel.open()
  return api
}

export function decodeCatalogCursorOr409 (cursor, signerPubkey) {
  try {
    return Object.freeze({ ok: true, cursor: verifyAppCatalogExternalCursor(cursor, signerPubkey) })
  } catch (err) {
    return Object.freeze({
      ok: false,
      statusCode: 409,
      code: 'CURSOR_EXPIRED',
      error: err instanceof Error ? err.message : 'catalog cursor expired'
    })
  }
}

export function cloneCatalogSnapshotForStage (snapshot) {
  return Object.freeze(cloneJson(snapshot))
}
