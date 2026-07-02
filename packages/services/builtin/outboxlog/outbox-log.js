/**
 * OutboxLog — single-writer-per-pubkey append log for app availability.
 *
 * This is the additive HiveRelay port of Peerit's relay `core-memory` sync
 * surface. It preserves the browser-facing sync contract while adding the
 * server-side check the relay core intentionally lacked: records must be signed
 * by the outbox writer key (`appId`). The record body remains opaque to the
 * relay; only the generic signed envelope is verified.
 */

import { randomBytes } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { createOutboxSwarmHub } from './swarm-hub.js'

export const DEFAULT_MAX_GROUPS = 20000
export const DEFAULT_MAX_ROWS_PER_GROUP = 50000
export const DEFAULT_MAX_ID_LENGTH = 256
export const DEFAULT_MAX_APP_ID_LENGTH = 128
export const DEFAULT_MAX_VALUE_BYTES = 64 * 1024
export const DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
export const DEFAULT_DIRECTORY_LIMIT = 5000
export const DEFAULT_MAX_DIRECTORY_LIMIT = 5000
export const DEFAULT_MAX_APPEND_EVENTS_PER_OUTBOX = 1000
export const DEFAULT_MAX_APPEND_EVENT_LIMIT = 1000
export const DEFAULT_OUTBOXLOG_NAMESPACE = 'peerit'
export const OUTBOXLOG_BLIND_SEAL_VERSION = 1
export const OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG = 'xchacha20poly1305'
export const OUTBOXLOG_STATE_VERSION = 1
export const OUTBOXLOG_JOURNAL_VERSION = 1

const SIG_BYTES = 64
const PUBKEY_BYTES = 32
const SIG_FIELDS = new Set(['_sig', '_k', '_dk', '_ns', '_alg'])
const OUTBOXLOG_NAMESPACE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/
const BLIND_FORBIDDEN_FIELDS = new Set(['plaintext', 'plainText', 'cleartext', 'clearText', 'dataKey'])
const BLIND_BODY_FIELDS = new Set(['sealed'])
const BLIND_SEAL_FIELDS = new Set(['version', 'alg', 'nonce', 'ciphertext', 'keyId'])
const BLIND_SEAL_ALG = /^[a-z0-9][a-z0-9._+-]{0,63}$/

const hex = (n) => randomBytes(n).toString('hex')

export function createOutboxLog ({
  maxGroups = DEFAULT_MAX_GROUPS,
  maxRowsPerGroup = DEFAULT_MAX_ROWS_PER_GROUP,
  maxIdLength = DEFAULT_MAX_ID_LENGTH,
  maxAppIdLength = DEFAULT_MAX_APP_ID_LENGTH,
  maxValueBytes = DEFAULT_MAX_VALUE_BYTES,
  maxTotalBytes = DEFAULT_MAX_TOTAL_BYTES,
  directoryLimit = DEFAULT_DIRECTORY_LIMIT,
  maxDirectoryLimit = DEFAULT_MAX_DIRECTORY_LIMIT,
  maxAppendEventsPerOutbox = DEFAULT_MAX_APPEND_EVENTS_PER_OUTBOX,
  maxAppendEventLimit = DEFAULT_MAX_APPEND_EVENT_LIMIT,
  namespace = DEFAULT_OUTBOXLOG_NAMESPACE,
  namespaces = null,
  verifyAppend = null,
  swarm = createOutboxSwarmHub(),
  persistence = null,
  persistencePath = null,
  journal = null,
  journalPath = null,
  storagePath = null,
  onAppend = null,
  log = () => {}
} = {}) {
  const groups = new Map()
  const subscribers = new Map()
  const appendEventsByApp = new Map()
  let namespaceRegistry = createOutboxNamespaceRegistry({ namespace, namespaces })
  const customVerifyAppend = typeof verifyAppend === 'function' ? verifyAppend : null
  const shouldVerifyAppend = verifyAppend !== false
  let statePersistence = normalizePersistence(persistence)
  if (!statePersistence && persistencePath) statePersistence = createJsonFileOutboxPersistence(persistencePath)
  if (!statePersistence && storagePath) statePersistence = createJsonFileOutboxPersistence(join(storagePath, 'outboxlog-state.json'))
  let operationJournal = normalizeJournal(journal)
  if (!operationJournal && journalPath) operationJournal = createJsonlOutboxJournal(journalPath)
  let totalBytes = 0
  let directorySeq = 0
  let appendSeq = 0
  let journalSeq = 0

  loadState()

  const getGroup = (appId) => groups.get(appId) || null
  const ensureGroup = (appId, namespaceInfo = null) => {
    if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength) throw fail('bad appId', 400)
    let group = groups.get(appId)
    if (!group) {
      if (groups.size >= maxGroups) throw fail('relay at group capacity', 503)
      assertNamespaceOutboxCapacity(namespaceInfo)
      group = { inviteKey: hex(32), rows: new Map(), version: 0, directorySeq: 0, namespace: namespaceInfo ? namespaceInfo.name : null }
      groups.set(appId, group)
    } else {
      bindGroupNamespace(group, namespaceInfo)
    }
    return group
  }

  const EMPTY = { inviteKey: null, rows: new Map(), version: 0 }

  const sync = {
    create (appId, opts = {}) {
      const namespaceInfo = namespaceInfoForCreate(opts)
      const existed = groups.has(appId)
      const previousGroup = groups.get(appId)
      const previousGroupNamespace = previousGroup ? previousGroup.namespace || null : null
      const group = ensureGroup(appId, namespaceInfo)
      try {
        saveState(existed ? null : journalCreateEntry(appId, group))
      } catch (err) {
        if (!existed) groups.delete(appId)
        else group.namespace = previousGroupNamespace
        throw fail('persistence failed', 500, err)
      }
      return { appId, inviteKey: group.inviteKey, writerPublicKey: appId }
    },

    join (appId, inviteKey) {
      const group = getGroup(appId)
      if (!group) throw fail('no such outbox', 404)
      if (inviteKey && inviteKey !== group.inviteKey) throw fail('bad invite', 400)
      return { appId, inviteKey: group.inviteKey, writerPublicKey: appId }
    },

    append (appId, op) {
      if (!op || typeof op.type !== 'string' || op.type.length > 64 || !op.data || op.data.id == null) throw fail('bad op', 400)
      const namespaceInfo = namespaceInfoForAppend(op.data)
      const id = String(op.data.id)
      if (id.length > maxIdLength) throw fail('id too long', 400)

      let size
      try {
        size = Buffer.byteLength(JSON.stringify(op.data))
      } catch {
        throw fail('unserializable record', 400)
      }
      if (size > namespaceCap(namespaceInfo, 'maxValueBytes', maxValueBytes)) throw fail('record too large', 413)

      if (shouldVerifyAppend) {
        let verified = false
        try {
          verified = customVerifyAppend
            ? customVerifyAppend({ appId, type: op.type, data: op.data, namespace: namespaceInfo ? namespaceInfo.name : null, namespaceConfig: namespaceInfo })
            : verifyOutboxRecordSignature({ appId, type: op.type, data: op.data }, { registry: namespaceRegistry })
        } catch (err) {
          throw fail('bad signature', 400, err)
        }
        if (verified && typeof verified.then === 'function') throw fail('async verifier unsupported', 500)
        if (!isVerified(verified)) throw fail('bad signature', 400)
      }

      const createdGroup = !groups.has(appId)
      const previousGroup = groups.get(appId)
      const previousGroupNamespace = previousGroup ? previousGroup.namespace || null : null
      const group = ensureGroup(appId, namespaceInfo)
      const key = op.type.replace(':', '!') + '!' + id
      const old = group.rows.get(key)
      const oldSize = old === undefined ? 0 : Buffer.byteLength(JSON.stringify(old))
      const updatesDirectory = key === 'head!' + appId
      const previousDirectorySeq = directorySeq
      const previousGroupDirectorySeq = group.directorySeq
      const previousAppendSeq = appendSeq
      const previousAppEvents = appendEventsByApp.has(appId) ? appendEventsByApp.get(appId).slice() : null
      if (old === undefined && group.rows.size >= namespaceCap(namespaceInfo, 'maxEntriesPerOutbox', maxRowsPerGroup)) throw fail('outbox at row capacity', 503)
      if (size > oldSize && totalBytes - oldSize + size > maxTotalBytes) throw fail('relay at storage capacity', 503)

      group.rows.set(key, op.data)
      totalBytes += size - oldSize
      group.version++
      if (updatesDirectory) group.directorySeq = ++directorySeq
      const event = rememberAppendEvent({
        seq: ++appendSeq,
        topic: 'outbox/' + appId,
        appId,
        key,
        type: op.type,
        version: group.version
      })

      try {
        saveState(journalAppendEntry(appId, group, op))
      } catch (err) {
        if (old === undefined) group.rows.delete(key)
        else group.rows.set(key, old)
        totalBytes += oldSize - size
        group.version--
        directorySeq = previousDirectorySeq
        group.directorySeq = previousGroupDirectorySeq
        appendSeq = previousAppendSeq
        if (previousAppEvents) appendEventsByApp.set(appId, previousAppEvents)
        else appendEventsByApp.delete(appId)
        if (createdGroup) groups.delete(appId)
        else group.namespace = previousGroupNamespace
        throw fail('persistence failed', 500, err)
      }

      emitAppend({ ...event, value: op.data })
      return { ok: true, key }
    },

    get (appId, key) {
      const group = getGroup(appId)
      return group ? (group.rows.get(key) ?? null) : null
    },

    list (appId, prefix, opts = {}) {
      return rangeRows(getGroup(appId) || EMPTY, { prefix, limit: opts.limit })
    },

    range (appId, opts = {}) {
      return rangeRows(getGroup(appId) || EMPTY, opts)
    },

    count (appId, prefix) {
      const group = getGroup(appId)
      if (!group) return { count: 0 }
      if (!prefix) return { count: group.rows.size }
      let count = 0
      for (const key of group.rows.keys()) {
        if (key >= prefix && key < prefix + '\xff') count++
      }
      return { count }
    },

    status (appId) {
      const group = getGroup(appId)
      if (!group) return { appId, inviteKey: null, writerCount: 0, viewLength: 0 }
      return { appId, inviteKey: group.inviteKey, writerCount: 1, viewLength: group.rows.size }
    },

    heads (appIds) {
      const heads = {}
      if (Array.isArray(appIds)) {
        for (const appId of appIds) {
          if (typeof appId !== 'string' || appId.length > maxAppIdLength) continue
          const group = getGroup(appId)
          heads[appId] = group ? group.version : 0
        }
      }
      return { heads }
    },

    directory (opts = {}) {
      return directoryPage(opts)
    },

    events (appId, opts = {}) {
      return appendEventsPage(appId, opts)
    }
  }

  return {
    sync,
    swarm,
    subscribe,
    flush,
    configurePersistence,
    configureNamespaces,
    namespaces: () => namespaceRegistry.snapshot(),
    snapshot,
    _stats () {
      return { groups: groups.size, totalBytes, directorySeq, appendSeq }
    }
  }

  function namespaceInfoForCreate (opts = {}) {
    if (!opts || typeof opts !== 'object' || opts.namespace == null) return null
    const info = namespaceRegistry.get(opts.namespace)
    if (!info) throw fail('unknown namespace', 400)
    return info
  }

  function namespaceInfoForAppend (data) {
    const ns = recordNamespace(data)
    if (!ns && customVerifyAppend && !namespaceRegistry.configured) return null
    if (!ns) throw fail('missing namespace', 400)
    const info = namespaceRegistry.get(ns)
    if (!info) throw fail('unknown namespace', 400)
    if (!namespaceRecordAllowed(info, data)) throw fail('namespace policy rejected record', 400)
    return info
  }

  function bindGroupNamespace (group, namespaceInfo) {
    if (!namespaceInfo) return
    if (group.namespace && group.namespace !== namespaceInfo.name) throw fail('namespace mismatch', 400)
    if (!group.namespace) {
      assertNamespaceOutboxCapacity(namespaceInfo)
      group.namespace = namespaceInfo.name
    }
  }

  function assertNamespaceOutboxCapacity (namespaceInfo) {
    if (!namespaceInfo) return
    const maxOutboxes = namespaceInfo.caps.maxOutboxes
    if (maxOutboxes != null && namespaceOutboxCount(namespaceInfo.name) >= maxOutboxes) {
      throw fail('namespace at outbox capacity', 503)
    }
  }

  function namespaceOutboxCount (name) {
    let count = 0
    for (const group of groups.values()) {
      if (group.namespace === name) count++
    }
    return count
  }

  function subscribe (appId, opts, fn) {
    if (typeof appId === 'function') {
      fn = appId
      appId = '*'
      opts = {}
    } else if (typeof opts === 'function') {
      fn = opts
      opts = {}
    }
    if (typeof fn !== 'function') throw new Error('OutboxLog.subscribe: not a function')
    const key = appId || '*'
    let set = subscribers.get(key)
    if (!set) {
      set = new Set()
      subscribers.set(key, set)
    }
    set.add(fn)
    if (key !== '*' && shouldReplayAppendEvents(opts)) {
      const replay = appendEventsPage(key, opts)
      for (const event of replay.events) safeCall(fn, { ...event, replay: true })
    }
    return () => {
      set.delete(fn)
      if (set.size === 0) subscribers.delete(key)
    }
  }

  function shouldReplayAppendEvents (opts) {
    return !!(opts && (opts.replay === true || opts.since != null))
  }

  function emitAppend (event) {
    if (onAppend) safeCall(onAppend, event)
    const globalSubscribers = subscribers.get('*')
    const appSubscribers = subscribers.get(event.appId)
    if (globalSubscribers) {
      for (const fn of globalSubscribers) safeCall(fn, event)
    }
    if (appSubscribers) {
      for (const fn of appSubscribers) safeCall(fn, event)
    }
  }

  function safeCall (fn, event) {
    try {
      fn(event)
    } catch (err) {
      log('outboxlog-subscribe-error', { error: err })
    }
  }

  function rangeRows (group, opts = {}) {
    let rows = sortedRows(group)
    if (opts.prefix) rows = rows.filter((row) => row.key >= opts.prefix && row.key < opts.prefix + '\xff')
    if (opts.gte != null && opts.gte !== '') rows = rows.filter((row) => row.key >= opts.gte)
    if (opts.gt != null && opts.gt !== '') rows = rows.filter((row) => row.key > opts.gt)
    if (opts.lte != null && opts.lte !== '') rows = rows.filter((row) => row.key <= opts.lte)
    if (opts.lt != null && opts.lt !== '') rows = rows.filter((row) => row.key < opts.lt)
    if (opts.reverse) rows.reverse()
    let limit = Number(opts.limit) || 100
    if (limit < 1) limit = 100
    if (limit > 1000) limit = 1000
    return rows.slice(0, limit)
  }

  function directoryPage ({ limit = directoryLimit, cursor = null, since = null } = {}) {
    const pageLimit = clampDirectoryLimit(limit, directoryLimit, maxDirectoryLimit)
    const after = normalizeDirectoryCursor(cursor, maxAppIdLength)
    const minSeq = normalizeDirectorySince(since)
    const rows = []

    for (const [appId, group] of groups) {
      const head = group.rows.get('head!' + appId)
      if (!head) continue
      const seq = Number.isSafeInteger(group.directorySeq) ? group.directorySeq : 0
      if (minSeq > 0 && seq <= minSeq) continue
      if (after && appId <= after) continue
      rows.push({ appId, head, seq })
    }

    rows.sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0))
    const page = rows.slice(0, pageLimit)
    const heads = {}
    for (const row of page) heads[row.appId] = row.head

    return {
      heads,
      count: page.length,
      total: rows.length,
      cursor: after,
      nextCursor: rows.length > page.length && page.length > 0 ? page[page.length - 1].appId : null,
      hasMore: rows.length > page.length,
      watermark: directorySeq
    }
  }

  function appendEventsPage (appId, { since = null, limit = maxAppendEventLimit } = {}) {
    if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength) {
      return emptyAppendEventsPage(since)
    }
    const minSeq = normalizeAppendSince(since)
    const pageLimit = clampAppendEventLimit(limit, maxAppendEventLimit)
    const events = appendEventsByApp.get(appId) || []
    const changed = events.filter(event => event.seq > minSeq)
    const page = changed.slice(0, pageLimit).map(clone)
    return {
      events: page,
      count: page.length,
      watermark: appendSeq,
      nextSince: page.length ? page[page.length - 1].seq : minSeq,
      hasMore: changed.length > page.length
    }
  }

  function emptyAppendEventsPage (since) {
    const minSeq = normalizeAppendSince(since)
    return {
      events: [],
      count: 0,
      watermark: appendSeq,
      nextSince: minSeq,
      hasMore: false
    }
  }

  function rememberAppendEvent (event) {
    const saved = {
      seq: event.seq,
      topic: event.topic,
      appId: event.appId,
      key: event.key,
      type: event.type,
      version: event.version
    }
    let events = appendEventsByApp.get(event.appId)
    if (!events) {
      events = []
      appendEventsByApp.set(event.appId, events)
    }
    events.push(saved)
    const cap = positiveInteger(maxAppendEventsPerOutbox, DEFAULT_MAX_APPEND_EVENTS_PER_OUTBOX)
    while (events.length > cap) events.shift()
    return saved
  }

  function configurePersistence ({ persistence = null, persistencePath = null, journal = null, journalPath = null, storagePath = null } = {}) {
    if (statePersistence || operationJournal) return false
    statePersistence = normalizePersistence(persistence) ||
      (persistencePath ? createJsonFileOutboxPersistence(persistencePath) : null) ||
      (storagePath ? createJsonFileOutboxPersistence(join(storagePath, 'outboxlog-state.json')) : null)
    operationJournal = normalizeJournal(journal) ||
      (journalPath ? createJsonlOutboxJournal(journalPath) : null)
    if (!statePersistence && !operationJournal) return false
    loadState()
    return true
  }

  function configureNamespaces (opts = {}) {
    const next = createOutboxNamespaceRegistry(opts)
    for (const group of groups.values()) {
      if (group.namespace && !next.get(group.namespace)) throw fail('configured namespaces do not include persisted outbox namespace', 400)
    }
    namespaceRegistry = next
    return namespaceRegistry.snapshot()
  }

  function loadState () {
    let loaded = false
    if (statePersistence) {
      const state = statePersistence.loadSync()
      if (state) {
        applyState(state)
        loaded = true
      }
    }
    if (!loaded && operationJournal) loadJournal()
  }

  function saveState (journalEntry = null) {
    // Journal-first layering: the append-log is the durable fast path, so land
    // the entry whenever a journal is configured — even alongside snapshot
    // persistence, which is a periodic checkpoint, not a replacement. The old
    // `!statePersistence` guard left the journal silently empty when start()
    // wired both journalPath + storagePath. (#146)
    if (operationJournal && journalEntry) appendJournalEntry(journalEntry)
    if (!statePersistence) return
    statePersistence.saveSync(snapshot())
  }

  function flush () {
    saveState()
    if (operationJournal && typeof operationJournal.flush === 'function') {
      return operationJournal.flush()
    }
  }

  function snapshot () {
    return {
      version: OUTBOXLOG_STATE_VERSION,
      directorySeq,
      appendSeq,
      journalSeq,
      appendEvents: [...appendEventsByApp.entries()].map(([appId, events]) => [
        appId,
        events.map(event => clone(event))
      ]),
      groups: [...groups.entries()].map(([appId, group]) => [
        appId,
        {
          inviteKey: group.inviteKey,
          version: group.version,
          directorySeq: group.directorySeq || 0,
          namespace: group.namespace || null,
          rows: [...group.rows.entries()].map(([key, value]) => [key, clone(value)])
        }
      ])
    }
  }

  // Re-run the same verification the live append path applies (:141-152), but
  // return a boolean instead of throwing so callers can DROP an unverifiable
  // row rather than aborting the whole load. The persisted state file / journal
  // is not a trust root — anyone who can write it must not be able to inject
  // rows attributed to another writer key. (#146)
  function restoreVerifies (appId, type, data, namespaceInfo) {
    if (!shouldVerifyAppend) return true
    if (typeof type !== 'string' || !type) return false
    let verified = false
    try {
      verified = customVerifyAppend
        ? customVerifyAppend({ appId, type, data, namespace: namespaceInfo ? namespaceInfo.name : null, namespaceConfig: namespaceInfo })
        : verifyOutboxRecordSignature({ appId, type, data }, { registry: namespaceRegistry })
    } catch {
      return false
    }
    if (verified && typeof verified.then === 'function') return false
    return isVerified(verified)
  }

  function applyState (state) {
    if (!state || typeof state !== 'object') return
    if (state.version !== OUTBOXLOG_STATE_VERSION) throw fail('unsupported outboxlog state version', 500)
    const nextGroups = new Map()
    const nextAppendEvents = new Map()
    let nextTotalBytes = 0
    let nextDirectorySeq = 0
    let nextAppendSeq = 0
    for (const entry of Array.isArray(state.groups) ? state.groups : []) {
      if (!Array.isArray(entry) || entry.length !== 2) continue
      const appId = entry[0]
      const groupState = entry[1]
      if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength) continue
      if (!groupState || typeof groupState !== 'object' || Array.isArray(groupState)) continue
      if (nextGroups.size >= maxGroups) throw fail('persisted outbox group capacity exceeded', 503)
      const namespaceName = normalizePersistedNamespace(groupState.namespace)
      const namespaceInfo = namespaceName ? namespaceRegistry.get(namespaceName) : null
      if (namespaceName && !namespaceInfo) throw fail('persisted outbox namespace is not registered', 400)
      if (namespaceInfo && namespaceInfo.caps.maxOutboxes != null && namespaceOutboxCountIn(nextGroups, namespaceName) >= namespaceInfo.caps.maxOutboxes) {
        throw fail('persisted namespace outbox capacity exceeded', 503)
      }
      const rowLimit = namespaceCap(namespaceInfo, 'maxEntriesPerOutbox', maxRowsPerGroup)
      const rowMaxBytes = namespaceCap(namespaceInfo, 'maxValueBytes', maxValueBytes)
      const rows = new Map()
      for (const row of Array.isArray(groupState.rows) ? groupState.rows : []) {
        if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string') continue
        if (row[0].length > maxIdLength + 65) continue
        const value = clone(row[1])
        // Reconstruct the record type from the row key (`type!id`, first ':'
        // mangled to '!') so the signature can be re-verified; drop any row that
        // fails — before it consumes capacity budget. (#146)
        const rowId = value && value.id != null ? String(value.id) : null
        const rowType = rowId != null && row[0].endsWith('!' + rowId)
          ? row[0].slice(0, row[0].length - rowId.length - 1)
          : null
        if (!restoreVerifies(appId, rowType, value, namespaceInfo)) continue
        const size = Buffer.byteLength(JSON.stringify(value))
        if (size > rowMaxBytes) throw fail('persisted outbox row too large', 413)
        if (rows.size >= rowLimit) throw fail('persisted outbox row capacity exceeded', 503)
        if (nextTotalBytes + size > maxTotalBytes) throw fail('persisted outbox storage capacity exceeded', 503)
        rows.set(row[0], value)
        nextTotalBytes += size
      }
      let restoredDirectorySeq = Number.isSafeInteger(groupState.directorySeq) && groupState.directorySeq >= 0 ? groupState.directorySeq : 0
      if (restoredDirectorySeq > nextDirectorySeq) nextDirectorySeq = restoredDirectorySeq
      if (restoredDirectorySeq === 0 && rows.has('head!' + appId)) restoredDirectorySeq = ++nextDirectorySeq
      nextGroups.set(appId, {
        inviteKey: typeof groupState.inviteKey === 'string' ? groupState.inviteKey : hex(32),
        rows,
        directorySeq: restoredDirectorySeq,
        namespace: namespaceName,
        version: Number.isSafeInteger(groupState.version) && groupState.version >= rows.size ? groupState.version : rows.size
      })
    }
    for (const entry of Array.isArray(state.appendEvents) ? state.appendEvents : []) {
      if (!Array.isArray(entry) || entry.length !== 2) continue
      const appId = entry[0]
      const events = entry[1]
      if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength || !Array.isArray(events)) continue
      if (!nextGroups.has(appId)) continue
      const restored = []
      for (const event of events) {
        const normalized = normalizeAppendEvent(appId, event)
        if (!normalized) continue
        restored.push(normalized)
        if (normalized.seq > nextAppendSeq) nextAppendSeq = normalized.seq
      }
      if (restored.length > 0) {
        nextAppendEvents.set(appId, restored.slice(-positiveInteger(maxAppendEventsPerOutbox, DEFAULT_MAX_APPEND_EVENTS_PER_OUTBOX)))
      }
    }
    groups.clear()
    for (const [appId, group] of nextGroups) groups.set(appId, group)
    appendEventsByApp.clear()
    for (const [appId, events] of nextAppendEvents) appendEventsByApp.set(appId, events)
    totalBytes = nextTotalBytes
    directorySeq = Math.max(
      Number.isSafeInteger(state.directorySeq) && state.directorySeq >= 0 ? state.directorySeq : 0,
      nextDirectorySeq
    )
    appendSeq = Math.max(
      Number.isSafeInteger(state.appendSeq) && state.appendSeq >= 0 ? state.appendSeq : 0,
      nextAppendSeq
    )
    journalSeq = Number.isSafeInteger(state.journalSeq) && state.journalSeq >= 0 ? state.journalSeq : journalSeq
  }

  function journalCreateEntry (appId, group) {
    return {
      kind: 'create',
      appId,
      inviteKey: group.inviteKey,
      namespace: group.namespace || null
    }
  }

  function journalAppendEntry (appId, group, op) {
    return {
      kind: 'append',
      appId,
      inviteKey: group.inviteKey,
      namespace: group.namespace || recordNamespace(op.data),
      op: {
        type: op.type,
        data: clone(op.data)
      }
    }
  }

  function appendJournalEntry (entry) {
    const record = {
      version: OUTBOXLOG_JOURNAL_VERSION,
      seq: journalSeq + 1,
      ...entry
    }
    operationJournal.appendSync(record)
    journalSeq = record.seq
  }

  function loadJournal () {
    const entries = operationJournal.loadSync()
    if (!entries) return
    if (!Array.isArray(entries)) throw fail('outboxlog journal must be an array', 500)
    let expected = 1
    for (const entry of entries) {
      const normalized = normalizeJournalEntry(entry, expected)
      if (!normalized) throw fail('corrupt outboxlog journal entry ' + expected, 500)
      applyJournalEntry(normalized)
      journalSeq = normalized.seq
      expected++
    }
  }

  function applyJournalEntry (entry) {
    if (entry.appId.length > maxAppIdLength) throw fail('persisted outbox appId too long', 400)
    const entryNamespace = normalizePersistedNamespace(entry.namespace)
    const entryNamespaceInfo = entryNamespace ? namespaceRegistry.get(entryNamespace) : null
    if (entryNamespace && !entryNamespaceInfo) throw fail('persisted outbox namespace is not registered', 400)
    if (entry.kind === 'create') {
      if (!groups.has(entry.appId)) {
        if (groups.size >= maxGroups) throw fail('persisted outbox group capacity exceeded', 503)
        assertNamespaceOutboxCapacity(entryNamespaceInfo)
        groups.set(entry.appId, {
          inviteKey: entry.inviteKey,
          rows: new Map(),
          version: 0,
          directorySeq: 0,
          namespace: entryNamespace
        })
      }
      return
    }

    const op = entry.op
    const opNamespace = entryNamespace || recordNamespace(op.data)
    const opNamespaceInfo = opNamespace ? namespaceRegistry.get(opNamespace) : null
    if (opNamespace && !opNamespaceInfo) throw fail('persisted outbox namespace is not registered', 400)
    // Drop a journal op whose signature does not re-verify: the journal is a
    // trust root only if every replayed row is re-checked on load. (#146)
    if (!restoreVerifies(entry.appId, op.type, op.data, opNamespaceInfo)) return
    const id = String(op.data.id)
    if (id.length > maxIdLength) throw fail('persisted outbox id too long', 400)
    const key = op.type.replace(':', '!') + '!' + id
    const size = Buffer.byteLength(JSON.stringify(op.data))
    if (size > namespaceCap(opNamespaceInfo, 'maxValueBytes', maxValueBytes)) throw fail('persisted outbox row too large', 413)
    let group = groups.get(entry.appId)
    if (!group) {
      if (groups.size >= maxGroups) throw fail('persisted outbox group capacity exceeded', 503)
      assertNamespaceOutboxCapacity(opNamespaceInfo)
      group = {
        inviteKey: entry.inviteKey,
        rows: new Map(),
        version: 0,
        directorySeq: 0,
        namespace: opNamespace
      }
      groups.set(entry.appId, group)
    } else if (!group.namespace) {
      if (opNamespaceInfo) assertNamespaceOutboxCapacity(opNamespaceInfo)
      group.namespace = opNamespace
    } else if (opNamespace && group.namespace !== opNamespace) {
      throw fail('persisted outbox namespace mismatch', 400)
    }
    const old = group.rows.get(key)
    const oldSize = old === undefined ? 0 : Buffer.byteLength(JSON.stringify(old))
    if (old === undefined && group.rows.size >= namespaceCap(opNamespaceInfo, 'maxEntriesPerOutbox', maxRowsPerGroup)) throw fail('persisted outbox row capacity exceeded', 503)
    if (size > oldSize && totalBytes - oldSize + size > maxTotalBytes) throw fail('persisted outbox storage capacity exceeded', 503)

    group.rows.set(key, clone(op.data))
    totalBytes += size - oldSize
    group.version++
    if (key === 'head!' + entry.appId) group.directorySeq = ++directorySeq
    rememberAppendEvent({
      seq: ++appendSeq,
      topic: 'outbox/' + entry.appId,
      appId: entry.appId,
      key,
      type: op.type,
      version: group.version
    })
  }
}

export function createOutboxSignatureVerifier (opts = {}) {
  const registry = opts.registry || createOutboxNamespaceRegistry(opts)
  return (input) => verifyOutboxRecordSignature(input, { ...opts, registry })
}

export function createMemoryOutboxPersistence (initialState = null) {
  let state = initialState ? clone(initialState) : null
  return {
    loadSync () {
      return state ? clone(state) : null
    },
    saveSync (snapshot) {
      state = snapshot ? clone(snapshot) : null
    },
    snapshot () {
      return state ? clone(state) : null
    }
  }
}

export function createMemoryOutboxJournal (initialEntries = []) {
  const entries = Array.isArray(initialEntries) ? clone(initialEntries) : []
  return {
    loadSync () {
      return clone(entries)
    },
    appendSync (entry) {
      entries.push(clone(entry))
    },
    entries () {
      return clone(entries)
    }
  }
}

export function createJsonFileOutboxPersistence (path) {
  if (typeof path !== 'string' || !path) throw new Error('OutboxLog: persistence path required')
  return {
    loadSync () {
      try {
        return JSON.parse(readFileSync(path, 'utf8'))
      } catch (err) {
        if (err && err.code === 'ENOENT') return null
        throw err
      }
    },
    saveSync (snapshot) {
      const tmp = path + '.tmp-' + process.pid + '-' + Date.now()
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(tmp, JSON.stringify(snapshot), 'utf8')
      renameSync(tmp, path)
    }
  }
}

export function createJsonlOutboxJournal (path) {
  if (typeof path !== 'string' || !path) throw new Error('OutboxLog: journal path required')
  return {
    loadSync () {
      try {
        const text = readFileSync(path, 'utf8')
        return text
          .split('\n')
          .filter(line => line.trim() !== '')
          .map(line => JSON.parse(line))
      } catch (err) {
        if (err && err.code === 'ENOENT') return []
        throw err
      }
    },
    appendSync (entry) {
      mkdirSync(dirname(path), { recursive: true })
      appendFileSync(path, JSON.stringify(entry) + '\n', 'utf8')
    }
  }
}

export function createOutboxNamespaceRegistry ({ namespace = DEFAULT_OUTBOXLOG_NAMESPACE, namespaces = null } = {}) {
  const entries = new Map()
  const configured = namespaces != null || namespace !== DEFAULT_OUTBOXLOG_NAMESPACE
  const source = namespaces && typeof namespaces === 'object' && !Array.isArray(namespaces)
    ? namespaces
    : { [namespace || DEFAULT_OUTBOXLOG_NAMESPACE]: { blind: false } }

  for (const [name, config] of Object.entries(source)) {
    const normalized = normalizeNamespaceEntry(name, config)
    entries.set(normalized.name, normalized)
  }

  const defaultName = normalizeNamespaceName(namespace || DEFAULT_OUTBOXLOG_NAMESPACE)
  if (!entries.has(defaultName)) entries.set(defaultName, normalizeNamespaceEntry(defaultName, { blind: false }))

  return {
    configured,
    get (name) {
      const normalized = normalizeNamespaceName(name)
      return normalized ? entries.get(normalized) || null : null
    },
    snapshot () {
      return [...entries.values()]
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
        .map(entry => ({
          name: entry.name,
          blind: entry.blind,
          caps: { ...entry.caps }
        }))
    }
  }
}

export function verifyOutboxRecordSignature ({ appId, type, data }, { namespace = DEFAULT_OUTBOXLOG_NAMESPACE, namespaces = null, registry = null } = {}) {
  if (typeof type !== 'string' || !type) return false
  if (!data || typeof data !== 'object') return false

  const writer = typeof data._k === 'string' ? data._k.toLowerCase() : ''
  const outboxWriter = typeof appId === 'string' ? appId.toLowerCase() : ''
  const driveKey = typeof data._dk === 'string' ? data._dk.toLowerCase() : ''
  const ns = typeof data._ns === 'string' ? data._ns : ''
  const sigHex = typeof data._sig === 'string' ? data._sig : ''
  const namespaceRegistry = registry || createOutboxNamespaceRegistry({ namespace, namespaces })
  const namespaceInfo = namespaceRegistry.get(ns)

  if (!isHex(writer, 64) || !isHex(outboxWriter, 64) || writer !== outboxWriter) return false
  if (!isHex(driveKey, 64) || !isHex(sigHex, 128)) return false
  if (!namespaceInfo) return false
  if (!namespaceRecordAllowed(namespaceInfo, data)) return false

  const signed = `pear.app.${driveKey}:${ns}:${canonicalOutboxRecord(type, data)}`
  const signature = b4a.from(sigHex, 'hex')
  const publicKey = b4a.from(writer, 'hex')
  if (signature.byteLength !== SIG_BYTES || publicKey.byteLength !== PUBKEY_BYTES) return false
  return sodium.crypto_sign_verify_detached(signature, b4a.from(signed, 'utf8'), publicKey)
}

export function canonicalOutboxRecord (type, data) {
  return type + '|' + stable(data)
}

function normalizeNamespaceEntry (name, config = {}) {
  const normalized = normalizeNamespaceName(name)
  if (!normalized) throw new Error('OutboxLog: invalid namespace name')
  const input = config && typeof config === 'object' && !Array.isArray(config) ? config : {}
  const caps = input.caps && typeof input.caps === 'object' && !Array.isArray(input.caps) ? input.caps : {}
  return {
    name: normalized,
    blind: input.blind === true,
    caps: {
      maxOutboxes: optionalPositiveInteger(caps.maxOutboxes),
      maxEntriesPerOutbox: optionalPositiveInteger(caps.maxEntriesPerOutbox),
      maxValueBytes: optionalPositiveInteger(caps.maxValueBytes),
      bytesPerDay: optionalPositiveInteger(caps.bytesPerDay)
    }
  }
}

function normalizeNamespaceName (name) {
  if (typeof name !== 'string') return null
  const normalized = name.trim().toLowerCase()
  return OUTBOXLOG_NAMESPACE_NAME.test(normalized) ? normalized : null
}

function normalizePersistedNamespace (name) {
  if (name == null || name === '') return null
  return normalizeNamespaceName(name)
}

function recordNamespace (data) {
  return data && typeof data._ns === 'string' ? normalizeNamespaceName(data._ns) : null
}

function namespaceRecordAllowed (namespaceInfo, data) {
  if (!namespaceInfo) return false
  if (!namespaceInfo.blind) return true
  return isOutboxBlindRecord(data) && !hasBlindForbiddenField(data)
}

export function createOutboxBlindSealedBody ({
  alg = OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG,
  nonce,
  ciphertext,
  keyId = null
} = {}) {
  const body = normalizeBlindSealedBody({
    sealed: {
      version: OUTBOXLOG_BLIND_SEAL_VERSION,
      alg,
      nonce,
      ciphertext,
      ...(keyId == null ? {} : { keyId })
    }
  })
  if (!body) throw new Error('OutboxLog: invalid blind sealed body')
  return body
}

export function isOutboxBlindRecord (data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false
  return !!normalizeBlindSealedBody(data.body)
}

export function isOutboxBlindSealedBody (body) {
  return !!normalizeBlindSealedBody(body)
}

function hasBlindForbiddenField (value) {
  if (!value || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(hasBlindForbiddenField)
  for (const [key, child] of Object.entries(value)) {
    if (BLIND_FORBIDDEN_FIELDS.has(key)) return true
    if (hasBlindForbiddenField(child)) return true
  }
  return false
}

function normalizeBlindSealedBody (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  for (const key of Object.keys(body)) {
    if (!BLIND_BODY_FIELDS.has(key)) return null
  }
  const sealed = normalizeBlindSeal(body.sealed)
  return sealed ? { sealed } : null
}

function normalizeBlindSeal (sealed) {
  if (!sealed || typeof sealed !== 'object' || Array.isArray(sealed)) return null
  for (const key of Object.keys(sealed)) {
    if (!BLIND_SEAL_FIELDS.has(key)) return null
  }
  if (sealed.version !== OUTBOXLOG_BLIND_SEAL_VERSION) return null
  if (!isShortString(sealed.alg, 64) || !BLIND_SEAL_ALG.test(sealed.alg)) return null
  if (!isShortString(sealed.nonce, 512)) return null
  if (typeof sealed.ciphertext !== 'string' || sealed.ciphertext.length === 0) return null
  const body = {
    version: sealed.version,
    alg: sealed.alg,
    nonce: sealed.nonce,
    ciphertext: sealed.ciphertext
  }
  if (sealed.keyId != null) {
    if (!isShortString(sealed.keyId, 256)) return null
    body.keyId = sealed.keyId
  }
  return body
}

function isShortString (value, maxLength) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
}

function namespaceCap (namespaceInfo, cap, fallback) {
  const value = namespaceInfo && namespaceInfo.caps ? namespaceInfo.caps[cap] : null
  return value == null ? fallback : Math.min(value, fallback)
}

function namespaceOutboxCountIn (groups, name) {
  let count = 0
  for (const group of groups.values()) {
    if (group.namespace === name) count++
  }
  return count
}

function optionalPositiveInteger (value) {
  const n = Number(value)
  return Number.isSafeInteger(n) && n > 0 ? n : null
}

function sortedRows (group) {
  return [...group.rows.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, value]) => ({ key, value }))
}

function clampDirectoryLimit (value, defaultLimit = DEFAULT_DIRECTORY_LIMIT, maxLimit = DEFAULT_MAX_DIRECTORY_LIMIT) {
  const fallback = positiveInteger(defaultLimit, DEFAULT_DIRECTORY_LIMIT)
  const cap = positiveInteger(maxLimit, DEFAULT_MAX_DIRECTORY_LIMIT)
  let limit = Number(value)
  if (!Number.isSafeInteger(limit) || limit < 1) limit = fallback
  if (limit > cap) limit = cap
  return limit
}

function positiveInteger (value, fallback) {
  const n = Number(value)
  return Number.isSafeInteger(n) && n > 0 ? n : fallback
}

function normalizeDirectorySince (value) {
  const since = Number(value)
  return Number.isSafeInteger(since) && since > 0 ? since : 0
}

function clampAppendEventLimit (value, maxLimit = DEFAULT_MAX_APPEND_EVENT_LIMIT) {
  const cap = positiveInteger(maxLimit, DEFAULT_MAX_APPEND_EVENT_LIMIT)
  let limit = Number(value)
  if (!Number.isSafeInteger(limit) || limit < 1) limit = cap
  if (limit > cap) limit = cap
  return limit
}

function normalizeAppendSince (value) {
  const since = Number(value)
  return Number.isSafeInteger(since) && since > 0 ? since : 0
}

function normalizeDirectoryCursor (value, maxLength = DEFAULT_MAX_APP_ID_LENGTH) {
  if (typeof value !== 'string' || !value || value.length > maxLength) return null
  return value
}

function normalizeAppendEvent (appId, event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return null
  const seq = Number(event.seq)
  const version = Number(event.version)
  if (!Number.isSafeInteger(seq) || seq < 1) return null
  if (!Number.isSafeInteger(version) || version < 1) return null
  if (event.appId !== appId) return null
  if (typeof event.key !== 'string' || !event.key || event.key.length > DEFAULT_MAX_ID_LENGTH + 65) return null
  if (typeof event.type !== 'string' || !event.type || event.type.length > 64) return null
  return {
    seq,
    topic: 'outbox/' + appId,
    appId,
    key: event.key,
    type: event.type,
    version
  }
}

function isVerified (result) {
  return result === true || (result && typeof result === 'object' && result.ok === true)
}

function normalizePersistence (persistence) {
  if (!persistence) return null
  if (typeof persistence.loadSync !== 'function' || typeof persistence.saveSync !== 'function') {
    throw new Error('OutboxLog: persistence requires loadSync() and saveSync(snapshot)')
  }
  return persistence
}

function normalizeJournal (journal) {
  if (!journal) return null
  if (typeof journal.loadSync !== 'function' || typeof journal.appendSync !== 'function') {
    throw new Error('OutboxLog: journal requires loadSync() and appendSync(entry)')
  }
  return journal
}

function normalizeJournalEntry (entry, expectedSeq) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  if (entry.version !== OUTBOXLOG_JOURNAL_VERSION) return null
  if (entry.seq !== expectedSeq) return null
  if (typeof entry.appId !== 'string' || !entry.appId || entry.appId.length > DEFAULT_MAX_APP_ID_LENGTH) return null
  if (typeof entry.inviteKey !== 'string' || entry.inviteKey.length !== 64) return null
  const namespace = normalizePersistedNamespace(entry.namespace)
  if (entry.kind === 'create') {
    return {
      version: entry.version,
      seq: entry.seq,
      kind: 'create',
      appId: entry.appId,
      inviteKey: entry.inviteKey,
      namespace
    }
  }
  if (entry.kind !== 'append') return null
  const op = entry.op
  if (!op || typeof op !== 'object' || Array.isArray(op)) return null
  if (typeof op.type !== 'string' || !op.type || op.type.length > 64) return null
  if (!op.data || typeof op.data !== 'object' || Array.isArray(op.data) || op.data.id == null) return null
  const id = String(op.data.id)
  if (id.length > DEFAULT_MAX_ID_LENGTH) return null
  let size
  try {
    size = Buffer.byteLength(JSON.stringify(op.data))
  } catch {
    return null
  }
  if (size > DEFAULT_MAX_VALUE_BYTES) return null
  return {
    version: entry.version,
    seq: entry.seq,
    kind: 'append',
    appId: entry.appId,
    inviteKey: entry.inviteKey,
    namespace,
    op: {
      type: op.type,
      data: clone(op.data)
    }
  }
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}

function fail (message, status, cause) {
  const err = new Error(message)
  err.status = status
  if (cause) err.cause = cause
  return err
}

function isHex (value, length) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/i.test(value)
}

function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  const keys = Object.keys(value).filter(key => !SIG_FIELDS.has(key)).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}
