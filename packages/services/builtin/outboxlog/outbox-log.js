/**
 * OutboxLog — single-writer-per-pubkey append log for app availability.
 *
 * This is the additive HiveRelay port of Peerit's relay `core-memory` sync
 * surface. It preserves the browser-facing sync contract while adding the
 * server-side check the relay core intentionally lacked: records must be signed
 * by the outbox writer key (`appId`). The record body remains opaque to the
 * relay; only the generic signed envelope is verified.
 */

import { createHash, randomBytes } from 'node:crypto'
import { closeSync, existsSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, statSync, truncateSync, unlinkSync, writeSync } from 'node:fs'
import { hostname, tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { createOutboxSwarmHub } from './swarm-hub.js'

export const DEFAULT_MAX_GROUPS = 20000
// Ghost-outbox sweep: an outbox with ZERO rows and version 0 older than this TTL
// is a leaked group slot (a create whose writer never appended — the peerit
// web-client churn era minted one per page refresh until 2026-07-08). Sweeping
// is safe by construction: an empty group holds no content, and the client's
// open-my-outbox path is join-with-stored-key -> catch -> create, so a false
// positive self-heals on the owner's next write.
export const DEFAULT_SWEEP_TTL_MS = 24 * 60 * 60 * 1000
const SWEEP_JOURNAL_BATCH = 1000 // appIds per journal entry (bounds the entry size)
export const DEFAULT_MAX_ROWS_PER_GROUP = 50000
export const DEFAULT_MAX_ID_LENGTH = 256
export const DEFAULT_MAX_APP_ID_LENGTH = 128
export const DEFAULT_MAX_VALUE_BYTES = 64 * 1024
export const DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
export const DEFAULT_DIRECTORY_LIMIT = 5000
export const DEFAULT_MAX_DIRECTORY_LIMIT = 5000
export const DEFAULT_MAX_APPEND_EVENTS_PER_OUTBOX = 1000
export const DEFAULT_MAX_APPEND_EVENT_LIMIT = 1000
export const DEFAULT_CHECKPOINT_INTERVAL = 4096
export const DEFAULT_MAX_COMMIT_RECEIPTS_PER_GROUP = 4096
export const DEFAULT_MAX_COMMIT_TOMBSTONES_PER_GROUP = 16384
export const DEFAULT_MAX_COMMIT_HISTORY_TOTAL = 40000
export const DEFAULT_MAX_COMMIT_MUTATIONS = 256
export const DEFAULT_MAX_JOURNAL_BYTES = 64 * 1024 * 1024
export const OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES = 1024 * 1024
export const DEFAULT_OUTBOXLOG_SERVICE_VERSION = '0.24.3'
// App-neutral default namespace. Registered apps SHOULD pass an explicit
// namespace; this fallback exists only so an operator who configures nothing
// still gets a working single-namespace registry. It is intentionally NOT
// 'peerit' — that was the last app-coupling in the generalized outboxlog.
// Back-compat: an explicit namespace:'peerit' (or a namespaces map containing
// 'peerit') still works exactly as before.
export const DEFAULT_OUTBOXLOG_NAMESPACE = 'outbox'
export const OUTBOXLOG_BLIND_SEAL_VERSION = 1
export const OUTBOXLOG_BLIND_SEAL_DEFAULT_ALG = 'xchacha20poly1305'
export const OUTBOXLOG_STATE_VERSION = 1
export const OUTBOXLOG_JOURNAL_VERSION = 1
export const OUTBOXLOG_CHECKPOINT_VERSION = 1
export const OUTBOXLOG_JOURNAL_MANIFEST_VERSION = 1

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
  checkpointInterval = DEFAULT_CHECKPOINT_INTERVAL,
  maxCommitReceiptsPerGroup = DEFAULT_MAX_COMMIT_RECEIPTS_PER_GROUP,
  maxCommitTombstonesPerGroup = DEFAULT_MAX_COMMIT_TOMBSTONES_PER_GROUP,
  maxCommitHistoryTotal = DEFAULT_MAX_COMMIT_HISTORY_TOTAL,
  maxCommitMutations = DEFAULT_MAX_COMMIT_MUTATIONS,
  maxJournalBytes = DEFAULT_MAX_JOURNAL_BYTES,
  journalFaultInjector = null,
  serviceVersion = DEFAULT_OUTBOXLOG_SERVICE_VERSION,
  legacyWrites = true,
  onAppend = null,
  log = () => {}
} = {}) {
  const groups = new Map()
  const subscribers = new Map()
  const appendEventsByApp = new Map()
  // DO-NOT-SERVE suppression set (operator takedown / liability parity). Keys
  // are opaque `appId \x00 rowKey` composites — an operator drops a record by
  // its opaque id WITHOUT reading the (possibly blind) content. The record
  // stays in `group.rows`; suppression is applied only at serve time. Persisted
  // so a takedown survives restart.
  const suppressed = new Set()
  let namespaceRegistry = createOutboxNamespaceRegistry({ namespace, namespaces })
  const customVerifyAppend = typeof verifyAppend === 'function' ? verifyAppend : null
  const shouldVerifyAppend = verifyAppend !== false
  let statePersistence = normalizePersistence(persistence)
  if (!statePersistence && persistencePath) statePersistence = createJsonFileOutboxPersistence(persistencePath)
  if (!statePersistence && storagePath) statePersistence = createJsonFileOutboxPersistence(join(storagePath, 'outboxlog-state.json'))
  let operationJournal = normalizeJournal(journal)
  let totalBytes = 0
  let directorySeq = 0
  let appendSeq = 0
  let journalSeq = 0
  const checkpointEvery = positiveInteger(checkpointInterval, DEFAULT_CHECKPOINT_INTERVAL)
  let entriesSinceCheckpoint = 0
  let snapshotDirty = false
  let legacyWritesEnabled = legacyWrites !== false
  let journalWriteFailed = false
  let closeRequested = false
  let closed = false
  let commitHistoryCount = 0
  let commitHistoryOrder = []
  const commitReceiptLimit = Math.min(
    positiveInteger(maxCommitReceiptsPerGroup, DEFAULT_MAX_COMMIT_RECEIPTS_PER_GROUP),
    positiveInteger(maxRowsPerGroup, DEFAULT_MAX_ROWS_PER_GROUP)
  )
  const commitMutationLimit = Math.min(
    positiveInteger(maxCommitMutations, DEFAULT_MAX_COMMIT_MUTATIONS),
    positiveInteger(maxRowsPerGroup, DEFAULT_MAX_ROWS_PER_GROUP)
  )
  const commitTombstoneLimit = positiveInteger(maxCommitTombstonesPerGroup, DEFAULT_MAX_COMMIT_TOMBSTONES_PER_GROUP)
  const commitHistoryLimit = positiveInteger(maxCommitHistoryTotal, DEFAULT_MAX_COMMIT_HISTORY_TOTAL)
  if (commitHistoryLimit < maxGroups) throw new Error('OutboxLog: maxCommitHistoryTotal must reserve at least one receipt per outbox')
  const reportedServiceVersion = typeof serviceVersion === 'string' && serviceVersion ? serviceVersion : DEFAULT_OUTBOXLOG_SERVICE_VERSION

  // Validate all constructor invariants before taking exclusive ownership. A
  // rejected engine configuration must never strand a writer lease.
  if (!operationJournal && journalPath) operationJournal = createJsonlOutboxJournal(journalPath, { maxBytes: maxJournalBytes, faultInjector: journalFaultInjector })

  try {
    loadState()
  } catch (err) {
    try { if (operationJournal && typeof operationJournal.close === 'function') operationJournal.close() } catch {}
    throw err
  }

  const getGroup = (appId) => groups.get(appId) || null
  const ensureGroup = (appId, namespaceInfo = null) => {
    if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength) throw fail('bad appId', 400)
    let group = groups.get(appId)
    if (!group) {
      if (groups.size >= maxGroups) throw fail('relay at group capacity', 503)
      assertNamespaceOutboxCapacity(namespaceInfo)
      group = { inviteKey: hex(32), rows: new Map(), commits: new Map(), commitTombstones: new Map(), version: 0, directorySeq: 0, namespace: namespaceInfo ? namespaceInfo.name : null, createdAt: Date.now() }
      groups.set(appId, group)
    } else {
      bindGroupNamespace(group, namespaceInfo)
    }
    return group
  }

  const EMPTY = { inviteKey: null, rows: new Map(), version: 0 }

  const sync = {
    create (appId, opts = {}) {
      if (!legacyWritesEnabled) throw fail('legacy create is disabled', 403)
      assertJournalMutationAllowed()
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
      if (!legacyWritesEnabled) throw fail('legacy append is disabled', 403)
      assertJournalMutationAllowed()
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

      group.rows.set(key, clone(op.data))
      group.atomicCensus = null
      group.atomicCensusRoot = null
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

      emitAppend({ ...event, value: clone(op.data) })
      return { ok: true, key }
    },

    commit (appId, commit) {
      assertJournalMutationAllowed()
      if (!hasDurableCommitJournal()) throw fail('durable commit persistence unavailable', 503)
      const prepared = prepareAtomicCommit(appId, commit)
      if (prepared.duplicate) return clone(prepared.receipt)

      // The complete transition is one journal record. A successful append is
      // the commit point; JSONL journals fsync it before returning. No group is
      // allocated and no row is visible before this succeeds.
      try {
        appendJournalEntry(journalCommitEntry(prepared))
      } catch (err) {
        throw fail('persistence failed', 500, err)
      }

      applyPreparedCommit(prepared)
      markJournalMutationForCheckpoint()
      for (const event of prepared.events) emitAppend({ ...event, value: clone(prepared.group.rows.get(event.key)) })
      return clone(prepared.receipt)
    },

    capabilities () {
      return commitCapabilities()
    },

    get (appId, key) {
      const group = getGroup(appId)
      if (!group) return null
      if (isSuppressed(appId, key)) return null // DO-NOT-SERVE
      const value = group.rows.get(key)
      return value === undefined ? null : clone(value)
    },

    list (appId, prefix, opts = {}) {
      return rangeRows(getGroup(appId) || EMPTY, { prefix, limit: opts.limit }, appId)
    },

    range (appId, opts = {}) {
      return rangeRows(getGroup(appId) || EMPTY, opts, appId)
    },

    count (appId, prefix) {
      const group = getGroup(appId)
      if (!group) return { count: 0 }
      let count = 0
      for (const key of group.rows.keys()) {
        if (prefix && !(key >= prefix && key < prefix + '\xff')) continue
        if (isSuppressed(appId, key)) continue // DO-NOT-SERVE
        count++
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
    },

    // Operator takedown: mark an opaque record id (appId + rowKey) DO-NOT-SERVE.
    // The record is NOT read, decoded, or deleted — subsequent serve-time reads
    // simply suppress it. Idempotent. Returns whether the id is now suppressed.
    takedown (appId, key) {
      return applyTakedown(appId, key, true)
    },

    // Reverse a takedown for an opaque record id. Idempotent.
    restore (appId, key) {
      return applyTakedown(appId, key, false)
    },

    // List the current DO-NOT-SERVE set as opaque { appId, key } ids. Content
    // is never read; this is the operator-facing audit surface for takedowns.
    takedowns () {
      const ids = []
      for (const composite of suppressed) {
        const split = composite.indexOf('\x00')
        if (split < 0) continue
        ids.push({ appId: composite.slice(0, split), key: composite.slice(split + 1) })
      }
      ids.sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      return { takedowns: ids, count: ids.length }
    }
  }

  sync.sweepGhosts = sweepGhosts

  return {
    sync,
    swarm,
    subscribe,
    flush,
    close,
    configurePersistence,
    configureNamespaces,
    configureLegacyWrites,
    assertAtomicWriteReady,
    namespaces: () => namespaceRegistry.snapshot(),
    takedown: sync.takedown,
    restore: sync.restore,
    takedowns: sync.takedowns,
    sweepGhosts,
    isSuppressed,
    snapshot,
    _stats () {
      return { groups: groups.size, totalBytes, directorySeq, appendSeq, commitHistoryCount }
    }
  }

  function hasDurableCommitJournal () {
    return !!(
      operationJournal &&
      operationJournal.durableSync === true &&
      operationJournal.ready !== false &&
      !journalWriteFailed &&
      !closeRequested
    )
  }

  function commitCapabilities () {
    const durable = hasDurableCommitJournal()
    const mutationReady = !journalWriteFailed && !closeRequested
    return {
      schema: 1,
      ready: mutationReady && (legacyWritesEnabled || durable),
      serviceVersion: reportedServiceVersion,
      atomicCommit: {
        schema: 1,
        method: 'POST',
        route: '/api/sync/commit',
        enabled: true,
        durable,
        ready: durable,
        cas: true,
        idempotent: true,
        idempotency: {
          mode: 'bounded',
          latestPerOutbox: true,
          hotReceiptsPerOutbox: commitReceiptLimit,
          tombstonesPerOutbox: commitTombstoneLimit,
          aggregateEntries: commitHistoryLimit,
          extraHistoryEntries: commitHistoryLimit - maxGroups
        }
      },
      legacyWrites: {
        create: mutationReady && legacyWritesEnabled,
        append: mutationReady && legacyWritesEnabled
      }
    }
  }

  function assertJournalMutationAllowed () {
    if (closeRequested) throw fail('outboxlog is closed', 503)
    if (journalWriteFailed) throw fail('journal write state is uncertain; restart required', 503)
  }

  function fenceJournalWrite (err) {
    journalWriteFailed = true
    if (operationJournal && typeof operationJournal.markFailed === 'function') {
      try { operationJournal.markFailed(err) } catch {}
    }
  }

  function assertAtomicWriteReady ({ requireFsyncedPath = false } = {}) {
    const capabilities = commitCapabilities()
    if (legacyWritesEnabled) throw fail('atomic-only mode requires legacy create/append disabled', 500)
    if (requireFsyncedPath && (!operationJournal || operationJournal.kind !== 'jsonl-fsync' || typeof operationJournal.path !== 'string' || operationJournal.ready !== true)) {
      throw fail('atomic-only mode requires a configured, fsync-probed JSONL journal path', 500)
    }
    if (!capabilities.atomicCommit.durable || !capabilities.atomicCommit.ready) {
      throw fail('atomic-only mode requires a ready fsynced durable journal', 500)
    }
    return true
  }

  function prepareAtomicCommit (appId, input, replay = {}) {
    if (!isHex(appId, 64)) throw fail('bad appId', 400)
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw fail('bad commit', 400)
    assertExactObjectFields(input, ['schema', 'commitId', 'expected', 'mutations', 'head', 'authorization'], 'bad commit fields')
    if (input.schema !== 1) throw fail('unsupported commit schema', 400)
    if (!isHex(input.commitId, 64)) throw fail('bad commitId', 400)

    const commit = clone(input)
    let commitBytes
    try {
      commitBytes = Buffer.byteLength(JSON.stringify(commit))
    } catch {
      throw fail('unserializable commit', 400)
    }
    // Replay applies the same 1 MiB bound. Reject before signature/CAS work so
    // no acknowledged commit can later make a restart fail as unreplayable.
    if (commitBytes > OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES) throw fail('commit too large', 413)
    const existingGroup = groups.get(appId) || null

    const expected = commit.expected
    if (!expected || typeof expected !== 'object' || Array.isArray(expected)) throw fail('bad expected head', 400)
    assertExactObjectFields(expected, ['version', 'root'], 'bad expected head fields')
    if (!Number.isSafeInteger(expected.version) || expected.version < 0) throw fail('bad expected version', 400)
    if (!isHex(expected.root, 64)) throw fail('bad expected root', 400)
    if (!Array.isArray(commit.mutations) || commit.mutations.length < 1 || commit.mutations.length > commitMutationLimit) {
      throw fail('bad mutations', 400)
    }
    if (!commit.head || typeof commit.head !== 'object' || Array.isArray(commit.head) || commit.head.type !== 'head') {
      throw fail('bad head mutation', 400)
    }
    assertCommitWrapperFields(commit.head, 'bad head mutation fields')
    if (!commit.authorization || typeof commit.authorization !== 'object' || Array.isArray(commit.authorization)) {
      throw fail('bad commit authorization', 400)
    }

    const authorization = commit.authorization
    const expectedAuthorizationFields = ['appId', 'createdAt', 'expectedRoot', 'expectedVersion', 'headSig', 'id', 'mutationSigs']
    assertExactObjectFields(authorization, [...expectedAuthorizationFields, ...SIG_FIELDS], 'bad commit authorization fields')
    const namespaceName = recordNamespace(authorization)
    const namespaceInfo = namespaceName ? namespaceRegistry.get(namespaceName) : null
    if (!namespaceName || !namespaceInfo) throw fail('unknown namespace', 400)
    if (existingGroup && existingGroup.namespace && existingGroup.namespace !== namespaceName) throw fail('namespace mismatch', 400)

    verifyAtomicRecord(appId, 'commit', authorization, namespaceName, 'commit authorization')
    const authorizationFields = Object.keys(authorization).filter(key => !SIG_FIELDS.has(key)).sort()
    if (!sameStringArray(authorizationFields, expectedAuthorizationFields)) throw fail('bad commit authorization fields', 400)
    if (authorization.id !== commit.commitId || authorization.appId !== appId) throw fail('commit authorization binding mismatch', 400)
    if (authorization.expectedVersion !== expected.version || authorization.expectedRoot !== expected.root) {
      throw fail('commit authorization binding mismatch', 400)
    }
    if (!Number.isSafeInteger(authorization.createdAt) || authorization.createdAt < 0) throw fail('bad commit authorization createdAt', 400)
    if (!Array.isArray(authorization.mutationSigs) || !authorization.mutationSigs.every(sig => isHex(sig, 128)) || !isHex(authorization.headSig, 128)) {
      throw fail('bad commit authorization bindings', 400)
    }
    const derivedCommitId = hashHex(canonicalOutboxRecord('commit-id', {
      appId: authorization.appId,
      expectedVersion: authorization.expectedVersion,
      expectedRoot: authorization.expectedRoot,
      mutationSigs: authorization.mutationSigs,
      headSig: authorization.headSig,
      createdAt: authorization.createdAt
    }))
    if (derivedCommitId !== commit.commitId) throw fail('commitId does not match authorization', 400)

    const mutationSigs = []
    const ops = []
    const seenKeys = new Set()
    for (const mutation of commit.mutations) {
      if (!mutation || typeof mutation !== 'object' || Array.isArray(mutation)) throw fail('bad mutation', 400)
      assertCommitWrapperFields(mutation, 'bad mutation fields')
      if (typeof mutation.type !== 'string' || !mutation.type || mutation.type.length > 64) throw fail('bad mutation type', 400)
      if (mutation.type.includes(':') || mutation.type.includes('!')) throw fail('ambiguous mutation type', 400)
      if (mutation.type === 'head' || mutation.type.startsWith('head:') || (mutation.data && mutation.data._t === 'head')) {
        throw fail('head is not allowed in mutations', 400)
      }
      if (!mutation.data || typeof mutation.data !== 'object' || Array.isArray(mutation.data) || mutation.data.id == null) {
        throw fail('bad mutation data', 400)
      }
      const id = String(mutation.data.id)
      if (id.length > maxIdLength) throw fail('id too long', 400)
      if (recordNamespace(mutation.data) !== namespaceName) throw fail('namespace mismatch', 400)
      verifyAtomicRecord(appId, mutation.type, mutation.data, namespaceName, 'mutation')
      const key = mutation.type.replace(':', '!') + '!' + id
      if (seenKeys.has(key)) throw fail('duplicate mutation key', 400)
      seenKeys.add(key)
      mutationSigs.push(mutation.data._sig)
      ops.push({ type: mutation.type, data: clone(mutation.data), key })
    }

    const headData = commit.head.data
    if (!headData || typeof headData !== 'object' || Array.isArray(headData) || headData.id !== appId) throw fail('bad head data', 400)
    if (recordNamespace(headData) !== namespaceName) throw fail('namespace mismatch', 400)
    verifyAtomicRecord(appId, 'head', headData, namespaceName, 'head')

    if (!sameStringArray(authorization.mutationSigs, mutationSigs) || authorization.headSig !== headData._sig) {
      throw fail('commit authorization binding mismatch', 400)
    }

    // Fingerprint only the authenticated state transition. Wrapper timestamps
    // are accepted for Peerit wire compatibility but are not security inputs;
    // changing one after a lost response must still replay the same receipt.
    // Unknown wrapper fields are rejected above so they cannot become a second
    // unauthenticated interpretation of the same commitId.
    const fingerprint = hashHex(stableAll({
      appId,
      schema: commit.schema,
      commitId: commit.commitId,
      expected,
      mutations: commit.mutations.map(({ type, data }) => ({ type, data })),
      head: { type: commit.head.type, data: commit.head.data },
      authorization
    }))
    const prior = findCommitReceipt(existingGroup, commit.commitId)
    if (prior) {
      if (prior.fingerprint !== fingerprint) throw fail('commitId conflict', 409)
      return { duplicate: true, receipt: prior.receipt }
    }
    const current = currentSignedHead(existingGroup, appId)
    if (current.version !== expected.version || current.root !== expected.root) throw fail('stale head', 409)
    if (expected.version === Number.MAX_SAFE_INTEGER) throw fail('head version exhausted', 409)

    // Keep the protocol's exact sorted-census root while avoiding a full rows
    // clone plus O(n log n) re-sort on every write. The current census is
    // verified/cached once; a bounded mutation batch is merged in O(n + mlogm).
    const census = applyAtomicCensusMutations(current.census, ops)
    const nextRoot = hashHex(census.join('\x01'))
    const nextVersion = expected.version + 1
    if (headData.version !== nextVersion || headData.count !== census.length || headData.root !== nextRoot) {
      throw fail('head does not match committed census', 400)
    }
    const headKey = 'head!' + appId

    const rowLimit = namespaceCap(namespaceInfo, 'maxEntriesPerOutbox', maxRowsPerGroup)
    let nextRowCount = existingGroup ? existingGroup.rows.size : 0
    for (const op of ops) {
      if (!existingGroup || !existingGroup.rows.has(op.key)) nextRowCount++
    }
    if (!existingGroup || !existingGroup.rows.has(headKey)) nextRowCount++
    if (nextRowCount > rowLimit) throw fail('outbox at row capacity', 503)
    let nextBytes = totalBytes
    for (const op of [...ops, { type: 'head', data: headData, key: headKey }]) {
      const old = existingGroup ? existingGroup.rows.get(op.key) : undefined
      const oldSize = old === undefined ? 0 : Buffer.byteLength(JSON.stringify(old))
      const size = Buffer.byteLength(JSON.stringify(op.data))
      if (size > namespaceCap(namespaceInfo, 'maxValueBytes', maxValueBytes)) throw fail('record too large', 413)
      nextBytes += size - oldSize
    }
    if (nextBytes > maxTotalBytes) throw fail('relay at storage capacity', 503)
    if (!existingGroup) {
      if (groups.size >= maxGroups) throw fail('relay at group capacity', 503)
      assertNamespaceOutboxCapacity(namespaceInfo)
    } else if (!existingGroup.namespace) {
      // Legacy create() could leave an unbound empty ghost. Binding it during
      // genesis must consume the same namespace slot as allocating a new group.
      assertNamespaceOutboxCapacity(namespaceInfo)
    }

    const inviteKey = existingGroup ? existingGroup.inviteKey : (replay.inviteKey || hex(32))
    const receipt = {
      ok: true,
      durable: true,
      commitId: commit.commitId,
      appId,
      inviteKey,
      head: { version: nextVersion, count: census.length, root: nextRoot },
      relayVersion: (existingGroup ? existingGroup.version : 0) + ops.length + 1
    }

    return {
      duplicate: false,
      appId,
      commit,
      fingerprint,
      receipt,
      inviteKey,
      namespace: namespaceName,
      createdAt: existingGroup ? existingGroup.createdAt : (Number.isFinite(replay.createdAt) ? replay.createdAt : Date.now()),
      existingGroup,
      census,
      nextRoot,
      ops: [...ops, { type: 'head', data: clone(headData), key: headKey }],
      nextBytes,
      events: []
    }
  }

  function verifyAtomicRecord (appId, type, data, namespaceName, label) {
    if (data._k !== appId || recordNamespace(data) !== namespaceName) throw fail(label + ' owner mismatch', 400)
    if (!verifyOutboxRecordSignature({ appId, type, data }, { registry: namespaceRegistry })) throw fail('bad ' + label + ' signature', 400)
  }

  function currentSignedHead (group, appId) {
    const emptyRoot = hashHex('')
    if (!group) return { version: 0, count: 0, root: emptyRoot, census: [] }
    const data = group.rows.get('head!' + appId)
    if (!data) {
      if (group.rows.size !== 0) throw fail('headless outbox cannot accept genesis commit', 409)
      return { version: 0, count: 0, root: emptyRoot, census: [] }
    }
    const namespaceName = recordNamespace(data)
    if (!namespaceName || (group.namespace && group.namespace !== namespaceName)) throw fail('current head is invalid', 409)
    try {
      verifyAtomicRecord(appId, 'head', data, namespaceName, 'current head')
    } catch {
      throw fail('current head is invalid', 409)
    }
    if (!Number.isSafeInteger(data.version) || data.version < 1 || !Number.isSafeInteger(data.count) || data.count < 0 || !isHex(data.root, 64)) {
      throw fail('current head is invalid', 409)
    }
    let census = null
    if (Array.isArray(group.atomicCensus) && group.atomicCensusRoot === data.root && group.atomicCensus.length === data.count) {
      census = group.atomicCensus
    } else {
      census = atomicCensus(group.rows, appId)
      if (data.count !== census.length || data.root !== hashHex(census.join('\x01'))) throw fail('current head census mismatch', 409)
      group.atomicCensus = census
      group.atomicCensusRoot = data.root
    }
    return { version: data.version, count: data.count, root: data.root, census }
  }

  function atomicCensus (rows, appId) {
    const census = []
    for (const [key, value] of rows) {
      if (!key || !value || typeof value._sig !== 'string') continue
      if (key.split('!')[0] === 'head' || value._t === 'head') continue
      if (value._k !== appId) continue
      census.push(key + '\x00' + value._sig)
    }
    census.sort()
    return census
  }

  function applyAtomicCensusMutations (current, ops) {
    const updates = new Map()
    for (const op of ops) updates.set(op.key, op.key + '\x00' + op.data._sig)
    const retained = []
    for (const entry of current) {
      const split = entry.lastIndexOf('\x00')
      const key = split < 0 ? entry : entry.slice(0, split)
      if (updates.has(key)) {
        retained.push(updates.get(key))
        updates.delete(key)
      } else {
        retained.push(entry)
      }
    }
    const additions = [...updates.values()].sort()
    if (additions.length === 0) return retained
    const merged = []
    let left = 0
    let right = 0
    while (left < retained.length || right < additions.length) {
      if (right >= additions.length || (left < retained.length && retained[left] < additions[right])) merged.push(retained[left++])
      else merged.push(additions[right++])
    }
    return merged
  }

  function applyPreparedCommit (prepared) {
    let group = prepared.existingGroup
    if (!group) {
      group = {
        inviteKey: prepared.inviteKey,
        rows: new Map(),
        commits: new Map(),
        commitTombstones: new Map(),
        version: 0,
        directorySeq: 0,
        namespace: prepared.namespace,
        createdAt: prepared.createdAt
      }
      groups.set(prepared.appId, group)
    } else {
      if (!group.commits) group.commits = new Map()
      if (!group.commitTombstones) group.commitTombstones = new Map()
      if (!group.namespace) group.namespace = prepared.namespace
    }
    prepared.group = group

    for (const op of prepared.ops) {
      group.rows.set(op.key, clone(op.data))
      group.version++
      if (op.type === 'head') group.directorySeq = ++directorySeq
      const event = rememberAppendEvent({
        seq: ++appendSeq,
        topic: 'outbox/' + prepared.appId,
        appId: prepared.appId,
        key: op.key,
        type: op.type,
        version: group.version
      })
      prepared.events.push(event)
    }
    totalBytes = prepared.nextBytes
    group.atomicCensus = prepared.census
    group.atomicCensusRoot = prepared.nextRoot
    rememberCommitReceipt(group, prepared.commit.commitId, prepared.fingerprint, prepared.receipt)
  }

  function rememberCommitReceipt (group, commitId, fingerprint, receipt) {
    if (!group.commits) group.commits = new Map()
    if (!group.commitTombstones) group.commitTombstones = new Map()
    const existed = group.commits.has(commitId) || group.commitTombstones.has(commitId)
    group.commitTombstones.delete(commitId)
    group.commits.set(commitId, { fingerprint, receipt: clone(receipt) })
    if (!existed) {
      commitHistoryCount++
      commitHistoryOrder.push([receipt.appId, commitId])
    }
    while (group.commits.size > commitReceiptLimit) {
      const oldestId = group.commits.keys().next().value
      const oldest = group.commits.get(oldestId)
      group.commits.delete(oldestId)
      group.commitTombstones.set(oldestId, oldest)
    }
    while (group.commitTombstones.size > commitTombstoneLimit) {
      group.commitTombstones.delete(group.commitTombstones.keys().next().value)
      commitHistoryCount--
    }
    evictGlobalCommitHistory()
  }

  function findCommitReceipt (group, commitId) {
    if (!group) return null
    return (group.commits && group.commits.get(commitId)) ||
      (group.commitTombstones && group.commitTombstones.get(commitId)) ||
      null
  }

  function evictGlobalCommitHistory () {
    if (commitHistoryCount <= commitHistoryLimit) {
      compactCommitHistoryOrderIfNeeded()
      return
    }
    const deferredLatest = []
    while (commitHistoryCount > commitHistoryLimit && commitHistoryOrder.length > 0) {
      const entry = commitHistoryOrder.shift()
      const appId = entry && entry[0]
      const commitId = entry && entry[1]
      const group = groups.get(appId)
      if (!group || !findCommitReceipt(group, commitId)) continue
      if (latestCommitId(group) === commitId) {
        deferredLatest.push(entry)
        continue
      }
      if (group.commits) group.commits.delete(commitId)
      if (group.commitTombstones) group.commitTombstones.delete(commitId)
      commitHistoryCount--
    }
    commitHistoryOrder.push(...deferredLatest)
    if (commitHistoryCount > commitHistoryLimit) {
      // Construction enforces one aggregate slot per possible outbox, so this
      // can only indicate corrupt internal accounting rather than load.
      throw fail('commit receipt retention invariant failed', 500)
    }
    compactCommitHistoryOrderIfNeeded()
  }

  function latestCommitId (group) {
    if (group.commits && group.commits.size > 0) return [...group.commits.keys()].at(-1)
    if (group.commitTombstones && group.commitTombstones.size > 0) return [...group.commitTombstones.keys()].at(-1)
    return null
  }

  function compactCommitHistoryOrderIfNeeded () {
    if (commitHistoryOrder.length <= commitHistoryLimit * 2 + maxGroups) return
    commitHistoryOrder = commitHistoryOrder.filter(([appId, commitId]) => findCommitReceipt(groups.get(appId), commitId))
  }

  function serializedCommitHistoryOrder () {
    const normalized = normalizeCommitHistoryOrder(commitHistoryOrder, groups)
    commitHistoryOrder = normalized
    return normalized.map(entry => [...entry])
  }

  function normalizeCommitHistoryOrder (savedOrder, sourceGroups) {
    const normalized = []
    const seen = new Set()
    const add = (appId, commitId) => {
      if (typeof appId !== 'string' || !isHex(commitId, 64)) return
      const group = sourceGroups.get(appId)
      const exists = group && ((group.commits && group.commits.has(commitId)) || (group.commitTombstones && group.commitTombstones.has(commitId)))
      const key = appId + '\x00' + commitId
      if (!exists || seen.has(key)) return
      seen.add(key)
      normalized.push([appId, commitId])
    }
    for (const entry of Array.isArray(savedOrder) ? savedOrder : []) {
      if (Array.isArray(entry) && entry.length === 2) add(entry[0], entry[1])
    }
    // Older checkpoints predate the global FIFO. Tombstones are older than
    // hot receipts; Map insertion order preserves chronology within each tier.
    for (const [appId, group] of sourceGroups) {
      for (const commitId of (group.commitTombstones || new Map()).keys()) add(appId, commitId)
      for (const commitId of (group.commits || new Map()).keys()) add(appId, commitId)
    }
    return normalized
  }

  function journalCommitEntry (prepared) {
    return {
      kind: 'commit',
      appId: prepared.appId,
      inviteKey: prepared.inviteKey,
      namespace: prepared.namespace,
      createdAt: prepared.createdAt,
      fingerprint: prepared.fingerprint,
      commit: clone(prepared.commit),
      receipt: clone(prepared.receipt)
    }
  }

  function markJournalMutationForCheckpoint () {
    if (!statePersistence && !(operationJournal && typeof operationJournal.checkpointSync === 'function')) return
    snapshotDirty = true
    entriesSinceCheckpoint++
    if (entriesSinceCheckpoint < checkpointEvery) return
    try {
      saveCheckpointSnapshot()
      snapshotDirty = false
      entriesSinceCheckpoint = 0
    } catch (err) {
      fenceJournalWrite(err)
      log('outboxlog-checkpoint-error', { error: err })
    }
  }

  function suppressionKey (appId, key) {
    if (typeof appId !== 'string' || !appId || appId.length > maxAppIdLength) return null
    if (typeof key !== 'string' || !key || key.length > maxIdLength + 65) return null
    return appId + '\x00' + key
  }

  function isSuppressed (appId, key) {
    const composite = suppressionKey(appId, key)
    return composite ? suppressed.has(composite) : false
  }

  function applyTakedown (appId, key, drop) {
    assertJournalMutationAllowed()
    const composite = suppressionKey(appId, key)
    if (!composite) throw fail('bad takedown id', 400)
    const already = suppressed.has(composite)
    if (drop === already) return { appId, key, suppressed: drop } // no change
    if (drop) suppressed.add(composite)
    else suppressed.delete(composite)
    try {
      saveState(journalTakedownEntry(appId, key, drop))
    } catch (err) {
      // Roll back the in-memory change so state and persistence stay coherent.
      if (drop) suppressed.delete(composite)
      else suppressed.add(composite)
      throw fail('persistence failed', 500, err)
    }
    return { appId, key, suppressed: drop }
  }

  // Remove ALL server-side state for an appId whose group is being swept:
  // the group itself, its buffered append events, and any takedown
  // suppressions scoped to it (nothing left to suppress). Namespace outbox
  // counts are derived live from `groups`, so capacity self-corrects.
  function deleteGroupState (appId) {
    const group = groups.get(appId)
    if (group) commitHistoryCount -= (group.commits ? group.commits.size : 0) + (group.commitTombstones ? group.commitTombstones.size : 0)
    groups.delete(appId)
    appendEventsByApp.delete(appId)
    const prefix = appId + '\x00'
    for (const composite of [...suppressed]) {
      if (composite.startsWith(prefix)) suppressed.delete(composite)
    }
  }

  // Ghost-outbox sweep (2026-07-08): reclaim group slots leaked by writers that
  // created an outbox and never appended — most notably the peerit web client's
  // identity-per-refresh churn era, which minted one empty group per page load
  // until the lazy-identity fix. Ghost = zero rows AND version 0 AND older than
  // ttlMs (a group with no createdAt predates this feature and is treated as
  // infinitely old — every such empty group is churn-era by definition).
  //
  // SAFE BY CONSTRUCTION: an empty group holds no user content, and the client
  // recreates its outbox on demand (join-with-stored-key -> catch -> create), so
  // even a false positive costs one extra create on the owner's next write.
  // Deletions are journaled (kind 'sweep') so they survive journal replay, and
  // stale swarm descriptors pointing at swept appIds are pruned — those replays
  // are the per-boot request amplifier the churn era left behind.
  function sweepGhosts ({ ttlMs = DEFAULT_SWEEP_TTL_MS, now = Date.now() } = {}) {
    assertJournalMutationAllowed()
    const ttl = Number.isFinite(ttlMs) && ttlMs >= 0 ? ttlMs : DEFAULT_SWEEP_TTL_MS
    const cutoff = now - ttl
    const victims = []
    for (const [appId, group] of groups) {
      if (group.rows.size !== 0 || group.version !== 0) continue
      const created = Number.isFinite(group.createdAt) ? group.createdAt : 0
      if (created <= cutoff) victims.push(appId)
    }
    let swept = 0
    for (let i = 0; i < victims.length; i += SWEEP_JOURNAL_BATCH) {
      const batch = victims.slice(i, i + SWEEP_JOURNAL_BATCH)
      const rollback = batch.map((appId) => [appId, groups.get(appId)])
      for (const appId of batch) deleteGroupState(appId)
      try {
        saveState(journalSweepEntry(batch))
      } catch (err) {
        // Same coherence contract as applyTakedown: if persistence refuses the
        // entry, restore the in-memory groups so state and journal agree.
        for (const [appId, group] of rollback) { if (group) groups.set(appId, group) }
        throw fail('persistence failed', 500, err)
      }
      swept += batch.length
    }
    // Prune remembered swarm descriptors that point at appIds with no live
    // group (swept now or ever). Conservative: only descriptors we can
    // positively attribute (JSON with a string appId) are considered — anything
    // else (another app's format) is kept. Feature-detected so an injected hub
    // without prune support is tolerated.
    let descriptorsPruned = 0
    if (swarm && typeof swarm.pruneDescriptors === 'function') {
      descriptorsPruned = swarm.pruneDescriptors((topic, data) => {
        let d = null
        try { d = JSON.parse(data) } catch { return true }
        if (!d || typeof d !== 'object' || typeof d.appId !== 'string' || !d.appId) return true
        return groups.has(d.appId)
      })
    }
    return { swept, remaining: groups.size, descriptorsPruned }
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
    // DO-NOT-SERVE: never push a live event for a suppressed row.
    if (event && isSuppressed(event.appId, event.key)) return
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

  function rangeRows (group, opts = {}, appId = null) {
    let rows = sortedRows(group)
    // DO-NOT-SERVE: drop suppressed rows before any paging so a taken-down
    // record never appears in list/range results (it still exists in storage).
    if (appId) rows = rows.filter((row) => !isSuppressed(appId, row.key))
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
      const headKey = 'head!' + appId
      if (isSuppressed(appId, headKey)) continue // DO-NOT-SERVE: hide from directory
      const head = group.rows.get(headKey)
      if (!head) continue
      const seq = Number.isSafeInteger(group.directorySeq) ? group.directorySeq : 0
      if (minSeq > 0 && seq <= minSeq) continue
      if (after && appId <= after) continue
      rows.push({ appId, head, seq })
    }

    rows.sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0))
    const page = rows.slice(0, pageLimit)
    const heads = {}
    for (const row of page) heads[row.appId] = clone(row.head)

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
    // DO-NOT-SERVE: drop append markers for suppressed rows so a taken-down
    // record is not re-advertised to sync clients via the event stream.
    const changed = events.filter(event => event.seq > minSeq && !isSuppressed(appId, event.key))
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
    const nextStatePersistence = normalizePersistence(persistence) ||
      (persistencePath ? createJsonFileOutboxPersistence(persistencePath) : null) ||
      (storagePath ? createJsonFileOutboxPersistence(join(storagePath, 'outboxlog-state.json')) : null)
    const nextOperationJournal = normalizeJournal(journal) ||
      (journalPath ? createJsonlOutboxJournal(journalPath, { maxBytes: maxJournalBytes, faultInjector: journalFaultInjector }) : null)
    if (!nextStatePersistence && !nextOperationJournal) return false
    statePersistence = nextStatePersistence
    operationJournal = nextOperationJournal
    try {
      loadState()
    } catch (err) {
      try { if (nextOperationJournal && typeof nextOperationJournal.close === 'function') nextOperationJournal.close() } catch {}
      statePersistence = null
      operationJournal = null
      throw err
    }
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

  function configureLegacyWrites (enabled) {
    legacyWritesEnabled = enabled !== false
    return legacyWritesEnabled
  }

  function loadState () {
    let loaded = false
    if (operationJournal && typeof operationJournal.loadCheckpointSync === 'function') {
      const state = operationJournal.loadCheckpointSync()
      if (state) {
        applyState(state)
        loaded = true
      }
    }
    if (statePersistence) {
      try {
        const state = statePersistence.loadSync()
        if (state && (!loaded || persistedJournalSeq(state) > journalSeq)) {
          applyState(state)
          loaded = true
        }
      } catch (err) {
        // A journal-managed checkpoint (or the journal from sequence zero) is
        // a complete recovery source. A corrupt convenience snapshot must not
        // take down an otherwise recoverable atomic relay.
        if (!operationJournal) throw err
        log('outboxlog-snapshot-recovery', { error: err })
      }
    }
    // With checkpointing the snapshot may lag the journal: replay the journal
    // tail (entries past the snapshot's journalSeq) to recover appends that
    // landed after the last checkpoint. Without a snapshot, replay it all.
    if (operationJournal) loadJournal(loaded ? journalSeq : 0)
  }

  function saveState (journalEntry = null) {
    // Journal-first layering: the append-log is the durable fast path, so land
    // the entry whenever a journal is configured — even alongside snapshot
    // persistence, which is a periodic checkpoint, not a replacement. The old
    // `!statePersistence` guard left the journal silently empty when start()
    // wired both journalPath + storagePath. (#146)
    if (operationJournal && journalEntry) appendJournalEntry(journalEntry)
    const hasJournalCheckpoint = operationJournal && typeof operationJournal.checkpointSync === 'function'
    if (!statePersistence && !hasJournalCheckpoint) return
    if (operationJournal) {
      // Contract: with a journal configured every mutation passes a journal
      // entry, so a null entry here means nothing changed (create on an
      // existing group) — skip. The journal already made real mutations
      // durable; the full snapshot is an O(state) write that must not run
      // per-append. Checkpoint every checkpointInterval entries;
      // flush()/stop force the rest. (#144)
      if (!journalEntry) return
      snapshotDirty = true
      entriesSinceCheckpoint++
      if (entriesSinceCheckpoint < checkpointEvery) return
    }
    try {
      saveCheckpointSnapshot()
      snapshotDirty = false
      entriesSinceCheckpoint = 0
    } catch (err) {
      fenceJournalWrite(err)
      throw err
    }
  }

  function flush () {
    assertJournalMutationAllowed()
    const hasJournalCheckpoint = operationJournal && typeof operationJournal.checkpointSync === 'function'
    try {
      if ((statePersistence || hasJournalCheckpoint) && (snapshotDirty || !operationJournal)) {
        saveCheckpointSnapshot()
        snapshotDirty = false
        entriesSinceCheckpoint = 0
      }
      if (operationJournal && typeof operationJournal.flush === 'function') {
        return operationJournal.flush()
      }
    } catch (err) {
      fenceJournalWrite(err)
      throw err
    }
  }

  function close () {
    if (closed) return
    closeRequested = true
    subscribers.clear()
    try {
      if (operationJournal && typeof operationJournal.close === 'function') operationJournal.close()
      closed = true
    } catch (err) {
      fenceJournalWrite(err)
      throw err
    }
  }

  function saveCheckpointSnapshot () {
    const state = snapshot()
    // The journal checkpoint is the authoritative crash-recovery boundary and
    // rotates the JSONL tail. Do not write the same O(state) image a second
    // time through compatibility persistence; non-compacting journals still
    // use that snapshot layer exactly as before.
    if (operationJournal && typeof operationJournal.checkpointSync === 'function') operationJournal.checkpointSync(state)
    else if (statePersistence) statePersistence.saveSync(state)
  }

  function snapshot () {
    return {
      version: OUTBOXLOG_STATE_VERSION,
      directorySeq,
      appendSeq,
      journalSeq,
      commitHistoryOrder: serializedCommitHistoryOrder(),
      // Persist DO-NOT-SERVE ids as opaque [appId, key] pairs so takedowns
      // survive restart. Never carries any record content.
      suppressed: [...suppressed].map(splitSuppressionKey).filter(Boolean),
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
          createdAt: Number.isFinite(group.createdAt) ? group.createdAt : null,
          commits: [...(group.commits || new Map()).entries()].map(([commitId, saved]) => [commitId, clone(saved)]),
          commitTombstones: [...(group.commitTombstones || new Map()).entries()].map(([commitId, saved]) => [commitId, clone(saved)]),
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
    let nextCommitHistoryCount = 0
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
      const commits = new Map()
      const commitTombstones = new Map()
      const restoredInviteKey = typeof groupState.inviteKey === 'string' && isHex(groupState.inviteKey, 64) ? groupState.inviteKey : hex(32)
      for (const saved of Array.isArray(groupState.commits) ? groupState.commits.slice(-commitReceiptLimit) : []) {
        const normalized = normalizePersistedCommitReceipt(saved, appId, restoredInviteKey)
        if (normalized) commits.set(normalized[0], normalized[1])
      }
      for (const saved of Array.isArray(groupState.commitTombstones) ? groupState.commitTombstones.slice(-commitTombstoneLimit) : []) {
        const normalized = normalizePersistedCommitReceipt(saved, appId, restoredInviteKey)
        if (normalized && !commits.has(normalized[0])) commitTombstones.set(normalized[0], normalized[1])
      }
      nextCommitHistoryCount += commits.size + commitTombstones.size
      let restoredDirectorySeq = Number.isSafeInteger(groupState.directorySeq) && groupState.directorySeq >= 0 ? groupState.directorySeq : 0
      if (restoredDirectorySeq > nextDirectorySeq) nextDirectorySeq = restoredDirectorySeq
      if (restoredDirectorySeq === 0 && rows.has('head!' + appId)) restoredDirectorySeq = ++nextDirectorySeq
      nextGroups.set(appId, {
        inviteKey: restoredInviteKey,
        rows,
        commits,
        commitTombstones,
        directorySeq: restoredDirectorySeq,
        namespace: namespaceName,
        version: Number.isSafeInteger(groupState.version) && groupState.version >= rows.size ? groupState.version : rows.size,
        createdAt: Number.isFinite(groupState.createdAt) ? groupState.createdAt : null
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
    commitHistoryCount = nextCommitHistoryCount
    commitHistoryOrder = normalizeCommitHistoryOrder(state.commitHistoryOrder, nextGroups)
    evictGlobalCommitHistory()
    appendEventsByApp.clear()
    for (const [appId, events] of nextAppendEvents) appendEventsByApp.set(appId, events)
    suppressed.clear()
    for (const entry of Array.isArray(state.suppressed) ? state.suppressed : []) {
      if (!Array.isArray(entry) || entry.length !== 2) continue
      const composite = suppressionKey(entry[0], entry[1])
      if (composite) suppressed.add(composite)
    }
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
      namespace: group.namespace || null,
      createdAt: Number.isFinite(group.createdAt) ? group.createdAt : null
    }
  }

  // One entry per sweep batch: replaying it deletes the same ghosts, so a swept
  // slot can never resurrect from journal replay after a restart.
  function journalSweepEntry (appIds) {
    return {
      kind: 'sweep',
      appId: '*', // entry-level appId is unused for sweeps; batch rides in appIds
      appIds: [...appIds]
    }
  }

  function journalTakedownEntry (appId, key, drop) {
    return {
      kind: 'takedown',
      appId,
      key,
      drop: drop === true
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
    assertJournalMutationAllowed()
    const record = {
      version: OUTBOXLOG_JOURNAL_VERSION,
      seq: journalSeq + 1,
      ...entry
    }
    try {
      if (typeof operationJournal.needsCheckpointSync === 'function' && operationJournal.needsCheckpointSync(record)) {
        if (typeof operationJournal.checkpointSync !== 'function') throw new Error('OutboxLog: journal byte quota exceeded')
        operationJournal.checkpointSync(snapshot())
      }
      operationJournal.appendSync(record)
      journalSeq = record.seq
    } catch (err) {
      // A failed fsync/write/checkpoint can have landed any prefix, including a
      // committed manifest rename. Never concatenate another mutation in this
      // process; a clean restart re-reads disk topology and repairs a torn tail.
      fenceJournalWrite(err)
      throw err
    }
  }

  function loadJournal (afterSeq = 0) {
    const entries = operationJournal.loadSync()
    if (!entries) return
    if (!Array.isArray(entries)) throw fail('outboxlog journal must be an array', 500)
    if (entries.length === 0) return
    const firstSeq = entries[0] && entries[0].seq
    if (!Number.isSafeInteger(firstSeq) || firstSeq < 1 || firstSeq > afterSeq + 1) {
      throw fail('corrupt outboxlog journal entry ' + (afterSeq + 1), 500)
    }
    let expected = firstSeq
    for (const entry of entries) {
      const normalized = normalizeJournalEntry(entry, expected)
      if (!normalized) throw fail('corrupt outboxlog journal entry ' + expected, 500)
      // Entries at or below afterSeq are already reflected in the snapshot
      // checkpoint — sequence-check them (the file must still be coherent)
      // but do not re-apply.
      if (normalized.seq > afterSeq) applyJournalEntry(normalized)
      journalSeq = normalized.seq
      expected++
    }
  }

  function applyJournalEntry (entry) {
    if (entry.kind === 'sweep') {
      for (const appId of entry.appIds) deleteGroupState(appId)
      return
    }
    if (entry.appId.length > maxAppIdLength) throw fail('persisted outbox appId too long', 400)
    if (entry.kind === 'takedown') {
      const composite = suppressionKey(entry.appId, entry.key)
      if (!composite) return
      if (entry.drop) suppressed.add(composite)
      else suppressed.delete(composite)
      return
    }
    if (entry.kind === 'commit') {
      const prepared = prepareAtomicCommit(entry.appId, entry.commit, {
        inviteKey: entry.inviteKey,
        createdAt: entry.createdAt
      })
      if (prepared.duplicate) {
        if (stableAll(prepared.receipt) !== stableAll(entry.receipt)) throw fail('conflicting persisted commit receipt', 500)
        return
      }
      if (prepared.fingerprint !== entry.fingerprint || prepared.inviteKey !== entry.inviteKey) throw fail('corrupt persisted commit', 500)
      if (stableAll(prepared.receipt) !== stableAll(entry.receipt)) throw fail('corrupt persisted commit receipt', 500)
      prepared.receipt = clone(entry.receipt)
      applyPreparedCommit(prepared)
      return
    }
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
          commits: new Map(),
          commitTombstones: new Map(),
          version: 0,
          directorySeq: 0,
          namespace: entryNamespace,
          createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : null
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
        commits: new Map(),
        commitTombstones: new Map(),
        version: 0,
        directorySeq: 0,
        namespace: opNamespace,
        createdAt: null // unknown; irrelevant — the append below makes it non-ghost
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
    group.atomicCensus = null
    group.atomicCensusRoot = null
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

export function createMemoryOutboxJournal (initialEntries = [], { durableSync = false } = {}) {
  const entries = Array.isArray(initialEntries) ? clone(initialEntries) : []
  return {
    // In-memory storage is never process-durable. Tests that intentionally
    // model a synchronous durable journal must opt in explicitly.
    durableSync: durableSync === true,
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
      atomicWriteFileSync(path, JSON.stringify(snapshot))
    }
  }
}

export function createJsonlOutboxJournal (path, { maxBytes = DEFAULT_MAX_JOURNAL_BYTES, faultInjector = null } = {}) {
  if (typeof path !== 'string' || !path) throw new Error('OutboxLog: journal path required')
  const parent = dirname(path)
  const manifestPath = path + '.manifest.json'
  const ownership = acquireJsonlWriterOwnership(path)
  const journalByteLimit = positiveInteger(maxBytes, DEFAULT_MAX_JOURNAL_BYTES)
  let activeGeneration = 0
  let fallbackGeneration = null
  let selectedBaseGeneration = 0
  let selectedCheckpointState = null
  let loadPlanReady = false
  let ready = false
  let closeRequested = false
  let closed = false
  const injectFault = typeof faultInjector === 'function' ? faultInjector : null

  const journal = {
    kind: 'jsonl-fsync',
    path,
    durableSync: true,
    get ready () { return ready && !closeRequested && !closed },
    probeSync,
    loadCheckpointSync,
    checkpointSync,
    needsCheckpointSync (entry) {
      assertOpen()
      const file = journalGenerationPath(path, activeGeneration)
      const bytes = Buffer.byteLength(JSON.stringify(entry) + '\n')
      if (bytes > journalByteLimit) throw new Error('OutboxLog: journal entry exceeds byte quota')
      return fileSizeSync(file) + bytes > journalByteLimit
    },
    loadSync () {
      assertOpen()
      if (!loadPlanReady) loadCheckpointSync()
      const entries = []
      for (let generation = selectedBaseGeneration; generation <= activeGeneration; generation++) {
        const file = journalGenerationPath(path, generation)
        if (!existsSync(file)) throw new Error('OutboxLog: missing journal generation ' + generation)
        entries.push(...readJsonlGenerationSync(file, generation === activeGeneration))
      }
      return entries
    },
    appendSync (entry) {
      assertOpen()
      if (!ready) probeSync()
      try {
        const file = journalGenerationPath(path, activeGeneration)
        const line = Buffer.from(JSON.stringify(entry) + '\n', 'utf8')
        const currentBytes = fileSizeSync(file)
        if (line.byteLength > journalByteLimit || currentBytes + line.byteLength > journalByteLimit) {
          throw new Error('OutboxLog: journal byte quota exceeded')
        }
        appendFsyncedSync(file, line)
      } catch (err) {
        ready = false
        throw err
      }
    },
    flush () {
      assertOpen()
      try {
        if (!ready) probeSync()
        const file = journalGenerationPath(path, activeGeneration)
        const fd = openSync(file, 'r+')
        try {
          fsyncSync(fd)
        } finally {
          closeSync(fd)
        }
        fsyncDirectory(parent)
      } catch (err) {
        ready = false
        throw err
      }
    },
    markFailed () { ready = false },
    close () {
      if (closed) return
      closeRequested = true
      ready = false
      ownership.release()
      closed = true
    },
    paths () {
      return {
        lock: ownership.path,
        manifest: manifestPath,
        activeGeneration,
        fallbackGeneration,
        activeJournal: journalGenerationPath(path, activeGeneration),
        activeCheckpoint: checkpointGenerationPath(path, activeGeneration),
        fallbackJournal: fallbackGeneration == null ? null : journalGenerationPath(path, fallbackGeneration),
        fallbackCheckpoint: fallbackGeneration == null ? null : checkpointGenerationPath(path, fallbackGeneration)
      }
    }
  }

  try {
    probeSync()
    return journal
  } catch (err) {
    try { ownership.release() } catch {}
    throw err
  }

  function assertOpen () {
    if (closeRequested || closed) throw new Error('OutboxLog: journal is closed')
  }

  function fault (stage) {
    if (injectFault) injectFault(stage, { path, activeGeneration, fallbackGeneration })
  }

  function probeSync () {
    assertOpen()
    try {
      mkdirSync(parent, { recursive: true })
      refreshTopology()
      const file = journalGenerationPath(path, activeGeneration)
      const created = !existsSync(file)
      const fd = openSync(file, 'a+')
      try {
        // This is deliberately a real file fsync, not merely a successful open:
        // atomic-only readiness means the configured volume accepts the same
        // durability primitive used before receipts are returned.
        fsyncSync(fd)
      } finally {
        closeSync(fd)
      }
      if (created) fsyncDirectory(parent)
      else fsyncDirectory(parent) // readiness also probes directory fsync support
      ready = true
      return true
    } catch (err) {
      ready = false
      throw err
    }
  }

  function loadCheckpointSync () {
    assertOpen()
    refreshTopology()
    const active = readCheckpointGeneration(path, activeGeneration)
    if (active.ok) {
      selectedBaseGeneration = activeGeneration
      selectedCheckpointState = active.state
    } else {
      const fallback = fallbackGeneration == null
        ? { ok: false }
        : readCheckpointGeneration(path, fallbackGeneration)
      if (!fallback.ok) {
        throw new Error('OutboxLog: corrupt active checkpoint and no valid fallback')
      }
      selectedBaseGeneration = fallbackGeneration
      selectedCheckpointState = fallback.state
    }
    loadPlanReady = true
    return selectedCheckpointState ? clone(selectedCheckpointState) : null
  }

  function checkpointSync (snapshot) {
    assertOpen()
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new Error('OutboxLog: invalid checkpoint state')
    if (!Number.isSafeInteger(snapshot.journalSeq) || snapshot.journalSeq < 0) throw new Error('OutboxLog: invalid checkpoint sequence')
    const seq = snapshot.journalSeq
    refreshTopology()
    const nextGeneration = activeGeneration + 1
    const nextFallback = loadPlanReady && selectedBaseGeneration < activeGeneration
      ? selectedBaseGeneration
      : activeGeneration
    const state = clone(snapshot)
    const serializedState = JSON.stringify(state)
    const checkpoint = {
      version: OUTBOXLOG_CHECKPOINT_VERSION,
      generation: nextGeneration,
      seq,
      checksum: hashHex(serializedState),
      state
    }

    // Each file is individually fsynced + atomically renamed. The manifest is
    // the commit point: before it lands the old generation remains active;
    // afterwards the old generation is the complete fallback segment.
    try {
      fault('before-checkpoint-file')
      atomicWriteFileSync(checkpointGenerationPath(path, nextGeneration), JSON.stringify(checkpoint))
      fault('after-checkpoint-file')
      fault('before-journal-file')
      atomicWriteFileSync(journalGenerationPath(path, nextGeneration), '')
      fault('after-journal-file')
      fault('before-manifest-file')
      atomicWriteFileSync(manifestPath, JSON.stringify({
        version: OUTBOXLOG_JOURNAL_MANIFEST_VERSION,
        active: nextGeneration,
        fallback: nextFallback
      }), () => fault('manifest-after-rename-before-directory-fsync'))
      fault('after-manifest-file')

      fallbackGeneration = nextFallback
      activeGeneration = nextGeneration
      selectedBaseGeneration = activeGeneration
      selectedCheckpointState = state
      loadPlanReady = true
      ready = true
      fault('before-cleanup')
      cleanupOldJournalGenerations(path, fallbackGeneration, activeGeneration)
      fault('after-cleanup')
    } catch (err) {
      // The manifest rename/fsync may already be the durable commit point while
      // these in-memory generation fields still name the old file. Stay closed
      // to writes; only a new engine may refresh/reconcile the disk topology.
      ready = false
      throw err
    }
  }

  function refreshTopology () {
    const manifest = readJournalManifest(manifestPath)
    if (manifest && existsSync(journalGenerationPath(path, manifest.active))) {
      activeGeneration = manifest.active
      fallbackGeneration = manifest.fallback
      return
    }
    const generations = scanJournalGenerations(path)
    activeGeneration = generations.length ? generations[generations.length - 1] : 0
    fallbackGeneration = generations.length > 1 ? generations[generations.length - 2] : null
  }
}

function acquireJsonlWriterOwnership (path) {
  const parent = dirname(path)
  const lockPath = path + '.writer.lock'
  const host = hostname()
  const hostId = jsonlWriterHostId()
  const token = hex(32)
  const owner = { version: 2, hostname: host, hostId, pid: process.pid, token, createdAt: Date.now() }
  const candidate = lockPath + '.candidate-' + process.pid + '-' + token
  mkdirSync(parent, { recursive: true })
  const fd = openSync(candidate, 'wx', 0o600)
  try {
    writeAllSync(fd, Buffer.from(JSON.stringify(owner), 'utf8'))
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }

  let ownsLock = false
  try {
    // All owner acquisition, stale recovery, and release transitions take the
    // same create-exclusive gate. The gate is intentionally never reclaimed:
    // if a process dies in this tiny window, operator intervention is safer
    // than guessing and permitting two writers. The hostId comes from a
    // random per-user file in the OS-local tmpdir, not the potentially shared
    // journal volume, so equal hostnames on two machines are not trusted.
    const gate = acquireJsonlOwnershipGate(lockPath, owner)
    try {
      try {
        linkSync(candidate, lockPath)
        ownsLock = true
      } catch (err) {
        if (!err || err.code !== 'EEXIST') throw err
        const existing = readWriterOwner(lockPath)
        // Only reclaim when a cryptographic OS-local host instance matches and
        // that host's kernel says the pid is absent. Malformed, legacy, or
        // remote/shared-volume owners remain locked and require intervention.
        if (!existing || existing.hostId !== hostId || isProcessAlive(existing.pid)) {
          throw new Error('OutboxLog: journal already has an active or unverifiable writer owner')
        }
        unlinkSync(lockPath)
        fsyncDirectory(parent)
        linkSync(candidate, lockPath)
        ownsLock = true
      }
      fsyncDirectory(parent)
    } finally {
      gate.release()
    }
  } catch (err) {
    // If ownership linked but its directory fsync (or gate release) failed,
    // do not throw away the only release handle while leaving our lock behind.
    if (ownsLock) {
      try {
        const existing = readWriterOwner(lockPath)
        if (sameWriterOwner(existing, owner)) {
          unlinkSync(lockPath)
          fsyncDirectory(parent)
        }
      } catch {}
    }
    throw err
  } finally {
    try { unlinkSync(candidate) } catch {}
  }
  if (!ownsLock) throw new Error('OutboxLog: could not acquire exclusive journal writer ownership')

  let released = false
  return {
    path: lockPath,
    release () {
      if (released) return
      const gate = acquireJsonlOwnershipGate(lockPath, owner)
      try {
        const existing = readWriterOwner(lockPath)
        if (sameWriterOwner(existing, owner)) {
          unlinkSync(lockPath)
          fsyncDirectory(parent)
        }
      } finally {
        gate.release()
      }
      released = true
    }
  }
}

function acquireJsonlOwnershipGate (lockPath, owner) {
  const gatePath = lockPath + '.gate'
  const parent = dirname(lockPath)
  let fd = null
  let created = false
  try {
    fd = openSync(gatePath, 'wx', 0o600)
    created = true
    writeAllSync(fd, Buffer.from(JSON.stringify(owner), 'utf8'))
    fsyncSync(fd)
    closeSync(fd)
    fd = null
    fsyncDirectory(parent)
  } catch (err) {
    if (fd !== null) {
      try { closeSync(fd) } catch {}
    }
    if (created) {
      try { unlinkSync(gatePath) } catch {}
    }
    if (err && err.code === 'EEXIST') throw new Error('OutboxLog: journal ownership transition is active or unverifiable')
    throw err
  }

  let released = false
  return {
    release () {
      if (released) return
      unlinkSync(gatePath)
      fsyncDirectory(parent)
      released = true
    }
  }
}

let cachedJsonlWriterHostId = null

function jsonlWriterHostId () {
  if (cachedJsonlWriterHostId) return cachedJsonlWriterHostId
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'user'
  const identityPath = join(tmpdir(), '.hiverelay-outboxlog-host-' + uid + '.id')
  const token = hex(32)
  const candidate = identityPath + '.candidate-' + process.pid + '-' + token
  mkdirSync(dirname(identityPath), { recursive: true })
  const fd = openSync(candidate, 'wx', 0o600)
  try {
    writeAllSync(fd, Buffer.from(token, 'utf8'))
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  try {
    try {
      linkSync(candidate, identityPath)
      fsyncDirectory(dirname(identityPath))
    } catch (err) {
      if (!err || err.code !== 'EEXIST') throw err
    }
  } finally {
    try { unlinkSync(candidate) } catch {}
  }
  const hostId = readFileSync(identityPath, 'utf8').trim().toLowerCase()
  if (!isHex(hostId, 64)) throw new Error('OutboxLog: invalid local writer host identity')
  cachedJsonlWriterHostId = hostId
  return hostId
}

function readWriterOwner (path) {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    if (parsed.version !== 2 || typeof parsed.hostname !== 'string' || !parsed.hostname) return null
    if (!isHex(parsed.hostId, 64)) return null
    if (!Number.isSafeInteger(parsed.pid) || parsed.pid < 1 || !isHex(parsed.token, 64)) return null
    return parsed
  } catch {
    return null
  }
}

function sameWriterOwner (left, right) {
  return !!(
    left &&
    right &&
    left.version === right.version &&
    left.hostId === right.hostId &&
    left.pid === right.pid &&
    left.token === right.token
  )
}

function isProcessAlive (pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return !!(err && err.code !== 'ESRCH')
  }
}

function journalGenerationPath (path, generation) {
  return generation === 0 ? path : path + '.g' + generation + '.jsonl'
}

function checkpointGenerationPath (path, generation) {
  return path + '.g' + generation + '.checkpoint.json'
}

function scanJournalGenerations (path) {
  const parent = dirname(path)
  const name = basename(path)
  let names
  try {
    names = readdirSync(parent)
  } catch (err) {
    if (err && err.code === 'ENOENT') return []
    throw err
  }
  const generations = []
  if (names.includes(name)) generations.push(0)
  const pattern = new RegExp('^' + escapeRegExp(name) + '\\.g([0-9]+)\\.jsonl$')
  for (const entry of names) {
    const match = pattern.exec(entry)
    if (!match) continue
    const generation = Number(match[1])
    if (Number.isSafeInteger(generation) && generation > 0) generations.push(generation)
  }
  generations.sort((a, b) => a - b)
  return [...new Set(generations)]
}

function readJournalManifest (path) {
  let parsed
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'))
  } catch (err) {
    if (err && err.code === 'ENOENT') return null
    return null
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
  if (!sameStringArray(Object.keys(parsed).sort(), ['active', 'fallback', 'version'])) return null
  if (parsed.version !== OUTBOXLOG_JOURNAL_MANIFEST_VERSION) return null
  if (!Number.isSafeInteger(parsed.active) || parsed.active < 0) return null
  if (parsed.fallback !== null && (!Number.isSafeInteger(parsed.fallback) || parsed.fallback < 0 || parsed.fallback >= parsed.active)) return null
  return parsed
}

function readCheckpointGeneration (path, generation) {
  if (generation === 0 && !existsSync(checkpointGenerationPath(path, generation))) {
    return { ok: true, state: null, seq: 0 }
  }
  let parsed
  try {
    parsed = JSON.parse(readFileSync(checkpointGenerationPath(path, generation), 'utf8'))
  } catch {
    return { ok: false }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false }
  if (!sameStringArray(Object.keys(parsed).sort(), ['checksum', 'generation', 'seq', 'state', 'version'])) return { ok: false }
  if (parsed.version !== OUTBOXLOG_CHECKPOINT_VERSION || parsed.generation !== generation) return { ok: false }
  if (!Number.isSafeInteger(parsed.seq) || parsed.seq < 0) return { ok: false }
  if (!parsed.state || typeof parsed.state !== 'object' || Array.isArray(parsed.state)) return { ok: false }
  if (parsed.state.version !== OUTBOXLOG_STATE_VERSION || persistedJournalSeq(parsed.state) !== parsed.seq) return { ok: false }
  if (!Array.isArray(parsed.state.groups) || !isHex(parsed.checksum, 64)) return { ok: false }
  if (hashHex(JSON.stringify(parsed.state)) !== parsed.checksum) return { ok: false }
  return { ok: true, state: parsed.state, seq: parsed.seq }
}

function readJsonlGenerationSync (path, allowTornTail) {
  let text
  try {
    text = readFileSync(path, 'utf8')
  } catch (err) {
    if (err && err.code === 'ENOENT') throw new Error('OutboxLog: missing journal generation')
    throw err
  }
  if (!text) return []
  const lastNewline = text.lastIndexOf('\n')
  if (!text.endsWith('\n')) {
    if (!allowTornTail) throw new Error('OutboxLog: torn non-final journal generation')
    const safeLength = lastNewline < 0 ? 0 : Buffer.byteLength(text.slice(0, lastNewline + 1), 'utf8')
    truncateFsyncedSync(path, safeLength)
    text = lastNewline < 0 ? '' : text.slice(0, lastNewline + 1)
  }
  if (!text) return []
  const lines = text.slice(0, -1).split('\n')
  const entries = []
  for (const line of lines) {
    if (!line) throw new Error('OutboxLog: corrupt interior journal entry')
    try {
      entries.push(JSON.parse(line))
    } catch {
      throw new Error('OutboxLog: corrupt interior journal entry')
    }
  }
  return entries
}

function appendFsyncedSync (path, bytes) {
  const parent = dirname(path)
  mkdirSync(parent, { recursive: true })
  const created = !existsSync(path)
  const fd = openSync(path, 'a')
  try {
    writeAllSync(fd, bytes)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  if (created) fsyncDirectory(parent)
}

function truncateFsyncedSync (path, length) {
  truncateSync(path, length)
  const fd = openSync(path, 'r+')
  try {
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

function atomicWriteFileSync (path, value, afterRename = null) {
  const parent = dirname(path)
  mkdirSync(parent, { recursive: true })
  const tmp = path + '.tmp-' + process.pid + '-' + Date.now() + '-' + hex(4)
  const bytes = Buffer.from(String(value), 'utf8')
  let fd = null
  try {
    fd = openSync(tmp, 'wx', 0o600)
    writeAllSync(fd, bytes)
    fsyncSync(fd)
    closeSync(fd)
    fd = null
    renameSync(tmp, path)
    if (typeof afterRename === 'function') afterRename()
    fsyncDirectory(parent)
  } catch (err) {
    if (fd !== null) {
      try { closeSync(fd) } catch {}
    }
    try { unlinkSync(tmp) } catch {}
    throw err
  }
}

function writeAllSync (fd, bytes) {
  let offset = 0
  while (offset < bytes.byteLength) {
    const written = writeSync(fd, bytes, offset, bytes.byteLength - offset)
    if (written < 1) throw new Error('OutboxLog: write made no progress')
    offset += written
  }
}

function cleanupOldJournalGenerations (path, fallback, active) {
  const generations = scanJournalGenerations(path)
  let changed = false
  for (const generation of generations) {
    if (generation >= fallback && generation <= active) continue
    for (const file of [journalGenerationPath(path, generation), checkpointGenerationPath(path, generation)]) {
      try {
        unlinkSync(file)
        changed = true
      } catch (err) {
        if (!err || err.code !== 'ENOENT') throw err
      }
    }
  }
  if (changed) fsyncDirectory(dirname(path))
}

function fileSizeSync (path) {
  try {
    return statSync(path).size
  } catch (err) {
    if (err && err.code === 'ENOENT') return 0
    throw err
  }
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function fsyncDirectory (path) {
  const fd = openSync(path, 'r')
  try {
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

export function createOutboxNamespaceRegistry ({ namespace = DEFAULT_OUTBOXLOG_NAMESPACE, namespaces = null } = {}) {
  const entries = new Map()
  const explicitNamespace = typeof namespace === 'string' && namespace !== DEFAULT_OUTBOXLOG_NAMESPACE
  const explicitNamespaces = namespaces != null
  const configured = explicitNamespaces || explicitNamespace
  const source = namespaces && typeof namespaces === 'object' && !Array.isArray(namespaces)
    ? namespaces
    : { [namespace || DEFAULT_OUTBOXLOG_NAMESPACE]: { blind: false } }

  for (const [name, config] of Object.entries(source)) {
    const normalized = normalizeNamespaceEntry(name, config)
    entries.set(normalized.name, normalized)
  }

  // Only seed a default namespace when the caller configured NOTHING. When an
  // explicit `namespaces` map or an explicit `namespace` is supplied, the
  // registry admits exactly what was asked for — it no longer hard-injects a
  // house namespace ('peerit' historically, now the app-neutral default). This
  // is the last app-coupling removed: a Poked-only registry is Poked-only.
  if (!configured) {
    const defaultName = normalizeNamespaceName(namespace || DEFAULT_OUTBOXLOG_NAMESPACE)
    if (!entries.has(defaultName)) entries.set(defaultName, normalizeNamespaceEntry(defaultName, { blind: false }))
  }

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
  const algorithm = typeof data._alg === 'string' ? data._alg : ''
  const sigHex = typeof data._sig === 'string' ? data._sig : ''
  const namespaceRegistry = registry || createOutboxNamespaceRegistry({ namespace, namespaces })
  const namespaceInfo = namespaceRegistry.get(ns)

  if (!isHex(writer, 64) || !isHex(outboxWriter, 64) || writer !== outboxWriter) return false
  if (!isHex(driveKey, 64) || !isHex(sigHex, 128)) return false
  if (algorithm !== 'ed25519') return false
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
    .map(([key, value]) => ({ key, value: clone(value) }))
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

function persistedJournalSeq (state) {
  return state && Number.isSafeInteger(state.journalSeq) && state.journalSeq >= 0 ? state.journalSeq : 0
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
  // Takedown entries carry no inviteKey/op — just an opaque (appId,key) id and a
  // drop flag. Normalize them before the inviteKey requirement below.
  if (entry.kind === 'takedown') {
    if (typeof entry.key !== 'string' || !entry.key || entry.key.length > DEFAULT_MAX_ID_LENGTH + 65) return null
    return {
      version: entry.version,
      seq: entry.seq,
      kind: 'takedown',
      appId: entry.appId,
      key: entry.key,
      drop: entry.drop === true
    }
  }
  // Sweep entries carry no inviteKey/op — just the batch of ghost appIds whose
  // deletion must survive journal replay. Normalize before the inviteKey
  // requirement below (same pattern as takedown).
  if (entry.kind === 'sweep') {
    if (!Array.isArray(entry.appIds) || entry.appIds.length === 0) return null
    const appIds = []
    for (const id of entry.appIds) {
      if (typeof id !== 'string' || !id || id.length > DEFAULT_MAX_APP_ID_LENGTH) return null
      appIds.push(id)
    }
    return {
      version: entry.version,
      seq: entry.seq,
      kind: 'sweep',
      appId: '*',
      appIds
    }
  }
  if (typeof entry.inviteKey !== 'string' || entry.inviteKey.length !== 64) return null
  const namespace = normalizePersistedNamespace(entry.namespace)
  if (entry.kind === 'commit') {
    if (!namespace || !isHex(entry.fingerprint, 64)) return null
    if (!entry.commit || typeof entry.commit !== 'object' || Array.isArray(entry.commit) || entry.commit.schema !== 1) return null
    const receipt = normalizeCommitReceipt(entry.receipt, entry.appId, entry.commit.commitId, entry.inviteKey)
    if (!receipt) return null
    let size
    try {
      size = Buffer.byteLength(JSON.stringify(entry.commit))
    } catch {
      return null
    }
    if (size > OUTBOXLOG_MAX_REPLAY_COMMIT_BYTES) return null
    return {
      version: entry.version,
      seq: entry.seq,
      kind: 'commit',
      appId: entry.appId,
      inviteKey: entry.inviteKey,
      namespace,
      createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : null,
      fingerprint: entry.fingerprint,
      commit: clone(entry.commit),
      receipt
    }
  }
  if (entry.kind === 'create') {
    return {
      version: entry.version,
      seq: entry.seq,
      kind: 'create',
      appId: entry.appId,
      inviteKey: entry.inviteKey,
      namespace,
      // Optional since sweep shipped; legacy entries lack it (treated as
      // infinitely old by the sweep — every timestamp-less empty group predates
      // the client-side lazy-identity fix and is churn-era by definition).
      createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : null
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

function splitSuppressionKey (composite) {
  if (typeof composite !== 'string') return null
  const split = composite.indexOf('\x00')
  if (split < 0) return null
  return [composite.slice(0, split), composite.slice(split + 1)]
}

function normalizePersistedCommitReceipt (saved, appId, inviteKey) {
  if (!Array.isArray(saved) || saved.length !== 2 || !isHex(saved[0], 64)) return null
  const value = saved[1]
  if (!value || typeof value !== 'object' || !isHex(value.fingerprint, 64)) return null
  const receipt = normalizeCommitReceipt(value.receipt, appId, saved[0], inviteKey)
  return receipt ? [saved[0], { fingerprint: value.fingerprint, receipt }] : null
}

function normalizeCommitReceipt (receipt, appId, commitId, inviteKey) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return null
  if (receipt.ok !== true || receipt.durable !== true) return null
  if (receipt.appId !== appId || receipt.commitId !== commitId || receipt.inviteKey !== inviteKey || !isHex(inviteKey, 64)) return null
  if (!Number.isSafeInteger(receipt.relayVersion) || receipt.relayVersion < 1) return null
  const head = receipt.head
  if (!head || typeof head !== 'object' || Array.isArray(head)) return null
  if (!Number.isSafeInteger(head.version) || head.version < 1 || !Number.isSafeInteger(head.count) || head.count < 0 || !isHex(head.root, 64)) return null
  return {
    ok: true,
    durable: true,
    commitId,
    appId,
    inviteKey,
    head: { version: head.version, count: head.count, root: head.root },
    relayVersion: receipt.relayVersion
  }
}

function sameStringArray (left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) {
    if (typeof left[i] !== 'string' || left[i] !== right[i]) return false
  }
  return true
}

function assertExactObjectFields (value, expected, message) {
  const keys = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (!sameStringArray(keys, wanted)) throw fail(message, 400)
}

function assertCommitWrapperFields (value, message) {
  const keys = Object.keys(value).sort()
  const allowed = new Set(['type', 'data', 'timestamp'])
  if (!keys.includes('type') || !keys.includes('data') || keys.some(key => !allowed.has(key))) throw fail(message, 400)
  if (value.timestamp !== undefined && (typeof value.timestamp !== 'string' || value.timestamp.length > 128)) throw fail(message, 400)
}

function hashHex (value) {
  return createHash('sha256').update(String(value), 'utf8').digest('hex')
}

function stableAll (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value)
  if (Array.isArray(value)) return '[' + value.map(stableAll).join(',') + ']'
  const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableAll(value[key])).join(',') + '}'
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
