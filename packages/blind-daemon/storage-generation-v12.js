import b4a from 'b4a'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import { link, lstat, open, readdir, realpath, rename, unlink } from 'node:fs/promises'
import path from 'node:path'
import { blake2b256 } from '@hiverelay/blind-protocol'

export const BLIND_STORE_GENERATION = Object.freeze({
  schema: 'hiverelay-blind-installation-generation-record-v2',
  headSchema: 'hiverelay-blind-installation-generation-head-v2',
  formatVersion: '1.2',
  legacyFormatVersion: '1.1',
  scope: 'installation',
  headFile: 'blind-store-generation-head-v2.json'
})

export const BLIND_STORE_READER_MODE = Object.freeze({ BLIND_ONLY: 'blind-only' })
export const BLIND_STORE_GENERATION_CAPABILITIES = Object.freeze({
  authorityScope: 'installation',
  triggerKinds: Object.freeze(['blind-only-write', 'hc11-only-write']),
  storeRoles: Object.freeze(['cell', 'inbox', 'core', 'hc11']),
  supportedReaderModes: Object.freeze([BLIND_STORE_READER_MODE.BLIND_ONLY]),
  dualReadRollbackImplemented: false,
  postTriggerLegacyOnlyRollbackAllowed: false,
  runtimeWriterExclusion: 'exclusive-writer-lock-plus-wal-fence-for-cooperating-v2-writers',
  targetLegacyRuntimeRestartFence: 'd40-v1-floor-missing-after-v2-installation-authority',
  targetLegacyRuntimeRestartFenceImplemented: true,
  permanentArbitraryLegacyWriterFenceImplemented: false,
  externalOldWriterLeaseProofRequired: true,
  crossRuntimeBlindHc11AuthorityImplemented: false,
  hc11RoleIsUnassembledContractSeam: true,
  preFloorOpenMutationInvariantImplemented: false,
  irreversibleHistorySurvivesGcCompactionImplemented: false,
  acknowledgmentFailureWriterQuarantineImplemented: false,
  rc9BlindProductionMustRemainDisabled: true,
  rc9BlindProductionBlocker: 'pre-floor open may mutate or erase evidence; cumulative blind-plus-hc11 authority is unassembled',
  predecessorEvidencePolicy: 'v1-requires-reviewed-offline-migration'
})

const RECORD = /^blind-store-generation-record-([0-9]{16})-v2\.json$/
const TEMP = /^\.blind-store-generation-(?:record|head)\.tmp-[0-9a-f]{32}$/
const PREDECESSOR = /^(blind-store-generation-head-v1\.json|blind-store-generation-record-[0-9]{16}-v1\.json)$/
const GENERATION_NAMESPACE = /^\.?blind-store-generation-/
const ROLE_ORDER = Object.freeze(['cell', 'inbox', 'core', 'hc11'])
const TRIGGER_KIND = Object.freeze({
  cell: 'blind-only-write',
  inbox: 'blind-only-write',
  core: 'blind-only-write',
  hc11: 'hc11-only-write'
})
const MAX_SIGNED_AUTHORITY_BYTES = 1024 * 1024

export async function openBlindStoreGenerationFloor (controlDirectory, options = {}) {
  if (typeof controlDirectory !== 'string' || controlDirectory.length === 0) {
    throw new TypeError('controlDirectory must be a non-empty string')
  }
  const manifestKey = asBytes(options.manifestKey, 'manifestKey', 32)
  const installationIdentity = options.installationIdentity == null
    ? options.storeIdentity
    : options.installationIdentity
  const installationIdentityHash = hashHex(asBytes(
    installationIdentity, 'installationIdentity'))
  const currentStores = normalizeCurrentStores(options)
  await assertPrivateControlDirectory(controlDirectory)
  const initialNames = await readdir(controlDirectory)
  await validateGenerationNames(initialNames)

  let records = await loadRecords()
  if (records.length === 0) {
    if (initialNames.includes(BLIND_STORE_GENERATION.headFile)) {
      throw new Error('blind store generation head exists without a valid record chain')
    }
    if (options.allowCreate !== true) throw new Error('blind store generation evidence is missing')
    assertCreationProof(options.creationProof, currentStores)
    const initial = record(0, false, null, null, [])
    await appendRecord(initial)
    records = [initial]
  }
  validateChain(records)
  let latest = records.at(-1)
  const headPath = path.join(controlDirectory, BLIND_STORE_GENERATION.headFile)
  const head = await readSignedOptional(headPath, 'generation head')
  if (head === null) {
    await writeHead(latest)
  } else {
    validateHead(head)
    if (head.sequence > latest.sequence) throw new Error('invalid blind store generation head')
    if (head.recordHash !== recordHash(records[head.sequence])) {
      throw new Error('invalid blind store generation head')
    }
    if (head.sequence < latest.sequence) await writeHead(latest)
  }
  if (latest.installationIdentityHash !== installationIdentityHash) {
    throw new Error('blind store generation evidence belongs to another installation')
  }

  let registrations = registrationMap(records)
  for (const current of currentStores) {
    const registered = registrations.get(current.role)
    if (registered && registered.storeIdentityHash !== current.storeIdentityHash) {
      throw new Error(`blind store generation ${current.role} evidence belongs to another store`)
    }
    if (!registered) {
      if (latest.firstIrreversibleWriteAcknowledged) {
        throw new Error('a post-trigger installation cannot add an unregistered store role')
      }
      const next = record(latest.sequence + 1, false, recordHash(latest), null, [{
        role: current.role,
        storeIdentityHash: current.storeIdentityHash,
        storeEvidence: current.storeEvidence
      }])
      await appendRecord(next)
      records.push(next)
      latest = next
      registrations = registrationMap(records)
    }
  }

  let acknowledged = latest.firstIrreversibleWriteAcknowledged
  let trigger = latest.trigger
  if (acknowledged) validatePostTriggerStores(trigger, currentStores, registrations)
  if (!acknowledged) {
    for (const current of currentStores) {
      const baseline = registrations.get(current.role)
      assertEvidenceNotRolledBack(baseline.storeEvidence, current.storeEvidence,
        `blind store generation ${current.role} evidence`)
    }
    const recoveredTrigger = currentStores
      .filter(current => current.hasIrreversibleState)
      .sort(compareStores)[0]
    if (recoveredTrigger) {
      const next = record(latest.sequence + 1, true, recordHash(latest), {
        kind: TRIGGER_KIND[recoveredTrigger.role],
        role: recoveredTrigger.role,
        storeIdentityHash: recoveredTrigger.storeIdentityHash,
        storeEvidence: recoveredTrigger.storeEvidence,
        recoveryConservative: true
      }, [])
      await appendRecord(next)
      records.push(next)
      latest = next
      acknowledged = true
      trigger = next.trigger
    } else {
      const changed = currentStores.filter(current => {
        const baseline = registrations.get(current.role).storeEvidence
        return evidenceCompare(current.storeEvidence, baseline) > 0
      })
      if (changed.length > 0) {
        const registrationUpdates = changed.map(current => ({
          role: current.role,
          storeIdentityHash: current.storeIdentityHash,
          storeEvidence: current.storeEvidence
        }))
        const next = record(latest.sequence + 1, false, recordHash(latest), null, registrationUpdates)
        await appendRecord(next)
        records.push(next)
        latest = next
        registrations = registrationMap(records)
      }
    }
  }

  const pendingAcknowledgments = []
  let acknowledgmentDrain = null

  return {
    get firstBlindOnlyWriteAcknowledged () { return acknowledged },
    get firstIrreversibleWriteAcknowledged () { return acknowledged },
    get trigger () { return trigger == null ? null : publicTrigger(trigger, latest) },
    get capabilities () { return BLIND_STORE_GENERATION_CAPABILITIES },
    assertReaderMode (mode) {
      if (mode !== BLIND_STORE_READER_MODE.BLIND_ONLY) {
        throw new Error('only blind-only reader mode is implemented; dual-read rollback belongs to a separately verified compatibility target')
      }
      return true
    },
    acknowledgeBlindOnlyWrite (storeEvidence) {
      const current = currentStores.find(store => store.role === 'cell') || currentStores[0]
      return queueAcknowledgment({
        kind: TRIGGER_KIND[current.role],
        role: current.role,
        storeIdentityHash: current.storeIdentityHash,
        storeEvidence: evidence(storeEvidence),
        recoveryConservative: false
      })
    },
    acknowledgeWrite (input) {
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new TypeError('write acknowledgment must be an object')
      }
      const role = storeRole(input.role)
      const current = currentStores.find(store => store.role === role)
      if (!current) throw new Error(`write acknowledgment role ${role} is not registered in this runtime`)
      const kind = input.kind == null ? TRIGGER_KIND[role] : input.kind
      if (kind !== TRIGGER_KIND[role]) throw new Error(`write acknowledgment kind does not match ${role}`)
      if (input.storeIdentity != null &&
          roleStoreIdentityHash(role, asBytes(input.storeIdentity, 'storeIdentity')) !== current.storeIdentityHash) {
        throw new Error('write acknowledgment belongs to another store')
      }
      return queueAcknowledgment({
        kind,
        role,
        storeIdentityHash: current.storeIdentityHash,
        storeEvidence: evidence(input.storeEvidence),
        recoveryConservative: false
      })
    },
    triggerReceipt () {
      if (!acknowledged || !trigger) return null
      return Object.freeze({
        schema: 'hiverelay-blind-generation-trigger-receipt-v1',
        authorityScope: BLIND_STORE_GENERATION.scope,
        generationSequence: latest.sequence,
        triggerKind: trigger.kind,
        storeRole: trigger.role,
        storeIdentityHash: trigger.storeIdentityHash,
        walSequence: trigger.storeEvidence.walSequence,
        walHash: trigger.storeEvidence.walHash,
        recordSha256: signedRecordHash(latest),
        migrationRecordCompatible: false,
        crossRuntimeBlindHc11AuthorityImplemented: false,
        migrationBoundary: 'consumer migration tooling must bind this receipt digest and independently prove dual-read rollback, cross-runtime HC11 coordination, and external old-writer fencing'
      })
    }
  }

  function queueAcknowledgment (candidate) {
    if (acknowledged) return Promise.resolve(false)
    const operation = new Promise((resolve, reject) => {
      pendingAcknowledgments.push({ candidate, resolve, reject })
    })
    if (acknowledgmentDrain === null) acknowledgmentDrain = Promise.resolve().then(drainAcknowledgments)
    return operation
  }

  async function drainAcknowledgments () {
    const batch = pendingAcknowledgments.splice(0)
    try {
      const diskRecords = await loadRecords()
      validateChain(diskRecords)
      if (diskRecords.at(-1).sequence > latest.sequence) {
        latest = diskRecords.at(-1)
        records = diskRecords
        registrations = registrationMap(records)
        acknowledged = latest.firstIrreversibleWriteAcknowledged
        trigger = latest.trigger
        await writeHead(latest)
      }
      if (acknowledged) {
        for (const item of batch) item.resolve(false)
        return
      }
      for (const item of batch) validateCandidate(item.candidate)
      const selected = batch.map(item => item.candidate).sort(compareTriggers)[0]
      const next = record(latest.sequence + 1, true, recordHash(latest), selected, [])
      await writeExclusive(recordPath(next.sequence), signed(next))
      records.push(next)
      latest = next
      acknowledged = true
      trigger = selected
      if (options.faultInjector) await options.faultInjector('after-record-sync')
      await writeHead(next)
      for (const item of batch) item.resolve(true)
    } catch (error) {
      for (const item of batch) {
        if (acknowledged) item.resolve(true)
        else item.reject(error)
      }
    } finally {
      acknowledgmentDrain = null
      if (pendingAcknowledgments.length > 0) {
        if (acknowledged) {
          for (const item of pendingAcknowledgments.splice(0)) item.resolve(false)
        } else {
          acknowledgmentDrain = Promise.resolve().then(drainAcknowledgments)
        }
      }
    }
  }

  function validateCandidate (candidate) {
    const registered = registrations.get(candidate.role)
    if (!registered || registered.storeIdentityHash !== candidate.storeIdentityHash) {
      throw new Error('write acknowledgment store role or identity is not registered')
    }
    if (evidenceCompare(candidate.storeEvidence, registered.storeEvidence) <= 0) {
      throw new Error('write acknowledgment must bind a newer durable WAL write')
    }
  }

  function record (sequence, value, previousRecordHash, trigger, registrationUpdates) {
    return {
      schema: BLIND_STORE_GENERATION.schema,
      formatVersion: BLIND_STORE_GENERATION.formatVersion,
      scope: BLIND_STORE_GENERATION.scope,
      installationIdentityHash,
      sequence,
      previousRecordHash,
      firstIrreversibleWriteAcknowledged: value,
      trigger,
      registrationUpdates
    }
  }

  function recordPath (sequence) {
    return path.join(controlDirectory,
      `blind-store-generation-record-${String(sequence).padStart(16, '0')}-v2.json`)
  }

  async function loadRecords () {
    const allNames = await readdir(controlDirectory)
    await validateGenerationNames(allNames)
    const names = allNames.filter(name => RECORD.test(name)).sort()
    const output = []
    for (let index = 0; index < names.length; index++) {
      const name = names[index]
      const filenameSequence = Number(RECORD.exec(name)[1])
      if (!Number.isSafeInteger(filenameSequence) || filenameSequence !== index) {
        throw new Error('blind store generation record filenames must be contiguous from zero')
      }
      const body = await readSigned(path.join(controlDirectory, name), 'generation record')
      if (body.sequence !== filenameSequence) {
        throw new Error('blind store generation record filename does not match its signed sequence')
      }
      output.push(body)
    }
    return output
  }

  async function validateGenerationNames (names) {
    if (names.some(name => PREDECESSOR.test(name))) {
      throw new Error('per-root v1 generation evidence requires a reviewed offline migration to installation-scoped v2')
    }
    for (const name of names) {
      if (GENERATION_NAMESPACE.test(name) && name !== BLIND_STORE_GENERATION.headFile &&
          !RECORD.test(name) && !TEMP.test(name)) {
        throw new Error(`malformed blind store generation namespace entry: ${name}`)
      }
      if (!TEMP.test(name)) continue
      const state = await lstat(path.join(controlDirectory, name))
      const uid = typeof process.getuid === 'function' ? process.getuid() : null
      if (!state.isFile() || state.isSymbolicLink() || (state.mode & 0o777) !== 0o600 ||
          (uid != null && state.uid !== uid)) {
        throw new Error(`unsafe blind store generation temporary: ${name}`)
      }
    }
  }

  async function readAuthorityFile (file, label) {
    let before = await lstat(file)
    if (before.nlink === 2 && RECORD.test(path.basename(file))) {
      const matching = []
      for (const name of await readdir(controlDirectory)) {
        if (!/^\.blind-store-generation-record\.tmp-[0-9a-f]{32}$/.test(name)) continue
        const temporary = path.join(controlDirectory, name)
        const state = await lstat(temporary)
        if (state.dev === before.dev && state.ino === before.ino) matching.push(temporary)
      }
      if (matching.length !== 1) throw new Error(`invalid blind store ${label}`)
      await unlink(matching[0])
      await syncDirectory()
      before = await lstat(file)
    }
    const uid = typeof process.getuid === 'function' ? process.getuid() : null
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 ||
        (before.mode & 0o777) !== 0o600 || (uid != null && before.uid !== uid) ||
        before.size < 2 || before.size > MAX_SIGNED_AUTHORITY_BYTES) {
      throw new Error(`invalid blind store ${label}`)
    }
    const handle = await open(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
    const bytes = b4a.allocUnsafe(before.size)
    try {
      const opened = await handle.stat()
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
        throw new Error(`invalid blind store ${label}`)
      }
      let offset = 0
      while (offset < bytes.byteLength) {
        const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset)
        if (bytesRead === 0) throw new Error(`invalid blind store ${label}`)
        offset += bytesRead
      }
      const after = await handle.stat()
      if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
        throw new Error(`invalid blind store ${label}`)
      }
    } finally {
      await handle.close()
    }
    return bytes
  }

  async function readSigned (file, label) {
    let raw
    let value
    try {
      raw = await readAuthorityFile(file, label)
      value = JSON.parse(raw.toString('utf8'))
    } catch (error) {
      if (error.code === 'ENOENT') {
        const missing = new Error(`blind store ${label} is missing`)
        missing.code = 'BLIND_STORE_GENERATION_MISSING'
        throw missing
      }
      throw new Error(`invalid blind store ${label}`)
    }
    if (!validMac(value, manifestKey)) throw new Error(`invalid blind store ${label}`)
    const body = { ...value }
    delete body.mac
    if (!b4a.equals(raw, canonicalBytes(signed(body)))) {
      throw new Error(`invalid blind store ${label}: signed bytes are not canonical`)
    }
    return body
  }

  async function readSignedOptional (file, label) {
    try {
      return await readSigned(file, label)
    } catch (error) {
      if (error.code === 'BLIND_STORE_GENERATION_MISSING') return null
      throw error
    }
  }

  function validateHead (value) {
    if (!exactKeys(value, ['installationIdentityHash', 'recordHash', 'schema', 'sequence']) ||
        value.schema !== BLIND_STORE_GENERATION.headSchema ||
        value.installationIdentityHash !== installationIdentityHash ||
        !Number.isSafeInteger(value.sequence) || value.sequence < 0 ||
        typeof value.recordHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.recordHash)) {
      throw new Error('invalid blind store generation head')
    }
  }

  function validateChain (values) {
    for (let index = 0; index < values.length; index++) {
      const value = values[index]
      if (!exactKeys(value, [
        'firstIrreversibleWriteAcknowledged',
        'formatVersion',
        'installationIdentityHash',
        'previousRecordHash',
        'registrationUpdates',
        'schema',
        'scope',
        'sequence',
        'trigger'
      ]) || value.schema !== BLIND_STORE_GENERATION.schema ||
          value.formatVersion !== BLIND_STORE_GENERATION.formatVersion ||
          value.scope !== BLIND_STORE_GENERATION.scope ||
          !Number.isSafeInteger(value.sequence) || value.sequence !== index ||
          value.installationIdentityHash !== installationIdentityHash ||
          value.previousRecordHash !== (index === 0 ? null : recordHash(values[index - 1])) ||
          typeof value.firstIrreversibleWriteAcknowledged !== 'boolean' ||
          !Array.isArray(value.registrationUpdates) ||
          (index > 0 && values[index - 1].firstIrreversibleWriteAcknowledged &&
            !value.firstIrreversibleWriteAcknowledged) ||
          (value.firstIrreversibleWriteAcknowledged !== (value.trigger != null))) {
        throw new Error('invalid blind store generation evidence chain')
      }
      if (new Set(value.registrationUpdates.map(update => update?.role)).size !== value.registrationUpdates.length) {
        throw new Error('invalid blind store generation evidence chain')
      }
      for (const update of value.registrationUpdates) normalizeRegistration(update)
      if (value.trigger != null) normalizeTrigger(value.trigger)
      if (value.trigger != null && index > 0 && values[index - 1].firstIrreversibleWriteAcknowledged &&
          !b4a.equals(canonicalBytes(value.trigger), canonicalBytes(values[index - 1].trigger))) {
        throw new Error('invalid blind store generation evidence chain')
      }
    }
  }

  async function appendRecord (value) {
    await writeExclusive(recordPath(value.sequence), signed(value))
    await writeHead(value)
  }

  async function writeHead (value) {
    const body = {
      schema: BLIND_STORE_GENERATION.headSchema,
      installationIdentityHash,
      sequence: value.sequence,
      recordHash: recordHash(value)
    }
    await writeAtomic(path.join(controlDirectory, BLIND_STORE_GENERATION.headFile), signed(body))
  }

  async function writeExclusive (file, value) {
    const temporary = temporaryPath('record')
    const bytes = canonicalBytes(value)
    const handle = await open(temporary, 'wx', 0o600)
    try {
      const split = Math.max(1, Math.floor(bytes.byteLength / 2))
      await writeAll(handle, bytes.subarray(0, split))
      if (options.faultInjector) {
        await options.faultInjector('after-record-temp-partial', { sequence: value.sequence })
      }
      await writeAll(handle, bytes.subarray(split))
      await handle.sync()
    } finally {
      await handle.close()
    }
    if (options.faultInjector) {
      await options.faultInjector('after-record-temp-sync', { sequence: value.sequence })
    }
    try {
      await link(temporary, file)
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
      const existing = await readAuthorityFile(file, 'generation record')
      if (!b4a.equals(existing, bytes)) throw new Error('conflicting blind store generation record already exists')
    }
    await syncDirectory()
    if (options.faultInjector) {
      await options.faultInjector('after-record-link', { sequence: value.sequence })
    }
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error })
    await syncDirectory()
  }

  async function writeAtomic (file, value) {
    const temporary = temporaryPath('head')
    const handle = await open(temporary, 'wx', 0o600)
    try {
      await handle.writeFile(canonicalBytes(value))
      await handle.sync()
    } finally {
      await handle.close()
    }
    if (options.faultInjector) await options.faultInjector('after-head-temp-sync', { sequence: value.sequence })
    await rename(temporary, file)
    await syncDirectory()
    if (options.faultInjector) await options.faultInjector('after-head-rename', { sequence: value.sequence })
  }

  function temporaryPath (kind) {
    return path.join(controlDirectory,
      `.blind-store-generation-${kind}.tmp-${randomBytes(16).toString('hex')}`)
  }

  async function writeAll (handle, bytes) {
    let offset = 0
    while (offset < bytes.byteLength) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.byteLength - offset, null)
      if (bytesWritten === 0) throw new Error('blind store generation temporary write made no progress')
      offset += bytesWritten
    }
  }

  async function syncDirectory () {
    const directory = await open(controlDirectory, 'r')
    try { await directory.sync() } finally { await directory.close() }
  }

  function signed (body) { return { ...body, mac: mac(body, manifestKey) } }
  function signedRecordHash (value) { return createHash('sha256').update(canonicalBytes(signed(value))).digest('hex') }
}

function assertCreationProof (value, currentStores) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('generation evidence creation requires an explicit pristine-store proof')
  }
  const fresh = value.freshStoreBindingCreated === true
  const genesis = value.sealedGenesisValidated === true
  if (fresh === genesis || Object.keys(value).some(key => !['freshStoreBindingCreated', 'sealedGenesisValidated'].includes(key))) {
    throw new Error('generation evidence creation requires exactly one accepted pristine-store proof')
  }
  if (currentStores.some(store => store.hasIrreversibleState)) {
    throw new Error('generation evidence cannot be created over irreversible store state')
  }
}

function normalizeCurrentStores (options) {
  const inputs = options.currentStores == null
    ? [{
        role: options.storeRole || 'cell',
        storeIdentity: options.storeIdentity,
        storeEvidence: options.storeEvidence,
        hasIrreversibleState: options.hasIrreversibleState === true
      }]
    : options.currentStores
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > ROLE_ORDER.length) {
    throw new TypeError('currentStores must contain 1..4 store descriptors')
  }
  const stores = inputs.map(input => {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new TypeError('currentStores entries must be objects')
    }
    const role = storeRole(input.role)
    if (input.hasIrreversibleState != null && typeof input.hasIrreversibleState !== 'boolean') {
      throw new TypeError('hasIrreversibleState must be boolean')
    }
    return {
      role,
      storeIdentityHash: roleStoreIdentityHash(role, asBytes(input.storeIdentity, 'storeIdentity')),
      storeEvidence: evidence(input.storeEvidence),
      hasIrreversibleState: input.hasIrreversibleState === true
    }
  }).sort(compareStores)
  if (new Set(stores.map(store => store.role)).size !== stores.length) {
    throw new TypeError('currentStores roles must be unique')
  }
  return stores
}

function normalizeRegistration (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !exactKeys(value, ['role', 'storeEvidence', 'storeIdentityHash'])) {
    throw new Error('invalid store registration')
  }
  normalizeStoreBinding(value, 'store registration')
  return value
}

function normalizeStoreBinding (value, label) {
  storeRole(value.role)
  if (typeof value.storeIdentityHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.storeIdentityHash)) {
    throw new Error(`invalid ${label}`)
  }
  evidenceFromDisk(value.storeEvidence)
}

function normalizeTrigger (value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !exactKeys(value, ['kind', 'recoveryConservative', 'role', 'storeEvidence', 'storeIdentityHash'])) {
    throw new Error('invalid generation trigger')
  }
  normalizeStoreBinding(value, 'generation trigger')
  if (value.kind !== TRIGGER_KIND[value.role] || typeof value.recoveryConservative !== 'boolean') {
    throw new Error('invalid generation trigger')
  }
  return value
}

function registrationMap (records) {
  const registrations = new Map()
  for (const value of records) {
    for (const update of value.registrationUpdates) {
      normalizeRegistration(update)
      const prior = registrations.get(update.role)
      if (prior && prior.storeIdentityHash !== update.storeIdentityHash) {
        throw new Error('store registration identity changed')
      }
      if (prior) assertEvidenceNotRolledBack(prior.storeEvidence, update.storeEvidence, 'store registration')
      registrations.set(update.role, update)
    }
  }
  return registrations
}

function validatePostTriggerStores (trigger, currentStores, registrations) {
  normalizeTrigger(trigger)
  if (currentStores.length !== registrations.size ||
      currentStores.some(store => !registrations.has(store.role))) {
    throw new Error('post-trigger restart must present every registered store role')
  }
  for (const currentStore of currentStores) {
    const registered = registrations.get(currentStore.role)
    if (registered.storeIdentityHash !== currentStore.storeIdentityHash) {
      throw new Error(`registered ${currentStore.role} store identity changed`)
    }
    assertEvidenceNotRolledBack(registered.storeEvidence, currentStore.storeEvidence,
      `registered ${currentStore.role} store evidence`)
  }
  const current = currentStores.find(store => store.role === trigger.role)
  if (!current) throw new Error(`trigger store role ${trigger.role} is unavailable`)
  if (current.storeIdentityHash !== trigger.storeIdentityHash) {
    throw new Error('trigger store identity changed')
  }
  assertEvidenceNotRolledBack(trigger.storeEvidence, current.storeEvidence, 'trigger store evidence')
}

function assertEvidenceNotRolledBack (prior, current, label) {
  const comparison = evidenceCompare(current, prior)
  if (comparison < 0 || (comparison === 0 && current.walHash !== prior.walHash)) {
    throw new Error(`${label} was rolled back or replayed`)
  }
}

function evidenceCompare (left, right) {
  const leftSequence = BigInt(left.walSequence)
  const rightSequence = BigInt(right.walSequence)
  return leftSequence < rightSequence ? -1 : leftSequence > rightSequence ? 1 : 0
}

function evidence (value) {
  if (!value || typeof value.walSequence !== 'bigint' || value.walSequence < 0n) {
    throw new TypeError('storeEvidence.walSequence must be a non-negative bigint')
  }
  return {
    walSequence: value.walSequence.toString(),
    walHash: hashHex(asBytes(value.walHash, 'storeEvidence.walHash', 32))
  }
}

function evidenceFromDisk (value) {
  if (!value || !exactKeys(value, ['walHash', 'walSequence']) ||
      typeof value.walSequence !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value.walSequence) ||
      typeof value.walHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.walHash)) {
    throw new Error('invalid durable WAL evidence')
  }
  return value
}

function storeRole (value) {
  if (!ROLE_ORDER.includes(value)) throw new TypeError('store role must be cell, inbox, core, or hc11')
  return value
}

function roleStoreIdentityHash (role, value) {
  return hashHex(b4a.concat([
    b4a.from('hiverelay.blind.installation-store-role.v1', 'ascii'),
    b4a.from([ROLE_ORDER.indexOf(role) + 1]),
    value
  ]))
}

function compareStores (left, right) {
  return ROLE_ORDER.indexOf(left.role) - ROLE_ORDER.indexOf(right.role)
}

function compareTriggers (left, right) {
  return compareStores(left, right) ||
    evidenceCompare(left.storeEvidence, right.storeEvidence) ||
    codeUnitCompare(left.storeEvidence.walHash, right.storeEvidence.walHash)
}

function codeUnitCompare (left, right) { return left < right ? -1 : left > right ? 1 : 0 }

function publicTrigger (trigger, record) {
  return Object.freeze({
    kind: trigger.kind,
    role: trigger.role,
    storeIdentityHash: trigger.storeIdentityHash,
    walSequence: BigInt(trigger.storeEvidence.walSequence),
    walHash: trigger.storeEvidence.walHash,
    recoveryConservative: trigger.recoveryConservative,
    generationSequence: record.sequence,
    recordHash: recordHash(record)
  })
}

function recordHash (value) { return hashHex(canonicalBytes(value)) }
function hashHex (value) { return b4a.toString(blake2b256(value), 'hex') }
function mac (body, key) { return createHmac('sha256', key).update(canonicalBytes(body)).digest('hex') }

function validMac (value, key) {
  if (!value || typeof value.mac !== 'string' || !/^[0-9a-f]{64}$/.test(value.mac)) return false
  const body = { ...value }
  delete body.mac
  return timingSafeEqual(b4a.from(value.mac, 'hex'), b4a.from(mac(body, key), 'hex'))
}

function canonicalBytes (value) {
  return b4a.from(JSON.stringify(stableValue(value)) + '\n', 'utf8')
}

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort(codeUnitCompare).map(key => [key, stableValue(value[key])]))
}

function exactKeys (value, expected) {
  return value != null && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort(codeUnitCompare)) === JSON.stringify([...expected].sort(codeUnitCompare))
}

async function assertPrivateControlDirectory (directory) {
  const absolute = path.resolve(directory)
  const resolved = await realpath(directory)
  const state = await lstat(directory)
  const uid = typeof process.getuid === 'function' ? process.getuid() : null
  if (directory !== absolute || resolved !== absolute || !state.isDirectory() || state.isSymbolicLink() ||
      (state.mode & 0o077) !== 0 || (uid != null && state.uid !== uid)) {
    throw new Error('blind store generation control directory must be canonical, private, owner-controlled, and non-symlinked')
  }
}

function asBytes (value, label, length = null) {
  if (!b4a.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError(`${label} must be bytes`)
  const bytes = b4a.from(value)
  if (length != null && bytes.byteLength !== length) throw new TypeError(`${label} must be ${length} bytes`)
  return bytes
}
