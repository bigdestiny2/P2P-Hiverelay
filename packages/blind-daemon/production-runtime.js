import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHmac, timingSafeEqual } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  DISPATCH_LIMITS,
  HEALTH_CLOCK_STATE,
  HEALTH_INTEGRITY_STATE,
  HEALTH_REBALANCE_STATE,
  OUTER_CLASS,
  OUTER_ENVELOPE_HEADER_BYTES,
  RESULT_SIGNATURE_DOMAIN_ID,
  STORE_LIFECYCLE_STATE,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  blindHealthResultV1,
  encodeCanonical,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import {
  ADVERTISED_OPERATION_BITS,
  FAMILY,
  OPERATION,
  assertReleaseReady,
  operationBit
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { assertPrivateIpcReady } from '@hiverelay/blind-ipc'
import {
  CELL_PUT_OPERATION_BIT_V2,
  REQUIRED_LOCAL_IPC_FEATURE_BITS_V2
} from '@hiverelay/blind-ipc/private-ipc-v2-contract'
import { AdmissionCoordinator } from './admission-coordinator.js'
import {
  BLIND_CELL_RUNTIME_BLOCKERS,
  BlindCellRuntimeAdapter
} from './cell-runtime-adapter.js'
import {
  BLIND_INBOX_RUNTIME_BLOCKERS,
  BlindInboxRuntimeAdapter
} from './inbox-runtime-adapter.js'
import {
  BLIND_CORE_RUNTIME_BLOCKERS,
  BlindCoreRuntimeAdapter
} from './core-runtime-adapter.js'
import { BlindOperationCoordinator } from './coordinator.js'
import { DescriptorState } from './descriptor-state.js'
import { READINESS_STATE_KIND, ReadinessCoordinator } from './readiness-coordinator.js'
import { ResourceBudget } from './resource-budget.js'
import { BlindDaemon } from './server.js'
import { createDaemonPrivatePostEofAuthorityIssuer } from './post-eof-authority.js'
import {
  closePrivateIpcReplayJournalV2,
  createPrivateIpcReplayReservationAuthorityV2,
  openPrivateIpcReplayJournalV2,
  privateIpcReplayJournalV2Status
} from './private-ipc-replay-journal-v2.js'
import {
  BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS,
  BlindCellStorageEngine
} from './storage-engine.js'
import { BlindInboxStorageEngine } from './inbox-storage-engine.js'
import { BlindCoreStorageEngine } from './core-storage-engine.js'
import { loadBundledBlindStoreFormatAuthority } from './store-format-binding.js'

const operationBits = (familyId, operationIds) => operationIds.reduce(
  (bits, operationId) => bits | operationBit(familyId, operationId), 0)
const DESCRIBE_OPERATION_BITS = operationBits(FAMILY.DESCRIBE, Object.values(OPERATION.DESCRIBE))
const CELL_OPERATION_BITS = operationBits(FAMILY.CELL, Object.values(OPERATION.CELL))
const INBOX_OPERATION_BITS = operationBits(FAMILY.INBOX, Object.values(OPERATION.INBOX))
const CORE_UNARY_OPERATION_BITS = operationBits(FAMILY.CORE, [OPERATION.CORE.MIRROR, OPERATION.CORE.PROVE])
const DESCRIBE_AND_CELL_OPERATION_BITS = DESCRIBE_OPERATION_BITS | CELL_OPERATION_BITS
const DESCRIBE_CELL_INBOX_OPERATION_BITS = DESCRIBE_AND_CELL_OPERATION_BITS | INBOX_OPERATION_BITS
const DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS = DESCRIBE_CELL_INBOX_OPERATION_BITS | CORE_UNARY_OPERATION_BITS
if (DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS !== ADVERTISED_OPERATION_BITS) {
  throw new Error('production runtime operation assembly drifted from the advertised release profile')
}
const INBOX_RESULT_SIGNATURE_DOMAIN_IDS = new Set([
  RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT,
  RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK,
  RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT
])
const CORE_RESULT_SIGNATURE_DOMAIN_IDS = new Set([
  RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK
])
const KNOWN_TRANSPORT_SUPPORT_BITS = Object.values(TRANSPORT_SUPPORT)
  .reduce((bits, bit) => bits | bit, 0)
const MAX_U64 = (1n << 64n) - 1n
const SIX_HOURS_MILLIS = 21_600_000
const RUNTIME_BINDING_MAGIC = b4a.from('HRBRT001', 'ascii')
const RUNTIME_BINDING_PREFIX_BYTES = 8 + 32 + 32 + 32 + 1 + 2 + 2 + 32 + 8 + 32
const RUNTIME_BINDING_BYTES = RUNTIME_BINDING_PREFIX_BYTES + 32
const RUNTIME_BINDING_FILE = 'runtime-binding.v1'

export const PRODUCTION_RUNTIME_OPERATION_BITS = DESCRIBE_OPERATION_BITS
export const PRODUCTION_CELL_RUNTIME_OPERATION_BITS = CELL_OPERATION_BITS
export const PRODUCTION_INBOX_RUNTIME_OPERATION_BITS = INBOX_OPERATION_BITS
export const PRODUCTION_CORE_UNARY_RUNTIME_OPERATION_BITS = CORE_UNARY_OPERATION_BITS
export const PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS = DESCRIBE_AND_CELL_OPERATION_BITS
export const PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS = DESCRIBE_CELL_INBOX_OPERATION_BITS
export const PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS = DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS
export const PRODUCTION_RUNTIME_EXCLUSIONS = Object.freeze([
  'FINAL_BUILD_PROFILE_LOCAL_BINDING_UNASSEMBLED',
  'TWO_SLOT_MANIFEST_RUNTIME_INTEGRATION_UNASSEMBLED',
  'DESCRIPTOR_REFRESH_PERSISTED_FLOOR_UNASSEMBLED',
  'CELL_PUBLIC_EXECUTION_UNASSEMBLED',
  'INBOX_PUBLIC_EXECUTION_UNASSEMBLED',
  'CORE_PUBLIC_EXECUTION_UNASSEMBLED',
  'FORWARD_PUBLIC_EXECUTION_UNASSEMBLED',
  'PRIVATE_CONTENT_STREAM_RUNTIME_UNASSEMBLED',
  'ADMISSION_REDEMPTION_ADAPTER_UNASSEMBLED',
  'PROFILE2_EXTERNAL_JOURNAL_WITNESS_UNASSEMBLED'
])

export function assertProductionRuntimeReleaseReady () {
  assertReleaseReady()
  assertPrivateIpcReady()
  assertProductionRuntimeCompleteness()
}

export function assertProductionRuntimeCompleteness ({
  runtimeExclusions = PRODUCTION_RUNTIME_EXCLUSIONS,
  storageBlockers = BLIND_CELL_STORAGE_PRODUCTION_BLOCKERS
} = {}) {
  if (!Array.isArray(runtimeExclusions) || !Array.isArray(storageBlockers)) {
    throw new TypeError('production completeness inputs must be blocker arrays')
  }
  if (runtimeExclusions.length > 0) {
    runtimeFailure('BLIND_RUNTIME_INCOMPLETE',
      `production runtime is incomplete: ${runtimeExclusions.join(',')}`)
  }
  if (storageBlockers.length > 0) {
    runtimeFailure('BLIND_STORAGE_INCOMPLETE',
      `production storage is incomplete: ${storageBlockers.join(',')}`)
  }
}

function runtimeFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function canonicalAbsolutePath (value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') ||
      !path.isAbsolute(value) || path.normalize(value) !== value) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${field} must be a canonical absolute path`)
  }
  return value
}

function requiredPath (environment, name) {
  return canonicalAbsolutePath(environment[name], name)
}

function optionalPath (environment, name) {
  const value = environment[name]
  return value == null || value === '' ? null : canonicalAbsolutePath(value, name)
}

function requiredPathList (environment, name, maximum) {
  const raw = environment[name]
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 32768 || raw.includes(' ')) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} must be a comma-separated canonical path list`)
  }
  const values = raw.split(',')
  if (values.length < 1 || values.length > maximum) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} must contain 1..${maximum} paths`)
  }
  const seen = new Set()
  for (let index = 0; index < values.length; index++) {
    canonicalAbsolutePath(values[index], `${name}[${index}]`)
    if (seen.has(values[index])) runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} contains a duplicate path`)
    seen.add(values[index])
  }
  return Object.freeze(values)
}

function canonicalUnsigned (environment, name, fallback, minimum, maximum) {
  const raw = environment[name]
  if (raw == null && fallback != null) return fallback
  if (typeof raw !== 'string' || raw.length > 16 || !/^(0|[1-9][0-9]*)$/.test(raw)) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} must be a canonical unsigned integer`)
  }
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} is outside ${minimum}..${maximum}`)
  }
  return value
}

function canonicalU64 (environment, name, minimum = 1n) {
  const raw = environment[name]
  if (typeof raw !== 'string' || raw.length > 20 || !/^(0|[1-9][0-9]*)$/.test(raw)) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} must be a canonical u64 integer`)
  }
  const value = BigInt(raw)
  if (value < minimum || value > MAX_U64) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} is outside its required u64 range`)
  }
  return value
}

function requiredHash (environment, name) {
  const raw = environment[name]
  if (typeof raw !== 'string' || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', `${name} must be an exact 32-byte hash in hex`)
  }
  return b4a.from(raw, 'hex')
}

function endpointSupportBindings (environment, endpointIds) {
  const raw = environment.HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2039 ||
      !/^[1-9][0-9]*:[1-9][0-9]*(?:,[1-9][0-9]*:[1-9][0-9]*)*$/.test(raw)) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID',
      'HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS must be a canonical endpoint:support-bit list')
  }
  const rows = raw.split(',').map(row => {
    const [endpoint, support] = row.split(':')
    return { endpointId: Number(endpoint), transportSupportBit: Number(support) }
  })
  if (rows.length !== endpointIds.length) {
    runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID', 'endpoint support bindings must cover the exact launch endpoint set')
  }
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index]
    if (row.endpointId !== endpointIds[index] || !Number.isInteger(row.transportSupportBit) ||
        row.transportSupportBit === 0 || (row.transportSupportBit & (row.transportSupportBit - 1)) !== 0 ||
        (row.transportSupportBit & ~KNOWN_TRANSPORT_SUPPORT_BITS) !== 0) {
      runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID',
        'endpoint support bindings must be ordered, exact, and use one registered support bit')
    }
    Object.freeze(row)
  }
  return Object.freeze(rows)
}

export function loadProductionRuntimeConfig (environment = process.env, endpointIds) {
  if (!Array.isArray(endpointIds) || endpointIds.length === 0) {
    throw new TypeError('endpointIds from the signed launch topology are required')
  }
  return Object.freeze({
    descriptorFiles: requiredPathList(environment, 'HIVERELAY_BLIND_DESCRIPTOR_FILES', 4096),
    admissionParameterFiles: requiredPathList(environment, 'HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES', 64),
    relaySecretKeyFile: requiredPath(environment, 'HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE'),
    storeRoot: requiredPath(environment, 'HIVERELAY_BLIND_STORE_ROOT'),
    privateIpcReplayRoot: optionalPath(environment, 'HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT'),
    inboxStoreRoot: optionalPath(environment, 'HIVERELAY_BLIND_INBOX_STORE_ROOT'),
    inboxCursorKeyFile: optionalPath(environment, 'HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE'),
    coreStoreRoot: optionalPath(environment, 'HIVERELAY_BLIND_CORE_STORE_ROOT'),
    partitionKeyFile: requiredPath(environment, 'HIVERELAY_BLIND_PARTITION_KEY_FILE'),
    ownerFenceTokenHashFile: requiredPath(environment, 'HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE'),
    mapGeneration: canonicalU64(environment, 'HIVERELAY_BLIND_MAP_GENERATION'),
    expectedDescriptorSequence: canonicalU64(environment, 'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE', 0n),
    expectedDescriptorHash: requiredHash(environment, 'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH'),
    endpointSupportBindings: endpointSupportBindings(environment, endpointIds),
    resourceBudget: Object.freeze({
      maxItems: canonicalUnsigned(environment, 'HIVERELAY_BLIND_MAX_INFLIGHT_ITEMS', 1024, 1, 1_000_000),
      maxBytes: canonicalUnsigned(environment, 'HIVERELAY_BLIND_MAX_INFLIGHT_BYTES', 64 * 1024 * 1024,
        1, 1024 * 1024 * 1024),
      reservePercent: canonicalUnsigned(environment, 'HIVERELAY_BLIND_RESERVED_PERCENT', 5, 5, 50)
    }),
    server: Object.freeze({
      maxConnections: canonicalUnsigned(environment, 'HIVERELAY_BLIND_MAX_CONNECTIONS', 1024, 1, 1_000_000),
      maxBufferedBytes: canonicalUnsigned(environment, 'HIVERELAY_BLIND_MAX_BUFFERED_BYTES',
        64 * 1024 * 1024, 1, 1024 * 1024 * 1024),
      closeTimeoutMs: canonicalUnsigned(environment, 'HIVERELAY_BLIND_CLOSE_TIMEOUT_MS', 5000, 1, 60000)
    })
  })
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function sameFileState (left, right) {
  return sameInode(left, right) && left.size === right.size && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
}

async function readBoundFile (file, options = {}) {
  const maximumBytes = options.maximumBytes == null ? 1024 * 1024 : options.maximumBytes
  const handle = await fs.open(file, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
  try {
    const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(file)])
    if (!opened.isFile() || linked.isSymbolicLink() || !sameInode(opened, linked) || opened.size < 1 ||
        opened.size > maximumBytes || (linked.mode & 0o022) !== 0) {
      runtimeFailure('BLIND_RUNTIME_FILE_INVALID', `${options.field || file} is not a stable protected regular file`)
    }
    if (options.secret === true) {
      const permissions = linked.mode & 0o777
      if (typeof process.getuid !== 'function' || linked.uid !== process.getuid() || linked.nlink !== 1 ||
          (permissions !== 0o600 && permissions !== 0o400)) {
        runtimeFailure('BLIND_RUNTIME_FILE_INVALID', `${options.field || file} must be daemon-owned and mode 0600/0400`)
      }
    }
    if (await fs.realpath(file) !== file) {
      runtimeFailure('BLIND_RUNTIME_FILE_INVALID', `${options.field || file} must not traverse a symlinked path`)
    }
    const value = await handle.readFile()
    const [after, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(file)])
    if (!sameFileState(opened, after) || !sameFileState(after, linkedAfter) ||
        value.byteLength !== opened.size || await fs.realpath(file) !== file) {
      runtimeFailure('BLIND_RUNTIME_FILE_INVALID', `${options.field || file} changed while it was read`)
    }
    if (options.exactBytes != null && value.byteLength !== options.exactBytes) {
      runtimeFailure('BLIND_RUNTIME_FILE_INVALID', `${options.field || file} must contain exactly ${options.exactBytes} bytes`)
    }
    return value
  } finally {
    await handle.close()
  }
}

async function verifyPrivateStoreRoot (root) {
  const stat = await fs.lstat(root)
  if (!stat.isDirectory() || stat.isSymbolicLink() || typeof process.getuid !== 'function' ||
      stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || await fs.realpath(root) !== root) {
    runtimeFailure('BLIND_RUNTIME_STORE_INVALID', 'blind store root must be a canonical daemon-owned private directory')
  }
}

function encodeRuntimeBinding (descriptor, mapGeneration, ownerFenceTokenHash, partitionKey) {
  const prefix = b4a.alloc(RUNTIME_BINDING_PREFIX_BYTES)
  let offset = 0
  b4a.copy(RUNTIME_BINDING_MAGIC, prefix, offset); offset += 8
  b4a.copy(descriptor.relayPublicKey, prefix, offset); offset += 32
  b4a.copy(descriptor.storeId, prefix, offset); offset += 32
  b4a.copy(descriptor.durabilityContinuityHash, prefix, offset); offset += 32
  prefix[offset++] = descriptor.durability.profileId
  prefix.writeUInt16BE(descriptor.durability.storeFormatMajor, offset); offset += 2
  prefix.writeUInt16BE(descriptor.durability.storeFormatMinor, offset); offset += 2
  b4a.copy(descriptor.durability.storeFormatHash, prefix, offset); offset += 32
  prefix.writeBigUInt64BE(mapGeneration, offset); offset += 8
  b4a.copy(ownerFenceTokenHash, prefix, offset)
  const mac = createHmac('sha256', partitionKey).update(prefix).digest()
  return b4a.concat([prefix, mac], RUNTIME_BINDING_BYTES)
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function bindStoreIdentity (root, expected) {
  const file = path.join(root, RUNTIME_BINDING_FILE)
  let existing
  try {
    existing = await readBoundFile(file, {
      field: 'runtime store binding',
      maximumBytes: RUNTIME_BINDING_BYTES,
      exactBytes: RUNTIME_BINDING_BYTES,
      secret: true
    })
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }
  if (!existing) {
    const entries = await fs.readdir(root)
    if (entries.length !== 0) {
      runtimeFailure('BLIND_RUNTIME_STORE_BINDING_REQUIRED',
        'a nonempty store without a verified runtime binding must not be claimed or modified')
    }
    let handle
    try {
      handle = await fs.open(file, FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL |
        FS_CONSTANTS.O_NOFOLLOW, 0o600)
      await handle.writeFile(expected)
      await handle.sync()
      await handle.close()
      handle = null
      await syncDirectory(root)
      existing = b4a.from(expected)
    } catch (error) {
      if (handle) await handle.close().catch(() => {})
      if (!error || error.code !== 'EEXIST') throw error
      existing = await readBoundFile(file, {
        field: 'runtime store binding',
        maximumBytes: RUNTIME_BINDING_BYTES,
        exactBytes: RUNTIME_BINDING_BYTES,
        secret: true
      })
    }
  }
  if (!timingSafeEqual(existing, expected)) {
    runtimeFailure('BLIND_RUNTIME_STORE_IDENTITY_MISMATCH',
      'store root is bound to another relay/store/durability/map/fence tuple')
  }
}

function verifyDetached (input) {
  if (input.signal && input.signal.aborted) return false
  try {
    return sodium.crypto_sign_verify_detached(input.signature, input.payload, input.publicKey)
  } catch {
    return false
  }
}

function currentSigner (secretKey, publicKey, inboxRuntimeEnabled, coreRuntimeEnabled) {
  let closed = false
  return Object.freeze({
    async sign (input) {
      if (closed || (input.signal && input.signal.aborted) ||
          (input.domainId !== RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT &&
            input.domainId !== RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT &&
            input.domainId !== RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT &&
            !(inboxRuntimeEnabled && INBOX_RESULT_SIGNATURE_DOMAIN_IDS.has(input.domainId)) &&
            !(coreRuntimeEnabled && CORE_RESULT_SIGNATURE_DOMAIN_IDS.has(input.domainId))) ||
          !b4a.equals(input.publicKey, publicKey)) {
        runtimeFailure('BLIND_RUNTIME_SIGNING_REFUSED', 'runtime signer refused an unbound signing request')
      }
      const signature = b4a.alloc(sodium.crypto_sign_BYTES)
      sodium.crypto_sign_detached(signature, input.payload, secretKey)
      return signature
    },
    async verify (input) {
      return verifyDetached(input)
    },
    close () {
      closed = true
      secretKey.fill(0)
    }
  })
}

function describeResultVerifier () {
  return Object.freeze({
    async verify (input) {
      if (input.signal && input.signal.aborted) return false
      if (input.familyId !== FAMILY.DESCRIBE || !input.result || !input.result.relayPublicKey ||
          !input.result.signature || input.result.signature.byteLength !== sodium.crypto_sign_BYTES ||
          input.canonicalResultBytes.byteLength <= sodium.crypto_sign_BYTES) return false
      if (input.operationId === OPERATION.DESCRIBE.GET &&
          input.resultSignatureDomainId !== RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR) return false
      if (input.operationId === OPERATION.DESCRIBE.CHALLENGE &&
          input.resultSignatureDomainId !== RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT) return false
      if (input.operationId === OPERATION.DESCRIBE.ADMISSION_PARAMETERS &&
          input.resultSignatureDomainId !== RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS) return false
      const unsigned = input.canonicalResultBytes.subarray(0,
        input.canonicalResultBytes.byteLength - sodium.crypto_sign_BYTES)
      const trailing = input.canonicalResultBytes.subarray(unsigned.byteLength)
      if (!b4a.equals(trailing, input.result.signature)) return false
      let payload
      try {
        payload = resultSignaturePayload(input.resultSignatureDomainId, unsigned)
      } catch {
        return false
      }
      return sodium.crypto_sign_verify_detached(input.result.signature, payload, input.result.relayPublicKey)
    }
  })
}

function unavailableHook (method, label) {
  return Object.freeze({
    async [method] () {
      runtimeFailure('INTERNAL', `${label} is deliberately unavailable in the signed DESCRIBE-only runtime`)
    }
  })
}

function cellHook (adapterHook, method, label) {
  const unavailable = unavailableHook(method, label)
  return Object.freeze({
    async [method] (input) {
      if (input && input.profile && input.profile.familyId === FAMILY.CELL) {
        return adapterHook[method](input)
      }
      return unavailable[method](input)
    }
  })
}

function inboxHook (adapterHook, method, label) {
  const unavailable = unavailableHook(method, label)
  return Object.freeze({
    async [method] (input) {
      if (input && input.profile && input.profile.familyId === FAMILY.INBOX) {
        return adapterHook[method](input)
      }
      return unavailable[method](input)
    }
  })
}

function coreHook (adapterHook, method, label) {
  const unavailable = unavailableHook(method, label)
  return Object.freeze({
    async [method] (input) {
      if (input && input.profile && input.profile.familyId === FAMILY.CORE) {
        return adapterHook[method](input)
      }
      return unavailable[method](input)
    }
  })
}

function cellInboxCoreHook (cellAdapter, inboxAdapter, coreAdapter, hookField, method, label) {
  const cell = cellAdapter == null ? null : cellHook(cellAdapter[hookField], method, label)
  const inbox = inboxAdapter == null ? null : inboxHook(inboxAdapter[hookField], method, label)
  const core = coreAdapter == null ? null : coreHook(coreAdapter[hookField], method, label)
  const unavailable = unavailableHook(method, label)
  return Object.freeze({
    async [method] (input) {
      const familyId = input && input.profile && input.profile.familyId
      if (familyId === FAMILY.CELL && cell) return cell[method](input)
      if (familyId === FAMILY.INBOX && inbox) return inbox[method](input)
      if (familyId === FAMILY.CORE && core) return core[method](input)
      return unavailable[method](input)
    }
  })
}

function cellInboxCoreTransactionCoordinator (cellAdapter, inboxAdapter, coreAdapter) {
  const coordinatorFor = input => {
    const familyId = input && input.profile && input.profile.familyId
    if (familyId === FAMILY.CELL) return cellAdapter.transactionCoordinator
    if (familyId === FAMILY.INBOX && inboxAdapter) return inboxAdapter.transactionCoordinator
    if (familyId === FAMILY.CORE && coreAdapter) return coreAdapter.transactionCoordinator
    return null
  }
  const invoke = method => (input, ...rest) => {
    const coordinator = coordinatorFor(input)
    if (!coordinator) runtimeFailure('INTERNAL', `admission transaction reached an unwired family at ${method}`)
    return coordinator[method](input, ...rest)
  }
  return Object.freeze({
    lookup: invoke('lookup'),
    run: invoke('run'),
    replay: invoke('replay')
  })
}

function cellInboxCoreOperationExecutor (cellAdapter, inboxAdapter, coreAdapter) {
  return Object.freeze({
    ...cellInboxCoreHook(cellAdapter, inboxAdapter, coreAdapter, 'operationExecutor', 'execute',
      'non-CELL/INBOX/CORE operation executor'),
    ...(cellAdapter == null
      ? {}
      : {
          stageAtomicPut: input => cellAdapter.operationExecutor.stageAtomicPut(input),
          commitAtomicPut: input => cellAdapter.operationExecutor.commitAtomicPut(input),
          cancelAtomicPut: input => cellAdapter.operationExecutor.cancelAtomicPut(input)
        })
  })
}

function describeAndCellResultVerifier (cellAdapter) {
  const describe = describeResultVerifier()
  return Object.freeze({
    async verify (input) {
      if (input && input.familyId === FAMILY.DESCRIBE) return describe.verify(input)
      if (input && input.familyId === FAMILY.CELL) return cellAdapter.resultVerifier.verify(input)
      return false
    }
  })
}

function describeCellInboxResultVerifier (cellAdapter, inboxAdapter) {
  const describeAndCell = describeAndCellResultVerifier(cellAdapter)
  return Object.freeze({
    async verify (input) {
      if (input && input.familyId === FAMILY.INBOX) return inboxAdapter.resultVerifier.verify(input)
      return describeAndCell.verify(input)
    }
  })
}

function describeCellInboxCoreResultVerifier (cellAdapter, inboxAdapter, coreAdapter) {
  const describeCellInbox = describeCellInboxResultVerifier(cellAdapter, inboxAdapter)
  return Object.freeze({
    async verify (input) {
      if (input && input.familyId === FAMILY.CORE) return coreAdapter.resultVerifier.verify(input)
      return describeCellInbox.verify(input)
    }
  })
}

// The pinned upstream blind-peer authority (signed-head proof authority and
// Hypercore interop stack) is not assembled. MIRROR still durably accepts its
// sponsorship and records the recoverable RETRY_PENDING activation state;
// PROVE only serves an ACTIVE sponsored generation, which this authority can
// never produce, so it fails before any spend reaches it.
function unavailableCoreUpstream () {
  return Object.freeze({
    async activateMirror () {
      runtimeFailure('INTERNAL', 'upstream CORE activation is unavailable until the pinned blind-peer authority is assembled')
    },
    async serveProof () {
      runtimeFailure('INTERNAL', 'upstream CORE proof authority is unavailable until the pinned blind-peer authority is assembled')
    },
    async estimateProofBytes () {
      runtimeFailure('INTERNAL', 'upstream CORE proof estimate is unavailable until the pinned blind-peer authority is assembled')
    }
  })
}

function currentUnixMillis () {
  return BigInt(Date.now())
}

function currentLeaseEpoch () {
  return Math.floor(Date.now() / SIX_HOURS_MILLIS)
}

function sameNumberSet (left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function assertRuntimeDescriptor (snapshot, bootstrap, config, cellRuntimeEnabled, inboxRuntimeEnabled, coreRuntimeEnabled) {
  const descriptor = snapshot.descriptor
  const expectedOperationBits = cellRuntimeEnabled
    ? inboxRuntimeEnabled
      ? coreRuntimeEnabled
        ? DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS
        : DESCRIBE_CELL_INBOX_OPERATION_BITS
      : DESCRIBE_AND_CELL_OPERATION_BITS
    : DESCRIBE_OPERATION_BITS
  if (descriptor.storeLifecycleState !== STORE_LIFECYCLE_STATE.ACTIVE ||
      descriptor.enabledOperationBits !== expectedOperationBits) {
    runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
      `production runtime requires an ACTIVE descriptor with exact enabled operation bits 0x${expectedOperationBits.toString(16)}`)
  }
  if (descriptor.durability.profileId !== 1) {
    runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
      'durability profile 2 is unavailable until its external journal and witness coordinator are assembled')
  }
  if (!b4a.equals(descriptor.build.storeFormatHash, descriptor.durability.storeFormatHash)) {
    runtimeFailure('BLIND_RUNTIME_STORE_FORMAT_MISMATCH',
      'signed build and durability profiles name different store-format authorities')
  }
  if (descriptor.capacityBand !== 0) {
    runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
      'runtime must not attest an unmeasured nonzero capacity band')
  }
  const endpointIds = descriptor.endpoints.map(endpoint => endpoint.endpointId)
  if (!sameNumberSet(endpointIds, bootstrap.endpointIds)) {
    runtimeFailure('BLIND_RUNTIME_TOPOLOGY_MISMATCH',
      'signed descriptor endpoints must equal the signed local launch endpoint set')
  }
  for (let index = 0; index < descriptor.endpoints.length; index++) {
    const endpoint = descriptor.endpoints[index]
    const support = config.endpointSupportBindings[index]
    const expectedRoleBits = cellRuntimeEnabled
      ? ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY | ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER
      : ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY
    if (endpoint.roleBits !== expectedRoleBits ||
        endpoint.transportId !== TRANSPORT_ID.HTTPS_DIRECT ||
        support.transportSupportBit !== TRANSPORT_SUPPORT.DIRECT_HTTP) {
      runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
        'runtime endpoint roles and HTTPS_DIRECT/DIRECT_HTTP support must equal the assembled family surface')
    }
  }
}

function assertDescribeResponseFit (snapshot, descriptorBytes, parameterBytes) {
  const descriptor = snapshot.descriptor
  const healthBytes = encodeCanonical(blindHealthResultV1, {
    version: 1,
    relayPublicKey: descriptor.relayPublicKey,
    storeId: descriptor.storeId,
    descriptorSequence: descriptor.descriptorSequence,
    descriptorHash: snapshot.hash,
    endpointId: descriptor.endpoints[0].endpointId,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    durabilityContinuityHash: descriptor.durabilityContinuityHash,
    durabilityProfileHash: descriptor.durabilityProfileHash,
    clientNonce: b4a.alloc(32, 1),
    readyRoleBits: ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY,
    readyOperationBits: DESCRIBE_OPERATION_BITS,
    clockState: HEALTH_CLOCK_STATE.READY,
    effectiveEpochFloor: descriptor.issuedEpoch,
    integrityState: HEALTH_INTEGRITY_STATE.DEGRADED,
    checkpointAgeBand: 0,
    scrubAgeBand: 0,
    rebalanceState: HEALTH_REBALANCE_STATE.FENCED,
    capacityBand: 0,
    challengeEpoch: descriptor.issuedEpoch,
    signature: b4a.alloc(64)
  })
  const maximumBodyBytes = Math.max(healthBytes.byteLength,
    ...descriptorBytes.map(bytes => bytes.byteLength), ...parameterBytes.map(bytes => bytes.byteLength))
  if (descriptor.maxResponseBytes < maximumBodyBytes) {
    runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
      'signed maxResponseBytes cannot carry every configured DESCRIBE result')
  }
  const requiredOuterBytes = OUTER_ENVELOPE_HEADER_BYTES + DISPATCH_LIMITS.PREFIX_BYTES +
    DISPATCH_LIMITS.HEADER_BYTES + maximumBodyBytes
  for (const endpoint of descriptor.endpoints) {
    const maximumOuterBytes = Object.entries(OUTER_CLASS).reduce((maximum, [id, bytes]) =>
      (endpoint.envelopeClassBits & (1 << Number(id))) !== 0 ? Math.max(maximum, bytes) : maximum, 0)
    if (maximumOuterBytes < requiredOuterBytes) {
      runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED',
        'endpoint envelope classes cannot carry every configured DESCRIBE result')
    }
  }
}

function assertDescriptorLaunchFloor (snapshot, config) {
  if (snapshot.descriptorSequence !== config.expectedDescriptorSequence ||
      !b4a.equals(snapshot.hash, config.expectedDescriptorHash)) {
    runtimeFailure('BLIND_RUNTIME_DESCRIPTOR_FLOOR_MISMATCH',
      'activated descriptor does not match the exact signed launch sequence/hash floor')
  }
}

function contextAuthority (snapshot, supportByEndpoint, context) {
  const endpoint = snapshot.descriptor.endpoints.find(entry => entry.endpointId === context.endpointId)
  const supportBit = supportByEndpoint.get(context.endpointId)
  if (!endpoint || context.transportId !== endpoint.transportId || context.transportSupportBit !== supportBit) {
    runtimeFailure('TRANSPORT_UNSUPPORTED',
      'private IPC context does not match its signed descriptor endpoint and explicit launch support bit')
  }
  return endpoint
}

export function productionStorageOperationalIntegrity (status) {
  if (!status || typeof status !== 'object') {
    throw new TypeError('production storage status is required')
  }
  const readOnly = status.state === 'READ_ONLY'
  const operationalState = status.state === 'READY' || status.state === 'CLOCK_UNSAFE'
  const formatBound = status.storeFormat?.bound === true
  return Object.freeze({
    fullStoreVerified: !readOnly && operationalState && formatBound,
    integrityState: readOnly
      ? HEALTH_INTEGRITY_STATE.FAILED
      : operationalState && formatBound
        ? HEALTH_INTEGRITY_STATE.VERIFIED
        : HEALTH_INTEGRITY_STATE.DEGRADED
  })
}

function storageDependencySnapshot (storage, enabledOperationBits, readyRoleBits, writeReadinessGuard = null, inboxReadinessGuard = null) {
  return async input => {
    const status = storage.status()
    // Promotion blockers describe missing future surfaces (profile 2,
    // rebalance, repair evidence, accelerated scrub). They are not evidence
    // that this opened profile-1 store failed its own WAL/body verification.
    // Keep those limitations visible through blockers/rebalanceState while
    // deriving integrity only from the bound format and live store state.
    const operationalIntegrity = productionStorageOperationalIntegrity(status)
    const writeReady = writeReadinessGuard == null || writeReadinessGuard(input) === true
    const inboxReady = inboxReadinessGuard == null || inboxReadinessGuard() === true
    const readyOperationBits = writeReady
      ? enabledOperationBits
      : enabledOperationBits & ~CELL_PUT_OPERATION_BIT_V2
    return Object.freeze({
      selfVerified: true,
      descriptorSequence: input.descriptorSequence,
      descriptorHash: b4a.from(input.descriptorHash),
      endpointId: input.endpointId,
      transportSupportBit: input.transportSupportBit,
      fullStoreVerified: operationalIntegrity.fullStoreVerified,
      readyRoleBits,
      readyOperationBits: inboxReady
        ? readyOperationBits
        : readyOperationBits & ~INBOX_OPERATION_BITS,
      clockState: status.state === 'CLOCK_UNSAFE' ? HEALTH_CLOCK_STATE.UNSAFE : HEALTH_CLOCK_STATE.READY,
      effectiveEpochFloor: status.epochFloor,
      integrityState: operationalIntegrity.integrityState,
      checkpointAgeBand: 0,
      scrubAgeBand: 0,
      rebalanceState: status.blockers.includes('ONLINE_REBALANCE_UNIMPLEMENTED')
        ? HEALTH_REBALANCE_STATE.FENCED
        : HEALTH_REBALANCE_STATE.STABLE,
      capacityBand: input.descriptor.capacityBand
    })
  }
}

function exactParameterHashes (snapshot, installed) {
  const expected = snapshot.descriptor.admissionProfiles
    .map(profile => b4a.toString(profile.parameterHash, 'hex')).sort()
  const actual = installed.map(record => b4a.toString(record.hash, 'hex')).sort()
  if (expected.length !== actual.length || expected.some((hash, index) => hash !== actual[index])) {
    runtimeFailure('BLIND_RUNTIME_ADMISSION_MISMATCH',
      'configured admission parameter files must equal the exact current signed descriptor profile set')
  }
}

function admissionAdapterKey (input) {
  return `${input.profileId}:${input.schemeId}:${b4a.toString(input.parameterHash, 'hex')}:${input.endpointId}`
}

function capturedAdmissionAdapter (adapter) {
  if (!adapter || typeof adapter.prepare !== 'function' ||
      typeof adapter.preparePreflight !== 'function' || typeof adapter.confirmAfterEof !== 'function') {
    return null
  }
  const receiver = adapter
  const prepare = adapter.prepare
  const preparePreflight = adapter.preparePreflight
  const confirmAfterEof = adapter.confirmAfterEof
  return Object.freeze({
    prepare: input => prepare.call(receiver, input),
    preparePreflight: input => preparePreflight.call(receiver, input),
    confirmAfterEof: input => confirmAfterEof.call(receiver, input)
  })
}

async function captureCellPutAdmissionAdapters (resolver, snapshot, installed) {
  const captured = new Map()
  const required = []
  for (const record of installed) {
    if (!record.value.resourceCosts.some(row =>
      row.familyId === FAMILY.CELL && row.operationId === OPERATION.CELL.PUT)) continue
    for (const endpoint of snapshot.descriptor.endpoints) {
      if ((record.value.roleBits & endpoint.roleBits) === 0) continue
      required.push({ record, endpoint })
    }
  }
  let complete = required.length > 0
  for (const { record, endpoint } of required) {
    let adapter = null
    try {
      adapter = capturedAdmissionAdapter(await resolver({
        profileId: record.value.profileId,
        schemeId: record.value.schemeId,
        parameterHash: b4a.from(record.hash),
        descriptor: snapshot.descriptor,
        parameters: record.value,
        endpointId: endpoint.endpointId,
        endpointRoleBits: endpoint.roleBits,
        signal: null
      }))
    } catch {}
    if (adapter == null) {
      complete = false
      continue
    }
    captured.set(admissionAdapterKey({
      profileId: record.value.profileId,
      schemeId: record.value.schemeId,
      parameterHash: record.hash,
      endpointId: endpoint.endpointId
    }), adapter)
  }
  return Object.freeze({ captured, complete, required: required.length })
}

export async function assembleProductionBlindDaemon (options = {}) {
  const bootstrap = options.bootstrap
  if (!bootstrap || !Array.isArray(bootstrap.endpointIds) || !bootstrap.launchTopologyHash) {
    throw new TypeError('validated daemon bootstrap configuration is required')
  }
  const releaseGate = options.releaseGate || assertProductionRuntimeReleaseReady
  const testOnlyReplayJournalOptions = options.testOnlyPrivateIpcReplayJournalOptions
  if (testOnlyReplayJournalOptions != null) {
    if (releaseGate === assertProductionRuntimeReleaseReady ||
        !testOnlyReplayJournalOptions || typeof testOnlyReplayJournalOptions !== 'object' ||
        Array.isArray(testOnlyReplayJournalOptions)) {
      runtimeFailure('BLIND_RUNTIME_TEST_SEAM_FORBIDDEN',
        'private IPC replay journal overrides are available only behind an explicit non-production release gate')
    }
    const unknown = Object.keys(testOnlyReplayJournalOptions).find(key =>
      !['monotonicMillis', 'faultInjector', 'compactionRecordLimit'].includes(key))
    if (unknown) {
      runtimeFailure('BLIND_RUNTIME_TEST_SEAM_FORBIDDEN',
        `unknown private IPC replay journal test override ${unknown}`)
    }
  }
  await releaseGate()
  const cellRuntimeEnabled = options.enableCellRuntime === true
  const inboxRuntimeEnabled = options.enableInboxRuntime === true
  const coreRuntimeEnabled = options.enableCoreRuntime === true
  if (inboxRuntimeEnabled && !cellRuntimeEnabled) {
    runtimeFailure('BLIND_RUNTIME_INBOX_CELL_RUNTIME_REQUIRED',
      'INBOX runtime assembly requires the assembled CELL runtime line')
  }
  if (coreRuntimeEnabled && !inboxRuntimeEnabled) {
    runtimeFailure('BLIND_RUNTIME_CORE_INBOX_RUNTIME_REQUIRED',
      'CORE runtime assembly requires the assembled INBOX runtime line')
  }
  if (cellRuntimeEnabled && typeof options.resolveAdmissionAdapter !== 'function') {
    runtimeFailure('BLIND_RUNTIME_ADMISSION_ADAPTER_REQUIRED',
      'CELL runtime assembly requires an explicit admission adapter resolver')
  }
  const config = options.runtimeConfig || loadProductionRuntimeConfig(options.environment, bootstrap.endpointIds)
  if (inboxRuntimeEnabled) {
    if (config.inboxStoreRoot == null || config.inboxCursorKeyFile == null) {
      runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID',
        'INBOX runtime assembly requires HIVERELAY_BLIND_INBOX_STORE_ROOT and HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE')
    }
    if (config.inboxStoreRoot === config.storeRoot ||
        config.inboxStoreRoot.startsWith(`${config.storeRoot}${path.sep}`) ||
        config.storeRoot.startsWith(`${config.inboxStoreRoot}${path.sep}`) ||
        (config.privateIpcReplayRoot != null &&
          (config.inboxStoreRoot === config.privateIpcReplayRoot ||
            config.inboxStoreRoot.startsWith(`${config.privateIpcReplayRoot}${path.sep}`) ||
            config.privateIpcReplayRoot.startsWith(`${config.inboxStoreRoot}${path.sep}`)))) {
      runtimeFailure('BLIND_RUNTIME_INBOX_STORE_ROOT_OVERLAP',
        'INBOX store root must be disjoint from the cell store and replay journal roots')
    }
  }
  if (coreRuntimeEnabled) {
    if (config.coreStoreRoot == null) {
      runtimeFailure('BLIND_RUNTIME_CONFIG_INVALID',
        'CORE runtime assembly requires HIVERELAY_BLIND_CORE_STORE_ROOT')
    }
    const overlapsCoreRoot = root =>
      config.coreStoreRoot === root ||
      config.coreStoreRoot.startsWith(`${root}${path.sep}`) ||
      root.startsWith(`${config.coreStoreRoot}${path.sep}`)
    if (overlapsCoreRoot(config.storeRoot) || overlapsCoreRoot(config.inboxStoreRoot) ||
        (config.privateIpcReplayRoot != null && overlapsCoreRoot(config.privateIpcReplayRoot))) {
      runtimeFailure('BLIND_RUNTIME_CORE_STORE_ROOT_OVERLAP',
        'CORE store root must be disjoint from the cell store, inbox store, and replay journal roots')
    }
  }
  let secretKey
  let signer
  let storage
  let inboxStorage
  let inboxCursorKey
  let coreStorage
  let privateIpcReplayJournal
  let privateIpcReplayFailure = null
  let durableReplayAuthority
  let readiness
  let daemon
  let runtime
  let cellAdapter
  let inboxAdapter
  let coreAdapter
  try {
    const descriptorBytes = await Promise.all(config.descriptorFiles.map((file, index) => readBoundFile(file, {
      field: `descriptorFiles[${index}]`,
      maximumBytes: 16 * 1024
    })))
    const descriptorState = new DescriptorState({ verifySignature: verifyDetached })
    let descriptorSnapshot
    for (const bytes of descriptorBytes) descriptorSnapshot = await descriptorState.activate(bytes)
    assertDescriptorLaunchFloor(descriptorSnapshot, config)
    assertRuntimeDescriptor(descriptorSnapshot, bootstrap, config, cellRuntimeEnabled, inboxRuntimeEnabled,
      coreRuntimeEnabled)
    const storeFormatAuthority = await loadBundledBlindStoreFormatAuthority({
      expectedStoreFormatHash: descriptorSnapshot.descriptor.durability.storeFormatHash,
      expectedFormatMajor: descriptorSnapshot.descriptor.durability.storeFormatMajor,
      expectedFormatMinor: descriptorSnapshot.descriptor.durability.storeFormatMinor
    })

    secretKey = await readBoundFile(config.relaySecretKeyFile, {
      field: 'relay secret key',
      exactBytes: sodium.crypto_sign_SECRETKEYBYTES,
      maximumBytes: sodium.crypto_sign_SECRETKEYBYTES,
      secret: true
    })
    const derivedPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    sodium.crypto_sign_ed25519_sk_to_pk(derivedPublicKey, secretKey)
    if (!b4a.equals(derivedPublicKey, descriptorSnapshot.descriptor.relayPublicKey)) {
      runtimeFailure('BLIND_RUNTIME_SIGNING_KEY_MISMATCH',
        'relay signing secret does not match the current signed descriptor relay key')
    }
    signer = currentSigner(secretKey, derivedPublicKey, inboxRuntimeEnabled, coreRuntimeEnabled)

    const postEofAuthorityIssuer = createDaemonPrivatePostEofAuthorityIssuer()
    let admissionResolver = options.resolveAdmissionAdapter || (async () => null)
    const admission = new AdmissionCoordinator({
      descriptorState,
      verifySignature: verifyDetached,
      resolveAdapter: input => admissionResolver(input),
      consumePostEofAuthority: input => postEofAuthorityIssuer.consume(input)
    })
    const parameterBytes = await Promise.all(config.admissionParameterFiles.map((file, index) => readBoundFile(file, {
      field: `admissionParameterFiles[${index}]`,
      maximumBytes: 1024 * 1024
    })))
    const installedParameters = []
    for (const bytes of parameterBytes) installedParameters.push(await admission.installParameters(bytes))
    exactParameterHashes(descriptorSnapshot, installedParameters)
    if (!admission.descriptorParametersAvailable(descriptorSnapshot)) {
      runtimeFailure('BLIND_RUNTIME_ADMISSION_MISMATCH', 'current signed admission parameters are unavailable')
    }
    const admissionCapture = cellRuntimeEnabled
      ? await captureCellPutAdmissionAdapters(admissionResolver, descriptorSnapshot, installedParameters)
      : Object.freeze({ captured: new Map(), complete: false, required: 0 })
    if (cellRuntimeEnabled) {
      const fallbackResolver = admissionResolver
      admissionResolver = input => admissionCapture.captured.get(admissionAdapterKey(input)) ||
        fallbackResolver(input)
    }
    assertDescribeResponseFit(descriptorSnapshot, descriptorBytes, parameterBytes)

    const partitionKey = await readBoundFile(config.partitionKeyFile, {
      field: 'store partition key', exactBytes: 32, maximumBytes: 32, secret: true
    })
    let ownerFenceTokenHash
    try {
      ownerFenceTokenHash = await readBoundFile(config.ownerFenceTokenHashFile, {
        field: 'owner fence token hash', exactBytes: 32, maximumBytes: 32, secret: true
      })
      await verifyPrivateStoreRoot(config.storeRoot)
      const binding = encodeRuntimeBinding(descriptorSnapshot.descriptor, config.mapGeneration,
        ownerFenceTokenHash, partitionKey)
      await bindStoreIdentity(config.storeRoot, binding)
      storage = new BlindCellStorageEngine({
        root: config.storeRoot,
        relayPublicKey: descriptorSnapshot.descriptor.relayPublicKey,
        storeId: descriptorSnapshot.descriptor.storeId,
        durabilityProfileId: descriptorSnapshot.descriptor.durability.profileId,
        durabilityProfileHash: descriptorSnapshot.descriptor.durabilityProfileHash,
        partitionKey,
        mapGeneration: config.mapGeneration,
        ownerFenceTokenHash,
        durabilityContinuityHash: descriptorSnapshot.descriptor.durabilityContinuityHash,
        storeFormatAuthority
      })
      await storage.open()
      if (inboxRuntimeEnabled) {
        await verifyPrivateStoreRoot(config.inboxStoreRoot)
        await bindStoreIdentity(config.inboxStoreRoot, binding)
        inboxCursorKey = await readBoundFile(config.inboxCursorKeyFile, {
          field: 'inbox cursor key',
          exactBytes: 32,
          maximumBytes: 32,
          secret: true
        })
        inboxStorage = new BlindInboxStorageEngine({
          root: config.inboxStoreRoot,
          relayPublicKey: descriptorSnapshot.descriptor.relayPublicKey,
          storeId: descriptorSnapshot.descriptor.storeId,
          durabilityProfileId: descriptorSnapshot.descriptor.durability.profileId,
          durabilityProfileHash: descriptorSnapshot.descriptor.durabilityProfileHash,
          partitionKey,
          cursorKey: inboxCursorKey,
          mapGeneration: config.mapGeneration,
          ownerFenceTokenHash,
          durabilityContinuityHash: descriptorSnapshot.descriptor.durabilityContinuityHash,
          storeFormatAuthority
        })
        await inboxStorage.open()
      }
      if (coreRuntimeEnabled) {
        await verifyPrivateStoreRoot(config.coreStoreRoot)
        await bindStoreIdentity(config.coreStoreRoot, binding)
        coreStorage = new BlindCoreStorageEngine({
          root: config.coreStoreRoot,
          relayPublicKey: descriptorSnapshot.descriptor.relayPublicKey,
          partitionKey,
          ownerFenceTokenHash,
          durabilityContinuityHash: descriptorSnapshot.descriptor.durabilityContinuityHash,
          maximumSponsoredCoreLength: descriptorSnapshot.descriptor.maxSponsoredCoreLength,
          nowEpoch: currentLeaseEpoch,
          nowUnixMillis: currentUnixMillis
        })
        await coreStorage.open()
      }
      if (cellRuntimeEnabled) {
        try {
          if (config.privateIpcReplayRoot == null) {
            runtimeFailure('PRIVATE_IPC_V2_REPLAY_JOURNAL_ROOT_UNCONFIGURED',
              'private IPC replay journal root is not configured')
          }
          if (config.privateIpcReplayRoot === config.storeRoot ||
              config.privateIpcReplayRoot.startsWith(`${config.storeRoot}${path.sep}`) ||
              config.storeRoot.startsWith(`${config.privateIpcReplayRoot}${path.sep}`)) {
            runtimeFailure('PRIVATE_IPC_V2_REPLAY_JOURNAL_ROOT_OVERLAP',
              'private IPC replay journal and blind store roots must be disjoint')
          }
          privateIpcReplayJournal = await openPrivateIpcReplayJournalV2({
            root: config.privateIpcReplayRoot,
            partitionKey,
            launchTopologyHash: bootstrap.launchTopologyHash,
            relayPublicKey: descriptorSnapshot.descriptor.relayPublicKey,
            storeId: descriptorSnapshot.descriptor.storeId,
            durabilityContinuityHash: descriptorSnapshot.descriptor.durabilityContinuityHash,
            durabilityProfileHash: descriptorSnapshot.descriptor.durabilityProfileHash,
            storeFormatHash: descriptorSnapshot.descriptor.durability.storeFormatHash,
            mapGeneration: config.mapGeneration,
            ownerFenceTokenHash,
            ...(testOnlyReplayJournalOptions || {})
          })
          durableReplayAuthority = createPrivateIpcReplayReservationAuthorityV2(
            privateIpcReplayJournal)
        } catch (error) {
          privateIpcReplayFailure = Object.freeze({
            state: 'UNAVAILABLE',
            ready: false,
            reason: typeof error?.code === 'string'
              ? error.code
              : 'PRIVATE_IPC_V2_REPLAY_JOURNAL_OPEN_FAILED',
            recovery: 'OPERATOR_REPLAY_JOURNAL_REPAIR_OR_MIGRATION_AND_RESTART_REQUIRED'
          })
          if (typeof options.onError === 'function') {
            try {
              options.onError(error)
            } catch {}
          }
        }
      }
    } finally {
      partitionKey.fill(0)
      if (ownerFenceTokenHash) ownerFenceTokenHash.fill(0)
      if (inboxCursorKey) inboxCursorKey.fill(0)
    }

    const durableReplayReady = Boolean(durableReplayAuthority &&
      typeof durableReplayAuthority.reserve === 'function')
    const v2WritePathAssembled = cellRuntimeEnabled && admissionCapture.complete
    const v2WritePathReady = v2WritePathAssembled && durableReplayReady
    const assembledOperationBits = cellRuntimeEnabled
      ? inboxRuntimeEnabled
        ? coreRuntimeEnabled
          ? DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS
          : DESCRIBE_CELL_INBOX_OPERATION_BITS
        : DESCRIBE_AND_CELL_OPERATION_BITS
      : DESCRIBE_OPERATION_BITS
    const enabledOperationBits = cellRuntimeEnabled && !v2WritePathReady
      ? assembledOperationBits ^ CELL_PUT_OPERATION_BIT_V2
      : assembledOperationBits
    const readyRoleBits = cellRuntimeEnabled
      ? ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY | ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER
      : ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY
    readiness = new ReadinessCoordinator({
      descriptorState,
      admission,
      dependencySnapshot: storageDependencySnapshot(storage, enabledOperationBits, readyRoleBits, () => {
        const current = descriptorState.state().snapshot
        return v2WritePathReady && current &&
          current.descriptorSequence === descriptorSnapshot.descriptorSequence &&
          b4a.equals(current.hash, descriptorSnapshot.hash) &&
          privateIpcReplayJournal != null &&
          privateIpcReplayJournalV2Status(privateIpcReplayJournal).ready
      }, inboxRuntimeEnabled
        ? () => {
            const inboxStatus = inboxStorage.status()
            return inboxStatus.opened === true && inboxStatus.readOnlyReason == null
          }
        : null),
      signer
    })
    const budget = new ResourceBudget(config.resourceBudget)
    if (cellRuntimeEnabled) {
      cellAdapter = new BlindCellRuntimeAdapter({ storage, descriptorState, signer })
    }
    if (inboxRuntimeEnabled) {
      inboxAdapter = new BlindInboxRuntimeAdapter({ storage: inboxStorage, descriptorState, signer })
    }
    if (coreRuntimeEnabled) {
      coreAdapter = new BlindCoreRuntimeAdapter({
        storage: coreStorage,
        descriptorState,
        signer,
        upstream: unavailableCoreUpstream()
      })
    }
    const familyHook = (hookField, method, label) =>
      cellInboxCoreHook(cellAdapter, inboxAdapter, coreAdapter, hookField, method, label)
    const coordinator = new BlindOperationCoordinator({
      descriptorState,
      admission,
      readiness,
      budget,
      relationVerifier: cellRuntimeEnabled
        ? familyHook('relationVerifier', 'verify', 'non-CELL/INBOX/CORE relation verifier')
        : unavailableHook('verify', 'non-DESCRIBE relation verifier'),
      capabilityVerifier: cellRuntimeEnabled
        ? familyHook('capabilityVerifier', 'verify', 'non-CELL/INBOX/CORE capability verifier')
        : unavailableHook('verify', 'non-DESCRIBE capability verifier'),
      cheapStateVerifier: cellRuntimeEnabled
        ? familyHook('cheapStateVerifier', 'inspect', 'non-CELL/INBOX/CORE state inspector')
        : unavailableHook('inspect', 'non-DESCRIBE state inspector'),
      terminalStateVerifier: cellRuntimeEnabled
        ? familyHook('terminalStateVerifier', 'check', 'non-CELL/INBOX/CORE terminal-state verifier')
        : unavailableHook('check', 'non-DESCRIBE terminal-state verifier'),
      capacityGuard: cellRuntimeEnabled
        ? familyHook('capacityGuard', 'check', 'non-CELL/INBOX/CORE capacity guard')
        : unavailableHook('check', 'non-DESCRIBE capacity guard'),
      operationExecutor: cellRuntimeEnabled
        ? cellInboxCoreOperationExecutor(cellAdapter, inboxAdapter, coreAdapter)
        : unavailableHook('execute', 'non-DESCRIBE operation executor'),
      transactionCoordinator: cellRuntimeEnabled
        ? cellInboxCoreTransactionCoordinator(cellAdapter, inboxAdapter, coreAdapter)
        : null,
      resultVerifier: cellRuntimeEnabled
        ? inboxRuntimeEnabled
          ? coreRuntimeEnabled
            ? describeCellInboxCoreResultVerifier(cellAdapter, inboxAdapter, coreAdapter)
            : describeCellInboxResultVerifier(cellAdapter, inboxAdapter)
          : describeAndCellResultVerifier(cellAdapter)
        : describeResultVerifier(),
      authenticatedSessionVerifier: unavailableHook('verify', 'non-DESCRIBE authenticated session verifier')
    })
    const supportByEndpoint = new Map(config.endpointSupportBindings
      .map(row => [row.endpointId, row.transportSupportBit]))
    const readinessSnapshot = input => {
      const supportBit = supportByEndpoint.get(input.endpointId)
      if (!supportBit || !b4a.equals(input.launchTopologyHash, bootstrap.launchTopologyHash)) {
        runtimeFailure('BLIND_RUNTIME_TOPOLOGY_MISMATCH', 'readiness request is outside the signed launch topology')
      }
      return readiness.serverSnapshot({
        ...input,
        transportSupportBit: supportBit
      })
    }
    const dispatch = (frame, context) => {
      contextAuthority(descriptorSnapshot, supportByEndpoint, context)
      return coordinator.dispatch(frame, context)
    }
    const dispatchStagedPut = v2WritePathAssembled
      ? (staged, context) => {
          contextAuthority(descriptorSnapshot, supportByEndpoint, context)
          return coordinator.dispatchStagedCellPut(staged, context)
        }
      : null
    const streamTransportProfileHashForEndpoint = v2WritePathAssembled
      ? input => b4a.from(contextAuthority(descriptorSnapshot, supportByEndpoint, input).transportProfileHash)
      : null
    const writeReadinessProjection = v2WritePathAssembled
      ? async input => {
        const supportBit = supportByEndpoint.get(input.endpointId)
        if (!supportBit || supportBit !== TRANSPORT_SUPPORT.DIRECT_HTTP ||
              !b4a.equals(input.launchTopologyHash, bootstrap.launchTopologyHash)) {
          runtimeFailure('BLIND_RUNTIME_TOPOLOGY_MISMATCH',
            'V2 write readiness is outside the exact production topology')
        }
        const state = await readiness.evaluate({
          endpointId: input.endpointId,
          transportSupportBit: supportBit,
          signal: input.signal
        })
        const storageStatus = storage.status()
        const replayStatus = privateIpcReplayJournal == null
          ? privateIpcReplayFailure
          : privateIpcReplayJournalV2Status(privateIpcReplayJournal)
        const current = descriptorState.state().snapshot
        const captureCurrent = current &&
            current.descriptorSequence === descriptorSnapshot.descriptorSequence &&
            b4a.equals(current.hash, descriptorSnapshot.hash)
        const expiresMonotonicMillis = input.absoluteDeadlineMonotonicMillis - 1n
        return Object.freeze({
          selfVerified: state.kind === READINESS_STATE_KIND.READY,
          cellRuntimeReady: captureCurrent && state.kind === READINESS_STATE_KIND.READY &&
              (state.readyOperationBits & CELL_PUT_OPERATION_BIT_V2) !== 0,
          storageReady: storageStatus.state === 'READY',
          admissionReady: captureCurrent && admissionCapture.complete,
          replayJournalReady: replayStatus?.ready === true &&
            replayStatus.occupied < replayStatus.capacity,
          endpointId: input.endpointId,
          launchTopologyHash: b4a.from(bootstrap.launchTopologyHash),
          transportProfileHash: b4a.from(input.transportProfileHash),
          descriptorSequence: descriptorSnapshot.descriptorSequence,
          descriptorHash: b4a.from(descriptorSnapshot.hash),
          descriptorRoleBits: descriptorSnapshot.descriptor.endpoints.find(
            endpoint => endpoint.endpointId === input.endpointId).roleBits,
          descriptorEnabledOperationBits: descriptorSnapshot.descriptor.enabledOperationBits,
          readyRoleBits: state.kind === READINESS_STATE_KIND.READY ? state.readyRoleBits : 0,
          readyOperationBits: state.kind === READINESS_STATE_KIND.READY ? state.readyOperationBits : 0,
          readyWriteOperationBits: state.kind === READINESS_STATE_KIND.READY
            ? state.readyOperationBits & CELL_PUT_OPERATION_BIT_V2
            : 0,
          readyIpcFeatureBits: REQUIRED_LOCAL_IPC_FEATURE_BITS_V2,
          expiresMonotonicMillis,
          descriptorExpiresMonotonicMillis: input.absoluteDeadlineMonotonicMillis
        })
      }
      : null
    daemon = new BlindDaemon({
      ...bootstrap,
      ...config.server,
      dispatch,
      dispatchStagedPut,
      postEofAuthorityIssuer,
      stagedPutRelayPublicKey: descriptorSnapshot.descriptor.relayPublicKey,
      streamTransportProfileHashForEndpoint,
      durableReplayAuthority,
      writeReadinessProjection,
      readinessSnapshot,
      releaseGate: async () => {},
      onError: options.onError
    })

    let started = false
    let closed = false
    let closePromise = null
    const publicExecutionAssembled = value =>
      (v2WritePathReady &&
        (value === 'CELL_PUBLIC_EXECUTION_UNASSEMBLED' ||
          value === 'PRIVATE_CONTENT_STREAM_RUNTIME_UNASSEMBLED' ||
          value === 'ADMISSION_REDEMPTION_ADAPTER_UNASSEMBLED')) ||
      (inboxRuntimeEnabled && value === 'INBOX_PUBLIC_EXECUTION_UNASSEMBLED') ||
      (coreRuntimeEnabled && value === 'CORE_PUBLIC_EXECUTION_UNASSEMBLED')
    const runtimeExclusions = cellRuntimeEnabled
      ? Object.freeze([
        ...PRODUCTION_RUNTIME_EXCLUSIONS.filter(value => !publicExecutionAssembled(value)),
        ...BLIND_CELL_RUNTIME_BLOCKERS,
        ...(inboxRuntimeEnabled ? BLIND_INBOX_RUNTIME_BLOCKERS : []),
        ...(coreRuntimeEnabled ? BLIND_CORE_RUNTIME_BLOCKERS : [])
      ])
      : PRODUCTION_RUNTIME_EXCLUSIONS
    runtime = Object.freeze({
      descriptorState,
      admission,
      readiness,
      budget,
      coordinator,
      cellAdapter,
      inboxAdapter,
      coreAdapter,
      storage,
      inboxStorage,
      coreStorage,
      ...(testOnlyReplayJournalOptions == null
        ? {}
        : { testOnlyDurableReplayAuthority: durableReplayAuthority }),
      daemon,
      exclusions: runtimeExclusions,
      async start () {
        if (closed) throw new Error('blind production runtime is closed')
        if (!started) {
          await daemon.start()
          started = true
        }
        return runtime
      },
      close () {
        if (closePromise) return closePromise
        closed = true
        readiness.close()
        closePromise = (async () => {
          let failure = null
          try {
            await daemon.close()
          } catch (error) {
            failure = error
          }
          try {
            if (privateIpcReplayJournal) {
              await closePrivateIpcReplayJournalV2(privateIpcReplayJournal)
            }
          } catch (error) {
            failure = failure || error
          }
          try {
            if (coreStorage) await coreStorage.close()
          } catch (error) {
            failure = failure || error
          }
          try {
            if (inboxStorage) await inboxStorage.close()
          } catch (error) {
            failure = failure || error
          }
          try {
            await storage.close()
          } catch (error) {
            failure = failure || error
          } finally {
            signer.close()
          }
          if (failure) throw failure
        })()
        return closePromise
      },
      status () {
        const replayStatus = privateIpcReplayJournal == null
          ? privateIpcReplayFailure
          : privateIpcReplayJournalV2Status(privateIpcReplayJournal)
        return Object.freeze({
          started,
          closed,
          descriptorSequence: descriptorSnapshot.descriptorSequence,
          descriptorHash: b4a.from(descriptorSnapshot.hash),
          enabledOperationBits: replayStatus == null || replayStatus.ready
            ? enabledOperationBits
            : enabledOperationBits & ~CELL_PUT_OPERATION_BIT_V2,
          v2WritePathReady: v2WritePathReady && replayStatus != null && replayStatus.ready,
          v2WritePathAssembled,
          privateIpcReplayJournal: replayStatus,
          admissionCapture: Object.freeze({
            complete: admissionCapture.complete,
            required: admissionCapture.required,
            captured: admissionCapture.captured.size
          }),
          exclusions: runtimeExclusions,
          cell: cellAdapter == null ? null : cellAdapter.status(),
          storage: storage.status(),
          inbox: inboxAdapter == null ? null : inboxAdapter.status(),
          inboxStorage: inboxStorage == null ? null : inboxStorage.status(),
          core: coreAdapter == null ? null : coreAdapter.status(),
          coreStorage: coreStorage == null ? null : coreStorage.status()
        })
      }
    })
    return runtime
  } catch (error) {
    if (readiness) readiness.close()
    if (daemon) await daemon.close().catch(() => {})
    if (privateIpcReplayJournal) {
      await closePrivateIpcReplayJournalV2(privateIpcReplayJournal).catch(() => {})
    }
    if (coreStorage) await coreStorage.close().catch(() => {})
    if (inboxStorage) await inboxStorage.close().catch(() => {})
    if (storage) await storage.close().catch(() => {})
    if (signer) signer.close()
    else if (secretKey) secretKey.fill(0)
    throw error
  }
}
