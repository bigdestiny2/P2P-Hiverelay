import { createHash } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import { TextDecoder, types as utilTypes } from 'node:util'
import { Script, createContext } from 'node:vm'

const MAX_ADMISSION_ADAPTER_SCRIPT_BYTES = 256 * 1024
const MAX_ADMISSION_ADAPTER_MESSAGE_BYTES = 1024 * 1024
const MAX_ADMISSION_ADAPTER_DATA_NODES = 16 * 1024
const MAX_ADMISSION_ADAPTER_DATA_DEPTH = 32
const ADMISSION_ADAPTER_EXECUTION_TIMEOUT_MILLIS = 250
const ADMISSION_ADAPTER_SCHEMA = 'hiverelay-admission-adapter-script-v1'
const MAX_U64 = (1n << 64n) - 1n
const ABORT_SIGNAL_PROTOTYPE = AbortSignal.prototype
const ABORT_SIGNAL_ABORTED_GETTER = Object.getOwnPropertyDescriptor(
  ABORT_SIGNAL_PROTOTYPE, 'aborted').get
const REFLECT_APPLY = Reflect.apply
const BUFFER_IS_BUFFER = Buffer.isBuffer
const BUFFER_TO_STRING = Buffer.prototype.toString
const ARRAY_BUFFER_IS_VIEW = ArrayBuffer.isView
const IS_DATA_VIEW = utilTypes.isDataView
const IS_PROXY = utilTypes.isProxy
const IS_SHARED_ARRAY_BUFFER = utilTypes.isSharedArrayBuffer
const IS_TYPED_ARRAY = utilTypes.isTypedArray
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype)
const TYPED_ARRAY_BUFFER_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'buffer').get
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get
const TYPED_ARRAY_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteOffset').get
const DATA_VIEW_BUFFER_GETTER = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get
const DATA_VIEW_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get
const DATA_VIEW_BYTE_OFFSET_GETTER = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get
const BRIDGE_INVOKE_SLOT = '__hiverelay_admission_bridge_invoke_v1__'
const BRIDGE_OPERATION_SLOT = '__hiverelay_admission_bridge_operation_v1__'
const BRIDGE_PAYLOAD_SLOT = '__hiverelay_admission_bridge_payload_v1__'
const BRIDGE_PREFLIGHT_SLOT = '__hiverelay_admission_bridge_preflight_v1__'
const BRIDGE_INSTALL_SLOT = '__hiverelay_admission_bridge_install_v1__'
const BRIDGE_CANDIDATE_SLOT = '__hiverelay_admission_bridge_candidate_v1__'
const BRIDGE_TAKE_PREFLIGHT_SLOT = '__hiverelay_admission_bridge_take_preflight_v1__'
const FORBIDDEN_SOURCE_IDENTIFIERS = Object.freeze([
  ['import', /\bimport\b/u],
  ['Promise', /\bPromise\b/u],
  ['async', /\basync\b/u],
  ['await', /\bawait\b/u],
  ['Array.fromAsync', /\bArray\s*\.\s*fromAsync\b/u],
  ['process', /\bprocess\b/u],
  ['require', /\brequire\b/u],
  ['module', /\bmodule\b/u],
  ['global', /\bglobal\b/u],
  ['Buffer', /\bBuffer\b/u]
])
const MASKED_CONTEXT_GLOBALS = Object.freeze([
  'process',
  'require',
  'module',
  'exports',
  'global',
  'Buffer',
  'console',
  'fetch',
  'crypto',
  'performance',
  'structuredClone',
  'setTimeout',
  'setInterval',
  'setImmediate',
  'clearTimeout',
  'clearInterval',
  'clearImmediate',
  'queueMicrotask',
  'Promise',
  'Function',
  'eval',
  'WebAssembly',
  'SharedArrayBuffer',
  'Atomics',
  'FinalizationRegistry',
  'WeakRef'
])
const ADMISSION_ADAPTER_CONTEXT_HARDENING_SOURCE = String.raw`
(() => {
  'use strict'
  Object.defineProperty(Array, 'fromAsync', {
    value: undefined,
    writable: false,
    enumerable: false,
    configurable: false
  })
  return true
})()
`

export const PRODUCTION_RUNTIME_PROFILE = Object.freeze({
  DESCRIBE_ONLY_V1: 'DESCRIBE_ONLY_V1',
  CELL_V1: 'CELL_V1',
  CELL_INBOX_V1: 'CELL_INBOX_V1',
  CELL_INBOX_CORE_V1: 'CELL_INBOX_CORE_V1',
  // The bounded vNext direct-HTTPS public-test profile. This is the release
  // profile ID 1 (mask 0x0001ffff, the baseline 17 DESCRIBE/CELL/INBOX/CORE
  // operations) assembled for live public testing. Selecting it assembles the
  // full CELL/INBOX/CORE public execution line plus the bounded one-hop
  // FORWARD class (whose descriptor/readiness bits stay zero per the run's
  // forward-activation rule). It is distinct from the incremental runtime-line
  // selectors above, which remain fail-closed at the release gate.
  LIMITED_PUBLIC_TEST_V1: 'LIMITED_PUBLIC_TEST_V1'
})

export const PRODUCTION_ADMISSION_ADAPTER_SCRIPT_CONTRACT = Object.freeze({
  schema: ADMISSION_ADAPTER_SCHEMA,
  scriptFileEnvironment: 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE',
  scriptSha256Environment: 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256',
  synchronous: true,
  importFree: true,
  hostApis: Object.freeze([]),
  maximumScriptBytes: MAX_ADMISSION_ADAPTER_SCRIPT_BYTES,
  maximumMessageBytes: MAX_ADMISSION_ADAPTER_MESSAGE_BYTES,
  executionTimeoutMillis: ADMISSION_ADAPTER_EXECUTION_TIMEOUT_MILLIS
})

function entrypointFailure (code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause })
  error.code = code
  throw error
}

function optionalEnvironment (environment, name) {
  const value = environment[name]
  if (value == null || value === '') return null
  if (typeof value !== 'string') {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be a string`)
  }
  return value
}

function canonicalAbsolutePath (value, name) {
  if (value == null || !path.isAbsolute(value) || value.includes('\0') || path.normalize(value) !== value) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be one canonical absolute path`)
  }
  return value
}

function sha256Hex (value, name) {
  if (value == null || !/^[0-9a-f]{64}$/.test(value)) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be one canonical lowercase SHA-256 digest`)
  }
  return value
}

function profileFlags (profile) {
  switch (profile) {
    case PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1:
      return { enableCellRuntime: false, enableInboxRuntime: false, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_V1:
      return { enableCellRuntime: true, enableInboxRuntime: false, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_V1:
      return { enableCellRuntime: true, enableInboxRuntime: true, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_CORE_V1:
      return { enableCellRuntime: true, enableInboxRuntime: true, enableCoreRuntime: true }
    case PRODUCTION_RUNTIME_PROFILE.LIMITED_PUBLIC_TEST_V1:
      return { enableCellRuntime: true, enableInboxRuntime: true, enableCoreRuntime: true }
    default:
      entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
        'HIVERELAY_BLIND_RUNTIME_PROFILE must select one exact supported production runtime profile')
  }
}

export function loadProductionEntrypointConfig (environment = process.env, options = {}) {
  for (const legacy of [
    'HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE',
    'HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256'
  ]) {
    if (optionalEnvironment(environment, legacy) != null) {
      entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
        `${legacy} names the retired executable-module contract and is forbidden`)
    }
  }
  const profile = optionalEnvironment(environment, 'HIVERELAY_BLIND_RUNTIME_PROFILE')
  const flags = profileFlags(profile)
  const scriptFile = optionalEnvironment(environment, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE')
  const scriptSha256 = optionalEnvironment(environment, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256')

  if (!flags.enableCellRuntime) {
    if (scriptFile != null || scriptSha256 != null) {
      entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
        'DESCRIBE_ONLY_V1 forbids admission adapter script configuration')
    }
    return Object.freeze({ profile, ...flags, admissionAdapter: null })
  }

  if (options.allowInjectedAdmissionAdapter === true && scriptFile == null && scriptSha256 == null) {
    return Object.freeze({ profile, ...flags, admissionAdapter: null })
  }
  if (scriptFile == null || scriptSha256 == null) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
      'CELL runtime profiles require both an admission adapter script file and its exact SHA-256 digest')
  }
  return Object.freeze({
    profile,
    ...flags,
    admissionAdapter: Object.freeze({
      scriptFile: canonicalAbsolutePath(scriptFile, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE'),
      scriptSha256: sha256Hex(scriptSha256, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256')
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

async function readProtectedScript (file, expectedSha256, identity) {
  let handle
  try {
    handle = await fs.open(file, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(file)])
    const currentUid = typeof identity?.getuid === 'function' ? identity.getuid() : null
    if (!opened.isFile() || linked.isSymbolicLink() || !sameInode(opened, linked) || opened.size < 1 ||
        opened.size > MAX_ADMISSION_ADAPTER_SCRIPT_BYTES || linked.nlink !== 1 || (linked.mode & 0o022) !== 0 ||
        currentUid == null || (linked.uid !== currentUid && linked.uid !== 0) || await fs.realpath(file) !== file) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
        'admission adapter script must be a stable root- or daemon-owned protected regular file')
    }
    const bytes = await handle.readFile()
    const [after, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(file)])
    if (!sameFileState(opened, after) || !sameFileState(after, linkedAfter) ||
        bytes.byteLength !== opened.size || await fs.realpath(file) !== file) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
        'admission adapter script changed while its exact bytes were read')
    }
    const actualSha256 = createHash('sha256').update(bytes).digest('hex')
    if (actualSha256 !== expectedSha256) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH',
        'admission adapter script does not match its exact configured SHA-256 digest')
    }
    return bytes
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('BLIND_')) throw error
    entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      'admission adapter script could not be opened as a protected file', error)
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

function decodeAdapterSource (bytes) {
  let source
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch (error) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      'admission adapter script must be exact valid UTF-8', error)
  }
  if (source.includes('\0')) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      'admission adapter script must not contain NUL bytes')
  }
  for (const [name, pattern] of FORBIDDEN_SOURCE_IDENTIFIERS) {
    if (pattern.test(source)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
        `admission adapter script contains forbidden ${name} syntax or authority`)
    }
  }
  return source
}

function taggedRecord (type, valueName, value) {
  const record = Object.create(null)
  record.$hiverelayType = type
  record[valueName] = value
  return record
}

function encodeHostData (value, state = { nodes: 0, seen: new Set() }, depth = 0) {
  state.nodes++
  if (state.nodes > MAX_ADMISSION_ADAPTER_DATA_NODES || depth > MAX_ADMISSION_ADAPTER_DATA_DEPTH) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
      'admission adapter input exceeds the bounded data graph')
  }
  if (value == null || typeof value === 'boolean') return value
  if (typeof value === 'string') {
    if (value.length > MAX_ADMISSION_ADAPTER_MESSAGE_BYTES) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID', 'admission adapter string input is oversized')
    }
    return value
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter numeric input must be one safe integer')
    }
    return value
  }
  if (typeof value === 'bigint') {
    if (value < 0n || value > MAX_U64) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID', 'admission adapter bigint input is outside u64')
    }
    return taggedRecord('u64', 'value', value.toString())
  }
  if (typeof value !== 'object') {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
      'admission adapter input contains an unsupported value')
  }
  if (IS_PROXY(value)) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
      'admission adapter input contains a Proxy')
  }
  if (BUFFER_IS_BUFFER(value) || ARRAY_BUFFER_IS_VIEW(value)) {
    const dataView = IS_DATA_VIEW(value)
    if (!dataView && !IS_TYPED_ARRAY(value)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter byte input is not one supported ArrayBuffer view')
    }
    const arrayBuffer = REFLECT_APPLY(
      dataView ? DATA_VIEW_BUFFER_GETTER : TYPED_ARRAY_BUFFER_GETTER, value, [])
    if (IS_SHARED_ARRAY_BUFFER(arrayBuffer)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter byte input must not use shared memory')
    }
    const byteOffset = REFLECT_APPLY(
      dataView ? DATA_VIEW_BYTE_OFFSET_GETTER : TYPED_ARRAY_BYTE_OFFSET_GETTER, value, [])
    const byteLength = REFLECT_APPLY(
      dataView ? DATA_VIEW_BYTE_LENGTH_GETTER : TYPED_ARRAY_BYTE_LENGTH_GETTER, value, [])
    const bytes = Buffer.from(arrayBuffer, byteOffset, byteLength)
    return taggedRecord('bytes', 'hex', REFLECT_APPLY(BUFFER_TO_STRING, bytes, ['hex']))
  }
  if (state.seen.has(value)) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID', 'admission adapter input contains a cycle')
  }
  state.seen.add(value)
  let encoded
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter input array has a forbidden prototype')
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Reflect.ownKeys(descriptors).filter(key => key !== 'length')
    if (keys.some((key, index) => typeof key !== 'string' || key !== String(index) ||
        !Object.prototype.hasOwnProperty.call(descriptors[key], 'value'))) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter input array must contain only contiguous own data elements')
    }
    encoded = keys.map(key => encodeHostData(descriptors[key].value, state, depth + 1))
  } else {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter input record has a forbidden prototype')
    }
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const keys = Reflect.ownKeys(descriptors)
    if (keys.some(key => typeof key !== 'string' ||
        !Object.prototype.hasOwnProperty.call(descriptors[key], 'value'))) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter input record must contain only own data properties')
    }
    encoded = Object.create(null)
    for (const key of keys.sort()) {
      if (key === 'signal') encoded.signal = null
      else if (key !== 'adapterPreflight') {
        encoded[key] = encodeHostData(descriptors[key].value, state, depth + 1)
      }
    }
  }
  state.seen.delete(value)
  return encoded
}

function decodeHostData (value, state = { nodes: 0 }, depth = 0) {
  state.nodes++
  if (state.nodes > MAX_ADMISSION_ADAPTER_DATA_NODES || depth > MAX_ADMISSION_ADAPTER_DATA_DEPTH) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
      'admission adapter output exceeds the bounded data graph')
  }
  if (value == null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
        'admission adapter output number is not a safe integer')
    }
    return value
  }
  if (typeof value !== 'object') {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
      'admission adapter output contains an unsupported value')
  }
  if (Array.isArray(value)) return value.map(entry => decodeHostData(entry, state, depth + 1))
  const keys = Object.keys(value).sort()
  if (Object.prototype.hasOwnProperty.call(value, '$hiverelayType')) {
    if (value.$hiverelayType === 'bytes' && keys.length === 2 && keys[0] === '$hiverelayType' &&
        keys[1] === 'hex' && typeof value.hex === 'string' && /^(?:[0-9a-f]{2})*$/.test(value.hex) &&
        value.hex.length <= MAX_ADMISSION_ADAPTER_MESSAGE_BYTES * 2) {
      return Buffer.from(value.hex, 'hex')
    }
    if (value.$hiverelayType === 'u64' && keys.length === 2 && keys[0] === '$hiverelayType' &&
        keys[1] === 'value' && typeof value.value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value.value)) {
      const decoded = BigInt(value.value)
      if (decoded <= MAX_U64) return decoded
    }
    entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
      'admission adapter output contains one invalid tagged value')
  }
  const decoded = Object.create(null)
  for (const key of keys) decoded[key] = decodeHostData(value[key], state, depth + 1)
  return decoded
}

const ADMISSION_ADAPTER_BRIDGE_SOURCE = String.raw`
(() => {
  'use strict'
  const schema = 'hiverelay-admission-adapter-script-v1'
  const maxDepth = 32
  const maxNodes = 16384
  const maxString = 1048576
  const parse = JSON.parse
  const stringify = JSON.stringify
  const objectKeys = Object.keys
  const objectCreate = Object.create
  const objectFreeze = Object.freeze
  const objectIsFrozen = Object.isFrozen
  const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor
  const objectGetPrototypeOf = Object.getPrototypeOf
  const objectHasOwnProperty = Object.prototype.hasOwnProperty
  const objectPrototype = Object.prototype
  const BridgeTypeError = TypeError
  const arrayPrototype = Array.prototype
  const arrayIsArray = Array.isArray
  const arraySort = arrayPrototype.sort
  const numberIsSafeInteger = Number.isSafeInteger
  const regexpTest = RegExp.prototype.test
  const reflectApply = Reflect.apply
  const reflectOwnKeys = Reflect.ownKeys
  const mapGet = Map.prototype.get
  const mapSet = Map.prototype.set
  const mapDelete = Map.prototype.delete
  const mapHas = Map.prototype.has
  const call = (fn, receiver, args) => reflectApply(fn, receiver, args)
  const byteHexPattern = /^(?:[0-9a-f]{2})*$/
  const u64Pattern = /^(?:0|[1-9][0-9]{0,19})$/
  const maps = {
    get: (map, key) => call(mapGet, map, [key]),
    set: (map, key, value) => call(mapSet, map, [key, value]),
    delete: (map, key) => call(mapDelete, map, [key]),
    has: (map, key) => call(mapHas, map, [key])
  }
  let contract = null
  let factory = null
  let resolver = null
  let nextAdapterId = 1
  let pendingPreflight = null
  const adapters = new Map()
  objectFreeze(arrayPrototype)

  function fail (message) {
    throw new BridgeTypeError(message)
  }

  function hasKey (keys, expected) {
    for (let index = 0; index < keys.length; index++) {
      if (keys[index] === expected) return true
    }
    return false
  }

  function ownData (value, key) {
    const descriptor = objectGetOwnPropertyDescriptor(value, key)
    if (!descriptor || !call(objectHasOwnProperty, descriptor, ['value'])) {
      fail('data must contain only own data properties')
    }
    return descriptor.value
  }

  function sortedDataKeys (value) {
    const keys = reflectOwnKeys(value)
    for (let index = 0; index < keys.length; index++) {
      if (typeof keys[index] !== 'string') fail('data record keys must be strings')
      ownData(value, keys[index])
    }
    return call(arraySort, keys, [])
  }

  function exactKeys (value, expected) {
    const actual = reflectOwnKeys(value)
    if (actual.length !== expected.length) return false
    for (let index = 0; index < actual.length; index++) {
      if (typeof actual[index] !== 'string') return false
      const descriptor = objectGetOwnPropertyDescriptor(value, actual[index])
      if (!descriptor || descriptor.enumerable !== true ||
          !call(objectHasOwnProperty, descriptor, ['value'])) return false
    }
    call(arraySort, actual, [])
    for (let index = 0; index < actual.length; index++) {
      if (actual[index] !== expected[index]) return false
    }
    return true
  }

  function data (value, state, depth) {
    state.nodes++
    if (state.nodes > maxNodes || depth > maxDepth) fail('data graph is outside its bound')
    if (value === null || typeof value === 'boolean') return value
    if (typeof value === 'string') {
      if (value.length > maxString) fail('string is outside its bound')
      return value
    }
    if (typeof value === 'number') {
      if (!numberIsSafeInteger(value)) fail('number must be a safe integer')
      return value
    }
    if (typeof value !== 'object') fail('unsupported data value')
    if (arrayIsArray(value)) {
      const length = ownData(value, 'length')
      if (!numberIsSafeInteger(length) || length < 0 || reflectOwnKeys(value).length !== length + 1) {
        fail('data array must contain only contiguous own data elements')
      }
      const output = []
      for (let index = 0; index < length; index++) {
        output[index] = data(ownData(value, String(index)), state, depth + 1)
      }
      return objectFreeze(output)
    }
    const prototype = objectGetPrototypeOf(value)
    if (prototype !== objectPrototype && prototype !== null) fail('data record has a forbidden prototype')
    const keys = sortedDataKeys(value)
    if (keys.length > maxNodes) fail('data record has too many fields')
    if (hasKey(keys, '$hiverelayType')) {
      const type = ownData(value, '$hiverelayType')
      if (type === 'bytes' && exactKeys(value, ['$hiverelayType', 'hex']) &&
          typeof ownData(value, 'hex') === 'string' &&
          call(regexpTest, byteHexPattern, [ownData(value, 'hex')]) &&
          ownData(value, 'hex').length <= maxString * 2) {
        const tagged = objectCreate(null)
        tagged.$hiverelayType = 'bytes'
        tagged.hex = ownData(value, 'hex')
        return objectFreeze(tagged)
      }
      if (type === 'u64' && exactKeys(value, ['$hiverelayType', 'value']) &&
          typeof ownData(value, 'value') === 'string' &&
          call(regexpTest, u64Pattern, [ownData(value, 'value')])) {
        const tagged = objectCreate(null)
        tagged.$hiverelayType = 'u64'
        tagged.value = ownData(value, 'value')
        return objectFreeze(tagged)
      }
      fail('invalid tagged data value')
    }
    const output = objectCreate(null)
    for (let index = 0; index < keys.length; index++) {
      const key = keys[index]
      if (typeof key !== 'string' || key.length === 0 || key.length > 256) fail('invalid data record key')
      output[key] = data(ownData(value, key), state, depth + 1)
    }
    return objectFreeze(output)
  }

  function parseInput (payload) {
    if (typeof payload !== 'string' || payload.length > maxString) fail('invalid bridge payload')
    return data(parse(payload), { nodes: 0 }, 0)
  }

  function response (value) {
    const encoded = data(value, { nodes: 0 }, 0)
    const output = stringify(encoded)
    if (typeof output !== 'string' || output.length > maxString) fail('invalid bridge response')
    return output
  }

  function synchronous (value, label) {
    if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
      let then
      try { then = value.then } catch { fail(label + ' exposed a throwing then property') }
      if (typeof then === 'function') fail(label + ' must be synchronous and non-thenable')
    }
    return value
  }

  function adapter (id) {
    if (!numberIsSafeInteger(id) || id < 1 || !maps.has(adapters, id)) fail('unknown adapter id')
    return maps.get(adapters, id)
  }

  function install (candidate) {
    if (contract !== null) fail('adapter contract is already installed')
    if (!candidate || typeof candidate !== 'object' ||
        !exactKeys(candidate, ['createAdmissionAdapterResolver', 'schema']) ||
        ownData(candidate, 'schema') !== schema ||
        typeof ownData(candidate, 'createAdmissionAdapterResolver') !== 'function') {
      fail('script completion value does not implement the exact adapter contract')
    }
    contract = candidate
    factory = ownData(candidate, 'createAdmissionAdapterResolver')
    return true
  }

  function invoke (operation, payload, retainedPreflight) {
    if (contract === null || typeof operation !== 'string') fail('adapter bridge is not installed')
    const input = parseInput(payload)
    if (operation === 'initialize') {
      if (resolver !== null) fail('adapter resolver is already initialized')
      const created = synchronous(call(factory, contract, [input]), 'adapter factory')
      if (typeof created !== 'function') fail('adapter factory returned no resolver')
      resolver = created
      return response({ contractVersion: 1 })
    }
    if (operation === 'resolve') {
      if (resolver === null) fail('adapter resolver is not initialized')
      const resolved = synchronous(call(resolver, undefined, [input]), 'adapter resolver')
      if (resolved == null) return response({ adapterId: null })
      if (typeof resolved !== 'object' || !exactKeys(resolved,
        ['confirmAfterEof', 'prepare', 'preparePreflight']) ||
        typeof ownData(resolved, 'prepare') !== 'function' ||
        typeof ownData(resolved, 'preparePreflight') !== 'function' ||
        typeof ownData(resolved, 'confirmAfterEof') !== 'function') {
        fail('adapter resolver returned no exact synchronous adapter')
      }
      const adapterId = nextAdapterId++
      maps.set(adapters, adapterId, resolved)
      return response({ adapterId })
    }
    if (!input || typeof input !== 'object' || !numberIsSafeInteger(input.adapterId)) {
      fail('adapter invocation is malformed')
    }
    const selected = adapter(input.adapterId)
    if (operation === 'prepare') {
      return response(synchronous(call(ownData(selected, 'prepare'), selected, [input.input]), 'adapter prepare'))
    }
    if (operation === 'preparePreflight') {
      if (pendingPreflight !== null) fail('previous preflight capability was not collected')
      const capability = synchronous(call(ownData(selected, 'preparePreflight'), selected, [input.input]),
        'adapter preparePreflight')
      if (!capability || typeof capability !== 'object' || !objectIsFrozen(capability) ||
          reflectOwnKeys(capability).length !== 0) {
        fail('adapter preparePreflight returned no empty frozen capability')
      }
      const output = response({ preflightReady: true })
      pendingPreflight = capability
      return output
    }
    if (operation === 'confirmAfterEof') {
      if (!retainedPreflight || typeof retainedPreflight !== 'object' ||
          !objectIsFrozen(retainedPreflight) || reflectOwnKeys(retainedPreflight).length !== 0) {
        fail('adapter confirmation has no retained same-realm preflight capability')
      }
      if (!input.input || typeof input.input !== 'object') fail('adapter confirmation input is malformed')
      const confirmedInput = objectCreate(null)
      const inputKeys = objectKeys(input.input)
      for (let index = 0; index < inputKeys.length; index++) {
        const key = inputKeys[index]
        confirmedInput[key] = input.input[key]
      }
      confirmedInput.adapterPreflight = retainedPreflight
      objectFreeze(confirmedInput)
      return response(synchronous(call(ownData(selected, 'confirmAfterEof'), selected, [confirmedInput]),
        'adapter confirmAfterEof'))
    }
    fail('unknown adapter bridge operation')
  }

  function takePreflight () {
    if (pendingPreflight === null) fail('adapter bridge has no pending preflight capability')
    const capability = pendingPreflight
    pendingPreflight = null
    return capability
  }

  return objectFreeze([install, invoke, takePreflight])
})()
`

function adapterVmContext () {
  const sandbox = Object.create(null)
  for (const name of MASKED_CONTEXT_GLOBALS) {
    Object.defineProperty(sandbox, name, {
      value: undefined,
      writable: false,
      enumerable: false,
      configurable: false
    })
  }
  return createContext(sandbox, {
    name: 'hiverelay-production-admission-adapter-v1',
    codeGeneration: { strings: false, wasm: false },
    microtaskMode: 'afterEvaluate'
  })
}

function runBoundedScript (script, context, code, message) {
  try {
    return script.runInContext(context, { timeout: ADMISSION_ADAPTER_EXECUTION_TIMEOUT_MILLIS })
  } catch {
    entrypointFailure(code, message)
  }
}

function compileScript (source, filename, code, message) {
  try {
    return new Script(source, { filename })
  } catch (error) {
    entrypointFailure(code, message, error)
  }
}

function createAdapterBridge (source, scriptFile) {
  const context = adapterVmContext()
  const hardened = runBoundedScript(
    compileScript(ADMISSION_ADAPTER_CONTEXT_HARDENING_SOURCE,
      'hiverelay-admission-adapter-context-hardening-v1.js',
      'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID', 'admission adapter context hardening did not compile'),
    context,
    'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
    'admission adapter context hardening did not initialize'
  )
  if (hardened !== true) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      'admission adapter context hardening returned no exact success marker')
  }
  const bridge = runBoundedScript(
    compileScript(ADMISSION_ADAPTER_BRIDGE_SOURCE, 'hiverelay-admission-adapter-bridge-v1.js',
      'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID', 'admission adapter bridge did not compile'),
    context,
    'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
    'admission adapter bridge did not initialize'
  )
  const candidate = runBoundedScript(
    compileScript(source, scriptFile, 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
      'admission adapter script is not valid Script syntax'),
    context,
    'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
    'admission adapter script failed while producing its contract completion value'
  )
  Object.defineProperties(context, {
    [BRIDGE_INSTALL_SLOT]: { value: bridge[0], configurable: true },
    [BRIDGE_CANDIDATE_SLOT]: { value: candidate, configurable: true }
  })
  try {
    const install = compileScript(`${BRIDGE_INSTALL_SLOT}(${BRIDGE_CANDIDATE_SLOT})`,
      'hiverelay-admission-adapter-install-v1.js', 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID',
      'admission adapter install bridge did not compile')
    runBoundedScript(install, context, 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID',
      'admission adapter script exported no exact contract object')
  } finally {
    delete context[BRIDGE_INSTALL_SLOT]
    delete context[BRIDGE_CANDIDATE_SLOT]
  }
  Object.defineProperties(context, {
    [BRIDGE_INVOKE_SLOT]: { value: bridge[1], writable: false, configurable: false },
    [BRIDGE_TAKE_PREFLIGHT_SLOT]: { value: bridge[2], writable: false, configurable: false },
    [BRIDGE_OPERATION_SLOT]: { value: '', writable: true, configurable: false },
    [BRIDGE_PAYLOAD_SLOT]: { value: '', writable: true, configurable: false },
    [BRIDGE_PREFLIGHT_SLOT]: { value: undefined, writable: true, configurable: false }
  })
  const invoke = compileScript(
    `${BRIDGE_INVOKE_SLOT}(${BRIDGE_OPERATION_SLOT}, ${BRIDGE_PAYLOAD_SLOT}, ${BRIDGE_PREFLIGHT_SLOT})`,
    'hiverelay-admission-adapter-invoke-v1.js', 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
    'admission adapter invocation bridge did not compile')
  const takePreflight = compileScript(`${BRIDGE_TAKE_PREFLIGHT_SLOT}()`,
    'hiverelay-admission-adapter-take-preflight-v1.js', 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID',
    'admission adapter preflight bridge did not compile')

  const execute = (operation, input, code, message, retainedPreflight = undefined) => {
    const encoded = JSON.stringify(encodeHostData(input))
    if (Buffer.byteLength(encoded) > MAX_ADMISSION_ADAPTER_MESSAGE_BYTES) {
      entrypointFailure(code, `${message}: encoded input exceeds the bridge bound`)
    }
    context[BRIDGE_OPERATION_SLOT] = operation
    context[BRIDGE_PAYLOAD_SLOT] = encoded
    context[BRIDGE_PREFLIGHT_SLOT] = retainedPreflight
    let output
    try {
      output = runBoundedScript(invoke, context, code, message)
    } finally {
      context[BRIDGE_OPERATION_SLOT] = ''
      context[BRIDGE_PAYLOAD_SLOT] = ''
      context[BRIDGE_PREFLIGHT_SLOT] = undefined
    }
    if (typeof output !== 'string' || Buffer.byteLength(output) > MAX_ADMISSION_ADAPTER_MESSAGE_BYTES) {
      entrypointFailure(code, `${message}: script returned no bounded primitive JSON string`)
    }
    let decoded
    try {
      decoded = JSON.parse(output)
    } catch (error) {
      entrypointFailure(code, `${message}: script returned malformed JSON`, error)
    }
    return decodeHostData(decoded)
  }
  return Object.freeze({
    execute,
    takePreflight (code, message) {
      return runBoundedScript(takePreflight, context, code, message)
    }
  })
}

function adapterBootstrapData (config, bootstrap) {
  if (!bootstrap || !bootstrap.launchTopologyHash || !Array.isArray(bootstrap.endpointIds)) {
    throw new TypeError('validated daemon bootstrap configuration is required for the admission adapter')
  }
  return {
    contractVersion: 1,
    runtimeProfile: config.profile,
    launchTopologyHash: Buffer.from(bootstrap.launchTopologyHash),
    endpointIds: [...bootstrap.endpointIds]
  }
}

function exactResponse (value, keys) {
  if (!value || typeof value !== 'object') return false
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

function signalFrom (input) {
  let signal = null
  if (input != null) {
    if (typeof input !== 'object') throw new TypeError('admission adapter input must be an object')
    if (IS_PROXY(input)) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
        'admission adapter input must not be a Proxy')
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, 'signal')
    if (descriptor != null) {
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        entrypointFailure('BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID',
          'admission adapter input signal must be an own data property')
      }
      signal = descriptor.value
    }
  }
  if (signal != null && (typeof signal !== 'object' || IS_PROXY(signal) ||
      Object.getPrototypeOf(signal) !== ABORT_SIGNAL_PROTOTYPE)) {
    throw new TypeError('admission adapter signal must be one direct AbortSignal or null')
  }
  if (signal != null && REFLECT_APPLY(ABORT_SIGNAL_ABORTED_GETTER, signal, [])) {
    const error = new Error('admission adapter call crossed its abort fence')
    error.code = 'ABORT_ERR'
    throw error
  }
  return signal
}

function assertSignalRemainsLive (signal) {
  if (signal != null && REFLECT_APPLY(ABORT_SIGNAL_ABORTED_GETTER, signal, [])) {
    const error = new Error('admission adapter call crossed its abort fence')
    error.code = 'ABORT_ERR'
    throw error
  }
}

export async function loadProductionAdmissionAdapter (config, bootstrap, options = {}) {
  if (!config || config.enableCellRuntime !== true || !config.admissionAdapter) {
    throw new TypeError('an explicit CELL production entrypoint configuration is required')
  }
  const bytes = await readProtectedScript(config.admissionAdapter.scriptFile,
    config.admissionAdapter.scriptSha256, options.identity || process)
  const source = decodeAdapterSource(bytes)
  const bridge = createAdapterBridge(source, config.admissionAdapter.scriptFile)
  const initialized = bridge.execute('initialize', adapterBootstrapData(config, bootstrap),
    'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED',
    'admission adapter script initialization failed')
  if (!exactResponse(initialized, ['contractVersion']) || initialized.contractVersion !== 1) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED',
      'admission adapter script returned no exact initialization acknowledgement')
  }
  const preflightCapabilities = new WeakMap()

  function adapterWrapper (adapterId) {
    return Object.freeze({
      prepare (input) {
        const signal = signalFrom(input)
        const prepared = bridge.execute('prepare', { adapterId, input },
          'BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED', 'admission adapter prepare failed')
        assertSignalRemainsLive(signal)
        return prepared
      },
      preparePreflight (input) {
        const signal = signalFrom(input)
        const result = bridge.execute('preparePreflight', { adapterId, input },
          'BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED', 'admission adapter preflight failed')
        const vmCapability = bridge.takePreflight('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
          'admission adapter preflight capability could not be collected')
        assertSignalRemainsLive(signal)
        if (!exactResponse(result, ['preflightReady']) || result.preflightReady !== true) {
          entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
            'admission adapter preflight returned no exact capability acknowledgement')
        }
        const capability = Object.freeze({})
        preflightCapabilities.set(capability, Object.freeze({ adapterId, vmCapability }))
        return capability
      },
      confirmAfterEof (input) {
        const signal = signalFrom(input)
        const descriptor = input == null ? null : Object.getOwnPropertyDescriptor(input, 'adapterPreflight')
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
          entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
            'admission adapter confirmation has no own host capability')
        }
        const capability = descriptor.value
        const retained = capability && preflightCapabilities.get(capability)
        if (!retained || retained.adapterId !== adapterId) {
          entrypointFailure('BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED',
            'admission adapter confirmation has no live host capability')
        }
        preflightCapabilities.delete(capability)
        const prepared = bridge.execute('confirmAfterEof', {
          adapterId,
          input
        }, 'BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED', 'admission adapter confirmation failed',
        retained.vmCapability)
        assertSignalRemainsLive(signal)
        return prepared
      }
    })
  }

  return Object.freeze({
    scriptFile: config.admissionAdapter.scriptFile,
    scriptSha256: config.admissionAdapter.scriptSha256,
    resolveAdmissionAdapter (input) {
      const signal = signalFrom(input)
      const result = bridge.execute('resolve', input, 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED',
        'admission adapter required-profile resolution failed')
      assertSignalRemainsLive(signal)
      if (!exactResponse(result, ['adapterId']) || !Number.isSafeInteger(result.adapterId) ||
          result.adapterId < 1) {
        entrypointFailure('BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED',
          'admission adapter script resolved no exact adapter for a required profile')
      }
      return adapterWrapper(result.adapterId)
    }
  })
}
