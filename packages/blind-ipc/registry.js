import b4a from 'b4a'
import c from 'compact-encoding'
import {
  FAMILY,
  OUTER_CLASS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  hashImportedWireAbi,
  privateBlake2b256
} from './private-hashes.js'
import {
  LOCAL_ABORT_CODE,
  LOCAL_CIPHERTEXT_BYTES,
  LOCAL_CIPHERTEXT_PHASE,
  LOCAL_STREAM_ADJACENT_POLICY,
  LOCAL_STREAM_CONTEXT_KIND,
  LOCAL_STREAM_CONTROL_BYTES,
  LOCAL_STREAM_CONTROL_KIND,
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LOCAL_STREAM_MODE,
  LOCAL_STREAM_OPEN_COMBINATION,
  LOCAL_STREAM_OPEN_KIND,
  LOCAL_STREAM_OPEN_TABLE,
  PRIVATE_IPC_LIMITS,
  PRIVATE_IPC_TIMING_MILLIS
} from './policy.js'

const FORMAT_DOMAIN = b4a.from('hiverelay.blind.private-ipc-format-hash.v1', 'ascii')
const VECTOR_DOMAIN = b4a.from('hiverelay.blind.private-ipc-vector-set-hash.v1', 'ascii')
const MAX_PRIVATE_IPC_REGISTRY_BYTES = 1024 * 1024
const MAX_PRIVATE_IPC_LIST_ITEMS = 4096

function registryFailure (message) {
  const error = new Error(message)
  error.code = 'BAD_PRIVATE_IPC_REGISTRY'
  throw error
}

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') registryFailure(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return b4a.from(value)
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

export const PRIVATE_IPC_SCHEMAS = Object.freeze([
  Object.freeze({
    schemaId: 1,
    schemaName: 'LocalDispatchV1',
    fields: Object.freeze([
      'totalLength:u32be', 'version:u8=1', 'family:wire-family-u8',
      'transportId:wire-transport-u8-or-ready-zero',
      'transportSupportBit:u16be[one-hot-wire-support-or-ready-zero]',
      'endpointId:u8[1..255]', 'outerClass:wire-outer-class-u8-or-ready-zero',
      'acceptedMonotonicMillis:u64be', 'absoluteDeadlineMonotonicMillis:u64be',
      'adjacentRelayKeyPresent:u8[0..1]', 'adjacentRelayKey:optional-fixed32[nonzero]',
      'bodyLength:u32be[class-exact-or-ready65]', 'externalCanonicalBytes:bytes[bodyLength]',
      'readyVariant:DESCRIBE|transport0|support0|outer0|no-adjacent|deadline=t0+2000'
    ])
  }),
  Object.freeze({
    schemaId: 2,
    schemaName: 'LocalUnaryResponseV1',
    fields: Object.freeze([
      'totalLength:u32be', 'version:u8=1', 'responseKind:u8[1..3]', 'localBrokerError:u8[0..6]',
      'bodyLength:u32be[class-exact-or-zero-or-ready120]', 'externalCanonicalBytes:bytes[bodyLength]'
    ])
  }),
  Object.freeze({
    schemaId: 3,
    schemaName: 'LocalStreamOpenV1',
    fields: Object.freeze([
      'totalLength:u32be', 'version:u8=1', 'openKind:u8[1..4]', 'transportId:wire-transport-u8',
      'transportSupportBit:u16be[one-hot-wire-support]', 'endpointId:u8[1..255]',
      'streamMode:u8[1..5]', 'channelClass:u8[closed-combination]',
      'acceptedMonotonicMillis:u64be', 'openDeadlineMonotonicMillis:u64be',
      'adjacentRelayKeyPresent:u8[0..1]', 'adjacentRelayKey:optional-fixed32[nonzero]',
      'contextLength:u32be[exact-by-open-combination]', 'context:closed-canonical-private-context',
      'combination1:open1|mode1|class1..3|context1:225|adjacent-optional',
      'combination2:open1|mode2|class1..3|context1:225|adjacent-optional',
      'combination3:open2|mode3|class1..3|context2:137|adjacent-required',
      'combination4:open3|mode4|class0|context2:137|adjacent-forbidden',
      'combination5:open4|mode5|class1..3|context2:137|adjacent-forbidden'
    ])
  }),
  Object.freeze({
    schemaId: 4,
    schemaName: 'LocalStreamFrameV1',
    fields: Object.freeze([
      'totalLength:u32be', 'version:u8=1', 'direction:u8[1..2]', 'frameKind:u8[1..5]',
      'sequence:u64be[first0-exact+1-per-physical-direction]', 'wireClass:u8[0..3]',
      'flags:u8[FIN-only]', 'bodyLength:u32be[kind/class/phase-bound]', 'bytes:bytes[bodyLength]',
      'CONTENT:class1..3|max=classBytes-23|zero-only-with-FIN',
      'CORE_RAW:class0|bytes0..65535|zero-only-with-FIN',
      'CIPHERTEXT:class0=flights32,96,64|class1..3=exact-class|FIN-forbidden',
      'CONTROL:class0|flags0|exact-LocalStreamControlV1',
      'ABORT:class0|flags0|one-registered-generic-code'
    ])
  }),
  Object.freeze({
    schemaId: 5,
    schemaName: 'LocalAuthenticatedChannelV1',
    fields: Object.freeze([
      'version:u8=1', 'edgeProcessNonce:fixed32[nonzero]', 'localChannelNonce:fixed32[nonzero]',
      'parentSessionId:fixed32[derived-nonzero]', 'transportProfileHash:fixed32[nonzero]',
      'finalNoiseHandshakeHash:fixed64[nonzero]', 'channelBindingMac:fixed32[keyed-blake2b]',
      'exporter-domain:hiverelay.blind.native-session-exporter.v1',
      'parent-domain:hiverelay.blind.private-parent-session.v1',
      'binding-domain:hiverelay.blind.private-channel-binding.v1',
      'authority:constant-time-verify-to-opaque-branded-handle'
    ])
  }),
  Object.freeze({
    schemaId: 6,
    schemaName: 'LocalStreamAttachContextV1',
    fields: Object.freeze([
      'version:u8=1', 'ticket:fixed32[nonzero-one-use]', 'parentSessionId:fixed32[nonzero]',
      'descriptorSequence:u64be[nonzero]', 'descriptorHash:fixed32[nonzero]', 'bindingHash:fixed32[nonzero]',
      'ticket:delete-before-compare|ttl<=2000ms|pending<=1024',
      'authority:successful-consume-to-opaque-branded-handle'
    ])
  }),
  Object.freeze({
    schemaId: 7,
    schemaName: 'LocalStreamControlV1',
    fields: Object.freeze([
      'version:u8=1', 'controlKind:u8[closed-1..7]', 'controlId:u64be[nonzero]',
      'CHANNEL_ACCEPT:bindingHash32|total42',
      'CHANNEL_REJECT:localBrokerError-u8|total11',
      'ATTACH_TICKET:ticket32|bindingHash32|total74',
      'EGRESS_DIAL:endpointBindingHash32|bindingTableHash32|transportProfileHash32|wireClass-u8|deadline-u64|maxOpen-u32|maxStream-u64|idle-u32|lifetime-u32|ticket32|total167',
      'EGRESS_RESULT:status-u8|endpointBindingHash32|adjacent-tag-and-optional32|ticket32|failure76-or-success108',
      'CORE_CHILD_OPEN:streamId-u64|ticket32|bindingHash32|total82',
      'NOISE_SESSION_OPEN:endpointBindingHash32|handshakeProfileHash32|prologueHash32|wireClass-u8|ticket32|total139',
      'no-freeform-payload-or-text'
    ])
  })
])

const LOCAL_BINDINGS = Object.freeze({
  responseKind: Object.freeze({ EXTERNAL_CANONICAL: 1, LOCAL_BROKER_ERROR: 2, LOCAL_READY_ACK: 3 }),
  controlKind: Object.freeze({ EDGE_READY: 1 }),
  localBrokerError: Object.freeze({
    MALFORMED_IPC: 1,
    UNAUTHORIZED_EDGE_PEER: 2,
    TOPOLOGY_PROFILE_ENDPOINT_MISMATCH: 3,
    CLASS_LENGTH_CAP: 4,
    DAEMON_DRAINING: 5,
    INTERNAL_IPC_FAILURE: 6
  }),
  streamOpenKind: LOCAL_STREAM_OPEN_KIND,
  streamMode: LOCAL_STREAM_MODE,
  streamContextKind: LOCAL_STREAM_CONTEXT_KIND,
  streamAdjacentPolicy: LOCAL_STREAM_ADJACENT_POLICY,
  streamOpenCombination: LOCAL_STREAM_OPEN_COMBINATION,
  streamDirection: LOCAL_STREAM_DIRECTION,
  streamFlag: LOCAL_STREAM_FLAG,
  streamFrameKind: LOCAL_STREAM_FRAME_KIND,
  streamControlKind: LOCAL_STREAM_CONTROL_KIND,
  ciphertextPhase: LOCAL_CIPHERTEXT_PHASE,
  ciphertextBytes: LOCAL_CIPHERTEXT_BYTES,
  streamControlBytes: LOCAL_STREAM_CONTROL_BYTES,
  localAbortCode: LOCAL_ABORT_CODE,
  readyRules: Object.freeze({ REQUIRED_DESCRIBE_OPERATION_BITS: 0x00000007, ENABLED_OPERATION_BITS_MASK: 0x003fffff }),
  limits: PRIVATE_IPC_LIMITS,
  timingMillis: PRIVATE_IPC_TIMING_MILLIS
})

function list (encoding) {
  return {
    preencode (state, values) {
      c.uint.preencode(state, values.length)
      for (const value of values) encoding.preencode(state, value)
    },
    encode (state, values) {
      c.uint.encode(state, values.length)
      for (const value of values) encoding.encode(state, value)
    },
    decode (state) {
      const count = c.uint.decode(state)
      if (!Number.isSafeInteger(count) || count < 0 || count > MAX_PRIVATE_IPC_LIST_ITEMS) {
        registryFailure('private IPC registry list count exceeds its bound')
      }
      const values = new Array(count)
      for (let index = 0; index < count; index++) values[index] = encoding.decode(state)
      return values
    }
  }
}

const stringList = list(c.string)
const schemaEncoding = {
  preencode (state, value) {
    c.uint.preencode(state, value.schemaId)
    c.string.preencode(state, value.schemaName)
    stringList.preencode(state, value.fields)
  },
  encode (state, value) {
    c.uint.encode(state, value.schemaId)
    c.string.encode(state, value.schemaName)
    stringList.encode(state, value.fields)
  },
  decode (state) {
    return {
      schemaId: c.uint.decode(state),
      schemaName: c.string.decode(state),
      fields: stringList.decode(state)
    }
  }
}
const bindingEntryEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.name)
    c.uint.preencode(state, value.id)
    c.uint.preencode(state, value.value)
  },
  encode (state, value) {
    c.string.encode(state, value.name)
    c.uint.encode(state, value.id)
    c.uint.encode(state, value.value)
  },
  decode (state) {
    return {
      name: c.string.decode(state),
      id: c.uint.decode(state),
      value: c.uint.decode(state)
    }
  }
}
const bindingTableEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.name)
    list(bindingEntryEncoding).preencode(state, value.entries)
  },
  encode (state, value) {
    c.string.encode(state, value.name)
    list(bindingEntryEncoding).encode(state, value.entries)
  },
  decode (state) {
    return {
      name: c.string.decode(state),
      entries: list(bindingEntryEncoding).decode(state)
    }
  }
}

const registryEncoding = {
  preencode (state, value) {
    c.string.preencode(state, value.magic)
    c.uint.preencode(state, value.formatVersion)
    c.fixed32.preencode(state, value.wireAbiHash)
    list(schemaEncoding).preencode(state, value.schemas)
    list(bindingTableEncoding).preencode(state, value.importedWireBindings)
    list(bindingTableEncoding).preencode(state, value.localBindings)
  },
  encode (state, value) {
    c.string.encode(state, value.magic)
    c.uint.encode(state, value.formatVersion)
    c.fixed32.encode(state, value.wireAbiHash)
    list(schemaEncoding).encode(state, value.schemas)
    list(bindingTableEncoding).encode(state, value.importedWireBindings)
    list(bindingTableEncoding).encode(state, value.localBindings)
  },
  decode (state) {
    return {
      magic: c.string.decode(state),
      formatVersion: c.uint.decode(state),
      wireAbiHash: b4a.from(c.fixed32.decode(state)),
      schemas: list(schemaEncoding).decode(state),
      importedWireBindings: list(bindingTableEncoding).decode(state),
      localBindings: list(bindingTableEncoding).decode(state)
    }
  }
}

function enumBindings (name, values) {
  return {
    name,
    entries: Object.entries(values)
      .map(([entryName, raw]) => ({ name: entryName, id: Number(raw), value: Number(raw) }))
      .sort((left, right) => left.id - right.id || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0))
  }
}

function classBindings (name, values) {
  return {
    name,
    entries: Object.entries(values)
      .map(([id, value]) => ({ name: id, id: Number(id), value: Number(value) }))
      .sort((left, right) => left.id - right.id)
  }
}

function namedValueBindings (name, values) {
  return {
    name,
    entries: Object.entries(values)
      .filter(([, value]) => Number.isSafeInteger(value) && value >= 0)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([entryName, value], index) => ({ name: entryName, id: index + 1, value: Number(value) }))
  }
}

function openCombinationBindings (name, field) {
  const names = Object.fromEntries(Object.entries(LOCAL_STREAM_OPEN_COMBINATION).map(([entryName, id]) => [id, entryName]))
  return {
    name,
    entries: LOCAL_STREAM_OPEN_TABLE.map(row => ({ name: names[row.id], id: row.id, value: row[field] }))
  }
}

function encode (encoding, value) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, value)
  return state.buffer
}

function len64 (length) {
  let value = BigInt(length)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

export function privateIpcRegistryValue (wireAbiBytes) {
  return {
    magic: 'hiverelay-blind-private-ipc-v1',
    formatVersion: 1,
    wireAbiHash: hashImportedWireAbi(wireAbiBytes),
    schemas: PRIVATE_IPC_SCHEMAS,
    importedWireBindings: [
      enumBindings('FAMILY', FAMILY),
      enumBindings('TRANSPORT_ID', TRANSPORT_ID),
      enumBindings('TRANSPORT_SUPPORT', TRANSPORT_SUPPORT),
      classBindings('OUTER_CLASS', OUTER_CLASS),
      classBindings('STREAM_WIRE_CLASS', STREAM_WIRE_CLASS)
    ],
    localBindings: [
      ...Object.entries(LOCAL_BINDINGS).map(([name, values]) =>
        name === 'limits' || name === 'timingMillis' || name === 'readyRules' ||
        name === 'ciphertextBytes' || name === 'streamControlBytes'
          ? namedValueBindings(name, values)
          : enumBindings(name, values)),
      openCombinationBindings('streamOpenKindByCombination', 'openKind'),
      openCombinationBindings('streamModeByCombination', 'streamMode'),
      openCombinationBindings('streamClassMinimumByCombination', 'classMinimum'),
      openCombinationBindings('streamClassMaximumByCombination', 'classMaximum'),
      openCombinationBindings('streamContextKindByCombination', 'contextKind'),
      openCombinationBindings('streamAdjacentPolicyByCombination', 'adjacentPolicy')
    ]
  }
}

export function encodePrivateIpcRegistry (wireAbiBytes) {
  return encode(registryEncoding, privateIpcRegistryValue(wireAbiBytes))
}

function decodeRegistryBytes (input) {
  const bytes = asBuffer(input, 'private IPC registry')
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_PRIVATE_IPC_REGISTRY_BYTES) {
    registryFailure(`private IPC registry must be bytes[1..${MAX_PRIVATE_IPC_REGISTRY_BYTES}]`)
  }
  const state = { start: 0, end: bytes.byteLength, buffer: bytes }
  let value
  try {
    value = registryEncoding.decode(state)
  } catch (error) {
    if (error && error.code === 'BAD_PRIVATE_IPC_REGISTRY') throw error
    registryFailure('private IPC registry is truncated or malformed')
  }
  if (state.start !== state.end) registryFailure('private IPC registry has trailing bytes')
  const canonical = encode(registryEncoding, value)
  if (!b4a.equals(canonical, bytes)) registryFailure('private IPC registry is not canonical')
  return { value, bytes }
}

export function decodePrivateIpcRegistry (input) {
  return decodeRegistryBytes(input).value
}

export function verifyPrivateIpcRegistry (input, wireAbiBytes) {
  const decoded = decodeRegistryBytes(input)
  const expected = encodePrivateIpcRegistry(asBuffer(wireAbiBytes, 'public WIRE ABI'))
  if (!b4a.equals(decoded.bytes, expected)) {
    registryFailure('private IPC registry does not equal the exact local schemas and final WIRE ABI bindings')
  }
  return decoded.value
}

export function hashPrivateIpcRegistry (registryBytes) {
  return privateBlake2b256(b4a.concat([FORMAT_DOMAIN, len64(registryBytes.byteLength), registryBytes]))
}

export function hashPrivateIpcVectorManifest (manifestBytes) {
  return privateBlake2b256(b4a.concat([VECTOR_DOMAIN, len64(manifestBytes.byteLength), manifestBytes]))
}

export { registryEncoding as privateIpcRegistryEncoding }
