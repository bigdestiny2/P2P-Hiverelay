import b4a from 'b4a'
import {
  blindCoreReadCapV1,
  readCellCapV1
} from './client-composition-external-codecs.js'
import { decodeCanonical, encodeCanonical } from './codec.js'
import { protocolError } from './errors.js'
import {
  blindCoreAckV1,
  blindReceiptV1,
  inboxAppendAckV1,
  inboxReceiptV1
} from './schemas.js'

const BLIND_CORE_ACK = Object.freeze({ codec: blindCoreAckV1, minimum: 1, maximum: 16384 })
const BLIND_CORE_READ_CAP = Object.freeze({ codec: blindCoreReadCapV1, minimum: 1, maximum: 8192 })
const BLIND_RECEIPT = Object.freeze({ codec: blindReceiptV1, minimum: 1, maximum: 16384 })
const INBOX_APPEND_ACK = Object.freeze({ codec: inboxAppendAckV1, minimum: 1, maximum: 16384 })
const INBOX_RECEIPT = Object.freeze({ codec: inboxReceiptV1, minimum: 1, maximum: 16384 })
const READ_CELL_CAP = Object.freeze({ codec: readCellCapV1, minimum: 99, maximum: 131 })

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isSharedArrayBuffer (value) {
  return typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer
}

function snapshotBytes (input) {
  let view
  if (input instanceof ArrayBuffer) {
    view = new Uint8Array(input)
  } else if (ArrayBuffer.isView(input)) {
    if (isSharedArrayBuffer(input.buffer)) fail('external profile value cannot use shared memory')
    view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
  } else {
    fail('external profile value must be ArrayBuffer-backed bytes')
  }
  const output = b4a.alloc(view.byteLength)
  output.set(view)
  return output
}

function selectCodec (name) {
  switch (name) {
    case 'BlindCoreAckV1': return BLIND_CORE_ACK
    case 'BlindCoreReadCapV1': return BLIND_CORE_READ_CAP
    case 'BlindReceiptV1': return BLIND_RECEIPT
    case 'InboxAppendAckV1': return INBOX_APPEND_ACK
    case 'InboxReceiptV1': return INBOX_RECEIPT
    case 'ReadCellCapV1': return READ_CELL_CAP
    default: fail('external profile decoder schema name is outside its closed inventory')
  }
}

function freezeContainers (value) {
  if (value == null || typeof value !== 'object' || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return value
  }
  if (Array.isArray(value)) {
    for (const child of value) freezeContainers(child)
  } else {
    for (const child of Object.values(value)) freezeContainers(child)
  }
  return Object.freeze(value)
}

// This is the only executable schema-selection API exported into the browser
// control artifact. Callers select one of six fixed names and provide bytes;
// they cannot supply a codec, registry, callback, or schema description.
export function decodeBlindExternalProfileValueV1 (name, input) {
  if (arguments.length !== 2 || typeof name !== 'string') {
    fail('external profile decoder requires exactly a schema name and bytes')
  }
  const selected = selectCodec(name)
  const bytes = snapshotBytes(input)
  if (bytes.byteLength < selected.minimum || bytes.byteLength > selected.maximum) {
    fail(`${name} length is outside ${selected.minimum}..${selected.maximum}`)
  }
  const value = decodeCanonical(selected.codec, bytes, { copyBytes: true })
  if (!b4a.equals(encodeCanonical(selected.codec, value), bytes)) {
    fail(`${name} is not canonically reproducible`)
  }
  return freezeContainers(value)
}
