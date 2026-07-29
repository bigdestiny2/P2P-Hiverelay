import test from 'brittle'
import b4a from 'b4a'
import {
  DISPATCH_LIMITS,
  DispatchSequenceGuard,
  FAMILY,
  FRAME_KIND,
  MAX_U64,
  OPERATION,
  decodeDispatchFrame,
  encodeDispatchFrame,
  readDispatchLengthPrefix
} from '@hiverelay/blind-protocol'

const requestId = (byte = 1) => b4a.alloc(16, byte)
const zeroRequestId = () => b4a.alloc(16)

test('blind dispatch: unary request round-trips byte-exact fields', (t) => {
  const body = b4a.from('opaque')
  const encoded = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: requestId(0x11),
    body
  })
  t.is(b4a.readUInt32BE(encoded, 0), DISPATCH_LIMITS.HEADER_BYTES + body.byteLength)
  const decoded = decodeDispatchFrame(encoded)
  t.is(decoded.version, 1)
  t.is(decoded.frameKind, FRAME_KIND.REQUEST)
  t.is(decoded.familyId, FAMILY.CELL)
  t.is(decoded.operationId, OPERATION.CELL.GET)
  t.ok(b4a.equals(decoded.requestId, requestId(0x11)))
  t.is(decoded.streamId, 0n)
  t.is(decoded.sequence, 0n)
  t.ok(b4a.equals(decoded.body, body))
})

test('blind dispatch: streaming open response and stream data round-trip u64', (t) => {
  const open = encodeDispatchFrame({
    frameKind: FRAME_KIND.RESPONSE,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.OPEN,
    requestId: requestId(0x22),
    streamId: MAX_U64,
    body: b4a.alloc(0)
  })
  t.is(decodeDispatchFrame(open).streamId, MAX_U64)

  const data = encodeDispatchFrame({
    frameKind: FRAME_KIND.STREAM,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.DATA,
    requestId: zeroRequestId(),
    streamId: 9n,
    sequence: 7n,
    body: b4a.from('ciphertext')
  })
  const decoded = decodeDispatchFrame(data)
  t.is(decoded.streamId, 9n)
  t.is(decoded.sequence, 7n)
})

test('blind dispatch: rejects unknown IDs, reserved flags and invalid correlations', (t) => {
  const base = {
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: requestId(),
    body: b4a.alloc(0)
  }
  t.exception(() => encodeDispatchFrame({ ...base, operationId: 255 }), /unknown family\/operation/)
  t.exception(() => encodeDispatchFrame({ ...base, flags: 1 }), /flags are reserved/)
  t.exception(() => encodeDispatchFrame({ ...base, requestId: zeroRequestId() }), /correlation fields/)
  t.exception(() => encodeDispatchFrame({ ...base, streamId: 1n }), /correlation fields/)
  t.exception(() => encodeDispatchFrame({ ...base, streamId: -1n }), /outside u64/)
  t.exception(() => encodeDispatchFrame({ ...base, streamId: MAX_U64 + 1n }), /outside u64/)
  t.exception(() => encodeDispatchFrame({
    ...base,
    frameKind: FRAME_KIND.STREAM,
    requestId: zeroRequestId(),
    streamId: 1n
  }), /frame kind is not allowed/)
})

test('blind dispatch: declared caps reject before body materialization', (t) => {
  const prefix = b4a.alloc(4)
  b4a.writeUInt32BE(prefix, DISPATCH_LIMITS.MAX_FRAME_AFTER_PREFIX_BYTES + 1, 0)
  t.exception(() => readDispatchLengthPrefix(prefix), /absolute cap/)
  t.exception(() => encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    requestId: requestId(),
    body: b4a.alloc(DISPATCH_LIMITS.MAX_BODY_BYTES + 1)
  }), /body exceeds/)
  t.exception(() => encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: requestId(),
    body: b4a.alloc(16385)
  }), /operation cap/)

  const header = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: requestId(),
    body: b4a.alloc(0)
  })
  const oversized = b4a.concat([header, b4a.alloc(16385)])
  b4a.writeUInt32BE(oversized, DISPATCH_LIMITS.HEADER_BYTES + 16385, 0)
  b4a.writeUInt32BE(oversized, 16385, 41)
  t.exception(() => decodeDispatchFrame(oversized, { copyBody: true }), /operation cap/)
})

test('blind dispatch: malformed, truncated and trailing frames fail closed', (t) => {
  const encoded = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    requestId: requestId(),
    body: b4a.from('x')
  })
  t.exception(() => decodeDispatchFrame(encoded.subarray(0, encoded.length - 1)), /length mismatch/)
  t.exception(() => decodeDispatchFrame(b4a.concat([encoded, b4a.from([0])])), /length mismatch/)

  const badBodyLength = b4a.from(encoded)
  b4a.writeUInt32BE(badBodyLength, 99, 41)
  t.exception(() => decodeDispatchFrame(badBodyLength), /body length mismatch/)

  const badVersion = b4a.from(encoded)
  badVersion[4] = 2
  t.exception(() => decodeDispatchFrame(badVersion), /version must be 1/)

  const badOperation = b4a.from(encoded)
  badOperation[7] = 255
  t.exception(() => decodeDispatchFrame(badOperation), /unknown family\/operation/)
})

test('blind dispatch: sequence guard bounds streams and rejects rollback', (t) => {
  const guard = new DispatchSequenceGuard({ maxStreams: 1 })
  const frame = { frameKind: FRAME_KIND.STREAM, streamId: 3n, sequence: 0n }
  guard.accept(frame)
  guard.accept({ ...frame, sequence: 1n })
  t.exception(() => guard.accept({ ...frame, sequence: 1n }), /non-monotonic/)
  t.exception(() => guard.accept({ ...frame, streamId: 4n }), /guard is full/)
  guard.close(3n)
  guard.accept({ ...frame, streamId: 4n })
  guard.clear()
})
