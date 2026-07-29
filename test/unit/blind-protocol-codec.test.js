import test from 'brittle'
import b4a from 'b4a'
import {
  admissionV1,
  blindAdmissionParametersRequestV1,
  blindDescribeGetV1,
  blindErrorV1,
  boundedBytes,
  compactUint,
  decodeCanonical,
  encodeCanonical,
  optional,
  u32be,
  u64be
} from '../../packages/blind-protocol/index.js'

const bytes = (length, value) => b4a.alloc(length, value)

test('blind codec: fixed-width fields and compact lengths are byte exact', t => {
  const encoded = encodeCanonical(admissionV1, {
    profileId: 0x0102,
    schemeId: 0x0304,
    parameterHash: bytes(32, 0xaa),
    token: b4a.from([0x10, 0x11, 0x12])
  })

  t.is(b4a.toString(encoded, 'hex'), `01020304${'aa'.repeat(32)}03101112`)
  const decoded = decodeCanonical(admissionV1, encoded)
  t.is(decoded.profileId, 0x0102)
  t.is(decoded.schemeId, 0x0304)
  t.alike(decoded.parameterHash, bytes(32, 0xaa))
  t.alike(decoded.token, b4a.from([0x10, 0x11, 0x12]))

  const prefixed = encodeCanonical(boundedBytes(0, 4096), bytes(253, 0x7a))
  t.alike(prefixed.subarray(0, 3), b4a.from([0xfd, 0xfd, 0x00]))
  t.is(prefixed.byteLength, 256)
})

test('blind codec: non-canonical lengths, tags and trailing bytes fail closed', t => {
  t.exception(() => decodeCanonical(boundedBytes(0, 64), b4a.from([0xfd, 0x03, 0x00, 1, 2, 3])))
  t.exception(() => decodeCanonical(optional(u32be), b4a.from([2, 0, 0, 0, 1])))
  t.exception(() => decodeCanonical(compactUint, b4a.from([0xfe, 0xfd, 0x00, 0x00, 0x00])))

  const encoded = encodeCanonical(blindErrorV1, {
    version: 1,
    code: 18,
    retryable: 1,
    retryAfterEpoch: 0x01020304
  })
  t.is(b4a.toString(encoded, 'hex'), '0112010101020304')
  t.exception(() => decodeCanonical(blindErrorV1, b4a.concat([encoded, b4a.from([0])])))
})

test('blind codec: optionals use an explicit presence byte', t => {
  const nonce = bytes(32, 0x22)
  const current = encodeCanonical(blindDescribeGetV1, {
    version: 1,
    descriptorHash: null,
    clientNonce: nonce
  })
  t.is(current[0], 1)
  t.is(current[1], 0)
  t.is(current.byteLength, 34)

  const historical = encodeCanonical(blindDescribeGetV1, {
    version: 1,
    descriptorHash: bytes(32, 0x33),
    clientNonce: nonce
  })
  t.is(historical[1], 1)
  t.is(historical.byteLength, 66)
  t.alike(decodeCanonical(blindDescribeGetV1, historical).descriptorHash, bytes(32, 0x33))
})

test('blind codec: admission parameter selector is fixed and bounded', t => {
  const encoded = encodeCanonical(blindAdmissionParametersRequestV1, {
    version: 1,
    profileId: 7,
    schemeId: 9,
    clientNonce: bytes(32, 0x44)
  })
  t.is(b4a.toString(encoded.subarray(0, 5), 'hex'), '0100070009')
  t.exception(() => encodeCanonical(blindAdmissionParametersRequestV1, {
    version: 1,
    profileId: 0,
    schemeId: 9,
    clientNonce: bytes(32, 0x44)
  }))
})

test('blind codec: u64 is big-endian and preserves bigint', t => {
  const value = 0x0102030405060708n
  const encoded = encodeCanonical(u64be, value)
  t.is(b4a.toString(encoded, 'hex'), '0102030405060708')
  t.is(decodeCanonical(u64be, encoded), value)
  t.exception(() => encodeCanonical(u64be, -1n))
  t.exception(() => decodeCanonical(u64be, encoded.subarray(0, 7)))
})
