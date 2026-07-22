import test from 'brittle'
import b4a from 'b4a'
import {
  ABI_STATUS,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  admissionParametersHash,
  assertReleaseReady,
  blake2b256,
  decodeVectorManifest,
  decodeOuterEnvelope,
  durabilityContinuityHash,
  durabilityProfileHash,
  encodeDispatchFrame,
  encodeWireAbiRegistry,
  encodeOuterEnvelope,
  encodeVectorManifest,
  hashAbi,
  hashBuildArtifact,
  hashBuildManifest,
  hashSpec,
  hashVectorSet,
  persistentResultCommitment,
  serviceDescriptorHash,
  smallestOuterClass
} from '@hiverelay/blind-protocol'

function requestFrame (body = b4a.alloc(0)) {
  return encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, 0x41),
    body
  })
}

test('blind outer envelope: exact class, padding seam and round-trip', (t) => {
  const innerDispatch = requestFrame(b4a.from('hello'))
  const encoded = encodeOuterEnvelope({ innerDispatch }, {
    randomFill: padding => padding.fill(0xa5)
  })
  t.is(encoded.byteLength, OUTER_CLASS[1])
  t.is(encoded[1], 1)
  const paddingStart = 6 + innerDispatch.byteLength
  t.is(encoded[paddingStart], 0xa5)
  t.is(encoded[encoded.length - 1], 0xa5)
  const decoded = decodeOuterEnvelope(encoded)
  t.is(decoded.outerClass, 1)
  t.ok(b4a.equals(decoded.innerDispatch, innerDispatch))
  t.ok(b4a.equals(decoded.frame.body, b4a.from('hello')))
})

test('blind outer envelope: class boundaries and mismatch failures', (t) => {
  t.is(smallestOuterClass(OUTER_CLASS[1] - 6), 1)
  t.is(smallestOuterClass(OUTER_CLASS[1] - 5), 2)
  t.exception(() => smallestOuterClass(OUTER_CLASS[6]), /does not fit/)

  const innerDispatch = requestFrame()
  t.exception(() => encodeOuterEnvelope({ outerClass: 99, innerDispatch }), /unknown outer class/)
  const encoded = encodeOuterEnvelope({ innerDispatch }, { randomFill: () => {} })
  t.exception(() => decodeOuterEnvelope(encoded.subarray(0, encoded.length - 1)), /exactly match/)

  const wrongClass = b4a.from(encoded)
  wrongClass[1] = 2
  t.exception(() => decodeOuterEnvelope(wrongClass), /exactly match/)

  const wrongInner = b4a.from(encoded)
  b4a.writeUInt32BE(wrongInner, encoded.length, 2)
  t.exception(() => decodeOuterEnvelope(wrongInner), /exceeds the outer class/)
})

test('blind hashes: domains are deterministic and separated', (t) => {
  const bytes = b4a.from('abc')
  t.ok(b4a.equals(hashSpec(bytes), hashSpec(bytes)))
  t.absent(b4a.equals(hashSpec(bytes), hashAbi(bytes)))
  t.absent(b4a.equals(hashAbi(bytes), hashVectorSet(bytes)))
  t.absent(b4a.equals(hashBuildArtifact(bytes), hashBuildManifest(bytes)))
  t.ok(b4a.equals(serviceDescriptorHash(bytes), blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.descriptor-hash.v1', 'ascii'), bytes
  ]))))
  t.ok(b4a.equals(admissionParametersHash(bytes), blake2b256(b4a.concat([
    b4a.from('hiverelay.blind.admission-parameters-hash.v1', 'ascii'), bytes
  ]))))
  t.absent(b4a.equals(durabilityProfileHash(bytes), durabilityContinuityHash(bytes)))
  t.absent(b4a.equals(serviceDescriptorHash(bytes), durabilityProfileHash(bytes)))
  t.ok(b4a.equals(
    persistentResultCommitment(FAMILY.CELL, OPERATION.CELL.PUT, bytes),
    blake2b256(b4a.concat([
      b4a.from('hiverelay.blind.persistent-result.v1', 'ascii'),
      b4a.from([FAMILY.CELL, OPERATION.CELL.PUT, 0, 0, 0, 0, 0, 0, 0, bytes.byteLength]),
      bytes
    ]))
  ))
  t.exception(() => persistentResultCommitment(0xff, 0xff, bytes), /unknown operation/)
})

test('blind vector manifest: path order is canonical and invalid paths fail', (t) => {
  const a = { path: 'dispatch/a.bin', bytes: b4a.from('a') }
  const z = { path: 'outer/z.bin', bytes: b4a.from('z') }
  const first = encodeVectorManifest([z, a])
  const second = encodeVectorManifest([a, z])
  t.ok(b4a.equals(first, second), 'input order does not change canonical bytes')
  t.ok(b4a.equals(hashVectorSet(first), hashVectorSet(second)))
  const decoded = decodeVectorManifest(first)
  t.alike(decoded.map(entry => entry.path), ['dispatch/a.bin', 'outer/z.bin'])
  t.is(decoded[0].vectorLength, 1n)
  t.exception(() => encodeVectorManifest([]), /cannot be empty/)
  t.exception(() => encodeVectorManifest([a, a]), /duplicate normalized/)
  t.exception(() => encodeVectorManifest([{ path: '../a', bytes: b4a.alloc(0) }]), /forbidden component/)
  t.exception(() => encodeVectorManifest([{ path: '/a', bytes: b4a.alloc(0) }]), /must be relative/)
  t.exception(() => encodeVectorManifest([{ path: 'a\\b', bytes: b4a.alloc(0) }]), /slash separators/)
  t.exception(() => decodeVectorManifest(first.subarray(0, first.byteLength - 1)), /truncated/)
  t.exception(() => decodeVectorManifest(b4a.concat([first, b4a.from([0])])), /trailing/)
  const unsorted = b4a.from(first)
  const firstPathOffset = 6
  const secondPathOffset = firstPathOffset + 'dispatch/a.bin'.length + 42
  unsorted[firstPathOffset] = 0x7a
  unsorted[secondPathOffset] = 0x61
  t.exception(() => decodeVectorManifest(unsorted), /strictly sorted/)
})

test('blind public WIRE ABI: canonical registry is release ready', (t) => {
  t.ok(encodeWireAbiRegistry().byteLength > 0)
  t.is(ABI_STATUS.releaseReady, true)
  t.is(ABI_STATUS.missingSchemaNames.length, 0)
  t.alike(ABI_STATUS.releaseBlockers, [])
  t.is(assertReleaseReady(), undefined)
})
