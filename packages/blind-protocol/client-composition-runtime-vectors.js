import b4a from 'b4a'
import {
  CELL_BLOB_V1_BY_SIZE_CLASS,
  blindCoreReadCapV1,
  opaqueChainCheckpointV1,
  opaqueChainFrameV1,
  readCellCapV1,
  writeCellCapV1
} from './client-internal-schemas.js'
import { encodeCanonical } from './codec.js'
import {
  blake2b256,
  encodeVectorManifest,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet
} from './hashes.js'

const bytes = (length, value) => b4a.alloc(length, value)
const hex = value => b4a.toString(value, 'hex')

function readCap (seed, sizeClass = 1, expected = true) {
  return {
    version: 1,
    relayPublicKey: bytes(32, seed),
    storageSlot: bytes(32, seed + 1),
    cellKey: bytes(32, seed + 2),
    sizeClass,
    expectedCellBlobHash: expected ? bytes(32, seed + 3) : null
  }
}

function fixtureValues () {
  const firstCap = readCap(0x21)
  const secondCap = readCap(0x31, 2, false)
  const checkpoint = {
    version: 1,
    coveredFrontier: [
      { chainId: bytes(32, 0x11), sequence: 7n, frameHash: bytes(32, 0x12) },
      { chainId: bytes(32, 0x13), sequence: 8n, frameHash: bytes(32, 0x14) }
    ],
    opaqueStateCommitment: bytes(32, 0x15),
    snapshotPayloadHash: bytes(32, 0x16),
    snapshotReadCaps: [firstCap, secondCap]
  }
  const genesisFrame = {
    version: 1,
    chainId: bytes(32, 0x41),
    sequence: 0n,
    previousFrameHash: null,
    transportVerifyKey: bytes(32, 0x42),
    opaquePayloads: [bytes(0, 0)],
    nextReadCellCaps: [firstCap, secondCap],
    checkpoint: null,
    transportSignature: bytes(64, 0x43)
  }
  const successorFrame = {
    version: 1,
    chainId: genesisFrame.chainId,
    sequence: 1n,
    previousFrameHash: bytes(32, 0x44),
    transportVerifyKey: genesisFrame.transportVerifyKey,
    opaquePayloads: [],
    nextReadCellCaps: [],
    checkpoint,
    transportSignature: bytes(64, 0x45)
  }
  const writeCap = {
    readCap: firstCap,
    allocationEpoch: 0x01020304,
    createPrivateKey: bytes(32, 0x51),
    renewPrivateKey: bytes(32, 0x52),
    dropPrivateKey: bytes(32, 0x53)
  }
  const coreCap = {
    version: 1,
    corePublicKey: bytes(32, 0x61),
    blockEncryptionKey: bytes(32, 0x62),
    witnessedFork: 3n,
    witnessedLength: 9n,
    witnessedSignedHead: b4a.from('0102030405060708', 'hex')
  }
  return { firstCap, checkpoint, genesisFrame, successorFrame, writeCap, coreCap }
}

function positiveVectors () {
  const values = fixtureValues()
  const vectors = new Map([
    ['positive/blind-core-read-cap-v1.bin', encodeCanonical(blindCoreReadCapV1, values.coreCap)],
    ['positive/opaque-chain-checkpoint-v1.bin', encodeCanonical(opaqueChainCheckpointV1, values.checkpoint)],
    ['positive/opaque-chain-frame-v1-genesis.bin', encodeCanonical(opaqueChainFrameV1, values.genesisFrame)],
    ['positive/opaque-chain-frame-v1-successor.bin', encodeCanonical(opaqueChainFrameV1, values.successorFrame)],
    ['positive/read-cell-cap-v1.bin', encodeCanonical(readCellCapV1, values.firstCap)],
    ['positive/write-cell-cap-v1.bin', encodeCanonical(writeCellCapV1, values.writeCap)]
  ])
  for (let sizeClass = 1; sizeClass <= 5; sizeClass++) {
    const length = [0, 4096, 16384, 65536, 262144, 1048576][sizeClass]
    vectors.set(`positive/cell-blob-v1-class-${sizeClass}.bin`, encodeCanonical(
      CELL_BLOB_V1_BY_SIZE_CLASS[sizeClass],
      {
        formatVersion: 1,
        nonce: bytes(12, 0x70 + sizeClass),
        sealed: bytes(length - 13, 0x80 + sizeClass)
      }
    ))
  }
  return vectors
}

export function buildClientCompositionFixtureVectorsV1 () {
  const vectors = positiveVectors()

  const zeroCoreKey = b4a.from(vectors.get('positive/blind-core-read-cap-v1.bin'))
  zeroCoreKey.fill(0, 1, 33)
  vectors.set('negative/blind-core-read-cap-zero-core-public-key.bin', zeroCoreKey)

  const classOne = vectors.get('positive/cell-blob-v1-class-1.bin')
  vectors.set('negative/cell-blob-v1-class-1-truncated.bin', b4a.from(classOne.subarray(0, classOne.byteLength - 1)))

  const unsortedCheckpoint = b4a.from(vectors.get('positive/opaque-chain-checkpoint-v1.bin'))
  if (unsortedCheckpoint[1] !== 2) throw new Error('checkpoint fixture array prefix drifted')
  unsortedCheckpoint.fill(0x20, 2, 34)
  unsortedCheckpoint.fill(0x10, 74, 106)
  vectors.set('negative/opaque-chain-checkpoint-unsorted-frontier.bin', unsortedCheckpoint)

  const sequenceWithoutPredecessor = b4a.from(vectors.get('positive/opaque-chain-frame-v1-genesis.bin'))
  sequenceWithoutPredecessor[40] = 1
  vectors.set('negative/opaque-chain-frame-sequence-one-without-predecessor.bin', sequenceWithoutPredecessor)

  const zeroRelayKey = b4a.from(vectors.get('positive/read-cell-cap-v1.bin'))
  zeroRelayKey.fill(0, 1, 33)
  vectors.set('negative/read-cell-cap-zero-relay-public-key.bin', zeroRelayKey)

  const duplicatePrivateKeys = b4a.from(vectors.get('positive/write-cell-cap-v1.bin'))
  const privateKeyOffset = duplicatePrivateKeys.byteLength - 96
  b4a.copy(duplicatePrivateKeys, duplicatePrivateKeys, privateKeyOffset + 32, privateKeyOffset, privateKeyOffset + 32)
  vectors.set('negative/write-cell-cap-duplicate-private-keys.bin', duplicatePrivateKeys)

  return new Map([...vectors].map(([path, value]) => [path, b4a.from(value)]))
}

export function computeClientCompositionRuntimeVectors () {
  const vectors = buildClientCompositionFixtureVectorsV1()
  const manifest = encodeVectorManifest([...vectors].map(([path, value]) => ({ path, bytes: value })))
  const vectorDigests = {}
  for (const [path, value] of [...vectors].sort(([left], [right]) => left.localeCompare(right))) {
    vectorDigests[path] = Object.freeze({
      byteLength: value.byteLength,
      hash: hex(blake2b256(value))
    })
  }
  return Object.freeze({
    vectorDigests: Object.freeze(vectorDigests),
    sampleFormatHash: hex(hashClientCompositionFormat(b4a.from('client-composition-runtime-format-v1', 'ascii'))),
    fixtureVectorSetHash: hex(hashClientCompositionVectorSet(manifest))
  })
}
