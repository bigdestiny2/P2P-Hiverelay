import b4a from 'b4a'
import {
  CELL_SIZE_CLASS, INBOX_FRAME_CLASS, decodeCanonical,
  blindCellRecordSnapshotV1, blindCellChargedReadRetrySnapshotV1,
  blindInboxFrameSnapshotV1
} from '@hiverelay/blind-protocol'

// Input is a fresh value read from the original engine-owned capture token,
// never a caller's map. Historical rows alone do not own retired bodies.
export function capturedBodyReferences (value, limits) {
  const bodies = new Map()
  let totalBytes = 0
  let references = 0
  const add = (reference, owner) => {
    if (++references > limits.maximumReferences) throw new TypeError('captured opaque references exceed configured work budget')
    const { virtualBucket, objectId, byteLength, hash } = reference
    if (!Number.isInteger(virtualBucket) || virtualBucket < 0 || virtualBucket > 65535 ||
        !Number.isSafeInteger(byteLength) || byteLength < 1 || byteLength > limits.maximumBodyBytes ||
        !(objectId instanceof Uint8Array) || objectId.byteLength !== 32 || !(hash instanceof Uint8Array) || hash.byteLength !== 32 ||
        !objectId.some(byte => byte !== 0) || !hash.some(byte => byte !== 0)) throw new TypeError('invalid captured opaque body reference')
    const key = `${virtualBucket.toString(16).padStart(4, '0')}/${b4a.toString(objectId, 'hex')}`
    const previous = bodies.get(key)
    if (previous) {
      if (previous.byteLength !== byteLength || !b4a.equals(previous.hash, hash)) throw new TypeError('captured body owners disagree on immutable bytes')
      previous.owners++
      return
    }
    if (bodies.size >= limits.maximumBodies || totalBytes + byteLength > limits.maximumTotalBytes) throw new TypeError('captured opaque bodies exceed configured work budget')
    totalBytes += byteLength
    bodies.set(key, { key, virtualBucket, objectId: b4a.from(objectId), byteLength, hash: b4a.from(hash), owners: 1, owner })
  }
  if (value.role === 'cell') {
    const cells = new Map()
    for (const row of value.rows) {
      if (row.kind === 3 && row.subtype === 1) {
        const cell = decodeCanonical(blindCellRecordSnapshotV1, row.value, { copyBytes: true })
        cells.set(b4a.toString(cell.storageSlot, 'hex'), cell)
        if (cell.objectState === 1) add({ virtualBucket: cell.blobVirtualBucket, objectId: cell.blobObjectId, byteLength: CELL_SIZE_CLASS[cell.sizeClass], hash: cell.cellBlobHash }, 'present-cell')
      }
    }
    for (const row of value.rows) {
      if (row.kind !== 8 || row.subtype !== 1) continue
      const retry = decodeCanonical(blindCellChargedReadRetrySnapshotV1, row.value, { copyBytes: true })
      if (retry.lifecycleState === 3) continue
      for (const pin of retry.entries) {
        if (!pin.present) continue
        const cell = cells.get(b4a.toString(pin.storageSlot, 'hex'))
        if (!cell || cell.objectState !== 1 || cell.sizeClass !== pin.sizeClass || !b4a.equals(cell.cellBlobHash, pin.cellBlobHash)) throw new TypeError('live charged CELL read lacks its body owner')
        add({ virtualBucket: cell.blobVirtualBucket, objectId: cell.blobObjectId, byteLength: CELL_SIZE_CLASS[pin.sizeClass], hash: pin.cellBlobHash }, 'charged-cell-read')
      }
    }
  } else if (value.role === 'inbox') {
    // The accepted semantic capture joins every live retry pin to these frame
    // rows, including retained frames whose normal lease has expired.
    for (const row of value.rows) {
      if (row.kind !== 4 || row.subtype !== 2) continue
      const frame = decodeCanonical(blindInboxFrameSnapshotV1, row.value, { copyBytes: true })
      add({ virtualBucket: frame.frameVirtualBucket, objectId: frame.frameObjectId, byteLength: INBOX_FRAME_CLASS[frame.frameClass], hash: frame.frameHash }, 'retained-inbox-frame')
    }
  } else if (value.role === 'core') {
    const keyOf = key => `${b4a.toString(key.corePublicKey, 'hex')}:${key.revision}`
    const generations = new Map(value.core.generations.map(generation => [keyOf(generation.key), generation]))
    const owner = (key, kind) => {
      const generation = generations.get(keyOf(key))
      if (!generation) throw new TypeError('live CORE owner lacks its original generation')
      add(generation.corpus, kind)
    }
    for (const floor of value.core.floors) if (floor.active) owner(floor.key, 'active-core')
    for (const proof of value.core.proofs) if (proof.expiredAtUnixMillis === null) owner(proof.source, 'paid-core-proof')
  } else throw new TypeError('unknown captured body role')
  return { bodies: [...bodies.values()].sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0), totalBytes, references }
}
