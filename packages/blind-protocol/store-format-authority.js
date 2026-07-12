import b4a from 'b4a'
import { protocolError } from './errors.js'
import { hashStoreFormat } from './hashes.js'

const MAGIC = b4a.from('HRBSFA01', 'ascii')
const AUTHORITY_VERSION = 1
const FORMAT_MAJOR = 1
const FORMAT_MINOR = 0
const HEADER_BYTES = 22
const MAX_SCHEMA_CATALOG_BYTES = 16 * 1024 * 1024
const MAX_ENTRY_COUNT = 256
const MAX_NAME_BYTES = 127
const MAX_VALUE_BYTES = 4096

function entry (name, value) {
  return Object.freeze({ name, value })
}

// These entries are deliberately implementation-neutral filesystem and crash
// semantics. They contain no app namespace, key, route, or payload knowledge.
export const STORE_FORMAT_AUTHORITY_V1 = Object.freeze([
  entry('artifact.encoding', 'magic[8]=ASCII(HRBSFA01) || authorityVersion:u16be=1 || formatMajor:u16be=1 || formatMinor:u16be=0 || schemaCatalogLength:u64be || exact schemaCatalog bytes || entryCount:u16be || sorted entries(nameLength:u16be || printable ASCII name || valueLength:u32be || printable ASCII value)'),
  entry('artifact.hash-recipe', 'storeFormatHash=BLAKE2B256(ASCII(hiverelay.blind.store-format-hash.v1) || U64BE(len(exact complete authority artifact)) || exact complete authority artifact)'),
  entry('artifact.schema-catalog-binding', 'schemaCatalog bytes are the exact complete generated INTERNAL_STORE schema catalog; names, canonical schema bytes, order, length, and every byte are inside the storeFormatHash preimage'),
  entry('binding.runtime-root', 'runtime-binding.v1 is exactly 213 bytes: ASCII(HRBRT001)||relayPublicKey32||storeId32||durabilityContinuityHash32||durabilityProfileId:u8||formatMajor:u16be||formatMinor:u16be||storeFormatHash32||mapGeneration:u64be||writerFenceTokenHash32||HMAC-SHA256(K_partition, every preceding byte); a preexisting byte mismatch or unbound nonempty root fails before store mutation'),
  entry('binding.runtime-verification', 'before store-root binding or engine open, require signed build.storeFormatHash=signed durability.storeFormatHash, verify the exact bundled authority artifact reproduces from its embedded generated INTERNAL_STORE catalog and frozen rules, require its version/format/hash equal the signed durability tuple, and pass only the resulting unforgeable local verifier authority into the storage engine'),
  entry('control-snapshot.cell-authority-scope', 'Cell reconstruction is recovery-only and requires a privately copied nonzero K_partition to rederive every blobVirtualBucket; it never authorizes checkpoint publication, does not expose K_partition, and remains a separately composed fragment from Inbox, Core, descriptor/identity floors, and daemon-global state'),
  entry('control-snapshot.cell-entry-keyspace', 'sort by (entryKind,key); key=U8(FAMILY.CELL=2)||U8(subtype)||identity; kind1 subtypes 1=committed-put/spendTag32,2=committed-renew/spendTag32,3=terminal-put/spendTag32,4=drop-result/requestCommitment32; kind2 subtype1=reserved-put/spendTag32; kind3 subtype1=cell/storageSlot32; kind6 subtype1=global/no identity,2=profile-staging/profileId:u16be,3=integrity/evidenceHash32; kind8 subtype1=charged-read-retry/spendTag32; unknown, duplicate, non-Cell, unsorted, missing-global, or orphan-index entries fail closed'),
  entry('control-snapshot.cell-reconstruction', 'decode every Cell value canonically and reconstruct spends, derived commitment/charged-expiry indexes, request results, cells, epoch/clock/recovery-gap state, integrity evidence, per-profile staging, and exact byte/count accounting; canonically decode prepared admission and historical result bindings, bind profile-1 relay/store continuity, rederive request fingerprints, verify historical result cells against retained authoritative Cell state, and preserve charged GET/PROVE/BATCH pinned/finalized/expired lifecycle, exact source entries, result commitment, 15-minute retry deadline, and control cost; active charged cost is exact READ_PIN_COMMITTED payload bytes plus the fixed finalization record while expired charged spends remain exactly one 512-byte control tombstone; verify self-certifying slots, allocation commitments including immutable allocationLeaseClass, private keyed virtual buckets, floors, state-machine invariants, tombstoneBytes=(cells+reserved)*512, and exact global counts; in-flight reservations are ineligible and active pins are never pruned by snapshot construction'),
  entry('control-snapshot.cell-value-codecs', 'kind1/subtype1=BlindCellCommittedPutSpendSnapshotV1;1/2=BlindCellCommittedRenewSpendSnapshotV1;1/3=BlindCellTerminalSpendSnapshotV1;1/4=BlindCellRequestResultSnapshotV1;2/1=BlindCellReservedSpendSnapshotV1;3/1=BlindCellRecordSnapshotV1;6/1=BlindCellControlGlobalSnapshotV1;6/2=BlindCellProfileStagingSnapshotV1;6/3=BlindCellIntegrityEvidenceSnapshotV1;8/1=BlindCellChargedReadRetrySnapshotV1 containing BlindCellChargedReadPinEntrySnapshotV1; mutation result records contain BlindCellHistoricalResultSnapshotV1 and canonical BlindPreparedAdmissionStoreV1 bytes'),
  entry('control-snapshot.core-authority-scope', 'Core reconstruction is recovery-only and covers only persistent CORE.OPEN_REPLICATION retry/lifecycle idempotency; it privately copies nonzero K_partition, never exposes it or authorizes publication, and explicitly excludes CORE.MIRROR/PROVE body state, upstream child recreation, ticket resurrection, stream-engine restore, descriptor/global composition, and WAL-barrier authority'),
  entry('control-snapshot.core-entry-keyspace', 'sort by (entryKind,key); key=U8(FAMILY.CORE=4)||U8(subtype)||identity; kind5 subtype1=open-retry/logicalRetryKey32; kind6 subtype1=global/no identity; the retry value carries lifecycleState 1=RESERVED,2=LIVE,3=TERMINAL; unknown, duplicate, non-Core, unsorted, missing-global, colliding spend/logical/channel/stream, or miscounted entries fail closed'),
  entry('control-snapshot.core-reconstruction', 'decode every Core value canonically and reconstruct the retained logical, spend, and authenticated parent/control-channel indexes; rederive logicalRetryKey, requestCommitment, K_partition virtual bucket, class limits, canonical result/request tuple, relay/store/durability binding, result signature, opened-at epoch floor, lifecycle/result presence, terminal reason presence, unique stream IDs, exact state/index/result counts, and snapshotRecordBytes'),
  entry('control-snapshot.core-value-codecs', 'kind5/subtype1=BlindCoreOpenReplicationRetrySnapshotV1 keyed by logicalRetryKey32;kind6/subtype1=BlindCoreControlGlobalSnapshotV1; RESERVED/LIVE require a canonical signed CoreOpenReplicationResultV1, while TERMINAL may omit a result only when failure preceded result construction'),
  entry('control-snapshot.inbox-authority-scope', 'Inbox reconstruction is recovery-only and requires a privately copied nonzero K_partition to rederive every metadata/frame virtual bucket; it proves the complete bounded Inbox control fragment, never exposes K_partition or authorizes checkpoint publication, and requires separate frame-body availability/hash, WAL-engine restore, Cell/Core/descriptor, and daemon-global composition authorities'),
  entry('control-snapshot.inbox-entry-keyspace', 'sort by (entryKind,key); key=U8(FAMILY.INBOX=3)||U8(subtype)||identity; kind1 subtypes 1=committed/spendTag32,2=terminal/spendTag32,3=close-result/requestCommitment32,4=expired-append/spendTag32; kind2 subtype1=reserved/spendTag32; kind4 subtype1=inbox/physicalTopic32,2=frame/physicalTopic32||appendRevision:u64be; kind6 subtype1=global/no identity,2=profile-staging/profileId:u16be,3=integrity/evidenceHash32; kind8 subtype1=retry/spendTag32,2=retry-frame-pin/spendTag32||appendRevision:u64be,3=retry-material/spendTag32; unknown, duplicate, non-Inbox, unsorted, missing-global, or orphan-index entries fail closed'),
  entry('control-snapshot.inbox-reconstruction', 'decode every Inbox value canonically and reconstruct spends, derived commitment index, close results, inboxes, immutable frame references, charged retry records/exact frame pins/exact retry material, epoch/clock/recovery-gap state, integrity evidence, per-profile staging, and byte/count accounting; every committed spend retains canonical resultBindingBytes and clientNonce and binds profile-1 relay/store continuity; CREATE/RENEW retain their exact result lease class and epoch, and CLOSE retains its exact binding, nonce, zero result lease class, and resulting lease epoch; finalized APPEND reconstructs and verifies the exact Ed25519-signed InboxAppendAckV1 and result commitment; live APPEND requires its exact frame, while expired APPEND kind1/subtype4 requires frame absence, preserves self-contained retention/lease/expiry facts plus exact signed ACK authority, and remains one 512-byte anti-replay control record; charged READ/WATCH reconstruct exact entriesCommitment, optional nextCursor, pinned entry identities, result binding, clientNonce, and committed epoch; verify self-certifying topics, immutable allocationLeaseClass/create commitment, private keyed virtual buckets, frame class/retention/lease, cross-record result identities, retry source commitments, floors, state-machine invariants, and exact global counts; provisional/in-flight reservations are ineligible; live frame body bytes remain external and separately verified'),
  entry('control-snapshot.inbox-value-codecs', 'kind1/subtype1=BlindInboxCommittedSpendSnapshotV1;1/2=BlindInboxTerminalSpendSnapshotV1;1/3=BlindInboxRequestResultSnapshotV1;1/4=BlindInboxExpiredAppendSpendSnapshotV1;2/1=BlindInboxReservedSpendSnapshotV1;4/1=BlindInboxRecordSnapshotV1;4/2=BlindInboxFrameSnapshotV1;6/1=BlindInboxControlGlobalSnapshotV1;6/2=BlindInboxProfileStagingSnapshotV1;6/3=BlindInboxIntegrityEvidenceSnapshotV1;8/1=ChargedUnaryRetryV1 with BlindInboxRetryReconstructionV1;8/2=BlindInboxRetryFramePinSnapshotV1;8/3=BlindInboxRetryMaterialSnapshotV1'),
  entry('control-snapshot.prepared-admission-at-rest', 'BlindPreparedAdmissionStoreV1 preserves the exact bounded admission walCommitRecord already durably committed by the engine so checkpoint recovery can rederive fingerprints and cannot recharge or substitute authority; it contains no application plaintext or capability private key, but operators MUST treat checkpoint/control files as admission-sensitive at-rest data with the same mode-0600, mode-0700-root, backup-encryption, access-control, and secure-retirement requirements as the WAL'),
  entry('hash.checkpoint', 'BLAKE2B256(ASCII(hiverelay.blind.local-checkpoint-hash.v1) || U64BE(len(canonical BlindLocalCheckpointV1)) || canonical BlindLocalCheckpointV1)'),
  entry('hash.control-snapshot', 'BLAKE2B256(ASCII(hiverelay.blind.control-snapshot.v1) || U64BE(len(canonical BlindControlStateSnapshotV1)) || canonical BlindControlStateSnapshotV1)'),
  entry('hash.manifest', 'BLAKE2B256(ASCII(hiverelay.blind.store-manifest-hash.v1) || U64BE(len(canonical complete BlindStoreManifestV1)) || canonical complete BlindStoreManifestV1)'),
  entry('hash.manifest-mac', 'keyed-BLAKE2B256(K_store_manifest, ASCII(hiverelay.blind.store-manifest-mac.v1) || U64BE(len(canonical BlindStoreManifestV1 fields before mac)) || canonical BlindStoreManifestV1 fields before mac)'),
  entry('hash.wal-checksum', 'BLAKE2B256(ASCII(hiverelay.blind.wal-frame-checksum.v1) || complete WAL frame bytes [0,totalLength-32))'),
  entry('hash.wal-frame', 'BLAKE2B256(ASCII(hiverelay.blind.wal-frame-hash.v1) || exact complete WAL frame including checksum)'),
  entry('hash.wal-payload', 'BLAKE2B256(exact payload bytes)'),
  entry('layout.checkpoint-final', 'control/checkpoint-<hash32>.v1'),
  entry('layout.checkpoint-temp', 'control/.checkpoint-<hash32>.v1.<nonce16>.tmp'),
  entry('layout.control-directory', 'control'),
  entry('layout.genesis-intent-final', 'control/genesis-intent.v1'),
  entry('layout.genesis-intent-temp', 'control/.genesis-intent.v1.<nonce16>.tmp'),
  entry('layout.manifest-a-final', 'control/manifest-a.v1'),
  entry('layout.manifest-a-temp', 'control/.manifest-a.v1.<nonce16>.tmp'),
  entry('layout.manifest-b-final', 'control/manifest-b.v1'),
  entry('layout.manifest-b-temp', 'control/.manifest-b.v1.<nonce16>.tmp'),
  entry('layout.placeholder-grammar', '<hash32> is exactly 64 lowercase ASCII hex characters; <nonce16> is exactly 32 lowercase ASCII hex characters'),
  entry('layout.runtime-binding-final', 'runtime-binding.v1'),
  entry('layout.snapshot-final', 'control/snapshot-<hash32>.v1'),
  entry('layout.snapshot-temp', 'control/.snapshot-<hash32>.v1.<nonce16>.tmp'),
  entry('layout.wal-final', 'control/wal.v2'),
  entry('layout.wal-temp', 'NONE; WAL frames append in place to control/wal.v2'),
  entry('layout.writer-lock-final', 'control/writer.lock.v1'),
  entry('layout.writer-lock-temp', 'NONE; the canonical writer-lock inode is opened and exclusively locked for the complete writer session'),
  entry('publication.checkpoint', 'snapshot: CREATE_EXCL temp -> write exact bytes -> fsync temp -> reopen and stream-verify canonical bytes, hash, bindings, and branded semantic reconstruction -> atomic rename-no-replace final -> fsync control directory -> verify final is the same opened inode; checkpoint header: write/fsync/canonical-verify then same no-replace sequence; only then advance both manifest slots by linked CAS; an existing final is accepted only after exact-byte verification and the unused temp is then unlinked and the directory fsynced'),
  entry('publication.genesis', 'profile-1 empty genesis only: classify and stably recheck one canonical daemon-owned mode-0700 empty root; create/fsync control and writer lock under the exclusive store-session lease; install the exact authenticated genesis intent by CREATE_EXCL temp, write, fsync, atomic rename-no-replace, and control-directory fsync; create/fsync blobs and staging; append/fsync exactly one intent-bound WAL sequence-1 frame; require exactly three sorted kind6/subtype1 family-global Cell, Inbox, and Core snapshot entries accepted by the separately branded empty-genesis semantic verifier; publish immutable revision-1 snapshot/checkpoint with no predecessor; initialize both manifest slots to exact authenticated bytes; validate the resulting manifest/checkpoint/snapshot/WAL through validation-only joint recovery while retaining the writer lock; only then unlink/fsync the intent and return the transferred writer lease'),
  entry('publication.manifest', 'advance inactive/opposite slot first and the other slot second; for each: CREATE_EXCL temp -> write exact canonical bytes -> fsync temp -> atomic rename-replace target slot -> fsync control directory -> reopen and verify exact bytes plus MAC'),
  entry('publication.no-overwrite', 'checkpoint and snapshot finals are immutable and content-addressed: an existing target is accepted only after exact-byte equality and is never replaced; manifest slots intentionally use rename-replace; WAL is append-only'),
  entry('publication.wal', 'append one exact complete frame at current EOF -> fsync control/wal.v2 -> advance the in-memory WAL anchor -> only then apply, expose visibility, sign, or acknowledge the transition'),
  entry('recovery.checkpoint-selection', 'only the checkpoint hash and WAL sequence in the selected manifest are current; validate that named header, its adjacent predecessor chain to revision 1, its named snapshot, and every binding/hash before mutation; unreferenced finals are never selected; a missing or conflicting artifact fails closed'),
  entry('recovery.genesis', 'a genesis-incomplete root is resumable only while the exclusive writer lock is held and control/genesis-intent.v1 exactly equals ASCII(HRBGI001)||U16BE(1)||commitment32||keyed-BLAKE2B256(K_store_manifest,ASCII(hiverelay.blind.profile1-genesis-intent-mac.v1)||U64BE(len(prefix))||prefix), where commitment32=BLAKE2B256(ASCII(hiverelay.blind.profile1-genesis-intent.v1)||U64BE(len(canonical manifest-revision-0 template||genesis record))||canonical manifest-revision-0 template||U8(recordType)||U16BE(virtualBucket)||U32BE(payload length)||payload); every existing WAL, snapshot, checkpoint, manifest, directory, and recognized temporary must be the exact intent-derived byte/state transition; WAL/data without the intent, a different intent, extra final, conflicting temp, unsupported root entry, or nonempty semantic fragment fails as legacy-ambiguous; only exact matching checkpoint/snapshot orphan temps may be removed after validation and directory fsync'),
  entry('recovery.manifest-selection', 'MAC/check both slots; zero valid slots fails; one valid slot is selected and needs repair; equal revisions require byte-identical hashes and bytes; unequal revisions require exactly high=low+1 and high.previousManifestHash=hash(low); every other fork or gap fails closed'),
  entry('recovery.temp-selection', 'temporary files are never recovery candidates; validation-only startup never deletes them; a writer may remove recognized manifest temps only after complete validation; checkpoint/snapshot crash-orphan temp reclamation is unsupported'),
  entry('retention.checkpoint', 'retain every immutable checkpoint final indefinitely; checkpoint garbage collection is unsupported'),
  entry('retention.manifest', 'retain exactly two mutable final slots; a completed advance leaves both at the same revision, while a crash may leave one exact adjacent predecessor; recognized manifest temps are bounded and post-validation cleanup only'),
  entry('retention.snapshot', 'retain every immutable snapshot final indefinitely; snapshot garbage collection is part of unsupported checkpoint garbage collection'),
  entry('retention.wal', 'retain every complete WAL v2 frame from sequence 1; WAL pruning and segment replacement are unsupported'),
  entry('retention.writer-lock', 'retain the canonical writer-lock file; hold its exclusive OS/filesystem lock from pre-mutation validation until every store component closes, releasing it last'),
  entry('unsupported.checkpoint-gc', 'UNSUPPORTED; no checkpoint, snapshot, or crash-orphan checkpoint-temp final reclamation algorithm is authorized'),
  entry('unsupported.migration', 'UNSUPPORTED; no online or offline format migration executor is authorized; unknown/mismatched format major, format hash, WAL v1, or provisional layout fails closed'),
  entry('unsupported.wal-pruning', 'UNSUPPORTED; no frame, prefix, segment, or whole-WAL pruning/replacement algorithm is authorized')
])

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function asBytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function printableAscii (value, field, maximum) {
  if (typeof value !== 'string' || value.length === 0 || value !== value.normalize('NFC')) {
    fail(`${field} must be non-empty NFC text`)
  }
  const bytes = b4a.from(value, 'ascii')
  if (bytes.byteLength > maximum || b4a.toString(bytes, 'ascii') !== value) fail(`${field} is outside its ASCII bound`)
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e) fail(`${field} must be printable ASCII`)
  }
  return bytes
}

function readU16 (bytes, offset) {
  return bytes[offset] * 0x100 + bytes[offset + 1]
}

function readU32 (bytes, offset) {
  return bytes[offset] * 0x1000000 + bytes[offset + 1] * 0x10000 + bytes[offset + 2] * 0x100 + bytes[offset + 3]
}

function readU64 (bytes, offset) {
  let value = 0n
  for (let index = 0; index < 8; index++) value = (value << 8n) | BigInt(bytes[offset + index])
  return value
}

function writeU16 (bytes, value, offset) {
  bytes[offset] = value >>> 8
  bytes[offset + 1] = value
}

function writeU32 (bytes, value, offset) {
  bytes[offset] = value >>> 24
  bytes[offset + 1] = value >>> 16
  bytes[offset + 2] = value >>> 8
  bytes[offset + 3] = value
}

function writeU64 (bytes, value, offset) {
  value = BigInt(value)
  for (let index = 7; index >= 0; index--) {
    bytes[offset + index] = Number(value & 0xffn)
    value >>= 8n
  }
}

function validateEntries (entries) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_ENTRY_COUNT) {
    fail(`store-format authority entry count is outside 1..${MAX_ENTRY_COUNT}`)
  }
  let previous = null
  return entries.map((value, index) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`store-format authority entry ${index} must be an object`)
    const name = printableAscii(value.name, `store-format authority entry ${index} name`, MAX_NAME_BYTES)
    const entryValue = printableAscii(value.value, `store-format authority entry ${index} value`, MAX_VALUE_BYTES)
    if (previous != null && b4a.compare(previous, name) >= 0) {
      fail('store-format authority entries must be strictly raw-ASCII sorted and duplicate-free')
    }
    previous = name
    return { name, value: entryValue }
  })
}

export function encodeStoreFormatAuthorityV1 (schemaCatalogBytes, entries = STORE_FORMAT_AUTHORITY_V1) {
  schemaCatalogBytes = asBytes(schemaCatalogBytes, 'store schema catalog')
  if (schemaCatalogBytes.byteLength === 0 || schemaCatalogBytes.byteLength > MAX_SCHEMA_CATALOG_BYTES) {
    fail(`store schema catalog length is outside 1..${MAX_SCHEMA_CATALOG_BYTES}`)
  }
  const normalized = validateEntries(entries)
  let total = HEADER_BYTES + schemaCatalogBytes.byteLength + 2
  for (const value of normalized) total += 2 + value.name.byteLength + 4 + value.value.byteLength
  const output = b4a.alloc(total)
  b4a.copy(MAGIC, output, 0)
  writeU16(output, AUTHORITY_VERSION, 8)
  writeU16(output, FORMAT_MAJOR, 10)
  writeU16(output, FORMAT_MINOR, 12)
  writeU64(output, schemaCatalogBytes.byteLength, 14)
  let offset = HEADER_BYTES
  b4a.copy(schemaCatalogBytes, output, offset)
  offset += schemaCatalogBytes.byteLength
  writeU16(output, normalized.length, offset)
  offset += 2
  for (const value of normalized) {
    writeU16(output, value.name.byteLength, offset)
    offset += 2
    b4a.copy(value.name, output, offset)
    offset += value.name.byteLength
    writeU32(output, value.value.byteLength, offset)
    offset += 4
    b4a.copy(value.value, output, offset)
    offset += value.value.byteLength
  }
  return output
}

export function decodeStoreFormatAuthorityV1 (input, options = {}) {
  const bytes = asBytes(input, 'store-format authority artifact')
  const copyBytes = options && options.copyBytes === true
  if (bytes.byteLength < HEADER_BYTES + 2 || !b4a.equals(bytes.subarray(0, 8), MAGIC)) {
    fail('store-format authority artifact has invalid magic or is truncated')
  }
  const authorityVersion = readU16(bytes, 8)
  const formatMajor = readU16(bytes, 10)
  const formatMinor = readU16(bytes, 12)
  if (authorityVersion !== AUTHORITY_VERSION || formatMajor !== FORMAT_MAJOR || formatMinor !== FORMAT_MINOR) {
    fail('store-format authority artifact has an unsupported version')
  }
  const schemaLengthBig = readU64(bytes, 14)
  if (schemaLengthBig === 0n || schemaLengthBig > BigInt(MAX_SCHEMA_CATALOG_BYTES)) {
    fail('store-format authority schema catalog length is invalid')
  }
  const schemaLength = Number(schemaLengthBig)
  let offset = HEADER_BYTES
  if (offset + schemaLength + 2 > bytes.byteLength) fail('store-format authority schema catalog is truncated')
  const schemaCatalogBytes = bytes.subarray(offset, offset + schemaLength)
  offset += schemaLength
  const count = readU16(bytes, offset)
  offset += 2
  if (count === 0 || count > MAX_ENTRY_COUNT) fail('store-format authority entry count is invalid')
  const entries = []
  for (let index = 0; index < count; index++) {
    if (offset + 2 > bytes.byteLength) fail('store-format authority entry name length is truncated')
    const nameLength = readU16(bytes, offset)
    offset += 2
    if (nameLength === 0 || nameLength > MAX_NAME_BYTES || offset + nameLength + 4 > bytes.byteLength) {
      fail('store-format authority entry name is invalid or truncated')
    }
    const nameBytes = bytes.subarray(offset, offset + nameLength)
    offset += nameLength
    const valueLength = readU32(bytes, offset)
    offset += 4
    if (valueLength === 0 || valueLength > MAX_VALUE_BYTES || offset + valueLength > bytes.byteLength) {
      fail('store-format authority entry value is invalid or truncated')
    }
    const valueBytes = bytes.subarray(offset, offset + valueLength)
    offset += valueLength
    entries.push({
      name: b4a.toString(nameBytes, 'ascii'),
      value: b4a.toString(valueBytes, 'ascii')
    })
  }
  if (offset !== bytes.byteLength) fail('store-format authority artifact has trailing bytes')
  validateEntries(entries)
  return Object.freeze({
    authorityVersion,
    formatMajor,
    formatMinor,
    schemaCatalogBytes: copyBytes ? b4a.from(schemaCatalogBytes) : schemaCatalogBytes,
    entries: Object.freeze(entries.map(value => Object.freeze(value)))
  })
}

// Verifies the complete authority artifact, rather than only decoding its
// framing. A conforming local implementation must bind the exact generated
// INTERNAL_STORE catalog, the frozen rule set in this module, and (when used by
// a signed runtime) the expected descriptor hash. Keeping this verifier beside
// the encoder makes source/catalog drift executable and fail-closed.
export function verifyStoreFormatAuthorityV1 (input, options = {}) {
  const bytes = asBytes(input, 'store-format authority artifact')
  const schemaCatalogBytes = asBytes(options.schemaCatalogBytes, 'store schema catalog')
  const expectedStoreFormatHash = options.expectedStoreFormatHash == null
    ? null
    : asBytes(options.expectedStoreFormatHash, 'expected storeFormatHash')
  if (expectedStoreFormatHash != null && expectedStoreFormatHash.byteLength !== 32) {
    fail('expected storeFormatHash must be exactly 32 bytes')
  }

  const decoded = decodeStoreFormatAuthorityV1(bytes)
  if (!b4a.equals(decoded.schemaCatalogBytes, schemaCatalogBytes)) {
    fail('store-format authority does not embed the expected complete schema catalog')
  }
  if (decoded.entries.length !== STORE_FORMAT_AUTHORITY_V1.length) {
    fail('store-format authority does not contain the complete frozen rule set')
  }
  for (let index = 0; index < STORE_FORMAT_AUTHORITY_V1.length; index++) {
    const expected = STORE_FORMAT_AUTHORITY_V1[index]
    const actual = decoded.entries[index]
    if (actual.name !== expected.name || actual.value !== expected.value) {
      fail(`store-format authority rule ${index} does not match the frozen source authority`)
    }
  }
  const reproduced = encodeStoreFormatAuthorityV1(schemaCatalogBytes)
  if (!b4a.equals(reproduced, bytes)) {
    fail('store-format authority is not the exact deterministic generated artifact')
  }
  const storeFormatHash = hashStoreFormat(bytes)
  if (expectedStoreFormatHash != null && !b4a.equals(storeFormatHash, expectedStoreFormatHash)) {
    fail('store-format authority hash does not match the expected storeFormatHash')
  }

  return Object.freeze({
    authorityVersion: decoded.authorityVersion,
    formatMajor: decoded.formatMajor,
    formatMinor: decoded.formatMinor,
    authorityBytes: b4a.from(bytes),
    schemaCatalogBytes: b4a.from(schemaCatalogBytes),
    storeFormatHash: b4a.from(storeFormatHash)
  })
}

export const STORE_FORMAT_AUTHORITY_LAYOUT_V1 = Object.freeze({
  magic: b4a.toString(MAGIC, 'ascii'),
  authorityVersion: AUTHORITY_VERSION,
  formatMajor: FORMAT_MAJOR,
  formatMinor: FORMAT_MINOR,
  headerBytes: HEADER_BYTES,
  maximumSchemaCatalogBytes: MAX_SCHEMA_CATALOG_BYTES,
  maximumEntryCount: MAX_ENTRY_COUNT
})
