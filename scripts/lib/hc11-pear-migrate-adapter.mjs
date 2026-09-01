import { createHash } from 'node:crypto'
import {
  CORESTORE_GENERATION_ENVELOPE,
  CORESTORE_GENERATION_MIGRATION_BINDING
} from '../../packages/core/core/persistence/corestore-generation-envelope.js'

export const HC11_PEAR_MIGRATE_ADAPTER = Object.freeze({
  inputSchema: 'hiverelay-pear-migrate-hc11-adapter-input-v1',
  profileId: 'hiverelay-d7b-cutover',
  profileSha256: 'sha256:f1d578f20a2529ce1280c2883df88ed1fcd9ab35ef1da240d3cb90430e894a41',
  contractBindings: Object.freeze({
    'canonical-contracts-acceptance': 'sha256:ac6f4fbff7b7af9ff196947e3fe0d3ee3df9c22471e5e6f5ab98cf5af3f8fb75',
    'canonical-contract-artifact': 'sha256:fa4d11ef9554870b752a843d0b04c5df4d104029fd07feb1f44d9dbd6b331a6d',
    'canonical-vector-record': 'sha256:ba62fa3cdcf0e1ca76bea71ac3074ee2814aad1808510cd1166ef3cf0b5f2549',
    'compatibility-record': 'sha256:67a04157a7168e9d7d45ce2d614f0cd9c061e5600d47b0daf459e2956c79dfda',
    'owner-ratification': 'sha256:0b24dfd493990e6b6b2cbd1ded61ee1c246f349e21694aaf7bcbfe20eca7d4c5',
    'owner-ratification-independent-review': 'sha256:3014198aac75508c54e54e2e25d2db5b0298761e235cd50abbff86b817f5ea4d'
  })
})

const INPUT_KEYS = ['migration_id', 'old_writer_fence', 'rollback', 'schema', 'state_objects']
const TRIGGER_KEYS = [
  'activationSentinel',
  'blindCumulativeDualReadImplemented',
  'deviceRestoreReceiptSha256',
  'generationFingerprintSha256',
  'importedLegacyContentSha256',
  'installationId',
  'kind',
  'manifestSha256',
  'migrationRecordAdapterRequired',
  'migrationRecordCompatible',
  'migrationTooling',
  'participant',
  'pearMigrateCandidateWriterMode',
  'result',
  'schema',
  'sequence',
  'triggerRecordSha256',
  'verifiedReaderState'
]
const ACTIVATION_KEYS = ['blockSha256', 'fork', 'key', 'length', 'participant', 'schema']
const STATE_KEYS = ['before_sha256', 'classification', 'id', 'preservation', 'restore']
const PRESERVATION_KEYS = ['artifact_sha256', 'content_sha256', 'evidence_sha256', 'method', 'verified']
const RESTORE_KEYS = ['evidence_sha256', 'restored_sha256', 'status']
const FENCE_INPUT_KEYS = ['evidence_sha256', 'legacy_writer_result', 'status']
const ROLLBACK_KEYS = ['evidence_sha256', 'read_generations', 'status', 'target_mode']
const DIGEST = /^sha256:[0-9a-f]{64}$/
const HEX_32 = /^[0-9a-f]{64}$/
const IDENTIFIER = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const CLASSIFICATIONS = new Set(['reproducible', 'independently-retrieval-proven', 'sacred-contractual'])
const PRESERVATION_METHODS = new Set(['exact-copy', 'offline-backup', 'independent-retrieval', 'authenticated-republish'])

export function adaptHc11TriggerToPearMigrateRecord ({
  triggerReceipt,
  triggerReceiptBytes,
  evidence,
  evidenceBytes
} = {}) {
  exactCanonicalBinding(triggerReceipt, triggerReceiptBytes, 'HC11 trigger receipt')
  exactCanonicalBinding(evidence, evidenceBytes, 'HC11 pear-migrate adapter evidence')
  validateTriggerReceipt(triggerReceipt)
  validateEvidence(evidence)

  return deepFreeze({
    schema_version: 1,
    migration_id: evidence.migration_id,
    profile_id: HC11_PEAR_MIGRATE_ADAPTER.profileId,
    contract_bindings: { ...HC11_PEAR_MIGRATE_ADAPTER.contractBindings },
    state_objects: clone(evidence.state_objects),
    writes: [{
      sequence: triggerReceipt.sequence,
      kind: triggerReceipt.kind,
      writer_mode: triggerReceipt.pearMigrateCandidateWriterMode,
      result: triggerReceipt.result,
      receipt_sha256: sha256(Buffer.from(triggerReceiptBytes))
    }],
    old_writer_fence: {
      activated_at_sequence: triggerReceipt.sequence,
      legacy_writer_result: evidence.old_writer_fence.legacy_writer_result,
      status: evidence.old_writer_fence.status,
      evidence_sha256: evidence.old_writer_fence.evidence_sha256
    },
    rollback: clone(evidence.rollback)
  })
}

export function hc11PearMigrateRecordBytes (record) {
  return canonicalBytes(record)
}

export function parseExactCanonicalJsonBytes (bytes, label) {
  bytes = Buffer.from(bytes || [])
  if (bytes.byteLength < 2 || bytes.byteLength > 2 * 1024 * 1024) throw new Error(`${label} must contain 2..2097152 bytes`)
  const text = bytes.toString('utf8')
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error(`${label} must be valid UTF-8`)
  let value
  try {
    value = JSON.parse(text)
  } catch {
    throw new Error(`${label} must be valid JSON`)
  }
  exactCanonicalBinding(value, bytes, label)
  return value
}

function validateTriggerReceipt (receipt) {
  exactObject(receipt, TRIGGER_KEYS, 'HC11 trigger receipt')
  if (receipt.schema !== 'hiverelay-corestore-generation-trigger-receipt-v1' ||
      receipt.sequence !== 1 || receipt.kind !== 'hc11-only-write' || receipt.result !== 'acknowledged') {
    throw new Error('HC11 trigger receipt does not establish the accepted first acknowledged HC11-only write')
  }
  if (!HEX_32.test(receipt.installationId || '') || !DIGEST.test(receipt.manifestSha256 || '') ||
      !DIGEST.test(receipt.generationFingerprintSha256 || '') || !DIGEST.test(receipt.triggerRecordSha256 || '') ||
      !DIGEST.test(receipt.importedLegacyContentSha256 || '')) {
    throw new Error('HC11 trigger receipt identity or content digests are invalid')
  }
  if (receipt.deviceRestoreReceiptSha256 != null && !DIGEST.test(receipt.deviceRestoreReceiptSha256)) {
    throw new Error('HC11 trigger receipt device restore digest is invalid')
  }
  if (typeof receipt.participant !== 'string' || !SAFE_NAME.test(receipt.participant)) {
    throw new Error('HC11 trigger receipt participant is invalid')
  }
  if (receipt.verifiedReaderState !== 'imported-cs6-plus-hc11' ||
      receipt.pearMigrateCandidateWriterMode !== 'dual-read' ||
      receipt.migrationRecordCompatible !== false ||
      receipt.migrationRecordAdapterRequired !== true ||
      receipt.blindCumulativeDualReadImplemented !== false) {
    throw new Error('HC11 trigger receipt is not the accepted non-blind imported-state adapter boundary')
  }
  exactObject(receipt.activationSentinel, ACTIVATION_KEYS, 'HC11 activation sentinel')
  if (receipt.activationSentinel.schema !== CORESTORE_GENERATION_ENVELOPE.activationSchema ||
      !HEX_32.test(receipt.activationSentinel.key || '') ||
      receipt.activationSentinel.length !== 1 ||
      !Number.isSafeInteger(receipt.activationSentinel.fork) || receipt.activationSentinel.fork < 0 ||
      !DIGEST.test(receipt.activationSentinel.blockSha256 || '') ||
      receipt.activationSentinel.participant !== receipt.participant) {
    throw new Error('HC11 activation sentinel does not close the trigger participant and first durable block')
  }
  exactObject(receipt.migrationTooling, Object.keys(CORESTORE_GENERATION_MIGRATION_BINDING).sort(compareCodeUnits), 'HC11 trigger migrationTooling')
  if (!canonicalBytes(receipt.migrationTooling).equals(canonicalBytes(CORESTORE_GENERATION_MIGRATION_BINDING))) {
    throw new Error('HC11 trigger migrationTooling does not match the accepted binding')
  }
}

function validateEvidence (evidence) {
  exactObject(evidence, INPUT_KEYS, 'HC11 pear-migrate adapter evidence')
  if (evidence.schema !== HC11_PEAR_MIGRATE_ADAPTER.inputSchema) throw new Error('HC11 adapter evidence schema is invalid')
  if (typeof evidence.migration_id !== 'string' || !IDENTIFIER.test(evidence.migration_id)) {
    throw new Error('HC11 adapter migration_id is invalid')
  }
  if (!Array.isArray(evidence.state_objects) || evidence.state_objects.length < 1) {
    throw new Error('HC11 adapter requires a non-empty exact state inventory')
  }
  const ids = new Set()
  for (const state of evidence.state_objects) {
    exactObject(state, STATE_KEYS, 'HC11 adapter state object')
    if (!IDENTIFIER.test(state.id || '') || ids.has(state.id)) throw new Error('HC11 adapter state object ids must be unique bounded identifiers')
    ids.add(state.id)
    if (!CLASSIFICATIONS.has(state.classification)) throw new Error('HC11 adapter state object classification is not promotable')
    digest(state.before_sha256, 'state before_sha256')
    exactObject(state.preservation, PRESERVATION_KEYS, 'HC11 adapter state preservation')
    if (!PRESERVATION_METHODS.has(state.preservation.method) || state.preservation.verified !== true) {
      throw new Error('HC11 adapter state preservation is not verified under the accepted method inventory')
    }
    for (const field of ['content_sha256', 'artifact_sha256', 'evidence_sha256']) digest(state.preservation[field], `state preservation ${field}`)
    if (state.preservation.content_sha256 !== state.before_sha256) throw new Error('HC11 adapter preserved state digest does not match pre-cutover state')
    exactObject(state.restore, RESTORE_KEYS, 'HC11 adapter state restore')
    digest(state.restore.restored_sha256, 'state restore restored_sha256')
    digest(state.restore.evidence_sha256, 'state restore evidence_sha256')
    if (state.restore.status !== 'passed' || state.restore.restored_sha256 !== state.before_sha256) {
      throw new Error('HC11 adapter isolated restore proof does not match pre-cutover state')
    }
  }
  exactObject(evidence.old_writer_fence, FENCE_INPUT_KEYS, 'HC11 adapter old-writer fence')
  digest(evidence.old_writer_fence.evidence_sha256, 'old-writer fence evidence_sha256')
  if (evidence.old_writer_fence.legacy_writer_result !== 'rejected' || evidence.old_writer_fence.status !== 'passed') {
    throw new Error('HC11 adapter old-writer fence is not a passed legacy rejection')
  }
  exactObject(evidence.rollback, ROLLBACK_KEYS, 'HC11 adapter rollback')
  digest(evidence.rollback.evidence_sha256, 'rollback evidence_sha256')
  if (evidence.rollback.target_mode !== 'dual-read' || evidence.rollback.status !== 'passed' ||
      !sameStrings(evidence.rollback.read_generations, ['legacy', 'hc11'])) {
    throw new Error('HC11 adapter rollback must be a passed dual-read rehearsal over legacy and hc11')
  }
}

function exactCanonicalBinding (value, bytes, label) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  if (!canonicalBytes(value).equals(Buffer.from(bytes || []))) throw new Error(`${label} bytes must be the unique canonical JSON encoding`)
}

function exactObject (value, keys, label) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  const actual = Object.keys(value).sort(compareCodeUnits)
  if (!sameStrings(actual, keys)) throw new Error(`${label} fields do not match the closed schema`)
}

function digest (value, label) {
  if (!DIGEST.test(value || '')) throw new Error(`${label} must be sha256:<64 lowercase hex>`)
}

function clone (value) {
  return JSON.parse(JSON.stringify(value))
}

function canonicalBytes (value) {
  return Buffer.from(JSON.stringify(stableValue(value)) + '\n')
}

function stableValue (value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value == null || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort(compareCodeUnits).map(key => [key, stableValue(value[key])]))
}

function deepFreeze (value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child)
    Object.freeze(value)
  }
  return value
}

function sha256 (bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function sameStrings (left, right) {
  return Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index])
}

function compareCodeUnits (left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}
