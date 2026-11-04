import test from 'brittle'
import { execFileSync } from 'child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  CORESTORE_GENERATION_ENVELOPE,
  CORESTORE_GENERATION_MIGRATION_BINDING
} from '../../packages/core/core/persistence/corestore-generation-envelope.js'
import {
  adaptHc11TriggerToPearMigrateRecord,
  HC11_PEAR_MIGRATE_ADAPTER,
  hc11PearMigrateRecordBytes,
  parseExactCanonicalJsonBytes
} from '../../scripts/lib/hc11-pear-migrate-adapter.mjs'

const D = value => `sha256:${String(value).repeat(64)}`

function triggerReceipt () {
  return {
    schema: 'hiverelay-corestore-generation-trigger-receipt-v1',
    installationId: '11'.repeat(32),
    manifestSha256: D('2'),
    sequence: 1,
    kind: 'hc11-only-write',
    result: 'acknowledged',
    participant: 'relay-node',
    generationFingerprintSha256: D('3'),
    activationSentinel: {
      schema: CORESTORE_GENERATION_ENVELOPE.activationSchema,
      key: '44'.repeat(32),
      length: 1,
      fork: 0,
      blockSha256: D('5'),
      participant: 'relay-node'
    },
    triggerRecordSha256: D('6'),
    deviceRestoreReceiptSha256: null,
    importedLegacyContentSha256: D('7'),
    verifiedReaderState: 'imported-cs6-plus-hc11',
    pearMigrateCandidateWriterMode: 'dual-read',
    migrationRecordCompatible: false,
    migrationRecordAdapterRequired: true,
    blindCumulativeDualReadImplemented: false,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
}

function adapterEvidence () {
  return {
    schema: HC11_PEAR_MIGRATE_ADAPTER.inputSchema,
    migration_id: 'utah-rc9-hc11-cutover',
    state_objects: [{
      id: 'legacy-root',
      classification: 'sacred-contractual',
      before_sha256: D('8'),
      preservation: {
        method: 'offline-backup',
        content_sha256: D('8'),
        artifact_sha256: D('9'),
        evidence_sha256: D('a'),
        verified: true
      },
      restore: {
        status: 'passed',
        restored_sha256: D('8'),
        evidence_sha256: D('b')
      }
    }],
    old_writer_fence: {
      legacy_writer_result: 'rejected',
      status: 'passed',
      evidence_sha256: D('c')
    },
    rollback: {
      target_mode: 'dual-read',
      status: 'passed',
      read_generations: ['legacy', 'hc11'],
      evidence_sha256: D('d')
    }
  }
}

test('HC11 adapter emits the exact accepted pear-migrate D7-B record shape', (t) => {
  const trigger = triggerReceipt()
  const evidence = adapterEvidence()
  const triggerBytes = canonicalBytes(trigger)
  const evidenceBytes = canonicalBytes(evidence)
  const record = adaptHc11TriggerToPearMigrateRecord({
    triggerReceipt: trigger,
    triggerReceiptBytes: triggerBytes,
    evidence,
    evidenceBytes
  })

  t.is(record.profile_id, HC11_PEAR_MIGRATE_ADAPTER.profileId)
  t.alike(record.contract_bindings, HC11_PEAR_MIGRATE_ADAPTER.contractBindings)
  t.alike(record.writes.map(write => [write.sequence, write.kind, write.writer_mode, write.result]), [
    [1, 'hc11-only-write', 'dual-read', 'acknowledged']
  ])
  t.is(record.old_writer_fence.activated_at_sequence, 1)
  t.alike(record.rollback.read_generations, ['legacy', 'hc11'])
  t.ok(Object.isFrozen(record))
  t.alike(parseExactCanonicalJsonBytes(hc11PearMigrateRecordBytes(record), 'record'), JSON.parse(JSON.stringify(record)))
})

test('HC11 adapter rejects fresh roots, evidence gaps, drift, and non-canonical bytes', (t) => {
  const trigger = triggerReceipt()
  const evidence = adapterEvidence()

  const fresh = { ...trigger, importedLegacyContentSha256: null, verifiedReaderState: 'fresh-hc11-only', pearMigrateCandidateWriterMode: null }
  t.exception(() => adapt(fresh, evidence), /identity or content digests are invalid|accepted non-blind imported-state adapter boundary/)

  const blind = { ...trigger, blindCumulativeDualReadImplemented: true }
  t.exception(() => adapt(blind, evidence), /accepted non-blind imported-state adapter boundary/)

  const unverified = adapterEvidence()
  unverified.state_objects[0].preservation.verified = false
  t.exception(() => adapt(trigger, unverified), /preservation is not verified/)

  const legacyRollback = adapterEvidence()
  legacyRollback.rollback.target_mode = 'legacy-only'
  t.exception(() => adapt(trigger, legacyRollback), /passed dual-read rehearsal/)

  const pretty = Buffer.from(JSON.stringify(trigger, null, 2) + '\n')
  t.exception(() => adaptHc11TriggerToPearMigrateRecord({
    triggerReceipt: trigger,
    triggerReceiptBytes: pretty,
    evidence,
    evidenceBytes: canonicalBytes(evidence)
  }), /unique canonical JSON/)
})

test('HC11 adapter CLI writes one exclusive canonical record', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'hiverelay-pear-migrate-adapter-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const triggerFile = join(root, 'trigger.json')
  const evidenceFile = join(root, 'evidence.json')
  const outputFile = join(root, 'record.json')
  writeFileSync(triggerFile, canonicalBytes(triggerReceipt()))
  writeFileSync(evidenceFile, canonicalBytes(adapterEvidence()))

  execFileSync(process.execPath, [
    'scripts/adapt-pear-migrate-hc11-trigger.mjs',
    '--trigger-receipt', triggerFile,
    '--evidence', evidenceFile,
    '--out', outputFile
  ], { cwd: process.cwd() })

  const record = parseExactCanonicalJsonBytes(readFileSync(outputFile), 'record')
  t.is(record.migration_id, 'utah-rc9-hc11-cutover')
  t.is(record.writes[0].kind, 'hc11-only-write')
  t.exception(() => execFileSync(process.execPath, [
    'scripts/adapt-pear-migrate-hc11-trigger.mjs',
    '--trigger-receipt', triggerFile,
    '--evidence', evidenceFile,
    '--out', outputFile
  ], { cwd: process.cwd(), stdio: 'pipe' }), /Command failed/)
})

function adapt (trigger, evidence) {
  return adaptHc11TriggerToPearMigrateRecord({
    triggerReceipt: trigger,
    triggerReceiptBytes: canonicalBytes(trigger),
    evidence,
    evidenceBytes: canonicalBytes(evidence)
  })
}

function canonicalBytes (value) {
  return Buffer.from(JSON.stringify(stable(value)) + '\n')
}

function stable (value) {
  if (Array.isArray(value)) return value.map(stable)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
}
