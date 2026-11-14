import test from 'brittle'
import { createHash } from 'crypto'
import {
  mkdtempSync,
  mkdirSync,
  chmodSync,
  symlinkSync,
  writeFileSync
} from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  CORESTORE_GENERATION_CAPABILITIES,
  CORESTORE_GENERATION_ENVELOPE,
  CORESTORE_GENERATION_MIGRATION_BINDING
} from '../../packages/core/core/persistence/corestore-generation-envelope.js'
import {
  corestoreGenerationReceiptBytes,
  parseCorestoreGenerationReceiptBytes,
  parseGenerationReceiptRequiredEnvironment,
  readCorestoreGenerationReceipt,
  resolveCorestoreGenerationReceiptLaunch
} from '../../packages/core/core/persistence/storage-generation-receipt.js'

function fixture (participants = ['bare-relay', 'relay-node']) {
  return {
    schema: CORESTORE_GENERATION_ENVELOPE.schema,
    mode: CORESTORE_GENERATION_ENVELOPE.mode,
    installationId: '11'.repeat(32),
    authorityKeySha256: `sha256:${'22'.repeat(32)}`,
    manifestSha256: `sha256:${'33'.repeat(32)}`,
    participants,
    topLevelSidecars: ['app-registry.json', 'identity.key'],
    generation: CORESTORE_GENERATION_ENVELOPE.generation,
    generationRoot: CORESTORE_GENERATION_ENVELOPE.generationRoot,
    oldWriterFenceScope: CORESTORE_GENERATION_CAPABILITIES.oldWriterFenceScope,
    migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING
  }
}

function sha256 (bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function temporaryLayout (t) {
  const root = mkdtempSync(join(tmpdir(), 'hiverelay-generation-receipt-'))
  const storage = join(root, 'storage')
  const config = join(root, 'config')
  mkdirSync(storage)
  mkdirSync(config)
  t.teardown(() => rm(root, { recursive: true, force: true }))
  return { root, storage, config }
}

test('generation receipt accepts one canonical externally pinned byte sequence', (t) => {
  const receipt = fixture()
  const bytes = corestoreGenerationReceiptBytes(receipt)
  const parsed = parseCorestoreGenerationReceiptBytes(bytes, {
    expectedSha256: sha256(bytes),
    participant: 'relay-node'
  })

  t.is(parsed.receiptSha256, sha256(bytes))
  t.is(parsed.hiverelayGeneration.mode, CORESTORE_GENERATION_ENVELOPE.mode)
  t.is(parsed.hiverelayGeneration.expectedInstallationId, receipt.installationId)
  t.absent(parsed.hiverelayGeneration.participant, 'runtime participant is injected at the owning open call')
  t.ok(Object.isFrozen(parsed.receipt))
})

test('generation receipt rejects byte, schema, tooling, ordering, and participant drift', (t) => {
  const receipt = fixture()
  const bytes = corestoreGenerationReceiptBytes(receipt)
  const digest = sha256(bytes)

  t.exception(() => parseCorestoreGenerationReceiptBytes(bytes, {
    expectedSha256: `sha256:${'ff'.repeat(32)}`,
    participant: 'relay-node'
  }), /external SHA-256 pin/)

  const pretty = Buffer.from(JSON.stringify(receipt, null, 2) + '\n')
  t.exception(() => parseCorestoreGenerationReceiptBytes(pretty, {
    expectedSha256: sha256(pretty),
    participant: 'relay-node'
  }), /unique canonical JSON/)

  const unknown = { ...receipt, unexpected: true }
  const unknownBytes = Buffer.from(JSON.stringify(unknown) + '\n')
  t.exception(() => parseCorestoreGenerationReceiptBytes(unknownBytes, {
    expectedSha256: sha256(unknownBytes),
    participant: 'relay-node'
  }), /closed schema/)

  t.exception(() => corestoreGenerationReceiptBytes({
    ...receipt,
    migrationTooling: { ...receipt.migrationTooling, toolingCommit: '00'.repeat(20) }
  }), /accepted storage-generation binding/)

  t.exception(() => parseCorestoreGenerationReceiptBytes(bytes, {
    expectedSha256: digest,
    participant: 'standalone-gateway'
  }), /does not authorize runtime participant/)

  t.exception(() => corestoreGenerationReceiptBytes({
    ...receipt,
    participants: ['relay-node', 'bare-relay']
  }), /code-unit order/)
})

test('generation receipt file and external pin file close launcher input', (t) => {
  const { storage, config } = temporaryLayout(t)
  const bytes = corestoreGenerationReceiptBytes(fixture())
  const digest = sha256(bytes)
  const receiptPath = join(config, 'storage-generation-receipt.v1.json')
  const pinPath = join(config, 'storage-generation-receipt.v1.sha256')
  writeFileSync(receiptPath, bytes, { mode: 0o600 })
  writeFileSync(pinPath, `${digest}\n`, { mode: 0o600 })
  chmodSync(receiptPath, 0o400)
  chmodSync(pinPath, 0o400)

  const fromFile = readCorestoreGenerationReceipt(receiptPath, {
    expectedSha256File: pinPath,
    participant: 'bare-relay',
    storageRoot: storage
  })
  t.is(fromFile.pinSource, 'file')
  t.is(fromFile.receiptSha256, digest)

  const fromBoth = resolveCorestoreGenerationReceiptLaunch({
    required: true,
    receiptPath,
    expectedSha256: digest,
    expectedSha256File: pinPath,
    participant: 'relay-node',
    storageRoot: storage
  })
  t.is(fromBoth.pinSource, 'direct-and-file')
  t.is(fromBoth.receiptSha256, digest)

  t.is(resolveCorestoreGenerationReceiptLaunch({ required: false }), null)
  t.exception(() => resolveCorestoreGenerationReceiptLaunch({ required: true }), /requires an exact external/)
  t.exception(() => resolveCorestoreGenerationReceiptLaunch({ receiptPath }), /direct SHA-256 pin or an external pin file/)
})

test('generation receipt rejects mutable-root placement, symlinks, and conflicting pins', (t) => {
  const { storage, config } = temporaryLayout(t)
  const bytes = corestoreGenerationReceiptBytes(fixture())
  const digest = sha256(bytes)
  const receiptPath = join(config, 'receipt.json')
  const pinPath = join(config, 'receipt.sha256')
  writeFileSync(receiptPath, bytes)
  writeFileSync(pinPath, `${digest}\n`)

  const embedded = join(storage, 'receipt.json')
  writeFileSync(embedded, bytes)
  t.exception(() => readCorestoreGenerationReceipt(embedded, {
    expectedSha256: digest,
    participant: 'relay-node',
    storageRoot: storage
  }), /external to the mutable Corestore generation root/)

  t.exception(() => readCorestoreGenerationReceipt(receiptPath, {
    expectedSha256: digest,
    participant: 'relay-node',
    storageRoot: storage
  }), /must be read-only to the runtime/)

  chmodSync(receiptPath, 0o400)
  chmodSync(pinPath, 0o400)

  const linked = join(config, 'linked.json')
  symlinkSync(receiptPath, linked)
  t.exception(() => readCorestoreGenerationReceipt(linked, {
    expectedSha256: digest,
    participant: 'relay-node',
    storageRoot: storage
  }), /must not be a symbolic link/)

  t.exception(() => readCorestoreGenerationReceipt(receiptPath, {
    expectedSha256: `sha256:${'aa'.repeat(32)}`,
    expectedSha256File: pinPath,
    participant: 'relay-node',
    storageRoot: storage
  }), /pins disagree/)
})

test('generation receipt production flag parsing is closed', (t) => {
  t.is(parseGenerationReceiptRequiredEnvironment(undefined), false)
  t.is(parseGenerationReceiptRequiredEnvironment('true'), true)
  t.is(parseGenerationReceiptRequiredEnvironment('1'), true)
  t.is(parseGenerationReceiptRequiredEnvironment('false'), false)
  t.is(parseGenerationReceiptRequiredEnvironment('0'), false)
  t.exception(() => parseGenerationReceiptRequiredEnvironment('yes'), /must be 1, true, 0, or false/)
})
