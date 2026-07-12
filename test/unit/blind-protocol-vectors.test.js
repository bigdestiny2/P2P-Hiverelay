import fs from 'fs'
import test from 'brittle'
import b4a from 'b4a'
import {
  admissionParametersV1,
  admissionProfileV1,
  batchGetResultV1,
  batchGetSignaturePayloadV1,
  batchGetV1,
  blindBackupChunkManifestV1,
  blindBackupEncryptionProfileV1,
  blindBackupManifestV1,
  blindBackupRetentionTransitionV1,
  blindCleanRestoreEvidenceV1,
  blindCoreAckV1,
  blindDhtPointerV1,
  blindExternalJournalTopologyV1,
  blindExternalCommitWitnessV1,
  blindForwardCloseV1,
  blindForwardDataV1,
  blindForwardOpenResultV1,
  blindForwardOpenV1,
  blindForwardWindowV1,
  blindHealthChallengeV1,
  blindHealthResultV1,
  blindControlStateSnapshotV1,
  blindLocalCheckpointV1,
  blindOhttpKeyConfigV1,
  blindRestoreEvidenceBundleV1,
  blindRestoreEvidenceHeadV1,
  blindServiceDescriptorV1,
  blindStreamChunkPlainV1,
  blindWalHeaderV2,
  blake2b256,
  coreMirrorRequestV1,
  coreServeChallengeV1,
  coreServeResultV1,
  compileMasterSchemaCatalog,
  compileMasterSchemaCatalogForCategory,
  controlSnapshotHash,
  decodeCanonical,
  decodeSchemaCatalog,
  decodeDispatchFrame,
  decodeOuterEnvelope,
  decodeVectorManifest,
  domainRegistryEntryV1,
  durabilityContinuityBindingV1,
  encodeWireAbiRegistry,
  encodeCanonical,
  errorProfileEntryV1,
  getCellResultV1,
  hashAbi,
  hashSpec,
  hashVectorSet,
  inboxAppendV1,
  inboxReadResultV1,
  inboxReadSignaturePayloadV1,
  inboxReadV1,
  localCheckpointHash,
  operationProfileV1,
  putCellV1,
  relayResultBindingV1,
  relayIdentityTransitionV1,
  SCHEMA_CATEGORY,
  SCHEMA_NAMES_BY_CATEGORY,
  schemaCatalogEntryV1
} from '@hiverelay/blind-protocol'

const vectorUrl = name => new URL(`../../packages/blind-protocol/vectors/draft/${name}`, import.meta.url)
const readVector = name => fs.readFileSync(vectorUrl(name))
const masterSpecUrl = new URL('../../docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md', import.meta.url)
const masterSchemaCatalog = () => compileMasterSchemaCatalog(fs.readFileSync(masterSpecUrl, 'utf8'))

test('blind vectors: checked-in dispatch bytes are frozen', (t) => {
  const cellGet = readVector('dispatch/cell-get-request.bin')
  const forwardData = readVector('dispatch/forward-data.bin')
  t.is(
    b4a.toString(cellGet, 'hex'),
    '0000002d010102020000112233445566778899aabbccddeeff000000000000000000000000000000000000000401020304'
  )
  t.is(
    b4a.toString(forwardData, 'hex'),
    '0000002d0104050200000000000000000000000000000000000102030405060708000000000000000900000004a0a1a2a3'
  )
  t.is(decodeDispatchFrame(cellGet).familyId, 2)
  t.is(decodeDispatchFrame(forwardData).streamId, 0x0102030405060708n)
})

test('blind vectors: negative frames and padded outer fixture behave as declared', (t) => {
  t.exception(() => decodeDispatchFrame(readVector('invalid/dispatch-nonzero-flags.bin')), /flags are reserved/)
  t.exception(() => decodeDispatchFrame(readVector('invalid/dispatch-unknown-operation.bin')), /unknown family\/operation/)
  const outer = decodeOuterEnvelope(readVector('outer/cell-get-class-1.bin'))
  t.is(outer.outerClass, 1)
  t.is(outer.frame.familyId, 2)
})

test('blind vectors: checked-in authority remains immutable while candidate regeneration is blocked', (t) => {
  const artifact = fs.readFileSync(new URL('../../packages/blind-protocol/hiverelay-blind-abi-v1.cenc', import.meta.url))
  const alias = fs.readFileSync(new URL('../../packages/blind-protocol/hiverelay-blind-abi-v1.draft.cenc', import.meta.url))
  t.ok(b4a.equals(alias, artifact))
  t.is(hashAbi(artifact).byteLength, 32)
  let encodingError = null
  try {
    encodeWireAbiRegistry()
  } catch (error) {
    encodingError = error
  }
  t.ok(encodingError)
  t.is(encodingError.code, 'BLIND_ABI_INCOMPLETE')
  t.alike(encodingError.releaseBlockers, ['FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING'])
})

test('blind vectors: final WIRE manifest is category-isolated, complete and byte-reproducible', t => {
  const packageUrl = new URL('../../packages/blind-protocol/', import.meta.url)
  const manifest = fs.readFileSync(new URL('vector-manifest-v1.cenc', packageUrl))
  const alias = fs.readFileSync(new URL('vectors/draft/vector-manifest-v1.draft.cenc', packageUrl))
  t.alike(alias, manifest)
  const entries = decodeVectorManifest(manifest)
  t.is(entries.length, 233)
  t.ok(entries.some(entry => entry.path === 'registry/wire-schema-catalog.bin'))
  t.is(entries.filter(entry => entry.path.startsWith('registry/schemas/')).length, 71)
  t.is(entries.filter(entry => entry.path.startsWith('registry/operations/')).length, 22)
  t.is(entries.filter(entry => entry.path.startsWith('registry/domains/')).length, 39)
  t.is(entries.filter(entry => entry.path.startsWith('registry/errors/')).length, 20)
  t.is(entries.filter(entry => entry.path.startsWith('registry/admission-costs/')).length, 11)
  for (const entry of entries) {
    t.absent(entry.path.startsWith('store/'), `${entry.path} is not an internal-store vector`)
    t.absent([
      'registry/master-schema-catalog.bin',
      'registry/evidence-schema-catalog.bin',
      'registry/client-example-schema-catalog.bin',
      'registry/internal-store-schema-catalog.bin'
    ].includes(entry.path), `${entry.path} is not a non-WIRE catalog`)
    const bytes = fs.readFileSync(new URL(`vectors/${entry.path}`, packageUrl))
    t.is(entry.vectorLength, BigInt(bytes.byteLength), `${entry.path} length`)
    t.alike(entry.vectorHash, blake2b256(bytes), `${entry.path} hash`)
  }
  const abi = fs.readFileSync(new URL('hiverelay-blind-abi-v1.cenc', packageUrl))
  for (const category of [SCHEMA_CATEGORY.EVIDENCE, SCHEMA_CATEGORY.CLIENT_EXAMPLE,
    SCHEMA_CATEGORY.INTERNAL_STORE, SCHEMA_CATEGORY.PRIVATE_IPC]) {
    for (const schemaName of SCHEMA_NAMES_BY_CATEGORY[category]) {
      t.absent(abi.includes(b4a.from(schemaName, 'ascii')), `${schemaName} is absent from WIRE ABI bytes`)
    }
  }

  const authority = JSON.parse(fs.readFileSync(
    new URL('hiverelay-blind-wire-authority-v1.json', packageUrl), 'utf8'))
  const spec = fs.readFileSync(new URL('../../docs/protocol/HIVERELAY-BLIND-WIRE-V1.md', import.meta.url))
  const master = fs.readFileSync(masterSpecUrl)
  t.is(authority.specHash, b4a.toString(hashSpec(spec), 'hex'))
  t.absent(authority.specHash === b4a.toString(hashSpec(master), 'hex'),
    'public specHash does not import the full master/store/private prose')
  const changedMaster = b4a.concat([master, b4a.from('internal-store-only-edit')])
  t.is(authority.specHash, b4a.toString(hashSpec(spec), 'hex'))
  t.absent(b4a.equals(hashSpec(master), hashSpec(changedMaster)))
  t.is(authority.abiHash, b4a.toString(hashAbi(abi), 'hex'))
  t.is(authority.vectorSetHash, b4a.toString(hashVectorSet(manifest), 'hex'))
})

test('blind vectors: frozen master catalog stays unchanged while candidate schemas await reconciliation', t => {
  let compileError = null
  try {
    masterSchemaCatalog()
  } catch (error) {
    compileError = error
  }
  t.ok(compileError)
  t.is(compileError.code, 'BLIND_MASTER_SCHEMA_INVENTORY_MISMATCH')
  t.is(compileError.audit.namedMasterSchemaCount, 147)
  t.is(compileError.audit.catalogSchemaCount, 150)
  t.alike(compileError.audit.missingMasterDefinitions, [
    'BlindForwardRouteHopV1',
    'BlindForwardRouteScopeV1'
  ])
  const complete = decodeSchemaCatalog(readVector('registry/master-schema-catalog.bin'), {
    minimum: 148,
    maximum: 148
  })
  t.is(complete.length, 148)
  for (const [name, count] of [
    ['wire', 71],
    ['evidence', 28],
    ['client-example', 6],
    ['internal-store', 36]
  ]) {
    t.is(decodeSchemaCatalog(readVector(`registry/${name}-schema-catalog.bin`), {
      minimum: count,
      maximum: count
    }).length, count)
  }
})

test('blind vectors: candidate WIRE schemas remain absent after unrelated category edits', t => {
  let isolatedMaster = fs.readFileSync(masterSpecUrl, 'utf8')
  for (const name of ['BuildManifestV1', 'ReadCellCapV1', 'BlindStoreManifestV1', 'LocalDispatchV1']) {
    const declaration = `${name} {`
    t.ok(isolatedMaster.includes(declaration), `${name} declaration exists in the full master`)
    isolatedMaster = isolatedMaster.replace(declaration, `${name}Removed {`)
  }
  let categoryError = null
  try {
    compileMasterSchemaCatalogForCategory(isolatedMaster, SCHEMA_CATEGORY.WIRE)
  } catch (error) {
    categoryError = error
  }
  t.ok(categoryError)
  t.is(categoryError.code, 'BLIND_MASTER_SCHEMA_CATEGORY_MISMATCH')
  t.is(categoryError.category, SCHEMA_CATEGORY.WIRE)
  t.alike(categoryError.missingSchemaNames, [
    'BlindForwardRouteHopV1',
    'BlindForwardRouteScopeV1'
  ])
  t.exception(() => compileMasterSchemaCatalog(isolatedMaster), /inventory does not match/)
})

test('blind vectors: version-2 WAL header is executable store-format authority', t => {
  const header = readVector('store/wal-header-v2.bin')
  t.is(header.byteLength, 192)
  const decoded = decodeCanonical(blindWalHeaderV2, header)
  t.is(decoded.walVersion, 2)
  t.is(decoded.totalLength, 241)
  t.is(decoded.payloadLength, 17)
  t.alike(encodeCanonical(blindWalHeaderV2, decoded), header)
})

test('blind vectors: local checkpoint binds the frozen canonical control snapshot', t => {
  const snapshotBytes = readVector('store/control-state-snapshot-v1.bin')
  const snapshot = decodeCanonical(blindControlStateSnapshotV1, snapshotBytes)
  const checkpointBytes = readVector('store/local-checkpoint-v1.bin')
  const checkpoint = decodeCanonical(blindLocalCheckpointV1, checkpointBytes)
  t.is(snapshot.entries.length, 3)
  t.is(checkpoint.checkpointRevision, 1n)
  t.is(checkpoint.coveredWalSequence, 9n)
  t.is(checkpoint.snapshotByteLength, BigInt(snapshotBytes.byteLength))
  t.alike(checkpoint.snapshotHash, controlSnapshotHash(snapshotBytes))
  t.is(b4a.toString(controlSnapshotHash(snapshotBytes), 'hex'),
    '4157fea639272105bbd1771686f3fd22a644f388e4addc8d6e1934c726cec218')
  t.alike(snapshot.relayPublicKey, checkpoint.relayPublicKey)
  t.alike(snapshot.storeId, checkpoint.storeId)
  t.alike(snapshot.durabilityContinuityHash, checkpoint.durabilityContinuityHash)
  t.is(snapshot.walSequence, checkpoint.coveredWalSequence)
  t.alike(snapshot.walHash, checkpoint.coveredWalHash)
  t.is(localCheckpointHash(checkpointBytes).byteLength, 32)
  t.alike(encodeCanonical(blindControlStateSnapshotV1, snapshot), snapshotBytes)
  t.alike(encodeCanonical(blindLocalCheckpointV1, checkpoint), checkpointBytes)
})

test('blind vectors: public durability and persistent-result binding fixtures decode', t => {
  for (const [name, codec] of [
    ['external-commit-witness', blindExternalCommitWitnessV1],
    ['relay-result-binding', relayResultBindingV1],
    ['batch-signature-payload', batchGetSignaturePayloadV1],
    ['inbox-signature-payload', inboxReadSignaturePayloadV1],
    ['continuity-binding', durabilityContinuityBindingV1],
    ['backup-encryption-profile', blindBackupEncryptionProfileV1],
    ['backup-chunk-manifest', blindBackupChunkManifestV1],
    ['backup-manifest', blindBackupManifestV1],
    ['clean-restore', blindCleanRestoreEvidenceV1],
    ['retention-transition', blindBackupRetentionTransitionV1],
    ['restore-head', blindRestoreEvidenceHeadV1],
    ['restore-bundle', blindRestoreEvidenceBundleV1]
  ]) {
    const bytes = readVector(`durability/${name}.bin`)
    const decoded = decodeCanonical(codec, bytes)
    t.ok(decoded)
    t.alike(encodeCanonical(codec, decoded), bytes)
  }
})

test('blind vectors: CELL/INBOX bodies and registry rows are executable', t => {
  t.is(decodeCanonical(putCellV1, readVector('cell/put-class-1.bin')).cellBlob.byteLength, 4096)
  t.is(decodeCanonical(batchGetResultV1, readVector('cell/batch-get-result.bin')).entries[1].status, 1)
  t.is(decodeCanonical(inboxAppendV1, readVector('inbox/append-class-1.bin')).frame.byteLength, 4096)
  t.is(decodeCanonical(inboxReadResultV1, readVector('inbox/read-result-empty.bin')).entries.length, 0)
  t.is(decodeCanonical(operationProfileV1, readVector('registry/cell-put-operation-profile.bin')).requestCommitmentDomainId, 1)
  t.is(decodeCanonical(domainRegistryEntryV1, readVector('registry/cell-put-domain.bin')).domainId, 1)
  t.is(decodeCanonical(errorProfileEntryV1,
    readVector('registry/renew-not-due-error-profile.bin')).retryAfterMode, 1)
  t.is(b4a.toString(readVector('commitment/cell-put.bin'), 'hex'), '5cd5e4bb62e986c97b2426c8727a7610a7253ec78e539d2041385d89aafd86ff')
  t.is(b4a.toString(readVector('commitment/inbox-read.bin'), 'hex'), '6c65ea21c8d71e6ee649bf47f951bb3c4b78d30ee9e6f41431cb1145c9a09712')
  t.is(b4a.toString(readVector('commitment/core-mirror.bin'), 'hex'), 'b1b78e44b1530ea6317925f80fd92e9c93ba1e454e042f88a73fe5d6eb649f98')
  t.is(b4a.toString(readVector('commitment/core-serve.bin'), 'hex'), '01e645341ecbfbf4903950d1bfcbd83d91c60f86bdebaf532080d4e1e39993ef')
  t.is(b4a.toString(readVector('commitment/forward-open.bin'), 'hex'), 'acb1031d9557ae1fc18cacc762002c12cfc1337cdb1aebe1f6e5e063c0ef1a3c')
})

test('blind vectors: malformed CELL/INBOX and registry bytes remain negative', t => {
  t.exception(() => decodeCanonical(getCellResultV1, readVector('invalid/cell-get-unknown-class.bin')), /outside 1..5/)
  t.exception(() => decodeCanonical(batchGetV1, readVector('invalid/batch-get-duplicate-slots.bin')), /duplicate/)
  t.exception(() => decodeCanonical(batchGetResultV1, readVector('invalid/batch-get-unknown-entry-tag.bin')), /status must be 0 or 1/)
  t.exception(() => decodeCanonical(inboxReadV1, readVector('invalid/inbox-read-cursor-129.bin')), /outside 0..128/)
  t.exception(() => decodeCanonical(operationProfileV1, readVector('invalid/operation-profile-wrong-domain-purpose.bin')), /not a registered request domain/)
  t.exception(() => decodeCanonical(domainRegistryEntryV1, readVector('invalid/domain-entry-wrong-purpose.bin')), /not in the frozen registry/)
  t.exception(() => decodeCanonical(errorProfileEntryV1,
    readVector('invalid/error-profile-wrong-retryable.bin')), /not in the frozen registry/)
})

test('blind vectors: unchanged public closure stays executable while revised FORWARD rows await vectors', t => {
  const vectors = [
    ['describe/admission-parameters.bin', admissionParametersV1],
    ['describe/admission-profile.bin', admissionProfileV1],
    ['describe/dht-pointer.bin', blindDhtPointerV1],
    ['describe/external-journal-topology.bin', blindExternalJournalTopologyV1],
    ['describe/health-challenge.bin', blindHealthChallengeV1],
    ['describe/health-result.bin', blindHealthResultV1],
    ['describe/identity-transition.bin', relayIdentityTransitionV1],
    ['describe/ohttp-key-config.bin', blindOhttpKeyConfigV1],
    ['describe/schema-catalog-entry.bin', schemaCatalogEntryV1],
    ['describe/service-descriptor.bin', blindServiceDescriptorV1],
    ['core/ack.bin', blindCoreAckV1],
    ['core/mirror-request.bin', coreMirrorRequestV1],
    ['core/serve-challenge.bin', coreServeChallengeV1],
    ['core/serve-result.bin', coreServeResultV1],
    ['forward/data-body.bin', blindForwardDataV1],
    ['forward/window.bin', blindForwardWindowV1],
    ['forward/close.bin', blindForwardCloseV1],
    ['forward/stream-chunk-class-1.bin', blindStreamChunkPlainV1]
  ]
  for (const [name, codec] of vectors) {
    const bytes = readVector(name)
    t.ok(decodeCanonical(codec, bytes), `${name} decodes`)
    for (const end of [...new Set([0, 1, Math.floor(bytes.byteLength / 2), bytes.byteLength - 1])]) {
      t.exception(() => decodeCanonical(codec, bytes.subarray(0, end)))
    }
    t.exception(() => decodeCanonical(codec, b4a.concat([bytes, b4a.from([0])])))
  }
  t.exception(() => decodeCanonical(blindForwardOpenV1, readVector('forward/open.bin')))
  t.exception(() => decodeCanonical(blindForwardOpenResultV1, readVector('forward/open-result.bin')))
  t.exception(() => decodeCanonical(blindStreamChunkPlainV1,
    readVector('invalid/stream-chunk-unknown-class.bin')), /outside 1\.\.3/)
})

test('blind vectors: all ten newly closed public operation rows are checked in', t => {
  const names = [
    'describe-get',
    'describe-challenge',
    'describe-admission-parameters',
    'core-mirror',
    'core-prove',
    'core-open-replication',
    'forward-open',
    'forward-data',
    'forward-window',
    'forward-close'
  ]
  for (const name of names) {
    const row = decodeCanonical(operationProfileV1, readVector(`registry/${name}-operation-profile.bin`))
    t.ok(row.familyId === 1 || row.familyId === 4 || row.familyId === 5, `${name} family`)
  }
})
