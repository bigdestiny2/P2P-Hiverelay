import {
  DRAFT_SCHEMA_CATALOG,
  SCHEMA_CATEGORY,
  SCHEMA_NAMES_BY_CATEGORY,
  deepFreeze
} from './registry.js'

export const SCHEMA_DEFINITION_KIND = deepFreeze({
  STANDALONE: 1,
  COMPOSITION: 2,
  INLINE_UNION: 3,
  EXTERNAL_OWNER: 4
})

export const SCHEMA_IMPLEMENTATION_OWNER = deepFreeze({
  BLIND_PROTOCOL: 1,
  BLIND_IPC: 2
})

const compositionDependencies = deepFreeze({
  BatchGetResultV1: ['BatchGetEntryV1', 'RelayResultBindingV1'],
  BatchGetSignaturePayloadV1: ['RelayResultBindingV1'],
  BatchGetV1: ['AdmissionV1'],
  BlindBackupChunkManifestV1: ['BlindBackupEncryptionProfileV1'],
  BlindCoreAckV1: ['RelayResultBindingV1'],
  BlindCellAtomicCommittedPutSpendSnapshotV1: [
    'BlindCellHistoricalResultSnapshotV1',
    'BlindPreparedAdmissionStoreV1'
  ],
  BlindCellChargedReadRetrySnapshotV1: [
    'BlindCellChargedReadPinEntrySnapshotV1',
    'BlindPreparedAdmissionStoreV1'
  ],
  BlindCellCommittedPutSpendSnapshotV1: [
    'BlindCellHistoricalResultSnapshotV1',
    'BlindPreparedAdmissionStoreV1'
  ],
  BlindCellCommittedRenewSpendSnapshotV1: [
    'BlindCellHistoricalResultSnapshotV1',
    'BlindPreparedAdmissionStoreV1'
  ],
  BlindCellRequestResultSnapshotV1: ['BlindCellHistoricalResultSnapshotV1'],
  BlindCellReservedSpendSnapshotV1: ['BlindPreparedAdmissionStoreV1'],
  BlindCellTerminalSpendSnapshotV1: ['BlindPreparedAdmissionStoreV1'],
  BlindForwardHopAcceptV1: ['RelayResultBindingV1'],
  BlindForwardHopOpenV1: ['BlindForwardRouteScopeV1', 'BlindTransportRouteV1'],
  BlindForwardOpenResultV1: ['BlindForwardHopAcceptV1', 'RelayResultBindingV1'],
  BlindForwardOpenV1: ['AdmissionV1'],
  BlindForwardRouteScopeV1: ['BlindForwardRouteHopV1'],
  BlindListenerCatalogV1: ['BlindListenerEntryV1'],
  BlindOuterEnvelopeV1: ['BlindDispatchFrameV1'],
  BlindPutAtomicCommittedStoreV1: ['BlindPreparedAdmissionStoreV1'],
  BlindProductIsolationReportBundleV1: [
    'BlindArtifactFileInventoryV1',
    'BlindExecutableEntrypointCatalogV1',
    'BlindListenerCatalogV1',
    'BlindProcessInspectionEvidenceV1',
    'BlindRouteAbsenceEvidenceV1',
    'BlindRuntimeImportGraphV1'
  ],
  BlindReceiptV1: ['RelayResultBindingV1'],
  BlindReleaseEvidenceBundleV1: [
    'BlindLaunchTopologyV1',
    'BlindProductIsolationEvidenceV1',
    'BlindProductIsolationReportBundleV1',
    'BlindReleaseSupportHorizonV1',
    'BuildManifestV1',
    'ReproductionEnvironmentV1',
    'ToolchainManifestV1'
  ],
  BlindRestoreEvidenceBundleV1: ['BlindRestoreEvidenceHeadV1'],
  BlindRuntimeBoundaryEvidenceV1: ['BlindListenerEntryV1'],
  BlindServiceDescriptorV1: [
    'AdmissionProfileV1',
    'BuildProfileV1',
    'DurabilityProfileV1',
    'ProtocolProfileV1',
    'RelayIdentityTransitionV1',
    'TransportEndpointV1'
  ],
  CellBlobV1: [],
  CoreMirrorRequestV1: ['AdmissionV1'],
  CoreOpenReplicationResultV1: ['RelayResultBindingV1'],
  CoreOpenReplicationV1: ['AdmissionV1'],
  CoreServeChallengeV1: ['AdmissionV1'],
  CoreServeResultV1: ['BlindCoreAckV1'],
  GetCellV1: ['AdmissionV1'],
  HiveRelayCompatibilityBuildManifestV1: ['BuildInputV1'],
  HiveRelayCompatibilityRuntimeBoundaryEvidenceV1: [
    'BlindListenerEntryV1',
    'BlindRuntimeBoundaryEvidenceV1',
    'BuildManifestV1'
  ],
  InboxAppendAckV1: ['RelayResultBindingV1'],
  InboxAppendV1: ['AdmissionV1'],
  InboxCreateV1: ['AdmissionV1'],
  InboxManageV1: ['AdmissionV1'],
  InboxReadResultV1: ['InboxReadSignaturePayloadV1', 'RelayResultBindingV1'],
  InboxReadSignaturePayloadV1: ['RelayResultBindingV1'],
  InboxReadV1: ['AdmissionV1'],
  InboxReceiptV1: ['RelayResultBindingV1'],
  InboxWatchV1: ['AdmissionV1'],
  OpaqueChainCheckpointV1: ['ReadCellCapV1'],
  OpaqueChainFrameV1: ['OpaqueChainCheckpointV1', 'ReadCellCapV1'],
  OperationProfileV1: ['BlindErrorV1'],
  ProveCellResultV1: ['BlindReceiptV1'],
  ProveCellV1: ['AdmissionV1'],
  PutCellV1: ['AdmissionV1'],
  RelayResultBindingV1: ['BlindExternalCommitWitnessV1'],
  RenewCellV1: ['AdmissionV1'],
  ToolchainManifestV1: ['ToolchainEntryV1'],
  WriteCellCapV1: ['ReadCellCapV1']
})

const inlineUnionNames = new Set(['BatchGetEntryV1'])
const compositionNames = new Set(Object.keys(compositionDependencies))

export const MASTER_SCHEMA_INVENTORY = deepFreeze(DRAFT_SCHEMA_CATALOG.map(entry => {
  const external = entry.category === SCHEMA_CATEGORY.PRIVATE_IPC
  return {
    ...entry,
    definitionKind: external
      ? SCHEMA_DEFINITION_KIND.EXTERNAL_OWNER
      : inlineUnionNames.has(entry.schemaName)
        ? SCHEMA_DEFINITION_KIND.INLINE_UNION
        : compositionNames.has(entry.schemaName)
          ? SCHEMA_DEFINITION_KIND.COMPOSITION
          : SCHEMA_DEFINITION_KIND.STANDALONE,
    implementationOwner: external
      ? SCHEMA_IMPLEMENTATION_OWNER.BLIND_IPC
      : SCHEMA_IMPLEMENTATION_OWNER.BLIND_PROTOCOL,
    aliasOf: null,
    compositionDependencies: compositionDependencies[entry.schemaName] || []
  }
}))

const inventoryByName = new Map(MASTER_SCHEMA_INVENTORY.map(entry => [entry.schemaName, entry]))

export function masterSchemaInventoryEntry (schemaName) {
  return inventoryByName.get(schemaName) || null
}

export function extractMasterNamedSchemas (canonicalMasterText) {
  if (typeof canonicalMasterText !== 'string') throw new TypeError('canonical master text must be a string')
  const declarations = []
  const expression = /^([A-Za-z][A-Za-z0-9]*V[1-9][0-9]*)\s*\{/gm
  let match
  while ((match = expression.exec(canonicalMasterText)) !== null) {
    const before = canonicalMasterText.slice(0, match.index)
    declarations.push({
      schemaName: match[1],
      line: 1 + (before.match(/\n/g) || []).length
    })
  }
  return declarations
}

export function auditMasterSchemaInventory (canonicalMasterText) {
  const declarations = extractMasterNamedSchemas(canonicalMasterText)
  const declarationCounts = new Map()
  for (const declaration of declarations) {
    declarationCounts.set(declaration.schemaName, (declarationCounts.get(declaration.schemaName) || 0) + 1)
  }
  const duplicateMasterNames = [...declarationCounts]
    .filter(([, count]) => count !== 1)
    .map(([name]) => name)
    .sort()
  const masterNames = [...declarationCounts.keys()].sort()
  const unclassifiedMasterNames = masterNames.filter(name => !inventoryByName.has(name))
  const missingMasterDefinitions = MASTER_SCHEMA_INVENTORY
    .filter(entry => entry.definitionKind !== SCHEMA_DEFINITION_KIND.INLINE_UNION &&
      !declarationCounts.has(entry.schemaName))
    .map(entry => entry.schemaName)
    .sort()
  const inlineUnionDefinitionErrors = MASTER_SCHEMA_INVENTORY
    .filter(entry => entry.definitionKind === SCHEMA_DEFINITION_KIND.INLINE_UNION &&
      declarationCounts.has(entry.schemaName))
    .map(entry => entry.schemaName)
    .sort()
  const ownershipErrors = MASTER_SCHEMA_INVENTORY
    .filter(entry => (entry.category === SCHEMA_CATEGORY.PRIVATE_IPC) !==
      (entry.implementationOwner === SCHEMA_IMPLEMENTATION_OWNER.BLIND_IPC))
    .map(entry => entry.schemaName)
    .sort()
  const dependencyErrors = []
  for (const entry of MASTER_SCHEMA_INVENTORY) {
    for (const dependency of entry.compositionDependencies) {
      const target = inventoryByName.get(dependency)
      if (!target || target.category !== entry.category) {
        dependencyErrors.push(`${entry.schemaName}->${dependency}`)
      }
    }
  }
  const categoryTotals = Object.fromEntries(Object.values(SCHEMA_CATEGORY).map(category => [
    category,
    SCHEMA_NAMES_BY_CATEGORY[category].length
  ]))
  const ok = duplicateMasterNames.length === 0 && unclassifiedMasterNames.length === 0 &&
    missingMasterDefinitions.length === 0 && inlineUnionDefinitionErrors.length === 0 &&
    ownershipErrors.length === 0 && dependencyErrors.length === 0
  return deepFreeze({
    ok,
    namedMasterSchemaCount: masterNames.length,
    catalogSchemaCount: MASTER_SCHEMA_INVENTORY.length,
    masterNames,
    duplicateMasterNames,
    unclassifiedMasterNames,
    missingMasterDefinitions,
    inlineUnionDefinitionErrors,
    ownershipErrors,
    dependencyErrors: dependencyErrors.sort(),
    categoryTotals
  })
}

export function assertMasterSchemaInventory (canonicalMasterText) {
  const audit = auditMasterSchemaInventory(canonicalMasterText)
  if (audit.ok) return audit
  const error = new Error('master schema inventory does not match the executable category catalog')
  error.code = 'BLIND_MASTER_SCHEMA_INVENTORY_MISMATCH'
  error.audit = audit
  throw error
}
