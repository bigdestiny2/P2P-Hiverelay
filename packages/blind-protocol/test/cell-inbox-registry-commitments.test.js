import test from 'brittle'
import b4a from 'b4a'
import {
  ADMISSION_COST_RULES,
  ADMISSION_MODE,
  ABI_STATUS,
  AUXILIARY_SIGNATURE_DOMAIN,
  AUXILIARY_SIGNATURE_DOMAIN_ID,
  COST_CLASS_RULE_ID,
  DOMAIN_RECIPE,
  DOMAIN_PURPOSE,
  DOMAIN_REGISTRY,
  ERROR_CODE,
  ERROR_PROFILE_ROWS,
  FAMILY,
  OPERATION,
  OPERATION_PROFILE_ROWS,
  OPERATION_PROFILE_STATUS,
  REQUEST_COMMITMENT_DOMAIN_ID,
  RESULT_SIGNATURE_DOMAIN,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionCostRuleV1,
  allocationCommitment,
  auxiliarySignaturePayload,
  batchGetEntriesCommitment,
  blindErrorV1,
  cellBatchGetRequestCommitment,
  cellGetRequestCommitment,
  cellManageRequestCommitment,
  cellProveRequestCommitment,
  cellPutRequestCommitment,
  cellStorageSlot,
  decodeCanonical,
  domainRegistryEntry,
  domainRegistryEntryV1,
  draftAbiRegistryValue,
  draftSchemaId,
  encodeCanonical,
  encodeDraftAbiRegistry,
  errorProfileEntry,
  errorProfileEntryV1,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxCreateRequestCommitment,
  inboxManageRequestCommitment,
  inboxPhysicalTopic,
  inboxReadRequestCommitment,
  inboxWatchRequestCommitment,
  operationProfileV1,
  resultSignaturePayload
} from '../index.js'

const bytes = (length, value) => b4a.alloc(length, value)
const hex = value => b4a.toString(value, 'hex')

function commitmentFixtures () {
  const relayPublicKey = bytes(32, 1)
  const clientNonce = bytes(32, 3)
  const allocationEpoch = 0x01020304
  const createPublicKey = bytes(32, 0x11)
  const storageSlot = cellStorageSlot({ allocationEpoch, createPublicKey })
  const allocation = allocationCommitment({
    relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass: 2,
    leaseClass: 3,
    declaredCellBlobHash: bytes(32, 2),
    createPublicKey,
    renewPublicKey: bytes(32, 0x12),
    dropPublicKey: bytes(32, 0x13)
  })
  const inboxAllocationEpoch = 0x05060708
  const inboxCreatePublicKey = bytes(32, 0x21)
  const physicalTopic = inboxPhysicalTopic({
    allocationEpoch: inboxAllocationEpoch,
    createPublicKey: inboxCreatePublicKey
  })
  const createCommitment = inboxCreateCommitment({
    relayPublicKey,
    physicalTopic,
    allocationEpoch: inboxAllocationEpoch,
    frameClassBits: 7,
    appendAuthMode: 1,
    appendPublicKey: bytes(32, 0x22),
    createPublicKey: inboxCreatePublicKey,
    renewPublicKey: bytes(32, 0x23),
    closePublicKey: bytes(32, 0x24),
    retentionClass: 2,
    leaseClass: 4
  })
  return { relayPublicKey, clientNonce, allocationEpoch, createPublicKey, storageSlot, allocation, physicalTopic, createCommitment }
}

test('CELL and INBOX commitments match the frozen cross-runtime hash vectors', t => {
  const f = commitmentFixtures()
  const values = {
    cellStorageSlot: f.storageSlot,
    allocationCommitment: f.allocation,
    cellPut: cellPutRequestCommitment({ allocationCommitment: f.allocation, clientNonce: f.clientNonce }),
    cellRenew: cellManageRequestCommitment({
      operation: 'cell-renew',
      relayPublicKey: f.relayPublicKey,
      storageSlot: f.storageSlot,
      expectedRevision: 0x0102030405060708n,
      expectedLeaseEpoch: 0x11121314,
      requestedLeaseClass: 2,
      clientNonce: f.clientNonce
    }),
    cellDrop: cellManageRequestCommitment({
      operation: 'cell-drop',
      relayPublicKey: f.relayPublicKey,
      storageSlot: f.storageSlot,
      expectedRevision: 0x0102030405060708n,
      expectedLeaseEpoch: 0x11121314,
      requestedLeaseClass: 0,
      clientNonce: f.clientNonce
    }),
    cellGet: cellGetRequestCommitment({ relayPublicKey: f.relayPublicKey, storageSlot: f.storageSlot, clientNonce: f.clientNonce }),
    cellProve: cellProveRequestCommitment({ relayPublicKey: f.relayPublicKey, storageSlot: f.storageSlot, clientNonce: f.clientNonce }),
    cellBatch: cellBatchGetRequestCommitment({
      relayPublicKey: f.relayPublicKey,
      clientNonce: f.clientNonce,
      slots: [f.storageSlot, bytes(32, 4)]
    }),
    inboxPhysicalTopic: f.physicalTopic,
    inboxCreateCommitment: f.createCommitment,
    inboxCreate: inboxCreateRequestCommitment({ inboxCreateCommitment: f.createCommitment, clientNonce: f.clientNonce }),
    inboxRenew: inboxManageRequestCommitment({
      operation: 'inbox-renew',
      relayPublicKey: f.relayPublicKey,
      physicalTopic: f.physicalTopic,
      expectedRevision: 0x0102030405060708n,
      expectedLeaseEpoch: 0x11121314,
      requestedLeaseClass: 3,
      clientNonce: f.clientNonce
    }),
    inboxClose: inboxManageRequestCommitment({
      operation: 'inbox-close',
      relayPublicKey: f.relayPublicKey,
      physicalTopic: f.physicalTopic,
      expectedRevision: 0x0102030405060708n,
      expectedLeaseEpoch: 0x11121314,
      requestedLeaseClass: 0,
      clientNonce: f.clientNonce
    }),
    inboxAppend: inboxAppendRequestCommitment({
      relayPublicKey: f.relayPublicKey,
      physicalTopic: f.physicalTopic,
      frameClass: 2,
      frameHash: bytes(32, 5),
      clientNonce: f.clientNonce
    }),
    inboxRead: inboxReadRequestCommitment({
      relayPublicKey: f.relayPublicKey,
      physicalTopic: f.physicalTopic,
      cursor: b4a.from('a0a1a2', 'hex'),
      limit: 64,
      clientNonce: f.clientNonce
    }),
    inboxWatch: inboxWatchRequestCommitment({
      relayPublicKey: f.relayPublicKey,
      physicalTopic: f.physicalTopic,
      afterRevision: 0x0102030405060708n,
      limit: 64,
      maxWaitMillis: 30000,
      clientNonce: f.clientNonce
    })
  }
  const expected = {
    cellStorageSlot: '5a6f98221689be8b02ca65cf30651002d7ea8a50bd7770c879f6843a499b433a',
    allocationCommitment: 'f618358275922ee5c6645548551d736bc1544b74981b5075da9ef91dfc97eb7c',
    cellPut: 'f7de4a38f07fac629c2f0e7f013b157b816d4aaf49018a54d1833d72d58d97d3',
    cellRenew: 'ab8bf2bf8a2f0954d4f26ed4fc6d2241a6bcc31e257bad7ce3c330ea7ebbd2c1',
    cellDrop: 'b306e0297410efa6e0607bc7f1a6737712fa95b4781327ec76e00cedf8077b54',
    cellGet: 'dde7f8b2fc7c86028e405f90fd748dfc030612dedf2272482d3a796f63a5acfd',
    cellProve: 'f9cde10c6976a28000350fe97d9118eaaf937ceca1aedec320980a627d34328a',
    cellBatch: '5d73a0711a7fa1887e19545b645aa4ead94b5d4bc869dcc1386b2f15796f62ce',
    inboxPhysicalTopic: '7f6abd0fe9006fbde6a74992719f85b20650baff2a26ff25b3821c2b5031211e',
    inboxCreateCommitment: '2893d5bfbeae6442b3cf03173aa69bec5fe431041aade1acf2fb4145a74cc788',
    inboxCreate: '1d34ebbdc6c049417bd903d23ce1d6a0a57bc43bfa5eafdc60615fc8050efaea',
    inboxRenew: '8282b542299410b4091891bfc5114afd0750630bc03db37b21dbf465193ab167',
    inboxClose: '2c76b23564cfa2075f69586085074251b325efa0d1e33381822f8cf0abc2eb43',
    inboxAppend: '3c33902e0cf27559932bbf376fc5c30ec26f81a5131f3107bf859c199478f12b',
    inboxRead: 'eab36584002e027c49386691462a478e8208f82b5d5cb17c38febb1f9fd91d90',
    inboxWatch: '2854afaef8fb335e0a60187e95d2eb701f241ef1837bdf6e0a925de1a5d31251'
  }
  for (const [name, value] of Object.entries(values)) t.is(hex(value), expected[name], `${name} vector`)

  t.unlike(values.cellRenew, values.cellDrop)
  t.unlike(values.cellGet, values.cellProve)
  t.unlike(values.inboxRenew, values.inboxClose)
})

test('commitment helpers reject ambiguous classes, management modes and bounds', t => {
  const f = commitmentFixtures()
  t.exception(() => allocationCommitment({
    relayPublicKey: f.relayPublicKey,
    storageSlot: bytes(32, 0),
    allocationEpoch: f.allocationEpoch,
    sizeClass: 1,
    leaseClass: 1,
    declaredCellBlobHash: bytes(32, 1),
    createPublicKey: f.createPublicKey,
    renewPublicKey: bytes(32, 2),
    dropPublicKey: bytes(32, 3)
  }), /not self-certifying/)
  t.exception(() => cellManageRequestCommitment({
    operation: 'cell-drop',
    relayPublicKey: f.relayPublicKey,
    storageSlot: f.storageSlot,
    expectedRevision: 1n,
    expectedLeaseEpoch: 2,
    requestedLeaseClass: 1,
    clientNonce: f.clientNonce
  }), /does not match/)
  t.exception(() => cellBatchGetRequestCommitment({
    relayPublicKey: f.relayPublicKey,
    clientNonce: f.clientNonce,
    slots: [f.storageSlot, f.storageSlot]
  }), /duplicate/)
  t.exception(() => inboxCreateCommitment({
    relayPublicKey: f.relayPublicKey,
    physicalTopic: f.physicalTopic,
    allocationEpoch: 1,
    frameClassBits: 8,
    appendAuthMode: 0,
    appendPublicKey: null,
    createPublicKey: bytes(32, 1),
    renewPublicKey: bytes(32, 2),
    closePublicKey: bytes(32, 3),
    retentionClass: 1,
    leaseClass: 1
  }), /advertised inbox classes/)
  t.exception(() => inboxCreateCommitment({
    relayPublicKey: f.relayPublicKey,
    physicalTopic: bytes(32, 0),
    allocationEpoch: 1,
    frameClassBits: 1,
    appendAuthMode: 0,
    appendPublicKey: null,
    createPublicKey: bytes(32, 1),
    renewPublicKey: bytes(32, 2),
    closePublicKey: bytes(32, 3),
    retentionClass: 1,
    leaseClass: 1
  }), /not self-certifying/)
  t.exception(() => inboxAppendRequestCommitment({
    relayPublicKey: f.relayPublicKey,
    physicalTopic: f.physicalTopic,
    frameClass: 4,
    frameHash: bytes(32, 1),
    clientNonce: f.clientNonce
  }), /outside 1..3/)
  t.exception(() => inboxReadRequestCommitment({
    relayPublicKey: f.relayPublicKey,
    physicalTopic: f.physicalTopic,
    cursor: bytes(129, 0),
    limit: 1,
    clientNonce: f.clientNonce
  }), /exceeds 128/)
  t.exception(() => inboxWatchRequestCommitment({
    relayPublicKey: f.relayPublicKey,
    physicalTopic: f.physicalTopic,
    afterRevision: 1n,
    limit: 1,
    maxWaitMillis: 30001,
    clientNonce: f.clientNonce
  }), /outside 1..30000/)
})

test('all 39 domain IDs, purposes, recipes and ASCII bytes match the frozen table', t => {
  const expected = [
    [1, 1, 1, 'hiverelay.blind.request.v1cell-put'],
    [2, 1, 1, 'hiverelay.blind.request.v1cell-get'],
    [3, 1, 1, 'hiverelay.blind.request.v1cell-renew'],
    [4, 1, 1, 'hiverelay.blind.request.v1cell-drop'],
    [5, 1, 1, 'hiverelay.blind.request.v1cell-prove'],
    [6, 1, 1, 'hiverelay.blind.request.v1cell-batch-get'],
    [7, 1, 1, 'hiverelay.blind.request.v1inbox-create'],
    [8, 1, 1, 'hiverelay.blind.request.v1inbox-renew'],
    [9, 1, 1, 'hiverelay.blind.request.v1inbox-close'],
    [10, 1, 1, 'hiverelay.blind.request.v1inbox-append'],
    [11, 1, 1, 'hiverelay.blind.request.v1inbox-read'],
    [12, 1, 1, 'hiverelay.blind.request.v1inbox-watch'],
    [13, 1, 1, 'hiverelay.blind.request.v1core-mirror'],
    [14, 1, 1, 'hiverelay.blind.request.v1core-serve'],
    [15, 1, 1, 'hiverelay.blind.request.v1core-open-replication'],
    [16, 1, 1, 'hiverelay.blind.forward-open.v1'],
    [101, 2, 2, 'hiverelay.blind.descriptor.v1'],
    [102, 2, 2, 'hiverelay.blind.health-result.v1'],
    [103, 2, 2, 'hiverelay.blind.admission-parameters.v1'],
    [104, 2, 2, 'hiverelay.blind.cell-receipt.v1'],
    [105, 2, 2, 'hiverelay.blind.batch-get-result.v1'],
    [106, 2, 2, 'hiverelay.blind.inbox-receipt.v1'],
    [107, 2, 2, 'hiverelay.blind.inbox-append-ack.v1'],
    [108, 2, 2, 'hiverelay.blind.inbox-read-result.v1'],
    [109, 2, 2, 'hiverelay.blind.core-ack.v1'],
    [110, 2, 2, 'hiverelay.blind.core-open-result.v1'],
    [111, 2, 2, 'hiverelay.blind.forward-open-result.v1'],
    [201, 3, 2, 'hiverelay.blind.ohttp-key-config.v1'],
    [202, 3, 2, 'hiverelay.blind.identity-transition.v1'],
    [203, 3, 2, 'hiverelay.blind.dht-pointer.v1'],
    [204, 3, 2, 'hiverelay.blind.transport-route.v1'],
    [205, 3, 2, 'hiverelay.blind.forward-hop-open.v1'],
    [206, 3, 2, 'hiverelay.blind.forward-hop-accept.v1'],
    [207, 3, 2, 'hiverelay.blind.external-journal-topology.v1'],
    [208, 3, 2, 'hiverelay.blind.external-commit-witness.v1'],
    [209, 3, 2, 'hiverelay.blind.restore-evidence-head.v1'],
    [210, 3, 2, 'hiverelay.blind.backup-manifest.v1'],
    [211, 3, 2, 'hiverelay.blind.clean-restore-evidence.v1'],
    [212, 3, 2, 'hiverelay.blind.backup-retention-transition.v1']
  ]
  t.alike(DOMAIN_REGISTRY.map(entry => [
    entry.domainId,
    entry.purpose,
    entry.recipeId,
    entry.exactAsciiBytes
  ]), expected)
  t.alike(Object.keys(REQUEST_COMMITMENT_DOMAIN_ID).map(name => REQUEST_COMMITMENT_DOMAIN_ID[name]),
    expected.slice(0, 16).map(row => row[0]))
  t.alike(Object.keys(RESULT_SIGNATURE_DOMAIN_ID).map(name => RESULT_SIGNATURE_DOMAIN_ID[name]),
    expected.slice(16, 27).map(row => row[0]))
  t.alike(Object.keys(AUXILIARY_SIGNATURE_DOMAIN_ID).map(name => AUXILIARY_SIGNATURE_DOMAIN_ID[name]),
    expected.slice(27).map(row => row[0]))
  t.alike(Object.values(RESULT_SIGNATURE_DOMAIN), Object.values(RESULT_SIGNATURE_DOMAIN_ID).map(id =>
    DOMAIN_REGISTRY.find(entry => entry.domainId === id).exactAsciiBytes))
  t.alike(Object.values(AUXILIARY_SIGNATURE_DOMAIN), Object.values(AUXILIARY_SIGNATURE_DOMAIN_ID).map(id =>
    DOMAIN_REGISTRY.find(entry => entry.domainId === id).exactAsciiBytes))
})

test('domain and admission-cost registries encode only their frozen rows', t => {
  t.is(DOMAIN_REGISTRY.length, 39)
  t.is(ADMISSION_COST_RULES.length, 11)
  for (let i = 1; i < DOMAIN_REGISTRY.length; i++) {
    t.ok(DOMAIN_REGISTRY[i - 1].domainId < DOMAIN_REGISTRY[i].domainId, 'domain IDs are sorted')
  }
  for (const entry of DOMAIN_REGISTRY) {
    const value = { ...entry, exactAsciiBytes: b4a.from(entry.exactAsciiBytes, 'ascii') }
    const decoded = decodeCanonical(domainRegistryEntryV1, encodeCanonical(domainRegistryEntryV1, value))
    t.is(decoded.domainId, entry.domainId)
    t.is(decoded.purpose, entry.purpose)
    t.is(decoded.recipeId, entry.recipeId)
  }
  for (const rule of ADMISSION_COST_RULES) {
    t.alike(decodeCanonical(admissionCostRuleV1, encodeCanonical(admissionCostRuleV1, rule)), rule)
  }
  t.is(domainRegistryEntry(REQUEST_COMMITMENT_DOMAIN_ID.CELL_PUT).purpose, DOMAIN_PURPOSE.REQUEST_COMMITMENT)
  t.is(domainRegistryEntry(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT).purpose, DOMAIN_PURPOSE.RESULT_SIGNATURE)
  t.is(domainRegistryEntry(AUXILIARY_SIGNATURE_DOMAIN_ID.DHT_POINTER).purpose, DOMAIN_PURPOSE.AUXILIARY_SIGNATURE)
  t.exception(() => encodeCanonical(domainRegistryEntryV1, {
    domainId: 1,
    purpose: 2,
    recipeId: 1,
    exactAsciiBytes: b4a.from('hiverelay.blind.request.v1cell-put', 'ascii')
  }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(domainRegistryEntryV1, {
    domainId: 1,
    purpose: 1,
    recipeId: 1,
    exactAsciiBytes: b4a.from('hiverelay.blind.request.v1cell-get', 'ascii')
  }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(domainRegistryEntryV1, {
    domainId: 1,
    purpose: 1,
    recipeId: 2,
    exactAsciiBytes: b4a.from('hiverelay.blind.request.v1cell-put', 'ascii')
  }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(admissionCostRuleV1, { costClassRuleId: 1, ruleKind: 2 }), /not in the frozen registry/)

  const payload = resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, b4a.from([1, 2, 3]))
  t.alike(payload, b4a.concat([
    b4a.from('hiverelay.blind.cell-receipt.v1', 'ascii'),
    b4a.from('0000000000000003', 'hex'),
    b4a.from([1, 2, 3])
  ]))
  const auxiliaryPayload = auxiliarySignaturePayload(AUXILIARY_SIGNATURE_DOMAIN_ID.DHT_POINTER, b4a.from([4, 5]))
  t.alike(auxiliaryPayload, b4a.concat([
    b4a.from(AUXILIARY_SIGNATURE_DOMAIN[AUXILIARY_SIGNATURE_DOMAIN_ID.DHT_POINTER], 'ascii'),
    b4a.from('0000000000000002', 'hex'),
    b4a.from([4, 5])
  ]))
  t.is(DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE, 1)
  t.is(DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD, 2)
  t.exception(() => resultSignaturePayload(REQUEST_COMMITMENT_DOMAIN_ID.CELL_PUT, b4a.alloc(0)), /unknown result signature domain/)
  t.exception(() => auxiliarySignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, b4a.alloc(0)), /unknown auxiliary signature domain/)
})

test('error profile 1 is closed over all 20 codes and BlindError body bits', t => {
  const retryable = new Set([9, 16, 17, 18])
  t.alike(Object.entries(ERROR_CODE), [
    ['BAD_VERSION', 1],
    ['BAD_ENCODING', 2],
    ['TOO_LARGE', 3],
    ['BAD_SLOT', 4],
    ['BAD_CREATE_SIG', 5],
    ['BAD_MANAGEMENT_SIG', 6],
    ['STALE_REVISION', 7],
    ['CONFLICT', 8],
    ['SPEND_REQUIRED', 9],
    ['SPEND_INVALID', 10],
    ['SPEND_REPLAY', 11],
    ['LEASE_UNSUPPORTED', 12],
    ['NOT_FOUND', 13],
    ['EXPIRED', 14],
    ['SUPPRESSED', 15],
    ['BUSY', 16],
    ['INTERNAL', 17],
    ['RENEW_NOT_DUE', 18],
    ['RETRY_TERMINAL', 19],
    ['TRANSPORT_UNSUPPORTED', 20]
  ])
  t.is(ERROR_PROFILE_ROWS.length, 20)
  for (let code = 1; code <= 20; code++) {
    const expected = {
      errorProfileId: 1,
      code,
      directCorrelatedStatus: 200,
      protectedInnerStatus: 200,
      retryable: retryable.has(code) ? 1 : 0,
      retryAfterMode: code === 18 ? 1 : 0
    }
    t.alike(ERROR_PROFILE_ROWS[code - 1], expected, `error row ${code}`)
    t.alike(errorProfileEntry(1, code), expected, `error lookup ${code}`)
    t.alike(
      decodeCanonical(errorProfileEntryV1, encodeCanonical(errorProfileEntryV1, expected)),
      expected,
      `error codec ${code}`
    )
    const error = {
      version: 1,
      code,
      retryable: expected.retryable,
      retryAfterEpoch: code === 18 ? 123 : null
    }
    t.alike(decodeCanonical(blindErrorV1, encodeCanonical(blindErrorV1, error)), error, `blind error ${code}`)
  }
  t.is(errorProfileEntry(1, 21), null)
  t.is(errorProfileEntry(2, 1), null)
  t.exception(() => encodeCanonical(errorProfileEntryV1, {
    ...ERROR_PROFILE_ROWS[0],
    directCorrelatedStatus: 400
  }), /must be 200/)
  t.exception(() => encodeCanonical(errorProfileEntryV1, {
    ...ERROR_PROFILE_ROWS[0],
    retryable: 1
  }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(errorProfileEntryV1, {
    ...ERROR_PROFILE_ROWS[17],
    retryAfterMode: 0
  }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(blindErrorV1, {
    version: 1,
    code: 16,
    retryable: 0,
    retryAfterEpoch: null
  }), /does not match error profile 1/)
  t.exception(() => encodeCanonical(blindErrorV1, {
    version: 1,
    code: 18,
    retryable: 1,
    retryAfterEpoch: null
  }), /does not match error profile 1/)
  t.exception(() => encodeCanonical(blindErrorV1, {
    version: 1,
    code: 17,
    retryable: 1,
    retryAfterEpoch: 123
  }), /does not match error profile 1/)
})

test('12 CELL/INBOX operation rows match exact caps, schema IDs and numeric registries', t => {
  const expected = [
    [FAMILY.CELL, OPERATION.CELL.PUT, 'PutCellV1', 'BlindReceiptV1', 1056768, 16384, 2, 1, 1, 104],
    [FAMILY.CELL, OPERATION.CELL.GET, 'GetCellV1', 'GetCellResultV1', 16384, 1048832, 1, 2, 2, 0],
    [FAMILY.CELL, OPERATION.CELL.RENEW, 'RenewCellV1', 'BlindReceiptV1', 16384, 16384, 2, 3, 3, 104],
    [FAMILY.CELL, OPERATION.CELL.DROP, 'DropCellV1', 'BlindReceiptV1', 16384, 16384, 0, 0, 4, 104],
    [FAMILY.CELL, OPERATION.CELL.PROVE, 'ProveCellV1', 'ProveCellResultV1', 16384, 1049600, 1, 2, 5, 104],
    [FAMILY.CELL, OPERATION.CELL.BATCH_GET, 'BatchGetV1', 'BatchGetResultV1', 16384, 4194304, 1, 4, 6, 105],
    [FAMILY.INBOX, OPERATION.INBOX.CREATE, 'InboxCreateV1', 'InboxReceiptV1', 16384, 16384, 2, 5, 7, 106],
    [FAMILY.INBOX, OPERATION.INBOX.RENEW, 'InboxManageV1', 'InboxReceiptV1', 16384, 16384, 2, 6, 8, 106],
    [FAMILY.INBOX, OPERATION.INBOX.CLOSE, 'InboxManageV1', 'InboxReceiptV1', 16384, 16384, 0, 0, 9, 106],
    [FAMILY.INBOX, OPERATION.INBOX.APPEND, 'InboxAppendV1', 'InboxAppendAckV1', 70656, 16384, 2, 7, 10, 107],
    [FAMILY.INBOX, OPERATION.INBOX.READ, 'InboxReadV1', 'InboxReadResultV1', 16384, 4194304, 1, 4, 11, 108],
    [FAMILY.INBOX, OPERATION.INBOX.WATCH, 'InboxWatchV1', 'InboxReadResultV1', 16384, 4194304, 2, 8, 12, 108]
  ]
  const cellInboxRows = OPERATION_PROFILE_ROWS.filter(row =>
    row.familyId === FAMILY.CELL || row.familyId === FAMILY.INBOX)
  t.is(cellInboxRows.length, expected.length)
  for (let i = 0; i < expected.length; i++) {
    const [familyId, operationId, requestSchema, resultSchema, requestCap, resultCap,
      admissionMode, costId, requestDomainId, resultDomainId] = expected[i]
    const row = cellInboxRows[i]
    t.alike(row, {
      familyId,
      operationId,
      requestSchemaId: draftSchemaId(requestSchema),
      resultSchemaId: draftSchemaId(resultSchema),
      allowedRequestKindBits: 1,
      allowedResultKindBits: 6,
      streamTransition: 0,
      maxRequestBodyBytes: requestCap,
      maxResultBodyBytes: resultCap,
      admissionMode,
      costClassRuleId: costId,
      requestCommitmentDomainId: requestDomainId,
      resultSignatureDomainId: resultDomainId,
      errorProfileId: 1,
      transportSupportBits: 31
    })
    const encoded = encodeCanonical(operationProfileV1, row)
    t.is(encoded.byteLength, 27)
    t.alike(decodeCanonical(operationProfileV1, encoded), row)
  }
  t.is(OPERATION_PROFILE_STATUS.requiredPairs.length, 22)
  t.is(OPERATION_PROFILE_STATUS.implementedPairs.length, 22)
  t.is(OPERATION_PROFILE_STATUS.missingPairs.length, 0)
  t.is(ABI_STATUS.releaseReady, true)
  t.is(ABI_STATUS.wireAuthorityPublished, true)
  t.is(TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE |
    TRANSPORT_SUPPORT.OHTTP | TRANSPORT_SUPPORT.TOR_HTTP | TRANSPORT_SUPPORT.TOR_NATIVE, 31)
  t.is(COST_CLASS_RULE_ID.INBOX_WATCH_BOUND_WAIT, 8)

  const registry = draftAbiRegistryValue()
  t.is(registry.domainRegistry.length, 39)
  t.is(registry.domainRecipes.length, 2)
  t.is(registry.errorProfiles.length, 20)
  t.is(registry.admissionCostRules.length, 11)
  t.is(registry.operationProfiles.length, 22)
  t.ok(encodeDraftAbiRegistry().byteLength > 0)
})

test('OperationProfileV1 rejects wrong-purpose domains and inconsistent admission rows', t => {
  const row = OPERATION_PROFILE_ROWS.find(row =>
    row.familyId === FAMILY.CELL && row.operationId === OPERATION.CELL.PUT)
  t.exception(() => encodeCanonical(operationProfileV1, {
    ...row,
    requestCommitmentDomainId: RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT
  }), /not a registered request domain/)
  t.exception(() => encodeCanonical(operationProfileV1, {
    ...row,
    resultSignatureDomainId: REQUEST_COMMITMENT_DOMAIN_ID.CELL_PUT
  }), /not a registered result-signature domain/)
  t.exception(() => encodeCanonical(operationProfileV1, { ...row, costClassRuleId: 99 }), /not in the frozen registry/)
  t.exception(() => encodeCanonical(operationProfileV1, {
    ...row,
    admissionMode: ADMISSION_MODE.NONE,
    costClassRuleId: 1
  }), /zero state does not match/)
  t.exception(() => encodeCanonical(operationProfileV1, { ...row, requestCommitmentDomainId: 0 }), /needs a request commitment/)
  t.exception(() => encodeCanonical(operationProfileV1, { ...row, resultSchemaId: 0 }), /only forward-active/)
  t.exception(() => batchGetEntriesCommitment([]), /outside 1..64/)
})
