import {
  EXTENDED_SCHEMA_METADATA,
  SCHEMA_METADATA_OVERRIDES
} from './extended-schema-metadata.js'

const KiB = 1024
const MiB = 1024 * KiB

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

export const PROTOCOL = deepFreeze({
  family: 'hiverelay-blind',
  major: 1,
  minor: 0,
  mediaType: 'application/vnd.hiverelay.blind-v1'
})

export const FRAME_KIND = deepFreeze({
  REQUEST: 1,
  RESPONSE: 2,
  ERROR: 3,
  STREAM: 4
})

export const FAMILY = deepFreeze({
  DESCRIBE: 1,
  CELL: 2,
  INBOX: 3,
  CORE: 4,
  FORWARD: 5
})

export const SCHEMA_CATEGORY = deepFreeze({
  WIRE: 1,
  EVIDENCE: 2,
  CLIENT_EXAMPLE: 3,
  INTERNAL_STORE: 4,
  PRIVATE_IPC: 5
})

export const TRANSPORT_ID = deepFreeze({
  HTTPS_DIRECT: 1,
  DIRECT_PROTOMUX_NOISE: 2,
  OHTTP_INGRESS: 3,
  OHTTP_GATEWAY: 4,
  SPLIT_PROTOMUX_NOISE: 5,
  HTTP3_MASQUE: 6,
  TOR_V3_ONION: 7,
  WEBTRANSPORT_WEBSOCKET_TUNNEL: 8,
  MIX_PACKET_INGRESS: 9
})

export const TRANSPORT_EXPORTER_ID = deepFreeze({
  NONE: 0,
  NOISE_HANDSHAKE_HASH_BLAKE2B: 1
})

export const CONTROL_CHANNEL_ID_TYPE = deepFreeze({
  NONE: 0,
  NONZERO_U64BE: 1
})

export const DURABILITY_PROFILE_ID = deepFreeze({
  LOCAL_FSYNC_IDENTITY_RESET_V1: 1,
  CONTROL_RPO0_3_NODE_V1: 2
})

export const DURABILITY_RPO_BAND = deepFreeze({
  UNDECLARED: 0,
  AT_MOST_15_MINUTES: 1,
  AT_MOST_1_HOUR: 2,
  AT_MOST_6_HOURS: 3
})

export const DURABILITY_RTO_BAND = deepFreeze({
  UNDECLARED: 0,
  AT_MOST_1_HOUR: 1,
  AT_MOST_4_HOURS: 2,
  AT_MOST_24_HOURS: 3
})

export const REDUNDANCY_CLASS = deepFreeze({
  SINGLE: 0,
  LOCAL_REDUNDANT: 1,
  VERIFIED_OFF_HOST_BACKUP: 2
})

export const AGE_BAND = deepFreeze({
  UNDECLARED: 0,
  AT_MOST_15_MINUTES: 1,
  AT_MOST_1_HOUR: 2,
  AT_MOST_6_HOURS: 3,
  AT_MOST_24_HOURS: 4,
  AT_MOST_7_DAYS: 5,
  AT_MOST_30_DAYS: 6,
  OLDER_THAN_30_DAYS: 7
})

export const ENDPOINT_LIMITS = deepFreeze({
  ROLE_BITS_MASK: 0x007f,
  PRIVACY_PROFILE_BITS_MASK: 0x00ff,
  ENVELOPE_CLASS_BITS_MASK: 0x007e,
  WIRE_CLASS_BITS_MASK: 0x0e
})

// Generic infrastructure capabilities only. Signed descriptors must never use
// either registry to encode an application, tenant, namespace, or content type.
export const ENDPOINT_ROLE = deepFreeze({
  STORAGE: 0x0001,
  INGRESS_ENTRY: 0x0002,
  GATEWAY_EXIT: 0x0004,
  QUOTA_ISSUER: 0x0008,
  QUOTA_REDEEMER: 0x0010,
  DESCRIPTOR_DISCOVERY: 0x0020,
  MIX_HOP: 0x0040
})

export const PRIVACY_PROFILE = deepFreeze({
  DIRECT: 0x0001,
  SPLIT_WEB: 0x0002,
  SPLIT_NATIVE: 0x0004,
  MASQUE: 0x0008,
  TOR_NATIVE: 0x0010,
  TOR_SINGLE: 0x0020,
  MIX: 0x0040,
  TOR_BROWSER: 0x0080
})

export const PUBLIC_PROFILE_LIMITS = deepFreeze({
  CELL_SIZE_CLASS_BITS_MASK: 0x3e,
  LEASE_CLASS_BITS_MASK: 0x1e,
  ENABLED_OPERATION_BITS_MASK: 0x003fffff,
  TRANSPORT_BITS_MASK: 0x03fe,
  MAX_DESCRIPTOR_BYTES: 16 * KiB,
  MAX_DHT_POINTER_BYTES: 1000,
  MAX_RESPONSE_BYTES: 4 * MiB,
  MAX_BATCH_COUNT: 64,
  MAX_ADMISSION_TOKEN_BYTES: 4096,
  MAX_ADMISSION_RESOURCE_COST_ROWS: 512,
  MAX_OHTTP_CONFIG_EPOCHS: 120
})

export const OPERATION = deepFreeze({
  DESCRIBE: { GET: 1, CHALLENGE: 2, ADMISSION_PARAMETERS: 3 },
  CELL: { PUT: 1, GET: 2, RENEW: 3, DROP: 4, PROVE: 5, BATCH_GET: 6 },
  INBOX: { CREATE: 1, RENEW: 2, CLOSE: 3, APPEND: 4, READ: 5, WATCH: 6 },
  CORE: { MIRROR: 1, PROVE: 2, OPEN_REPLICATION: 3 },
  FORWARD: { OPEN: 1, DATA: 2, WINDOW: 3, CLOSE: 4 }
})

export const FAMILY_ROUTES = deepFreeze({
  [FAMILY.DESCRIBE]: '/api/blind/v1/describe',
  [FAMILY.CELL]: '/api/blind/v1/cell',
  [FAMILY.INBOX]: '/api/blind/v1/inbox',
  [FAMILY.CORE]: '/api/blind/v1/core',
  [FAMILY.FORWARD]: '/api/blind/v1/forward'
})

export const ERROR_CODE = deepFreeze({
  BAD_VERSION: 1,
  BAD_ENCODING: 2,
  TOO_LARGE: 3,
  BAD_SLOT: 4,
  BAD_CREATE_SIG: 5,
  BAD_MANAGEMENT_SIG: 6,
  STALE_REVISION: 7,
  CONFLICT: 8,
  SPEND_REQUIRED: 9,
  SPEND_INVALID: 10,
  SPEND_REPLAY: 11,
  LEASE_UNSUPPORTED: 12,
  NOT_FOUND: 13,
  EXPIRED: 14,
  SUPPRESSED: 15,
  BUSY: 16,
  INTERNAL: 17,
  RENEW_NOT_DUE: 18,
  RETRY_TERMINAL: 19,
  TRANSPORT_UNSUPPORTED: 20
})

export const OHTTP_TRANSPORT_ERROR_CODE = deepFreeze({
  MALFORMED_INNER: 1,
  TARGET_UNAVAILABLE: 2,
  TARGET_TIMEOUT: 3
})

export const OHTTP_DELIVERY_BOUNDARY = deepFreeze({
  BEFORE_VALID_DISPATCH: 1,
  BEFORE_TARGET_HANDOFF: 2,
  MAY_HAVE_REACHED_TARGET: 3
})

export const OHTTP_RETRY_ACTION = deepFreeze({
  NONE: 0,
  FRESH_HPKE_SAME_DESTINATION_POLICY: 1,
  RECONCILE_WITHOUT_AUTOMATIC_RETRY: 2
})

export const OHTTP_TRANSPORT_ERROR_ROWS = deepFreeze([
  {
    code: OHTTP_TRANSPORT_ERROR_CODE.MALFORMED_INNER,
    protectedStatus: 400,
    deliveryBoundary: OHTTP_DELIVERY_BOUNDARY.BEFORE_VALID_DISPATCH,
    retryAction: OHTTP_RETRY_ACTION.NONE
  },
  {
    code: OHTTP_TRANSPORT_ERROR_CODE.TARGET_UNAVAILABLE,
    protectedStatus: 503,
    deliveryBoundary: OHTTP_DELIVERY_BOUNDARY.BEFORE_TARGET_HANDOFF,
    retryAction: OHTTP_RETRY_ACTION.FRESH_HPKE_SAME_DESTINATION_POLICY
  },
  {
    code: OHTTP_TRANSPORT_ERROR_CODE.TARGET_TIMEOUT,
    protectedStatus: 504,
    deliveryBoundary: OHTTP_DELIVERY_BOUNDARY.MAY_HAVE_REACHED_TARGET,
    retryAction: OHTTP_RETRY_ACTION.RECONCILE_WITHOUT_AUTOMATIC_RETRY
  }
])

export const CELL_RECEIPT_RESULT = deepFreeze({
  STORED: 1,
  SERVED: 2,
  RENEWED: 3,
  DROPPED: 4
})

export const INBOX_MANAGE_OPERATION = deepFreeze({
  RENEW: 1,
  CLOSE: 2
})

export const INBOX_APPEND_AUTH_MODE = deepFreeze({
  OPEN_CAPABILITY: 0,
  SIGNATURE_REQUIRED: 1
})

export const INBOX_RECEIPT_RESULT = deepFreeze({
  CREATED: 1,
  RENEWED: 2,
  CLOSED: 3
})

export const INBOX_APPEND_RESULT = deepFreeze({
  STORED: 1
})

export const ADMISSION_CONFORMANCE_CLASS = deepFreeze({
  OPEN: 1,
  PRIVATE: 2
})

export const CORE_ACK_RESULT = deepFreeze({
  MIRROR_ACCEPTED: 1,
  RECENTLY_SERVED: 2
})

export const FORWARD_CLOSE_KIND = deepFreeze({
  FIN: 1,
  ABORT: 2
})

export const STORE_LIFECYCLE_STATE = deepFreeze({
  ACTIVE: 1,
  DRAINING: 2,
  RETIRED: 3
})

export const HEALTH_CLOCK_STATE = deepFreeze({
  READY: 1,
  UNSAFE: 2,
  VERIFYING: 3
})

export const HEALTH_INTEGRITY_STATE = deepFreeze({
  VERIFIED: 1,
  DEGRADED: 2,
  FAILED: 3
})

export const HEALTH_REBALANCE_STATE = deepFreeze({
  STABLE: 0,
  COPYING: 1,
  CATCHING_UP: 2,
  FENCED: 3
})

export const ADMISSION_MODE = deepFreeze({
  NONE: 0,
  OPTIONAL: 1,
  REQUIRED: 2
})

export const STREAM_TRANSITION = deepFreeze({
  UNARY: 0,
  CORE_CHILD: 1,
  FORWARD_OPEN: 2,
  FORWARD_ACTIVE: 3
})

export const TRANSPORT_SUPPORT = deepFreeze({
  DIRECT_HTTP: 1,
  DIRECT_NATIVE: 2,
  OHTTP: 4,
  TOR_HTTP: 8,
  TOR_NATIVE: 16,
  MASQUE_NATIVE: 32
})

export const DOMAIN_PURPOSE = deepFreeze({
  REQUEST_COMMITMENT: 1,
  RESULT_SIGNATURE: 2,
  AUXILIARY_SIGNATURE: 3
})

export const DOMAIN_RECIPE = deepFreeze({
  OPERATION_DEFINED_COMMITMENT_PREIMAGE: 1,
  ED25519_DOMAIN_LEN64_PAYLOAD: 2
})

// Keep the explicit ID suffix available to consumers that distinguish the
// registry identifier from a recipe implementation.
export const DOMAIN_RECIPE_ID = DOMAIN_RECIPE

export const REQUEST_COMMITMENT_DOMAIN_ID = deepFreeze({
  CELL_PUT: 1,
  CELL_GET: 2,
  CELL_RENEW: 3,
  CELL_DROP: 4,
  CELL_PROVE: 5,
  CELL_BATCH_GET: 6,
  INBOX_CREATE: 7,
  INBOX_RENEW: 8,
  INBOX_CLOSE: 9,
  INBOX_APPEND: 10,
  INBOX_READ: 11,
  INBOX_WATCH: 12,
  CORE_MIRROR: 13,
  CORE_SERVE: 14,
  CORE_OPEN_REPLICATION: 15,
  FORWARD_OPEN: 16
})

export const RESULT_SIGNATURE_DOMAIN_ID = deepFreeze({
  DESCRIPTOR: 101,
  HEALTH_RESULT: 102,
  ADMISSION_PARAMETERS: 103,
  CELL_RECEIPT: 104,
  BATCH_GET_RESULT: 105,
  INBOX_RECEIPT: 106,
  INBOX_APPEND_ACK: 107,
  INBOX_READ_RESULT: 108,
  CORE_ACK: 109,
  CORE_OPEN_RESULT: 110,
  FORWARD_OPEN_RESULT: 111
})

export const AUXILIARY_SIGNATURE_DOMAIN_ID = deepFreeze({
  OHTTP_KEY_CONFIG: 201,
  IDENTITY_TRANSITION: 202,
  DHT_POINTER: 203,
  TRANSPORT_ROUTE: 204,
  FORWARD_HOP_OPEN: 205,
  FORWARD_HOP_ACCEPT: 206,
  EXTERNAL_JOURNAL_TOPOLOGY: 207,
  EXTERNAL_COMMIT_WITNESS: 208,
  RESTORE_EVIDENCE_HEAD: 209,
  BACKUP_MANIFEST: 210,
  CLEAN_RESTORE_EVIDENCE: 211,
  BACKUP_RETENTION_TRANSITION: 212
})

export const DOMAIN_REGISTRY = deepFreeze([
  { domainId: 1, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-put' },
  { domainId: 2, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-get' },
  { domainId: 3, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-renew' },
  { domainId: 4, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-drop' },
  { domainId: 5, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-prove' },
  { domainId: 6, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1cell-batch-get' },
  { domainId: 7, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-create' },
  { domainId: 8, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-renew' },
  { domainId: 9, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-close' },
  { domainId: 10, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-append' },
  { domainId: 11, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-read' },
  { domainId: 12, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1inbox-watch' },
  { domainId: 13, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1core-mirror' },
  { domainId: 14, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1core-serve' },
  { domainId: 15, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.request.v1core-open-replication' },
  { domainId: 16, purpose: 1, recipeId: 1, exactAsciiBytes: 'hiverelay.blind.forward-open.v1' },
  { domainId: 101, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.descriptor.v1' },
  { domainId: 102, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.health-result.v1' },
  { domainId: 103, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.admission-parameters.v1' },
  { domainId: 104, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.cell-receipt.v1' },
  { domainId: 105, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.batch-get-result.v1' },
  { domainId: 106, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.inbox-receipt.v1' },
  { domainId: 107, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.inbox-append-ack.v1' },
  { domainId: 108, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.inbox-read-result.v1' },
  { domainId: 109, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.core-ack.v1' },
  { domainId: 110, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.core-open-result.v1' },
  { domainId: 111, purpose: 2, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.forward-open-result.v1' },
  { domainId: 201, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.ohttp-key-config.v1' },
  { domainId: 202, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.identity-transition.v1' },
  { domainId: 203, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.dht-pointer.v1' },
  { domainId: 204, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.transport-route.v1' },
  { domainId: 205, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.forward-hop-open.v1' },
  { domainId: 206, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.forward-hop-accept.v1' },
  { domainId: 207, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.external-journal-topology.v1' },
  { domainId: 208, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.external-commit-witness.v1' },
  { domainId: 209, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.restore-evidence-head.v1' },
  { domainId: 210, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.backup-manifest.v1' },
  { domainId: 211, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.clean-restore-evidence.v1' },
  { domainId: 212, purpose: 3, recipeId: 2, exactAsciiBytes: 'hiverelay.blind.backup-retention-transition.v1' }
])

export const RESULT_SIGNATURE_DOMAIN = deepFreeze(Object.fromEntries(
  DOMAIN_REGISTRY
    .filter(entry => entry.purpose === DOMAIN_PURPOSE.RESULT_SIGNATURE)
    .map(entry => [entry.domainId, entry.exactAsciiBytes])
))

export const AUXILIARY_SIGNATURE_DOMAIN = deepFreeze(Object.fromEntries(
  DOMAIN_REGISTRY
    .filter(entry => entry.purpose === DOMAIN_PURPOSE.AUXILIARY_SIGNATURE)
    .map(entry => [entry.domainId, entry.exactAsciiBytes])
))

export const ERROR_PROFILE_ID = deepFreeze({
  CANONICAL_V1: 1
})

export const ERROR_RETRY_AFTER_MODE = deepFreeze({
  MUST_BE_ABSENT: 0,
  MUST_BE_PRESENT: 1
})

export const ERROR_PROFILE_ROWS = deepFreeze([
  { errorProfileId: 1, code: 1, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 2, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 3, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 4, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 5, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 6, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 7, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 8, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 9, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 1, retryAfterMode: 0 },
  { errorProfileId: 1, code: 10, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 11, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 12, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 13, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 14, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 15, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 16, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 1, retryAfterMode: 0 },
  { errorProfileId: 1, code: 17, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 1, retryAfterMode: 0 },
  { errorProfileId: 1, code: 18, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 1, retryAfterMode: 1 },
  { errorProfileId: 1, code: 19, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 },
  { errorProfileId: 1, code: 20, directCorrelatedStatus: 200, protectedInnerStatus: 200, retryable: 0, retryAfterMode: 0 }
])

export const COST_CLASS_RULE_ID = deepFreeze({
  CELL_PUT_CLASS_LEASE: 1,
  STORED_CELL_CLASS_NONE: 2,
  STORED_CELL_CLASS_REQUEST_LEASE: 3,
  CANONICAL_RESULT_BAND_NONE: 4,
  INBOX_CREATE_SHAPE_LEASE: 5,
  INBOX_STORED_SHAPE_REQUEST_LEASE: 6,
  INBOX_APPEND_FRAME_RETENTION: 7,
  INBOX_WATCH_BOUND_WAIT: 8,
  CORE_MIRROR_LENGTH_LEASE: 9,
  CORE_SESSION_CLASS_NONE: 10,
  FORWARD_CIRCUIT_CLASS_NONE: 11
})

export const ADMISSION_COST_RULES = deepFreeze(
  Object.values(COST_CLASS_RULE_ID).map(costClassRuleId => ({ costClassRuleId, ruleKind: costClassRuleId }))
)

const domainRegistryById = new Map(DOMAIN_REGISTRY.map(entry => [entry.domainId, entry]))
const admissionCostRuleById = new Map(ADMISSION_COST_RULES.map(entry => [entry.costClassRuleId, entry]))
const errorProfileByKey = new Map(ERROR_PROFILE_ROWS.map(entry => [`${entry.errorProfileId}:${entry.code}`, entry]))

export function domainRegistryEntry (domainId) {
  return domainRegistryById.get(domainId) || null
}

export function admissionCostRule (costClassRuleId) {
  return admissionCostRuleById.get(costClassRuleId) || null
}

export function errorProfileEntry (errorProfileId, code) {
  return errorProfileByKey.get(`${errorProfileId}:${code}`) || null
}

export const CELL_SIZE_CLASS = deepFreeze({
  1: 4 * KiB,
  2: 16 * KiB,
  3: 64 * KiB,
  4: 256 * KiB,
  5: 1 * MiB
})

export const INBOX_FRAME_CLASS = deepFreeze({
  1: 4 * KiB,
  2: 16 * KiB,
  3: 64 * KiB
})

export const OUTER_CLASS = deepFreeze({
  1: 4 * KiB,
  2: 16 * KiB,
  3: 64 * KiB,
  4: 256 * KiB,
  5: 1 * MiB,
  6: 8 * MiB
})

export const STREAM_WIRE_CLASS = deepFreeze({
  1: 4 * KiB,
  2: 16 * KiB,
  3: 65535
})

export const FORWARD_CIRCUIT_CLASS = deepFreeze({
  1: {
    grantedInitialWindow: 64 * KiB,
    maxCircuitBytes: 16 * MiB,
    idleMillis: 30_000,
    lifetimeMillis: 10 * 60_000
  },
  2: {
    grantedInitialWindow: 256 * KiB,
    maxCircuitBytes: 64 * MiB,
    idleMillis: 60_000,
    lifetimeMillis: 30 * 60_000
  },
  3: {
    grantedInitialWindow: MiB,
    maxCircuitBytes: 256 * MiB,
    idleMillis: 120_000,
    lifetimeMillis: 60 * 60_000
  }
})

export const CORE_SESSION_CLASS = deepFreeze({
  1: { maxSessionBytes: 16 * MiB, idleMillis: 30_000, lifetimeMillis: 10 * 60_000 },
  2: { maxSessionBytes: 64 * MiB, idleMillis: 60_000, lifetimeMillis: 30 * 60_000 },
  3: { maxSessionBytes: 256 * MiB, idleMillis: 120_000, lifetimeMillis: 60 * 60_000 }
})

export const LEASE_CLASS_EPOCHS = deepFreeze({
  0: 0,
  1: 4,
  2: 28,
  3: 120,
  4: 360
})

export const DISPATCH_LIMITS = deepFreeze({
  PREFIX_BYTES: 4,
  HEADER_BYTES: 41,
  REQUEST_ID_BYTES: 16,
  MAX_BODY_BYTES: 4 * MiB,
  MAX_FRAME_AFTER_PREFIX_BYTES: 4 * MiB + 64,
  MAX_WIRE_BYTES: 4 + 4 * MiB + 64,
  MAX_FORWARD_DATA_BYTES: 65535,
  MAX_FORWARD_WINDOW_BYTES: 1 * MiB
})

const BASE_IMPLEMENTED_SCHEMAS = deepFreeze([
  {
    name: 'AdmissionCostRuleV1',
    fields: [
      ['costClassRuleId', 'u16be[1..11]'],
      ['ruleKind', 'u8[1..11]']
    ]
  },
  {
    name: 'AdmissionV1',
    fields: [
      ['profileId', 'u16be[1..65535]'],
      ['schemeId', 'u16be[1..65535]'],
      ['parameterHash', 'fixed32'],
      ['token', 'compact-bytes[1..4096]']
    ]
  },
  {
    name: 'BlindAdmissionParametersRequestV1',
    fields: [
      ['version', 'u8=1'],
      ['profileId', 'u16be[1..65535]'],
      ['schemeId', 'u16be[1..65535]'],
      ['clientNonce', 'fixed32']
    ]
  },
  {
    name: 'BlindDescribeGetV1',
    fields: [
      ['version', 'u8=1'],
      ['descriptorHash', 'optional-u8(fixed32)'],
      ['clientNonce', 'fixed32']
    ]
  },
  {
    name: 'BlindDispatchFrameV1',
    fields: [
      ['frameLength', 'u32be'],
      ['version', 'u8=1'],
      ['frameKind', 'u8'],
      ['familyId', 'u8'],
      ['operationId', 'u8'],
      ['flags', 'u8=0'],
      ['requestId', 'fixed16'],
      ['streamId', 'u64be'],
      ['sequence', 'u64be'],
      ['bodyLength', 'u32be'],
      ['body', 'bytes[bodyLength]']
    ]
  },
  {
    name: 'BlindErrorV1',
    fields: [
      ['version', 'u8=1'],
      ['code', 'u8[1..20]'],
      ['retryable', 'u8[0..1]'],
      ['retryAfterEpoch', 'optional-u8(u32be)']
    ]
  },
  {
    name: 'BlindForwardHopAcceptV1',
    fields: [
      ['version', 'u8=1'],
      ['previousRelayKey', 'fixed32'],
      ['previousDescriptorSequence', 'u64be'],
      ['previousDescriptorHash', 'fixed32'],
      ['nextRelayKey', 'fixed32'],
      ['nextDescriptorSequence', 'u64be'],
      ['nextDescriptorHash', 'fixed32'],
      ['routeId', 'fixed16'],
      ['circuitNonce', 'fixed32'],
      ['nextStreamId', 'u64be[1..2^64-1]'],
      ['grantedWireClass', 'u8[1..3]'],
      ['circuitClass', 'u8[1..3]'],
      ['grantedInitialWindow', 'u32be[class-tuple]'],
      ['maxDataBytes', 'u32be[wire-class]'],
      ['maxCircuitBytes', 'u64be[class-tuple]'],
      ['idleMillis', 'u32be[class-tuple]'],
      ['lifetimeMillis', 'u32be[class-tuple]'],
      ['openedAtEpoch', 'u32be'],
      ['hopOpenCommitment', 'fixed32'],
      ['handshakeFlight2', 'fixed96'],
      ['nextSignature', 'fixed64']
    ]
  },
  {
    name: 'BlindForwardHopOpenV1',
    fields: [
      ['version', 'u8=1'],
      ['route', 'BlindTransportRouteV1'],
      ['previousDescriptorSequence', 'u64be'],
      ['previousDescriptorHash', 'fixed32'],
      ['circuitNonce', 'fixed32'],
      ['requestedWireClass', 'u8[1..3]'],
      ['circuitClass', 'u8[1..3]'],
      ['grantedInitialWindow', 'u32be[class-tuple]'],
      ['maxDataBytes', 'u32be[wire-class]'],
      ['maxCircuitBytes', 'u64be[class-tuple]'],
      ['idleMillis', 'u32be[class-tuple]'],
      ['lifetimeMillis', 'u32be[class-tuple]'],
      ['clientRequestCommitment', 'fixed32'],
      ['handshakeFlight1', 'fixed32'],
      ['forwarderSignature', 'fixed64']
    ]
  },
  {
    name: 'BlindOhttpTransportErrorV1',
    fields: [
      ['version', 'u8=1'],
      ['code', 'u8[1..3]']
    ]
  },
  {
    name: 'BlindOuterEnvelopeV1',
    fields: [
      ['version', 'u8=1'],
      ['outerClass', 'u8'],
      ['innerLength', 'u32be'],
      ['innerDispatch', 'bytes[innerLength]'],
      ['randomPadding', 'bytes[classLength-6-innerLength]']
    ]
  },
  {
    name: 'BlindTransportRouteV1',
    fields: [
      ['version', 'u8=1'],
      ['routeKind', 'u8[1..6]'],
      ['routeId', 'fixed16'],
      ['previousRelayKey', 'fixed32'],
      ['previousEndpointId', 'u8[1..255]'],
      ['nextRelayKey', 'fixed32'],
      ['nextDescriptorSequence', 'u64be'],
      ['nextDescriptorHash', 'fixed32'],
      ['nextEndpointId', 'u8[1..255]'],
      ['envelopeClassBits', 'u16be'],
      ['wireClassBits', 'u8'],
      ['maxCanonicalDispatchBytes', 'u32be[0..absolute-dispatch-cap]'],
      ['maxEncapsulatedRequestBytes', 'u32be'],
      ['maxOpenBytes', 'u32be[0..131072]'],
      ['maxCircuitBytes', 'u64be'],
      ['maxConcurrentStreams', 'u16be[0..1024]'],
      ['hopAdmissionProfileId', 'u16be[1..65535]'],
      ['issuedEpoch', 'u32be'],
      ['expiresEpoch', 'u32be[issued+1..issued+4]'],
      ['routeNonce', 'fixed32'],
      ['previousSignature', 'fixed64']
    ]
  },
  {
    name: 'BatchGetEntryV1',
    fields: [
      ['status', 'tag-u8[0..1]'],
      ['found.sizeClass', 'u8[1..5]'],
      ['found.cellBlob', 'exact-by-sizeClass']
    ]
  },
  {
    name: 'BatchGetResultV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['entries', 'ordered-array[1..64](BatchGetEntryV1)'],
      ['entriesCommitment', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BatchGetV1',
    fields: [
      ['version', 'u8=1'],
      ['clientNonce', 'fixed32'],
      ['slots', 'ordered-distinct-array[1..64](fixed32)'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'BlindReceiptV1',
    fields: [
      ['version', 'u8=1'],
      ['protocol', 'fixed-ascii="hiverelay-blind-cell-v1"'],
      ['relayPublicKey', 'fixed32'],
      ['slotCommitment', 'fixed32'],
      ['cellBlobHash', 'fixed32'],
      ['allocationCommitment', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['sizeClass', 'u8[1..5]'],
      ['allocationEpoch', 'u32be'],
      ['leaseClass', 'u8[0..4]'],
      ['leaseEpoch', 'u32be'],
      ['stateRevision', 'u64be'],
      ['receiptEpoch', 'u32be'],
      ['requestNonce', 'fixed32'],
      ['result', 'u8[1..4]'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BuildProfileV1',
    fields: [
      ['specHash', 'fixed32'],
      ['abiHash', 'fixed32'],
      ['vectorSetHash', 'fixed32'],
      ['evidenceFormatHash', 'fixed32'],
      ['evidenceVectorSetHash', 'fixed32'],
      ['storeFormatHash', 'fixed32'],
      ['storeVectorSetHash', 'fixed32'],
      ['buildArtifactHash', 'fixed32'],
      ['buildManifestUrl', 'optional-u8(canonical-https[1..512])'],
      ['buildManifestHash', 'fixed32']
    ]
  },
  {
    name: 'CoreOpenReplicationResultV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['wireProfileHash', 'fixed32'],
      ['sessionClass', 'u8[1..3]'],
      ['controlChannelId', 'u64be[1..2^64-1]'],
      ['parentChannelBinding', 'fixed32'],
      ['streamId', 'u64be[1..2^64-1]'],
      ['maxSessionBytes', 'u64be[class-tuple]'],
      ['idleMillis', 'u32be[class-tuple]'],
      ['lifetimeMillis', 'u32be[class-tuple]'],
      ['openedAtEpoch', 'u32be'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'CoreOpenReplicationV1',
    fields: [
      ['version', 'u8=1'],
      ['wireProfileHash', 'fixed32'],
      ['sessionClass', 'u8[1..3]'],
      ['controlChannelId', 'u64be[1..2^64-1]'],
      ['parentChannelBinding', 'fixed32'],
      ['clientNonce', 'fixed32'],
      ['admission', 'AdmissionV1']
    ]
  },
  {
    name: 'DropCellV1',
    fields: [
      ['version', 'u8=1'],
      ['storageSlot', 'fixed32'],
      ['expectedRevision', 'u64be'],
      ['expectedLeaseEpoch', 'u32be'],
      ['clientNonce', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'DomainRegistryEntryV1',
    fields: [
      ['domainId', 'u16be[registered]'],
      ['purpose', 'u8[1..3]'],
      ['recipeId', 'u8[1..2]'],
      ['exactAsciiBytes', 'canonical-ascii[1..96]']
    ]
  },
  {
    name: 'DurabilityProfileV1',
    fields: [
      ['profileId', 'u8=1'],
      ['storeFormatMajor', 'u16be'],
      ['storeFormatMinor', 'u16be'],
      ['storeFormatHash', 'fixed32'],
      ['externalJournalId', 'fixed32[nonzero]'],
      ['externalWitnessPublicKey', 'fixed32[nonzero]'],
      ['externalJournalReplicationClass', 'u8=1'],
      ['externalCheckpointAgeBand', 'u8[0..7]'],
      ['externalJournalTopologyUrl', 'optional-u8(canonical-https[1..512])'],
      ['externalJournalTopologyHash', 'fixed32'],
      ['acknowledgedRpoBand', 'u8[0..3]'],
      ['targetRtoBand', 'u8[0..3]'],
      ['redundancyClass', 'u8[0..3]'],
      ['restoreDrillAgeBand', 'u8[0..7]']
    ]
  },
  {
    name: 'ErrorProfileEntryV1',
    fields: [
      ['errorProfileId', 'u8=1'],
      ['code', 'u8[1..20]'],
      ['directCorrelatedStatus', 'u16be=200'],
      ['protectedInnerStatus', 'u16be=200'],
      ['retryable', 'u8[0..1]'],
      ['retryAfterMode', 'u8[0..1]']
    ]
  },
  {
    name: 'GetCellResultV1',
    fields: [
      ['version', 'u8=1'],
      ['sizeClass', 'u8[1..5]'],
      ['cellBlob', 'exact-by-sizeClass']
    ]
  },
  {
    name: 'GetCellV1',
    fields: [
      ['version', 'u8=1'],
      ['storageSlot', 'fixed32'],
      ['clientNonce', 'fixed32'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'InboxAppendAckV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['topicCommitment', 'fixed32'],
      ['frameHash', 'fixed32'],
      ['appendRevision', 'u64be'],
      ['storedAtEpoch', 'u32be'],
      ['expiresAtEpoch', 'u32be'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['result', 'u8=1'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'InboxAppendV1',
    fields: [
      ['version', 'u8=1'],
      ['physicalTopic', 'fixed32'],
      ['frameClass', 'u8[1..3]'],
      ['frameHash', 'fixed32'],
      ['clientNonce', 'fixed32'],
      ['appendSignature', 'optional-u8(fixed64)'],
      ['admission', 'AdmissionV1'],
      ['frame', 'exact-by-frameClass']
    ]
  },
  {
    name: 'InboxCreateV1',
    fields: [
      ['version', 'u8=1'],
      ['allocationEpoch', 'u32be'],
      ['physicalTopic', 'fixed32'],
      ['frameClassBits', 'u8[known-nonzero-bits]'],
      ['appendAuthMode', 'u8[0..1]'],
      ['createPublicKey', 'fixed32'],
      ['appendPublicKey', 'optional-u8(fixed32)'],
      ['renewPublicKey', 'fixed32'],
      ['closePublicKey', 'fixed32'],
      ['retentionClass', 'u8[1..4]'],
      ['leaseClass', 'u8[1..4]'],
      ['clientNonce', 'fixed32'],
      ['createSignature', 'fixed64'],
      ['admission', 'AdmissionV1']
    ]
  },
  {
    name: 'InboxManageV1',
    fields: [
      ['version', 'u8=1'],
      ['operation', 'u8[1..2]'],
      ['physicalTopic', 'fixed32'],
      ['expectedRevision', 'u64be'],
      ['expectedLeaseEpoch', 'u32be'],
      ['leaseClass', 'u8[0..4]'],
      ['clientNonce', 'fixed32'],
      ['signature', 'fixed64'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'InboxReadResultV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['snapshotRevision', 'u64be'],
      ['entries', 'ordered-array[0..64](u64be,fixed32,u8,exact-by-frameClass)'],
      ['entriesCommitment', 'fixed32'],
      ['nextCursor', 'optional-u8(compact-bytes[0..128])'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'InboxReadV1',
    fields: [
      ['version', 'u8=1'],
      ['physicalTopic', 'fixed32'],
      ['cursor', 'compact-bytes[0..128]'],
      ['limit', 'u16be[1..64]'],
      ['clientNonce', 'fixed32'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'InboxReceiptV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['topicCommitment', 'fixed32'],
      ['stateRevision', 'u64be'],
      ['leaseClass', 'u8[0..4]'],
      ['leaseEpoch', 'u32be'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['result', 'u8[1..3]'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'InboxWatchV1',
    fields: [
      ['version', 'u8=1'],
      ['physicalTopic', 'fixed32'],
      ['afterRevision', 'u64be'],
      ['limit', 'u16be[1..64]'],
      ['maxWaitMillis', 'u16be[1..30000]'],
      ['clientNonce', 'fixed32'],
      ['admission', 'AdmissionV1']
    ]
  },
  {
    name: 'OperationProfileV1',
    fields: [
      ['familyId', 'u8[1..5]'],
      ['operationId', 'u8[1..255]'],
      ['requestSchemaId', 'u16be[1..65535]'],
      ['resultSchemaId', 'u16be'],
      ['allowedRequestKindBits', 'u8[known-bits]'],
      ['allowedResultKindBits', 'u8[known-bits]'],
      ['streamTransition', 'u8[0..3]'],
      ['maxRequestBodyBytes', 'u32be[1..4194304]'],
      ['maxResultBodyBytes', 'u32be[1..4194304]'],
      ['admissionMode', 'u8[0..2]'],
      ['costClassRuleId', 'u16be'],
      ['requestCommitmentDomainId', 'u16be'],
      ['resultSignatureDomainId', 'u16be'],
      ['errorProfileId', 'u8=1'],
      ['transportSupportBits', 'u16be[known-bits]']
    ]
  },
  {
    name: 'ProtocolProfileArtifactV1',
    fields: [
      ['version', 'u8=1'],
      ['protocolId', 'u16be[1..5]'],
      ['major', 'u16be'],
      ['minor', 'u16be'],
      ['featureBits', 'u64be'],
      ['wireSchemaSetHash', 'fixed32'],
      ['dependencyManifestHash', 'fixed32'],
      ['interoperabilityVectorSetHash', 'fixed32']
    ]
  },
  {
    name: 'ProtocolProfileV1',
    fields: [
      ['protocolId', 'u16be[1..5]'],
      ['major', 'u16be'],
      ['minor', 'u16be'],
      ['featureBits', 'u64be'],
      ['profileHash', 'fixed32']
    ]
  },
  {
    name: 'ProveCellResultV1',
    fields: [
      ['version', 'u8=1'],
      ['receipt', 'BlindReceiptV1'],
      ['sizeClass', 'u8[1..5]'],
      ['cellBlob', 'exact-by-sizeClass']
    ]
  },
  {
    name: 'ProveCellV1',
    fields: [
      ['version', 'u8=1'],
      ['storageSlot', 'fixed32'],
      ['clientNonce', 'fixed32'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'PutCellV1',
    fields: [
      ['version', 'u8=1'],
      ['storageSlot', 'fixed32'],
      ['allocationEpoch', 'u32be'],
      ['sizeClass', 'u8[1..5]'],
      ['leaseClass', 'u8[1..4]'],
      ['clientNonce', 'fixed32'],
      ['createPublicKey', 'fixed32'],
      ['renewPublicKey', 'fixed32'],
      ['dropPublicKey', 'fixed32'],
      ['declaredBlobHash', 'fixed32'],
      ['createSignature', 'fixed64'],
      ['admission', 'AdmissionV1'],
      ['cellBlob', 'exact-by-sizeClass']
    ]
  },
  {
    name: 'RenewCellV1',
    fields: [
      ['version', 'u8=1'],
      ['storageSlot', 'fixed32'],
      ['expectedRevision', 'u64be'],
      ['expectedLeaseEpoch', 'u32be'],
      ['leaseClass', 'u8[1..4]'],
      ['clientNonce', 'fixed32'],
      ['admission', 'AdmissionV1'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'TransportEndpointV1',
    fields: [
      ['endpointId', 'u8[1..255]'],
      ['transportId', 'u8[1..9]'],
      ['transportProfileHash', 'fixed32'],
      ['roleBits', 'u16be[known-bits]'],
      ['privacyProfileBits', 'u16be[known-bits]'],
      ['canonicalUrl', 'canonical-listener-authority-url[1..512]'],
      ['endpointKey', 'optional-u8(fixed32)'],
      ['envelopeClassBits', 'u16be[known-bits]'],
      ['wireClassBits', 'u8[known-bits]'],
      ['maxStreams', 'u16be'],
      ['auxiliaryUrl', 'optional-u8(canonical-utf8[1..512])'],
      ['auxiliaryHash', 'optional-u8(fixed32)']
    ]
  },
  {
    name: 'TransportProfileArtifactV1',
    fields: [
      ['version', 'u8=1'],
      ['transportId', 'u8[1..9]'],
      ['profileName', 'canonical-ascii[1..64]'],
      ['major', 'u16be'],
      ['minor', 'u16be'],
      ['exporterId', 'u8[0..1]'],
      ['controlChannelIdType', 'u8[0..1]'],
      ['handshakeProfileHash', 'fixed32'],
      ['dependencyManifestHash', 'fixed32'],
      ['interoperabilityVectorSetHash', 'fixed32']
    ]
  },
  {
    name: 'AdmissionParametersV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['profileId', 'u16be[1..65535]'],
      ['schemeId', 'u16be[1..65535]'],
      ['conformanceClass', 'u8[1..2]'],
      ['roleBits', 'u16be[known-bits]'],
      ['verifierKey', 'compact-bytes[0..4096]'],
      ['resourceCosts', 'sorted-distinct-array[1..512](u8,u8,u8,u8,u64be)'],
      ['tokenMaxBytes', 'u16be[1..4096]'],
      ['issuanceUrl', 'optional-u8(canonical-https[1..512])'],
      ['issuerRelayKey', 'optional-u8(fixed32)'],
      ['validFromEpoch', 'u32be'],
      ['expiresEpoch', 'u32be[>validFromEpoch]'],
      ['nonce', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'AdmissionProfileV1',
    fields: [
      ['profileId', 'u16be[1..65535]'],
      ['schemeId', 'u16be[1..65535]'],
      ['conformanceClass', 'u8[1..2]'],
      ['roleBits', 'u16be[known-bits]'],
      ['parameterUrl', 'optional-u8(canonical-https[1..512])'],
      ['parameterHash', 'fixed32']
    ]
  },
  {
    name: 'BlindCoreAckV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['corePublicKey', 'fixed32'],
      ['fork', 'u64be'],
      ['length', 'u64be'],
      ['signedHeadHash', 'fixed32'],
      ['observedAtEpoch', 'u32be'],
      ['leaseEpoch', 'u32be'],
      ['result', 'u8[1..2]'],
      ['requestNonce', 'fixed32'],
      ['requestCommitment', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindDhtPointerV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['descriptorSequence', 'u64be'],
      ['descriptorHash', 'fixed32'],
      ['descriptorUrl', 'canonical-https[1..512]'],
      ['transportBits', 'u16be[known-nonzero-bits]'],
      ['issuedEpoch', 'u32be'],
      ['expiresEpoch', 'u32be[issued+1..issued+4]'],
      ['nonce', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindExternalJournalTopologyV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['storeId', 'fixed32[nonzero]'],
      ['externalJournalId', 'fixed32[nonzero]'],
      ['durabilityContinuityHash', 'fixed32'],
      ['topologySequence', 'u64be'],
      ['previousTopologyHash', 'optional-u8(fixed32)'],
      ['replicationClass', 'u8=1'],
      ['commitQuorum', 'u8=2'],
      ['sharedFailureGroupId', 'fixed32[nonzero]'],
      ['liveStoreFailureGroupId', 'fixed32[nonzero]'],
      ['backupFailureGroups', 'sorted-distinct-array[0..16](fixed32,fixed32)'],
      ['nodes', 'sorted-distinct-array[3..3](fixed32,fixed32,fixed32,u16be)'],
      ['issuedEpoch', 'u32be'],
      ['expiresEpoch', 'u32be[issued+1..issued+4]'],
      ['witnessPublicKey', 'fixed32[nonzero]'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindForwardCloseV1',
    fields: [
      ['version', 'u8=1'],
      ['circuitNonce', 'fixed32'],
      ['closeKind', 'u8[1..2]'],
      ['finalSendOffset', 'u64be'],
      ['reasonCode', 'u8']
    ]
  },
  {
    name: 'BlindForwardDataV1',
    fields: [
      ['version', 'u8=1'],
      ['circuitNonce', 'fixed32'],
      ['offset', 'u64be'],
      ['bytes', 'compact-bytes[1..65535]']
    ]
  },
  {
    name: 'BlindForwardOpenResultV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['routeId', 'fixed16'],
      ['nextDescriptorSequence', 'u64be'],
      ['nextDescriptorHash', 'fixed32'],
      ['circuitNonce', 'fixed32'],
      ['grantedWireClass', 'u8[1..3]'],
      ['circuitClass', 'u8[1..3]'],
      ['streamId', 'u64be[1..2^64-1]'],
      ['grantedInitialWindow', 'u32be[class-tuple]'],
      ['maxDataBytes', 'u32be[wire-class]'],
      ['maxCircuitBytes', 'u64be[class-tuple]'],
      ['idleMillis', 'u32be[class-tuple]'],
      ['lifetimeMillis', 'u32be[class-tuple]'],
      ['openedAtEpoch', 'u32be'],
      ['requestCommitment', 'fixed32'],
      ['nextHopAccept', 'BlindForwardHopAcceptV1'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindForwardOpenV1',
    fields: [
      ['version', 'u8=1'],
      ['routeId', 'fixed16'],
      ['nextDescriptorSequence', 'u64be'],
      ['nextDescriptorHash', 'fixed32'],
      ['requestedWireClass', 'u8[1..3]'],
      ['circuitClass', 'u8[1..3]'],
      ['circuitNonce', 'fixed32[nonzero]'],
      ['hopAdmission', 'AdmissionV1'],
      ['innerHandshake', 'compact-bytes[32]']
    ]
  },
  {
    name: 'BlindForwardWindowV1',
    fields: [
      ['version', 'u8=1'],
      ['circuitNonce', 'fixed32'],
      ['consumedThrough', 'u64be'],
      ['creditIncrement', 'u32be[1..1048576]']
    ]
  },
  {
    name: 'BlindHealthChallengeV1',
    fields: [
      ['version', 'u8=1'],
      ['descriptorSequence', 'u64be'],
      ['descriptorHash', 'fixed32'],
      ['endpointId', 'u8[1..255]'],
      ['transportSupportBit', 'u16be[known-one-hot-bit]'],
      ['requestedRoleBits', 'u16be[known-nonzero-bits]'],
      ['requestedOperationBits', 'u32be[known-nonzero-bits]'],
      ['clientNonce', 'fixed32']
    ]
  },
  {
    name: 'BlindHealthResultV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['storeId', 'fixed32[nonzero]'],
      ['descriptorSequence', 'u64be'],
      ['descriptorHash', 'fixed32'],
      ['endpointId', 'u8[1..255]'],
      ['transportSupportBit', 'u16be[known-one-hot-bit]'],
      ['durabilityContinuityHash', 'fixed32'],
      ['durabilityProfileHash', 'fixed32'],
      ['clientNonce', 'fixed32'],
      ['readyRoleBits', 'u16be[known-bits]'],
      ['readyOperationBits', 'u32be[known-bits]'],
      ['clockState', 'u8[1..3]'],
      ['effectiveEpochFloor', 'u32be'],
      ['integrityState', 'u8[1..3]'],
      ['checkpointAgeBand', 'u8[0..7]'],
      ['scrubAgeBand', 'u8[0..7]'],
      ['rebalanceState', 'u8[0..3]'],
      ['capacityBand', 'u8[0..7]'],
      ['challengeEpoch', 'u32be'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindOhttpKeyConfigV1',
    fields: [
      ['version', 'u8=1'],
      ['gatewayRelayKey', 'fixed32'],
      ['gatewayDescriptorSequence', 'u64be'],
      ['configId', 'u8'],
      ['kemId', 'u16be[1..65535]'],
      ['kdfId', 'u16be[1..65535]'],
      ['aeadId', 'u16be[1..65535]'],
      ['encodedPublicKey', 'compact-bytes[1..256]'],
      ['notBeforeEpoch', 'u32be'],
      ['notAfterEpoch', 'u32be[notBefore+1..notBefore+120]'],
      ['previousConfigHash', 'optional-u8(fixed32)'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindServiceDescriptorV1',
    fields: [
      ['version', 'u8=1'],
      ['relayPublicKey', 'fixed32'],
      ['storeId', 'fixed32[nonzero]'],
      ['descriptorSequence', 'u64be'],
      ['previousDescriptorHash', 'optional-u8(fixed32)'],
      ['identitySequence', 'u64be'],
      ['previousRelayKey', 'optional-u8(fixed32)'],
      ['identityTransition', 'optional-u8(RelayIdentityTransitionV1)'],
      ['build', 'BuildProfileV1'],
      ['protocols', 'sorted-distinct-array[1..16](ProtocolProfileV1)'],
      ['endpoints', 'sorted-distinct-array[1..16](TransportEndpointV1)'],
      ['cellSizeClassBits', 'u8[known-nonzero-bits]'],
      ['leaseClassBits', 'u8[known-nonzero-bits]'],
      ['maxBatchCount', 'u16be[1..64]'],
      ['maxResponseBytes', 'u32be[1..4194304]'],
      ['maxSponsoredCoreLength', 'u64be'],
      ['enabledOperationBits', 'u32be[known-bits]'],
      ['admissionProfiles', 'sorted-distinct-array[1..8](AdmissionProfileV1)'],
      ['durability', 'DurabilityProfileV1'],
      ['durabilityContinuityHash', 'fixed32'],
      ['durabilityProfileHash', 'fixed32'],
      ['storeLifecycleState', 'u8[1..3]'],
      ['drainStartedEpoch', 'optional-u8(u32be)'],
      ['capacityBand', 'u8[0..7]'],
      ['issuedEpoch', 'u32be'],
      ['expiresEpoch', 'u32be[issued+1..issued+4]'],
      ['descriptorNonce', 'fixed32'],
      ['signature', 'fixed64']
    ]
  },
  {
    name: 'BlindStreamChunkPlainV1',
    fields: [
      ['version', 'u8=1'],
      ['wireClass', 'u8[1..3]'],
      ['flags', 'u8[known-bits]'],
      ['contentLength', 'u32be'],
      ['content', 'bytes[contentLength]'],
      ['randomPadding', 'bytes[wireClass-23-contentLength]']
    ]
  },
  {
    name: 'CoreMirrorRequestV1',
    fields: [
      ['version', 'u8=1'],
      ['corePublicKey', 'fixed32'],
      ['fork', 'u64be'],
      ['length', 'u64be'],
      ['signedHeadHash', 'fixed32'],
      ['leaseClass', 'u8[1..4]'],
      ['clientNonce', 'fixed32'],
      ['admission', 'AdmissionV1']
    ]
  },
  {
    name: 'CoreServeChallengeV1',
    fields: [
      ['version', 'u8=1'],
      ['corePublicKey', 'fixed32'],
      ['fork', 'u64be'],
      ['length', 'u64be'],
      ['signedHeadHash', 'fixed32'],
      ['blockIndices', 'sorted-distinct-array[1..16](u64be<length)'],
      ['clientNonce', 'fixed32'],
      ['admission', 'optional-u8(AdmissionV1)']
    ]
  },
  {
    name: 'CoreServeResultV1',
    fields: [
      ['version', 'u8=1'],
      ['acknowledgement', 'BlindCoreAckV1'],
      ['proofsAndBlocks', 'compact-bytes[1..4194048]']
    ]
  },
  {
    name: 'RelayIdentityTransitionV1',
    fields: [
      ['version', 'u8=1'],
      ['oldRelayKey', 'fixed32'],
      ['newRelayKey', 'fixed32'],
      ['oldIdentitySequence', 'u64be'],
      ['newIdentitySequence', 'u64be[old+1]'],
      ['validFromEpoch', 'u32be'],
      ['reasonCode', 'u8[1..3]'],
      ['transitionNonce', 'fixed32'],
      ['oldSignature', 'fixed64'],
      ['newSignature', 'fixed64']
    ]
  },
  {
    name: 'SchemaCatalogEntryV1',
    fields: [
      ['category', 'u8[1..5]'],
      ['categoryLocalSchemaId', 'u16be[1..65535]'],
      ['schemaName', 'canonical-ascii[1..96]'],
      ['canonicalSchemaBytes', 'compact-bytes[1..65535]']
    ]
  }
])

const schemaMetadataOverrideNames = new Set(SCHEMA_METADATA_OVERRIDES.map(schema => schema.name))

export const IMPLEMENTED_SCHEMAS = deepFreeze([
  ...BASE_IMPLEMENTED_SCHEMAS.filter(schema => !schemaMetadataOverrideNames.has(schema.name)),
  ...SCHEMA_METADATA_OVERRIDES,
  ...EXTENDED_SCHEMA_METADATA
])

export const SCHEMA_NAMES_BY_CATEGORY = deepFreeze({
  [SCHEMA_CATEGORY.WIRE]: [
    'AdmissionCostRuleV1',
    'AdmissionParametersV1',
    'AdmissionProfileV1',
    'AdmissionV1',
    'BatchGetEntryV1',
    'BatchGetResultV1',
    'BatchGetSignaturePayloadV1',
    'BatchGetV1',
    'BlindAdmissionParametersRequestV1',
    'BlindBackupChunkManifestV1',
    'BlindBackupEncryptionProfileV1',
    'BlindBackupManifestV1',
    'BlindBackupRetentionTransitionV1',
    'BlindCleanRestoreEvidenceV1',
    'BlindCoreAckV1',
    'BlindDescribeGetV1',
    'BlindDhtPointerV1',
    'BlindDispatchFrameV1',
    'BlindErrorV1',
    'BlindExternalCommitWitnessV1',
    'BlindExternalJournalTopologyV1',
    'BlindForwardCloseV1',
    'BlindForwardDataV1',
    'BlindForwardHopAcceptV1',
    'BlindForwardHopOpenV1',
    'BlindForwardOpenResultV1',
    'BlindForwardOpenV1',
    'BlindForwardWindowV1',
    'BlindHealthChallengeV1',
    'BlindHealthResultV1',
    'BlindOhttpKeyConfigV1',
    'BlindOhttpTransportErrorV1',
    'BlindOuterEnvelopeV1',
    'BlindReceiptV1',
    'BlindRestoreEvidenceBundleV1',
    'BlindRestoreEvidenceHeadV1',
    'BlindServiceDescriptorV1',
    'BlindStreamChunkPlainV1',
    'BlindTransportRouteV1',
    'BuildProfileV1',
    'CoreMirrorRequestV1',
    'CoreOpenReplicationResultV1',
    'CoreOpenReplicationV1',
    'CoreServeChallengeV1',
    'CoreServeResultV1',
    'DomainRegistryEntryV1',
    'DropCellV1',
    'DurabilityContinuityBindingV1',
    'DurabilityProfileV1',
    'ErrorProfileEntryV1',
    'GetCellResultV1',
    'GetCellV1',
    'InboxAppendAckV1',
    'InboxAppendV1',
    'InboxCreateV1',
    'InboxManageV1',
    'InboxReadResultV1',
    'InboxReadSignaturePayloadV1',
    'InboxReadV1',
    'InboxReceiptV1',
    'InboxWatchV1',
    'OperationProfileV1',
    'ProtocolProfileV1',
    'ProveCellResultV1',
    'ProveCellV1',
    'PutCellV1',
    'RelayIdentityTransitionV1',
    'RelayResultBindingV1',
    'RenewCellV1',
    'SchemaCatalogEntryV1',
    'TransportEndpointV1'
  ],
  [SCHEMA_CATEGORY.EVIDENCE]: [
    'BlindArtifactFileInventoryV1',
    'BlindExecutableEntrypointCatalogV1',
    'BlindLaunchTopologyV1',
    'BlindListenerCatalogV1',
    'BlindListenerEntryV1',
    'BlindProcessInspectionEvidenceV1',
    'BlindProductDistributionBundleV1',
    'BlindProductIsolationEvidenceV1',
    'BlindProductIsolationReportBundleV1',
    'BlindReleaseEvidenceBundleV1',
    'BlindReleaseSupportHorizonV1',
    'BlindRouteAbsenceEvidenceV1',
    'BlindRuntimeBoundaryEvidenceV1',
    'BlindRuntimeImportGraphV1',
    'BuildInputV1',
    'BuildManifestV1',
    'BuildReproductionAttestationV1',
    'HiveRelayCompatibilityAuthorityTransitionV1',
    'HiveRelayCompatibilityBuildManifestV1',
    'HiveRelayCompatibilityRuntimeBoundaryEvidenceV1',
    'HiveRelayCompatibilitySunsetGenesisV1',
    'HiveRelayCompatibilitySunsetHeadV1',
    'HiveRelayLegacyCompatibilitySunsetV1',
    'ProtocolProfileArtifactV1',
    'ReproductionEnvironmentV1',
    'ToolchainEntryV1',
    'ToolchainManifestV1',
    'TransportProfileArtifactV1'
  ],
  [SCHEMA_CATEGORY.CLIENT_EXAMPLE]: [
    'BlindCoreReadCapV1',
    'CellBlobV1',
    'OpaqueChainCheckpointV1',
    'OpaqueChainFrameV1',
    'ReadCellCapV1',
    'WriteCellCapV1'
  ],
  [SCHEMA_CATEGORY.INTERNAL_STORE]: [
    'BlindCellChargedReadPinEntrySnapshotV1',
    'BlindCellChargedReadRetrySnapshotV1',
    'BlindCellCommittedPutSpendSnapshotV1',
    'BlindCellCommittedRenewSpendSnapshotV1',
    'BlindCellControlGlobalSnapshotV1',
    'BlindCellHistoricalResultSnapshotV1',
    'BlindCellIntegrityEvidenceSnapshotV1',
    'BlindCellProfileStagingSnapshotV1',
    'BlindCellRecordSnapshotV1',
    'BlindCellRequestResultSnapshotV1',
    'BlindCellReservedSpendSnapshotV1',
    'BlindCellTerminalSpendSnapshotV1',
    'BlindControlStateSnapshotV1',
    'BlindCoreControlGlobalSnapshotV1',
    'BlindCoreOpenReplicationRetrySnapshotV1',
    'BlindExternalAckFloorV1',
    'BlindExternalControlCheckpointV1',
    'BlindInboxCommittedSpendSnapshotV1',
    'BlindInboxControlGlobalSnapshotV1',
    'BlindInboxExpiredAppendSpendSnapshotV1',
    'BlindInboxFrameSnapshotV1',
    'BlindInboxIntegrityEvidenceSnapshotV1',
    'BlindInboxProfileStagingSnapshotV1',
    'BlindInboxRecordSnapshotV1',
    'BlindInboxRequestResultSnapshotV1',
    'BlindInboxReservedSpendSnapshotV1',
    'BlindInboxRetryFramePinSnapshotV1',
    'BlindInboxRetryMaterialSnapshotV1',
    'BlindInboxRetryReconstructionV1',
    'BlindInboxTerminalSpendSnapshotV1',
    'BlindLocalCheckpointV1',
    'BlindPreparedAdmissionStoreV1',
    'BlindStoreManifestV1',
    'BlindWalHeaderV2',
    'CellRecordV1',
    'ChargedUnaryRetryV1'
  ],
  [SCHEMA_CATEGORY.PRIVATE_IPC]: [
    'LocalAuthenticatedChannelV1',
    'LocalDispatchV1',
    'LocalStreamAttachContextV1',
    'LocalStreamControlV1',
    'LocalStreamFrameV1',
    'LocalStreamOpenV1',
    'LocalUnaryResponseV1'
  ]
})

function asciiSort (a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}

for (const names of Object.values(SCHEMA_NAMES_BY_CATEGORY)) {
  for (let i = 1; i < names.length; i++) {
    if (asciiSort(names[i - 1], names[i]) >= 0) {
      throw new Error('schema category names must be unique and raw-ASCII sorted')
    }
  }
}

export const DRAFT_SCHEMA_CATALOG = deepFreeze(
  Object.entries(SCHEMA_NAMES_BY_CATEGORY).flatMap(([category, names]) =>
    names.map((schemaName, index) => ({
      category: Number(category),
      categoryLocalSchemaId: index + 1,
      schemaName
    }))
  )
)

export const REQUIRED_SCHEMA_NAMES = deepFreeze(
  DRAFT_SCHEMA_CATALOG.map(entry => entry.schemaName).sort(asciiSort)
)

const schemaCategoryByName = new Map(DRAFT_SCHEMA_CATALOG.map(entry => [entry.schemaName, entry.category]))

export function schemaCategory (schemaName) {
  return schemaCategoryByName.get(schemaName) || null
}

export function draftSchemaId (schemaName) {
  const entry = DRAFT_SCHEMA_CATALOG.find(entry => entry.schemaName === schemaName)
  return entry ? entry.categoryLocalSchemaId : 0
}

const REQUEST_KIND_BITS = 1 << (FRAME_KIND.REQUEST - 1)
const UNARY_RESULT_KIND_BITS = (1 << (FRAME_KIND.RESPONSE - 1)) | (1 << (FRAME_KIND.ERROR - 1))
const ALL_UNARY_TRANSPORT_BITS = TRANSPORT_SUPPORT.DIRECT_HTTP | TRANSPORT_SUPPORT.DIRECT_NATIVE |
  TRANSPORT_SUPPORT.OHTTP | TRANSPORT_SUPPORT.TOR_HTTP | TRANSPORT_SUPPORT.TOR_NATIVE

function unaryOperationProfile (familyId, operationId, requestSchema, resultSchema, requestCap, resultCap,
  admissionMode, costClassRuleId, requestCommitmentDomainId, resultSignatureDomainId,
  transportSupportBits = ALL_UNARY_TRANSPORT_BITS, streamTransition = STREAM_TRANSITION.UNARY) {
  return {
    familyId,
    operationId,
    requestSchemaId: draftSchemaId(requestSchema),
    resultSchemaId: draftSchemaId(resultSchema),
    allowedRequestKindBits: REQUEST_KIND_BITS,
    allowedResultKindBits: UNARY_RESULT_KIND_BITS,
    streamTransition,
    maxRequestBodyBytes: requestCap,
    maxResultBodyBytes: resultCap,
    admissionMode,
    costClassRuleId,
    requestCommitmentDomainId,
    resultSignatureDomainId,
    errorProfileId: 1,
    transportSupportBits
  }
}

const NATIVE_TRANSPORT_BITS = TRANSPORT_SUPPORT.DIRECT_NATIVE | TRANSPORT_SUPPORT.TOR_NATIVE
const FORWARD_TRANSPORT_BITS = NATIVE_TRANSPORT_BITS | TRANSPORT_SUPPORT.MASQUE_NATIVE
const STREAM_KIND_BITS = 1 << (FRAME_KIND.STREAM - 1)
const ERROR_KIND_BITS = 1 << (FRAME_KIND.ERROR - 1)

function forwardActiveOperationProfile (operationId, requestSchema, requestCap, resultCap, allowErrorResult = false) {
  return {
    familyId: FAMILY.FORWARD,
    operationId,
    requestSchemaId: draftSchemaId(requestSchema),
    resultSchemaId: 0,
    allowedRequestKindBits: STREAM_KIND_BITS,
    allowedResultKindBits: STREAM_KIND_BITS | (allowErrorResult ? ERROR_KIND_BITS : 0),
    streamTransition: STREAM_TRANSITION.FORWARD_ACTIVE,
    maxRequestBodyBytes: requestCap,
    maxResultBodyBytes: resultCap,
    admissionMode: ADMISSION_MODE.NONE,
    costClassRuleId: 0,
    requestCommitmentDomainId: 0,
    resultSignatureDomainId: 0,
    errorProfileId: ERROR_PROFILE_ID.CANONICAL_V1,
    transportSupportBits: FORWARD_TRANSPORT_BITS
  }
}

export const OPERATION_PROFILE_ROWS = deepFreeze([
  unaryOperationProfile(FAMILY.DESCRIBE, OPERATION.DESCRIBE.GET, 'BlindDescribeGetV1', 'BlindServiceDescriptorV1',
    16384, 16384, ADMISSION_MODE.NONE, 0, 0, RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR),
  unaryOperationProfile(FAMILY.DESCRIBE, OPERATION.DESCRIBE.CHALLENGE, 'BlindHealthChallengeV1', 'BlindHealthResultV1',
    16384, 16384, ADMISSION_MODE.NONE, 0, 0, RESULT_SIGNATURE_DOMAIN_ID.HEALTH_RESULT),
  unaryOperationProfile(FAMILY.DESCRIBE, OPERATION.DESCRIBE.ADMISSION_PARAMETERS, 'BlindAdmissionParametersRequestV1',
    'AdmissionParametersV1', 16384, 16384, ADMISSION_MODE.NONE, 0, 0,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT, 'PutCellV1', 'BlindReceiptV1', 1056768, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.CELL_PUT_CLASS_LEASE, REQUEST_COMMITMENT_DOMAIN_ID.CELL_PUT,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.GET, 'GetCellV1', 'GetCellResultV1', 16384, 1048832,
    ADMISSION_MODE.OPTIONAL, COST_CLASS_RULE_ID.STORED_CELL_CLASS_NONE, REQUEST_COMMITMENT_DOMAIN_ID.CELL_GET, 0),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.RENEW, 'RenewCellV1', 'BlindReceiptV1', 16384, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.STORED_CELL_CLASS_REQUEST_LEASE, REQUEST_COMMITMENT_DOMAIN_ID.CELL_RENEW,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.DROP, 'DropCellV1', 'BlindReceiptV1', 16384, 16384,
    ADMISSION_MODE.NONE, 0, REQUEST_COMMITMENT_DOMAIN_ID.CELL_DROP, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.PROVE, 'ProveCellV1', 'ProveCellResultV1', 16384, 1049600,
    ADMISSION_MODE.OPTIONAL, COST_CLASS_RULE_ID.STORED_CELL_CLASS_NONE, REQUEST_COMMITMENT_DOMAIN_ID.CELL_PROVE,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT),
  unaryOperationProfile(FAMILY.CELL, OPERATION.CELL.BATCH_GET, 'BatchGetV1', 'BatchGetResultV1', 16384, 4194304,
    ADMISSION_MODE.OPTIONAL, COST_CLASS_RULE_ID.CANONICAL_RESULT_BAND_NONE, REQUEST_COMMITMENT_DOMAIN_ID.CELL_BATCH_GET,
    RESULT_SIGNATURE_DOMAIN_ID.BATCH_GET_RESULT),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.CREATE, 'InboxCreateV1', 'InboxReceiptV1', 16384, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.INBOX_CREATE_SHAPE_LEASE, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_CREATE,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.RENEW, 'InboxManageV1', 'InboxReceiptV1', 16384, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.INBOX_STORED_SHAPE_REQUEST_LEASE, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_RENEW,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.CLOSE, 'InboxManageV1', 'InboxReceiptV1', 16384, 16384,
    ADMISSION_MODE.NONE, 0, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_CLOSE, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.APPEND, 'InboxAppendV1', 'InboxAppendAckV1', 70656, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.INBOX_APPEND_FRAME_RETENTION, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_APPEND,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.READ, 'InboxReadV1', 'InboxReadResultV1', 16384, 4194304,
    ADMISSION_MODE.OPTIONAL, COST_CLASS_RULE_ID.CANONICAL_RESULT_BAND_NONE, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_READ,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT),
  unaryOperationProfile(FAMILY.INBOX, OPERATION.INBOX.WATCH, 'InboxWatchV1', 'InboxReadResultV1', 16384, 4194304,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.INBOX_WATCH_BOUND_WAIT, REQUEST_COMMITMENT_DOMAIN_ID.INBOX_WATCH,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT),
  unaryOperationProfile(FAMILY.CORE, OPERATION.CORE.MIRROR, 'CoreMirrorRequestV1', 'BlindCoreAckV1', 16384, 16384,
    ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.CORE_MIRROR_LENGTH_LEASE, REQUEST_COMMITMENT_DOMAIN_ID.CORE_MIRROR,
    RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK),
  unaryOperationProfile(FAMILY.CORE, OPERATION.CORE.PROVE, 'CoreServeChallengeV1', 'CoreServeResultV1', 16384, 4194304,
    ADMISSION_MODE.OPTIONAL, COST_CLASS_RULE_ID.CANONICAL_RESULT_BAND_NONE, REQUEST_COMMITMENT_DOMAIN_ID.CORE_SERVE,
    RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK),
  unaryOperationProfile(FAMILY.CORE, OPERATION.CORE.OPEN_REPLICATION, 'CoreOpenReplicationV1',
    'CoreOpenReplicationResultV1', 16384, 16384, ADMISSION_MODE.REQUIRED,
    COST_CLASS_RULE_ID.CORE_SESSION_CLASS_NONE, REQUEST_COMMITMENT_DOMAIN_ID.CORE_OPEN_REPLICATION,
    RESULT_SIGNATURE_DOMAIN_ID.CORE_OPEN_RESULT, NATIVE_TRANSPORT_BITS, STREAM_TRANSITION.CORE_CHILD),
  unaryOperationProfile(FAMILY.FORWARD, OPERATION.FORWARD.OPEN, 'BlindForwardOpenV1', 'BlindForwardOpenResultV1',
    131072, 131072, ADMISSION_MODE.REQUIRED, COST_CLASS_RULE_ID.FORWARD_CIRCUIT_CLASS_NONE,
    REQUEST_COMMITMENT_DOMAIN_ID.FORWARD_OPEN, RESULT_SIGNATURE_DOMAIN_ID.FORWARD_OPEN_RESULT,
    FORWARD_TRANSPORT_BITS, STREAM_TRANSITION.FORWARD_OPEN),
  forwardActiveOperationProfile(OPERATION.FORWARD.DATA, 'BlindForwardDataV1', 66000, 66000),
  forwardActiveOperationProfile(OPERATION.FORWARD.WINDOW, 'BlindForwardWindowV1', 1024, 1024),
  forwardActiveOperationProfile(OPERATION.FORWARD.CLOSE, 'BlindForwardCloseV1', 1024, 16384, true)
])

for (let i = 0; i < OPERATION_PROFILE_ROWS.length; i++) {
  const row = OPERATION_PROFILE_ROWS[i]
  const previous = i === 0 ? null : OPERATION_PROFILE_ROWS[i - 1]
  if (previous && (previous.familyId > row.familyId ||
      (previous.familyId === row.familyId && previous.operationId >= row.operationId))) {
    throw new Error('operation profile rows must be unique and family/operation sorted')
  }
  if (row.requestSchemaId === 0 ||
      (row.resultSchemaId === 0) !== (row.streamTransition === STREAM_TRANSITION.FORWARD_ACTIVE)) {
    throw new Error('operation profile references an unknown or transition-incompatible schema')
  }
  if ((row.admissionMode === ADMISSION_MODE.NONE) !== (row.costClassRuleId === 0) ||
      (row.costClassRuleId !== 0 && admissionCostRule(row.costClassRuleId) == null)) {
    throw new Error('operation profile references an invalid admission cost rule')
  }
  const requestDomain = domainRegistryEntry(row.requestCommitmentDomainId)
  const resultDomain = row.resultSignatureDomainId === 0 ? null : domainRegistryEntry(row.resultSignatureDomainId)
  if ((row.requestCommitmentDomainId !== 0 &&
       (!requestDomain || requestDomain.purpose !== DOMAIN_PURPOSE.REQUEST_COMMITMENT ||
        requestDomain.recipeId !== DOMAIN_RECIPE.OPERATION_DEFINED_COMMITMENT_PREIMAGE)) ||
      (row.admissionMode === ADMISSION_MODE.REQUIRED && row.requestCommitmentDomainId === 0) ||
      (row.resultSignatureDomainId !== 0 &&
       (!resultDomain || resultDomain.purpose !== DOMAIN_PURPOSE.RESULT_SIGNATURE ||
        resultDomain.recipeId !== DOMAIN_RECIPE.ED25519_DOMAIN_LEN64_PAYLOAD))) {
    throw new Error('operation profile references an invalid domain')
  }
  const isForwardActive = row.streamTransition === STREAM_TRANSITION.FORWARD_ACTIVE
  if (isForwardActive !== (row.allowedRequestKindBits === STREAM_KIND_BITS) ||
      (isForwardActive && (row.allowedResultKindBits & STREAM_KIND_BITS) === 0) ||
      (!isForwardActive && row.allowedRequestKindBits !== REQUEST_KIND_BITS) ||
      (!isForwardActive && row.allowedResultKindBits !== UNARY_RESULT_KIND_BITS)) {
    throw new Error('operation profile kind bits contradict its stream transition')
  }
}

const operationProfileByPair = new Map(
  OPERATION_PROFILE_ROWS.map(row => [`${row.familyId}:${row.operationId}`, row])
)

export const OPERATION_COUNT = OPERATION_PROFILE_ROWS.length
export const ALL_OPERATION_BITS = (1 << OPERATION_COUNT) - 1
export const CLOCK_UNSAFE_OPERATION_BITS = 0x00009628
export const DRAINING_OPERATION_BITS = 0x000129d7

export function operationOrdinal (familyId, operationId) {
  const index = OPERATION_PROFILE_ROWS.findIndex(row =>
    row.familyId === familyId && row.operationId === operationId)
  return index < 0 ? -1 : index
}

export function operationBit (familyId, operationId) {
  const ordinal = operationOrdinal(familyId, operationId)
  return ordinal < 0 ? 0 : 1 << ordinal
}

export function operationProfile (familyId, operationId) {
  return operationProfileByPair.get(`${familyId}:${operationId}`) || null
}

const implementedSchemaNames = IMPLEMENTED_SCHEMAS.map(schema => schema.name)
const wireImplementedSchemaNames = IMPLEMENTED_SCHEMAS
  .filter(schema => schemaCategory(schema.name) === SCHEMA_CATEGORY.WIRE)
  .map(schema => schema.name)
const externallyOwnedSchemaNames = [...SCHEMA_NAMES_BY_CATEGORY[SCHEMA_CATEGORY.PRIVATE_IPC]]
const protocolOwnedRequiredSchemaNames = REQUIRED_SCHEMA_NAMES.filter(name => !externallyOwnedSchemaNames.includes(name))
const missingSchemaNames = protocolOwnedRequiredSchemaNames.filter(name => !implementedSchemaNames.includes(name))
const duplicateSchemaNames = implementedSchemaNames.filter((name, index, names) => names.indexOf(name) !== index)
const unclassifiedImplementedSchemaNames = implementedSchemaNames.filter(name => schemaCategory(name) == null)
const wireDuplicateSchemaNames = wireImplementedSchemaNames
  .filter((name, index, names) => names.indexOf(name) !== index)
const wireUnexpectedSchemaNames = wireImplementedSchemaNames
  .filter(name => !SCHEMA_NAMES_BY_CATEGORY[SCHEMA_CATEGORY.WIRE].includes(name))

const schemaStatusByCategory = {}
for (const category of Object.values(SCHEMA_CATEGORY)) {
  const requiredSchemaNames = [...SCHEMA_NAMES_BY_CATEGORY[category]]
  const implemented = requiredSchemaNames.filter(name => implementedSchemaNames.includes(name))
  const externallyOwned = requiredSchemaNames.filter(name => externallyOwnedSchemaNames.includes(name))
  schemaStatusByCategory[category] = {
    requiredSchemaNames,
    implementedSchemaNames: implemented,
    externallyOwnedSchemaNames: externallyOwned,
    missingSchemaNames: requiredSchemaNames.filter(name =>
      !implementedSchemaNames.includes(name) && !externallyOwnedSchemaNames.includes(name))
  }
}

const requiredOperationPairs = []
for (const [familyName, familyId] of Object.entries(FAMILY)) {
  for (const [operationName, operationId] of Object.entries(OPERATION[familyName])) {
    requiredOperationPairs.push({ familyId, operationId, familyName, operationName })
  }
}

export const OPERATION_PROFILE_STATUS = deepFreeze({
  requiredPairs: requiredOperationPairs,
  implementedPairs: OPERATION_PROFILE_ROWS.map(row => ({ familyId: row.familyId, operationId: row.operationId })),
  missingPairs: requiredOperationPairs.filter(pair => !OPERATION_PROFILE_ROWS.some(row =>
    row.familyId === pair.familyId && row.operationId === pair.operationId))
})

export const OPERATION_CAP_ROWS = deepFreeze(OPERATION_PROFILE_ROWS.map(row => ({
  familyId: row.familyId,
  operationId: row.operationId,
  requestSchemaId: row.requestSchemaId,
  resultSchemaId: row.resultSchemaId,
  maxRequestBodyBytes: row.maxRequestBodyBytes,
  maxResultBodyBytes: row.maxResultBodyBytes
})))

const invalidOperationCapRows = OPERATION_CAP_ROWS.filter(row =>
  !Number.isSafeInteger(row.maxRequestBodyBytes) || row.maxRequestBodyBytes < 0 ||
  row.maxRequestBodyBytes > DISPATCH_LIMITS.MAX_BODY_BYTES ||
  !Number.isSafeInteger(row.maxResultBodyBytes) || row.maxResultBodyBytes < 0 ||
  row.maxResultBodyBytes > DISPATCH_LIMITS.MAX_BODY_BYTES ||
  row.requestSchemaId === 0 ||
  (row.resultSchemaId === 0) !== (row.familyId === FAMILY.FORWARD && row.operationId !== OPERATION.FORWARD.OPEN))

export const OPERATION_CAP_STATUS = deepFreeze({
  requiredRowCount: requiredOperationPairs.length,
  implementedRowCount: OPERATION_CAP_ROWS.length,
  invalidRows: invalidOperationCapRows.map(row => ({ familyId: row.familyId, operationId: row.operationId })),
  complete: OPERATION_CAP_ROWS.length === requiredOperationPairs.length &&
    OPERATION_PROFILE_STATUS.missingPairs.length === 0 && invalidOperationCapRows.length === 0
})

const errorTransportMappingComplete = OHTTP_TRANSPORT_ERROR_ROWS.length === 3 &&
  OHTTP_TRANSPORT_ERROR_ROWS.every((row, index) => row.code === index + 1 &&
    row.protectedStatus === [400, 503, 504][index] && row.deliveryBoundary === index + 1 &&
    row.retryAction === [0, 1, 2][index]) &&
  ERROR_PROFILE_ROWS.length === 20 && ERROR_PROFILE_ROWS.every(row =>
  row.directCorrelatedStatus === 200 && row.protectedInnerStatus === 200)

export const ERROR_TRANSPORT_MAPPING_STATUS = deepFreeze({
  correlatedErrorRowCount: ERROR_PROFILE_ROWS.length,
  protectedTransportErrorRowCount: OHTTP_TRANSPORT_ERROR_ROWS.length,
  complete: errorTransportMappingComplete
})

export const CATEGORY_REGISTRY_ARTIFACTS = deepFreeze({
  [SCHEMA_CATEGORY.WIRE]: 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  [SCHEMA_CATEGORY.EVIDENCE]: 'packages/blind-protocol/hiverelay-blind-evidence-v1.draft.cenc',
  [SCHEMA_CATEGORY.CLIENT_EXAMPLE]: 'packages/blind-protocol/hiverelay-blind-client-example-v1.draft.cenc',
  [SCHEMA_CATEGORY.INTERNAL_STORE]: 'packages/blind-protocol/hiverelay-blind-store-v1.draft.cenc',
  [SCHEMA_CATEGORY.PRIVATE_IPC]: 'packages/blind-ipc/hiverelay-blind-private-ipc-v1.cenc'
})

export const CATEGORY_REGISTRY_STATUS = deepFreeze({
  artifactCount: Object.keys(CATEGORY_REGISTRY_ARTIFACTS).length,
  packageOwnedCategoryCount: 4,
  externalCategoryCount: 1,
  complete: Object.values(schemaStatusByCategory).every(status => status.missingSchemaNames.length === 0) &&
    Object.keys(CATEGORY_REGISTRY_ARTIFACTS).length === 5
})

export const ABI_RELEASE_BLOCKERS = deepFreeze([])

export const ABI_STATUS = deepFreeze({
  profile: 'wire-authority-v1',
  authorityArtifactPath: CATEGORY_REGISTRY_ARTIFACTS[SCHEMA_CATEGORY.WIRE],
  vectorManifestPath: 'packages/blind-protocol/vector-manifest-v1.cenc',
  authorityMetadataPath: 'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json',
  transitionalAuthorityAliasPath: 'packages/blind-protocol/hiverelay-blind-abi-v1.draft.cenc',
  transitionalVectorAliasPath: 'packages/blind-protocol/vectors/draft/vector-manifest-v1.draft.cenc',
  wireAuthorityPublished: true,
  schemaInventorySource: 'stable-master-142-schema-category-catalog',
  implementedSchemaNames,
  requiredSchemaNames: REQUIRED_SCHEMA_NAMES,
  protocolOwnedRequiredSchemaNames,
  externallyOwnedSchemaNames,
  missingSchemaNames,
  schemaStatusByCategory,
  wireRequiredSchemaNames: schemaStatusByCategory[SCHEMA_CATEGORY.WIRE].requiredSchemaNames,
  wireImplementedSchemaNames: schemaStatusByCategory[SCHEMA_CATEGORY.WIRE].implementedSchemaNames,
  wireMissingSchemaNames: schemaStatusByCategory[SCHEMA_CATEGORY.WIRE].missingSchemaNames,
  wireDuplicateSchemaNames,
  wireUnexpectedSchemaNames,
  duplicateSchemaNames,
  unclassifiedImplementedSchemaNames,
  operationProfileStatus: OPERATION_PROFILE_STATUS,
  operationCapStatus: OPERATION_CAP_STATUS,
  errorTransportMappingStatus: ERROR_TRANSPORT_MAPPING_STATUS,
  categoryRegistryStatus: CATEGORY_REGISTRY_STATUS,
  releaseBlockers: ABI_RELEASE_BLOCKERS,
  releaseReady: schemaStatusByCategory[SCHEMA_CATEGORY.WIRE].missingSchemaNames.length === 0 &&
    wireDuplicateSchemaNames.length === 0 && wireUnexpectedSchemaNames.length === 0 &&
    OPERATION_PROFILE_STATUS.missingPairs.length === 0 && OPERATION_CAP_STATUS.complete &&
    ERROR_TRANSPORT_MAPPING_STATUS.complete && ABI_RELEASE_BLOCKERS.length === 0
})

const familyNameById = new Map(Object.entries(FAMILY).map(([name, id]) => [id, name]))
const operationIdsByFamily = new Map(
  Object.entries(FAMILY).map(([name, id]) => [id, new Set(Object.values(OPERATION[name]))])
)

export function familyName (familyId) {
  return familyNameById.get(familyId) || null
}

export function routeForFamily (familyId) {
  return FAMILY_ROUTES[familyId] || null
}

export function isKnownOperation (familyId, operationId) {
  const operations = operationIdsByFamily.get(familyId)
  return Boolean(operations && operations.has(operationId))
}

export function assertReleaseReady () {
  if (ABI_STATUS.releaseReady) return
  const error = new Error(`blind public WIRE ABI is incomplete; missing ${ABI_STATUS.wireMissingSchemaNames.length} required schemas; ${ABI_STATUS.releaseBlockers.length} release blockers remain`)
  error.code = 'BLIND_ABI_INCOMPLETE'
  error.missingSchemaNames = [...ABI_STATUS.missingSchemaNames]
  error.wireMissingSchemaNames = [...ABI_STATUS.wireMissingSchemaNames]
  error.missingOperationPairs = [...ABI_STATUS.operationProfileStatus.missingPairs]
  error.releaseBlockers = [...ABI_STATUS.releaseBlockers]
  throw error
}

export { deepFreeze }
