// The four index schemas (Design B §3.2). These are plain JSON Schema
// (draft-07) registered into the schema-sheets room via addNewSchema, and
// also used here to validate mapper output before a row is written.
//
// Trust model: the room is an INDEX, not an authority. relay-directory rows
// carry capabilitySig so clients re-verify via verifyCapabilityDoc without
// trusting the room writer; manifest rows carry keet attestations; anchored
// claims are re-checked against the relay's anchor-proof route. See README.
import Ajv from 'ajv'
import addFormats from 'ajv-formats'

export const SCHEMA_NAMES = ['pin-registry', 'relay-directory', 'app-manifest', 'verification']

// NOTE: no `$id` on any schema — schema-sheets compiles each row's schema in
// its own Ajv keyed by $id, so a duplicate $id across row applies throws
// "schema with id already exists". Schemas are identified by the name passed
// to addNewSchema, not by $id.
export const PIN_REGISTRY_SCHEMA = {
  type: 'object',
  properties: {
    appKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    type: { type: 'string' },
    name: { type: 'string' },
    version: { type: 'string' },
    sizeBytes: { type: 'number', minimum: 0 },
    anchored: { type: 'boolean' },
    anchoredLength: { type: 'number', minimum: 0 },
    // NB: pending/rejected are reserved for the Phase-2 operator-authed feed
    // (pending-seeds.json); the v1 catalogue projector only emits
    // accepted/anchored/unseeded. See mappers.pinRegistryRow + INDEX-LAYER.md.
    seedState: { type: 'string', enum: ['pending', 'accepted', 'anchored', 'unseeded', 'rejected'] },
    relayPubkey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    verified: { type: 'boolean' }
  },
  required: ['appKey'],
  // Closed: the row schema is the last structural guarantee of what becomes
  // public. Every field the mapper emits is enumerated above.
  additionalProperties: false
}

export const RELAY_DIRECTORY_SCHEMA = {
  type: 'object',
  properties: {
    pubkey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    gatewayUrl: { type: 'string' },
    software: { type: 'string' },
    version: { type: ['string', 'null'] },
    region: { type: ['string', 'null'] },
    features: { type: 'array', items: { type: 'string' } },
    limitation: { type: 'object' },
    health: {
      type: 'object',
      properties: {
        anchoredCount: { type: 'number' },
        totalCount: { type: 'number' },
        anchorRatio: { type: 'number' },
        lastSeen: { type: 'number' }
      }
    },
    capacity: { type: 'object' },
    reputation: { type: 'object' },
    // doc.signature copied verbatim (convenience); re-verification uses `doc`.
    capabilitySig: { type: ['object', 'null'] },
    // The full signed capability doc, verbatim — clients run
    // verifyCapabilityDoc(doc) on this (it has the original field set +
    // `signature`), then trust the derived view above.
    doc: { type: ['object', 'null'] }
  },
  required: ['pubkey', 'gatewayUrl'],
  additionalProperties: false
}

export const APP_MANIFEST_SCHEMA = {
  type: 'object',
  properties: {
    appId: { type: 'string' },
    name: { type: 'string' },
    driveKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    link: { type: 'string' },
    type: { type: 'string', enum: ['standalone', 'hypersite'] },
    catalogType: { type: ['string', 'null'] },
    manifestHash: { type: 'string' },
    author: { type: ['string', 'null'] },
    version: { type: ['string', 'null'] },
    icon: { type: ['string', 'null'] },
    categories: { type: 'array', items: { type: 'string' } },
    publisherPubkey: { type: ['string', 'null'] },
    publishedAt: { type: ['number', 'null'] },
    sizeBytes: { type: ['number', 'null'] }
  },
  required: ['appId', 'name'],
  // installable (driveKey) and/or launchable (link) — at least one.
  anyOf: [
    { required: ['driveKey'] },
    { required: ['link'] }
  ],
  // Closed: every field the mapper emits is enumerated above (last structural
  // guarantee of what becomes public).
  additionalProperties: false
}

export const VERIFICATION_SCHEMA = {
  type: 'object',
  properties: {
    subjectAppKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    verifierPubkey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
    verdict: { type: 'string', enum: ['agree', 'diverge', 'anchored', 'unanchored'] },
    method: { type: 'string', enum: ['capability-divergence', 'anchor-proof', 'catalog-divergence'] },
    anchorProofSig: { type: ['string', 'null'] },
    attestedAt: { type: ['number', 'null'] }
  },
  required: ['subjectAppKey', 'verifierPubkey', 'verdict'],
  additionalProperties: false
}

export const SCHEMAS = {
  'pin-registry': PIN_REGISTRY_SCHEMA,
  'relay-directory': RELAY_DIRECTORY_SCHEMA,
  'app-manifest': APP_MANIFEST_SCHEMA,
  verification: VERIFICATION_SCHEMA
}

// One Ajv instance compiling all four validators. Used to reject malformed
// rows before they hit the (append-only, write-amplifying) room.
const ajv = new Ajv({ allErrors: true, strict: false })
addFormats(ajv)
const validators = Object.fromEntries(
  Object.entries(SCHEMAS).map(([name, schema]) => [name, ajv.compile(schema)])
)

export function validateRow (schemaName, row) {
  const validate = validators[schemaName]
  if (!validate) return { valid: false, errors: ['unknown schema: ' + schemaName] }
  const valid = validate(row)
  return { valid, errors: valid ? [] : (validate.errors || []).map(e => `${e.instancePath || '/'} ${e.message}`) }
}
