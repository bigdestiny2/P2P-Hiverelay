import * as clientInternalSchemas from './client-internal-schemas.js'
import * as durabilitySchemas from './durability-schemas.js'
import * as evidenceSchemas from './evidence-schemas.js'
import * as resultBindingSchemas from './result-binding.js'
import * as wireSchemas from './schemas.js'
import { decodeDispatchFrame, encodeDispatchFrame } from './dispatch.js'
import { decodeOuterEnvelope, encodeOuterEnvelope } from './outer-envelope.js'
import {
  ABI_STATUS,
  SCHEMA_CATEGORY,
  schemaCategory
} from './registry.js'

const sources = Object.freeze({
  ...wireSchemas,
  ...resultBindingSchemas,
  ...durabilitySchemas,
  ...evidenceSchemas,
  ...clientInternalSchemas,
  blindDispatchFrameV1: Object.freeze({ encode: encodeDispatchFrame, decode: decodeDispatchFrame }),
  blindOuterEnvelopeV1: Object.freeze({ encode: encodeOuterEnvelope, decode: decodeOuterEnvelope })
})

function exportName (schemaName) {
  return schemaName[0].toLowerCase() + schemaName.slice(1)
}

const codecs = {}
const missingCodecNames = []
const invalidCodecNames = []

for (const schemaName of ABI_STATUS.protocolOwnedRequiredSchemaNames) {
  const codec = sources[exportName(schemaName)]
  if (codec == null) {
    missingCodecNames.push(schemaName)
    continue
  }
  const contextualFactory = schemaName === 'CellBlobV1' && typeof codec === 'function'
  const customFraming = (schemaName === 'BlindDispatchFrameV1' || schemaName === 'BlindOuterEnvelopeV1') &&
    typeof codec.encode === 'function' && typeof codec.decode === 'function'
  if (!contextualFactory && !customFraming && (typeof codec !== 'object' || typeof codec.preencode !== 'function' ||
      typeof codec.encode !== 'function' || typeof codec.decode !== 'function')) {
    invalidCodecNames.push(schemaName)
    continue
  }
  codecs[schemaName] = codec
}

export const EXECUTABLE_SCHEMA_CODECS = Object.freeze(codecs)

const wireRequiredCodecNames = ABI_STATUS.wireRequiredSchemaNames
const wireMissingCodecNames = wireRequiredCodecNames.filter(name => !Object.hasOwn(codecs, name))
const wireInvalidCodecNames = invalidCodecNames.filter(name => wireRequiredCodecNames.includes(name))
const wireCodecNames = Object.keys(codecs).filter(name => schemaCategory(name) === SCHEMA_CATEGORY.WIRE)

export const WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS = Object.freeze({
  requiredCodecCount: wireRequiredCodecNames.length,
  executableCodecCount: wireCodecNames.length,
  missingCodecNames: Object.freeze(wireMissingCodecNames),
  invalidCodecNames: Object.freeze(wireInvalidCodecNames),
  nonWireLeakNames: Object.freeze(wireCodecNames.filter(name =>
    !wireRequiredCodecNames.includes(name))),
  complete: wireMissingCodecNames.length === 0 && wireInvalidCodecNames.length === 0 &&
    wireCodecNames.length === wireRequiredCodecNames.length
})

export const EXECUTABLE_SCHEMA_CODEC_STATUS = Object.freeze({
  requiredCodecCount: ABI_STATUS.protocolOwnedRequiredSchemaNames.length,
  executableCodecCount: Object.keys(codecs).length,
  missingCodecNames: Object.freeze(missingCodecNames),
  invalidCodecNames: Object.freeze(invalidCodecNames),
  privateIpcCodecNames: Object.freeze(ABI_STATUS.externallyOwnedSchemaNames),
  privateIpcLeakNames: Object.freeze(Object.keys(codecs).filter(name => schemaCategory(name) === SCHEMA_CATEGORY.PRIVATE_IPC)),
  complete: missingCodecNames.length === 0 && invalidCodecNames.length === 0 &&
    Object.keys(codecs).length === ABI_STATUS.protocolOwnedRequiredSchemaNames.length
})

if (!WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS.complete ||
    WIRE_EXECUTABLE_SCHEMA_CODEC_STATUS.nonWireLeakNames.length !== 0 ||
    EXECUTABLE_SCHEMA_CODEC_STATUS.privateIpcLeakNames.length !== 0) {
  throw new Error(`executable schema codec catalog is incomplete or crosses the PRIVATE_IPC ownership boundary: missing=${missingCodecNames.join(',')} invalid=${invalidCodecNames.join(',')} private=${EXECUTABLE_SCHEMA_CODEC_STATUS.privateIpcLeakNames.join(',')}`)
}
