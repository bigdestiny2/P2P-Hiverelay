import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { forwardHttpsSessionIdV1 } from '@hiverelay/blind-protocol'
import {
  LOCAL_FORWARD_HTTPS_DIRECTION_V3,
  PRIVATE_IPC_V3_SCHEMA,
  decodeLocalForwardHttpsExporterBindingV3,
  decodeLocalForwardHttpsParentCapabilityV3,
  decodeLocalForwardHttpsTurnV3,
  decodePrivateIpcV3Registry,
  encodeLocalForwardHttpsExporterBindingV3,
  encodeLocalForwardHttpsTurnV3
} from '../private-ipc-v3-contract.js'
import {
  PRIVATE_IPC_LEGACY_STATUS_MIRROR_NOTICE,
  PRIVATE_IPC_V3_STATUS,
  assertPrivateIpcV3Status
} from '../private-ipc-v3-status.js'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = relative => fs.readFileSync(path.join(root, relative))

test('private IPC v3 imports WIRE v2 and appends IDs 13 through 15', t => {
  const registry = decodePrivateIpcV3Registry(read('hiverelay-blind-private-ipc-v3.cenc'))
  t.alike(PRIVATE_IPC_V3_SCHEMA, {
    LocalForwardHttpsExporterBindingV3: 13,
    LocalForwardHttpsParentCapabilityV3: 14,
    LocalForwardHttpsTurnV3: 15
  })
  t.is(registry.baseSchemaCount, 12)
  t.alike(registry.additionalSchemas.map(schema => schema.schemaId), [13, 14, 15])
  t.is(b4a.toString(registry.importedWireV2AbiHash, 'hex'), PRIVATE_IPC_V3_STATUS.importedWireV2AbiHash)
  t.is(registry.forwardReadinessOperationBits, 0)
  t.ok(assertPrivateIpcV3Status(JSON.parse(read('hiverelay-blind-private-ipc-authority-v3.json'))))
  t.is(PRIVATE_IPC_V3_STATUS.releaseReady, false)
  t.is(PRIVATE_IPC_LEGACY_STATUS_MIRROR_NOTICE.authoritative, false)
  t.is(PRIVATE_IPC_LEGACY_STATUS_MIRROR_NOTICE.authoritativeV1ImportedWireAbiHash, '199ba15d94d4d112cfac520a67055ce15ec870f0f6f7bd9adaaf47d552334567')
})

test('private IPC v3 carries only exporter binding hash and exact catalog target', t => {
  const bytes = read('vectors-v3/positive/exporter-binding-v3.bin')
  const value = decodeLocalForwardHttpsExporterBindingV3(bytes)
  t.is(bytes.byteLength, 336)
  t.alike(encodeLocalForwardHttpsExporterBindingV3(value), bytes)
  t.ok(value.targetCatalogEntryId)
  t.absent(value.tlsExporter)
  t.exception(() => encodeLocalForwardHttpsExporterBindingV3({
    ...value,
    tlsExporter: b4a.alloc(32, 99)
  }), /tlsExporter is forbidden/)
  t.exception(() => encodeLocalForwardHttpsExporterBindingV3({
    ...value,
    targetRelayPublicKey: value.sourceRelayPublicKey
  }), /source and target relay keys must differ/)
  t.exception(() => encodeLocalForwardHttpsExporterBindingV3({
    ...value,
    host: 'arbitrary.invalid'
  }), /host is forbidden/)
})

test('private IPC v3 capability and turns bind exact WIRE v2 session and sequence', t => {
  const capabilityBytes = read('vectors-v3/positive/parent-capability-v3.bin')
  const capability = decodeLocalForwardHttpsParentCapabilityV3(capabilityBytes)
  t.is(capabilityBytes.byteLength, 427)
  t.alike(capability.sessionId, forwardHttpsSessionIdV1(capability.parentCapability))

  const requestBytes = read('vectors-v3/positive/request-turn-v3.bin')
  const request = decodeLocalForwardHttpsTurnV3(requestBytes)
  t.is(requestBytes.byteLength, 65_584)
  t.is(request.direction, LOCAL_FORWARD_HTTPS_DIRECTION_V3.REQUEST)

  const result = decodeLocalForwardHttpsTurnV3(read('vectors-v3/positive/result-turn-v3.bin'))
  t.is(result.direction, LOCAL_FORWARD_HTTPS_DIRECTION_V3.RESULT)
  t.alike(result.sessionId, request.sessionId)
  t.exception(() => encodeLocalForwardHttpsTurnV3({
    ...request,
    sequence: request.sequence + 1n
  }), /sessionId or sequence does not match body/)
  t.exception(() => decodeLocalForwardHttpsTurnV3(read('vectors-v3/negative/request-turn-sequence-mismatch.bin')), /sessionId or sequence does not match body/)
})
