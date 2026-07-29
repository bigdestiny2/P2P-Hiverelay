import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import test from 'brittle'
import {
  ADVERTISED_OPERATION_BITS as REGISTRY_ADVERTISED_OPERATION_BITS,
  ADVERTISED_OPERATION_PROFILE_ROWS as REGISTRY_ADVERTISED_OPERATION_PROFILE_ROWS,
  DISPATCH_LIMITS as REGISTRY_DISPATCH_LIMITS,
  FAMILY as REGISTRY_FAMILY,
  FAMILY_ROUTES as REGISTRY_FAMILY_ROUTES,
  OUTER_CLASS as REGISTRY_OUTER_CLASS,
  PROTOCOL as REGISTRY_PROTOCOL,
  RESERVED_OPERATION_BITS as REGISTRY_RESERVED_OPERATION_BITS,
  RESERVED_OPERATION_PAIRS as REGISTRY_RESERVED_OPERATION_PAIRS,
  SCHEMA_NAMES_BY_CATEGORY,
  STREAM_WIRE_CLASS as REGISTRY_STREAM_WIRE_CLASS,
  TRANSPORT_ID as REGISTRY_TRANSPORT_ID,
  TRANSPORT_SUPPORT as REGISTRY_TRANSPORT_SUPPORT
} from '../registry.js'
import { blake2b256 } from '../hashes.js'
import { SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY } from '../schema-catalog-runtime-authority.js'
import {
  ADVERTISED_OPERATION_BITS,
  ADVERTISED_OPERATION_PROFILE_ROWS,
  DISPATCH_LIMITS,
  FAMILY,
  FAMILY_ROUTES,
  OUTER_CLASS,
  PROTOCOL,
  RESERVED_OPERATION_BITS,
  RESERVED_OPERATION_PAIRS,
  STREAM_WIRE_CLASS,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT,
  WIRE_RUNTIME_AUTHORITY,
  WIRE_RUNTIME_AUTHORITY_STATUS,
  assertAdvertisedOperation,
  assertWireAuthorityReady
} from '../wire-runtime-authority.js'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
test('frozen generated WIRE runtime authority remains exact, closed, and independently release ready', async t => {
  const metadata = JSON.parse(await fs.readFile(path.join(
    packageRoot, 'hiverelay-blind-wire-authority-v1.json'), 'utf8'))
  t.alike(WIRE_RUNTIME_AUTHORITY, metadata)
  t.is(assertWireAuthorityReady(), WIRE_RUNTIME_AUTHORITY_STATUS)
  t.is(WIRE_RUNTIME_AUTHORITY_STATUS.releaseReady, true)
  t.alike(WIRE_RUNTIME_AUTHORITY_STATUS.releaseBlockers, [])
  t.is(WIRE_RUNTIME_AUTHORITY_STATUS.specHash, metadata.specHash)
  t.is(WIRE_RUNTIME_AUTHORITY_STATUS.abiHash, metadata.abiHash)
  t.is(WIRE_RUNTIME_AUTHORITY_STATUS.vectorSetHash, metadata.vectorSetHash)
  t.is(ADVERTISED_OPERATION_BITS, REGISTRY_ADVERTISED_OPERATION_BITS)
  t.is(RESERVED_OPERATION_BITS, REGISTRY_RESERVED_OPERATION_BITS)
  t.alike(ADVERTISED_OPERATION_PROFILE_ROWS, REGISTRY_ADVERTISED_OPERATION_PROFILE_ROWS)
  t.alike(RESERVED_OPERATION_PAIRS, REGISTRY_RESERVED_OPERATION_PAIRS)
  t.is(assertAdvertisedOperation(REGISTRY_FAMILY.CELL, 2).operationId, 2)
  t.exception(() => assertAdvertisedOperation(REGISTRY_FAMILY.CORE, 3), /reserved by the active release profile/)
  t.exception(() => assertAdvertisedOperation(REGISTRY_FAMILY.FORWARD, 1), /reserved by the active release profile/)

  for (const [runtime, registry] of [
    [PROTOCOL, REGISTRY_PROTOCOL],
    [FAMILY, REGISTRY_FAMILY],
    [FAMILY_ROUTES, REGISTRY_FAMILY_ROUTES],
    [TRANSPORT_ID, REGISTRY_TRANSPORT_ID],
    [TRANSPORT_SUPPORT, REGISTRY_TRANSPORT_SUPPORT],
    [OUTER_CLASS, REGISTRY_OUTER_CLASS],
    [STREAM_WIRE_CLASS, REGISTRY_STREAM_WIRE_CLASS],
    [DISPATCH_LIMITS, REGISTRY_DISPATCH_LIMITS]
  ]) {
    t.alike(runtime, registry)
    t.ok(Object.isFrozen(runtime))
  }

  const source = await fs.readFile(path.join(packageRoot, 'wire-runtime-authority.js'), 'utf8')
  t.absent(source.match(/^\s*import\s/m), 'runtime authority has no transitive module imports')
  for (const forbidden of [
    'Peerit', 'OutboxLog', 'CLIENT_EXAMPLE', 'INTERNAL_STORE',
    'BlindStoreManifestV1', 'BackupManifest', 'moderation', 'namespace'
  ]) t.absent(source.includes(forbidden), `${forbidden} is absent from the WIRE-only runtime projection`)
})

test('schema catalog runtime commitment is exact and vocabulary-free', async t => {
  for (const [category, names] of Object.entries(SCHEMA_NAMES_BY_CATEGORY)) {
    t.alike(SCHEMA_CATALOG_NAME_HASHES_BY_CATEGORY[category], names.map(name =>
      b4a.toString(blake2b256(b4a.from(name, 'ascii')), 'hex')))
  }
  const source = await fs.readFile(path.join(packageRoot, 'schema-catalog-runtime-authority.js'), 'utf8')
  t.absent(source.match(/^\s*import\s/m), 'schema commitment authority is import-free')
  for (const forbidden of [
    'Peerit', 'OutboxLog', 'CLIENT_EXAMPLE', 'INTERNAL_STORE',
    'BlindStoreManifestV1', 'BlindBackupManifestV1', 'moderation', 'namespace'
  ]) t.absent(source.includes(forbidden), `${forbidden} is absent from the opaque catalog commitment`)
})
