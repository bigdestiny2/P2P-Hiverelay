import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import {
  blake2b256,
  decodeVectorManifest,
  hashAbi
} from '@hiverelay/blind-protocol'
import {
  PRIVATE_IPC_STATUS,
  PRIVATE_IPC_SCHEMAS,
  decodePrivateIpcRegistry,
  encodePrivateIpcRegistry,
  hashPrivateIpcRegistry,
  hashPrivateIpcVectorManifest,
  privateIpcRegistryValue,
  verifyPrivateIpcRegistry
} from '../index.js'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repositoryRoot = path.resolve(packageRoot, '../..')

test('private IPC registry and vector artifacts are byte-reproducible', async t => {
  const wireAbi = await fs.readFile(path.join(repositoryRoot, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc'))
  const registry = await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.cenc'))
  const registryAlias = await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.draft.cenc'))
  const vectors = await fs.readFile(path.join(packageRoot, 'vector-manifest-v1.cenc'))
  const vectorAlias = await fs.readFile(path.join(packageRoot, 'vectors/draft/vector-manifest-v1.draft.cenc'))
  const hashes = JSON.parse(await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-authority-v1.json'), 'utf8'))
  t.ok(b4a.equals(encodePrivateIpcRegistry(wireAbi), registry))
  t.ok(b4a.equals(registryAlias, registry))
  t.ok(b4a.equals(vectorAlias, vectors))
  t.is(verifyPrivateIpcRegistry(registry, wireAbi).schemas.length, 7)
  t.is(b4a.toString(hashPrivateIpcRegistry(registry), 'hex'), hashes.privateIpcFormatHash)
  t.is(b4a.toString(hashPrivateIpcVectorManifest(vectors), 'hex'), hashes.privateIpcVectorSetHash)
  t.is(b4a.toString(hashAbi(wireAbi), 'hex'), hashes.importedWireAbiHash)
  t.is(hashes.vectorCount, 79)
  t.is(PRIVATE_IPC_STATUS.releaseReady, true)

  const entries = decodeVectorManifest(vectors)
  t.is(entries.length, 79)
  for (const entry of entries) {
    const bytes = await fs.readFile(path.join(packageRoot, 'vectors', ...entry.path.split('/')))
    t.is(BigInt(bytes.byteLength), entry.vectorLength, `${entry.path} length`)
    t.ok(b4a.equals(blake2b256(bytes), entry.vectorHash), `${entry.path} hash`)
  }
})

test('private IPC registry imports and changes with the exact public WIRE ABI hash', async t => {
  const wireAbi = await fs.readFile(path.join(repositoryRoot, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc'))
  const value = privateIpcRegistryValue(wireAbi)
  t.alike(PRIVATE_IPC_SCHEMAS.map(schema => schema.schemaName), [
    'LocalDispatchV1',
    'LocalUnaryResponseV1',
    'LocalStreamOpenV1',
    'LocalStreamFrameV1',
    'LocalAuthenticatedChannelV1',
    'LocalStreamAttachContextV1',
    'LocalStreamControlV1'
  ])
  t.alike(value.importedWireBindings.map(table => table.name), [
    'FAMILY',
    'TRANSPORT_ID',
    'TRANSPORT_SUPPORT',
    'OUTER_CLASS',
    'STREAM_WIRE_CLASS'
  ])
  const local = Object.fromEntries(value.localBindings.map(table => [table.name, table.entries]))
  t.alike(local.streamOpenKindByCombination.map(entry => entry.value), [1, 1, 2, 3, 4])
  t.alike(local.streamModeByCombination.map(entry => entry.value), [1, 2, 3, 4, 5])
  t.alike(local.streamClassMinimumByCombination.map(entry => entry.value), [1, 1, 1, 0, 1])
  t.alike(local.streamClassMaximumByCombination.map(entry => entry.value), [3, 3, 3, 0, 3])
  t.alike(local.streamContextKindByCombination.map(entry => entry.value), [1, 1, 2, 2, 2])
  t.alike(local.streamAdjacentPolicyByCombination.map(entry => entry.value), [1, 1, 2, 3, 3])
  const changed = b4a.from(wireAbi)
  changed[changed.length - 1] ^= 1
  t.not(b4a.toString(privateIpcRegistryValue(changed).wireAbiHash, 'hex'), b4a.toString(value.wireAbiHash, 'hex'))
  t.not(b4a.toString(encodePrivateIpcRegistry(changed), 'hex'), b4a.toString(encodePrivateIpcRegistry(wireAbi), 'hex'))
})

test('private IPC registry decoder rejects truncation, trailing bytes, noncanonical bytes and substitution', async t => {
  const wireAbi = await fs.readFile(path.join(repositoryRoot, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc'))
  const registry = await fs.readFile(path.join(packageRoot, 'hiverelay-blind-private-ipc-v1.cenc'))
  t.is(decodePrivateIpcRegistry(registry).magic, 'hiverelay-blind-private-ipc-v1')
  t.exception(() => decodePrivateIpcRegistry(registry.subarray(0, registry.byteLength - 1)))
  t.exception(() => decodePrivateIpcRegistry(b4a.concat([registry, b4a.from([0])])))
  const changed = b4a.from(registry)
  changed[changed.byteLength - 1] ^= 1
  t.exception(() => verifyPrivateIpcRegistry(changed, wireAbi))
  const wrongWire = b4a.from(wireAbi)
  wrongWire[wrongWire.byteLength - 1] ^= 1
  t.exception(() => verifyPrivateIpcRegistry(registry, wrongWire))
})
