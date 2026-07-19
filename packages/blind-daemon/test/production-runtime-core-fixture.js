import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  encodeCanonical,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS,
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS
} from '../production-runtime.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'
import { createBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const CORE_PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

export const CORE_TEST_SHAPE = Object.freeze({
  mirrorLeaseClass: 1,
  mirrorLength: 4n,
  extensionLength: 6n
})

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

async function privateFile (file, bytes) {
  await fs.writeFile(file, bytes, { mode: 0o600 })
  await fs.chmod(file, 0o600)
}

export async function runtimeCoreFixture (options = {}) {
  const directory = await createBlindBoundaryScratch('brtc-')
  await fs.chmod(directory, 0o700)
  const storeRoot = path.join(directory, 'store')
  const inboxStoreRoot = path.join(directory, 'inbox-store')
  const coreStoreRoot = path.join(directory, 'core-store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  await fs.mkdir(storeRoot, { mode: 0o700 })
  await fs.mkdir(inboxStoreRoot, { mode: 0o700 })
  await fs.mkdir(coreStoreRoot, { mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { mode: 0o700 })

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    roleBits: CORE_PUBLIC_ROLE_BITS,
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x63),
    enabledOperationBits: options.coreRuntime === false
      ? PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS
      : PRODUCTION_DESCRIBE_CELL_INBOX_CORE_OPERATION_BITS,
    issuedEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = CORE_PUBLIC_ROLE_BITS
  descriptor.admissionProfiles = [descriptor.admissionProfiles[0]]
  descriptor.admissionProfiles[0].profileId = parameters.profileId
  descriptor.admissionProfiles[0].schemeId = parameters.schemeId
  descriptor.admissionProfiles[0].conformanceClass = parameters.conformanceClass
  descriptor.admissionProfiles[0].roleBits = parameters.roleBits
  descriptor.admissionProfiles[0].parameterHash = b4a.from(parameterHash)
  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
    import.meta.url
  ))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 1
  descriptor.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  descriptor.build.storeFormatHash = b4a.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const canonicalDescriptor = signCanonical(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const descriptorFile = path.join(directory, 'descriptor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const partitionKeyFile = path.join(directory, 'partition-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalDescriptor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(partitionKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72)),
    privateFile(inboxCursorKeyFile, b4a.alloc(32, 0x73))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const edgeUid = uid === 0xffffffff ? uid - 1 : uid + 1
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '81'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(edgeUid),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: descriptorFile,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: privateIpcReplayRoot,
    HIVERELAY_BLIND_INBOX_STORE_ROOT: inboxStoreRoot,
    HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE: inboxCursorKeyFile,
    HIVERELAY_BLIND_CORE_STORE_ROOT: coreStoreRoot,
    HIVERELAY_BLIND_PARTITION_KEY_FILE: partitionKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: String(descriptor.descriptorSequence),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(serviceDescriptorHash(canonicalDescriptor), 'hex')
  }
  return Object.freeze({
    directory,
    environment,
    relayPublicKey,
    parameterHash,
    currentEpoch,
    coreStoreRoot
  })
}

export function coreAdmission (parameterHash, byte) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.from(parameterHash),
    token: b4a.alloc(32, byte)
  }
}

export function coreMirrorFixture (parameterHash, overrides = {}) {
  return {
    version: 1,
    corePublicKey: overrides.corePublicKey || b4a.alloc(32, 0x31),
    fork: overrides.fork == null ? 0n : overrides.fork,
    length: overrides.length == null ? CORE_TEST_SHAPE.mirrorLength : overrides.length,
    signedHeadHash: overrides.signedHeadHash || b4a.alloc(32, 0x41),
    leaseClass: overrides.leaseClass == null ? CORE_TEST_SHAPE.mirrorLeaseClass : overrides.leaseClass,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x51),
    admission: coreAdmission(parameterHash, overrides.spendByte == null ? 0xb2 : overrides.spendByte)
  }
}

export function coreProveFixture (mirror, parameterHash, overrides = {}) {
  return {
    version: 1,
    corePublicKey: b4a.from(mirror.corePublicKey),
    fork: mirror.fork,
    length: mirror.length,
    signedHeadHash: b4a.from(mirror.signedHeadHash),
    blockIndices: overrides.blockIndices || [0n, mirror.length - 1n],
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x61),
    admission: overrides.charged === true
      ? coreAdmission(parameterHash, overrides.spendByte == null ? 0xc1 : overrides.spendByte)
      : null
  }
}

export function coreOpenReplicationFixture (parameterHash, overrides = {}) {
  return {
    version: 1,
    wireProfileHash: overrides.wireProfileHash || b4a.alloc(32, 0x35),
    sessionClass: overrides.sessionClass == null ? 1 : overrides.sessionClass,
    controlChannelId: overrides.controlChannelId == null ? 17n : overrides.controlChannelId,
    parentChannelBinding: overrides.parentChannelBinding || b4a.alloc(32, 0x33),
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x62),
    admission: coreAdmission(parameterHash, overrides.spendByte == null ? 0xc2 : overrides.spendByte)
  }
}
