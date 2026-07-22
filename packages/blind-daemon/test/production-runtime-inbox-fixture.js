import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ENDPOINT_ROLE,
  FAMILY,
  INBOX_APPEND_AUTH_MODE,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blake2b256,
  blindServiceDescriptorV1,
  encodeCanonical,
  hashStoreFormat,
  inboxAppendRequestCommitment,
  inboxCreateCommitment,
  inboxManageRequestCommitment,
  inboxPhysicalTopic,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
  PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS
} from '../production-runtime.js'
import { daemonOperationProfile, deriveAdmissionCost } from '../operation-catalog.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'
import { createBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const INBOX_PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

export const INBOX_TEST_SHAPE = Object.freeze({
  frameClassBits: 1,
  retentionClass: 2,
  createLeaseClass: 2,
  renewLeaseClass: 4,
  appendFrameClass: 1,
  pageLimit: 1,
  watchMaxWaitMillis: 1000
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

function inboxResourceCostRows () {
  const shape = INBOX_TEST_SHAPE
  const largestFrameBytes = INBOX_FRAME_CLASS[shape.frameClassBits]
  const predictedReadBytes = 4096 + shape.pageLimit * (41 + largestFrameBytes)
  const storedShape = Object.freeze({
    inboxRetentionClass: shape.retentionClass,
    inboxFrameClassBits: shape.frameClassBits
  })
  const costs = [
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.CREATE), {
      retentionClass: shape.retentionClass,
      frameClassBits: shape.frameClassBits,
      leaseClass: shape.createLeaseClass
    }),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.RENEW), {
      leaseClass: shape.renewLeaseClass
    }, storedShape),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.APPEND), {
      frameClass: shape.appendFrameClass
    }, storedShape),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.READ), {}, {
      canonicalResultBytes: predictedReadBytes
    }),
    deriveAdmissionCost(daemonOperationProfile(FAMILY.INBOX, OPERATION.INBOX.WATCH), {
      maxWaitMillis: shape.watchMaxWaitMillis
    }, { canonicalResultBytes: predictedReadBytes })
  ]
  return costs.map((cost, index) => Object.freeze({
    familyId: FAMILY.INBOX,
    operationId: index === 0
      ? OPERATION.INBOX.CREATE
      : index === 1
        ? OPERATION.INBOX.RENEW
        : index === 2
          ? OPERATION.INBOX.APPEND
          : index === 3
            ? OPERATION.INBOX.READ
            : OPERATION.INBOX.WATCH,
    resourceClass: cost.resourceClass,
    leaseClass: cost.leaseClass,
    costUnits: 10n
  }))
}

export async function runtimeInboxFixture (options = {}) {
  const directory = await createBlindBoundaryScratch('brti-')
  await fs.chmod(directory, 0o700)
  const storeRoot = path.join(directory, 'store')
  const inboxStoreRoot = path.join(directory, 'inbox-store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  await fs.mkdir(storeRoot, { mode: 0o700 })
  await fs.mkdir(inboxStoreRoot, { mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { mode: 0o700 })

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    roleBits: INBOX_PUBLIC_ROLE_BITS,
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  parameters.resourceCosts = [...parameters.resourceCosts, ...inboxResourceCostRows()]
    .sort((left, right) => {
      for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
        if (left[field] !== right[field]) return left[field] - right[field]
      }
      return 0
    })
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x62),
    enabledOperationBits: options.inboxRuntime === false
      ? PRODUCTION_DESCRIBE_AND_CELL_OPERATION_BITS
      : PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
    issuedEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = INBOX_PUBLIC_ROLE_BITS
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
  const storeManifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalDescriptor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(storeManifestKeyFile, b4a.alloc(32, 0x71)),
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
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
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
    inboxStoreRoot,
    inboxCursorKeyFile
  })
}

export function inboxKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return Object.freeze({ publicKey, secretKey })
}

function ed25519 (secretKey, message) {
  const output = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(output, message, secretKey)
  return output
}

export function inboxAdmission (parameterHash, byte) {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.from(parameterHash),
    token: b4a.alloc(32, byte)
  }
}

export function inboxCreateFixture (relayPublicKey, parameterHash, allocationEpoch, overrides = {}) {
  const shape = INBOX_TEST_SHAPE
  const create = inboxKeyPair()
  const append = inboxKeyPair()
  const renew = inboxKeyPair()
  const close = inboxKeyPair()
  const physicalTopic = inboxPhysicalTopic({ allocationEpoch, createPublicKey: create.publicKey })
  const request = {
    version: 1,
    allocationEpoch,
    physicalTopic,
    frameClassBits: shape.frameClassBits,
    appendAuthMode: INBOX_APPEND_AUTH_MODE.SIGNATURE_REQUIRED,
    appendPublicKey: append.publicKey,
    createPublicKey: create.publicKey,
    renewPublicKey: renew.publicKey,
    closePublicKey: close.publicKey,
    retentionClass: shape.retentionClass,
    leaseClass: shape.createLeaseClass,
    clientNonce: b4a.alloc(32, overrides.nonceByte == null ? 0xb1 : overrides.nonceByte),
    createSignature: b4a.alloc(64),
    admission: inboxAdmission(parameterHash, overrides.spendByte == null ? 0xb2 : overrides.spendByte)
  }
  request.createSignature = ed25519(create.secretKey,
    inboxCreateCommitment({ ...request, relayPublicKey }))
  return Object.freeze({ request, create, append, renew, close })
}

export function inboxAppendFixture (created, relayPublicKey, parameterHash, byte, overrides = {}) {
  const frameClass = INBOX_TEST_SHAPE.appendFrameClass
  const frame = b4a.alloc(INBOX_FRAME_CLASS[frameClass], byte)
  const frameHash = blake2b256(frame)
  const clientNonce = b4a.alloc(32, byte ^ 0x55)
  return {
    version: 1,
    physicalTopic: created.request.physicalTopic,
    frameClass,
    frameHash,
    clientNonce,
    appendSignature: ed25519(created.append.secretKey, inboxAppendRequestCommitment({
      relayPublicKey,
      physicalTopic: created.request.physicalTopic,
      frameClass,
      frameHash,
      clientNonce
    })),
    admission: inboxAdmission(parameterHash, overrides.spendByte == null ? byte : overrides.spendByte),
    frame
  }
}

export function inboxReadFixture (created, parameterHash, overrides = {}) {
  return {
    version: 1,
    physicalTopic: created.request.physicalTopic,
    cursor: b4a.alloc(0),
    limit: INBOX_TEST_SHAPE.pageLimit,
    clientNonce: b4a.alloc(32, overrides.nonceByte == null ? 0xf1 : overrides.nonceByte),
    admission: overrides.charged === true
      ? inboxAdmission(parameterHash, overrides.spendByte == null ? 0xf2 : overrides.spendByte)
      : null
  }
}

export function inboxWatchFixture (created, parameterHash, overrides = {}) {
  return {
    version: 1,
    physicalTopic: created.request.physicalTopic,
    afterRevision: overrides.afterRevision == null ? 0n : overrides.afterRevision,
    limit: INBOX_TEST_SHAPE.pageLimit,
    maxWaitMillis: overrides.maxWaitMillis == null
      ? INBOX_TEST_SHAPE.watchMaxWaitMillis
      : overrides.maxWaitMillis,
    clientNonce: b4a.alloc(32, overrides.nonceByte == null ? 0xf3 : overrides.nonceByte),
    admission: inboxAdmission(parameterHash, overrides.spendByte == null ? 0xf4 : overrides.spendByte)
  }
}

export function inboxRenewFixture (created, receipt, relayPublicKey, parameterHash, spendByte = 0xd1) {
  const request = {
    version: 1,
    operation: 1,
    physicalTopic: created.request.physicalTopic,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    leaseClass: INBOX_TEST_SHAPE.renewLeaseClass,
    clientNonce: b4a.alloc(32, 0xd2),
    signature: b4a.alloc(64),
    admission: inboxAdmission(parameterHash, spendByte)
  }
  request.signature = ed25519(created.renew.secretKey, inboxManageRequestCommitment({
    operation: 'inbox-renew',
    relayPublicKey,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: request.leaseClass,
    clientNonce: request.clientNonce
  }))
  return request
}

export function inboxCloseFixture (created, receipt, relayPublicKey) {
  const request = {
    version: 1,
    operation: 2,
    physicalTopic: created.request.physicalTopic,
    expectedRevision: receipt.stateRevision,
    expectedLeaseEpoch: receipt.leaseEpoch,
    leaseClass: 0,
    clientNonce: b4a.alloc(32, 0xe1),
    signature: b4a.alloc(64),
    admission: null
  }
  request.signature = ed25519(created.close.secretKey, inboxManageRequestCommitment({
    operation: 'inbox-close',
    relayPublicKey,
    physicalTopic: request.physicalTopic,
    expectedRevision: request.expectedRevision,
    expectedLeaseEpoch: request.expectedLeaseEpoch,
    requestedLeaseClass: 0,
    clientNonce: request.clientNonce
  }))
  return request
}
