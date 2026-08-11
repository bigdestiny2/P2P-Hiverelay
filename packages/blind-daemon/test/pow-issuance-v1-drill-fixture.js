// Shared pow-issuance-v1 drill fixture: relay keypair, OPEN-conformance
// AdmissionParametersV1 + seq-0/seq-1 descriptor chain signed for it, and the
// complete daemon environment. Used by the full-stack drill and the CLI wiring
// test. LOCAL only; never touches the fleet.
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ADMISSION_CONFORMANCE_CLASS,
  ENDPOINT_ROLE,
  FAMILY,
  INBOX_FRAME_CLASS,
  OPERATION,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { daemonOperationProfile, deriveAdmissionCost } from '../operation-catalog.js'
import {
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS
} from '../production-runtime.js'
import {
  POW_ISSUANCE_V1_SCHEME_ID,
  powIssuanceV1IssuerKeyCommitment
} from '../pow-issuance-v1/token-codec.js'
import {
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'

export const POW_DRILL_SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
export const POW_DRILL_PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER

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

function costRow (familyId, operationId, request, authenticatedState) {
  const cost = deriveAdmissionCost(daemonOperationProfile(familyId, operationId), request, authenticatedState)
  return Object.freeze({
    familyId,
    operationId,
    resourceClass: cost.resourceClass,
    leaseClass: cost.leaseClass,
    costUnits: 10n
  })
}

function drillResourceCosts () {
  const rows = []
  for (const sizeClass of [1, 2]) {
    for (const leaseClass of [1, 2, 3, 4]) {
      rows.push(costRow(FAMILY.CELL, OPERATION.CELL.PUT, { sizeClass, leaseClass }))
    }
  }
  const storedShape = Object.freeze({ inboxRetentionClass: 2, inboxFrameClassBits: 1 })
  const predictedReadBytes = 4096 + 1 * (41 + INBOX_FRAME_CLASS[1])
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.CREATE,
    { retentionClass: 2, frameClassBits: 1, leaseClass: 2 }))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.RENEW, { leaseClass: 4 }, storedShape))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.APPEND, { frameClass: 1 }, storedShape))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.READ, {}, { canonicalResultBytes: predictedReadBytes }))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.WATCH,
    { maxWaitMillis: 1000 }, { canonicalResultBytes: predictedReadBytes }))
  return rows.sort((left, right) => {
    for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
      if (left[field] !== right[field]) return left[field] - right[field]
    }
    return 0
  })
}

export async function powIssuanceV1DrillFixture ({ issuerPort, issuerKey, directory }) {
  const storeRoot = path.join(directory, 'store')
  const inboxStoreRoot = path.join(directory, 'inbox-store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  await fs.mkdir(storeRoot, { mode: 0o700 })
  await fs.mkdir(inboxStoreRoot, { mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { mode: 0o700 })

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / POW_DRILL_SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    profileId: 8,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    verifierKey: b4a.alloc(0),
    resourceCosts: drillResourceCosts(),
    tokenMaxBytes: 512,
    issuanceUrl: b4a.from(`https://127.0.0.1:${issuerPort}/`, 'utf8'),
    issuerRelayKey: powIssuanceV1IssuerKeyCommitment(issuerKey),
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const descriptor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x62),
    enabledOperationBits: PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
    issuedEpoch: currentEpoch - 1,
    expiresEpoch: currentEpoch + 3,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = POW_DRILL_PUBLIC_ROLE_BITS
  descriptor.admissionProfiles = [{
    profileId: 8,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    parameterUrl: null,
    parameterHash: b4a.from(parameterHash)
  }]
  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
    import.meta.url
  ))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  descriptor.build.storeFormatHash = b4a.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const canonicalGenesisDescriptor = signCanonical(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  // The V2 write path requires a nonzero descriptor sequence (server.js:1072):
  // activate a seq-1 successor chained to the genesis, exactly like the deployed
  // +1 hash chain. Both files are installed; the launch floor pins the successor.
  const activeDescriptor = decodeCanonical(blindServiceDescriptorV1, canonicalGenesisDescriptor, { copyBytes: true })
  activeDescriptor.descriptorSequence = 1n
  activeDescriptor.previousDescriptorHash = serviceDescriptorHash(canonicalGenesisDescriptor)
  activeDescriptor.issuedEpoch = currentEpoch
  activeDescriptor.expiresEpoch = currentEpoch + 4
  activeDescriptor.descriptorNonce = b4a.alloc(32, 0x64)
  const canonicalDescriptor = signCanonical(blindServiceDescriptorV1, activeDescriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const descriptorFile = path.join(directory, 'descriptor.bin')
  const successorDescriptorFile = path.join(directory, 'descriptor-successor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const storeManifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalGenesisDescriptor),
    privateFile(successorDescriptorFile, canonicalDescriptor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(storeManifestKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72)),
    privateFile(inboxCursorKeyFile, b4a.alloc(32, 0x73))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '81'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(uid + 1),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: `${descriptorFile},${successorDescriptorFile}`,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: privateIpcReplayRoot,
    HIVERELAY_BLIND_INBOX_STORE_ROOT: inboxStoreRoot,
    HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE: inboxCursorKeyFile,
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: String(activeDescriptor.descriptorSequence),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(serviceDescriptorHash(canonicalDescriptor), 'hex')
  }
  return Object.freeze({
    environment,
    relayPublicKey,
    parameterHash,
    currentEpoch,
    descriptor: activeDescriptor,
    unarySocketPath: environment.HIVERELAY_BLIND_UNARY_SOCKET,
    streamSocketPath: environment.HIVERELAY_BLIND_STREAM_SOCKET,
    launchTopologyHash: b4a.from('81'.repeat(32), 'hex'),
    transportProfileHash: b4a.from(activeDescriptor.endpoints[0].transportProfileHash)
  })
}
