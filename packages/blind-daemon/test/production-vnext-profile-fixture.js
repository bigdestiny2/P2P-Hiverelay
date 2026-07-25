import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { createHash } from 'node:crypto'
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
  bindDurability,
  descriptorValue,
  parameterValue
} from './coordinator-fixtures.js'

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000
const PUBLIC_ROLE_BITS = ENDPOINT_ROLE.DESCRIPTOR_DISCOVERY |
  ENDPOINT_ROLE.STORAGE | ENDPOINT_ROLE.QUOTA_REDEEMER
export const VNEXT_PROFILE = 'LIMITED_PUBLIC_TEST_V1'
export const VNEXT_BASELINE_OPERATION_BITS = 0x0001ffff

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

// A real admission adapter script (the sealed adapter.js analogue) bound to the
// vNext profile and the launch topology. Loaded and resolved through the
// production VM bridge during the full assembly; only its exact bytes/digest
// are needed by the release gate.
export function vnextAdmissionScript (launchTopologyHashHex) {
  return `
({
  schema: 'hiverelay-admission-adapter-script-v1',
  createAdmissionAdapterResolver (context) {
    if (context.runtimeProfile !== '${VNEXT_PROFILE}' ||
        context.launchTopologyHash.$hiverelayType !== 'bytes' ||
        context.launchTopologyHash.hex !== '${launchTopologyHashHex}' ||
        context.endpointIds.length !== 1 || context.endpointIds[0] !== 1) {
      throw new Error('entrypoint launch binding mismatch')
    }
    const adapter = Object.freeze({
      prepare () { throw new Error('not exercised during startup') },
      preparePreflight () { throw new Error('not exercised during startup') },
      confirmAfterEof () { throw new Error('not exercised during startup') }
    })
    return () => adapter
  }
})
`
}

// Build a sealed node-scoped material fixture for the vNext public-test profile
// under /tmp (never in the repo). The /tmp root is realpath-resolved so the
// private socket/store paths stay inside the 100-byte portable bound and are
// not shadowed by the /tmp symlink on macOS. Returns the directory, the signed
// environment, the relay public key, the parameter hash and the descriptor
// chain hashes used for continuity assertions.
export async function vnextSealedFixture (options = {}) {
  const root = await fs.realpath(await fs.mkdtemp(path.join('/tmp', 'hr-vnext-')))
  await fs.chmod(root, 0o700)
  const storeRoot = path.join(root, 'store')
  const inboxStoreRoot = path.join(root, 'inbox-store')
  const coreStoreRoot = path.join(root, 'core-store')
  const privateIpcReplayRoot = path.join(root, 'private-ipc-replay')
  const forwardStoreRoot = path.join(root, 'forward-storage')
  for (const dir of [storeRoot, inboxStoreRoot, coreStoreRoot, privateIpcReplayRoot, forwardStoreRoot]) {
    await fs.mkdir(dir, { mode: 0o700 })
  }

  const relayPublicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    roleBits: PUBLIC_ROLE_BITS,
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const authorityBytes = await fs.readFile(new URL(
    '../../blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc', import.meta.url))
  const operationBits = options.operationBits == null ? VNEXT_BASELINE_OPERATION_BITS : options.operationBits
  const genesis = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x63),
    enabledOperationBits: operationBits,
    issuedEpoch: currentEpoch - 1,
    expiresEpoch: currentEpoch + 3,
    capacityBand: 0
  })
  genesis.endpoints = [genesis.endpoints[0]]
  genesis.endpoints[0].endpointId = 1
  genesis.endpoints[0].transportId = 1
  genesis.endpoints[0].roleBits = PUBLIC_ROLE_BITS
  genesis.admissionProfiles = [genesis.admissionProfiles[0]]
  genesis.admissionProfiles[0].profileId = parameters.profileId
  genesis.admissionProfiles[0].schemeId = parameters.schemeId
  genesis.admissionProfiles[0].conformanceClass = parameters.conformanceClass
  genesis.admissionProfiles[0].roleBits = parameters.roleBits
  genesis.admissionProfiles[0].parameterHash = b4a.from(parameterHash)
  genesis.durability.profileId = options.durabilityProfileId == null ? 1 : options.durabilityProfileId
  genesis.durability.storeFormatMajor = 1
  genesis.durability.storeFormatMinor = 2
  genesis.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  genesis.build.storeFormatHash = b4a.from(genesis.durability.storeFormatHash)
  bindDurability(genesis)
  const canonicalGenesis = signCanonical(blindServiceDescriptorV1, genesis,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  // Successor descriptor (sequence 1) links the complete genesis hash, forming
  // the genesis+successor two-slot chain the manifest integration serves.
  const successor = descriptorValue({
    relayPublicKey: b4a.from(relayPublicKey),
    storeId: b4a.alloc(32, 0x63),
    enabledOperationBits: operationBits,
    issuedEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4,
    capacityBand: 0
  })
  successor.endpoints = [successor.endpoints[0]]
  successor.endpoints[0].endpointId = 1
  successor.endpoints[0].transportId = 1
  successor.endpoints[0].roleBits = PUBLIC_ROLE_BITS
  successor.admissionProfiles = [successor.admissionProfiles[0]]
  successor.admissionProfiles[0].profileId = parameters.profileId
  successor.admissionProfiles[0].schemeId = parameters.schemeId
  successor.admissionProfiles[0].conformanceClass = parameters.conformanceClass
  successor.admissionProfiles[0].roleBits = parameters.roleBits
  successor.admissionProfiles[0].parameterHash = b4a.from(parameterHash)
  successor.durability.profileId = genesis.durability.profileId
  successor.durability.storeFormatMajor = 1
  successor.durability.storeFormatMinor = 2
  successor.durability.storeFormatHash = b4a.from(genesis.durability.storeFormatHash)
  successor.build.storeFormatHash = b4a.from(genesis.durability.storeFormatHash)
  successor.descriptorSequence = 1n
  successor.previousDescriptorHash = serviceDescriptorHash(canonicalGenesis)
  successor.descriptorNonce = b4a.alloc(32, 0x64)
  bindDurability(successor)
  const canonicalSuccessor = signCanonical(blindServiceDescriptorV1, successor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  const genesisHash = serviceDescriptorHash(canonicalGenesis)
  const successorHash = serviceDescriptorHash(canonicalSuccessor)

  const descriptorFile = path.join(root, 'descriptor.bin')
  const successorDescriptorFile = path.join(root, 'descriptor-successor.bin')
  const parametersFile = path.join(root, 'admission.bin')
  const secretKeyFile = path.join(root, 'relay-secret.bin')
  const storeManifestKeyFile = path.join(root, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(root, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(root, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalGenesis),
    privateFile(successorDescriptorFile, canonicalSuccessor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(storeManifestKeyFile, b4a.alloc(32, 0x71)),
    privateFile(ownerFenceFile, b4a.alloc(32, 0x72)),
    privateFile(inboxCursorKeyFile, b4a.alloc(32, 0x73))
  ])

  const launchTopologyHash = '81'.repeat(32)
  const adapterScriptFile = path.join(root, 'admission-adapter.js')
  const adapterScriptBytes = Buffer.from(vnextAdmissionScript(launchTopologyHash))
  await privateFile(adapterScriptFile, adapterScriptBytes)
  const adapterScriptSha256 = createHash('sha256').update(adapterScriptBytes).digest('hex')

  const uid = process.getuid()
  const gid = process.getgid()
  const edgeUid = uid === 0xffffffff ? uid - 1 : uid + 1
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_RUNTIME_PROFILE: VNEXT_PROFILE,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(root, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(root, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: launchTopologyHash,
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(edgeUid),
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
    HIVERELAY_BLIND_CORE_STORE_ROOT: coreStoreRoot,
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: b4a.toString(successorHash, 'hex'),
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: adapterScriptFile,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: adapterScriptSha256
  }

  if (options.forward === true) {
    const forwardManifestKeyFile = path.join(root, 'forward-manifest-key.bin')
    const forwardAtRestKeyFile = path.join(root, 'forward-atrest-key.bin')
    await Promise.all([
      privateFile(forwardManifestKeyFile, b4a.alloc(32, 0x74)),
      privateFile(forwardAtRestKeyFile, b4a.alloc(32, 0x75))
    ])
    environment.HIVERELAY_BLIND_FORWARD_STORE_ROOT = forwardStoreRoot
    environment.HIVERELAY_BLIND_FORWARD_MANIFEST_KEY_FILE = forwardManifestKeyFile
    environment.HIVERELAY_BLIND_FORWARD_ATREST_KEY_FILE = forwardAtRestKeyFile
    environment.HIVERELAY_BLIND_FORWARD_SOURCE_STORE_ID = '76'.repeat(32)
    environment.HIVERELAY_BLIND_FORWARD_TARGET_STORE_ID = '77'.repeat(32)
    environment.HIVERELAY_BLIND_FORWARD_SOURCE_CONTINUITY_HASH = '78'.repeat(32)
    environment.HIVERELAY_BLIND_FORWARD_TARGET_CONTINUITY_HASH = '79'.repeat(32)
  }

  return Object.freeze({
    directory: root,
    environment,
    relayPublicKey,
    parameterHash,
    currentEpoch,
    genesisHash,
    successorHash,
    descriptorFile,
    successorDescriptorFile
  })
}
