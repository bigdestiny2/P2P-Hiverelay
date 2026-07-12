import b4a from 'b4a'
import {
  arrayOf,
  boundedBytes,
  canonicalAsciiBytes,
  canonicalHttpsUrlBytes,
  canonicalUtf8Bytes,
  constant,
  encodeCanonical,
  fixedBytes,
  optional,
  ranged,
  struct,
  u8,
  u16be,
  u32be,
  u64be
} from './codec.js'
import { protocolError } from './errors.js'

const KiB = 1024
const MiB = 1024 * KiB
const DAY_MILLIS = 86400000n
const bytes32 = fixedBytes(32)
const bytes64 = fixedBytes(64)
const version1 = constant(u8, 1, 'version')
const utf8Path = canonicalUtf8Bytes(1, 512, 'path')
const absolutePath = canonicalUtf8Bytes(1, 512, 'absolute path')
const httpsUrl = canonicalHttpsUrlBytes('canonical HTTPS URL')
const environmentName = canonicalAsciiBytes(1, 128, 'environmentName')

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function isZero (value) {
  for (const byte of value) if (byte !== 0) return false
  return true
}

function nonzero (value, field) {
  if (isZero(value)) fail(`${field} must be nonzero`)
}

function asU64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${field} is outside u64`)
  return value
}

function compareBytes (left, right) {
  return b4a.compare(left, right)
}

function compareCanonical (encoding, left, right) {
  return compareBytes(encodeCanonical(encoding, left), encodeCanonical(encoding, right))
}

function assertSorted (values, compare, name) {
  for (let index = 1; index < values.length; index++) {
    if (compare(values[index - 1], values[index]) >= 0) fail(`${name} must be strictly sorted and duplicate-free`)
  }
}

function assertOrderedIds (values, field, first, name) {
  for (let index = 0; index < values.length; index++) {
    if (values[index][field] !== first + index) fail(`${name} must use the frozen ordered identifiers`)
  }
}

function assertUnique (values, equal, name) {
  for (let left = 0; left < values.length; left++) {
    for (let right = left + 1; right < values.length; right++) {
      if (equal(values[left], values[right])) fail(`${name} must be duplicate-free`)
    }
  }
}

function assertSameBytes (left, right, message) {
  if (!b4a.equals(left, right)) fail(message)
}

function validateWindow (value, from, through, name) {
  if (asU64(value[from], from) > asU64(value[through], through)) fail(`${name} observation window is reversed`)
}

function validateAbsolutePath (value, name = 'absolute path') {
  const text = b4a.toString(value, 'utf8')
  if (!text.startsWith('/') || text.length === 1 || text.endsWith('/') || text.includes('\\')) fail(`${name} must be an absolute canonical path`)
  for (const component of text.slice(1).split('/')) {
    if (component === '' || component === '.' || component === '..') fail(`${name} contains a forbidden path component`)
  }
}

function validateRelativePath (value, name = 'relative path') {
  const text = b4a.toString(value, 'utf8')
  if (text.startsWith('/') || text.endsWith('/') || text.includes('\\')) fail(`${name} must be a canonical relative path`)
  for (const component of text.split('/')) {
    if (component === '' || component === '.' || component === '..') fail(`${name} contains a forbidden path component`)
  }
}

function validateBoundaryWindow (value, name) {
  const observedFrom = asU64(value.observedFromUnixMillis, 'observedFromUnixMillis')
  const observedThrough = asU64(value.observedThroughUnixMillis, 'observedThroughUnixMillis')
  const issued = asU64(value.issuedUnixMillis, 'issuedUnixMillis')
  const expires = asU64(value.expiresUnixMillis, 'expiresUnixMillis')
  if (observedFrom > observedThrough || observedThrough > issued || issued >= expires) fail(`${name} times are invalid`)
  if (expires - issued > DAY_MILLIS) fail(`${name} validity exceeds 24 hours`)
}

function pathsOverlap (left, right) {
  const leftText = b4a.toString(left, 'utf8')
  const rightText = b4a.toString(right, 'utf8')
  return leftText === rightText || leftText.startsWith(`${rightText}/`) || rightText.startsWith(`${leftText}/`)
}

function capped (encoding, maximum, name) {
  return {
    preencode (state, value) {
      const start = state.end
      encoding.preencode(state, value)
      if (state.end - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
    },
    encode (state, value) { encoding.encode(state, value) },
    decode (state) {
      const start = state.start
      const value = encoding.decode(state)
      if (state.start - start > maximum) fail(`${name} exceeds ${maximum} bytes`)
      return value
    }
  }
}

export const buildInputV1 = struct([
  ['path', utf8Path],
  ['byteLength', u64be],
  ['contentHash', bytes32]
], {
  name: 'BuildInputV1',
  validate (value) { validateRelativePath(value.path, 'build input path') }
})

export const toolchainEntryV1 = struct([
  ['name', canonicalAsciiBytes(1, 64, 'toolchain name')],
  ['version', canonicalAsciiBytes(1, 128, 'toolchain version')],
  ['distributionHash', bytes32]
], {
  name: 'ToolchainEntryV1'
})

export const toolchainManifestV1 = struct([
  ['version', version1],
  ['entries', arrayOf(toolchainEntryV1, 1, 256, 'entries')]
], {
  name: 'ToolchainManifestV1',
  validate (value) {
    assertSorted(value.entries, (left, right) => compareCanonical(toolchainEntryV1, left, right), 'toolchain entries')
    assertUnique(value.entries, (left, right) => b4a.equals(left.name, right.name), 'toolchain names')
  }
})

const reproductionVariableV1 = struct([
  ['name', canonicalAsciiBytes(1, 128, 'variable name')],
  ['valueHash', bytes32]
], { name: 'ReproductionVariableV1' })

export const reproductionEnvironmentV1 = struct([
  ['version', version1],
  ['os', canonicalAsciiBytes(1, 64, 'os')],
  ['architecture', canonicalAsciiBytes(1, 64, 'architecture')],
  ['containerOrVmHash', bytes32],
  ['sourceDateEpoch', u64be],
  ['locale', canonicalAsciiBytes(1, 64, 'locale')],
  ['timezone', canonicalAsciiBytes(1, 64, 'timezone')],
  ['variables', arrayOf(reproductionVariableV1, 0, 256, 'variables')]
], {
  name: 'ReproductionEnvironmentV1',
  validate (value) {
    assertSorted(value.variables, (left, right) => compareBytes(left.name, right.name), 'environment variables')
  }
})

export const buildReproductionAttestationV1 = struct([
  ['version', version1],
  ['builderPublicKey', bytes32],
  ['environmentHash', bytes32],
  ['unsignedBuildCommitment', bytes32],
  ['reproducedArtifactHash', bytes32]
], {
  name: 'BuildReproductionAttestationV1',
  validate (value) { nonzero(value.builderPublicKey, 'builderPublicKey') }
})

const packagingFileV1 = struct([
  ['path', utf8Path],
  ['mode', u16be],
  ['fileBytes', boundedBytes(1, 16 * MiB, 'fileBytes')]
], { name: 'BlindPackagingFileV1' })

export const blindProductDistributionBundleV1 = struct([
  ['version', version1],
  ['artifactFormat', ranged(u8, 1, 2, 'artifactFormat')],
  ['edgeComponentDistributionBytes', boundedBytes(1, 0xffffffff, 'edgeComponentDistributionBytes')],
  ['daemonComponentDistributionBytes', boundedBytes(1, 0xffffffff, 'daemonComponentDistributionBytes')],
  ['packagingFiles', arrayOf(packagingFileV1, 2, 256, 'packagingFiles')]
], {
  name: 'BlindProductDistributionBundleV1',
  validate (value) {
    assertSorted(value.packagingFiles, (left, right) => compareCanonical(packagingFileV1, left, right), 'packaging files')
    assertUnique(value.packagingFiles, (left, right) => b4a.equals(left.path, right.path), 'packaging file paths')
  }
})

const buildReproductionV1 = struct([
  ['builderPublicKey', bytes32],
  ['environmentHash', bytes32],
  ['reproducedArtifactHash', bytes32],
  ['signature', bytes64]
], { name: 'BuildManifestReproductionV1' })

export const buildManifestV1 = struct([
  ['version', version1],
  ['productMode', constant(u8, 1, 'productMode')],
  ['implementationId', canonicalAsciiBytes(1, 64, 'implementationId')],
  ['implementationVersion', canonicalAsciiBytes(1, 64, 'implementationVersion')],
  ['sourceRevision', canonicalUtf8Bytes(1, 256, 'sourceRevision')],
  ['sourceTreeHash', bytes32],
  ['implementationSpecHash', bytes32],
  ['specHash', bytes32],
  ['abiHash', bytes32],
  ['vectorSetHash', bytes32],
  ['evidenceFormatHash', bytes32],
  ['evidenceVectorSetHash', bytes32],
  ['storeFormatHash', bytes32],
  ['storeVectorSetHash', bytes32],
  ['privateIpcFormatHash', bytes32],
  ['privateIpcVectorSetHash', bytes32],
  ['toolchainManifestHash', bytes32],
  ['dependencyLockHash', bytes32],
  ['sbomHash', optional(bytes32, 'sbomHash')],
  ['artifactFormat', ranged(u8, 1, 2, 'artifactFormat')],
  ['inputs', arrayOf(buildInputV1, 1, 0xffff, 'inputs')],
  ['buildArtifactHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['releaseSupportHorizonHash', bytes32],
  ['productIsolationEvidenceHash', bytes32],
  ['reproductionPolicyId', constant(u8, 1, 'reproductionPolicyId')],
  ['reproductions', arrayOf(buildReproductionV1, 1, 16, 'reproductions')],
  ['releaseSignerPublicKey', bytes32],
  ['releaseSignature', bytes64]
], {
  name: 'BuildManifestV1',
  validate (value) {
    assertSorted(value.inputs, (left, right) => compareBytes(left.path, right.path), 'build inputs')
    assertSorted(value.reproductions, (left, right) => compareCanonical(buildReproductionV1, left, right), 'build reproductions')
    assertUnique(value.reproductions, (left, right) => b4a.equals(left.builderPublicKey, right.builderPublicKey) &&
      b4a.equals(left.environmentHash, right.environmentHash), 'builder/environment pairs')
    for (const reproduction of value.reproductions) {
      nonzero(reproduction.builderPublicKey, 'builderPublicKey')
      assertSameBytes(reproduction.reproducedArtifactHash, value.buildArtifactHash, 'reproducedArtifactHash must equal buildArtifactHash')
    }
    nonzero(value.releaseSignerPublicKey, 'releaseSignerPublicKey')
    if (!value.reproductions.some(reproduction => !b4a.equals(reproduction.builderPublicKey, value.releaseSignerPublicKey))) {
      fail('reproduction policy 1 requires a builder key distinct from the release signer')
    }
  }
})

const launchComponentV1 = struct([
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['componentArtifactHash', bytes32],
  ['entrypointPath', utf8Path],
  ['entrypointContentHash', bytes32],
  ['serviceUnitPath', utf8Path],
  ['serviceUnitContentHash', bytes32],
  ['uid', u32be],
  ['gid', u32be],
  ['readOnlyMounts', arrayOf(utf8Path, 0, 32, 'readOnlyMounts')],
  ['writableMounts', arrayOf(utf8Path, 0, 8, 'writableMounts')],
  ['publicListenerFamilyBits', u8],
  ['allowedChildEntrypointHashes', arrayOf(bytes32, 0, 8, 'allowedChildEntrypointHashes')]
], {
  name: 'BlindLaunchComponentV1',
  validate (value) {
    assertSorted(value.readOnlyMounts, (left, right) => compareCanonical(utf8Path, left, right), 'read-only mounts')
    assertSorted(value.writableMounts, (left, right) => compareCanonical(utf8Path, left, right), 'writable mounts')
    assertSorted(value.allowedChildEntrypointHashes, (left, right) => compareCanonical(bytes32, left, right), 'allowed child entrypoint hashes')
  }
})

const launchInitializerTargetV1 = struct([
  ['targetKind', ranged(u8, 1, 2, 'targetKind')],
  ['path', absolutePath],
  ['finalUid', u32be],
  ['finalGid', u32be],
  ['finalMode', u16be]
], {
  name: 'BlindLaunchInitializerTargetV1',
  validate (value) { validateAbsolutePath(value.path) }
})

const launchInitializerV1 = struct([
  ['initializerId', constant(u8, 1, 'initializerId')],
  ['componentArtifactHash', bytes32],
  ['argv', arrayOf(canonicalUtf8Bytes(1, 512, 'argv'), 1, 32, 'argv')],
  ['uid', u32be],
  ['gid', u32be],
  ['capabilityBits', u64be],
  ['networkDisabled', constant(u8, 1, 'networkDisabled')],
  ['rootFilesystemReadOnly', constant(u8, 1, 'rootFilesystemReadOnly')],
  ['noNewPrivileges', constant(u8, 1, 'noNewPrivileges')],
  ['maxPids', ranged(u16be, 1, 32, 'maxPids')],
  ['writableMounts', arrayOf(utf8Path, 1, 8, 'writableMounts')],
  ['targets', arrayOf(launchInitializerTargetV1, 2, 2, 'targets')],
  ['maxRuntimeMillis', ranged(u32be, 1, 60000, 'maxRuntimeMillis')]
], {
  name: 'BlindLaunchInitializerV1',
  validate (value) {
    assertSorted(value.writableMounts, (left, right) => compareCanonical(utf8Path, left, right), 'initializer writable mounts')
    assertOrderedIds(value.targets, 'targetKind', 1, 'initializer targets')
    if (value.uid !== 0 || value.gid !== 0 || asU64(value.capabilityBits, 'capabilityBits') !== 7n || value.maxPids !== 32) fail('initializer privilege profile does not match VOLUME_OWNERSHIP_V1')
    if (value.targets[0].finalMode !== 0x01e8 || value.targets[1].finalMode !== 0x01c0) fail('initializer target modes must be POSIX 0750 then 0700')
  }
})

export const blindLaunchTopologyV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['privateIpcFormatHash', bytes32],
  ['privateIpcVectorSetHash', bytes32],
  ['components', arrayOf(launchComponentV1, 2, 2, 'components')],
  ['ipcUnarySocketPath', absolutePath],
  ['ipcStreamSocketPath', absolutePath],
  ['ipcOwnerUid', u32be],
  ['ipcPeerUid', u32be],
  ['ipcGroupGid', u32be],
  ['ipcMode', constant(u16be, 0x01b0, 'ipcMode')],
  ['launcherKind', ranged(u8, 1, 2, 'launcherKind')],
  ['defaultCommand', arrayOf(canonicalUtf8Bytes(1, 512, 'defaultCommand'), 1, 32, 'defaultCommand')],
  ['initializers', arrayOf(launchInitializerV1, 1, 1, 'initializers')],
  ['releaseSignerPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindLaunchTopologyV1',
  validate (value) {
    assertOrderedIds(value.components, 'componentId', 1, 'launch components')
    const [edge, daemon] = value.components
    const initializer = value.initializers[0]
    if (edge.uid === 0 || daemon.uid === 0 || edge.uid === daemon.uid) fail('edge and daemon UIDs must be nonzero and distinct')
    if (edge.publicListenerFamilyBits !== 0x1f || daemon.publicListenerFamilyBits !== 0) fail('public listener family bits must be edge=0x1f and daemon=0')
    if (edge.writableMounts.length !== 0 || daemon.writableMounts.length !== 2) fail('only daemon may own the two writable runtime/data roots')
    if (edge.allowedChildEntrypointHashes.length !== 0 || daemon.allowedChildEntrypointHashes.length > 1) fail('only daemon may allowlist the single blind-peer child')
    const writableMounts = value.components.flatMap(component => component.writableMounts)
    for (let left = 0; left < writableMounts.length; left++) {
      for (let right = left + 1; right < writableMounts.length; right++) {
        if (pathsOverlap(writableMounts[left], writableMounts[right])) fail('component writable mounts must be disjoint')
      }
    }
    validateAbsolutePath(value.ipcUnarySocketPath, 'ipcUnarySocketPath')
    validateAbsolutePath(value.ipcStreamSocketPath, 'ipcStreamSocketPath')
    if (b4a.equals(value.ipcUnarySocketPath, value.ipcStreamSocketPath)) fail('IPC socket paths must be distinct')
    if (value.ipcOwnerUid !== daemon.uid || value.ipcPeerUid !== edge.uid) fail('IPC owner/peer UIDs must equal daemon/edge UIDs')
    assertSameBytes(initializer.componentArtifactHash, daemon.componentArtifactHash, 'initializer artifact must equal daemon component artifact')
    if (initializer.writableMounts.length !== daemon.writableMounts.length ||
        initializer.writableMounts.some((path, index) => !b4a.equals(path, daemon.writableMounts[index]))) {
      fail('initializer writable mounts must equal daemon writable mounts')
    }
    for (const target of initializer.targets) {
      if (target.finalUid !== daemon.uid || target.finalGid !== daemon.gid) fail('initializer target ownership must equal daemon ownership')
      if (!daemon.writableMounts.some(path => b4a.equals(path, target.path))) fail('initializer target must name a daemon writable mount')
    }
    assertUnique(initializer.targets, (left, right) => b4a.equals(left.path, right.path), 'initializer target paths')
    nonzero(value.releaseSignerPublicKey, 'releaseSignerPublicKey')
  }
})

const artifactFileV1 = struct([
  ['componentId', ranged(u8, 0, 2, 'componentId')],
  ['path', utf8Path],
  ['mode', u16be],
  ['byteLength', u64be],
  ['contentHash', bytes32]
], { name: 'BlindArtifactFileV1' })

export const blindArtifactFileInventoryV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['files', arrayOf(artifactFileV1, 1, 0xffff, 'files')]
], {
  name: 'BlindArtifactFileInventoryV1',
  validate (value) {
    assertSorted(value.files, (left, right) => compareCanonical(artifactFileV1, left, right), 'artifact files')
    assertUnique(value.files, (left, right) => left.componentId === right.componentId && b4a.equals(left.path, right.path), 'artifact component/path pairs')
  }
})

const executableEntrypointV1 = struct([
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['componentArtifactHash', bytes32],
  ['entrypointPath', utf8Path],
  ['entrypointContentHash', bytes32],
  ['argvPrefix', arrayOf(canonicalUtf8Bytes(1, 512, 'argvPrefix'), 1, 16, 'argvPrefix')]
], { name: 'BlindExecutableEntrypointV1' })

export const blindExecutableEntrypointCatalogV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['entries', arrayOf(executableEntrypointV1, 2, 2, 'entries')]
], {
  name: 'BlindExecutableEntrypointCatalogV1',
  validate (value) { assertOrderedIds(value.entries, 'componentId', 1, 'executable entrypoints') }
})

const runtimeImportNodeV1 = struct([
  ['nodeId', bytes32],
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['path', utf8Path],
  ['contentHash', bytes32],
  ['importedNodeIds', arrayOf(bytes32, 0, 4096, 'importedNodeIds')]
], {
  name: 'BlindRuntimeImportNodeV1',
  validate (value) {
    assertSorted(value.importedNodeIds, (left, right) => compareCanonical(bytes32, left, right), 'imported node IDs')
  }
})

export const blindRuntimeImportGraphV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['entrypointNodeIds', arrayOf(bytes32, 2, 2, 'entrypointNodeIds')],
  ['nodes', arrayOf(runtimeImportNodeV1, 2, 0xffff, 'nodes')]
], {
  name: 'BlindRuntimeImportGraphV1',
  validate (value) {
    assertSorted(value.nodes, (left, right) => compareCanonical(runtimeImportNodeV1, left, right), 'runtime import nodes')
    assertUnique(value.nodes, (left, right) => b4a.equals(left.nodeId, right.nodeId), 'runtime import node IDs')
    if (b4a.equals(value.entrypointNodeIds[0], value.entrypointNodeIds[1])) fail('entrypoint node IDs must be distinct')
    const nodeById = new Map(value.nodes.map(node => [b4a.toString(node.nodeId, 'hex'), node]))
    const roots = value.entrypointNodeIds.map(nodeId => nodeById.get(b4a.toString(nodeId, 'hex')))
    if (!roots[0] || !roots[1] || roots[0].componentId !== 1 || roots[1].componentId !== 2) fail('ordered entrypoint nodes must exist for edge then daemon')
    for (const node of value.nodes) {
      for (const importedNodeId of node.importedNodeIds) {
        const imported = nodeById.get(b4a.toString(importedNodeId, 'hex'))
        if (!imported) fail('runtime import graph references an unknown node')
        if (imported.componentId !== node.componentId) fail('runtime import graph crosses component boundaries')
      }
    }
    for (let componentId = 1; componentId <= 2; componentId++) {
      const reachable = new Set()
      const pending = [roots[componentId - 1]]
      while (pending.length > 0) {
        const node = pending.pop()
        const key = b4a.toString(node.nodeId, 'hex')
        if (reachable.has(key)) continue
        reachable.add(key)
        for (const importedNodeId of node.importedNodeIds) pending.push(nodeById.get(b4a.toString(importedNodeId, 'hex')))
      }
      for (const node of value.nodes) {
        if (node.componentId === componentId && !reachable.has(b4a.toString(node.nodeId, 'hex'))) fail('runtime import graph contains an unreachable node')
      }
    }
  }
})

export const blindListenerEntryV1 = struct([
  ['componentId', ranged(u8, 1, 3, 'componentId')],
  ['listenerClass', ranged(u8, 1, 2, 'listenerClass')],
  ['transportId', ranged(u8, 0, 9, 'transportId')],
  ['endpointId', u8],
  ['addressOrSocket', canonicalUtf8Bytes(1, 512, 'addressOrSocket')],
  ['port', u16be],
  ['ownerUid', u32be]
], {
  name: 'BlindListenerEntryV1',
  validate (value) {
    if (value.ownerUid === 0) fail('listener ownerUid must be nonzero')
    if (value.listenerClass === 1 && (value.transportId === 0 || value.endpointId === 0 || value.port === 0)) {
      fail('public listener requires public transport, endpoint, and port')
    }
    if (value.listenerClass === 1 && value.componentId !== 1 && value.componentId !== 3) fail('public listener must belong to blind edge or legacy compatibility')
    if (value.listenerClass === 2 && (value.transportId !== 0 || value.endpointId !== 0 || value.port !== 0)) {
      fail('private Unix listener requires zero transport, endpoint, and port')
    }
    if (value.listenerClass === 2 && value.componentId !== 2) fail('private Unix listener must belong to blind daemon')
    if (value.listenerClass === 2) validateAbsolutePath(value.addressOrSocket, 'private Unix listener socket')
  }
})

export const blindListenerCatalogV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['observedFromUnixMillis', u64be],
  ['observedThroughUnixMillis', u64be],
  ['listeners', arrayOf(blindListenerEntryV1, 1, 64, 'listeners')]
], {
  name: 'BlindListenerCatalogV1',
  validate (value) {
    validateWindow(value, 'observedFromUnixMillis', 'observedThroughUnixMillis', 'listener catalog')
    assertSorted(value.listeners, (left, right) => compareCanonical(blindListenerEntryV1, left, right), 'listeners')
    if (value.listeners.some(listener => listener.componentId === 3)) fail('blind listener catalog cannot contain legacy compatibility listeners')
  }
})

const allowedRouteV1 = struct([
  ['method', canonicalAsciiBytes(1, 16, 'method')],
  ['path', canonicalAsciiBytes(1, 256, 'route path')],
  ['familyId', ranged(u8, 1, 5, 'familyId')]
], { name: 'BlindAllowedRouteV1' })

const negativeProbeV1 = struct([
  ['method', canonicalAsciiBytes(1, 16, 'method')],
  ['path', canonicalAsciiBytes(1, 256, 'probe path')],
  ['expectedStatus', u16be],
  ['observedStatus', u16be],
  ['responseBodyBytes', boundedBytes(0, 4096, 'responseBodyBytes')]
], { name: 'BlindNegativeRouteProbeV1' })

export const blindRouteAbsenceEvidenceV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['abiHash', bytes32],
  ['evidenceVectorSetHash', bytes32],
  ['allowedRoutes', arrayOf(allowedRouteV1, 1, 16, 'allowedRoutes')],
  ['negativeProbes', arrayOf(negativeProbeV1, 1, 256, 'negativeProbes')]
], {
  name: 'BlindRouteAbsenceEvidenceV1',
  validate (value) {
    assertSorted(value.allowedRoutes, (left, right) => compareCanonical(allowedRouteV1, left, right), 'allowed routes')
    assertSorted(value.negativeProbes, (left, right) => compareCanonical(negativeProbeV1, left, right), 'negative probes')
    assertUnique(value.allowedRoutes, (left, right) => b4a.equals(left.method, right.method) && b4a.equals(left.path, right.path), 'allowed method/path pairs')
    assertUnique(value.negativeProbes, (left, right) => b4a.equals(left.method, right.method) && b4a.equals(left.path, right.path), 'negative-probe method/path pairs')
  }
})

const inspectionTargetV1 = struct([
  ['targetKind', ranged(u8, 1, 2, 'targetKind')],
  ['path', absolutePath],
  ['finalUid', u32be],
  ['finalGid', u32be],
  ['finalMode', u16be],
  ['inodeKind', constant(u8, 1, 'inodeKind')],
  ['symlinkFree', constant(u8, 1, 'symlinkFree')]
], { name: 'BlindInspectionTargetV1', validate: value => validateAbsolutePath(value.path) })

const completedInitializerV1 = struct([
  ['initializerId', constant(u8, 1, 'initializerId')],
  ['componentArtifactHash', bytes32],
  ['argv', arrayOf(canonicalUtf8Bytes(1, 512, 'argv'), 1, 32, 'argv')],
  ['uid', u32be],
  ['gid', u32be],
  ['startedUnixMillis', u64be],
  ['endedUnixMillis', u64be],
  ['exitCode', u8],
  ['observedCapabilityBits', u64be],
  ['networkDisabled', u8],
  ['rootFilesystemReadOnly', u8],
  ['noNewPrivileges', u8],
  ['pidsLimit', u16be],
  ['observedPeakPids', u16be],
  ['writableMounts', arrayOf(utf8Path, 1, 8, 'writableMounts')],
  ['targetsAfter', arrayOf(inspectionTargetV1, 2, 2, 'targetsAfter')]
], {
  name: 'BlindCompletedInitializerV1',
  validate (value) {
    if (asU64(value.startedUnixMillis, 'startedUnixMillis') >= asU64(value.endedUnixMillis, 'endedUnixMillis')) fail('initializer completion must follow its start')
    assertSorted(value.writableMounts, (left, right) => compareCanonical(utf8Path, left, right), 'initializer writable mounts')
    assertOrderedIds(value.targetsAfter, 'targetKind', 1, 'initializer targets')
    if (value.uid !== 0 || value.gid !== 0 || value.exitCode !== 0 || asU64(value.observedCapabilityBits, 'observedCapabilityBits') !== 7n ||
        value.networkDisabled !== 1 || value.rootFilesystemReadOnly !== 1 || value.noNewPrivileges !== 1) {
      fail('completed initializer does not match VOLUME_OWNERSHIP_V1')
    }
    if (value.pidsLimit !== 32 || value.observedPeakPids < 1 || value.observedPeakPids > value.pidsLimit) fail('initializer PID evidence is outside its signed limit')
    if (asU64(value.endedUnixMillis, 'endedUnixMillis') - asU64(value.startedUnixMillis, 'startedUnixMillis') > 60000n) fail('initializer runtime exceeds the signed v1 maximum')
    if (value.targetsAfter[0].finalMode !== 0x01e8 || value.targetsAfter[1].finalMode !== 0x01c0) fail('initializer target modes must be POSIX 0750 then 0700')
    if (value.writableMounts.length !== value.targetsAfter.length ||
        value.targetsAfter.some(target => !value.writableMounts.some(path => b4a.equals(path, target.path)))) fail('completed initializer targets must equal its writable mounts')
  }
})

const inspectionMountV1 = struct([
  ['path', utf8Path],
  ['accessMode', ranged(u8, 1, 2, 'accessMode')]
], { name: 'BlindInspectionMountV1' })

const inspectionProcessV1 = struct([
  ['processOrdinal', ranged(u16be, 1, 0xffff, 'processOrdinal')],
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['parentProcessOrdinal', optional(u16be, 'parentProcessOrdinal')],
  ['uid', u32be],
  ['gid', u32be],
  ['executablePath', utf8Path],
  ['executableContentHash', bytes32],
  ['argv', arrayOf(canonicalUtf8Bytes(1, 512, 'argv'), 1, 32, 'argv')],
  ['environmentNames', arrayOf(environmentName, 0, 256, 'environmentNames')],
  ['mounts', arrayOf(inspectionMountV1, 0, 64, 'mounts')]
], {
  name: 'BlindInspectionProcessV1',
  validate (value) {
    assertSorted(value.environmentNames, (left, right) => compareCanonical(environmentName, left, right), 'environment names')
    assertSorted(value.mounts, (left, right) => compareCanonical(inspectionMountV1, left, right), 'process mounts')
    assertUnique(value.mounts, (left, right) => b4a.equals(left.path, right.path), 'process mount paths')
  }
})

export const blindProcessInspectionEvidenceV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['observedFromUnixMillis', u64be],
  ['observedThroughUnixMillis', u64be],
  ['completedInitializers', arrayOf(completedInitializerV1, 1, 1, 'completedInitializers')],
  ['processes', arrayOf(inspectionProcessV1, 2, 16, 'processes')]
], {
  name: 'BlindProcessInspectionEvidenceV1',
  validate (value) {
    validateWindow(value, 'observedFromUnixMillis', 'observedThroughUnixMillis', 'process inspection')
    const observedFrom = asU64(value.observedFromUnixMillis, 'observedFromUnixMillis')
    const observedThrough = asU64(value.observedThroughUnixMillis, 'observedThroughUnixMillis')
    const initializer = value.completedInitializers[0]
    if (observedFrom > asU64(initializer.startedUnixMillis, 'startedUnixMillis') ||
        asU64(initializer.endedUnixMillis, 'endedUnixMillis') > observedThrough) fail('initializer execution must fit inside the inspection window')
    assertSorted(value.processes, (left, right) => compareCanonical(inspectionProcessV1, left, right), 'processes')
    assertUnique(value.processes, (left, right) => left.processOrdinal === right.processOrdinal, 'process ordinals')
    const prior = new Map()
    const rootCount = new Map([[1, 0], [2, 0]])
    for (const process of value.processes) {
      if (process.parentProcessOrdinal == null) {
        rootCount.set(process.componentId, rootCount.get(process.componentId) + 1)
      } else {
        const parent = prior.get(process.parentProcessOrdinal)
        if (!parent || parent.componentId !== process.componentId) fail('process parent must be an earlier process in the same component')
        if (process.componentId !== 2) fail('only daemon may own an allowlisted child process')
      }
      prior.set(process.processOrdinal, process)
    }
    if (rootCount.get(1) !== 1 || rootCount.get(2) !== 1) fail('process inspection requires one edge root and one daemon root')
  }
})

export const blindProductIsolationReportBundleV1 = struct([
  ['version', version1],
  ['artifactFileInventoryBytes', boundedBytes(1, 48 * MiB, 'artifactFileInventoryBytes')],
  ['executableEntrypointBytes', boundedBytes(1, 0x10000, 'executableEntrypointBytes')],
  ['runtimeImportGraphBytes', boundedBytes(1, 48 * MiB, 'runtimeImportGraphBytes')],
  ['listenerCatalogBytes', boundedBytes(1, MiB, 'listenerCatalogBytes')],
  ['routeAbsenceEvidenceBytes', boundedBytes(1, MiB, 'routeAbsenceEvidenceBytes')],
  ['processInspectionBytes', boundedBytes(1, 4 * MiB, 'processInspectionBytes')]
], { name: 'BlindProductIsolationReportBundleV1' })

export const blindProductIsolationEvidenceV1 = struct([
  ['version', version1],
  ['productMode', constant(u8, 1, 'productMode')],
  ['buildArtifactHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['artifactFileInventoryHash', bytes32],
  ['executableEntryPointHash', bytes32],
  ['runtimeImportGraphHash', bytes32],
  ['listenerCatalogHash', bytes32],
  ['forbiddenComponentPresenceBits', constant(u16be, 0, 'forbiddenComponentPresenceBits')],
  ['routeAbsenceEvidenceHash', bytes32],
  ['processInspectionEvidenceHash', bytes32],
  ['isolationReportBundleHash', bytes32],
  ['issuedUnixMillis', u64be],
  ['evidenceSignerPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindProductIsolationEvidenceV1',
  validate (value) { nonzero(value.evidenceSignerPublicKey, 'evidenceSignerPublicKey') }
})

const boundaryComponentV1 = struct([
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['entrypointPath', utf8Path],
  ['entrypointBytes', boundedBytes(1, 16 * MiB, 'entrypointBytes')],
  ['serviceUnitPath', utf8Path],
  ['serviceUnitBytes', boundedBytes(1, MiB, 'serviceUnitBytes')],
  ['uid', u32be],
  ['gid', u32be]
], { name: 'BlindBoundaryComponentV1' })

const publicCredentialV1 = struct([
  ['credentialClass', ranged(u8, 1, 4, 'credentialClass')],
  ['canonicalPublicBytes', boundedBytes(1, 0xffff, 'canonicalPublicBytes')]
], { name: 'BlindPublicCredentialV1' })

const storageRootV1 = struct([
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['path', utf8Path],
  ['rootClass', canonicalAsciiBytes(1, 64, 'rootClass')],
  ['encryptionPublicKey', optional(bytes32, 'encryptionPublicKey')]
], { name: 'BlindStorageRootV1' })

const observabilityV1 = struct([
  ['componentId', ranged(u8, 1, 2, 'componentId')],
  ['logSinkId', canonicalAsciiBytes(1, 128, 'logSinkId')],
  ['logNamespace', canonicalAsciiBytes(1, 128, 'logNamespace')],
  ['metricSinkId', canonicalAsciiBytes(1, 128, 'metricSinkId')],
  ['metricNamespace', canonicalAsciiBytes(1, 128, 'metricNamespace')]
], { name: 'BlindObservabilityBindingV1' })

export const blindRuntimeBoundaryEvidenceV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['buildManifestHash', bytes32],
  ['launchTopologyHash', bytes32],
  ['componentProcesses', arrayOf(boundaryComponentV1, 2, 2, 'componentProcesses')],
  ['listeners', arrayOf(blindListenerEntryV1, 1, 64, 'listeners')],
  ['descriptorProtocolId', canonicalAsciiBytes(1, 64, 'descriptorProtocolId')],
  ['descriptorSigningPublicKey', bytes32],
  ['discoveryTopic', bytes32],
  ['publicCredentials', arrayOf(publicCredentialV1, 1, 32, 'publicCredentials')],
  ['storageRoots', arrayOf(storageRootV1, 1, 16, 'storageRoots')],
  ['releaseChannelUrl', httpsUrl],
  ['releaseChannelPublicKey', bytes32],
  ['observability', arrayOf(observabilityV1, 2, 2, 'observability')],
  ['deploymentId', bytes32],
  ['observedFromUnixMillis', u64be],
  ['observedThroughUnixMillis', u64be],
  ['issuedUnixMillis', u64be],
  ['expiresUnixMillis', u64be],
  ['evidenceSignerPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindRuntimeBoundaryEvidenceV1',
  validate (value) {
    assertOrderedIds(value.componentProcesses, 'componentId', 1, 'boundary component processes')
    if (value.componentProcesses[0].uid === 0 || value.componentProcesses[1].uid === 0 || value.componentProcesses[0].uid === value.componentProcesses[1].uid) fail('boundary component UIDs must be nonzero and distinct')
    assertSorted(value.listeners, (left, right) => compareCanonical(blindListenerEntryV1, left, right), 'boundary listeners')
    if (value.listeners.some(listener => listener.componentId === 3)) fail('blind runtime boundary cannot contain legacy compatibility listeners')
    assertOrderedIds(value.observability, 'componentId', 1, 'observability bindings')
    assertSorted(value.publicCredentials, (left, right) => compareCanonical(publicCredentialV1, left, right), 'public credentials')
    assertUnique(value.publicCredentials, (left, right) => left.credentialClass === right.credentialClass, 'public credential classes')
    assertSorted(value.storageRoots, (left, right) => compareCanonical(storageRootV1, left, right), 'storage roots')
    assertUnique(value.storageRoots, (left, right) => left.componentId === right.componentId && b4a.equals(left.path, right.path), 'storage component/path pairs')
    validateBoundaryWindow(value, 'runtime boundary')
    nonzero(value.deploymentId, 'deploymentId')
    nonzero(value.descriptorSigningPublicKey, 'descriptorSigningPublicKey')
    nonzero(value.releaseChannelPublicKey, 'releaseChannelPublicKey')
    nonzero(value.evidenceSignerPublicKey, 'evidenceSignerPublicKey')
  }
})

const predecessorV1 = struct([
  ['buildArtifactHash', bytes32],
  ['buildManifestHash', bytes32],
  ['abiHash', bytes32],
  ['storeFormatHash', bytes32],
  ['privateIpcFormatHash', bytes32],
  ['oldAbiServeThroughUnixMillis', u64be],
  ['rollbackThroughUnixMillis', u64be],
  ['compatibilityVectorSetHash', bytes32]
], { name: 'BlindReleasePredecessorV1' })

export const blindReleaseSupportHorizonV1 = struct([
  ['version', version1],
  ['buildArtifactHash', bytes32],
  ['specHash', bytes32],
  ['abiHash', bytes32],
  ['vectorSetHash', bytes32],
  ['evidenceFormatHash', bytes32],
  ['evidenceVectorSetHash', bytes32],
  ['storeFormatHash', bytes32],
  ['storeVectorSetHash', bytes32],
  ['privateIpcFormatHash', bytes32],
  ['privateIpcVectorSetHash', bytes32],
  ['issuedUnixMillis', u64be],
  ['activationNotBeforeUnixMillis', u64be],
  ['fullSupportThroughUnixMillis', u64be],
  ['upgradeMode', ranged(u8, 1, 2, 'upgradeMode')],
  ['predecessors', arrayOf(predecessorV1, 0, 4, 'predecessors')],
  ['releaseSignerPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'BlindReleaseSupportHorizonV1',
  validate (value) {
    assertSorted(value.predecessors, (left, right) => compareCanonical(predecessorV1, left, right), 'release predecessors')
    assertUnique(value.predecessors, (left, right) => b4a.equals(left.buildArtifactHash, right.buildArtifactHash), 'predecessor build artifacts')
    const issued = asU64(value.issuedUnixMillis, 'issuedUnixMillis')
    const activation = asU64(value.activationNotBeforeUnixMillis, 'activationNotBeforeUnixMillis')
    const through = asU64(value.fullSupportThroughUnixMillis, 'fullSupportThroughUnixMillis')
    if (issued > activation || activation >= through) fail('release support horizon times are invalid')
    for (const predecessor of value.predecessors) {
      const oldAbiThrough = asU64(predecessor.oldAbiServeThroughUnixMillis, 'oldAbiServeThroughUnixMillis')
      const rollbackThrough = asU64(predecessor.rollbackThroughUnixMillis, 'rollbackThroughUnixMillis')
      if (oldAbiThrough < activation || oldAbiThrough > through || rollbackThrough < activation || rollbackThrough > through) fail('predecessor deadlines must lie within the support horizon')
    }
    nonzero(value.releaseSignerPublicKey, 'releaseSignerPublicKey')
  }
})

const releaseCompatibilityVectorManifestBytesV1 = boundedBytes(1, MiB, 'compatibilityVectorManifest')
const reproductionEnvironmentBytesV1 = boundedBytes(1, MiB, 'reproductionEnvironment')

export const blindReleaseEvidenceBundleV1 = capped(struct([
  ['version', version1],
  ['buildManifestBytes', boundedBytes(1, 48 * MiB, 'buildManifestBytes')],
  ['launchTopologyBytes', boundedBytes(1, MiB, 'launchTopologyBytes')],
  ['isolationEvidenceBytes', boundedBytes(1, 0x10000, 'isolationEvidenceBytes')],
  ['isolationReportBundleBytes', boundedBytes(1, 128 * MiB, 'isolationReportBundleBytes')],
  ['releaseSupportHorizonBytes', boundedBytes(1, MiB, 'releaseSupportHorizonBytes')],
  ['privateIpcRegistryBytes', boundedBytes(1, MiB, 'privateIpcRegistryBytes')],
  ['privateIpcVectorManifestBytes', boundedBytes(1, MiB, 'privateIpcVectorManifestBytes')],
  ['releaseCompatibilityVectorManifestBytes', arrayOf(releaseCompatibilityVectorManifestBytesV1, 0, 4, 'releaseCompatibilityVectorManifestBytes')],
  ['toolchainManifestBytes', boundedBytes(1, MiB, 'toolchainManifestBytes')],
  ['reproductionEnvironmentBytes', arrayOf(reproductionEnvironmentBytesV1, 1, 16, 'reproductionEnvironmentBytes')],
  ['dependencyLockBytes', boundedBytes(1, 16 * MiB, 'dependencyLockBytes')],
  ['sbomBytes', optional(boundedBytes(1, 32 * MiB, 'sbomBytes'), 'sbomBytes')]
], {
  name: 'BlindReleaseEvidenceBundleV1',
  validate (value) {
    assertSorted(value.releaseCompatibilityVectorManifestBytes, (left, right) => compareCanonical(releaseCompatibilityVectorManifestBytesV1, left, right), 'release compatibility vector manifests')
    assertSorted(value.reproductionEnvironmentBytes, (left, right) => compareCanonical(reproductionEnvironmentBytesV1, left, right), 'reproduction environments')
  }
}), 512 * MiB, 'BlindReleaseEvidenceBundleV1')

export const hiveRelayCompatibilityBuildManifestV1 = struct([
  ['version', version1],
  ['productMode', constant(u8, 2, 'productMode')],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['implementationVersion', canonicalAsciiBytes(1, 64, 'implementationVersion')],
  ['sourceRevision', canonicalUtf8Bytes(1, 256, 'sourceRevision')],
  ['sourceTreeHash', bytes32],
  ['inputs', arrayOf(buildInputV1, 1, 0xffff, 'inputs')],
  ['toolchainManifestHash', bytes32],
  ['dependencyLockHash', bytes32],
  ['compatibilityArtifactFormat', ranged(u8, 1, 2, 'compatibilityArtifactFormat')],
  ['compatibilityArtifactUrl', httpsUrl],
  ['compatibilityArtifactHash', bytes32],
  ['sunsetChainGenesisHash', bytes32],
  ['sunsetGenesisUrl', httpsUrl],
  ['sunsetLatestUrl', httpsUrl],
  ['releaseSignerPublicKey', bytes32],
  ['releaseSignature', bytes64]
], {
  name: 'HiveRelayCompatibilityBuildManifestV1',
  validate (value) {
    assertSorted(value.inputs, (left, right) => compareBytes(left.path, right.path), 'compatibility build inputs')
    nonzero(value.releaseSignerPublicKey, 'releaseSignerPublicKey')
  }
})

export const hiveRelayCompatibilitySunsetGenesisV1 = struct([
  ['version', version1],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['sunsetChainId', bytes32],
  ['sunsetSequence', constant(u64be, 0n, 'sunsetSequence')],
  ['successorSpecHash', bytes32],
  ['successorAbiHash', bytes32],
  ['successorVectorSetHash', bytes32],
  ['genesisAuthoritySequence', u64be],
  ['genesisAuthorityPublicKey', bytes32],
  ['genesisAuthorityKeyId', bytes32],
  ['sunsetHistoryBaseUrl', httpsUrl],
  ['issuedUnixMillis', u64be],
  ['lastWriteUnixMillis', u64be],
  ['lastReadUnixMillis', u64be],
  ['releaseChannelPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'HiveRelayCompatibilitySunsetGenesisV1',
  validate (value) {
    nonzero(value.sunsetChainId, 'sunsetChainId')
    const issued = asU64(value.issuedUnixMillis, 'issuedUnixMillis')
    const lastWrite = asU64(value.lastWriteUnixMillis, 'lastWriteUnixMillis')
    const lastRead = asU64(value.lastReadUnixMillis, 'lastReadUnixMillis')
    if (lastWrite === 0n || lastRead === 0n || issued > lastWrite || lastWrite > lastRead) fail('sunset deadlines are invalid')
    nonzero(value.genesisAuthorityPublicKey, 'genesisAuthorityPublicKey')
    nonzero(value.releaseChannelPublicKey, 'releaseChannelPublicKey')
  }
})

export const hiveRelayLegacyCompatibilitySunsetV1 = struct([
  ['version', version1],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['sunsetChainGenesisHash', bytes32],
  ['sunsetChainId', bytes32],
  ['sunsetSequence', u64be],
  ['compatibilityArtifactUrl', httpsUrl],
  ['compatibilityArtifactHash', bytes32],
  ['compatibilityBuildManifestUrl', httpsUrl],
  ['compatibilityBuildManifestHash', bytes32],
  ['compatibilityRuntimeBoundaryEvidenceUrl', httpsUrl],
  ['compatibilityRuntimeBoundaryEvidenceHash', bytes32],
  ['successorSpecHash', bytes32],
  ['successorAbiHash', bytes32],
  ['successorVectorSetHash', bytes32],
  ['successorBuildArtifactHash', bytes32],
  ['successorBuildManifestHash', bytes32],
  ['successorLaunchTopologyHash', bytes32],
  ['successorIsolationEvidenceHash', bytes32],
  ['successorRuntimeBoundaryEvidenceHash', bytes32],
  ['issuedUnixMillis', u64be],
  ['lastWriteUnixMillis', u64be],
  ['lastReadUnixMillis', u64be],
  ['previousSunsetHash', bytes32],
  ['releaseAuthoritySequence', u64be],
  ['releaseAuthorityPublicKey', bytes32],
  ['releaseAuthorityKeyId', bytes32],
  ['authorityTransitionHash', optional(bytes32, 'authorityTransitionHash')],
  ['signature', bytes64]
], {
  name: 'HiveRelayLegacyCompatibilitySunsetV1',
  validate (value) {
    const sequence = asU64(value.sunsetSequence, 'sunsetSequence')
    const lastWrite = asU64(value.lastWriteUnixMillis, 'lastWriteUnixMillis')
    const lastRead = asU64(value.lastReadUnixMillis, 'lastReadUnixMillis')
    if (sequence === 0n) fail('sunsetSequence must be nonzero after genesis')
    if (lastWrite === 0n || lastRead === 0n || lastWrite > lastRead) fail('sunset deadlines are invalid')
    nonzero(value.sunsetChainId, 'sunsetChainId')
    nonzero(value.releaseAuthorityPublicKey, 'releaseAuthorityPublicKey')
    if (sequence === 1n) {
      if (value.authorityTransitionHash != null) fail('sequence-one sunset must omit authority transition evidence')
      assertSameBytes(value.previousSunsetHash, value.sunsetChainGenesisHash, 'sequence-one previousSunsetHash must equal sunsetChainGenesisHash')
    }
  }
})

export const hiveRelayCompatibilitySunsetHeadV1 = struct([
  ['version', version1],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['sunsetChainGenesisHash', bytes32],
  ['sunsetChainId', bytes32],
  ['sunsetSequence', u64be],
  ['sunsetHash', bytes32],
  ['compatibilityBuildManifestHash', bytes32],
  ['headLeaseSlot', u64be],
  ['issuedUnixMillis', u64be],
  ['notBeforeUnixMillis', u64be],
  ['expiresUnixMillis', u64be],
  ['releaseAuthoritySequence', u64be],
  ['releaseAuthorityKeyId', bytes32],
  ['signature', bytes64]
], {
  name: 'HiveRelayCompatibilitySunsetHeadV1',
  validate (value) {
    const notBefore = asU64(value.notBeforeUnixMillis, 'notBeforeUnixMillis')
    const expires = asU64(value.expiresUnixMillis, 'expiresUnixMillis')
    if (asU64(value.sunsetSequence, 'sunsetSequence') === 0n) fail('sunset head must bind a nonzero sunset sequence')
    if (asU64(value.headLeaseSlot, 'headLeaseSlot') !== notBefore / 300000n) fail('headLeaseSlot does not match notBeforeUnixMillis')
    if (asU64(value.issuedUnixMillis, 'issuedUnixMillis') > notBefore || notBefore >= expires || expires - notBefore > 900000n) fail('sunset head times are invalid')
    nonzero(value.sunsetChainId, 'sunsetChainId')
  }
})

export const hiveRelayCompatibilityAuthorityTransitionV1 = struct([
  ['version', version1],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['sunsetChainGenesisHash', bytes32],
  ['sunsetChainId', bytes32],
  ['successorSpecHash', bytes32],
  ['successorAbiHash', bytes32],
  ['successorVectorSetHash', bytes32],
  ['previousSunsetHash', bytes32],
  ['previousSunsetSequence', u64be],
  ['nextSunsetSequence', u64be],
  ['previousAuthoritySequence', u64be],
  ['nextAuthoritySequence', u64be],
  ['previousPublicKey', bytes32],
  ['nextPublicKey', bytes32],
  ['previousKeyId', bytes32],
  ['nextKeyId', bytes32],
  ['validFromSunsetSequence', u64be],
  ['previousKeySignature', bytes64],
  ['nextKeySignature', bytes64]
], {
  name: 'HiveRelayCompatibilityAuthorityTransitionV1',
  validate (value) {
    if (asU64(value.previousSunsetSequence, 'previousSunsetSequence') === 0n ||
        asU64(value.nextSunsetSequence, 'nextSunsetSequence') !== asU64(value.previousSunsetSequence, 'previousSunsetSequence') + 1n ||
        asU64(value.nextAuthoritySequence, 'nextAuthoritySequence') !== asU64(value.previousAuthoritySequence, 'previousAuthoritySequence') + 1n ||
        asU64(value.validFromSunsetSequence, 'validFromSunsetSequence') !== asU64(value.nextSunsetSequence, 'nextSunsetSequence')) {
      fail('compatibility authority transition sequences are not contiguous')
    }
    if (b4a.equals(value.previousPublicKey, value.nextPublicKey) || b4a.equals(value.previousKeyId, value.nextKeyId)) fail('authority transition must change key and key ID')
    nonzero(value.sunsetChainId, 'sunsetChainId')
    nonzero(value.previousPublicKey, 'previousPublicKey')
    nonzero(value.nextPublicKey, 'nextPublicKey')
  }
})

const compatibilityStorageRootV1 = struct([
  ['path', utf8Path],
  ['rootClass', canonicalAsciiBytes(1, 64, 'rootClass')],
  ['encryptionPublicKey', optional(bytes32, 'encryptionPublicKey')]
], { name: 'HiveRelayCompatibilityStorageRootV1' })

export const hiveRelayCompatibilityRuntimeBoundaryEvidenceV1 = struct([
  ['version', version1],
  ['compatibilityProductId', canonicalAsciiBytes(1, 128, 'compatibilityProductId')],
  ['compatibilityArtifactHash', bytes32],
  ['compatibilityBuildManifestHash', bytes32],
  ['entrypointPath', utf8Path],
  ['entrypointBytes', boundedBytes(1, 16 * MiB, 'entrypointBytes')],
  ['serviceUnitPath', utf8Path],
  ['serviceUnitBytes', boundedBytes(1, MiB, 'serviceUnitBytes')],
  ['processUid', u32be],
  ['processGid', u32be],
  ['processArgv', arrayOf(canonicalUtf8Bytes(1, 512, 'processArgv'), 1, 64, 'processArgv')],
  ['listeners', arrayOf(blindListenerEntryV1, 1, 64, 'listeners')],
  ['descriptorProtocolId', canonicalAsciiBytes(1, 64, 'descriptorProtocolId')],
  ['descriptorSigningPublicKey', bytes32],
  ['discoveryTopic', bytes32],
  ['publicCredentials', arrayOf(publicCredentialV1, 1, 32, 'publicCredentials')],
  ['storageRoots', arrayOf(compatibilityStorageRootV1, 1, 16, 'storageRoots')],
  ['releaseChannelUrl', httpsUrl],
  ['releaseChannelPublicKey', bytes32],
  ['logSinkId', canonicalAsciiBytes(1, 128, 'logSinkId')],
  ['logNamespace', canonicalAsciiBytes(1, 128, 'logNamespace')],
  ['metricSinkId', canonicalAsciiBytes(1, 128, 'metricSinkId')],
  ['metricNamespace', canonicalAsciiBytes(1, 128, 'metricNamespace')],
  ['deploymentId', bytes32],
  ['observedFromUnixMillis', u64be],
  ['observedThroughUnixMillis', u64be],
  ['successorBuildArtifactHash', bytes32],
  ['successorBuildManifestHash', bytes32],
  ['successorBuildManifestBytes', boundedBytes(1, 48 * MiB, 'successorBuildManifestBytes')],
  ['successorBlindRuntimeBoundaryEvidenceBytes', boundedBytes(1, 48 * MiB, 'successorBlindRuntimeBoundaryEvidenceBytes')],
  ['disjointBoundaryBits', constant(u16be, 0x07ff, 'disjointBoundaryBits')],
  ['issuedUnixMillis', u64be],
  ['expiresUnixMillis', u64be],
  ['evidenceSignerPublicKey', bytes32],
  ['signature', bytes64]
], {
  name: 'HiveRelayCompatibilityRuntimeBoundaryEvidenceV1',
  validate (value) {
    assertSorted(value.listeners, (left, right) => compareCanonical(blindListenerEntryV1, left, right), 'compatibility boundary listeners')
    if (value.listeners.some(listener => listener.componentId !== 3 || listener.listenerClass !== 1)) fail('compatibility boundary listeners must be public component 3 listeners')
    assertSorted(value.publicCredentials, (left, right) => compareCanonical(publicCredentialV1, left, right), 'public credentials')
    assertUnique(value.publicCredentials, (left, right) => left.credentialClass === right.credentialClass, 'public credential classes')
    assertSorted(value.storageRoots, (left, right) => compareCanonical(compatibilityStorageRootV1, left, right), 'storage roots')
    assertUnique(value.storageRoots, (left, right) => b4a.equals(left.path, right.path), 'compatibility storage root paths')
    validateBoundaryWindow(value, 'compatibility runtime boundary')
    nonzero(value.deploymentId, 'deploymentId')
    nonzero(value.descriptorSigningPublicKey, 'descriptorSigningPublicKey')
    nonzero(value.releaseChannelPublicKey, 'releaseChannelPublicKey')
    nonzero(value.evidenceSignerPublicKey, 'evidenceSignerPublicKey')
  }
})
