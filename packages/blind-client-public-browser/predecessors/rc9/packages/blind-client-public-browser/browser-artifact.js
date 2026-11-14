import b4a from 'b4a'
import { createHash } from 'node:crypto'
import { domainLengthHash } from '../blind-protocol/hashes.js'

const ACCEPTED_SOURCE_COMMIT = '1a114f64c97547cab6a18102c2ef4bff930e53ed'
const ACCEPTED_SOURCE_TREE = '5a341ba17a3d91a750cac94ba51116fe3552a6aa'
const TUPLE_SCHEMA = 'HiveRelayBlindClientPublicBrowserArtifactTupleV1'
const TUPLE_HASH_DOMAIN = 'hiverelay.blind-client-public-browser.artifact-tuple.v1'
const SOURCE_CLOSURE_HASH_DOMAIN = 'hiverelay.blind-client-public-browser.source-closure.v1'
const MANIFEST_SCHEMA = 'HiveRelayBlindClientPublicBrowserArtifactManifestV1'
const CHROMIUM_EVIDENCE_SCHEMA = 'HiveRelayBlindClientPublicBrowserArtifactChromiumEvidenceV1'
const CROSS_HOST_EVIDENCE_SCHEMA = 'HiveRelayBlindClientPublicBrowserArtifactCrossHostEvidenceV1'
const NORMALIZED_GRAPH_SCHEMA = 'HiveRelayBlindClientPublicBrowserNormalizedGraphDigestV1'
const NORMALIZED_GRAPH_SET_SCHEMA = 'HiveRelayBlindClientPublicBrowserNormalizedGraphSetDigestV1'
const NORMALIZED_GRAPH_HASH_DOMAIN = 'hiverelay.blind-client-public-browser.normalized-graph.v1'
const NORMALIZED_GRAPH_SET_HASH_DOMAIN = 'hiverelay.blind-client-public-browser.normalized-graph-set.v1'
const CANDIDATE_IDENTITY_BINDING = 'external-postcommit-final-sequence'
const SOURCE_ARCHIVE_IDENTITY = 'same-committed-relative-bytes'
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
const MAX_CANONICAL_JSON_BYTES = 128 * 1024
const HASH_PATTERN = /^[0-9a-f]{64}$/
const CONTENT_SECURITY_POLICY = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const CONTENT_SECURITY_POLICY_HASH = 'b3c81c106609f04764e531e72842dffcaf061d33263a5c24c447a9a06cd0ed6b'
const HOST_NODE_EXECUTABLE = '/opt/homebrew/Cellar/node@22/22.22.0/bin/node'
const HOST_NODE_EXECUTABLE_HASH = '59776c1735b2c28a28b0ae00b58bd9cbe524572e0caf62e043d5e44a62d98cce'
const HEADER_CACHE_PATH = '/Users/localllm/Library/Caches/node-gyp/22.22.0'
const HEADER_CACHE_DIGEST = 'dcd517fb9670e6192712badf0bdf1a9dfc4c8ff88887d06e4d4f4eb42e574990'
const HEADER_INSTALL_VERSION_HASH = '25d4f2a86deb5e2574bb3210b67bb24fcc4afb19f93a7b65a057daa874a9d18e'
const HEADER_NODE_H_PATH = '/Users/localllm/Library/Caches/node-gyp/22.22.0/include/node/node.h'
const HEADER_NODE_H_HASH = '4da8d691b256d4bef9c0e89114645f08787dc4892eae76240d28efdf4fa55019'
const PATCH_HASH = 'fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53'
const CONTAINER_IMAGE_ID = 'sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4'
const CHROMIUM_EXECUTABLE_PATH = '/Users/localllm/Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell'
const CSP_SOURCE_COMMIT = '6a8c1743d7e7ed504ccb0482f248e77d77fddca3'
const CSP_SOURCE_PATH = 'deploy/render-security-headers.json'
const CSP_SOURCE_FILE_HASH = 'e672153d1c396e617491fce64ed5472635314e20c45864e959b48e5f1b52b312'

const FULL_EXPORTS = Object.freeze([
  'BlindDescriptorBootstrapHttpClient',
  'BlindDirectHttpClient',
  'BlindRelayQualifier',
  'CLIENT_SELECTION_LIMITS',
  'DescriptorTrustStore',
  'DurabilityTracker',
  'DurableAttempt',
  'EncryptedIntentStore',
  'HEALTH_QUALIFICATION_LIMITS',
  'INTENT_STATE',
  'MemoryDescriptorTrustBackend',
  'MemoryIntentBackend',
  'RESULT_VERIFIER_STATUS',
  'RelayCandidatePool',
  'TrustedDescriptor',
  'VerifiedAdmissionParameters',
  'VerifiedDescriptor',
  'VerifiedEndpoint',
  'VerifiedHealth',
  'VerifiedOperationResult',
  'createAdmissionParametersRequest',
  'createAesGcmIntentSealer',
  'createAppendInboxRequest',
  'createBrowserCryptoRuntime',
  'createCellReplica',
  'createClientIntent',
  'createDescribeGetRequest',
  'createGetCellRequest',
  'createHealthChallenge',
  'createReadInboxRequest',
  'decodeBlindExternalProfileValueV1',
  'decodeClientIntent',
  'encodeClientIntent',
  'journalSignedIntent',
  'openVerifiedCellGetResult',
  'qualifyDescribeControlEndpoint',
  'qualifyRelay',
  'trustedAdmissionProfile',
  'trustedDescriptorValidity',
  'verifiedAdmissionParametersValidity',
  'verifiedEndpointContext',
  'verifiedHealthValidity',
  'verifyAdmissionParametersBytes',
  'verifyDescriptorBytes',
  'verifyHealthResultBytes',
  'verifyOperationResult'
])

const LIMITED_EXPORTS = Object.freeze([
  'createBlindCellGetControl',
  'createBrowserCryptoRuntime'
])

const FULL_CHROMIUM_CHECKS = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'EXACT_RUNTIME_EXPORTS',
  'FORBIDDEN_INBOX_LIFECYCLE_EXPORTS_ABSENT',
  'BOUND_GLOBAL_FETCH',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'INBOX_APPEND',
  'COMPRESSED_INBOX_READ',
  'EXACT_CONTENT_SECURITY_POLICY',
  'PINNED_CHROMIUM_EXECUTABLE',
  'DURABLE_CSP_SOURCE',
  'CLOSED_EXACT_REQUEST_INVENTORY',
  'ZERO_SECURITYPOLICYVIOLATION_EVENTS',
  'ZERO_ERROR_EVENTS',
  'ZERO_UNHANDLEDREJECTION_EVENTS'
])

const LIMITED_CHROMIUM_CHECKS = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'EXACT_RUNTIME_EXPORTS',
  'CELL_GET_ONLY',
  'DESCRIBE_INTERNAL_ONLY',
  'BOUND_GLOBAL_FETCH',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'EXACT_CONTENT_SECURITY_POLICY',
  'PINNED_CHROMIUM_EXECUTABLE',
  'DURABLE_CSP_SOURCE',
  'CLOSED_EXACT_REQUEST_INVENTORY',
  'ZERO_SECURITYPOLICYVIOLATION_EVENTS',
  'ZERO_ERROR_EVENTS',
  'ZERO_UNHANDLEDREJECTION_EVENTS'
])

const CROSS_HOST_CHECKS = Object.freeze([
  'PINNED_HOST_NODE_AND_HEADER_CACHE',
  'PINNED_HOST_NATIVE_ADDON',
  'SOURCE_ARCHIVE_NATIVE_ADDON_EQUALITY',
  'CLEAN_LINUX_DEPENDENCY_INSTALL',
  'EXACT_TRACKED_PATCH_APPLIED',
  'NATIVE_ADDON_UNREACHABLE_FROM_BOTH_GRAPHS',
  'HARDENED_NETWORK_NONE_GENERATION',
  'FROZEN_GENERATOR_CHECK',
  'ARTIFACT_BYTE_EQUALITY',
  'MANIFEST_BYTE_EQUALITY',
  'COMMITTED_EVIDENCE_INPUTS_UNTOUCHED'
])

export const BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN = Object.freeze({
  node_major: 22,
  modules_abi: '127',
  napi: '10',
  esbuild: '0.28.1'
})

function profile (value) {
  return Object.freeze({
    ...value,
    exactSortedExports: value.exactSortedExports,
    chromiumChecks: value.chromiumChecks,
    chromiumRequestInventory: value.chromiumRequestInventory,
    crossHostChecks: CROSS_HOST_CHECKS
  })
}

const FULL_PROFILE = profile({
  id: 'full',
  artifactId: 'blind-client-public-control-v1',
  profile: 'hiverelay.blind-client-public-browser.full.v1',
  artifactHashDomain: 'hiverelay.blind-client-public-browser.full-artifact-hash.v1',
  manifestHashDomain: 'hiverelay.blind-client-public-browser.full-manifest-hash.v1',
  artifactPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.mjs',
  manifestPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.manifest.cenc',
  chromiumEvidencePath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.chromium-evidence.json',
  crossHostEvidencePath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-control-v1.cross-host-evidence.json',
  exactSortedExports: FULL_EXPORTS,
  chromiumRequestInventory: Object.freeze([
    '/',
    '/bootstrap.mjs',
    '/gate.mjs',
    '/blind-client-public-control-v1.mjs'
  ]),
  chromiumChecks: FULL_CHROMIUM_CHECKS
})

const LIMITED_PROFILE = profile({
  id: 'limited',
  artifactId: 'blind-client-public-cell-get-v1',
  profile: 'hiverelay.blind-client-public-browser.cell-get.v1',
  artifactHashDomain: 'hiverelay.blind-client-public-browser.cell-get-artifact-hash.v1',
  manifestHashDomain: 'hiverelay.blind-client-public-browser.cell-get-manifest-hash.v1',
  artifactPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-cell-get-v1.mjs',
  manifestPath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-cell-get-v1.manifest.cenc',
  chromiumEvidencePath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-cell-get-v1.chromium-evidence.json',
  crossHostEvidencePath: 'packages/blind-client-public-browser/browser-artifacts/blind-client-public-cell-get-v1.cross-host-evidence.json',
  exactSortedExports: LIMITED_EXPORTS,
  chromiumRequestInventory: Object.freeze([
    '/',
    '/bootstrap.mjs',
    '/gate.mjs',
    '/blind-client-public-cell-get-v1.mjs'
  ]),
  chromiumChecks: LIMITED_CHROMIUM_CHECKS
})

export const BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES = Object.freeze({
  full: FULL_PROFILE,
  limited: LIMITED_PROFILE
})

export const BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY = Object.freeze({
  acceptedSourceCommit: ACCEPTED_SOURCE_COMMIT,
  acceptedSourceTree: ACCEPTED_SOURCE_TREE,
  tupleSchema: TUPLE_SCHEMA,
  tupleHashDomain: TUPLE_HASH_DOMAIN,
  sourceClosureHashDomain: SOURCE_CLOSURE_HASH_DOMAIN,
  manifestSchema: MANIFEST_SCHEMA,
  chromiumEvidenceSchema: CHROMIUM_EVIDENCE_SCHEMA,
  crossHostEvidenceSchema: CROSS_HOST_EVIDENCE_SCHEMA,
  normalizedGraphSchema: NORMALIZED_GRAPH_SCHEMA,
  normalizedGraphSetSchema: NORMALIZED_GRAPH_SET_SCHEMA,
  normalizedGraphHashDomain: NORMALIZED_GRAPH_HASH_DOMAIN,
  normalizedGraphSetHashDomain: NORMALIZED_GRAPH_SET_HASH_DOMAIN,
  maximumArtifactBytes: MAX_ARTIFACT_BYTES,
  toolchain: BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN
})

const TUPLE_FIELDS = Object.freeze([
  'schema',
  'acceptedSourceCommit',
  'acceptedSourceTree',
  'sourceClosureHash',
  'profile',
  'artifactHashDomain',
  'manifestHashDomain',
  'artifactPath',
  'exactSortedExports',
  'toolchain'
])

const MANIFEST_FIELDS = Object.freeze([
  'schema',
  'version',
  'acceptedSourceCommit',
  'acceptedSourceTree',
  'sourceClosureHash',
  'profile',
  'artifactHashDomain',
  'manifestHashDomain',
  'artifactPath',
  'exactSortedExports',
  'toolchain',
  'tupleHash',
  'artifactLength',
  'artifactHash'
])

const CHROMIUM_EVIDENCE_FIELDS = Object.freeze([
  'schema',
  'version',
  'evidenceClass',
  'profile',
  'artifactPath',
  'artifactLength',
  'artifactHash',
  'manifestHash',
  'tupleHash',
  'sourceClosureHash',
  'chromium',
  'chromiumExecutablePath',
  'chromiumExecutableHash',
  'contentSecurityPolicySourceCommit',
  'contentSecurityPolicySourcePath',
  'contentSecurityPolicySourceFileHash',
  'contentSecurityPolicy',
  'contentSecurityPolicyHash',
  'requestInventory',
  'securityPolicyViolationCount',
  'errorCount',
  'unhandledRejectionCount',
  'candidateIdentityBinding',
  'standaloneAuthority',
  'checks',
  'passed'
])

const CROSS_HOST_EVIDENCE_FIELDS = Object.freeze([
  'schema',
  'version',
  'evidenceClass',
  'profile',
  'artifactPath',
  'artifactLength',
  'artifactHash',
  'manifestHash',
  'tupleHash',
  'sourceClosureHash',
  'acceptedSourceCommit',
  'acceptedSourceTree',
  'candidateIdentityBinding',
  'standaloneAuthority',
  'sourceArchiveIdentity',
  'hostNodeExecutable',
  'hostNodeExecutableHash',
  'hostNode',
  'hostModulesAbi',
  'hostNapi',
  'hostPlatform',
  'hostArchitecture',
  'headerCachePath',
  'headerCacheFileCount',
  'headerCacheSymlinkCount',
  'headerCacheDigest',
  'headerCachePostflightDigest',
  'headerCacheInstallVersion',
  'headerCacheInstallVersionHash',
  'headerCacheNodeHeaderPath',
  'headerCacheNodeHeaderBytes',
  'headerCacheNodeHeaderHash',
  'nativeAddonPath',
  'nativeAddonPackage',
  'nativeAddonVersion',
  'nativeAddonArchitecture',
  'nativeAddonHash',
  'sourceArchiveNativeAddonEqual',
  'containerImageId',
  'containerPlatform',
  'containerArchitecture',
  'containerNode',
  'containerModulesAbi',
  'containerNapi',
  'containerRootReadOnly',
  'containerCapabilitiesDropped',
  'containerNoNewPrivileges',
  'installNetworkPhase',
  'generationNetworkPhase',
  'patchApplied',
  'patchHash',
  'containerNativeRebuild',
  'fullNativeAddonReachable',
  'limitedNativeAddonReachable',
  'normalizedGraphHash',
  'normalizedGraphSetHash',
  'artifactManifestByteEquality',
  'committedEvidenceInputsUntouched',
  'committedEvidenceInputsProof',
  'toolchain',
  'checks',
  'passed'
])

function fail (code, message, options) {
  const error = new Error(message, options)
  error.code = code
  throw error
}

function bytes (value, field) {
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  if (value instanceof ArrayBuffer) return b4a.from(value)
  fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} must be bytes`)
}

function exactObject (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} must be an object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} has an unexpected prototype`)
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== fields.length || keys.some(key => typeof key !== 'string') ||
      fields.some(name => !Object.prototype.hasOwnProperty.call(value, name))) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} fields are missing or unexpected`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (fields.some(name => !descriptors[name].enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptors[name], 'value'))) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} fields must be enumerable data properties`)
  }
}

function exactOrderedObject (value, fields, field) {
  exactObject(value, fields, field)
  const keys = Reflect.ownKeys(value)
  if (keys.some((key, index) => key !== fields[index])) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      `${field} properties are not in canonical order`)
  }
}

function allowedObject (value, required, optional, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} must be an object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} has an unexpected prototype`)
  }
  const allowed = new Set([...required, ...optional])
  const keys = Reflect.ownKeys(value)
  if (keys.some(key => typeof key !== 'string' || !allowed.has(key)) ||
      required.some(name => !Object.prototype.hasOwnProperty.call(value, name))) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} fields are missing or unexpected`)
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  if (keys.some(name => !descriptors[name].enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptors[name], 'value'))) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} fields must be enumerable data properties`)
  }
}

function hashHex (value, field) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} must be a lowercase 32-byte hex hash`)
  }
  return value
}

function exactInteger (value, expected, field) {
  if (!Number.isSafeInteger(value) || value !== expected) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_RELEASE_EVIDENCE', `${field} changed its exact value`)
  }
  return expected
}

function nonNegativeInteger (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      `${field} must be a non-negative safe integer`)
  }
  return value
}

function boundedText (value, field, maximum = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum ||
      /[^\x20-\x7e]/.test(value)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} must be bounded printable ASCII`)
  }
  return value
}

function artifactLength (value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_ARTIFACT_BYTES) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT',
      `artifactLength must be within 1..${MAX_ARTIFACT_BYTES}`)
  }
  return value
}

function profileIdentity (value) {
  if (value === FULL_PROFILE.id || value === FULL_PROFILE.profile) return FULL_PROFILE
  if (value === LIMITED_PROFILE.id || value === LIMITED_PROFILE.profile) return LIMITED_PROFILE
  fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', 'profile is not an exact public-browser artifact identity')
}

function exactStringArray (value, expected, field) {
  if (!Array.isArray(value) || value.length !== expected.length ||
      value.some((entry, index) => entry !== expected[index])) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} is not the exact ordered inventory`)
  }
  return expected
}

function exactToolchain (value, field = 'toolchain') {
  exactObject(value, ['node_major', 'modules_abi', 'napi', 'esbuild'], field)
  for (const name of ['node_major', 'modules_abi', 'napi', 'esbuild']) {
    if (value[name] !== BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN[name]) {
      fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field}.${name} changed the deterministic compatibility identity`)
    }
  }
  return BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN
}

function digest (domain, value) {
  return b4a.toString(domainLengthHash(domain, bytes(value, 'hash input')), 'hex')
}

function encodeCanonicalJson (value) {
  return b4a.from(JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function codePointCompare (left, right) {
  const leftPoints = Array.from(left, value => value.codePointAt(0))
  const rightPoints = Array.from(right, value => value.codePointAt(0))
  const length = Math.min(leftPoints.length, rightPoints.length)
  for (let index = 0; index < length; index++) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index]
  }
  return leftPoints.length - rightPoints.length
}

function normalizedGraphPath (raw, field) {
  if (typeof raw !== 'string') {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH', `${field} must be a string`)
  }
  const value = raw.replaceAll('\\', '/')
  const segments = value.split('/')
  if (!value || value.includes('\0') || value.startsWith('/') || /^[A-Za-z]:\//.test(value) ||
      segments.some(segment => segment === '' || segment === '.' || segment === '..')) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      `${field} is not a canonical repository-relative path`)
  }
  return value
}

function normalizedGraphText (value, field, nullable = false) {
  if (nullable && value === null) return null
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 || value.includes('\0')) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      `${field} must be a bounded non-empty string${nullable ? ' or null' : ''}`)
  }
  return value
}

function normalizedGraphBoolean (value, field) {
  if (typeof value !== 'boolean') {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH', `${field} must be boolean`)
  }
  return value
}

function assertCanonicalOrder (values, key, field, unique = false) {
  for (let index = 1; index < values.length; index++) {
    const comparison = codePointCompare(key(values[index - 1]), key(values[index]))
    if (comparison > 0 || (unique && comparison === 0)) {
      fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
        `${field} is not in canonical order${unique ? ' or contains a duplicate' : ''}`)
    }
  }
}

function normalizedInputImport (value, field) {
  exactOrderedObject(value, ['path', 'kind', 'external', 'original'], field)
  return Object.freeze({
    path: normalizedGraphPath(value.path, `${field}.path`),
    kind: normalizedGraphText(value.kind, `${field}.kind`),
    external: normalizedGraphBoolean(value.external, `${field}.external`),
    original: normalizedGraphText(value.original, `${field}.original`, true)
  })
}

function normalizedOutputImport (value, field) {
  exactOrderedObject(value, ['path', 'kind', 'external'], field)
  return Object.freeze({
    path: normalizedGraphPath(value.path, `${field}.path`),
    kind: normalizedGraphText(value.kind, `${field}.kind`),
    external: normalizedGraphBoolean(value.external, `${field}.external`)
  })
}

function normalizedGraphInputEntry (value, field) {
  exactOrderedObject(value, ['path', 'bytes', 'format', 'imports'], field)
  if (!Array.isArray(value.imports)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH', `${field}.imports must be an array`)
  }
  const imports = value.imports.map((entry, index) => normalizedInputImport(entry, `${field}.imports[${index}]`))
  assertCanonicalOrder(imports, entry => JSON.stringify(entry), `${field}.imports`)
  return Object.freeze({
    path: normalizedGraphPath(value.path, `${field}.path`),
    bytes: nonNegativeInteger(value.bytes, `${field}.bytes`),
    format: normalizedGraphText(value.format, `${field}.format`),
    imports: Object.freeze(imports)
  })
}

function normalizedOutputInput (value, field) {
  exactOrderedObject(value, ['path', 'bytesInOutput'], field)
  return Object.freeze({
    path: normalizedGraphPath(value.path, `${field}.path`),
    bytesInOutput: nonNegativeInteger(value.bytesInOutput, `${field}.bytesInOutput`)
  })
}

function normalizedGraphOutputEntry (value, field) {
  exactOrderedObject(value, ['path', 'entryPoint', 'exports', 'imports', 'inputs', 'bytes'], field)
  if (!Array.isArray(value.exports) || !Array.isArray(value.imports) || !Array.isArray(value.inputs)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      `${field}.exports, imports and inputs must be arrays`)
  }
  const exports = value.exports.map((entry, index) =>
    normalizedGraphText(entry, `${field}.exports[${index}]`))
  const imports = value.imports.map((entry, index) =>
    normalizedOutputImport(entry, `${field}.imports[${index}]`))
  const inputs = value.inputs.map((entry, index) =>
    normalizedOutputInput(entry, `${field}.inputs[${index}]`))
  assertCanonicalOrder(exports, entry => entry, `${field}.exports`, true)
  assertCanonicalOrder(imports, entry => JSON.stringify(entry), `${field}.imports`)
  assertCanonicalOrder(inputs, entry => entry.path, `${field}.inputs`, true)
  return Object.freeze({
    path: normalizedGraphPath(value.path, `${field}.path`),
    entryPoint: value.entryPoint === null
      ? null
      : normalizedGraphPath(value.entryPoint, `${field}.entryPoint`),
    exports: Object.freeze(exports),
    imports: Object.freeze(imports),
    inputs: Object.freeze(inputs),
    bytes: nonNegativeInteger(value.bytes, `${field}.bytes`)
  })
}

function normalizedGraphInput (value) {
  exactOrderedObject(value, ['inputs', 'outputs'], 'normalized graph')
  if (!Array.isArray(value.inputs) || !Array.isArray(value.outputs)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      'normalized graph inputs and outputs must be arrays')
  }
  const inputs = value.inputs.map((entry, index) =>
    normalizedGraphInputEntry(entry, `normalized graph inputs[${index}]`))
  const outputs = value.outputs.map((entry, index) =>
    normalizedGraphOutputEntry(entry, `normalized graph outputs[${index}]`))
  assertCanonicalOrder(inputs, entry => entry.path, 'normalized graph inputs', true)
  assertCanonicalOrder(outputs, entry => entry.path, 'normalized graph outputs', true)
  return Object.freeze({ inputs: Object.freeze(inputs), outputs: Object.freeze(outputs) })
}

function normalizedGraphProfileId (value) {
  if (value !== 'full' && value !== 'limited') {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      'normalized graph profileId must be full or limited')
  }
  return value
}

function sha256NulDomain (domain, canonicalBytes) {
  return createHash('sha256')
    .update(b4a.from(domain, 'ascii'))
    .update(b4a.from([0]))
    .update(canonicalBytes)
    .digest('hex')
}

function normalizedGraphDigestPreimage (value) {
  exactOrderedObject(value, ['schema', 'profileId', 'normalizedGraph'],
    'normalized graph digest preimage')
  if (value.schema !== NORMALIZED_GRAPH_SCHEMA) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      'normalized graph digest schema is unsupported')
  }
  return Object.freeze({
    schema: NORMALIZED_GRAPH_SCHEMA,
    profileId: normalizedGraphProfileId(value.profileId),
    normalizedGraph: normalizedGraphInput(value.normalizedGraph)
  })
}

function normalizedGraphSetDigestPreimage (value) {
  exactOrderedObject(value, ['schema', 'profileOrder', 'profiles'],
    'normalized graph set digest preimage')
  exactStringArray(value.profileOrder, ['full', 'limited'], 'normalized graph profileOrder')
  exactOrderedObject(value.profiles, ['full', 'limited'], 'normalized graph set profiles')
  if (value.schema !== NORMALIZED_GRAPH_SET_SCHEMA) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH',
      'normalized graph set digest schema is unsupported')
  }
  return Object.freeze({
    schema: NORMALIZED_GRAPH_SET_SCHEMA,
    profileOrder: Object.freeze(['full', 'limited']),
    profiles: Object.freeze({
      full: hashHex(value.profiles.full, 'normalized graph set full hash'),
      limited: hashHex(value.profiles.limited, 'normalized graph set limited hash')
    })
  })
}

export function createBlindClientPublicBrowserNormalizedGraphDigestPreimageV1 (input) {
  exactOrderedObject(input, ['profileId', 'normalizedGraph'],
    'normalized graph digest creation input')
  return normalizedGraphDigestPreimage({
    schema: NORMALIZED_GRAPH_SCHEMA,
    profileId: input.profileId,
    normalizedGraph: input.normalizedGraph
  })
}

export function encodeBlindClientPublicBrowserNormalizedGraphDigestPreimageV1 (input) {
  return encodeCanonicalJson(normalizedGraphDigestPreimage(input))
}

export function hashBlindClientPublicBrowserNormalizedGraphV1 (input) {
  return sha256NulDomain(NORMALIZED_GRAPH_HASH_DOMAIN,
    encodeCanonicalJson(createBlindClientPublicBrowserNormalizedGraphDigestPreimageV1(input)))
}

export function createBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1 (input) {
  exactOrderedObject(input, ['full', 'limited'], 'normalized graph set creation input')
  return normalizedGraphSetDigestPreimage({
    schema: NORMALIZED_GRAPH_SET_SCHEMA,
    profileOrder: ['full', 'limited'],
    profiles: { full: input.full, limited: input.limited }
  })
}

export function encodeBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1 (input) {
  return encodeCanonicalJson(normalizedGraphSetDigestPreimage(input))
}

export function hashBlindClientPublicBrowserNormalizedGraphSetV1 (input) {
  return sha256NulDomain(NORMALIZED_GRAPH_SET_HASH_DOMAIN,
    encodeCanonicalJson(createBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1(input)))
}

function parseCanonicalJson (input, field, canonicalize) {
  input = bytes(input, field)
  if (input.byteLength < 1 || input.byteLength > MAX_CANONICAL_JSON_BYTES) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} is outside its canonical byte limit`)
  }
  const source = b4a.toString(input, 'utf8')
  if (!b4a.equals(b4a.from(source, 'utf8'), input)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} is not canonical UTF-8`)
  }
  let parsed
  try {
    parsed = JSON.parse(source)
  } catch (error) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} is not JSON`, { cause: error })
  }
  const canonical = canonicalize(parsed)
  if (!b4a.equals(encodeCanonicalJson(canonical), input)) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', `${field} is not canonical JSON`)
  }
  return canonical
}

function tupleInput (value) {
  exactObject(value, TUPLE_FIELDS, 'artifact tuple')
  const identity = profileIdentity(value.profile)
  if (value.schema !== TUPLE_SCHEMA ||
      value.acceptedSourceCommit !== ACCEPTED_SOURCE_COMMIT ||
      value.acceptedSourceTree !== ACCEPTED_SOURCE_TREE ||
      value.artifactHashDomain !== identity.artifactHashDomain ||
      value.manifestHashDomain !== identity.manifestHashDomain ||
      value.artifactPath !== identity.artifactPath) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', 'artifact tuple changed its immutable profile identity')
  }
  const output = {
    schema: TUPLE_SCHEMA,
    acceptedSourceCommit: ACCEPTED_SOURCE_COMMIT,
    acceptedSourceTree: ACCEPTED_SOURCE_TREE,
    sourceClosureHash: hashHex(value.sourceClosureHash, 'sourceClosureHash'),
    profile: identity.profile,
    artifactHashDomain: identity.artifactHashDomain,
    manifestHashDomain: identity.manifestHashDomain,
    artifactPath: identity.artifactPath,
    exactSortedExports: identity.exactSortedExports,
    toolchain: exactToolchain(value.toolchain)
  }
  return Object.freeze(output)
}

export function createBlindClientPublicBrowserArtifactTupleV1 (input) {
  exactObject(input, ['profile', 'sourceClosureHash'], 'artifact tuple creation input')
  const identity = profileIdentity(input.profile)
  return tupleInput({
    schema: TUPLE_SCHEMA,
    acceptedSourceCommit: ACCEPTED_SOURCE_COMMIT,
    acceptedSourceTree: ACCEPTED_SOURCE_TREE,
    sourceClosureHash: input.sourceClosureHash,
    profile: identity.profile,
    artifactHashDomain: identity.artifactHashDomain,
    manifestHashDomain: identity.manifestHashDomain,
    artifactPath: identity.artifactPath,
    exactSortedExports: identity.exactSortedExports,
    toolchain: BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN
  })
}

export function encodeBlindClientPublicBrowserArtifactTupleV1 (input) {
  return encodeCanonicalJson(tupleInput(input))
}

export function decodeBlindClientPublicBrowserArtifactTupleV1 (input) {
  return parseCanonicalJson(input, 'artifact tuple', tupleInput)
}

export function hashBlindClientPublicBrowserArtifactTupleV1 (input) {
  const encoded = b4a.isBuffer(input) || ArrayBuffer.isView(input) || input instanceof ArrayBuffer
    ? encodeBlindClientPublicBrowserArtifactTupleV1(
      decodeBlindClientPublicBrowserArtifactTupleV1(input))
    : encodeBlindClientPublicBrowserArtifactTupleV1(input)
  return digest(TUPLE_HASH_DOMAIN, encoded)
}

export function hashBlindClientPublicBrowserSourceClosure (input) {
  return digest(SOURCE_CLOSURE_HASH_DOMAIN, input)
}

export function hashBlindClientPublicBrowserArtifact (profileValue, input) {
  const identity = profileIdentity(profileValue)
  input = bytes(input, 'artifact')
  artifactLength(input.byteLength)
  return digest(identity.artifactHashDomain, input)
}

function manifestTuple (value) {
  return tupleInput({
    schema: TUPLE_SCHEMA,
    acceptedSourceCommit: value.acceptedSourceCommit,
    acceptedSourceTree: value.acceptedSourceTree,
    sourceClosureHash: value.sourceClosureHash,
    profile: value.profile,
    artifactHashDomain: value.artifactHashDomain,
    manifestHashDomain: value.manifestHashDomain,
    artifactPath: value.artifactPath,
    exactSortedExports: value.exactSortedExports,
    toolchain: value.toolchain
  })
}

function manifestInput (value) {
  exactObject(value, MANIFEST_FIELDS, 'artifact manifest')
  if (value.schema !== MANIFEST_SCHEMA || value.version !== 1) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT', 'artifact manifest schema or version is unsupported')
  }
  const tuple = manifestTuple(value)
  const tupleHash = hashBlindClientPublicBrowserArtifactTupleV1(tuple)
  if (hashHex(value.tupleHash, 'tupleHash') !== tupleHash) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_TUPLE_MISMATCH', 'artifact manifest does not bind its canonical tuple')
  }
  return Object.freeze({
    schema: MANIFEST_SCHEMA,
    version: 1,
    acceptedSourceCommit: tuple.acceptedSourceCommit,
    acceptedSourceTree: tuple.acceptedSourceTree,
    sourceClosureHash: tuple.sourceClosureHash,
    profile: tuple.profile,
    artifactHashDomain: tuple.artifactHashDomain,
    manifestHashDomain: tuple.manifestHashDomain,
    artifactPath: tuple.artifactPath,
    exactSortedExports: tuple.exactSortedExports,
    toolchain: tuple.toolchain,
    tupleHash,
    artifactLength: artifactLength(value.artifactLength),
    artifactHash: hashHex(value.artifactHash, 'artifactHash')
  })
}

export function createBlindClientPublicBrowserArtifactManifestV1 (input) {
  exactObject(input, ['tuple', 'artifactBytes'], 'artifact manifest creation input')
  const tuple = tupleInput(input.tuple)
  const artifactBytes = bytes(input.artifactBytes, 'artifactBytes')
  const identity = profileIdentity(tuple.profile)
  return manifestInput({
    schema: MANIFEST_SCHEMA,
    version: 1,
    acceptedSourceCommit: tuple.acceptedSourceCommit,
    acceptedSourceTree: tuple.acceptedSourceTree,
    sourceClosureHash: tuple.sourceClosureHash,
    profile: tuple.profile,
    artifactHashDomain: tuple.artifactHashDomain,
    manifestHashDomain: tuple.manifestHashDomain,
    artifactPath: tuple.artifactPath,
    exactSortedExports: tuple.exactSortedExports,
    toolchain: tuple.toolchain,
    tupleHash: hashBlindClientPublicBrowserArtifactTupleV1(tuple),
    artifactLength: artifactBytes.byteLength,
    artifactHash: hashBlindClientPublicBrowserArtifact(identity.profile, artifactBytes)
  })
}

export function encodeBlindClientPublicBrowserArtifactManifestV1 (input) {
  return encodeCanonicalJson(manifestInput(input))
}

export function decodeBlindClientPublicBrowserArtifactManifestV1 (input) {
  return parseCanonicalJson(input, 'artifact manifest', manifestInput)
}

export function hashBlindClientPublicBrowserArtifactManifestV1 (input) {
  let manifest
  let encoded
  if (b4a.isBuffer(input) || ArrayBuffer.isView(input) || input instanceof ArrayBuffer) {
    manifest = decodeBlindClientPublicBrowserArtifactManifestV1(input)
    encoded = encodeBlindClientPublicBrowserArtifactManifestV1(manifest)
  } else {
    manifest = manifestInput(input)
    encoded = encodeBlindClientPublicBrowserArtifactManifestV1(manifest)
  }
  return digest(manifest.manifestHashDomain, encoded)
}

export function verifyBlindClientPublicBrowserArtifactV1 (input) {
  allowedObject(input,
    ['profile', 'manifestBytes', 'artifactBytes', 'expectedManifestHash', 'expectedSourceClosureHash'],
    ['expectedTupleHash'], 'artifact verification input')
  const identity = profileIdentity(input.profile)
  const manifestBytes = bytes(input.manifestBytes, 'manifestBytes')
  const manifest = decodeBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
  if (manifest.profile !== identity.profile) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_PROFILE_SWAP', 'artifact manifest has the wrong profile identity')
  }
  const manifestHash = hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
  if (manifestHash !== hashHex(input.expectedManifestHash, 'expectedManifestHash')) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_MANIFEST_DRIFT', 'artifact manifest does not match its authenticated expected hash')
  }
  if (manifest.sourceClosureHash !== hashHex(input.expectedSourceClosureHash, 'expectedSourceClosureHash')) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_SOURCE_CLOSURE_MISMATCH', 'artifact manifest does not match the expected source closure')
  }
  if (input.expectedTupleHash != null &&
      manifest.tupleHash !== hashHex(input.expectedTupleHash, 'expectedTupleHash')) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_TUPLE_MISMATCH', 'artifact manifest does not match the expected tuple')
  }
  const artifactBytes = bytes(input.artifactBytes, 'artifactBytes')
  const artifactHash = hashBlindClientPublicBrowserArtifact(identity.profile, artifactBytes)
  if (artifactBytes.byteLength !== manifest.artifactLength || artifactHash !== manifest.artifactHash) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_DRIFT', 'artifact bytes do not match the manifest')
  }
  const tuple = manifestTuple(manifest)
  return Object.freeze({
    profile: identity.profile,
    artifactPath: identity.artifactPath,
    sourceClosureHash: manifest.sourceClosureHash,
    tuple,
    tupleHash: manifest.tupleHash,
    manifest,
    manifestHash,
    artifactLength: manifest.artifactLength,
    artifactHash
  })
}

function chromiumEvidenceInput (value) {
  exactObject(value, CHROMIUM_EVIDENCE_FIELDS, 'Chromium evidence')
  const identity = profileIdentity(value.profile)
  if (value.schema !== CHROMIUM_EVIDENCE_SCHEMA || value.version !== 1 ||
      value.evidenceClass !== 'real-chromium' || value.artifactPath !== identity.artifactPath ||
      value.chromium !== 'Google Chrome for Testing 151.0.7922.34' ||
      value.chromiumExecutablePath !== CHROMIUM_EXECUTABLE_PATH ||
      value.chromiumExecutableHash !== '7687bff7cb2db075f250e6d5848bbc8838cac3802ac3952a899c574f8eccab45' ||
      value.contentSecurityPolicySourceCommit !== CSP_SOURCE_COMMIT ||
      value.contentSecurityPolicySourcePath !== CSP_SOURCE_PATH ||
      value.contentSecurityPolicySourceFileHash !== CSP_SOURCE_FILE_HASH ||
      value.contentSecurityPolicy !== CONTENT_SECURITY_POLICY ||
      value.contentSecurityPolicyHash !== CONTENT_SECURITY_POLICY_HASH ||
      value.candidateIdentityBinding !== CANDIDATE_IDENTITY_BINDING ||
      value.standaloneAuthority !== false ||
      value.securityPolicyViolationCount !== 0 || value.errorCount !== 0 ||
      value.unhandledRejectionCount !== 0 ||
      value.passed !== true) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_RELEASE_EVIDENCE', 'Chromium evidence has the wrong authority identity')
  }
  return Object.freeze({
    schema: CHROMIUM_EVIDENCE_SCHEMA,
    version: 1,
    evidenceClass: 'real-chromium',
    profile: identity.profile,
    artifactPath: identity.artifactPath,
    artifactLength: artifactLength(value.artifactLength),
    artifactHash: hashHex(value.artifactHash, 'Chromium artifactHash'),
    manifestHash: hashHex(value.manifestHash, 'Chromium manifestHash'),
    tupleHash: hashHex(value.tupleHash, 'Chromium tupleHash'),
    sourceClosureHash: hashHex(value.sourceClosureHash, 'Chromium sourceClosureHash'),
    chromium: boundedText(value.chromium, 'Chromium version'),
    chromiumExecutablePath: CHROMIUM_EXECUTABLE_PATH,
    chromiumExecutableHash: hashHex(value.chromiumExecutableHash, 'Chromium executable hash'),
    contentSecurityPolicySourceCommit: CSP_SOURCE_COMMIT,
    contentSecurityPolicySourcePath: CSP_SOURCE_PATH,
    contentSecurityPolicySourceFileHash: CSP_SOURCE_FILE_HASH,
    contentSecurityPolicy: CONTENT_SECURITY_POLICY,
    contentSecurityPolicyHash: hashHex(value.contentSecurityPolicyHash, 'Content-Security-Policy hash'),
    requestInventory: exactStringArray(
      value.requestInventory, identity.chromiumRequestInventory, 'Chromium request inventory'),
    securityPolicyViolationCount: exactInteger(
      value.securityPolicyViolationCount, 0, 'securityPolicyViolationCount'),
    errorCount: exactInteger(value.errorCount, 0, 'errorCount'),
    unhandledRejectionCount: exactInteger(
      value.unhandledRejectionCount, 0, 'unhandledRejectionCount'),
    candidateIdentityBinding: CANDIDATE_IDENTITY_BINDING,
    standaloneAuthority: false,
    checks: exactStringArray(value.checks, identity.chromiumChecks, 'Chromium checks'),
    passed: true
  })
}

function crossHostEvidenceInput (value) {
  exactObject(value, CROSS_HOST_EVIDENCE_FIELDS, 'cross-host evidence')
  const identity = profileIdentity(value.profile)
  if (value.schema !== CROSS_HOST_EVIDENCE_SCHEMA || value.version !== 1 ||
      value.evidenceClass !== 'clean-linux-container' || value.artifactPath !== identity.artifactPath ||
      value.acceptedSourceCommit !== ACCEPTED_SOURCE_COMMIT ||
      value.acceptedSourceTree !== ACCEPTED_SOURCE_TREE ||
      value.candidateIdentityBinding !== CANDIDATE_IDENTITY_BINDING ||
      value.standaloneAuthority !== false || value.sourceArchiveIdentity !== SOURCE_ARCHIVE_IDENTITY ||
      value.hostNodeExecutable !== HOST_NODE_EXECUTABLE ||
      value.hostNodeExecutableHash !== HOST_NODE_EXECUTABLE_HASH ||
      value.hostNode !== 'v22.22.0' || value.hostModulesAbi !== '127' ||
      value.hostNapi !== '10' || value.hostPlatform !== 'darwin' ||
      value.hostArchitecture !== 'arm64' || value.headerCachePath !== HEADER_CACHE_PATH ||
      value.headerCacheFileCount !== 2726 || value.headerCacheSymlinkCount !== 0 ||
      value.headerCacheDigest !== HEADER_CACHE_DIGEST ||
      value.headerCachePostflightDigest !== HEADER_CACHE_DIGEST ||
      value.headerCacheInstallVersion !== '11' ||
      value.headerCacheInstallVersionHash !== HEADER_INSTALL_VERSION_HASH ||
      value.headerCacheNodeHeaderPath !== HEADER_NODE_H_PATH ||
      value.headerCacheNodeHeaderBytes !== 69621 ||
      value.headerCacheNodeHeaderHash !== HEADER_NODE_H_HASH ||
      value.nativeAddonPath !== 'packages/blind-peercred/build/Release/blind_peercred.node' ||
      value.nativeAddonPackage !== '@hiverelay/blind-peercred' ||
      value.nativeAddonVersion !== '1.0.0-rc.1' ||
      value.nativeAddonArchitecture !== 'Mach-O 64-bit bundle arm64' ||
      value.sourceArchiveNativeAddonEqual !== true ||
      value.containerImageId !== CONTAINER_IMAGE_ID ||
      value.containerPlatform !== 'linux/arm64' || value.containerArchitecture !== 'arm64' ||
      value.containerNode !== 'v22.23.1' || value.containerModulesAbi !== '127' ||
      value.containerNapi !== '10' || value.containerRootReadOnly !== true ||
      value.containerCapabilitiesDropped !== true || value.containerNoNewPrivileges !== true ||
      value.installNetworkPhase !== 'networked-exact-lock-npm-ci-ignore-scripts' ||
      value.generationNetworkPhase !== 'none' ||
      value.patchApplied !== 'hypercore-storage@3.2.0' || value.patchHash !== PATCH_HASH ||
      value.containerNativeRebuild !== 'omitted-unreachable' ||
      value.fullNativeAddonReachable !== false || value.limitedNativeAddonReachable !== false ||
      value.artifactManifestByteEquality !== true || value.committedEvidenceInputsUntouched !== true ||
      value.committedEvidenceInputsProof !== 'external-f2-pre-post-sha256' ||
      value.passed !== true) {
    fail('BAD_BLIND_CLIENT_PUBLIC_BROWSER_RELEASE_EVIDENCE', 'cross-host evidence has the wrong authority identity')
  }
  return Object.freeze({
    schema: CROSS_HOST_EVIDENCE_SCHEMA,
    version: 1,
    evidenceClass: 'clean-linux-container',
    profile: identity.profile,
    artifactPath: identity.artifactPath,
    artifactLength: artifactLength(value.artifactLength),
    artifactHash: hashHex(value.artifactHash, 'cross-host artifactHash'),
    manifestHash: hashHex(value.manifestHash, 'cross-host manifestHash'),
    tupleHash: hashHex(value.tupleHash, 'cross-host tupleHash'),
    sourceClosureHash: hashHex(value.sourceClosureHash, 'cross-host sourceClosureHash'),
    acceptedSourceCommit: ACCEPTED_SOURCE_COMMIT,
    acceptedSourceTree: ACCEPTED_SOURCE_TREE,
    candidateIdentityBinding: CANDIDATE_IDENTITY_BINDING,
    standaloneAuthority: false,
    sourceArchiveIdentity: SOURCE_ARCHIVE_IDENTITY,
    hostNodeExecutable: HOST_NODE_EXECUTABLE,
    hostNodeExecutableHash: HOST_NODE_EXECUTABLE_HASH,
    hostNode: 'v22.22.0',
    hostModulesAbi: '127',
    hostNapi: '10',
    hostPlatform: 'darwin',
    hostArchitecture: 'arm64',
    headerCachePath: HEADER_CACHE_PATH,
    headerCacheFileCount: 2726,
    headerCacheSymlinkCount: 0,
    headerCacheDigest: HEADER_CACHE_DIGEST,
    headerCachePostflightDigest: HEADER_CACHE_DIGEST,
    headerCacheInstallVersion: '11',
    headerCacheInstallVersionHash: HEADER_INSTALL_VERSION_HASH,
    headerCacheNodeHeaderPath: HEADER_NODE_H_PATH,
    headerCacheNodeHeaderBytes: 69621,
    headerCacheNodeHeaderHash: HEADER_NODE_H_HASH,
    nativeAddonPath: 'packages/blind-peercred/build/Release/blind_peercred.node',
    nativeAddonPackage: '@hiverelay/blind-peercred',
    nativeAddonVersion: '1.0.0-rc.1',
    nativeAddonArchitecture: 'Mach-O 64-bit bundle arm64',
    nativeAddonHash: hashHex(value.nativeAddonHash, 'nativeAddonHash'),
    sourceArchiveNativeAddonEqual: true,
    containerImageId: CONTAINER_IMAGE_ID,
    containerPlatform: 'linux/arm64',
    containerArchitecture: 'arm64',
    containerNode: 'v22.23.1',
    containerModulesAbi: '127',
    containerNapi: '10',
    containerRootReadOnly: true,
    containerCapabilitiesDropped: true,
    containerNoNewPrivileges: true,
    installNetworkPhase: 'networked-exact-lock-npm-ci-ignore-scripts',
    generationNetworkPhase: 'none',
    patchApplied: 'hypercore-storage@3.2.0',
    patchHash: PATCH_HASH,
    containerNativeRebuild: 'omitted-unreachable',
    fullNativeAddonReachable: false,
    limitedNativeAddonReachable: false,
    normalizedGraphHash: hashHex(value.normalizedGraphHash, 'normalizedGraphHash'),
    normalizedGraphSetHash: hashHex(value.normalizedGraphSetHash, 'normalizedGraphSetHash'),
    artifactManifestByteEquality: true,
    committedEvidenceInputsUntouched: true,
    committedEvidenceInputsProof: 'external-f2-pre-post-sha256',
    toolchain: exactToolchain(value.toolchain, 'cross-host toolchain'),
    checks: exactStringArray(value.checks, identity.crossHostChecks, 'cross-host checks'),
    passed: true
  })
}

export function encodeBlindClientPublicBrowserChromiumEvidenceV1 (input) {
  return encodeCanonicalJson(chromiumEvidenceInput(input))
}

export function decodeBlindClientPublicBrowserChromiumEvidenceV1 (input) {
  return parseCanonicalJson(input, 'Chromium evidence', chromiumEvidenceInput)
}

export function encodeBlindClientPublicBrowserCrossHostEvidenceV1 (input) {
  return encodeCanonicalJson(crossHostEvidenceInput(input))
}

export function decodeBlindClientPublicBrowserCrossHostEvidenceV1 (input) {
  return parseCanonicalJson(input, 'cross-host evidence', crossHostEvidenceInput)
}

function verifyEvidenceBinding (evidence, verified, field) {
  for (const name of [
    'profile', 'artifactPath', 'artifactLength', 'artifactHash',
    'manifestHash', 'tupleHash', 'sourceClosureHash'
  ]) {
    if (evidence[name] !== verified[name]) {
      fail('BLIND_CLIENT_PUBLIC_BROWSER_RELEASE_EVIDENCE_MISMATCH',
        `${field}.${name} does not bind the verified artifact`)
    }
  }
}

export function verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1 (input) {
  allowedObject(input, [
    'profile',
    'manifestBytes',
    'artifactBytes',
    'expectedManifestHash',
    'expectedSourceClosureHash',
    'expectedNormalizedGraphHash',
    'expectedNormalizedGraphSetHash',
    'chromiumEvidenceBytes',
    'crossHostEvidenceBytes'
  ], ['expectedTupleHash'], 'release evidence verification input')
  const verified = verifyBlindClientPublicBrowserArtifactV1({
    profile: input.profile,
    manifestBytes: input.manifestBytes,
    artifactBytes: input.artifactBytes,
    expectedManifestHash: input.expectedManifestHash,
    expectedSourceClosureHash: input.expectedSourceClosureHash,
    ...(input.expectedTupleHash == null ? {} : { expectedTupleHash: input.expectedTupleHash })
  })
  const chromium = decodeBlindClientPublicBrowserChromiumEvidenceV1(input.chromiumEvidenceBytes)
  const crossHost = decodeBlindClientPublicBrowserCrossHostEvidenceV1(input.crossHostEvidenceBytes)
  verifyEvidenceBinding(chromium, verified, 'Chromium evidence')
  verifyEvidenceBinding(crossHost, verified, 'cross-host evidence')
  if (crossHost.normalizedGraphHash !==
      hashHex(input.expectedNormalizedGraphHash, 'expectedNormalizedGraphHash')) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH_MISMATCH',
      'cross-host evidence does not match the generator-computed profile graph digest')
  }
  if (crossHost.normalizedGraphSetHash !==
      hashHex(input.expectedNormalizedGraphSetHash, 'expectedNormalizedGraphSetHash')) {
    fail('BLIND_CLIENT_PUBLIC_BROWSER_NORMALIZED_GRAPH_SET_MISMATCH',
      'cross-host evidence does not match the generator-computed ordered graph set digest')
  }
  return Object.freeze({
    evidenceValid: true,
    structuralEvidenceReady: true,
    releaseReady: false,
    standaloneAuthority: false,
    candidateIdentityBinding: CANDIDATE_IDENTITY_BINDING,
    authority: 'external-postcommit-final-sequence-required',
    profile: verified.profile,
    artifactPath: verified.artifactPath,
    artifactLength: verified.artifactLength,
    artifactHash: verified.artifactHash,
    manifestHash: verified.manifestHash,
    tupleHash: verified.tupleHash,
    sourceClosureHash: verified.sourceClosureHash,
    chromium: Object.freeze({
      version: chromium.chromium,
      executablePath: chromium.chromiumExecutablePath,
      executableHash: chromium.chromiumExecutableHash,
      contentSecurityPolicyHash: chromium.contentSecurityPolicyHash,
      requestInventory: chromium.requestInventory,
      securityPolicyViolationCount: chromium.securityPolicyViolationCount,
      errorCount: chromium.errorCount,
      unhandledRejectionCount: chromium.unhandledRejectionCount
    }),
    crossHost: Object.freeze({
      candidateIdentityBinding: crossHost.candidateIdentityBinding,
      sourceArchiveIdentity: crossHost.sourceArchiveIdentity,
      hostNode: crossHost.hostNode,
      hostModulesAbi: crossHost.hostModulesAbi,
      hostNapi: crossHost.hostNapi,
      hostPlatform: crossHost.hostPlatform,
      hostArchitecture: crossHost.hostArchitecture,
      nativeAddonHash: crossHost.nativeAddonHash,
      containerImageId: crossHost.containerImageId,
      containerPlatform: crossHost.containerPlatform,
      containerArchitecture: crossHost.containerArchitecture,
      containerNode: crossHost.containerNode,
      containerModulesAbi: crossHost.containerModulesAbi,
      containerNapi: crossHost.containerNapi,
      normalizedGraphHash: crossHost.normalizedGraphHash,
      normalizedGraphSetHash: crossHost.normalizedGraphSetHash
    })
  })
}
