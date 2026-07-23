import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import * as browser from '../../packages/blind-client/browser-artifacts/blind-client-control-v3.mjs'
import { decodeCanonical } from '../../packages/blind-protocol/codec.js'
import { blindForwardHttpsOriginForwardTurnRequestV1 } from '../../packages/blind-protocol/wire-v3.js'
import {
  CLIENT_COMPOSITION_SCHEMA_V3,
  FORWARD_HTTPS_OUTSTANDING_STATE_V3,
  assertForwardHttpsSessionV3,
  assertForwardHttpsVerifiedEndpointV3,
  decodeClientCompositionV3,
  decodeClientCompositionV3SchemaCatalog
} from '../../packages/blind-protocol/client-composition-v3.js'
import {
  CLIENT_COMPOSITION_AUTHORITY_V3,
  assertClientCompositionAuthorityV3
} from '../../packages/blind-protocol/client-composition-authority-generated-v3.js'
import {
  BlindClientBrowserCrashModelV3,
  decodeBlindClientBrowserArtifactManifestV3,
  verifyBlindClientBrowserArtifactV3
} from '../../packages/blind-client/browser-artifact-v3.js'
import {
  BLIND_CLIENT_CONTROL_V3_AUTHORITY,
  prepareForwardHttpsOriginPersistenceV3
} from '../../packages/blind-client/browser-forward-state-v3.js'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..')
const read = relative => fs.readFileSync(path.join(root, relative))

function endpointFixture () {
  const value = JSON.parse(read('packages/blind-protocol/vectors-v3/client-composition/positive/forward-https-verified-endpoint-v3.json'))
  for (const field of [
    'wireV3AbiHash', 'verifiedEndpointHandleHash', 'sourceRelayPublicKey', 'sourceDescriptorHash',
    'targetCatalogEntryId', 'targetRelayPublicKey', 'targetDescriptorHash', 'signedDescriptorHash', 'signedHealthHash'
  ]) value[field] = b4a.from(value[field], 'hex')
  value.sourceDescriptorSequence = BigInt(value.sourceDescriptorSequence)
  value.targetDescriptorSequence = BigInt(value.targetDescriptorSequence)
  return value
}

function sessionFixture () {
  const endpoint = endpointFixture()
  return {
    version: 3,
    verifiedEndpoint: endpoint,
    stableSessionId: b4a.alloc(32, 0x91),
    capabilityPrefixHash: b4a.alloc(32, 0x92),
    clientSessionNonce: b4a.alloc(32, 0x93),
    nextSequence: 0n,
    previousTargetResultHash: b4a.alloc(32),
    terminal: 0,
    outstandingState: 0,
    outstandingOriginRequestCommitment: b4a.alloc(32),
    outstandingOriginRequest: b4a.alloc(0),
    lastDefinitiveTargetResult: b4a.alloc(0)
  }
}

function wireFixture () {
  const origin = read('packages/blind-protocol/vectors-v3/wire/positive/open-origin.bin')
  const request = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, origin, { copyBytes: true })
  const capability = request.parentCapability
  const endpoint = {
    version: 3,
    releaseProfileId: 2,
    routeKind: 7,
    wireV3AbiHash: b4a.from(BLIND_CLIENT_CONTROL_V3_AUTHORITY.wireV3AbiHash, 'hex'),
    verifiedEndpointHandleHash: b4a.alloc(32, 0xa1),
    sourceRelayPublicKey: capability.sourceRelayPublicKey,
    sourceDescriptorSequence: capability.sourceDescriptorSequence,
    sourceDescriptorHash: capability.sourceDescriptorHash,
    targetCatalogEntryId: capability.targetCatalogEntryId,
    targetRelayPublicKey: capability.targetRelayPublicKey,
    targetDescriptorSequence: capability.targetDescriptorSequence,
    targetDescriptorHash: capability.targetDescriptorHash,
    signedDescriptorHash: b4a.alloc(32, 0xa2),
    signedHealthHash: b4a.alloc(32, 0xa3),
    descriptorFresh: true,
    signedHealthFresh: true,
    credentialFreeHttps: true,
    cookies: false,
    authorization: false,
    referrer: false,
    redirect: false,
    exactRequestBytes: 65_536,
    exactResultBytes: 65_536,
    continuityBackend: 'INDEXEDDB_PERSISTENT'
  }
  return { origin, endpoint }
}

function publicSession (record) {
  return {
    version: 3,
    verifiedEndpoint: record.verifiedEndpoint,
    stableSessionId: record.stableSessionId,
    capabilityPrefixHash: record.capabilityPrefixHash,
    clientSessionNonce: record.clientSessionNonce,
    nextSequence: BigInt(record.nextSequence),
    previousTargetResultHash: record.previousTargetResultHash,
    terminal: record.terminal,
    outstandingState: record.outstandingState,
    outstandingOriginRequestCommitment: record.outstandingOriginRequestCommitment,
    outstandingOriginRequest: record.outstandingOriginRequest,
    lastDefinitiveTargetResult: record.lastDefinitiveTargetResult
  }
}

test('client composition v3 imports exact v2 format and WIRE v3 and allocates only IDs 9/10', t => {
  const formatBytes = read('packages/blind-protocol/hiverelay-blind-client-composition-format-v3.cenc')
  const catalogBytes = read('packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v3.cenc')
  const format = decodeClientCompositionV3(formatBytes)
  const catalog = decodeClientCompositionV3SchemaCatalog(catalogBytes)
  t.alike(CLIENT_COMPOSITION_SCHEMA_V3, {
    ForwardHttpsVerifiedEndpointV3: 9,
    ForwardHttpsSessionV3: 10
  })
  t.is(b4a.toString(format.baseClientCompositionV2FormatHash, 'hex'), 'e289e6a1658db9f63c79ae13b50a055e16eccc997ef4c752bf1c94090b91dcc2')
  t.is(b4a.toString(format.wireV3AbiHash, 'hex'), CLIENT_COMPOSITION_AUTHORITY_V3.wireV3AbiHash)
  t.is(format.baseSchemaCount, 8)
  t.alike(format.additionalSchemas.map(value => value.schemaId), [9, 10])
  t.alike(catalog.map(value => value.schemaId), [9, 10])
  t.is(format.forwardReadinessOperationBits, 0)
  t.ok(assertClientCompositionAuthorityV3(CLIENT_COMPOSITION_AUTHORITY_V3))
  t.is(CLIENT_COMPOSITION_AUTHORITY_V3.browserRuntimeReady, false)
  t.is(CLIENT_COMPOSITION_AUTHORITY_V3.authorizesRelease, false)
  t.exception(() => decodeClientCompositionV3(b4a.concat([formatBytes, b4a.from([0])])), /canonical/)
})

test('composition v3 endpoint is opaque, two-relay, persistent, and credential-free', t => {
  const fixture = endpointFixture()
  const endpoint = assertForwardHttpsVerifiedEndpointV3(fixture, fixture.wireV3AbiHash)
  t.is(endpoint.continuityBackend, 'INDEXEDDB_PERSISTENT')
  t.is(endpoint.exactRequestBytes, 65_536)
  t.is(endpoint.exactResultBytes, 65_536)
  t.not(endpoint.sourceRelayPublicKey, endpoint.targetRelayPublicKey)
  for (const forbidden of ['url', 'host', 'ip', 'dialAddress', 'credentials']) t.absent(endpoint[forbidden])
  t.exception(() => assertForwardHttpsVerifiedEndpointV3({ ...fixture, host: 'arbitrary.invalid' }), /host is forbidden/)
  t.exception(() => assertForwardHttpsVerifiedEndpointV3({ ...fixture, cookies: true }), /policy is incomplete/)
  t.exception(() => assertForwardHttpsVerifiedEndpointV3({ ...fixture, continuityBackend: 'MEMORY' }), /policy is incomplete/)
  t.exception(() => assertForwardHttpsVerifiedEndpointV3({ ...fixture, targetRelayPublicKey: fixture.sourceRelayPublicKey }), /must differ/)
})

test('composition v3 session enforces exact IndexedDB outstanding and chain invariants', t => {
  const empty = sessionFixture()
  t.is(assertForwardHttpsSessionV3(empty).outstandingState, FORWARD_HTTPS_OUTSTANDING_STATE_V3.NONE)
  t.is(assertForwardHttpsSessionV3({ ...empty, terminal: 1 }).terminal, 1)
  const fixture = wireFixture()
  const record = prepareForwardHttpsOriginPersistenceV3(null, {
    sessionKey: 'composition-test',
    verifiedEndpoint: fixture.endpoint,
    requestBytes: fixture.origin
  }).record
  const outstanding = publicSession(record)
  t.is(assertForwardHttpsSessionV3(outstanding).outstandingOriginRequest.byteLength, 65_536)
  t.exception(() => assertForwardHttpsSessionV3({ ...outstanding, outstandingOriginRequest: b4a.alloc(65_535) }), /exact 65536/)
  t.exception(() => assertForwardHttpsSessionV3({ ...empty, previousTargetResultHash: b4a.alloc(32, 1) }), /zero iff/)
  t.exception(() => assertForwardHttpsSessionV3({ ...empty, outstandingState: 0, outstandingOriginRequestCommitment: b4a.alloc(32, 1) }), /NONE/)
  t.exception(() => assertForwardHttpsSessionV3({ ...outstanding, terminal: 1 }), /terminal session/)
  t.exception(() => assertForwardHttpsSessionV3({ ...outstanding, capabilityPrefixHash: b4a.alloc(32, 9) }), /session state/)
})

test('browser v3 manifest has exact HRBCBV03 214-byte layout and pins complete closure', t => {
  const artifact = read('packages/blind-client/browser-artifacts/blind-client-control-v3.mjs')
  const manifestBytes = read('packages/blind-client/browser-artifacts/blind-client-control-v3.manifest.cenc')
  const closure = read('packages/blind-client/browser-artifacts/blind-client-control-v3.source-closure.json')
  const authority = JSON.parse(read('packages/blind-client/browser-artifacts/blind-client-control-v3.authority.json'))
  const manifest = decodeBlindClientBrowserArtifactManifestV3(manifestBytes)
  t.is(manifestBytes.byteLength, 214)
  t.is(b4a.toString(manifestBytes.subarray(0, 8), 'ascii'), 'HRBCBV03')
  t.is(manifestBytes[8], 0)
  t.is(manifestBytes[9], 3)
  t.is(manifest.exactRequestBytes, 65_536)
  t.is(manifest.exactResultBytes, 65_536)
  t.is(manifest.forwardReadinessOperationBits, 0)
  t.ok(verifyBlindClientBrowserArtifactV3(artifact, manifestBytes, closure, {
    wireV3AbiHash: b4a.from(authority.wireV3AbiHash, 'hex'),
    clientCompositionV3FormatHash: b4a.from(authority.clientCompositionV3FormatHash, 'hex'),
    baseBrowserV2ArtifactHash: b4a.from(authority.baseBrowserV2ArtifactHash, 'hex'),
    baseBrowserV2ManifestHash: b4a.from(authority.baseBrowserV2ManifestHash, 'hex')
  }))
  const sourceClosure = JSON.parse(closure)
  const entries = sourceClosure.entries
  t.is(sourceClosure.schema, 'HiveRelayBlindClientBrowserSourceClosureV3')
  t.is(sourceClosure.toolchain, 'esbuild@0.28.1')
  t.alike(sourceClosure.externalArtifacts, ['./blind-client-control-v2.mjs'])
  t.ok(sourceClosure.metafileInputs.length > 0)
  for (const required of [
    'package.json',
    'packages/blind-client/package.json',
    'packages/blind-client/browser-artifact-v3.js',
    'packages/blind-client/browser-forward-state-v3.js',
    'packages/blind-client/generate-browser-artifact-v3.mjs',
    'packages/blind-client/browser-artifacts/blind-client-control-v2.mjs',
    'packages/blind-protocol/hiverelay-blind-abi-v3.cenc',
    'packages/blind-protocol/hiverelay-blind-wire-authority-v3.json',
    'packages/blind-protocol/hiverelay-blind-client-composition-format-v3.cenc',
    'packages/blind-protocol/hiverelay-blind-client-composition-authority-v3.json'
  ]) t.ok(entries.some(entry => entry.path === required), `closure includes ${required}`)
  t.is(authority.runtimeReady, false)
  t.is(authority.realBrowserEvidenceAccepted, false)
  t.is(authority.authorizesRelease, false)
  t.is(authority.forwardDescriptorOperationBits, 0)
  t.is(authority.forwardAdvertisedOperationBits, 0)
  t.is(authority.forwardReadinessOperationBits, 0)
  t.is(authority.toolchain, 'esbuild@0.28.1')
  t.alike(authority.externalArtifacts, ['./blind-client-control-v2.mjs'])
})

test('browser crash model persists before fetch, retries exact bytes, advances atomically, and retains source results', t => {
  const fixture = wireFixture()
  const input = { sessionKey: 'model', verifiedEndpoint: fixture.endpoint, requestBytes: fixture.origin }
  const model = new BlindClientBrowserCrashModelV3()
  t.exception(() => model.beginFetch(), /before exact request persistence/)
  model.persistBeforeFetch(input)
  const sent = model.beginFetch()
  t.alike(sent, fixture.origin)
  sent[0] ^= 1
  t.alike(model.restartExactRetry(), fixture.origin)
  const sourceResult = read('packages/blind-protocol/vectors-v3/wire/positive/open-source-pre-forward-error.bin')
  t.is(model.receiveResult(sourceResult).advanced, false)
  t.is(model.nextSequence, 0n)
  t.alike(model.restartExactRetry(), fixture.origin)
  const targetResult = read('packages/blind-protocol/vectors-v3/wire/positive/open-target-result.bin')
  t.is(model.receiveResult(targetResult).advanced, true)
  t.is(model.nextSequence, 1n)
  t.alike(model.lastDefinitiveTargetResult, targetResult)
  t.absent(model.outstanding)
  t.absent(model.receiveSourceResult)
  t.absent(model.receiveTargetResult)
  const inspected = model.inspectRecord()
  inspected.stableSessionId[0] ^= 1
  model.record = { forged: true }
  t.is(model.nextSequence, 1n)
  t.alike(model.inspectRecord().lastDefinitiveTargetResult, targetResult)
})

test('generated browser v3 module exposes IndexedDB transaction controls while fail-closed', t => {
  t.is(browser.BLIND_CLIENT_CONTROL_V3_AUTHORITY.runtimeReady, false)
  t.is(browser.BLIND_CLIENT_CONTROL_V3_AUTHORITY.realBrowserEvidenceAccepted, false)
  t.is(browser.BLIND_CLIENT_CONTROL_V3_AUTHORITY.authorizesRelease, false)
  for (const name of [
    'openForwardHttpsIndexedDbV3',
    'persistForwardHttpsOriginBeforeFetchV3',
    'loadForwardHttpsSessionV3',
    'fetchPersistedForwardHttpsOriginV3',
    'retryPersistedForwardHttpsOriginV3',
    'commitVerifiedForwardHttpsResultV3'
  ]) t.is(typeof browser[name], 'function')
})
