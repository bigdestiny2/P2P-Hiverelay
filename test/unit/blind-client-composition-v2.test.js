import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import * as browser from '../../packages/blind-client/browser-artifacts/blind-client-control-v2.mjs'
import {
  CLIENT_COMPOSITION_SCHEMA_V2,
  assertForwardHttpsVerifiedEndpointV2,
  decodeClientCompositionV2,
  decodeClientCompositionV2SchemaCatalog
} from '../../packages/blind-protocol/client-composition-v2.js'
import {
  CLIENT_COMPOSITION_AUTHORITY_V2,
  assertClientCompositionAuthorityV2
} from '../../packages/blind-protocol/client-composition-authority-generated-v2.js'
import {
  decodeBlindClientBrowserArtifactManifestV2,
  verifyBlindClientBrowserArtifactV2
} from '../../packages/blind-client/browser-artifact-v2.js'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..')
const read = relative => fs.readFileSync(path.join(root, relative))

test('client composition v2 is additive, WIRE-hash pinned and readiness zero', t => {
  const format = decodeClientCompositionV2(read('packages/blind-protocol/hiverelay-blind-client-composition-format-v2.cenc'))
  const catalog = decodeClientCompositionV2SchemaCatalog(read('packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v2.cenc'))
  t.alike(CLIENT_COMPOSITION_SCHEMA_V2, {
    ForwardHttpsVerifiedEndpointV2: 7,
    ForwardHttpsSessionV2: 8
  })
  t.is(format.baseSchemaCount, 6)
  t.alike(format.additionalSchemas.map(schema => schema.schemaId), [7, 8])
  t.alike(catalog.map(schema => schema.schemaId), [7, 8])
  t.is(b4a.toString(format.wireV2AbiHash, 'hex'), CLIENT_COMPOSITION_AUTHORITY_V2.wireV2AbiHash)
  t.is(format.forwardReadinessOperationBits, 0)
  t.ok(assertClientCompositionAuthorityV2(CLIENT_COMPOSITION_AUTHORITY_V2))
  t.is(CLIENT_COMPOSITION_AUTHORITY_V2.browserRuntimeReady, false)
})

test('composition v2 endpoint is opaque, persistent and credential-free', t => {
  const fixture = JSON.parse(read('packages/blind-protocol/vectors-v2/client-composition/positive/forward-https-verified-endpoint-v2.json'))
  for (const field of [
    'wireV2AbiHash', 'verifiedEndpointHandleHash', 'targetCatalogEntryId', 'targetRelayPublicKey',
    'targetDescriptorHash', 'signedDescriptorHash', 'signedHealthHash'
  ]) fixture[field] = b4a.from(fixture[field], 'hex')
  fixture.targetDescriptorSequence = BigInt(fixture.targetDescriptorSequence)
  const endpoint = assertForwardHttpsVerifiedEndpointV2(fixture, b4a.from(CLIENT_COMPOSITION_AUTHORITY_V2.wireV2AbiHash, 'hex'))
  t.is(endpoint.continuityBackend, 'INDEXEDDB_PERSISTENT')
  t.is(endpoint.exactRequestBytes, 65_536)
  t.exception(() => assertForwardHttpsVerifiedEndpointV2({ ...fixture, host: 'arbitrary.invalid' }), /host is forbidden/)
  t.exception(() => assertForwardHttpsVerifiedEndpointV2({ ...fixture, cookies: true }), /trust or privacy policy is incomplete/)
  t.exception(() => assertForwardHttpsVerifiedEndpointV2({ ...fixture, continuityBackend: 'MEMORY' }), /trust or privacy policy is incomplete/)
})

test('browser v2 artifact binds v1, WIRE v2, composition v2 and remains disabled', t => {
  const artifact = read('packages/blind-client/browser-artifacts/blind-client-control-v2.mjs')
  const manifestBytes = read('packages/blind-client/browser-artifacts/blind-client-control-v2.manifest.cenc')
  const authority = JSON.parse(read('packages/blind-client/browser-artifacts/blind-client-control-v2.authority.json'))
  const manifest = decodeBlindClientBrowserArtifactManifestV2(manifestBytes)
  t.is(manifest.forwardReadinessOperationBits, 0)
  t.is(manifest.exactRequestBytes, 65_536)
  t.ok(verifyBlindClientBrowserArtifactV2(artifact, manifestBytes, {
    wireV2AbiHash: b4a.from(authority.wireV2AbiHash, 'hex'),
    clientCompositionV2FormatHash: b4a.from(authority.clientCompositionV2FormatHash, 'hex')
  }))
  t.is(authority.runtimeReady, false)
  t.is(authority.realBrowserEvidenceAccepted, false)

  t.is(browser.BLIND_CLIENT_CONTROL_V2_AUTHORITY.runtimeReady, false)
  const body = new Uint8Array(65_536)
  t.is(browser.assertForwardHttpsBrowserCellV2({
    releaseProfileId: 2,
    routeKind: 7,
    body,
    credentialsMode: 'omit',
    cacheMode: 'no-store',
    redirectMode: 'error',
    referrerPolicy: 'no-referrer'
  }).body.byteLength, 65_536)
  t.exception.all(() => browser.assertForwardHttpsBrowserCellV2({
    releaseProfileId: 2,
    routeKind: 7,
    body,
    credentialsMode: 'omit',
    cacheMode: 'no-store',
    redirectMode: 'error',
    referrerPolicy: 'no-referrer',
    url: 'https://arbitrary.invalid'
  }), /url is forbidden/)
})
