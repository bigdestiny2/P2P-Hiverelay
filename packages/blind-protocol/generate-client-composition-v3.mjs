import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import b4a from 'b4a'
import {
  encodeVectorManifest,
  hashAbi,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet,
  hashSpec
} from './hashes.js'
import {
  CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS,
  createClientCompositionV3Value,
  encodeClientCompositionV3,
  encodeClientCompositionV3SchemaCatalog
} from './client-composition-v3.js'

const check = process.argv.includes('--check')
const root = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(root, '../..')
const vectorRoot = path.join(root, 'vectors-v3/client-composition')
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')

const compatibilityFloor = Object.freeze({
  'hiverelay-blind-client-composition-authority-v1.json': '4b1cd5835a2952b5e06914e59890ad2ebb4fa085cbc294a79e24b91ff20ed160',
  'hiverelay-blind-client-composition-format-v1.cenc': 'a525dc297bf8771ecb7a9204b5b3c031bd292991b210421f3fa713619e296b60',
  'hiverelay-blind-client-composition-schema-catalog-v1.cenc': '8ff920aece109f681f94ee655c9f273f78c66013fcff818bc40df86b867bb97f',
  'hiverelay-blind-client-composition-vector-manifest-v1.cenc': 'b26ab9a86ccd665255ee17dd742ffc39acceeb670bc01a7f7633460cb9d7cee9',
  'client-composition-authority-generated.js': 'a66d7211bdedd3b0d0e580c7d6c504584001ee1bf5747ad9b27d8ee5e2b566aa',
  'hiverelay-blind-client-composition-authority-v2.json': '76ec2bb659ac9efd345779256a116b3f8f051c81f47df4bff57f0b8d450479d0',
  'hiverelay-blind-client-composition-format-v2.cenc': 'fe183dbaf484007b27bb9c2616cc6e66071a70d65f3cfc23779aa24193cd251d',
  'hiverelay-blind-client-composition-schema-catalog-v2.cenc': '8d80f0ac2875eb52afd17b46b67b437992dda02777c6a78907d063b657122b05',
  'hiverelay-blind-client-composition-vector-manifest-v2.cenc': '0cd2174a1b2404cfd7c8703fa18db5cd91cc995d9af2d58c1d827d91c97e1b0c',
  'client-composition-authority-generated-v2.js': '2a9600023a51f841bcc51268e8d89f11ee702a77af59dc1a212a44d7aedc14a8',
  'client-composition-v2.js': 'dc314b1319b667ce2d1df042f65bb9aa61c743cef5ca3fdf128ced8662e33839'
})

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(root, relative)))
    if (actual !== expected) throw new Error(`frozen client composition v1/v2 artifact changed: ${relative} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated client composition v3 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated client composition v3 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

await assertCompatibilityFloor()

const v2FormatBytes = await fs.readFile(path.join(root, 'hiverelay-blind-client-composition-format-v2.cenc'))
const baseFormatHash = hashClientCompositionFormat(v2FormatBytes)
if (hex(baseFormatHash) !== 'e289e6a1658db9f63c79ae13b50a055e16eccc997ef4c752bf1c94090b91dcc2') {
  throw new Error('frozen client composition v2 format hash mismatch')
}
const wireV3AbiBytes = await fs.readFile(path.join(root, 'hiverelay-blind-abi-v3.cenc'))
const wireV3AbiHash = hashAbi(wireV3AbiBytes)
const wireAuthority = JSON.parse(await fs.readFile(path.join(root, 'hiverelay-blind-wire-authority-v3.json'), 'utf8'))
if (hex(wireV3AbiHash) !== wireAuthority.abiHash) throw new Error('WIRE v3 ABI hash does not match generated authority')
const formatBytes = encodeClientCompositionV3(createClientCompositionV3Value(baseFormatHash, wireV3AbiHash))
const catalogBytes = encodeClientCompositionV3SchemaCatalog()
const specBytes = await fs.readFile(path.join(repoRoot, 'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V3.md'))

const endpointFixture = {
  version: 3,
  releaseProfileId: 2,
  routeKind: 7,
  wireV3AbiHash: hex(wireV3AbiHash),
  verifiedEndpointHandleHash: '11'.repeat(32),
  sourceRelayPublicKey: '22'.repeat(32),
  sourceDescriptorSequence: '11',
  sourceDescriptorHash: '33'.repeat(32),
  targetCatalogEntryId: '44'.repeat(32),
  targetRelayPublicKey: '55'.repeat(32),
  targetDescriptorSequence: '22',
  targetDescriptorHash: '66'.repeat(32),
  signedDescriptorHash: '77'.repeat(32),
  signedHealthHash: '88'.repeat(32),
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
const sessionFixture = {
  version: 3,
  verifiedEndpoint: endpointFixture,
  stableSessionId: '91'.repeat(32),
  capabilityPrefixHash: '92'.repeat(32),
  clientSessionNonce: '93'.repeat(32),
  nextSequence: '0',
  previousTargetResultHash: '00'.repeat(32),
  terminal: 0,
  outstandingState: 0,
  outstandingOriginRequestCommitment: '00'.repeat(32),
  outstandingOriginRequest: '',
  lastDefinitiveTargetResult: ''
}
const vectorFiles = [
  { path: 'registry/client-composition-format-v3.cenc', bytes: formatBytes },
  { path: 'registry/client-composition-schema-catalog-v3.cenc', bytes: catalogBytes },
  { path: 'registry/compatibility-floor.json', bytes: json(compatibilityFloor) },
  { path: 'positive/forward-https-verified-endpoint-v3.json', bytes: json(endpointFixture) },
  { path: 'positive/forward-https-session-empty-v3.json', bytes: json(sessionFixture) },
  {
    path: 'negative/expectations.json',
    bytes: json({
      'caller-url-host-ip-dial-or-credential-fields': 'unrepresentable-and-rejected',
      'source-target-relay-key-equality': 'reject',
      'non-persistent-continuity': 'reject',
      'cookies-authorization-referrer-or-redirect': 'reject',
      'outstanding-request-not-exactly-65536': 'reject',
      'outstanding-state-or-zero-invariant': 'reject',
      'target-result-sequence-or-chain-invariant': 'reject',
      'forward-readiness-before-independent-acceptance': 'zero'
    })
  }
]
const manifestBytes = encodeVectorManifest(vectorFiles)
const authority = {
  profile: 'client-composition-authority-v3',
  authorityVersion: 3,
  formatMajor: 3,
  formatMinor: 0,
  specificationArtifact: 'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V3.md',
  formatAuthorityArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-format-v3.cenc',
  schemaCatalogArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v3.cenc',
  vectorManifestArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v3.cenc',
  vectorRoot: 'packages/blind-protocol/vectors-v3/client-composition',
  baseClientCompositionV2FormatHash: hex(baseFormatHash),
  wireV3AbiHash: hex(wireV3AbiHash),
  formatHash: hex(hashClientCompositionFormat(formatBytes)),
  specificationHash: hex(hashSpec(specBytes)),
  vectorSetHash: hex(hashClientCompositionVectorSet(manifestBytes)),
  baseSchemaCount: 8,
  additionalSchemas: CLIENT_COMPOSITION_V3_SCHEMA_DECLARATIONS,
  schemaCount: 10,
  vectorCount: vectorFiles.length,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  browserRuntimeReady: false,
  authorizesRelease: false,
  compatibilityFloor
}
const generatedSource = '/* eslint-disable */\n// Generated by generate-client-composition-v3.mjs. Do not edit.\n' +
  `export const CLIENT_COMPOSITION_AUTHORITY_V3 = Object.freeze(${JSON.stringify(authority, null, 2)})\n` +
  'export function assertClientCompositionAuthorityV3 (actual) {\n' +
  '  if (!actual || actual.formatHash !== CLIENT_COMPOSITION_AUTHORITY_V3.formatHash ||\n' +
  '      actual.wireV3AbiHash !== CLIENT_COMPOSITION_AUTHORITY_V3.wireV3AbiHash ||\n' +
  '      actual.baseClientCompositionV2FormatHash !== CLIENT_COMPOSITION_AUTHORITY_V3.baseClientCompositionV2FormatHash ||\n' +
  '      actual.schemaCount !== 10 || actual.forwardReadinessOperationBits !== 0 ||\n' +
  '      actual.browserRuntimeReady !== false || actual.authorizesRelease !== false) {\n' +
  '    throw new Error(\'client composition v3 authority mismatch\')\n' +
  '  }\n' +
  '  return true\n' +
  '}\n'

const outputs = [
  [path.join(root, 'hiverelay-blind-client-composition-format-v3.cenc'), formatBytes],
  [path.join(root, 'hiverelay-blind-client-composition-schema-catalog-v3.cenc'), catalogBytes],
  [path.join(root, 'hiverelay-blind-client-composition-vector-manifest-v3.cenc'), manifestBytes],
  [path.join(root, 'hiverelay-blind-client-composition-authority-v3.json'), json(authority)],
  [path.join(root, 'client-composition-authority-generated-v3.js'), b4a.from(generatedSource)]
]
for (const vector of vectorFiles) outputs.push([path.join(vectorRoot, vector.path), vector.bytes])
for (const [file, bytes] of outputs) await writeOrCheck(file, bytes)

if (check) {
  const expected = new Set(vectorFiles.map(vector => vector.path))
  async function walk (directory, prefix = '') {
    const found = []
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.isDirectory()) found.push(...await walk(path.join(directory, entry.name), relative))
      else found.push(relative)
    }
    return found
  }
  for (const found of await walk(vectorRoot)) if (!expected.has(found)) throw new Error(`unexpected client composition v3 vector: ${found}`)
}

console.log(check ? 'client composition v3 authority verified' : 'client composition v3 authority generated')
