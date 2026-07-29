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
  CLIENT_COMPOSITION_V2_SCHEMA_DECLARATIONS,
  createClientCompositionV2Value,
  encodeClientCompositionV2,
  encodeClientCompositionV2SchemaCatalog
} from './client-composition-v2.js'

const check = process.argv.includes('--check')
const root = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(root, '../..')
const vectorRoot = path.join(root, 'vectors-v2/client-composition')
const legacyVectorRoot = path.join(root, 'vectors/client-composition-v2')
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`)

const compatibilityFloor = Object.freeze({
  'hiverelay-blind-client-composition-authority-v1.json': '4b1cd5835a2952b5e06914e59890ad2ebb4fa085cbc294a79e24b91ff20ed160',
  'hiverelay-blind-client-composition-format-v1.cenc': 'a525dc297bf8771ecb7a9204b5b3c031bd292991b210421f3fa713619e296b60',
  'hiverelay-blind-client-composition-schema-catalog-v1.cenc': '8ff920aece109f681f94ee655c9f273f78c66013fcff818bc40df86b867bb97f',
  'hiverelay-blind-client-composition-vector-manifest-v1.cenc': 'b26ab9a86ccd665255ee17dd742ffc39acceeb670bc01a7f7633460cb9d7cee9',
  'client-composition-authority-generated.js': 'a66d7211bdedd3b0d0e580c7d6c504584001ee1bf5747ad9b27d8ee5e2b566aa'
})

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(root, relative)))
    if (actual !== expected) throw new Error(`frozen client composition v1 artifact changed: ${relative} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated client composition v2 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated client composition v2 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

await assertCompatibilityFloor()
if (!check) await fs.rm(legacyVectorRoot, { recursive: true, force: true })

const v1FormatBytes = await fs.readFile(path.join(root, 'hiverelay-blind-client-composition-format-v1.cenc'))
const baseFormatHash = hashClientCompositionFormat(v1FormatBytes)
const wireV2AbiBytes = await fs.readFile(path.join(root, 'hiverelay-blind-abi-v2.cenc'))
const wireV2AbiHash = hashAbi(wireV2AbiBytes)
const value = createClientCompositionV2Value(baseFormatHash, wireV2AbiHash)
const formatBytes = encodeClientCompositionV2(value)
const catalogBytes = encodeClientCompositionV2SchemaCatalog()
const specBytes = await fs.readFile(path.join(repoRoot, 'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V2.md'))

const endpointFixture = {
  version: 2,
  releaseProfileId: 2,
  routeKind: 7,
  wireV2AbiHash: hex(wireV2AbiHash),
  verifiedEndpointHandleHash: '11'.repeat(32),
  targetCatalogEntryId: '22'.repeat(32),
  targetRelayPublicKey: '33'.repeat(32),
  targetDescriptorSequence: '22',
  targetDescriptorHash: '44'.repeat(32),
  signedDescriptorHash: '55'.repeat(32),
  signedHealthHash: '66'.repeat(32),
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
const vectorFiles = [
  { path: 'registry/client-composition-format-v2.cenc', bytes: formatBytes },
  { path: 'registry/client-composition-schema-catalog-v2.cenc', bytes: catalogBytes },
  { path: 'registry/compatibility-floor.json', bytes: json(compatibilityFloor) },
  { path: 'positive/forward-https-verified-endpoint-v2.json', bytes: json(endpointFixture) },
  {
    path: 'negative/expectations.json',
    bytes: json({
      'caller-url-host-ip-dial-fields': 'unrepresentable-and-rejected',
      'non-persistent-continuity': 'reject',
      'cookies-authorization-referrer-or-redirect': 'reject',
      'forward-readiness-before-independent-acceptance': 'zero'
    })
  }
]
const manifestBytes = encodeVectorManifest(vectorFiles)
const authority = {
  profile: 'client-composition-authority-v2',
  authorityVersion: 2,
  formatMajor: 2,
  formatMinor: 0,
  specificationArtifact: 'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V2.md',
  formatAuthorityArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-format-v2.cenc',
  schemaCatalogArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v2.cenc',
  vectorManifestArtifact: 'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v2.cenc',
  vectorRoot: 'packages/blind-protocol/vectors-v2/client-composition',
  baseCompositionV1FormatHash: hex(baseFormatHash),
  wireV2AbiHash: hex(wireV2AbiHash),
  formatHash: hex(hashClientCompositionFormat(formatBytes)),
  specificationHash: hex(hashSpec(specBytes)),
  vectorSetHash: hex(hashClientCompositionVectorSet(manifestBytes)),
  baseSchemaCount: 6,
  additionalSchemas: CLIENT_COMPOSITION_V2_SCHEMA_DECLARATIONS,
  schemaCount: 8,
  vectorCount: vectorFiles.length,
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  browserRuntimeReady: false,
  compatibilityFloor
}
const generatedSource = '/* eslint-disable */\n// Generated by generate-client-composition-v2.mjs. Do not edit.\n' +
  `export const CLIENT_COMPOSITION_AUTHORITY_V2 = Object.freeze(${JSON.stringify(authority, null, 2)})\n` +
  'export function assertClientCompositionAuthorityV2 (actual) {\n' +
  '  if (!actual || actual.formatHash !== CLIENT_COMPOSITION_AUTHORITY_V2.formatHash ||\n' +
  '      actual.wireV2AbiHash !== CLIENT_COMPOSITION_AUTHORITY_V2.wireV2AbiHash ||\n' +
  '      actual.schemaCount !== 8 || actual.forwardReadinessOperationBits !== 0 || actual.browserRuntimeReady !== false) {\n' +
  '    throw new Error(\'client composition v2 authority mismatch\')\n' +
  '  }\n' +
  '  return true\n' +
  '}\n'

const outputs = [
  [path.join(root, 'hiverelay-blind-client-composition-format-v2.cenc'), formatBytes],
  [path.join(root, 'hiverelay-blind-client-composition-schema-catalog-v2.cenc'), catalogBytes],
  [path.join(root, 'hiverelay-blind-client-composition-vector-manifest-v2.cenc'), manifestBytes],
  [path.join(root, 'hiverelay-blind-client-composition-authority-v2.json'), json(authority)],
  [path.join(root, 'client-composition-authority-generated-v2.js'), b4a.from(generatedSource)]
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
  for (const found of await walk(vectorRoot)) {
    if (!expected.has(found)) throw new Error(`unexpected client composition v2 vector: ${found}`)
  }
}

console.log(check ? 'client composition v2 authority verified' : 'client composition v2 authority generated')
