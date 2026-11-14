import fs from 'node:fs/promises'
import { createHash } from 'node:crypto'
import assert from 'node:assert/strict'
const root = new URL('../../', import.meta.url)
const paths = [
  'package-lock.json',
  'packages/blind-daemon/coordinator.js',
  'packages/blind-daemon/admission-coordinator.js',
  'packages/blind-daemon/core-runtime-adapter.js',
  'packages/blind-daemon/core-storage-engine-checkpoint-v1.js',
  'packages/blind-protocol/hashes.js',
  'packages/blind-protocol/schemas.js',
  'packages/blind-core-upstream-hc11-v1/index.js',
  'packages/blind-core-upstream-hc11-v1/format.js',
  'packages/blind-core-upstream-hc11-v1/format-contract.json',
  'packages/blind-core-upstream-hc11-v1/package-lock.json'
]
const files = []
for (const path of paths) files.push({ path, sha256: createHash('sha256').update(await fs.readFile(new URL(path, root))).digest('hex') })
const contract = {
  version: 1,
  profile: 'hiverelay.private.core-paid-proof-routing.v1',
  masterBase: '44f81fff03676e8285e828e2fef94be94e555bd1',
  upstreamSource: 'd0d88ba363f316fdf36bf56ce9bec286c554e107',
  upstreamProfileDigest: '1e9945d3f46d388926058015b2424c36dd37686a1001546e2b6023d5deedb70e',
  modifiesWireOrWalBytes: false,
  preAdmissionLookup: 'full canonical CORE serve request including admission bytes and independently recomputed relay-bound request commitment; bounded committed pin sizing only',
  replayAuthority: 'parent storage prepared spend/op/request validation, live exact pin, immutable source reference and proof hash, signed acknowledgement and durability fences',
  retiredBodyRead: 'only storage-owned replay after admission revalidation and coordinator budget reservation',
  files
}
const output = JSON.stringify(contract, null, 2) + '\n'
const target = new URL('./source-bindings.json', import.meta.url)
if (process.argv.includes('--check')) assert.equal(await fs.readFile(target, 'utf8'), output)
else await fs.writeFile(target, output)
console.log('private paid-proof routing bindings exact: ' + files.length + ' unchanged predecessor files')
