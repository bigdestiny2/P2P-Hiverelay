import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { artifactBytes, canonicalJSON, encode, formatHash, snapshotHash, participantHash, validatorSha256 } from './codec.js'
import { positives } from './fixtures.js'
import { negatives } from './cases.js'
const args = process.argv.slice(2)
const check = args.includes('--check')
const index = args.indexOf('--out')
if (index < 0 || !args[index + 1]) throw new Error('--out directory is required')
const dir = resolve(args[index + 1])
const artifacts = []
function output (name, bytes) {
  const path = resolve(dir, name)
  if (check) { if (!readFileSync(path).equals(Buffer.from(bytes))) throw new Error(`generated drift: ${name}`) } else { mkdirSync(resolve(path, '..'), { recursive: true }); writeFileSync(path, bytes) }
  artifacts.push({ path: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') })
}
output('format-authority-v2.json', artifactBytes())
const bindings = JSON.parse(readFileSync(new URL('../../../contracts/hiverelay/027-checkpoint-format/source-bindings.json', import.meta.url)))
for (const entry of bindings.source) {
  const bytes = readFileSync(new URL('../../../' + entry.path, import.meta.url))
  if (bytes.length !== entry.bytes || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error(`protected source drift: ${entry.path}`)
}
bindings.successor_predecessor_commit = '699154da16a0be40b92134335bc0b113eb5c30a9'
bindings.format_hash = formatHash().toString('hex')
bindings.validator_sha256 = validatorSha256
bindings.private_source = readdirSync(new URL('./', import.meta.url), { withFileTypes: true }).filter(entry => entry.isFile()).map(entry => entry.name).sort().map(name => {
  const bytes = readFileSync(new URL('./' + name, import.meta.url))
  return { path: 'packages/blind-protocol/checkpoint-format-successor/' + name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
})
output('source-bindings.json', Buffer.from(JSON.stringify(bindings, null, 2) + '\n'))
const vectors = []
for (const [id, type, value] of positives()) {
  const bytes = encode(type, value)
  output(`vectors/${id}.bin`, bytes)
  vectors.push({ id, type, value, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length, domainHash: type === 'Snapshot' ? snapshotHash(value) : type === 'Participants' ? participantHash(value) : null })
}
output('vectors/positive.json', Buffer.from(canonicalJSON(vectors) + '\n'))
output('vectors/negative.json', Buffer.from(canonicalJSON(negatives()) + '\n'))
const manifest = { schema: 'hiverelay.private-checkpoint-vectors.v2', formatMajor: 2, formatMinor: 0, formatHash: formatHash().toString('hex'), positiveCount: vectors.length, negativeCount: negatives().length, syntheticStructuralFixtures: true, runtimeAuthority: false, artifacts }
const bytes = Buffer.from(canonicalJSON(manifest) + '\n')
if (check) { if (!readFileSync(resolve(dir, 'vectors-manifest.json')).equals(bytes)) throw new Error('manifest drift') } else writeFileSync(resolve(dir, 'vectors-manifest.json'), bytes)
console.log(JSON.stringify({ check, output: dir, positive: vectors.length, negative: negatives().length, formatHash: formatHash().toString('hex') }))
