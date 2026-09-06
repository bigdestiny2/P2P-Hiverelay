import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { createHash } from 'node:crypto'
import { artifactBytes, canonicalJSON, encode, formatHash, snapshotHash, participantHash } from './codec.js'
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
