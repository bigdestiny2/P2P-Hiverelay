import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFileSync } from 'node:fs'
import { encode, decode, canonicalJSON, formatHash, artifactBytes, assertSnapshotSuccessor, assertParticipantsSuccessor, participantHash, compatibility, predecessorPins, validatorSha256 } from './codec.js'
import { positives, successor, clone, H, lifecycleSuccessors } from './fixtures.js'
import { negatives } from './cases.js'
const checks = []
const check = (name, fn) => { fn(); checks.push(name); console.log(`ok ${checks.length} - ${name}`) }
for (const [id, type, input] of positives()) {
  check(`${id} canonical roundtrip`, () => { const bytes = encode(type, input); assert.equal(canonicalJSON(decode(type, bytes)), canonicalJSON(input)); assert.deepEqual(encode(type, decode(type, bytes)), bytes) })
  if (type === 'Snapshot' && id !== 'u64-high-checkpoint') check(`${id} successor`, () => assert.equal(assertSnapshotSuccessor(input, successor(input)), true))
}
for (const c of negatives()) {
  check(c.id, () => assert.throws(() => {
    if (c.mode === 'encode') encode(c.type, c.input)
    if (c.mode === 'decode') decode(c.type, c.input)
    if (c.mode === 'snapshot-successor') assertSnapshotSuccessor(c.previous, c.input)
    if (c.mode === 'participants-successor') assertParticipantsSuccessor(c.previous, c.input)
  }, new RegExp(c.pattern)))
}
for (const [id, previous, next] of lifecycleSuccessors()) check(`${id} relation`, () => assert.equal(assertSnapshotSuccessor(previous, next), true))
check('authority byte export cannot mutate format hash', () => { const before = formatHash(); artifactBytes().fill(0); assert.deepEqual(formatHash(), before) })
check('participant unchanged coverage successor', () => {
  const previous = positives().find(([id]) => id === 'typed-four-participants')[2]; const next = clone(previous)
  next.revision++; next.previousAuthorityHash = participantHash(previous)
  assert.equal(assertParticipantsSuccessor(previous, next), true)
})
check('explicit compatibility/refusal matrix', () => {
  assert.equal(compatibility({ major: 2, minor: 0, hash: formatHash(), reader: 'candidate-codec', genesisAvailable: false }), 'DECODE_ONLY_NO_RUNTIME_AUTHORITY')
  assert.equal(compatibility({ major: 2, minor: 0, hash: formatHash(), reader: 'frozen-runtime' }), 'REFUSE_UNSUPPORTED_FORMAT')
  assert.equal(compatibility({ major: 1, minor: 2, reader: 'candidate-codec', genesisAvailable: true }), 'REQUIRE_FROZEN_AUTHORITY_AND_FULL_WAL_READER')
  assert.equal(compatibility({ major: 1, minor: 2, reader: 'candidate-codec', genesisAvailable: false }), 'REFUSE_PRUNED_PREDECESSOR')
  assert.equal(compatibility({ major: 2, minor: 0, hash: H(90), reader: 'candidate-codec' }), 'REFUSE_UNKNOWN_FORMAT')
})
check('all frozen codec dependencies match exact pins', () => {
  assert.equal(createHash('sha256').update(readFileSync(new URL('./codec.js', import.meta.url))).digest('hex'), validatorSha256)
  for (const [path, hash] of Object.entries(predecessorPins)) assert.equal(createHash('sha256').update(readFileSync(new URL('../' + path, import.meta.url))).digest('hex'), hash)
})
const require = createRequire(import.meta.url)
console.log(JSON.stringify({ tests: checks.length, pass: true, runtime: process.versions, platform: process.platform, arch: process.arch, executable: process.execPath, formatHash: formatHash().toString('hex'), sodium: require.resolve('sodium-native'), executableSha256: createHash('sha256').update(readFileSync(process.execPath)).digest('hex'), loadedNativeObjects: process.report.getReport().sharedObjects.filter(p => p.includes('sodium') || p.includes('libnode')).map(path => ({ path, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') })), fixturesAreAuthority: false }))
