import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { constants, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const native = fileURLToPath(new URL('../native/', import.meta.url))
const require = createRequire(import.meta.url)
const selectNativeFlags = require('../native/targets.cjs')
const hash = bytes => createHash('sha256').update(bytes).digest('hex')

test('retains the accepted macOS artifact and selects only qualified runtime targets', () => {
  const bytes = readFileSync(join(native, 'flags-darwin-arm64.cjs'))
  assert.equal(hash(bytes), '70f171c86b5443165f0df4f41f0ae916e5bc7a085131d0c8797f3d12a48c1749')
  const selected = selectNativeFlags('darwin', 'arm64', 'v1.31.0')
  assert.equal(selected.platform, 'darwin')
  assert.equal(selected.arch, 'arm64')
  assert.equal(selected.sourceSha256, hash(readFileSync(join(native, 'flags.c'))))
  for (const [platform, arch, version] of [
    ['linux', 'x64', 'v1.31.0'], ['linux', 'arm64', 'v1.31.0'],
    ['darwin', 'x64', 'v1.31.0'], ['win32', 'arm64', 'v1.31.0'],
    ['darwin', 'arm64', 'v1.29.4'], ['darwin', 'arm64', 'v1.24.3'],
    ['darwin', 'arm64', 'v1.32.0'], ['darwin', 'arm64', undefined]
  ]) {
    assert.throws(() => selectNativeFlags(platform, arch, version), { code: 'INTENT_STORE_PLATFORM' })
  }
})

test('native build isolates targets and refuses to overwrite different reviewed bytes', t => {
  const directory = mkdtempSync(join(tmpdir(), 'intent-native-targets-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  for (const name of ['build.mjs', 'flags.c']) copyFileSync(join(native, name), join(directory, name))
  const target = process.platform + '-' + process.arch
  const otherTarget = target === 'linux-x64' ? 'darwin-arm64' : 'linux-x64'
  const otherPath = join(directory, 'flags-' + otherTarget + '.cjs')
  const retainedOther = Buffer.from('// Unqualified other-target test fixture, never selected.\n')
  writeFileSync(otherPath, retainedOther)
  const evidence = join(directory, 'evidence')
  mkdirSync(evidence)
  const run = () => spawnSync(process.execPath, [join(directory, 'build.mjs'), evidence], { encoding: 'utf8' })
  const first = run()
  assert.equal(first.status, 0, first.stderr || first.error?.message)
  const artifactPath = join(directory, 'flags-' + target + '.cjs')
  const original = readFileSync(artifactPath)
  const built = JSON.parse(first.stdout)
  assert.equal(built.platform, process.platform)
  assert.equal(built.arch, process.arch)
  for (const [name, value] of Object.entries(built.constants)) assert.equal(value, constants[name], name)
  assert.equal(built.sourceSha256, hash(readFileSync(join(native, 'flags.c'))))
  assert.equal(built.probeSha256, hash(readFileSync(join(evidence, 'native-flags-probe-' + target))))
  assert.deepEqual(readFileSync(otherPath), retainedOther)
  assert.deepEqual(readFileSync(join(evidence, 'native-flags-candidate-' + target + '.cjs')), original)
  const replay = run()
  assert.equal(replay.status, 0, replay.stderr)
  assert.deepEqual(readFileSync(artifactPath), original)

  const changed = Buffer.concat([original, Buffer.from('// Different retained artifact identity.\n')])
  writeFileSync(artifactPath, changed)
  const refused = run()
  assert.notEqual(refused.status, 0)
  assert.match(refused.stderr, /Existing native flag artifact differs/)
  assert.deepEqual(readFileSync(artifactPath), changed, 'failed rebuild preserves the existing artifact')
  assert.deepEqual(readFileSync(otherPath), retainedOther, 'all builds preserve the other target')
  assert.deepEqual(readFileSync(join(evidence, 'native-flags-candidate-' + target + '.cjs')), original)
})
