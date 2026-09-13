import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { createExactReleaseSource, verifyPackedReleaseSource } from '../../scripts/release-stages/exact-source.mjs'
import { waitForImmutableNpmDist } from '../../scripts/release-stages/npm-immutable-dist.mjs'

function run (command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8', timeout: 30000 })
  if (result.status !== 0 || result.error) throw new Error(result.stderr || result.error?.message || 'fixture failed')
  return result.stdout.trim()
}
function fixture (t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-source-binding-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const repoRoot = path.join(root, 'repo')
  fs.mkdirSync(repoRoot)
  run('git', ['init', '-q'], repoRoot)
  const pkg = path.join(repoRoot, 'packages/core')
  fs.mkdirSync(pkg, { recursive: true })
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'release-source-fixture', version: '1.0.0', files: ['*.js', '*.json'], scripts: { prepack: 'node -e "process.exit(9)"' } }))
  fs.writeFileSync(path.join(pkg, 'index.js'), 'export const reviewed = true\n')
  fs.writeFileSync(path.join(repoRoot, 'entry.sh'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  function commit () {
    run('git', ['add', '.'], repoRoot)
    run('git', ['-c', 'user.name=Release Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture'], repoRoot)
    return run('git', ['rev-parse', 'HEAD'], repoRoot)
  }
  return { root, repoRoot, pkg, commit, sha: commit() }
}

test('exact source uses admitted Git bytes and modes despite dirty and untracked checkout files', t => {
  const f = fixture(t)
  fs.writeFileSync(path.join(f.pkg, 'index.js'), 'dirty tracked bytes\n')
  fs.writeFileSync(path.join(f.pkg, 'release-review-marker.json'), '{"unreviewed":true}')
  const exact = createExactReleaseSource({ ...f, destination: path.join(f.root, 'exact') })
  t.is(fs.readFileSync(path.join(exact.source, 'packages/core/index.js'), 'utf8'), 'export const reviewed = true\n')
  t.absent(fs.existsSync(path.join(exact.source, 'packages/core/release-review-marker.json')))
  t.is(fs.readFileSync(path.join(f.pkg, 'index.js'), 'utf8'), 'dirty tracked bytes\n', 'preserves user work')
  t.ok((fs.statSync(path.join(exact.source, 'entry.sh')).mode & 0o111) !== 0)
  t.is(exact.receipt.sourceCommit, f.sha)
  t.is(exact.receipt.files.length, 3)
  t.ok(/^[a-f0-9]{64}$/.test(exact.receipt.archiveSha256))
  t.exception(() => createExactReleaseSource({ ...f, sha: 'HEAD', destination: path.join(f.root, 'ref') }), /Exact admitted/)
  t.exception(() => createExactReleaseSource({ ...f, sha: 'a'.repeat(40), destination: path.join(f.root, 'missing') }), /git failed/)
})

test('source archive rejects links and export attributes which change the admitted inventory', t => {
  const f = fixture(t)
  fs.symlinkSync('index.js', path.join(f.pkg, 'link.js'))
  const linked = f.commit()
  t.exception(() => createExactReleaseSource({ ...f, sha: linked, destination: path.join(f.root, 'linked') }), /ordinary committed files/)
  fs.unlinkSync(path.join(f.pkg, 'link.js'))
  fs.writeFileSync(path.join(f.repoRoot, '.gitattributes'), 'packages/core/index.js export-ignore\n')
  const omitted = f.commit()
  t.exception(() => createExactReleaseSource({ ...f, sha: omitted, destination: path.join(f.root, 'omitted') }), /inventory differs/)
  fs.writeFileSync(path.join(f.repoRoot, '.gitattributes'), 'packages/core/index.js export-subst\n')
  fs.writeFileSync(path.join(f.pkg, 'index.js'), '$Format:%H$\n')
  const substituted = f.commit()
  t.exception(() => createExactReleaseSource({ ...f, sha: substituted, destination: path.join(f.root, 'substituted') }), /bytes differ/)
})

test('actual npm packed files must match committed blobs and reject extra or changed source', t => {
  const f = fixture(t)
  const exact = createExactReleaseSource({ ...f, destination: path.join(f.root, 'exact') })
  const sourcePkg = path.join(exact.source, 'packages/core')
  const npm = fs.realpathSync(run('which', ['npm'], f.root))
  const packed = JSON.parse(run(process.execPath, [npm, 'pack', sourcePkg, '--ignore-scripts', '--json', '--pack-destination', f.root], f.root, { ...process.env, npm_config_cache: path.join(f.root, 'cache') }))
  const file = path.join(f.root, packed[0].filename)
  const options = { file, packageDirectory: 'packages/core', inventory: exact.inventory }
  t.alike(verifyPackedReleaseSource({ ...options, destination: path.join(f.root, 'valid') }), ['packages/core/index.js', 'packages/core/package.json'])
  const content = path.join(f.root, 'content')
  fs.mkdirSync(path.join(content, 'package'), { recursive: true })
  fs.cpSync(sourcePkg, path.join(content, 'package'), { recursive: true })
  fs.writeFileSync(path.join(content, 'package', 'extra.json'), '{}')
  run('tar', ['-czf', file, '-C', content, 'package'], f.root)
  t.exception(() => verifyPackedReleaseSource({ ...options, destination: path.join(f.root, 'extra') }), /Packed npm bytes/)
  fs.unlinkSync(path.join(content, 'package', 'extra.json'))
  fs.writeFileSync(path.join(content, 'package', 'index.js'), 'changed bytes')
  run('tar', ['-czf', file, '-C', content, 'package'], f.root)
  t.exception(() => verifyPackedReleaseSource({ ...options, destination: path.join(f.root, 'changed') }), /Packed npm bytes/)
  fs.symlinkSync('/tmp', path.join(content, 'package', 'external'))
  run('tar', ['-czf', file, '-C', content, 'package'], f.root)
  t.exception(() => verifyPackedReleaseSource({ ...options, destination: path.join(f.root, 'linked') }), /link or special/)
})

test('immutable dist readback retries only explicit absence with a finite attempt and delay bound', async t => {
  const expected = { integrity: 'sha512-exact', shasum: 'exact' }
  const absent = () => Object.assign(new Error('absent'), { code: 1, stderr: 'npm error code E404\n' })
  const delays = []
  let reads = 0
  const result = await waitForImmutableNpmDist({ expected, attempts: 5, initialDelayMs: 2, maxDelayMs: 5, sleep: async ms => delays.push(ms), readDist: async () => { if (++reads < 5) throw absent(); return expected } })
  t.is(result, expected)
  t.alike(delays, [2, 4, 5, 5])
  t.is(reads, 5)
  reads = 0
  await t.exception.all(waitForImmutableNpmDist({ expected, attempts: 2, initialDelayMs: 1, maxDelayMs: 1, sleep: async () => {}, readDist: async () => { reads++; throw absent() } }), /visibility bound/)
  t.is(reads, 2)
  for (const error of [
    Object.assign(new Error(), { code: 1, stderr: 'npm error code E401\n' }),
    Object.assign(new Error(), { code: 'ECONNRESET', stderr: 'npm error code E404\n' }),
    Object.assign(new Error(), { code: 1, stderr: 'npm error code E404\nnpm error code E401\n' }),
    new SyntaxError('bad JSON')
  ]) {
    reads = 0
    await t.exception.all(waitForImmutableNpmDist({ expected, readDist: async () => { reads++; throw error }, sleep: async () => t.fail('must not retry ambiguity') }), /Could not verify/)
    t.is(reads, 1)
  }
  for (const actual of [null, {}, { ...expected, integrity: 'wrong' }, { ...expected, shasum: 'wrong' }]) {
    await t.exception.all(waitForImmutableNpmDist({ expected, readDist: async () => actual, sleep: async () => t.fail('must not retry immutable mismatch') }), /differs/)
  }
})
