import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'

const installer = fs.readFileSync(new URL('../../packages/core/platform/apply-hypercore-storage-migration-patch.js', import.meta.url))
const patch = fs.readFileSync(new URL('../../packages/core/patches/hypercore-storage+3.4.0.patch', import.meta.url))
const installed = fs.readFileSync(fileURLToPath(import.meta.resolve('hypercore-storage/migrations/0/index.js')), 'utf8')
const original = installed.replace('corePointer: head.cores++,', 'corePointer: head.allocated.cores++,')
  .replace('dataPointer: head.datas++,', 'dataPointer: head.allocated.datas++,')
const patched = original.replace('corePointer: head.allocated.cores++,', 'corePointer: head.cores++,')
  .replace('dataPointer: head.allocated.datas++,', 'dataPointer: head.datas++,')

for (const scenario of [
  'original', 'already-patched', 'wrong-version', 'predecessor-version', 'wrong-name', 'unknown-source', 'wrong-patch',
  'symlink-source', 'symlink-source-outside', 'symlink-migrations', 'symlink-generation',
  'symlink-manifest', 'symlink-patch'
]) {
  test(`storage patch installer: ${scenario}`, (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-patch-installer-'))
    t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
    const core = path.join(root, 'packages', 'core')
    const dependency = path.join(root, 'node_modules', 'hypercore-storage')
    const script = path.join(core, 'platform', 'apply-hypercore-storage-migration-patch.js')
    const patchFile = path.join(core, 'patches', 'hypercore-storage+3.4.0.patch')
    const manifest = path.join(dependency, 'package.json')
    const source = path.join(dependency, 'migrations', '0', 'index.js')
    for (const file of [script, patchFile, source]) fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ type: 'module' }))
    fs.writeFileSync(script, installer)
    fs.writeFileSync(patchFile, scenario === 'wrong-patch' ? Buffer.concat([patch, Buffer.from('\n# drift\n')]) : patch)
    fs.writeFileSync(manifest, JSON.stringify({
      name: scenario === 'wrong-name' ? 'another-package' : 'hypercore-storage',
      version: scenario === 'wrong-version' ? '3.2.0' : scenario === 'predecessor-version' ? '3.3.1' : '3.4.0'
    }))
    fs.writeFileSync(source, scenario === 'already-patched' ? patched : scenario === 'unknown-source' ? original + '\n// drift\n' : original)
    const linkTarget = {
      'symlink-source': source,
      'symlink-source-outside': source,
      'symlink-migrations': path.join(dependency, 'migrations'),
      'symlink-generation': path.join(dependency, 'migrations', '0'),
      'symlink-manifest': manifest,
      'symlink-patch': patchFile
    }[scenario]
    if (linkTarget) {
      const retained = scenario === 'symlink-source-outside' ? path.join(root, 'outside-source.js') : linkTarget + '.retained'
      fs.renameSync(linkTarget, retained)
      fs.symlinkSync(retained, linkTarget)
    }
    const before = fs.readFileSync(source)
    const result = spawnSync(process.execPath, [script], { cwd: root, encoding: 'utf8', timeout: 10000 })
    t.absent(result.error, 'installer exited within the bound')
    const success = scenario === 'original' || scenario === 'already-patched'
    if (success) {
      t.is(result.status, 0, result.stderr)
      t.is(hash(fs.readFileSync(source)), '04153bfa8de76c0dc2a802936cbbeea6c22f20a1a79035cd65ed1957cc8ff2d5', 'exact accepted patch output')
      const second = spawnSync(process.execPath, [script], { cwd: root, encoding: 'utf8', timeout: 10000 })
      t.is(second.status, 0, 'accepted patch is idempotent')
    } else {
      t.is(result.status, 1, result.stderr)
      t.alike(fs.readFileSync(source), before, 'rejected source or symlink target remains byte-exact')
      if (linkTarget) t.ok(fs.lstatSync(linkTarget).isSymbolicLink(), 'link itself remains unchanged')
    }
  })
}

function hash (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

test('storage migration runtime binding rejects predecessor packages with identical migration bytes', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-migration-binding-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const modules = path.join(root, 'node_modules')
  const dependency = path.join(modules, 'hypercore-storage')
  fs.mkdirSync(path.join(dependency, 'migrations', '0'), { recursive: true })
  for (const name of ['device-file', 'fd-lock']) {
    fs.symlinkSync(path.dirname(fileURLToPath(import.meta.resolve(name))), path.join(modules, name))
  }
  fs.copyFileSync(new URL('../../packages/core/core/persistence/corestore-generation-envelope.js', import.meta.url), path.join(root, 'binding.mjs'))
  fs.writeFileSync(path.join(dependency, 'migrations', '0', 'index.js'), patched)
  for (const version of ['3.4.0', '3.3.1']) {
    fs.writeFileSync(path.join(dependency, 'package.json'), JSON.stringify({ name: 'hypercore-storage', version }))
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      "import { assertPatchedHypercoreStorageMigration as check } from './binding.mjs'; console.log(JSON.stringify(check()))"
    ], { cwd: root, encoding: 'utf8', timeout: 10000 })
    t.absent(result.error, 'runtime check exits within its bound')
    if (version === '3.4.0') {
      t.is(result.status, 0, result.stderr)
      t.is(JSON.parse(result.stdout).version, version, 'receipt identifies the actual dependency')
    } else {
      t.is(result.status, 1, 'same migration source does not qualify an older package')
      t.ok(result.stderr.includes('CORESTORE_GENERATION_MIGRATION_PATCH_MISSING'), 'version mismatch remains fail-closed')
    }
  }
})
