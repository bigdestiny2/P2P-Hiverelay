import test from 'brittle'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { fileURLToPath } from 'url'
import { verifyProductionWorkspaceDependencies } from '../../packages/core/platform/verify-production-workspace-dependencies.js'

const source = fileURLToPath(new URL('../../', import.meta.url))

test('production owner graph binds public patches and refuses a stale cached dependency', async t => {
  const actual = verifyProductionWorkspaceDependencies(source)
  t.is(Object.keys(actual.owningWorkspaceGraph).length, 4)
  const patched = { 'fs-native-extensions': ['1.5.3', '1.5.0'], streamx: ['2.28.1', '2.28.0'], 'protomux-rpc': ['1.10.1', '1.10.0'], rache: ['1.0.1', '1.0.0'] }
  for (const graph of Object.values(actual.owningWorkspaceGraph)) for (const [name, [version]] of Object.entries(patched)) t.is(graph[name]?.version, version)
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'hiverelay-production-graph-')))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const lock = JSON.parse(readFileSync(join(source, 'package-lock.json')))
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify(lock))
  writeFileSync(join(root, 'package.json'), '{}')
  const locations = new Map()
  for (const graph of Object.values(actual.owningWorkspaceGraph)) for (const [name, entry] of Object.entries(graph)) locations.set(entry.packageRootRelative, { name, version: entry.version, main: 'index.js' })
  for (const entry of actual.checked) locations.set(entry.location, { name: entry.dependency, version: entry.version, main: 'index.js' })
  for (const [location, metadata] of locations) {
    mkdirSync(join(root, location), { recursive: true })
    writeFileSync(join(root, location, 'package.json'), JSON.stringify(metadata))
    writeFileSync(join(root, location, 'index.js'), 'module.exports = {}\n')
  }
  for (const owner of ['packages/core', 'packages/services', 'packages/client']) {
    mkdirSync(join(root, owner), { recursive: true }); writeFileSync(join(root, owner, 'package.json'), '{}')
  }
  const baseline = verifyProductionWorkspaceDependencies(root)
  t.is(baseline.checked.length, actual.checked.length, 'nested workspace slots remain checked')
  for (const [name, [, staleVersion]] of Object.entries(patched)) {
    const location = actual.owningWorkspaceGraph['packages/core'][name].packageRootRelative
    const file = join(root, location, 'package.json'); const original = readFileSync(file)
    const metadata = JSON.parse(original); metadata.version = staleVersion; writeFileSync(file, JSON.stringify(metadata))
    t.exception(() => verifyProductionWorkspaceDependencies(root), /unlocked dependency resolution/, 'old ' + name + ' cache cannot pass the qualified graph')
    writeFileSync(file, original)
  }
  t.is(verifyProductionWorkspaceDependencies(root).passed, true)
})
