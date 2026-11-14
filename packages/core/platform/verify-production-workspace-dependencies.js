import assert from 'node:assert/strict'
import { readFileSync, realpathSync, existsSync } from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

// Run after the production dependency stage and committed source are combined.
// A root-only import check misses npm's conflicting workspace-local versions.
export function verifyProductionWorkspaceDependencies (root) {
  const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'))
  const checked = []
  for (const workspace of ['core', 'services', 'client']) {
    const prefix = `packages/${workspace}/node_modules/`
    for (const [location, expected] of Object.entries(lock.packages)) {
      if (!location.startsWith(prefix) || expected.dev === true || expected.link === true) continue
      const split = location.lastIndexOf('/node_modules/')
      const owner = location.slice(0, split)
      const name = location.slice(split + '/node_modules/'.length)
      const packageRoot = path.join(root, location)
      const metadata = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'))
      assert.equal(metadata.version, expected.version, `wrong locked version: ${location}`)
      const require = createRequire(path.join(root, owner, 'package.json'))
      const entry = require.resolve(name)
      let resolvedRoot = path.dirname(realpathSync(entry))
      while (!existsSync(path.join(resolvedRoot, 'package.json'))) {
        const parent = path.dirname(resolvedRoot)
        assert.notEqual(parent, resolvedRoot, `package metadata absent for ${owner}: ${name}`)
        resolvedRoot = parent
      }
      assert.equal(realpathSync(resolvedRoot), realpathSync(packageRoot), `wrong consuming-workspace resolution: ${owner}: ${name}`)
      checked.push({ owner, dependency: name, version: metadata.version, location })
    }
    assert(checked.some(item => item.owner === `packages/${workspace}`), `no workspace dependency proof: ${workspace}`)
  }
  const owningWorkspaceGraph = {}
  for (const owner of ['.', 'packages/core', 'packages/services', 'packages/client']) {
    const require = createRequire(path.join(root, owner, 'package.json'))
    const dependencies = ['hypercore', 'corestore', 'hypercore-storage', 'rocksdb-native', 'sodium-universal', 'sodium-native', 'b4a', 'fs-native-extensions', 'streamx', 'protomux-rpc', 'rache']
    if (owner === 'packages/core') dependencies.push('@x402/core', '@x402/evm', '@grpc/grpc-js')
    const graph = owningWorkspaceGraph[owner] = {}
    for (const name of dependencies) {
      let directory = path.dirname(realpathSync(require.resolve(name)))
      let bytes, metadata
      while (true) {
        if (existsSync(path.join(directory, 'package.json'))) {
          bytes = readFileSync(path.join(directory, 'package.json'))
          metadata = JSON.parse(bytes)
          if (metadata.name === name) break
        }
        const parent = path.dirname(directory)
        assert.notEqual(parent, directory, `dependency package root absent: ${owner}: ${name}`)
        directory = parent
      }
      const packageRootRelative = path.relative(root, directory).split(path.sep).join('/')
      assert.equal(metadata.version, lock.packages[packageRootRelative]?.version, `unlocked dependency resolution: ${owner}: ${name}`)
      graph[name] = {
        version: metadata.version,
        packageJsonSha256: createHash('sha256').update(bytes).digest('hex'),
        packageRootRelative
      }
    }
  }
  return { schema: 'HiveRelayProductionWorkspaceDependencyGraphV1', passed: true, checked, owningWorkspaceGraph }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ? path.resolve(process.argv[2]) : fileURLToPath(new URL('../../../', import.meta.url))
  process.stdout.write(JSON.stringify(verifyProductionWorkspaceDependencies(root)) + '\n')
}
