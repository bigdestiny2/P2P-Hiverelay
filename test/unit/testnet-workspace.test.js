import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { requireTestnetWorkspace } from '../../packages/core/cli/testnet-workspace.js'

function fixture (t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-testnet-layout-'))
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  const write = (file, bytes) => {
    const target = path.join(root, file)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, bytes)
  }
  write('package.json', JSON.stringify({ name: 'p2p-hiverelay-monorepo', private: true, type: 'module', workspaces: ['packages/core', 'packages/client'], devDependencies: { '@hyperswarm/testnet': '^3.1.2' } }))
  write('packages/core/cli/testnet-workspace.js', fs.readFileSync(new URL('../../packages/core/cli/testnet-workspace.js', import.meta.url)))
  return { root, write, helper: pathToFileURL(path.join(root, 'packages/core/cli/testnet-workspace.js')).href }
}

test('testnet accepts source workspace layout and rejects an installed package inside it', t => {
  const source = requireTestnetWorkspace()
  t.is(source.root, process.cwd())
  t.is(source.clientUrl, pathToFileURL(path.join(process.cwd(), 'packages/client/index.js')).href)
  const f = fixture(t)
  f.write('node_modules/p2p-hiverelay/cli/index.js', '')
  t.exception(() => requireTestnetWorkspace(pathToFileURL(path.join(f.root, 'node_modules/p2p-hiverelay/cli/index.js'))), /source-workspace development command/)
  f.write('package.json', JSON.stringify({ name: 'consumer', private: true }))
  t.exception(() => requireTestnetWorkspace(f.helper), /npm ci/)
})

test('source no-client load does not resolve or execute a sibling client', async t => {
  const f = fixture(t)
  f.write('node_modules/@hyperswarm/testnet/package.json', JSON.stringify({ name: '@hyperswarm/testnet', type: 'module', exports: './index.js' }))
  f.write('node_modules/@hyperswarm/testnet/index.js', 'export default function fixtureTestnet () {}\n')
  // A missing client is allowed only when disabled. This is a module-loading
  // fixture; actual local DHT lifecycle evidence is collected separately.
  const { loadTestnetDependencies } = await import(f.helper)
  const disabled = await loadTestnetDependencies({ runClient: false })
  t.is(typeof disabled.createTestnet, 'function')
  t.is(disabled.HiveRelayClient, null)
  await t.exception(loadTestnetDependencies(), /Cannot find module/)
  f.write('packages/client/index.js', 'export class HiveRelayClient {}\n')
  const enabled = await loadTestnetDependencies()
  t.is(typeof enabled.HiveRelayClient, 'function')
})

test('source testnet reports missing development installation before opening resources', async t => {
  const f = fixture(t)
  const { loadTestnetDependencies } = await import(f.helper)
  await t.exception(loadTestnetDependencies({ runClient: false }), /Run npm ci/)
})
