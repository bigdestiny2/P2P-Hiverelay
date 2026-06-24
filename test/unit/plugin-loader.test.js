import test from 'brittle'
import { expandPluginConfigs, PluginLoader } from '../../packages/core/core/plugin-loader.js'

test('plugin loader expands poker bundle and de-duplicates builtin dependencies', (t) => {
  t.alike(expandPluginConfigs(['poker', 'vrf', 'ai', 'poker']), [
    'poker',
    'vrf',
    'arbitration',
    'zk',
    'ai'
  ])
})

test('plugin loader resolves poker as a builtin service provider', async (t) => {
  const loader = new PluginLoader()
  const providers = await loader.load(['poker'])
  t.alike(providers.map(provider => provider.manifest().name), [
    'poker',
    'vrf',
    'arbitration',
    'zk'
  ])
  await loader.stopAll()
})
