import { readFileSync, realpathSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SOURCE_GUIDANCE = 'testnet is a source-workspace development command. In a HiveRelay checkout, run npm ci, then node packages/core/cli/index.js testnet (optionally --no-client). Published packages do not include testnet tooling.'

export function requireTestnetWorkspace (cliUrl = import.meta.url) {
  const core = resolve(dirname(fileURLToPath(cliUrl)), '..')
  const root = resolve(core, '../..')
  try {
    const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
    if (manifest.name !== 'p2p-hiverelay-monorepo' || manifest.private !== true ||
        !Array.isArray(manifest.workspaces) || !manifest.workspaces.includes('packages/core') ||
        !manifest.workspaces.includes('packages/client') ||
        typeof manifest.devDependencies?.['@hyperswarm/testnet'] !== 'string' ||
        realpathSync(core) !== realpathSync(join(root, 'packages/core'))) throw new Error('Not a source workspace')
  } catch {
    throw Object.assign(new Error(SOURCE_GUIDANCE), { code: 'HIVERELAY_TESTNET_SOURCE_ONLY' })
  }
  return { root, clientUrl: pathToFileURL(join(root, 'packages/client/index.js')).href }
}

export async function loadTestnetDependencies ({ runClient = true } = {}) {
  const workspace = requireTestnetWorkspace()
  let createTestnet
  try {
    createTestnet = (await import('@hyperswarm/testnet')).default
  } catch (error) {
    if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error
    throw new Error('Source testnet dependencies are unavailable. Run npm ci in the HiveRelay checkout before starting testnet.', { cause: error })
  }
  const HiveRelayClient = runClient ? (await import(workspace.clientUrl)).HiveRelayClient : null
  return { createTestnet, HiveRelayClient }
}
