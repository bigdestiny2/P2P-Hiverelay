/**
 * p2p-hiverelay — legacy Pear v2/Bare runtime entry point.
 *
 * This file is retained only to support an explicitly operated legacy v2
 * deployment. It is not a Pear v3 entrypoint and must not be packaged as one.
 * Pear v3 uses a separately reviewed native/Bare artifact with explicit
 * storage, an external health supervisor, and a resolved local worker passed
 * to PearRuntime.run().
 *
 * Differences from the Node CLI:
 *   - Uses Pear.config.storage for persistence (app-scoped by Pear)
 *   - No HTTP server, no TUI, no Lightning, no vm sandbox
 *   - Lifecycle is managed by Pear (teardown on app exit, etc.)
 *
 * Flags (parsed with paparam, the Pear-ecosystem CLI lib):
 *   --region|-r <region>     relay region            (default NA)
 *   --port|-p <port>         HTTP API port           (default 9100)
 *   --max-storage <size>     cap, e.g. 50GB          (default 50GB)
 *   --no-updates             disable P2P OTA updates (default: enabled)
 *
 * Parsing is sloppy() so an unexpected Pear-injected arg can never stop the
 * legacy relay from booting. This entry deliberately does not attempt an
 * in-place runtime upgrade: replacing an operating relay's storage or update
 * lifecycle requires the dedicated canary and rollback plan.
 */

/* global Pear */

import { command, flag, sloppy } from 'paparam'
import { BareRelay } from './core/relay-node/bare-relay.js'
import b4a from 'b4a'

const DEFAULT_MAX_STORAGE = 50 * 1024 * 1024 * 1024

const argv = Pear.config.args || []
const cmd = command(
  'p2p-hiverelay',
  sloppy({ flags: true, args: true }),
  flag('--region|-r [region]', 'relay region (default NA)'),
  flag('--port|-p [port]', 'HTTP API port (default 9100)'),
  flag('--max-storage [size]', 'max storage, e.g. 50GB (default 50GB)'),
  flag('--no-updates', 'disable P2P over-the-air updates')
)
const program = cmd.parse(argv)
const flags = (program && program.flags) || {}
// paparam collapses "not passed" and "--no-updates" to the same falsy value,
// so detect the explicit opt-out from argv to keep updates enabled by default.
const updatesEnabled = !argv.includes('--no-updates')

console.log()
console.log('  ╱═══════════════════════════════════════════════════════════════════╲')
console.log('      p2p-hiverelay  ·  pear/bare runtime  ·  always-on p2p relay')
console.log('  ╲═══════════════════════════════════════════════════════════════════╱')
console.log()
console.log('  [storage]', Pear.config.storage)
console.log()

const relay = new BareRelay({
  storage: Pear.config.storage,
  regions: [flags.region || 'NA'],
  maxStorageBytes: flags.maxStorage ? parseBytes(flags.maxStorage) : DEFAULT_MAX_STORAGE,
  httpPort: flags.port ? parseInt(flags.port, 10) : 9100
})

relay.on('started', ({ publicKey }) => {
  console.log()
  console.log('  ⬢ public key:', b4a.toString(publicKey, 'hex'))
  console.log()
})

await relay.start()

Pear.teardown(async () => {
  console.log()
  console.log('  [pear] teardown — stopping relay cleanly…')
  await relay.stop()
})

// Legacy P2P over-the-air updates (opt-out via --no-updates). The module is
// optional and undeclared; this is intentionally not a v3 update mechanism.
if (updatesEnabled) {
  try {
    const { default: updates } = await import('pear-updates')
    updates(() => {
      console.log('  [pear] update available — will apply on next restart')
    })
  } catch (_) { /* pear-updates not available; skip */ }
} else {
  console.log('  [pear] OTA updates disabled (--no-updates)')
}

// ─── Helpers ────────────────────────────────────────────────────────

function parseBytes (str) {
  const n = parseFloat(str)
  const s = String(str).toUpperCase()
  if (s.endsWith('TB')) return n * 1024 ** 4
  if (s.endsWith('GB')) return n * 1024 ** 3
  if (s.endsWith('MB')) return n * 1024 ** 2
  if (s.endsWith('KB')) return n * 1024
  return n
}
