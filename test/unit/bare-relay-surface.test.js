/**
 * BareRelay surface smoke test.
 *
 * We cannot exercise BareRelay end-to-end under Node because the file
 * declares imports for `bare-events`, `bare-fs/promises`, `bare-path` which
 * the package.json `imports` map redirects to Node built-ins under the
 * `default` condition. This test verifies that:
 *
 *   1. The BareRelay module loads at all under Node (no missing deps,
 *      no broken exports map).
 *   2. The class has the API surface the Pear runtime expects.
 *   3. Shared accept-mode helpers behave identically in BareRelay and
 *      RelayNode — this matters because both runtimes apply the same
 *      policy module and a divergence would silently break parity.
 *
 * End-to-end testing of the actual Bare runtime path requires running under
 * `bare` or `pear run` and is covered by manual operator verification, not
 * this suite.
 */

import test from 'brittle'
import { readFile, rm, stat } from 'fs/promises'
import { randomBytes } from 'crypto'
import { join } from 'path'
import { tmpdir } from 'os'
import { BareRelay } from 'p2p-hiverelay/core/relay-node/bare-relay.js'

function tmpStorage () {
  return join(tmpdir(), 'hiverelay-bare-identity-' + randomBytes(8).toString('hex'))
}

test('bare smoke: BareRelay module imports cleanly under Node via the imports map', (t) => {
  t.ok(BareRelay, 'BareRelay class is exported')
  t.is(typeof BareRelay, 'function', 'is a constructor')
})

test('bare smoke: BareRelay constructs with minimal config', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-smoke-' + Date.now() })
  t.ok(relay, 'instance constructed')
  t.is(relay.running, false, 'not running before start()')
  t.is(typeof relay.start, 'function', 'has start')
  t.is(typeof relay.stop, 'function', 'has stop')
  t.is(typeof relay._resolveAcceptMode, 'function', 'shares accept-mode resolver with RelayNode')
  t.is(typeof relay._decideAcceptance, 'function', 'shares accept-mode decision with RelayNode')
})

test('bare smoke: default config matches Bare-appropriate defaults', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-smoke-' + Date.now() })
  // Bare has no operator TUI to drain a review queue, so the default mode
  // must NOT be 'review' or every inbound seed would block forever.
  t.is(relay.config.acceptMode, 'open', 'Bare default is open (Pear operator opts into tighter modes explicitly)')
  t.is(relay.config.enableSeeding, true)
  t.is(relay.config.enableRelay, true)
  t.is(relay.config.catalogSync, true)
})

test('bare smoke: identity seed file is created owner-only and reloads', async (t) => {
  const storage = tmpStorage()
  const relay = new BareRelay({ storage })
  t.teardown(async () => {
    try { await relay.store.close() } catch (_) {}
    await rm(storage, { recursive: true, force: true })
  })

  const first = await relay._deriveKeypair()
  const mode = (await stat(join(storage, 'identity.key'))).mode & 0o777
  const second = await relay._deriveKeypair()

  t.is(mode, 0o600, 'Bare identity seed is owner-read/write only')
  t.alike(second.publicKey, first.publicKey, 'public key reloads from disk')
  t.alike(second.secretKey, first.secretKey, 'secret key reloads from disk')
})

test('bare smoke: identity temp path avoids Node-only process globals', async (t) => {
  const source = await readFile(new URL('../../packages/core/core/relay-node/bare-relay.js', import.meta.url), 'utf8')
  t.ok(source.includes('function identityTempPath (keyPath)'), 'uses a portable temp-path helper')
  t.absent(source.includes('process.pid'), 'Bare identity path does not depend on Node process.pid')
})

test('bare smoke: accept-mode resolver gives same answer as RelayNode for same config', async (t) => {
  // Symmetry check — if these ever diverge, the two runtimes silently apply
  // different policies for identical config. That would be a security bug.
  const bare = new BareRelay({ storage: '/tmp/bare-symm-' + Date.now() })
  const { RelayNode } = await import('p2p-hiverelay/core/relay-node/index.js')
  const node = new RelayNode({ storage: '/tmp/node-symm-' + Date.now() })

  const cases = [
    { acceptMode: 'open', expect: 'open' },
    { acceptMode: 'review', expect: 'review' },
    { acceptMode: 'allowlist', expect: 'allowlist' },
    { acceptMode: 'closed', expect: 'closed' },
    { registryAutoAccept: true, expect: 'open' },
    { registryAutoAccept: false, expect: 'review' }
  ]

  for (const { expect, ...cfg } of cases) {
    Object.assign(bare.config, cfg)
    Object.assign(node.config, cfg)
    delete bare.config.acceptMode
    delete node.config.acceptMode
    Object.assign(bare.config, cfg)
    Object.assign(node.config, cfg)

    const bareMode = bare._resolveAcceptMode()
    const nodeMode = node._resolveAcceptMode()
    t.is(bareMode, nodeMode, `runtimes agree for config ${JSON.stringify(cfg)}`)
    t.is(bareMode, expect, `result is ${expect} as expected`)
  }
})

test('bare smoke: federation module is wired (instance exists pre-start)', (t) => {
  const relay = new BareRelay({ storage: '/tmp/bare-fed-' + Date.now() })
  // Federation is constructed inside start() in BareRelay, not in the
  // constructor — verify the property exists and starts null.
  t.is(relay.federation, null, 'federation slot exists, lazily constructed in start()')
})
