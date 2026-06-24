/**
 * Bare-runtime test suite — runs under the ACTUAL Bare runtime (not Node).
 *
 * Run with:  npm run test:bare   (→ adds ./node_modules/bare/bin, then brittle-bare)
 *
 * Unlike test/unit/bare-relay-surface.test.js — which runs under Node and so
 * exercises the `default` condition of the imports map (Node built-ins) — this
 * suite is executed by `bare`, so the `bare` condition resolves to the REAL
 * bare-events / bare-fs / bare-http1 / bare-path / bare-crypto implementations.
 *
 * It is the verification gate for any storage-stack upgrade (corestore 7 /
 * hypercore 11): nothing else in CI actually loads the Bare module graph at
 * runtime. If the Bare relay can construct and resolve policy here, the wire
 * surface is sound under Bare.
 */

import test from 'brittle'
import { isBare, runtime } from 'which-runtime'

test('bare: suite is genuinely executing under the Bare runtime', (t) => {
  t.ok(isBare, 'which-runtime reports isBare === true (not the Node fallback)')
  t.is(runtime, 'bare', 'runtime string is "bare"')
})

test('bare: BareRelay imports via the bare condition of the imports map', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  t.ok(BareRelay, 'BareRelay class is exported under Bare')
  t.is(typeof BareRelay, 'function', 'is a constructor')
})

test('bare: BareRelay constructs with real bare-* modules loaded', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  const relay = new BareRelay({ storage: '/tmp/bare-rt-smoke-' + Date.now() })
  t.ok(relay, 'instance constructed under Bare')
  t.is(relay.running, false, 'not running before start()')
  t.is(typeof relay.start, 'function', 'has start()')
  t.is(typeof relay.stop, 'function', 'has stop()')
  t.is(relay.config.acceptMode, 'open', 'Bare default accept mode is open')
  t.is(relay.config.enableSeeding, true, 'seeding enabled by default')
  t.is(relay.config.catalogSync, true, 'catalog sync enabled by default')
})

test('bare: capability doc detects the Bare runtime via which-runtime', async (t) => {
  const { buildCapabilityDoc } = await import('p2p-hiverelay/core/capability-doc.js')
  const doc = buildCapabilityDoc({})
  t.is(doc.runtime, 'bare', 'capability doc reports runtime:"bare" when executed under Bare')
  t.is(doc.schemaVersion, 1, 'capability schema version present')
})

test('bare: accept-mode resolver is deterministic under Bare', async (t) => {
  const { BareRelay } = await import('p2p-hiverelay/core/relay-node/bare-relay.js')
  const relay = new BareRelay({ storage: '/tmp/bare-rt-mode-' + Date.now() })
  const cases = [
    { acceptMode: 'open', expect: 'open' },
    { acceptMode: 'review', expect: 'review' },
    { acceptMode: 'allowlist', expect: 'allowlist' },
    { acceptMode: 'closed', expect: 'closed' }
  ]
  for (const { acceptMode, expect } of cases) {
    relay.config.acceptMode = acceptMode
    t.is(relay._resolveAcceptMode(), expect, `acceptMode ${acceptMode} resolves to ${expect}`)
  }
})
