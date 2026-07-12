/**
 * Force-exit guard for the unit suite.
 *
 * Mirrors test/integration/zz-finalize.test.js. Some unit tests
 * instantiate real Hyperswarm / Hypercore / Corestore objects that
 * keep the Node event loop alive after assertions finish. Brittle
 * has no global afterAll hook, so we schedule a 5-second .unref()'d
 * force-exit timer as the last assertion. The .unref() ensures we
 * don't artificially block a clean natural exit.
 *
 * `scripts/run-brittle-suite.mjs` moves every `zz-finalize` file behind all
 * ordinary tests; relying on filesystem/glob order can terminate a live suite.
 * The forced exit preserves `process.exitCode`, so an earlier failure cannot
 * be converted into a successful run.
 *
 * If this guard ever stops needing to fire, that means whatever is
 * leaking has been fixed and this file can be removed.
 */

import { test } from 'brittle'

test('unit suite: schedule post-suite force-exit', async (t) => {
  setTimeout(() => process.exit(process.exitCode || 0), 5000).unref()
  t.pass('force-exit timer armed (5s, .unref())')
})
