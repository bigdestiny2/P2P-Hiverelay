/**
 * Force-exit guard for the integration suite.
 *
 * The integration tests all pass (assertion-wise) but the process hangs
 * for several minutes afterwards before exiting because some
 * Hyperswarm / Hypercore / DHT resource is held open across the file
 * boundary. Brittle has no global afterAll hook and no --exit flag.
 *
 * Two-stage workaround:
 *   1. Schedule a 5-second `.unref()` timer that calls process.exit(0)
 *      if the Node event loop is still alive after this last test.
 *   2. The .unref() ensures we don't artificially block a clean exit:
 *      if the loop drains naturally, the timer is collected and we
 *      exit normally. If something leaks, the timer fires.
 *
 * `scripts/run-brittle-suite.mjs` moves every `zz-finalize` file behind all
 * ordinary tests; relying on filesystem/glob order can terminate a live suite.
 * The forced exit preserves `process.exitCode`, so an earlier failure cannot
 * be converted into a successful run.
 *
 * If this guard ever stops firing, that means whatever leak this is
 * masking has been fixed and this file can be removed.
 */

import { test } from 'brittle'

test('integration suite: schedule post-suite force-exit', async (t) => {
  setTimeout(() => process.exit(process.exitCode || 0), 5000).unref()
  t.pass('force-exit timer armed (5s, .unref())')
})
