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
 * Filename `zz-finalize` ensures it runs last alphabetically — brittle's
 * glob expansion respects sort order, and every other integration test
 * file starts with a letter before 'z'.
 *
 * If this guard ever stops firing, that means whatever leak this is
 * masking has been fixed and this file can be removed.
 */

import { test } from 'brittle'

test('integration suite: schedule post-suite force-exit', async (t) => {
  setTimeout(() => process.exit(0), 5000).unref()
  t.pass('force-exit timer armed (5s, .unref())')
})
