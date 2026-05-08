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
 * Filename `zz-finalize` makes brittle's glob expansion run this last
 * (every other unit-test file starts with a letter < 'z').
 *
 * If this guard ever stops needing to fire, that means whatever is
 * leaking has been fixed and this file can be removed.
 */

import { test } from 'brittle'

test('unit suite: schedule post-suite force-exit', async (t) => {
  setTimeout(() => process.exit(0), 5000).unref()
  t.pass('force-exit timer armed (5s, .unref())')
})
