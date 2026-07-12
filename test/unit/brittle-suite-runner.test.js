import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import test from 'brittle'

test('suite runner deterministically places force-exit guards after ordinary tests', t => {
  const runner = path.resolve('scripts/run-brittle-suite.mjs')
  const scripts = JSON.parse(readFileSync(path.resolve('package.json'))).scripts
  t.is(scripts.test, 'node scripts/run-brittle-suite.mjs all')
  t.is(scripts['test:unit'], 'node scripts/run-brittle-suite.mjs unit')
  t.is(scripts['test:integration'], 'node scripts/run-brittle-suite.mjs integration')
  for (const [suite, expectedFinalizers] of [
    ['unit', ['test/unit/zz-finalize.test.js']],
    ['integration', ['test/integration/zz-finalize.test.js']],
    ['all', ['test/integration/zz-finalize.test.js', 'test/unit/zz-finalize.test.js']]
  ]) {
    const result = spawnSync(process.execPath, [runner, suite, '--list'], {
      cwd: path.resolve('.'),
      encoding: 'utf8'
    })
    t.is(result.status, 0, result.stderr)
    const files = result.stdout.trim().split('\n')
    t.alike(files.slice(-expectedFinalizers.length), expectedFinalizers)
    const ordinary = files.slice(0, -expectedFinalizers.length)
    t.ok(ordinary.length > 0)
    if (suite !== 'integration') t.ok(files.includes('test/unit/brittle-suite-runner.test.js'))
    t.absent(ordinary.some(file => path.basename(file) === 'zz-finalize.test.js'))
    t.alike(ordinary, [...ordinary].sort(compareNames))
  }
})

function compareNames (left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}
