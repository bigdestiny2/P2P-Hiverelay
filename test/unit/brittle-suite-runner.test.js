import { spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'
import test from 'brittle'
import { assertIntentTestTarget } from '../../scripts/integration-test-profiles.mjs'

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


function harnessFixture (t) {
  const directory = mkdtempSync(path.join(tmpdir(), 'hiverelay-suite-runner-'))
  t.teardown(() => rmSync(directory, { recursive: true, force: true }))
  const write = (name, contents) => {
    const target = path.join(directory, name)
    mkdirSync(path.dirname(target), { recursive: true })
    writeFileSync(target, contents)
  }
  write('package.json', '{"type":"module"}')
  for (const name of ['run-brittle-suite.mjs', 'integration-test-profiles.mjs']) {
    mkdirSync(path.join(directory, 'scripts'), { recursive: true })
    copyFileSync(path.resolve('scripts', name), path.join(directory, 'scripts', name))
  }
  const files = [
    'test/integration/alpha.test.js', 'test/integration/blind-intent-store-bare.test.js',
    'test/integration/blind-intent-store-pear.test.js', 'test/integration/zz-finalize.test.js',
    'test/unit/example.test.js'
  ]
  for (const name of files) write(name, '')
  const tool = 'scripts/test-tools/private-intent-runtime'
  write(tool + '/package.json', '{"private":true}')
  const executable = path.join(directory, 'bare-fixture.cjs')
  write('bare-fixture.cjs', `#!${process.execPath}\nif (!process.env.EMPTY_RECEIPT) console.log(JSON.stringify({ executable: __filename, version: process.env.RECEIPT_VERSION || 'v1.31.0' }))\n`)
  chmodSync(executable, 0o755)
  write(tool + '/node_modules/bare/bin/bare', `const child = require('node:child_process').spawnSync(${JSON.stringify(executable)}, process.argv.slice(2), { stdio: 'inherit' }); process.exit(child.status ?? 1)\n`)
  write(tool + '/node_modules/bare-runtime/index.js', `module.exports = () => ${JSON.stringify(executable)}\n`)
  for (const [base, name, version] of [
    [tool, 'bare', '1.31.0'], [tool, 'bare-runtime', '1.31.0'],
    ['packages/blind-intent-store-bare', 'brittle', '4.1.0'],
    ['packages/blind-intent-pear-consumer', 'pear-runtime', '1.3.1'],
    ['packages/blind-intent-pear-consumer', 'bare-sidecar', '0.5.2']
  ]) write(`${base}/node_modules/${name}/package.json`, JSON.stringify({ name, version }))
  for (const [name, label] of [['blind-intent-store-bare', 'bare'], ['blind-intent-pear-consumer', 'pear']]) {
    write(`packages/${name}/package.json`, JSON.stringify({ private: true, scripts: { test: 'node test/run.mjs' } }))
    write(`packages/${name}/package-lock.json`, '{}')
    write(`packages/${name}/test/run.mjs`, `import { appendFileSync } from 'node:fs'; appendFileSync(process.env.DISPATCH_LOG, JSON.stringify({ profile: '${label}', executable: process.env.BARE_EXECUTABLE }) + '\\n'); process.exit(process.env.FAIL_PROFILE === '${label}' ? 7 : 0)\n`)
  }
  write('node_modules/brittle/brittle-node.js', `const fs = require('node:fs'); fs.appendFileSync(process.env.DISPATCH_LOG, JSON.stringify({ profile: 'ordinary', files: process.argv.slice(4) }) + '\\n'); if (process.env.ORDINARY_SIGNAL) process.kill(process.pid, 'SIGTERM'); else process.exit(Number(process.env.ORDINARY_EXIT || 0))\n`)
  const log = path.join(directory, 'dispatch.jsonl')
  return {
    directory, executable, files,
    run (suite = 'integration', environment = {}, args = []) {
      writeFileSync(log, '')
      const result = spawnSync(process.execPath, ['scripts/run-brittle-suite.mjs', suite, ...args], {
        cwd: directory, encoding: 'utf8', env: { ...process.env, DISPATCH_LOG: log, ...environment }
      })
      return { ...result, dispatch: readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) }
    }
  }
}

test('suite dispatch executes every discovered file once through its owning harness', t => {
  const fixture = harnessFixture(t)
  const result = fixture.run()
  t.is(result.status, 0, result.stderr)
  t.alike(result.dispatch.map(item => item.profile), ['bare', 'pear', 'ordinary'])
  t.alike(result.dispatch.at(-1).files, ['test/integration/alpha.test.js', 'test/integration/zz-finalize.test.js'])
  t.is(result.dispatch[0].executable, fixture.executable, 'uses dedicated qualified executable')
  t.is(result.dispatch[1].executable, fixture.executable)
  const listed = fixture.run('integration', {}, ['--list'])
  t.is(listed.status, 0)
  t.alike(listed.stdout.trim().split('\n'), fixture.files.filter(file => file.startsWith('test/integration/')))
  t.alike(listed.dispatch, [], 'listing does not execute or prepare profiles')
  const unit = fixture.run('unit')
  t.is(unit.status, 0, unit.stderr)
  t.alike(unit.dispatch, [{ profile: 'ordinary', files: ['test/unit/example.test.js'] }])
})

test('private prerequisites fail closed and child failures cannot become suite success', t => {
  const fixture = harnessFixture(t)
  for (const environment of [{ RECEIPT_VERSION: 'v1.33.4' }, { EMPTY_RECEIPT: '1' }]) {
    const result = fixture.run('integration', environment)
    t.not(result.status, 0)
    t.ok(result.stderr.includes('private integration prerequisites failed'))
    t.alike(result.dispatch, [])
  }
  const privateFailure = fixture.run('integration', { FAIL_PROFILE: 'bare' })
  t.not(privateFailure.status, 0)
  t.alike(privateFailure.dispatch.map(item => item.profile), ['bare'])
  t.is(fixture.run('integration', { ORDINARY_EXIT: '9' }).status, 9)
  const signal = fixture.run('integration', { ORDINARY_SIGNAL: '1' })
  t.not(signal.status, 0)
  t.ok(signal.stderr.includes('SIGTERM'))
  rmSync(path.join(fixture.directory, 'scripts/test-tools/private-intent-runtime/node_modules'), { recursive: true })
  const missing = fixture.run()
  t.not(missing.status, 0)
  t.ok(missing.stderr.includes('npm run test:integration:prepare'))
  t.is(fixture.run('integration', {}, ['--list']).status, 0, 'inventory remains available before install')
  t.is(fixture.run('unit').status, 0, 'unit suite does not need private prerequisites')
  for (const [platform, arch] of [['linux', 'arm64'], ['darwin', 'x64'], ['win32', 'x64']]) {
    t.exception(() => assertIntentTestTarget(platform, arch), /unqualified/)
  }
})
