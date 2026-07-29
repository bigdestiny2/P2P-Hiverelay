import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const observer = path.resolve('scripts/observe-public-hive-gateway-rollout.mjs')

test('public gateway observer owns status-2 sampling until verified', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-observer-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const checker = path.join(dir, 'checker.mjs')
  const state = path.join(dir, 'window.json')
  const counter = path.join(dir, 'counter.txt')
  await writeFile(checker, `
    import { readFileSync, writeFileSync } from 'node:fs'
    let count = 0
    try { count = Number(readFileSync(process.env.OBSERVER_COUNTER, 'utf8')) } catch {}
    count++
    writeFileSync(process.env.OBSERVER_COUNTER, String(count))
    if (count === 1) {
      writeFileSync(process.env.OBSERVER_STATE, JSON.stringify({ maxProbeGapMs: 60000 }))
      process.exit(2)
    }
    process.exit(0)
  `)

  const result = runObserver(checker, state, {
    OBSERVER_COUNTER: counter,
    OBSERVER_STATE: state
  })
  t.is(result.status, 0, result.stderr)
  t.ok(result.stdout.includes('Observation incomplete after 1 checker run'))
  t.ok(result.stdout.includes('observation complete after 2 checker run'))
  t.is(await readFile(counter, 'utf8'), '2')
})

test('public gateway observer stops immediately on a red checker', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-observer-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const checker = path.join(dir, 'checker.mjs')
  const state = path.join(dir, 'window.json')
  const counter = path.join(dir, 'counter.txt')
  await writeFile(checker, `
    import { writeFileSync } from 'node:fs'
    writeFileSync(process.env.OBSERVER_COUNTER, '1')
    process.exit(1)
  `)

  const result = runObserver(checker, state, { OBSERVER_COUNTER: counter })
  t.not(result.status, 0)
  t.ok(result.stderr.includes('stopped red with exit 1'))
  t.is(await readFile(counter, 'utf8'), '1')
})

test('public gateway observer refuses incomplete or non-canary forwarding', (t) => {
  const missing = spawnSync(process.execPath, [observer, '--', '--target', 'v1.2.3'], {
    encoding: 'utf8'
  })
  t.not(missing.status, 0)
  t.ok(missing.stderr.includes('--gateway-evidence is required'))

  const args = forwarded('/tmp/window.json')
  args[args.indexOf('canary')] = 'stable'
  const stable = spawnSync(process.execPath, [observer, '--', ...args], { encoding: 'utf8' })
  t.not(stable.status, 0)
  t.ok(stable.stderr.includes('restricted to the canary'))
})

function runObserver (checker, state, extraEnv) {
  return spawnSync(process.execPath, [
    observer,
    '--checker', checker,
    '--sample-interval-ms', '1000',
    '--max-runtime-ms', '60000',
    '--',
    ...forwarded(state)
  ], {
    encoding: 'utf8',
    timeout: 10_000,
    env: { ...process.env, ...extraEnv }
  })
}

function forwarded (state) {
  return [
    '--target', 'v1.2.3',
    '--channel', 'canary',
    '--gateway-evidence', '/root/evidence.json',
    '--gateway-manifest', 'fleet/public-hive-gateway-release.json',
    '--gateway-window-state', state,
    '--evidence', '/tmp/rollout.json',
    '--known-hosts', '/tmp/known-hosts',
    '--allowed-signers', '/tmp/allowed-signers'
  ]
}
