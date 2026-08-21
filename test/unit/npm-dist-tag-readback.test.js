import test from 'brittle'
import { readFile } from 'node:fs/promises'
import {
  ensureNpmDistTag,
  execOutputWithTimeout,
  probeNpmPackageVersion
} from '../../scripts/ensure-npm-dist-tag.mjs'

const PACKAGE = 'p2p-hiverelay-client'
const VERSION = '0.26.0-rc.3'
const OLD_VERSION = '0.25.0-rc.9'

function sequence (values) {
  let index = 0
  return async () => {
    const value = values[Math.min(index++, values.length - 1)]
    if (value instanceof Error) throw value
    return value
  }
}

function fixture (overrides = {}) {
  const delays = []
  const logs = []
  const addCalls = []
  return {
    options: {
      packageName: PACKAGE,
      version: VERSION,
      distTag: 'next',
      attempts: 4,
      initialDelayMs: 10,
      maxDelayMs: 20,
      viewPackageVersion: async () => VERSION,
      viewDistTag: async () => VERSION,
      addDistTag: async (...args) => { addCalls.push(args) },
      sleep: async (delayMs) => { delays.push(delayMs) },
      log: (line) => { logs.push(line) },
      ...overrides
    },
    delays,
    logs,
    addCalls
  }
}

test('npm dist-tag readback retries package visibility and stale registry reads', async (t) => {
  const f = fixture({
    viewPackageVersion: sequence([new Error('404 Not Found'), OLD_VERSION, VERSION]),
    viewDistTag: sequence([OLD_VERSION, OLD_VERSION, VERSION])
  })

  const result = await ensureNpmDistTag(f.options)

  t.is(result.packageVisibilityAttempts, 3)
  t.is(result.distTagReadbackAttempts, 3)
  t.is(result.mutationRequested, true)
  t.alike(f.addCalls, [[PACKAGE, VERSION, 'next']])
  t.alike(f.delays, [10, 20, 10, 20])
  t.ok(f.logs.some(line => line.includes('404 Not Found')))
  t.ok(f.logs.some(line => line.includes(`returned ${OLD_VERSION}`)))
})

test('npm dist-tag readback leaves an already-current tag untouched', async (t) => {
  const f = fixture()

  const result = await ensureNpmDistTag(f.options)

  t.is(result.packageVisibilityAttempts, 1)
  t.is(result.distTagReadbackAttempts, 1)
  t.is(result.mutationRequested, false)
  t.alike(f.addCalls, [])
  t.alike(f.delays, [])
})

test('npm dist-tag readback retries a transient mutation failure', async (t) => {
  let addAttempts = 0
  const f = fixture({
    viewDistTag: sequence([OLD_VERSION, OLD_VERSION, VERSION]),
    addDistTag: async (...args) => {
      f.addCalls.push(args)
      addAttempts++
      if (addAttempts === 1) throw new Error('503 Service Unavailable')
    }
  })

  const result = await ensureNpmDistTag(f.options)

  t.is(result.distTagReadbackAttempts, 3)
  t.is(result.mutationRequested, true)
  t.is(f.addCalls.length, 2)
  t.alike(f.delays, [10, 20])
  t.ok(f.logs.some(line => line.includes('503 Service Unavailable')))
})

test('npm dist-tag readback fails closed when package visibility never converges', async (t) => {
  const f = fixture({
    attempts: 3,
    initialDelayMs: 5,
    maxDelayMs: 10,
    viewPackageVersion: async () => { throw new Error('404 Not Found') }
  })

  await t.exception(
    ensureNpmDistTag(f.options),
    /npm package p2p-hiverelay-client@0\.26\.0-rc\.3 was not visible after 3 attempts/
  )
  t.alike(f.addCalls, [])
  t.alike(f.delays, [5, 10])
})

test('npm dist-tag readback fails closed when the tag stays stale', async (t) => {
  const f = fixture({
    attempts: 3,
    initialDelayMs: 5,
    maxDelayMs: 10,
    viewDistTag: async () => OLD_VERSION
  })

  await t.exception(
    ensureNpmDistTag(f.options),
    /npm 'next' dist-tag did not converge to 0\.26\.0-rc\.3 after 3 attempts; last observation: 0\.25\.0-rc\.9/
  )
  t.is(f.addCalls.length, 1)
  t.alike(f.delays, [5, 10])
})

test('npm command timeout kills a hung registry subprocess', async (t) => {
  t.timeout(5000)
  const startedAt = Date.now()

  await t.exception(
    execOutputWithTimeout(process.execPath, [
      '-e',
      'setInterval(() => {}, 1000)'
    ], { timeoutMs: 50 }),
    /node command timed out after 50ms/
  )

  t.ok(Date.now() - startedAt < 2000, 'hung child is killed within the bounded timeout')
})

test('npm existence probe distinguishes an explicit E404 from a published version', async (t) => {
  const visible = await probeNpmPackageVersion({
    packageName: PACKAGE,
    version: VERSION,
    viewPackageVersion: async () => VERSION
  })
  const missingError = Object.assign(new Error('npm view failed'), {
    stderr: `npm error code E404\nnpm error 404 ${PACKAGE}@${VERSION} is not in this registry`
  })
  const missing = await probeNpmPackageVersion({
    packageName: PACKAGE,
    version: VERSION,
    viewPackageVersion: async () => { throw missingError }
  })

  t.is(visible, true)
  t.is(missing, false)
})

test('npm existence probe fails closed on registry timeouts and ambiguous output', async (t) => {
  const timeoutError = Object.assign(new Error('npm command timed out after 30ms'), {
    code: 'ETIMEDOUT',
    stderr: 'npm error code E404 from partial output before the timeout'
  })

  await t.exception(
    probeNpmPackageVersion({
      packageName: PACKAGE,
      version: VERSION,
      viewPackageVersion: async () => { throw timeoutError }
    }),
    /Could not determine whether p2p-hiverelay-client@0\.26\.0-rc\.3 already exists on npm: npm command timed out/
  )
  await t.exception(
    probeNpmPackageVersion({
      packageName: PACKAGE,
      version: VERSION,
      viewPackageVersion: async () => OLD_VERSION
    }),
    /npm returned 0\.25\.0-rc\.9 while probing p2p-hiverelay-client@0\.26\.0-rc\.3/
  )
})

test('release workflow verifies bounded npm readback before downstream surfaces', async (t) => {
  const workflow = await readFile('.github/workflows/release-surfaces.yml', 'utf8')
  const probe = workflow.indexOf('--probe-only')
  const publish = workflow.indexOf('npm publish "./$pkg" --access public --tag "$dist_tag"')
  const readback = workflow.indexOf('node scripts/ensure-npm-dist-tag.mjs', publish)
  const docker = workflow.indexOf('- name: Setup Docker Buildx')

  t.ok(probe >= 0)
  t.ok(publish > probe)
  t.ok(readback > publish)
  t.ok(docker > readback)
  t.ok(workflow.includes('--attempts 12'))
  t.ok(workflow.includes('--initial-delay-ms 2000'))
  t.ok(workflow.includes('--max-delay-ms 15000'))
  t.is(workflow.match(/--command-timeout-ms 30000/g)?.length, 2)
  t.absent(workflow.includes('if npm view "$name@$version" version'))
  t.absent(workflow.includes('current="$(npm view "$name" "dist-tags.$dist_tag")"'))
})
