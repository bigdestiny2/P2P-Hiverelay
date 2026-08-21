import test from 'brittle'
import { readFile } from 'node:fs/promises'
import { ensureNpmDistTag } from '../../scripts/ensure-npm-dist-tag.mjs'

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

test('release workflow verifies bounded npm readback before downstream surfaces', async (t) => {
  const workflow = await readFile('.github/workflows/release-surfaces.yml', 'utf8')
  const publish = workflow.indexOf('npm publish "./$pkg" --access public --tag "$dist_tag"')
  const readback = workflow.indexOf('node scripts/ensure-npm-dist-tag.mjs')
  const docker = workflow.indexOf('- name: Setup Docker Buildx')

  t.ok(publish >= 0)
  t.ok(readback > publish)
  t.ok(docker > readback)
  t.ok(workflow.includes('--attempts 12'))
  t.ok(workflow.includes('--initial-delay-ms 2000'))
  t.ok(workflow.includes('--max-delay-ms 15000'))
  t.absent(workflow.includes('current="$(npm view "$name" "dist-tags.$dist_tag")"'))
})
