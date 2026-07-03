import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

// check-npm-latest.mjs derives "expected" from the REAL repo package.json, so
// these expectations must track it dynamically — hardcoding a version rots the
// suite red on every release bump (was pinned at 0.20.2). 0.9.2 below stays a
// literal: it is the intentionally-stale "would downgrade" value.
const RELEASE_VERSION = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url), 'utf8')
).version

function runCheck (argv = [], env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-npm-latest.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH || '',
        ...env
      },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

async function tempDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-npm-latest-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

function npmLatestEnv (version) {
  return {
    HIVERELAY_NPM_LATEST_JSON: JSON.stringify({
      'p2p-hiverelay': version,
      'p2p-hiverelay-client': version,
      'p2p-hiverelay-verifier': version,
      'p2p-hiveservices': version
    })
  }
}

test('npm latest check fails while registry latest would downgrade app consumers', async (t) => {
  const res = await runCheck([], npmLatestEnv('0.9.2'))

  t.is(res.status, 1)
  t.ok(res.stdout.includes(`HiveRelay npm latest dist-tag check (expected ${RELEASE_VERSION})`))
  t.ok(res.stdout.includes('FAIL p2p-hiverelay: latest=0.9.2'))
  t.ok(res.stdout.includes('FAIL p2p-hiveservices: latest=0.9.2'))
  t.ok(res.stdout.includes('Blocked: app lockfiles and live consumer promotion must wait until npm latest points at this release.'))
  t.alike(res.stderr, '')
})

test('npm latest check passes once every package latest tag matches the release', async (t) => {
  const res = await runCheck([], npmLatestEnv(RELEASE_VERSION))

  t.is(res.status, 0)
  t.ok(res.stdout.includes(`PASS p2p-hiverelay: latest=${RELEASE_VERSION}`))
  t.ok(res.stdout.includes(`PASS p2p-hiverelay-client: latest=${RELEASE_VERSION}`))
  t.ok(res.stdout.includes(`PASS p2p-hiverelay-verifier: latest=${RELEASE_VERSION}`))
  t.ok(res.stdout.includes(`PASS p2p-hiveservices: latest=${RELEASE_VERSION}`))
  t.ok(res.stdout.includes('All HiveRelay npm latest dist-tags are promoted.'))
})

test('npm latest check emits machine-readable release evidence', async (t) => {
  const res = await runCheck(['--json'], npmLatestEnv('0.9.2'))
  const payload = JSON.parse(res.stdout)

  t.is(res.status, 1)
  t.is(payload.schemaVersion, 1)
  t.is(payload.kind, 'hiverelay-npm-latest-evidence')
  t.is(payload.ok, false)
  t.is(payload.status, 'blocked')
  t.is(payload.expectedVersion, RELEASE_VERSION)
  t.alike(payload.packages, [
    'p2p-hiverelay',
    'p2p-hiverelay-client',
    'p2p-hiverelay-verifier',
    'p2p-hiveservices'
  ])
  t.is(payload.checks.length, 4)
  t.ok(payload.errors.some(error => error.includes(`p2p-hiveservices npm latest dist-tag is 0.9.2; expected ${RELEASE_VERSION}`)))
})

test('npm latest check writes reusable evidence sidecar only after verified latest tags', async (t) => {
  const dir = await tempDir(t)
  const outFile = path.join(dir, 'npm-latest-evidence.json')
  const res = await runCheck(['--json', '--out', outFile], npmLatestEnv(RELEASE_VERSION))

  t.is(res.status, 0)
  t.alike(res.stderr, '')

  const payload = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(payload.schemaVersion, 1)
  t.is(payload.kind, 'hiverelay-npm-latest-evidence')
  t.is(payload.ok, true)
  t.is(payload.status, 'verified')
  t.is(payload.expectedVersion, RELEASE_VERSION)
  t.is(payload.checks.length, 4)
  t.ok(payload.checks.every(check => check.ok === true && check.latest === RELEASE_VERSION))
})

test('npm latest check refuses to write reusable evidence when latest tags are stale', async (t) => {
  const dir = await tempDir(t)
  const outFile = path.join(dir, 'npm-latest-evidence.json')
  const res = await runCheck(['--json', '--out', outFile], npmLatestEnv('0.9.2'))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Refusing to write npm latest evidence'))
  try {
    await readFile(outFile, 'utf8')
    t.fail('stale npm latest proof should not write a sidecar')
  } catch (err) {
    t.is(err.code, 'ENOENT')
  }
})

test('npm latest check distinguishes unverified registry proof from missing latest tags', async (t) => {
  const res = await runCheck([], {
    PATH: ''
  })

  t.is(res.status, 1)
  t.ok(res.stdout.includes('FAIL p2p-hiverelay: latest=unverified (Could not verify npm latest dist-tag for p2p-hiverelay:'))
  t.absent(res.stdout.includes('FAIL p2p-hiverelay: latest=(missing)'))
})
