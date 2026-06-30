import test from 'brittle'
import { execFile } from 'node:child_process'

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
  t.ok(res.stdout.includes('HiveRelay npm latest dist-tag check (expected 0.20.2)'))
  t.ok(res.stdout.includes('FAIL p2p-hiverelay: latest=0.9.2'))
  t.ok(res.stdout.includes('FAIL p2p-hiveservices: latest=0.9.2'))
  t.ok(res.stdout.includes('Blocked: app lockfiles and live consumer promotion must wait until npm latest points at this release.'))
  t.alike(res.stderr, '')
})

test('npm latest check passes once every package latest tag matches the release', async (t) => {
  const res = await runCheck([], npmLatestEnv('0.20.2'))

  t.is(res.status, 0)
  t.ok(res.stdout.includes('PASS p2p-hiverelay: latest=0.20.2'))
  t.ok(res.stdout.includes('PASS p2p-hiverelay-client: latest=0.20.2'))
  t.ok(res.stdout.includes('PASS p2p-hiverelay-verifier: latest=0.20.2'))
  t.ok(res.stdout.includes('PASS p2p-hiveservices: latest=0.20.2'))
  t.ok(res.stdout.includes('All HiveRelay npm latest dist-tags are promoted.'))
})

test('npm latest check emits machine-readable release evidence', async (t) => {
  const res = await runCheck(['--json'], npmLatestEnv('0.9.2'))
  const payload = JSON.parse(res.stdout)

  t.is(res.status, 1)
  t.is(payload.ok, false)
  t.is(payload.expectedVersion, '0.20.2')
  t.alike(payload.packages, [
    'p2p-hiverelay',
    'p2p-hiverelay-client',
    'p2p-hiverelay-verifier',
    'p2p-hiveservices'
  ])
  t.is(payload.checks.length, 4)
  t.ok(payload.errors.some(error => error.includes('p2p-hiveservices npm latest dist-tag is 0.9.2; expected 0.20.2')))
})

test('npm latest check distinguishes unverified registry proof from missing latest tags', async (t) => {
  const res = await runCheck([], {
    PATH: ''
  })

  t.is(res.status, 1)
  t.ok(res.stdout.includes('FAIL p2p-hiverelay: latest=unverified (Could not verify npm latest dist-tag for p2p-hiverelay:'))
  t.absent(res.stdout.includes('FAIL p2p-hiverelay: latest=(missing)'))
})
