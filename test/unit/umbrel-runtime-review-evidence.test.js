import crypto from 'node:crypto'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'brittle'

const CHECKS = [
  'installedThroughUmbrel',
  'dashboardProxyLoads',
  'liveFeedInBandAuth',
  'noWebSocketUrlTokens',
  'wizardCompletes',
  'setupActionLockObserved',
  'addWalletPersists',
  'dynamicPayoutControlsObserved',
  'walletBusyStateObserved',
  'managementActionsPersist',
  'serviceActionStateObserved',
  'serviceRestartPendingObserved',
  'aiModelAddStateObserved',
  'reviewModeDefault',
  'dataWritableUid999',
  'reinstallPreservesPublicKey'
]

const PUBLIC_KEY = 'a'.repeat(64)
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

function runWriter (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/write-umbrel-runtime-review-evidence.mjs', ...argv], {
      cwd: process.cwd(),
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

function validArgs (outFile, overrides = {}) {
  const values = {
    out: outFile,
    release: 'v9.9.9',
    device: 'Umbrel Home test appliance',
    umbrelVersion: '1.3.0',
    testedBy: 'bigdestiny2',
    publicKeyBefore: PUBLIC_KEY,
    publicKeyAfter: PUBLIC_KEY,
    checks: CHECKS.join(','),
    officialPrUrl: 'https://github.com/getumbrel/umbrel-apps/pull/123',
    ...overrides
  }

  return [
    '--out', values.out,
    '--release', values.release,
    '--device', values.device,
    '--umbrel-version', values.umbrelVersion,
    '--tested-by', values.testedBy,
    '--public-key-before', values.publicKeyBefore,
    '--public-key-after', values.publicKeyAfter,
    '--checks', values.checks,
    '--official-pr-url', values.officialPrUrl
  ]
}

test('Umbrel runtime review evidence writer keeps a closed public schema', async (t) => {
  const script = await readFile('scripts/write-umbrel-runtime-review-evidence.mjs', 'utf8')

  t.ok(script.includes('assertRuntimeReviewEvidenceSchema(body)'))
  t.ok(script.includes('function assertRuntimeReviewEvidenceSchema'))
  t.ok(script.includes("requireOnlyKeys('Umbrel runtime review evidence'"))
  t.ok(script.includes('has unsupported fields'))
})

test('Umbrel runtime review evidence writer records public-safe manual checks', async (t) => {
  const dir = await fixtureDir(t)
  const outFile = path.join(dir, 'umbrel-runtime-review-evidence.json')

  const res = await runWriter(validArgs(outFile))

  t.is(res.status, 0)
  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.ok(ISO_TIMESTAMP_PATTERN.test(body.generatedAt), 'Umbrel runtime review evidence generatedAt is an ISO timestamp')
  t.is(body.kind, 'umbrel-runtime-review')
  t.is(body.status, 'passed')
  t.is(body.release.version, 'v9.9.9')
  t.is(body.release.semver, '9.9.9')
  t.is(body.platform.name, 'umbrel')
  t.is(body.platform.device, 'Umbrel Home test appliance')
  t.is(body.platform.umbrelVersion, '1.3.0')
  t.is(body.review.testedBy, 'bigdestiny2')
  t.is(body.identity.publicKeySha256, sha256Hex(PUBLIC_KEY))
  t.is(body.identity.publicKeyBeforeSha256, sha256Hex(PUBLIC_KEY))
  t.is(body.identity.publicKeyAfterSha256, sha256Hex(PUBLIC_KEY))
  t.alike(body.checks.map(check => check.name), CHECKS)
  t.ok(body.checks.every(check => check.status === 'passed'))
  t.is(body.officialUmbrelPr.url, 'https://github.com/getumbrel/umbrel-apps/pull/123')
})

test('Umbrel runtime review evidence writer rejects missing manual checks', async (t) => {
  const dir = await fixtureDir(t)
  const outFile = path.join(dir, 'missing-check.json')
  const checks = CHECKS.filter(check => check !== 'setupActionLockObserved').join(',')

  const res = await runWriter(validArgs(outFile, { checks }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Missing Umbrel runtime checks: setupActionLockObserved'))
})

test('Umbrel runtime review evidence writer rejects reinstall public-key drift', async (t) => {
  const dir = await fixtureDir(t)
  const outFile = path.join(dir, 'key-drift.json')

  const res = await runWriter(validArgs(outFile, {
    publicKeyAfter: 'b'.repeat(64)
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('relay public key after reinstall'))
})

test('Umbrel runtime review evidence writer rejects local details and secrets', async (t) => {
  const dir = await fixtureDir(t)

  const localRes = await runWriter(validArgs(path.join(dir, 'local-device.json'), {
    device: 'Umbrel at 192.168.1.42'
  }))
  t.is(localRes.status, 1)
  t.ok(localRes.stderr.includes('must not include local hostnames or LAN addresses'))

  const secretRes = await runWriter(validArgs(path.join(dir, 'seed-label.json'), {
    testedBy: 'APP_SEED=do-not-publish'
  }))
  t.is(secretRes.status, 1)
  t.ok(secretRes.stderr.includes('must not contain APP_SEED'))
})

test('Umbrel runtime review evidence writer rejects placeholder and credentialed public URLs', async (t) => {
  const dir = await fixtureDir(t)

  const placeholderRes = await runWriter(validArgs(path.join(dir, 'placeholder-url.json'), {
    device: 'https://example.com'
  }))
  t.is(placeholderRes.status, 1)
  t.ok(placeholderRes.stderr.includes('must not contain non-public URL'))

  const credentialRes = await runWriter(validArgs(path.join(dir, 'credentialed-url.json'), {
    testedBy: 'https://reviewer:secret@review.example'
  }))
  t.is(credentialRes.status, 1)
  t.ok(credentialRes.stderr.includes('must not expose URL credentials'))
})

test('Umbrel runtime review evidence writer rejects non-upstream PR URLs', async (t) => {
  const dir = await fixtureDir(t)
  const outFile = path.join(dir, 'wrong-pr.json')

  const res = await runWriter(validArgs(outFile, {
    officialPrUrl: 'https://github.com/example/umbrel-apps/pull/123'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('official Umbrel PR URL'))
})

test('Umbrel runtime review evidence writer requires upstream PR binding', async (t) => {
  const dir = await fixtureDir(t)
  const outFile = path.join(dir, 'missing-pr.json')

  const res = await runWriter([
    '--out', outFile,
    '--release', 'v9.9.9',
    '--device', 'Umbrel Home test appliance',
    '--umbrel-version', '1.3.0',
    '--tested-by', 'bigdestiny2',
    '--public-key-before', PUBLIC_KEY,
    '--public-key-after', PUBLIC_KEY,
    '--checks', CHECKS.join(',')
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('official Umbrel PR URL'))
})

async function fixtureDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-umbrel-runtime-review-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

function sha256Hex (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}
