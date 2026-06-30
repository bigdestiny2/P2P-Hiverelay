import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
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
const OFFICIAL_PR = 'https://github.com/getumbrel/umbrel-apps/pull/123'

function runNode (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, argv, {
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

async function writeValidEvidence (dir) {
  const file = path.join(dir, 'umbrel-runtime-review-evidence.json')
  const res = await runNode([
    'scripts/write-umbrel-runtime-review-evidence.mjs',
    '--out', file,
    '--release', 'v9.9.9',
    '--device', 'Umbrel Home test appliance',
    '--umbrel-version', '1.3.0',
    '--tested-by', 'bigdestiny2',
    '--public-key-before', PUBLIC_KEY,
    '--public-key-after', PUBLIC_KEY,
    '--checks', CHECKS.join(','),
    '--official-pr-url', OFFICIAL_PR
  ])
  if (res.status !== 0) {
    throw new Error(`writer failed:\n${res.stderr}`)
  }
  return file
}

async function readJson (file) {
  return JSON.parse(await readFile(file, 'utf8'))
}

async function writeJson (file, body) {
  await writeFile(file, JSON.stringify(body, null, 2) + '\n')
}

function runVerifier (file, argv = []) {
  return runNode([
    'scripts/verify-umbrel-runtime-review-evidence.mjs',
    '--evidence', file,
    ...argv
  ])
}

test('Umbrel runtime review verifier accepts writer-produced evidence', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)

  const res = await runVerifier(file, [
    '--release', 'v9.9.9',
    '--official-pr-url', OFFICIAL_PR
  ])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('Umbrel runtime review evidence verified: v9.9.9'))
})

test('Umbrel runtime review verifier rejects missing, duplicate, and failed checks', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)

  body.checks = body.checks.filter(check => check.name !== 'dynamicPayoutControlsObserved')
  const missingFile = path.join(dir, 'missing-check.json')
  await writeJson(missingFile, body)
  const missing = await runVerifier(missingFile)
  t.is(missing.status, 1)
  t.ok(missing.stderr.includes('Missing Umbrel runtime checks: dynamicPayoutControlsObserved'))

  const duplicateBody = await readJson(file)
  duplicateBody.checks.push({ name: 'addWalletPersists', status: 'passed' })
  const duplicateFile = path.join(dir, 'duplicate-check.json')
  await writeJson(duplicateFile, duplicateBody)
  const duplicate = await runVerifier(duplicateFile)
  t.is(duplicate.status, 1)
  t.ok(duplicate.stderr.includes('Duplicate Umbrel runtime check: addWalletPersists'))

  const failedBody = await readJson(file)
  failedBody.checks.find(check => check.name === 'addWalletPersists').status = 'failed'
  const failedFile = path.join(dir, 'failed-check.json')
  await writeJson(failedFile, failedBody)
  const failed = await runVerifier(failedFile)
  t.is(failed.status, 1)
  t.ok(failed.stderr.includes('Umbrel runtime check addWalletPersists'))
})

test('Umbrel runtime review verifier rejects release and PR drift', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)

  const release = await runVerifier(file, ['--release', 'v9.9.8'])
  t.is(release.status, 1)
  t.ok(release.stderr.includes('release.version must be "v9.9.8"'))

  const pr = await runVerifier(file, [
    '--official-pr-url', 'https://github.com/getumbrel/umbrel-apps/pull/124'
  ])
  t.is(pr.status, 1)
  t.ok(pr.stderr.includes('official Umbrel PR URL must be "https://github.com/getumbrel/umbrel-apps/pull/124"'))
})

test('Umbrel runtime review verifier rejects future evidence timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)
  body.generatedAt = new Date(Date.now() + 60 * 60 * 1000).toISOString()
  await writeJson(file, body)

  const res = await runVerifier(file)

  t.is(res.status, 1)
  t.ok(res.stderr.includes('generatedAt must not be in the future'))
})

test('Umbrel runtime review verifier rejects reinstall public-key hash drift', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)

  body.identity.publicKeyAfterSha256 = 'b'.repeat(64)
  const driftFile = path.join(dir, 'hash-drift.json')
  await writeJson(driftFile, body)

  const drift = await runVerifier(driftFile)

  t.is(drift.status, 1)
  t.ok(drift.stderr.includes('relay public key hash after reinstall'))
})

test('Umbrel runtime review verifier rejects local details, secrets, and raw public-key fields', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)

  body.platform.device = 'Umbrel at http://192.168.1.42'
  const localFile = path.join(dir, 'local-url.json')
  await writeJson(localFile, body)
  const local = await runVerifier(localFile)
  t.is(local.status, 1)
  t.ok(local.stderr.includes('must not contain non-public URL') || local.stderr.includes('must not include local hostnames'))

  const secretBody = await readJson(file)
  secretBody.review.testedBy = 'APP_SEED=do-not-publish'
  const secretFile = path.join(dir, 'secret.json')
  await writeJson(secretFile, secretBody)
  const secret = await runVerifier(secretFile)
  t.is(secret.status, 1)
  t.ok(secret.stderr.includes('must not contain APP_SEED'))

  const rawKeyBody = await readJson(file)
  rawKeyBody.identity.publicKey = PUBLIC_KEY
  const rawKeyFile = path.join(dir, 'raw-key.json')
  await writeJson(rawKeyFile, rawKeyBody)
  const rawKey = await runVerifier(rawKeyFile)
  t.is(rawKey.status, 1)
  t.ok(rawKey.stderr.includes('must not expose raw public key fields'))
})

test('Umbrel runtime review verifier rejects placeholder and credentialed public URLs', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)

  const placeholderBody = await readJson(file)
  placeholderBody.platform.device = 'https://example.com'
  const placeholderFile = path.join(dir, 'placeholder-url.json')
  await writeJson(placeholderFile, placeholderBody)
  const placeholder = await runVerifier(placeholderFile)
  t.is(placeholder.status, 1)
  t.ok(placeholder.stderr.includes('must not contain non-public URL'))

  const credentialBody = await readJson(file)
  credentialBody.review.testedBy = 'https://reviewer:secret@review.example'
  const credentialFile = path.join(dir, 'credentialed-url.json')
  await writeJson(credentialFile, credentialBody)
  const credential = await runVerifier(credentialFile)
  t.is(credential.status, 1)
  t.ok(credential.stderr.includes('must not expose URL credentials'))
})

test('Umbrel runtime review verifier rejects unsupported schema fields', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)

  const topLevelBody = await readJson(file)
  topLevelBody.marketplacePublished = true
  const topLevelFile = path.join(dir, 'extra-top-level.json')
  await writeJson(topLevelFile, topLevelBody)
  const topLevel = await runVerifier(topLevelFile)
  t.is(topLevel.status, 1)
  t.ok(topLevel.stderr.includes('Umbrel runtime review evidence has unsupported fields: marketplacePublished'))

  const nestedBody = await readJson(file)
  nestedBody.platform.extraReviewClaim = 'dashboard reviewed through app proxy'
  const nestedFile = path.join(dir, 'extra-nested.json')
  await writeJson(nestedFile, nestedBody)
  const nested = await runVerifier(nestedFile)
  t.is(nested.status, 1)
  t.ok(nested.stderr.includes('platform has unsupported fields: extraReviewClaim'))

  const checkBody = await readJson(file)
  checkBody.checks[0].notes = 'Manual install reviewed'
  const checkFile = path.join(dir, 'extra-check-field.json')
  await writeJson(checkFile, checkBody)
  const check = await runVerifier(checkFile)
  t.is(check.status, 1)
  t.ok(check.stderr.includes('Umbrel runtime check installedThroughUmbrel has unsupported fields: notes'))
})

test('Umbrel runtime review verifier rejects unsafe evidence files before parsing', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)

  const symlinkFile = path.join(dir, 'symlink-review.json')
  await symlink(file, symlinkFile)
  const symlinkRes = await runVerifier(symlinkFile)
  t.is(symlinkRes.status, 1)
  t.ok(symlinkRes.stderr.includes('file must not be a symlink'))

  const directoryFile = path.join(dir, 'directory-review.json')
  await mkdir(directoryFile)
  const directoryRes = await runVerifier(directoryFile)
  t.is(directoryRes.status, 1)
  t.ok(directoryRes.stderr.includes('file must be a regular file'))

  const oversizedFile = path.join(dir, 'oversized-review.json')
  await writeFile(oversizedFile, '{"pad":"' + 'x'.repeat(2 * 1024 * 1024) + '"}\n')
  const oversizedRes = await runVerifier(oversizedFile)
  t.is(oversizedRes.status, 1)
  t.ok(oversizedRes.stderr.includes('file must be 2097152 bytes or smaller'))
})

test('Umbrel runtime review verifier rejects malformed upstream PR URLs', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)
  body.officialUmbrelPr.url = 'https://github.com/example/umbrel-apps/pull/123'
  await writeJson(file, body)

  const res = await runVerifier(file)

  t.is(res.status, 1)
  t.ok(res.stderr.includes('official Umbrel PR URL'))
})

test('Umbrel runtime review verifier requires upstream PR binding', async (t) => {
  const dir = await fixtureDir(t)
  const file = await writeValidEvidence(dir)
  const body = await readJson(file)
  delete body.officialUmbrelPr
  await writeJson(file, body)

  const res = await runVerifier(file)

  t.is(res.status, 1)
  t.ok(res.stderr.includes('officialUmbrelPr must be an object') || res.stderr.includes('official Umbrel PR URL'))
})

async function fixtureDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-umbrel-runtime-verify-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}
