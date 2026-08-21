import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdir as fsMkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

const VERSION = JSON.parse(readFileSync('package.json', 'utf8')).version
const TEST_GITHUB_TOKEN = `ghp_${'a'.repeat(36)}`
const TEST_GITHUB_TOKEN_ALT = `gho_${'b'.repeat(36)}`
const TEST_GITHUB_TOKEN_ECOSYSTEM = `ghu_${'e'.repeat(36)}`
const TEST_NPM_TOKEN = `npm_${'c'.repeat(36)}`
const TEST_PRIVATE_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nfake-fleet-key\n-----END OPENSSH PRIVATE KEY-----'
const TEST_STARTOS_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nfake-startos-key\n-----END PRIVATE KEY-----'
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024

function runCheck (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-release-blockers.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH || ''
      },
      timeout: 20000
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
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-blockers-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

async function writeJson (file, body) {
  await writeFile(file, JSON.stringify(body, null, 2) + '\n')
}

async function validEnvFile (t) {
  const dir = await tempDir(t)
  const file = path.join(dir, 'release.env')
  const lines = [
    'FLEET_SSH_PRIVATE_KEY<<FLEET_KEY',
    TEST_PRIVATE_KEY,
    'FLEET_KEY',
    `UMBREL_STORE_TOKEN=${TEST_GITHUB_TOKEN}`,
    `UMBREL_OFFICIAL_PR_TOKEN=${TEST_GITHUB_TOKEN_ALT}`,
    `ECOSYSTEM_CONSUMER_TOKEN=${TEST_GITHUB_TOKEN_ECOSYSTEM}`,
    'UMBREL_OFFICIAL_FORK=bigdestiny2/umbrel-apps',
    `NPM_TOKEN=${TEST_NPM_TOKEN}`,
    'STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY',
    TEST_STARTOS_PRIVATE_KEY,
    'STARTOS_KEY',
    'STARTOS_REGISTRY_URL=https://registry.start9.com/startos'
  ]
  await writeFile(file, lines.join('\n') + '\n')
  return file
}

function latestFixture (version = VERSION) {
  return {
    'p2p-hiverelay': version,
    'p2p-hiverelay-client': version,
    'p2p-hiverelay-verifier': version,
    'p2p-hiveservices': version
  }
}

function npmLatestEvidence (version = VERSION) {
  return {
    schemaVersion: 1,
    kind: 'hiverelay-npm-latest-evidence',
    ok: true,
    status: 'verified',
    generatedAt: '2026-07-01T00:00:00.000Z',
    expectedVersion: version,
    packages: [
      'p2p-hiverelay',
      'p2p-hiverelay-client',
      'p2p-hiverelay-verifier',
      'p2p-hiveservices'
    ],
    checks: Object.keys(latestFixture(version)).map(name => ({
      name,
      ok: true,
      latest: version
    })),
    errors: [],
    warnings: []
  }
}

test('release blocker closure script is exposed as a package command', (t) => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
  t.is(pkg.scripts['release:check-blockers'], 'node scripts/check-release-blockers.mjs')
  const source = readFileSync('scripts/check-release-blockers.mjs', 'utf8')
  t.ok(source.includes("argv: ['--bundle-dir', bundleDir, '--live-github', '--expected-prerelease', String(prerelease)]"))
})

test('release blocker closure reports missing full-release evidence', async (t) => {
  const dir = await tempDir(t)
  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])

  t.is(res.status, 1)
  t.is(res.stderr, '')

  const report = JSON.parse(res.stdout)
  t.is(report.kind, 'hiverelay-release-blocker-closure')
  t.is(report.status, 'blocked')
  t.ok(report.totals.blocker > 0)
  t.is(item(report, 'bundle.dir').status, 'pass')
  t.is(item(report, 'distribution.env').status, 'blocker')
  t.is(item(report, 'npm.latest').status, 'blocker')
  t.is(item(report, 'evidence.release').status, 'blocker')
  t.is(item(report, 'evidence.image-manifest').status, 'blocker')
  t.is(item(report, 'evidence.official-umbrel-pr').status, 'blocker')
  t.is(item(report, 'evidence.official-umbrel-pr').command, 'npm run release:write-official-umbrel-pr-evidence -- --out official-umbrel-pr-evidence.json')
  t.is(item(report, 'evidence.umbrel-runtime-review').status, 'blocker')
  t.is(item(report, 'artifact.startos04-package').status, 'blocker')
  t.is(item(report, 'evidence.startos04-release').status, 'blocker')
  t.is(item(report, 'evidence.release-closure').status, 'blocker')
  t.is(item(report, 'release.handoff.verify').status, 'blocker')
  t.is(item(report, 'release.closure.verify').status, 'blocker')
  t.is(item(report, 'release.closure.verify').command, 'GH_TOKEN=<token> npm run release:verify-closure-evidence -- --bundle-dir <dir> --live-github --expected-prerelease false')
  t.absent(res.stdout.includes(TEST_GITHUB_TOKEN))
  t.absent(res.stdout.includes(TEST_NPM_TOKEN))
})

test('release blocker closure writes public-safe JSON report when blocked', async (t) => {
  const dir = await tempDir(t)
  const envFile = await validEnvFile(t)
  const outFile = path.join(dir, 'release-blockers-report.json')

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', dir,
    '--env-file', envFile,
    '--out', outFile
  ])

  t.is(res.status, 1)
  t.is(res.stderr, '')

  const stdoutReport = JSON.parse(res.stdout)
  const fileReport = JSON.parse(await readFile(outFile, 'utf8'))
  const fileText = JSON.stringify(fileReport)

  t.alike(fileReport, stdoutReport)
  t.is(fileReport.kind, 'hiverelay-release-blocker-closure')
  t.is(fileReport.status, 'blocked')
  t.ok(fileReport.totals.blocker > 0)
  t.absent(fileText.includes(TEST_GITHUB_TOKEN))
  t.absent(fileText.includes(TEST_GITHUB_TOKEN_ALT))
  t.absent(fileText.includes(TEST_GITHUB_TOKEN_ECOSYSTEM))
  t.absent(fileText.includes(TEST_NPM_TOKEN))
  t.absent(fileText.includes(TEST_PRIVATE_KEY))
  t.absent(fileText.includes(TEST_STARTOS_PRIVATE_KEY))
})

test('release blocker closure redacts top-level report paths before printing or writing', async (t) => {
  const dir = await tempDir(t)
  const secretBundleDir = path.join(dir, `bundle-${TEST_GITHUB_TOKEN}`)
  const outFile = path.join(dir, 'release-blockers-report.json')

  await fsMkdir(secretBundleDir)

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', secretBundleDir,
    '--out', outFile
  ])

  t.is(res.status, 1)
  t.is(res.stderr, '')

  const stdoutReport = JSON.parse(res.stdout)
  const fileReport = JSON.parse(await readFile(outFile, 'utf8'))
  const stdoutText = JSON.stringify(stdoutReport)
  const fileText = JSON.stringify(fileReport)

  t.alike(fileReport, stdoutReport)
  t.absent(stdoutText.includes(TEST_GITHUB_TOKEN))
  t.absent(fileText.includes(TEST_GITHUB_TOKEN))
  t.ok(stdoutReport.bundleDir.includes('[redacted GitHub token]'))
  t.ok(fileReport.bundleDir.includes('[redacted GitHub token]'))
})

test('release blocker closure recommends artifact-producing commands for missing sidecars', async (t) => {
  const dir = await tempDir(t)
  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)

  t.is(res.status, 1)
  t.is(item(report, 'evidence.release').command, 'npm run release:write-evidence -- --out release-evidence.json')
  t.is(item(report, 'evidence.image-manifest').command, 'npm run release:check-image-manifest -- --image <ref>@sha256:<digest> --out release-image-manifest-evidence.json')
  t.is(item(report, 'evidence.image-smoke').command, 'npm run release:smoke-image -- <ref>@sha256:<digest> --evidence release-image-smoke-evidence.json')
  t.is(item(report, 'evidence.umbrel-package-smoke').command, 'npm run umbrel:smoke-package -- --image-ref <ref>@sha256:<digest> --evidence umbrel-package-smoke-evidence.json')
  t.is(item(report, 'evidence.official-umbrel-pr').command, 'npm run release:write-official-umbrel-pr-evidence -- --out official-umbrel-pr-evidence.json')
  t.is(item(report, 'evidence.umbrel-runtime-review').command, 'npm run umbrel:write-runtime-review -- --out umbrel-runtime-review-evidence.json --release v<version> --official-pr-url https://github.com/getumbrel/umbrel-apps/pull/<number>')
  t.is(item(report, 'evidence.startos-registry').command, 'npm run release:write-startos-registry-evidence -- --out startos-registry-evidence.json')
  t.is(item(report, 'artifact.startos04-package').command, 'Download blindspark-startos-0.4.s9pk from the exact GitHub Release tag')
  t.is(item(report, 'evidence.startos04-release').command, 'Download startos-0.4-release-evidence.json from the exact GitHub Release tag')
  t.is(item(report, 'evidence.release-closure').command, 'GH_TOKEN=<token> npm run release:verify-closure-evidence -- --bundle-dir <dir> --live-github --expected-prerelease <true|false>')
  t.is(item(report, 'evidence.fleet-rollout').command, 'npm run fleet:check-rollout -- --target v<version> --channel both --evidence fleet-rollout-evidence.json')
})

test('release blocker closure rejects symlinked evidence candidates before marking rows present', async (t) => {
  const dir = await tempDir(t)
  const target = path.join(dir, 'real-release-evidence.json')

  await writeFile(target, '{}\n')
  await symlink(target, path.join(dir, 'release-evidence.json'))

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)
  const release = item(report, 'evidence.release')

  t.is(res.status, 1)
  t.is(release.status, 'blocker')
  t.is(release.summary, 'release evidence is not usable')
  t.ok(release.detail.includes('release-evidence.json must not be a symlink'))
  t.ok(item(report, 'release.evidence.verify').detail.includes('evidence.release'))
})

test('release blocker closure rejects symlinked bundle directories before trusting sidecars', async (t) => {
  const dir = await tempDir(t)
  const realBundle = path.join(dir, 'real-bundle')
  const linkedBundle = path.join(dir, 'linked-bundle')

  await fsMkdir(realBundle)
  await writeFile(path.join(realBundle, 'release-evidence.json'), '{}\n')
  await writeJson(path.join(realBundle, 'npm-latest-evidence.json'), npmLatestEvidence())
  await symlink(realBundle, linkedBundle)

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', linkedBundle])
  const report = JSON.parse(res.stdout)
  const bundle = item(report, 'bundle.dir')
  const release = item(report, 'evidence.release')
  const npm = item(report, 'npm.latest')

  t.is(res.status, 1)
  t.is(bundle.status, 'blocker')
  t.is(bundle.summary, 'release asset bundle directory is not usable')
  t.ok(bundle.detail.includes('bundle-dir must not be a symlink'))
  t.is(release.status, 'blocker')
  t.is(release.summary, 'release evidence is not usable')
  t.ok(release.detail.includes('bundle-dir must not be a symlink'))
  t.is(npm.status, 'blocker')
  t.is(npm.summary, 'npm latest evidence sidecar is not usable')
  t.ok(npm.detail.includes('bundle-dir must not be a symlink'))
})

test('release blocker closure rejects empty and oversized JSON evidence candidates', async (t) => {
  const dir = await tempDir(t)

  await writeFile(path.join(dir, 'release-evidence.json'), '')
  await writeFile(path.join(dir, 'release-image-manifest-evidence.json'), Buffer.alloc(MAX_EVIDENCE_JSON_BYTES + 1))

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)
  const release = item(report, 'evidence.release')
  const manifest = item(report, 'evidence.image-manifest')

  t.is(res.status, 1)
  t.is(release.status, 'blocker')
  t.is(release.summary, 'release evidence is not usable')
  t.ok(release.detail.includes('release-evidence.json must not be empty'))
  t.is(manifest.status, 'blocker')
  t.is(manifest.summary, 'GHCR image manifest evidence is not usable')
  t.ok(manifest.detail.includes(`release-image-manifest-evidence.json must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller`))
})

test('release blocker closure rejects an empty StartOS 0.4 package artifact', async (t) => {
  const dir = await tempDir(t)
  await writeFile(path.join(dir, 'blindspark-startos-0.4.s9pk'), '')

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)
  const artifact = item(report, 'artifact.startos04-package')

  t.is(res.status, 1)
  t.is(artifact.status, 'blocker')
  t.is(artifact.summary, 'StartOS 0.4 package artifact is not usable')
  t.ok(artifact.detail.includes('blindspark-startos-0.4.s9pk must not be empty'))
})

test('release blocker closure rejects malformed and non-object JSON evidence candidates', async (t) => {
  const dir = await tempDir(t)

  await writeFile(path.join(dir, 'release-evidence.json'), '{not json\n')
  await writeFile(path.join(dir, 'release-image-smoke-evidence.json'), '[]\n')

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)
  const release = item(report, 'evidence.release')
  const smoke = item(report, 'evidence.image-smoke')

  t.is(res.status, 1)
  t.is(release.status, 'blocker')
  t.ok(release.detail.includes('release-evidence.json must contain valid JSON'))
  t.is(smoke.status, 'blocker')
  t.is(smoke.detail, 'release-image-smoke-evidence.json must contain a JSON object')
})

test('release blocker closure accepts a usable alternate artifact path when the preferred path is unusable', async (t) => {
  const dir = await tempDir(t)
  const startosDir = path.join(dir, 'startos')
  const badTarget = path.join(dir, 'bad-blindspark.s9pk')
  const preferred = path.join(startosDir, 'blindspark.s9pk')
  const alternate = path.join(dir, 'blindspark.s9pk')

  await writeFile(badTarget, 'bad package\n')
  await fsMkdir(startosDir)
  await symlink(badTarget, preferred)
  await writeFile(alternate, 'usable package\n')

  const res = await runCheck(['--json', '--skip-git', '--bundle-dir', dir])
  const report = JSON.parse(res.stdout)
  const artifact = item(report, 'artifact.startos-package')

  t.is(res.status, 1)
  t.is(artifact.status, 'pass')
  t.is(artifact.detail, 'blindspark.s9pk')
})

test('release blocker closure rejects unusable npm latest evidence before schema validation', async (t) => {
  const bundleDir = await tempDir(t)

  await writeFile(path.join(bundleDir, 'npm-latest-evidence.json'), '[]\n')

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--expected-version', VERSION
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  const npm = item(report, 'npm.latest')
  t.is(npm.status, 'blocker')
  t.is(npm.summary, 'npm latest evidence sidecar is not usable')
  t.is(npm.detail, 'npm-latest-evidence.json must contain a JSON object')
})

test('release blocker closure accepts offline npm latest and local env proof', async (t) => {
  const bundleDir = await tempDir(t)
  const fixtureDir = await tempDir(t)
  const envFile = await validEnvFile(t)
  const npmLatestFile = path.join(fixtureDir, 'npm-latest.json')

  await writeJson(npmLatestFile, latestFixture())

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--env-file', envFile,
    '--npm-latest-json', npmLatestFile,
    '--expected-version', VERSION
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  t.is(report.status, 'blocked')
  t.is(item(report, 'distribution.env').status, 'pass')
  t.is(item(report, 'npm.latest').status, 'pass')
  t.is(item(report, 'evidence.release').status, 'blocker')
  t.is(item(report, 'release.evidence.verify').status, 'blocker')
  t.is(item(report, 'release.handoff.verify').status, 'blocker')
})

test('release blocker closure accepts npm latest evidence from release bundle', async (t) => {
  const bundleDir = await tempDir(t)
  const envFile = await validEnvFile(t)
  await writeJson(path.join(bundleDir, 'npm-latest-evidence.json'), npmLatestEvidence())

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--env-file', envFile,
    '--expected-version', VERSION
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  t.is(report.status, 'blocked')
  t.is(item(report, 'distribution.env').status, 'pass')
  t.is(item(report, 'npm.latest').status, 'pass')
  t.is(item(report, 'npm.latest').detail, 'npm-latest-evidence.json')
  t.is(item(report, 'evidence.release').status, 'blocker')
})

test('release blocker closure rejects stale npm latest evidence from release bundle', async (t) => {
  const bundleDir = await tempDir(t)
  await writeJson(path.join(bundleDir, 'npm-latest-evidence.json'), npmLatestEvidence('0.9.2'))

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--expected-version', VERSION
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  const npm = item(report, 'npm.latest')
  t.is(npm.status, 'blocker')
  t.ok(npm.detail.includes('expectedVersion'))
})

test('release blocker closure reports the exact stale npm latest package from checker JSON', async (t) => {
  const bundleDir = await tempDir(t)
  const fixtureDir = await tempDir(t)
  const npmLatestFile = path.join(fixtureDir, 'npm-latest.json')

  await writeJson(npmLatestFile, {
    ...latestFixture(),
    'p2p-hiveservices': '0.9.2'
  })

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--npm-latest-json', npmLatestFile,
    '--expected-version', VERSION
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  const npm = item(report, 'npm.latest')
  t.is(npm.status, 'blocker')
  t.is(npm.summary, `npm latest dist-tags do not all point at ${VERSION}`)
  t.ok(npm.detail.includes(`p2p-hiveservices npm latest dist-tag is 0.9.2; expected ${VERSION}`))
  t.absent(npm.detail.includes('"schemaVersion"'))
})

test('release blocker closure rejects incomplete npm fixtures without live lookup', async (t) => {
  const bundleDir = await tempDir(t)
  const fixtureDir = await tempDir(t)
  const npmLatestFile = path.join(fixtureDir, 'npm-latest.json')

  await writeJson(npmLatestFile, {
    'p2p-hiverelay': VERSION
  })

  const res = await runCheck([
    '--json',
    '--skip-git',
    '--bundle-dir', bundleDir,
    '--npm-latest-json', npmLatestFile
  ])

  t.is(res.status, 1)

  const report = JSON.parse(res.stdout)
  const npm = item(report, 'npm.latest')
  t.is(npm.status, 'blocker')
  t.ok(npm.detail.includes('missing npm latest values'))
  t.absent(npm.detail.includes('Could not verify npm latest dist-tag'))
})

function item (report, id) {
  return report.items.find(check => check.id === id) || {}
}
