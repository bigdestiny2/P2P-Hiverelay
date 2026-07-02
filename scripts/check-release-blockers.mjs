#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const usage = `
Usage:
  node scripts/check-release-blockers.mjs --bundle-dir <release-assets-dir> --env-file <candidate-env> --npm-latest-json <npm-latest.json>
  node scripts/check-release-blockers.mjs --bundle-dir <release-assets-dir> --env-file <candidate-env> --check-npm-live

Options:
  --bundle-dir <path>       Downloaded release assets directory. Defaults to cwd.
  --env-file <path>         Local release secrets candidate for side-effect-free validation.
  --npm-latest-json <path>  Trusted offline npm latest fixture JSON.
                            If omitted, npm-latest-evidence.json from bundle-dir is accepted.
  --check-npm-live          Explicitly query npm for latest dist-tags.
  --expected-version <semver>
                            Expected HiveRelay npm latest version. Defaults to root package version.
  --channel <canary|stable|both>
                            Full-release fleet channel. Defaults to both.
  --prerelease <true|false> Defaults to false; this checker is intended for full release closure.
  --skip-git                Skip clean-worktree proof. Intended for hermetic tests only.
  --json                    Print machine-readable output.
  --out <path>              Write the public-safe JSON report, even when blocked.
`

const REQUIRED_NPM_LATEST_PACKAGES = Object.freeze([
  'p2p-hiverelay',
  'p2p-hiverelay-client',
  'p2p-hiverelay-verifier',
  'p2p-hiveservices'
])

const NPM_LATEST_EVIDENCE_FILE = 'npm-latest-evidence.json'
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024

const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----[\s\S]*?-----END [A-Z ]*(?:PRIVATE|SECRET) KEY-----/g, '[redacted private key block]'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]'],
  [/\bnpm_[A-Za-z0-9_]{20,}\b/g, '[redacted npm token]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/gi, 'Bearer [redacted]'],
  [/\bAuthorization\s*:\s*[^\n\r]+/gi, 'Authorization: [redacted]']
]

const EVIDENCE_FILES = Object.freeze([
  {
    id: 'evidence.release',
    label: 'release evidence',
    files: ['release-evidence.json'],
    command: 'npm run release:write-evidence -- --out release-evidence.json'
  },
  {
    id: 'evidence.image-manifest',
    label: 'GHCR image manifest evidence',
    files: ['release-image-manifest-evidence.json'],
    command: 'npm run release:check-image-manifest -- --image <ref>@sha256:<digest> --out release-image-manifest-evidence.json'
  },
  {
    id: 'evidence.image-smoke',
    label: 'digest-pinned image smoke evidence',
    files: ['release-image-smoke-evidence.json'],
    command: 'npm run release:smoke-image -- <ref>@sha256:<digest> --evidence release-image-smoke-evidence.json'
  },
  {
    id: 'evidence.umbrel-package-smoke',
    label: 'Umbrel package smoke evidence',
    files: ['umbrel-package-smoke-evidence.json'],
    command: 'npm run umbrel:smoke-package -- --image-ref <ref>@sha256:<digest> --evidence umbrel-package-smoke-evidence.json'
  },
  {
    id: 'evidence.official-umbrel-pr',
    label: 'official Umbrel PR evidence',
    files: ['official-umbrel-pr-evidence.json'],
    command: 'npm run release:write-official-umbrel-pr-evidence -- --out official-umbrel-pr-evidence.json'
  },
  {
    id: 'evidence.umbrel-runtime-review',
    label: 'real Umbrel runtime review evidence',
    files: ['umbrel-runtime-review-evidence.json'],
    command: 'npm run umbrel:write-runtime-review -- --out umbrel-runtime-review-evidence.json --release v<version> --official-pr-url https://github.com/getumbrel/umbrel-apps/pull/<number>'
  },
  {
    id: 'evidence.startos-registry',
    label: 'StartOS registry evidence',
    files: ['startos-registry-evidence.json'],
    command: 'npm run release:write-startos-registry-evidence -- --out startos-registry-evidence.json'
  },
  {
    id: 'evidence.fleet-rollout',
    label: 'fleet rollout evidence',
    files: ['fleet-rollout-evidence.json'],
    command: 'npm run fleet:check-rollout -- --target v<version> --channel both --evidence fleet-rollout-evidence.json'
  },
  {
    id: 'artifact.startos-package',
    label: 'StartOS package artifact',
    files: ['startos/blindspark.s9pk', 'blindspark.s9pk'],
    command: 'HIVERELAY_IMAGE_DIGEST=sha256:<digest> npm run startos:verify'
  }
])

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const rootPackage = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'))

let args
try {
  args = parseArgs(process.argv.slice(2))
} catch (err) {
  console.error(err.message)
  console.error(usage.trim())
  process.exit(1)
}

if (args.help) {
  console.log(usage.trim())
  process.exit(0)
}

if (args.npmLatestJson && args.checkNpmLive) {
  console.error('Use either --npm-latest-json or --check-npm-live, not both.')
  process.exit(1)
}

const bundleDir = path.resolve(args.bundleDir || process.cwd())
const bundleDirStatus = bundleDirectoryStatus(bundleDir)
const expectedVersion = args.expectedVersion || rootPackage.version
const channel = args.channel || 'both'
const prerelease = args.prerelease ?? false
const items = []

if (!['canary', 'stable', 'both'].includes(channel)) {
  console.error('--channel must be canary, stable, or both for full release closure.')
  process.exit(1)
}

addBundleDirCheck()
addGitCheck()
addDistributionEnvCheck()
addNpmLatestCheck()
addEvidenceFileChecks()
addReleaseVerifierChecks()

const blockers = items.filter(item => item.status === 'blocker')
const warnings = items.filter(item => item.status === 'warn')
const passes = items.filter(item => item.status === 'pass')
const report = sanitizeReport({
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  kind: 'hiverelay-release-blocker-closure',
  scope: 'Core Availability / Blindspark full-release closure',
  status: blockers.length === 0 ? 'ready' : 'blocked',
  expectedVersion,
  channel,
  prerelease,
  bundleDir,
  totals: {
    pass: passes.length,
    warn: warnings.length,
    blocker: blockers.length
  },
  items
})

if (args.out) {
  try {
    writeReport(args.out, report)
  } catch (err) {
    console.error(`Unable to write release blocker report ${args.out}: ${err.message}`)
    process.exit(1)
  }
}

if (args.json) {
  console.log(JSON.stringify(report, null, 2))
} else {
  console.log(formatReport(report))
}

process.exit(blockers.length === 0 ? 0 : 1)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--json') {
      out.json = true
      continue
    }
    if (arg === '--out') {
      out.out = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--skip-git') {
      out.skipGit = true
      continue
    }
    if (arg === '--check-npm-live') {
      out.checkNpmLive = true
      continue
    }
    if (arg === '--bundle-dir') {
      out.bundleDir = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--env-file') {
      out.envFile = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--npm-latest-json') {
      out.npmLatestJson = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--expected-version') {
      out.expectedVersion = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--channel') {
      out.channel = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--prerelease') {
      out.prerelease = readBoolean(readValue(argv, ++i, arg), arg)
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`)
  return value
}

function readBoolean (value, flag) {
  if (value === 'true') return true
  if (value === 'false') return false
  throw new Error(`${flag} must be true or false`)
}

function addBundleDirCheck () {
  addItem({
    id: 'bundle.dir',
    status: bundleDirStatus.ok ? 'pass' : 'blocker',
    summary: bundleDirStatus.ok
      ? 'release asset bundle directory is usable'
      : 'release asset bundle directory is not usable',
    detail: bundleDirStatus.ok ? bundleDir : `${bundleDir}: ${bundleDirStatus.error}`,
    command: 'download release assets into a regular directory and pass --bundle-dir <dir>'
  })
}

function addGitCheck () {
  if (args.skipGit) {
    addItem({
      id: 'worktree.clean',
      status: 'warn',
      summary: 'clean-worktree proof skipped',
      detail: '--skip-git is intended only for hermetic tests and local dry reports.',
      command: 'git status --porcelain=v1'
    })
    return
  }

  const res = spawnSync('git', ['status', '--porcelain=v1'], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 10000
  })

  if (res.error || res.status !== 0) {
    addItem({
      id: 'worktree.clean',
      status: 'blocker',
      summary: 'could not prove clean release worktree',
      detail: commandFailureDetail(res),
      command: 'git status --porcelain=v1'
    })
    return
  }

  const dirty = res.stdout.trim()
  addItem({
    id: 'worktree.clean',
    status: dirty ? 'blocker' : 'pass',
    summary: dirty ? 'release worktree has uncommitted changes' : 'release worktree is clean',
    detail: dirty ? firstLines(dirty, 12) : '',
    command: 'git status --porcelain=v1'
  })
}

function addDistributionEnvCheck () {
  if (!args.envFile) {
    addItem({
      id: 'distribution.env',
      status: 'blocker',
      summary: 'missing side-effect-free release credential proof',
      detail: 'Pass --env-file with a local candidate release secrets file before cutting a full release.',
      command: 'npm run release:check-distribution-env -- --env-file /private/tmp/hiverelay-release-secrets.env --channel both --prerelease false'
    })
    return
  }

  const envFile = path.resolve(args.envFile)
  if (!isReadableFile(envFile)) {
    addItem({
      id: 'distribution.env',
      status: 'blocker',
      summary: 'release credential candidate file is missing or unreadable',
      detail: envFile,
      command: 'npm run release:check-distribution-env -- --env-file <candidate-env> --channel both --prerelease false'
    })
    return
  }

  addCommandItem({
    id: 'distribution.env',
    passSummary: 'release credential candidate passes side-effect-free preflight',
    failSummary: 'release credential candidate is not ready',
    script: 'check-release-distribution-env.mjs',
    argv: ['--env-file', envFile, '--channel', channel, '--prerelease', String(prerelease)],
    timeout: 30000,
    command: `npm run release:check-distribution-env -- --env-file ${envFile} --channel ${channel} --prerelease ${prerelease}`
  })
}

function addNpmLatestCheck () {
  if (!args.npmLatestJson && !args.checkNpmLive) {
    const evidenceFile = path.join(bundleDir, NPM_LATEST_EVIDENCE_FILE)
    const evidenceStatus = evidenceFileStatus(evidenceFile)
    if (evidenceStatus.exists) {
      if (!evidenceStatus.ok) {
        addItem({
          id: 'npm.latest',
          status: 'blocker',
          summary: 'npm latest evidence sidecar is not usable',
          detail: evidenceStatus.error,
          command: `npm run release:check-npm-latest -- --expected-version ${expectedVersion} --out ${NPM_LATEST_EVIDENCE_FILE}`
        })
        return
      }
      const evidence = readNpmLatestEvidence(evidenceFile)
      addItem({
        id: 'npm.latest',
        status: evidence.ok ? 'pass' : 'blocker',
        summary: evidence.ok
          ? `npm latest dist-tags point at ${expectedVersion}`
          : 'npm latest evidence sidecar is not usable',
        detail: evidence.ok ? NPM_LATEST_EVIDENCE_FILE : evidence.error,
        command: `npm run release:check-npm-latest -- --expected-version ${expectedVersion} --out ${NPM_LATEST_EVIDENCE_FILE}`
      })
      return
    }

    addItem({
      id: 'npm.latest',
      status: 'blocker',
      summary: 'npm latest dist-tags have not been proven for this release',
      detail: 'Provide npm-latest-evidence.json in bundle-dir, use --npm-latest-json with trusted npm view output, or pass --check-npm-live to query npm explicitly.',
      command: 'npm run release:check-npm-latest -- --expected-version <semver> --out npm-latest-evidence.json'
    })
    return
  }

  const env = { HIVERELAY_NPM_LATEST_JSON: '' }

  if (args.npmLatestJson) {
    const fixtureFile = path.resolve(args.npmLatestJson)
    const fixture = readNpmLatestFixture(fixtureFile)
    if (!fixture.ok) {
      addItem({
        id: 'npm.latest',
        status: 'blocker',
        summary: 'npm latest fixture is not usable',
        detail: fixture.error,
        command: 'npm run release:check-npm-latest -- --expected-version <semver>'
      })
      return
    }
    env.HIVERELAY_NPM_LATEST_JSON = JSON.stringify(fixture.versions)
  }

  addCommandItem({
    id: 'npm.latest',
    passSummary: `npm latest dist-tags point at ${expectedVersion}`,
    failSummary: `npm latest dist-tags do not all point at ${expectedVersion}`,
    script: 'check-npm-latest.mjs',
    argv: ['--json', '--expected-version', expectedVersion],
    env,
    timeout: args.checkNpmLive ? 45000 : 30000,
    failureDetail: npmLatestCommandFailureDetail,
    command: args.checkNpmLive
      ? `npm run release:check-npm-latest -- --expected-version ${expectedVersion}`
      : `HIVERELAY_NPM_LATEST_JSON="$(cat ${path.resolve(args.npmLatestJson)})" npm run release:check-npm-latest -- --expected-version ${expectedVersion}`
  })
}

function readNpmLatestEvidence (file) {
  let parsed
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (err) {
    return { ok: false, error: `invalid JSON in ${file}: ${err.message}` }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: `${file} must contain an npm latest evidence object` }
  }
  if (parsed.schemaVersion !== 1 || parsed.kind !== 'hiverelay-npm-latest-evidence') {
    return { ok: false, error: `${file} is not a HiveRelay npm latest evidence sidecar` }
  }
  if (parsed.ok !== true || parsed.status !== 'verified') {
    return { ok: false, error: `${file} does not report verified npm latest status` }
  }
  if (parsed.expectedVersion !== expectedVersion) {
    return {
      ok: false,
      error: `${file} expectedVersion is ${JSON.stringify(parsed.expectedVersion)}; expected ${expectedVersion}`
    }
  }
  const packages = Array.isArray(parsed.packages) ? parsed.packages : []
  const missingPackages = REQUIRED_NPM_LATEST_PACKAGES.filter(name => !packages.includes(name))
  if (missingPackages.length > 0) {
    return { ok: false, error: `${file} is missing npm packages: ${missingPackages.join(', ')}` }
  }
  const checks = Array.isArray(parsed.checks) ? parsed.checks : []
  const badChecks = []
  for (const name of REQUIRED_NPM_LATEST_PACKAGES) {
    const check = checks.find(row => row && row.name === name)
    if (!check) {
      badChecks.push(`${name}: missing check row`)
      continue
    }
    if (check.ok !== true || check.latest !== expectedVersion) {
      badChecks.push(`${name}: latest=${check.latest || '(missing)'}`)
    }
  }
  if (badChecks.length > 0) {
    return { ok: false, error: `${file} has stale npm latest proof: ${badChecks.join(', ')}` }
  }
  if (Array.isArray(parsed.errors) && parsed.errors.length > 0) {
    return { ok: false, error: `${file} contains npm latest errors` }
  }
  return { ok: true }
}

function addEvidenceFileChecks () {
  for (const evidence of EVIDENCE_FILES) {
    const existing = firstUsableEvidenceFile(evidence.files.map(file => path.join(bundleDir, file)))
    addItem({
      id: evidence.id,
      status: existing.ok ? 'pass' : 'blocker',
      summary: existing.ok
        ? `${evidence.label} is present`
        : existing.error
          ? `${evidence.label} is not usable`
          : `${evidence.label} is missing`,
      detail: existing.ok
        ? path.relative(bundleDir, existing.file)
        : existing.error
          ? existing.error
          : `Expected one of: ${evidence.files.join(', ')}`,
      command: evidence.command
    })
  }
}

function addReleaseVerifierChecks () {
  const missing = EVIDENCE_FILES
    .filter(evidence => !firstUsableEvidenceFile(evidence.files.map(file => path.join(bundleDir, file))).ok)
    .map(evidence => evidence.id)

  if (missing.length > 0) {
    addItem({
      id: 'release.evidence.verify',
      status: 'blocker',
      summary: 'release evidence verifier was not run because required files are missing',
      detail: missing.join(', '),
      command: 'npm run release:verify-evidence -- --bundle-dir <dir>'
    })
    addItem({
      id: 'release.handoff.verify',
      status: 'blocker',
      summary: 'review-ready handoff verifier was not run because required files are missing',
      detail: missing.join(', '),
      command: 'npm run release:verify-review-ready-handoff -- --bundle-dir <dir>'
    })
    return
  }

  addCommandItem({
    id: 'release.evidence.verify',
    passSummary: 'hash-linked release evidence bundle verifies',
    failSummary: 'hash-linked release evidence bundle failed verification',
    script: 'verify-release-evidence.mjs',
    argv: ['--bundle-dir', bundleDir],
    timeout: 120000,
    command: `npm run release:verify-evidence -- --bundle-dir ${bundleDir}`
  })

  addCommandItem({
    id: 'release.handoff.verify',
    passSummary: 'review-ready handoff bundle verifies with real Umbrel runtime evidence',
    failSummary: 'review-ready handoff bundle failed verification',
    script: 'verify-release-handoff-evidence.mjs',
    argv: ['--bundle-dir', bundleDir, '--require-umbrel-runtime-review'],
    timeout: 120000,
    command: `npm run release:verify-review-ready-handoff -- --bundle-dir ${bundleDir}`
  })
}

function readNpmLatestFixture (file) {
  if (!isReadableFile(file)) return { ok: false, error: `${file} is missing or unreadable` }
  let parsed
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (err) {
    return { ok: false, error: `invalid JSON in ${file}: ${err.message}` }
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, error: `${file} must contain an object keyed by npm package name` }
  }
  const missing = REQUIRED_NPM_LATEST_PACKAGES.filter(name => typeof parsed[name] !== 'string' || parsed[name] === '')
  if (missing.length > 0) {
    return {
      ok: false,
      error: `${file} is missing npm latest values for: ${missing.join(', ')}`
    }
  }
  return { ok: true, versions: parsed }
}

function addCommandItem (opts) {
  const res = spawnSync(process.execPath, [path.join('scripts', opts.script), ...opts.argv], {
    cwd: repoRoot,
    env: { ...process.env, ...(opts.env || {}) },
    encoding: 'utf8',
    timeout: opts.timeout || 30000
  })
  const failed = res.error || res.status !== 0

  addItem({
    id: opts.id,
    status: failed ? 'blocker' : 'pass',
    summary: failed ? opts.failSummary : opts.passSummary,
    detail: failed && typeof opts.failureDetail === 'function' ? opts.failureDetail(res) : commandFailureDetail(res),
    command: opts.command
  })
}

function npmLatestCommandFailureDetail (res) {
  if (!res || res.error) return commandFailureDetail(res)
  let parsed
  try {
    parsed = JSON.parse(res.stdout || '')
  } catch {
    return commandFailureDetail(res)
  }
  if (!parsed || parsed.kind !== 'hiverelay-npm-latest-evidence') return commandFailureDetail(res)

  const errors = Array.isArray(parsed.errors) ? parsed.errors.filter(Boolean) : []
  if (errors.length > 0) return errors.join('\n')

  const checks = Array.isArray(parsed.checks) ? parsed.checks : []
  const failedChecks = checks
    .filter(check => check && check.ok !== true)
    .map(check => {
      if (check.error) return check.error
      const name = check.name || '(unknown package)'
      const latest = check.latest || '(missing)'
      const expected = check.expectedVersion || parsed.expectedVersion || expectedVersion
      return `${name}: latest=${latest}; expected ${expected}`
    })

  return failedChecks.length > 0 ? failedChecks.join('\n') : commandFailureDetail(res)
}

function commandFailureDetail (res) {
  if (!res) return ''
  if (res.error) return sanitizeOutput(res.error.message)
  if (res.status === 0) return sanitizeOutput(firstLines(res.stdout || '', 4))
  return sanitizeOutput(firstLines([res.stderr, res.stdout].filter(Boolean).join('\n'), 12))
}

function addItem (item) {
  items.push({
    id: item.id,
    status: item.status,
    summary: item.summary,
    ...(item.detail ? { detail: sanitizeOutput(item.detail) } : {}),
    ...(item.command ? { command: item.command } : {})
  })
}

function firstUsableEvidenceFile (files) {
  let firstProblem = null
  for (const file of files) {
    const status = evidenceFileStatus(file)
    if (status.ok) return { ...status, file }
    if (status.exists && !firstProblem) firstProblem = { ...status, file }
  }
  if (firstProblem) return firstProblem
  return { exists: false, ok: false }
}

function evidenceFileStatus (file) {
  const rel = path.relative(bundleDir, file) || path.basename(file)
  if (!bundleDirStatus.ok) {
    return { exists: true, ok: false, error: bundleDirStatus.error }
  }
  try {
    const stat = fs.lstatSync(file)
    if (stat.isSymbolicLink()) {
      return { exists: true, ok: false, error: `${rel} must not be a symlink` }
    }
    if (!stat.isFile()) {
      return { exists: true, ok: false, error: `${rel} must be a regular file` }
    }
    if (rel.endsWith('.json') && stat.size === 0) {
      return { exists: true, ok: false, error: `${rel} must not be empty` }
    }
    if (rel.endsWith('.json') && stat.size > MAX_EVIDENCE_JSON_BYTES) {
      return { exists: true, ok: false, error: `${rel} must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller` }
    }
    if (rel.endsWith('.json')) {
      try {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return { exists: true, ok: false, error: `${rel} must contain a JSON object` }
        }
      } catch (err) {
        return { exists: true, ok: false, error: `${rel} must contain valid JSON: ${err.message}` }
      }
    }
    return { exists: true, ok: true }
  } catch (err) {
    if (err && err.code === 'ENOENT') return { exists: false, ok: false }
    return { exists: true, ok: false, error: `${rel} is not usable: ${err.message}` }
  }
}

function bundleDirectoryStatus (dir) {
  try {
    const stat = fs.lstatSync(dir)
    if (stat.isSymbolicLink()) return { ok: false, error: 'bundle-dir must not be a symlink' }
    if (!stat.isDirectory()) return { ok: false, error: 'bundle-dir must be a directory' }
    return { ok: true }
  } catch (err) {
    if (err && err.code === 'ENOENT') return { ok: false, error: 'bundle-dir is missing' }
    return { ok: false, error: `bundle-dir is not usable: ${err.message}` }
  }
}

function isReadableFile (file) {
  try {
    const stat = fs.statSync(file)
    return stat.isFile()
  } catch {
    return false
  }
}

function firstLines (text, limit) {
  return String(text || '')
    .split(/\r?\n/)
    .map(line => line.trimEnd())
    .filter(Boolean)
    .slice(0, limit)
    .join('\n')
}

function sanitizeOutput (text) {
  let out = String(text || '')
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement)
  }
  return out
}

function sanitizeReport (value) {
  if (typeof value === 'string') return sanitizeOutput(value)
  if (Array.isArray(value)) return value.map(sanitizeReport)
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, child] of Object.entries(value)) out[key] = sanitizeReport(child)
    return out
  }
  return value
}

function writeReport (file, report) {
  fs.writeFileSync(path.resolve(file), JSON.stringify(report, null, 2) + '\n')
}

function formatReport (report) {
  const lines = [
    `HiveRelay release blocker closure (${report.scope})`,
    `status=${report.status} expected=${report.expectedVersion} channel=${report.channel} prerelease=${report.prerelease}`,
    `bundle=${report.bundleDir}`,
    `pass=${report.totals.pass} warn=${report.totals.warn} blocker=${report.totals.blocker}`,
    ''
  ]

  for (const item of report.items) {
    lines.push(`${item.status.toUpperCase()} ${item.id}: ${item.summary}`)
    if (item.detail) lines.push(`  ${item.detail.replace(/\n/g, '\n  ')}`)
    if (item.command) lines.push(`  proof: ${item.command}`)
  }

  if (report.status === 'ready') {
    lines.push('')
    lines.push('Ready: every tracked public-release blocker has evidence.')
  } else {
    lines.push('')
    lines.push('Blocked: do not cut the public full release until every BLOCKER row is closed.')
  }

  return lines.join('\n')
}
