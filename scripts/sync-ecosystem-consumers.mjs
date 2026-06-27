#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  CURRENT_HIVERELAY_VERSION,
  EXPECTED_STALE_CONSUMERS,
  checkConsumerState,
  getExpectedCurrentConsumers,
  normalizeDependencyMode,
  scanConsumerSourceChecks,
  scanCurrentConsumerLockChecks,
  scanHiverelayConsumers,
  scanSnapshotVersionChecks
} from './audit-ecosystem-consumers.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const hiverelayRoot = path.resolve(here, '..')
const workspaceRootDefault = path.resolve(hiverelayRoot, '..', '..')

const DEP_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies'
]

const usage = `
Usage:
  node scripts/sync-ecosystem-consumers.mjs [--workspace-root <path>] [--expected-version <semver>] [--dependency-mode <local|npm-latest>] [--check] [--dry-run]

Updates the known direct ecosystem app consumers so their default
p2p-hiverelay* package defaults point at either the current local Hiverelay
workspace packages (default) or the npm latest dist-tag. npm-latest mode first
verifies every relevant npm latest dist-tag equals the expected Hiverelay
version, then requires npm to refresh package-lock metadata. Use --check in CI
to fail if a consumer would be changed.
`

if (isMain()) main()

export function syncEcosystemConsumers (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedVersion = opts.expectedVersion || CURRENT_HIVERELAY_VERSION
  const dependencyMode = normalizeDependencyMode(opts.dependencyMode || 'local')
  const expectedCurrent = opts.expectedCurrent || getExpectedCurrentConsumers({ dependencyMode })
  const dryRun = Boolean(opts.dryRun || opts.check)
  const changes = []
  const errors = []
  const warnings = []

  if (dependencyMode === 'npm-latest') {
    const latestCheck = verifyNpmLatestDistTags({
      expectedCurrent,
      expectedVersion,
      npmLatestVersions: opts.npmLatestVersions
    })
    errors.push(...latestCheck.errors)
    warnings.push(...latestCheck.warnings)
    if (errors.length > 0) {
      return {
        ok: false,
        check: Boolean(opts.check),
        dryRun,
        dependencyMode,
        workspaceRoot,
        expectedVersion,
        changes,
        errors,
        warnings,
        summary: null
      }
    }
  }

  for (const consumer of expectedCurrent) {
    try {
      changes.push(...syncConsumerManifest({
        workspaceRoot,
        consumer,
        dryRun
      }))
      if (dependencyMode === 'local') {
        changes.push(...syncConsumerLockfile({
          workspaceRoot,
          consumer,
          expectedVersion,
          dryRun
        }))
      }
      changes.push(...syncConsumerSourceMarkers({
        workspaceRoot,
        consumer,
        expectedVersion,
        dryRun
      }))
    } catch (err) {
      errors.push(`${consumer.path}: ${err.message}`)
    }
  }

  if (dependencyMode === 'npm-latest' && !dryRun) {
    try {
      changes.push(...refreshNpmLatestLockfiles({
        workspaceRoot,
        expectedCurrent,
        skipNpmInstall: opts.skipNpmInstall
      }))
    } catch (err) {
      errors.push(err.message)
    }
  }

  const rows = scanHiverelayConsumers({ workspaceRoot })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot,
    expectedVersion,
    expectedCurrent,
    expectedStale: EXPECTED_STALE_CONSUMERS
  })
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot,
    expectedVersion,
    expectedCurrent
  })
  const snapshotChecks = opts.snapshotChecks === false
    ? []
    : scanSnapshotVersionChecks({
      workspaceRoot,
      expectedVersion,
      snapshotRoots: opts.snapshotRoots
    })
  const summary = checkConsumerState(rows, {
    expectedVersion,
    expectedCurrent,
    expectedStale: EXPECTED_STALE_CONSUMERS,
    sourceChecks,
    lockChecks,
    snapshotChecks
  })

  if (opts.check && changes.length > 0) {
    errors.push(`${changes.length} ecosystem consumer file(s) need default-version sync`)
  }
  errors.push(...summary.errors)
  warnings.push(...summary.warnings)

  return {
    ok: errors.length === 0,
    check: Boolean(opts.check),
    dryRun,
    dependencyMode,
    workspaceRoot,
    expectedVersion,
    changes,
    errors,
    warnings,
    summary
  }
}

function syncConsumerManifest ({ workspaceRoot, consumer, dryRun }) {
  const file = path.join(workspaceRoot, consumer.path)
  const pkg = readJson(file)
  const changes = []

  for (const [dep, value] of Object.entries(consumer.deps).sort(([a], [b]) => a.localeCompare(b))) {
    const preferredSection = findDepSection(pkg, dep) || 'dependencies'
    if (setDependency(pkg, dep, value, preferredSection)) {
      changes.push(`${slash(path.relative(workspaceRoot, file))}: ${dep} -> ${value}`)
    }
  }

  if (changes.length > 0 && !dryRun) writeJson(file, pkg)
  return changes
}

function syncConsumerLockfile ({ workspaceRoot, consumer, expectedVersion, dryRun }) {
  const packageFile = path.join(workspaceRoot, consumer.path)
  const packageDir = path.dirname(packageFile)
  const lockFile = findNearestLockfile(packageDir, workspaceRoot)
  if (!lockFile) throw new Error('missing nearest package-lock.json')

  const pkg = readJson(packageFile)
  const lock = readJson(lockFile)
  const lockRoot = path.dirname(lockFile)
  const relLockFile = slash(path.relative(workspaceRoot, lockFile))
  const packageKey = slash(path.relative(lockRoot, packageDir))
  const packageEntryKey = packageKey === '' ? '' : packageKey
  const packageEntry = lock.packages?.[packageEntryKey]
  if (!packageEntry) throw new Error(`${relLockFile} is missing lock entry ${JSON.stringify(packageEntryKey)}`)

  const changes = []
  for (const [dep, value] of Object.entries(consumer.deps).sort(([a], [b]) => a.localeCompare(b))) {
    const preferredSection = findDepSection(pkg, dep) || findDepSection(packageEntry, dep) || 'dependencies'
    if (setDependency(packageEntry, dep, value, preferredSection)) {
      changes.push(`${relLockFile}: ${packageEntryKey || 'root'} ${dep} -> ${value}`)
    }

    if (!value.startsWith('file:')) continue
    const target = path.resolve(packageDir, value.slice('file:'.length))
    const targetKey = slash(path.relative(lockRoot, target))
    const targetEntry = lock.packages?.[targetKey]
    if (!targetEntry) throw new Error(`${relLockFile} is missing linked package metadata for ${dep} at ${targetKey}`)

    if (targetEntry.name !== dep) {
      targetEntry.name = dep
      changes.push(`${relLockFile}: ${targetKey} name -> ${dep}`)
    }
    if (targetEntry.version !== expectedVersion) {
      targetEntry.version = expectedVersion
      changes.push(`${relLockFile}: ${targetKey} version -> ${expectedVersion}`)
    }
    if (targetEntry.dependencies?.['p2p-hiverelay']) {
      const expectedRange = `^${expectedVersion}`
      if (targetEntry.dependencies['p2p-hiverelay'] !== expectedRange) {
        targetEntry.dependencies['p2p-hiverelay'] = expectedRange
        changes.push(`${relLockFile}: ${targetKey} p2p-hiverelay -> ${expectedRange}`)
      }
    }
  }

  if (changes.length > 0 && !dryRun) writeJson(lockFile, lock)
  return changes
}

function syncConsumerSourceMarkers ({ workspaceRoot, consumer, expectedVersion, dryRun }) {
  const changes = []
  for (const spec of consumer.sourceChecks || []) {
    if (typeof spec.termTemplate !== 'string') continue
    const file = path.join(workspaceRoot, spec.file)
    const text = fs.readFileSync(file, 'utf8')
    const nextTerm = spec.termTemplate.replaceAll('{version}', expectedVersion)
    const marker = termTemplateRegex(spec.termTemplate)
    const next = text.replace(marker, nextTerm)
    if (next === text) continue
    const rel = slash(path.relative(workspaceRoot, file))
    changes.push(`${rel}: ${spec.label} -> ${expectedVersion}`)
    if (!dryRun) fs.writeFileSync(file, next)
  }
  return changes
}

function verifyNpmLatestDistTags ({ expectedCurrent, expectedVersion, npmLatestVersions } = {}) {
  const errors = []
  const warnings = []
  const names = Array.from(new Set(expectedCurrent.flatMap(consumer => Object.keys(consumer.deps)))).sort()
  const envVersions = npmLatestVersions || npmLatestVersionsFromEnv(process.env)

  for (const name of names) {
    let latest = envVersions?.[name]
    if (latest == null) {
      try {
        latest = execFileSync('npm', ['view', name, 'dist-tags.latest'], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 20000
        }).trim()
      } catch (err) {
        errors.push(`Could not verify npm latest dist-tag for ${name}: ${stderrMessage(err) || err.message}. Set HIVERELAY_NPM_LATEST_JSON to trusted npm view results when running in an offline or DNS-restricted environment.`)
        continue
      }
    }

    if (latest !== expectedVersion) {
      errors.push(`${name} npm latest dist-tag is ${latest || '(missing)'}; expected ${expectedVersion}. Refusing to switch app defaults to npm latest because that would not install the current HiveRelay release.`)
    }
  }

  if (names.length > 0 && errors.length === 0) {
    warnings.push(`npm latest dist-tags verified for ${names.join(', ')}`)
  }

  return { errors, warnings }
}

function npmLatestVersionsFromEnv (env) {
  if (env.HIVERELAY_NPM_LATEST_JSON) {
    try {
      const parsed = JSON.parse(env.HIVERELAY_NPM_LATEST_JSON)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
    } catch {
      return {}
    }
  }
  return {}
}

function refreshNpmLatestLockfiles ({ workspaceRoot, expectedCurrent, skipNpmInstall }) {
  const changes = []
  const roots = collectConsumerLockRoots({ workspaceRoot, expectedCurrent })
  for (const root of roots) {
    const rel = slash(path.relative(workspaceRoot, root))
    if (skipNpmInstall) {
      changes.push(`${rel || '.'}/package-lock.json: npm package-lock refresh skipped by test harness`)
      continue
    }
    try {
      execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--fund=false'], {
        cwd: root,
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 120000
      })
      changes.push(`${rel || '.'}/package-lock.json: refreshed from npm latest`)
    } catch (err) {
      throw new Error(`${rel || '.'}: npm package-lock refresh failed: ${stderrMessage(err) || err.message}`)
    }
  }
  return changes
}

function collectConsumerLockRoots ({ workspaceRoot, expectedCurrent }) {
  const roots = new Set()
  for (const consumer of expectedCurrent) {
    const packageFile = path.join(workspaceRoot, consumer.path)
    const packageDir = path.dirname(packageFile)
    const lockFile = findNearestLockfile(packageDir, workspaceRoot)
    if (!lockFile) throw new Error(`${consumer.path}: missing nearest package-lock.json`)
    roots.add(path.dirname(lockFile))
  }
  return Array.from(roots).sort()
}

function stderrMessage (err) {
  return Buffer.isBuffer(err?.stderr) ? err.stderr.toString().trim() : String(err?.stderr || '').trim()
}

function termTemplateRegex (template) {
  const semver = String.raw`v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?`
  const parts = template.split('{version}').map(escapeRegExp)
  return new RegExp(parts.join(semver), 'g')
}

function setDependency (target, dep, value, preferredSection) {
  const section = findDepSection(target, dep) || preferredSection
  let changed = false
  if (!target[section] || typeof target[section] !== 'object' || Array.isArray(target[section])) {
    target[section] = {}
    changed = true
  }
  if (target[section][dep] !== value) {
    target[section][dep] = value
    changed = true
  }

  for (const other of DEP_SECTIONS) {
    if (other === section) continue
    if (!target[other] || typeof target[other] !== 'object' || Array.isArray(target[other])) continue
    if (Object.hasOwn(target[other], dep)) {
      delete target[other][dep]
      changed = true
    }
  }

  return changed
}

function findDepSection (target, dep) {
  for (const section of DEP_SECTIONS) {
    const deps = target?.[section]
    if (deps && typeof deps === 'object' && !Array.isArray(deps) && typeof deps[dep] === 'string') {
      return section
    }
  }
  return null
}

function findNearestLockfile (startDir, stopDir) {
  let dir = path.resolve(startDir)
  const stop = path.resolve(stopDir)

  while (dir.startsWith(stop)) {
    const candidate = path.join(dir, 'package-lock.json')
    if (fs.existsSync(candidate)) return candidate
    if (dir === stop) break
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }

  return null
}

function readJson (file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function writeJson (file, body) {
  fs.writeFileSync(file, JSON.stringify(body, null, 2) + '\n')
}

function slash (value) {
  return value.split(path.sep).join('/')
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--check') {
      out.check = true
      continue
    }
    if (arg === '--dry-run') {
      out.dryRun = true
      continue
    }
    if (arg === '--workspace-root') {
      out.workspaceRoot = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--expected-version') {
      out.expectedVersion = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--dependency-mode') {
      out.dependencyMode = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--npm-latest') {
      out.dependencyMode = 'npm-latest'
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

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    process.exit(1)
  }

  const result = syncEcosystemConsumers(args)
  const mode = result.check ? 'check' : result.dryRun ? 'dry run' : 'sync'
  console.log(`HiveRelay ecosystem consumer ${mode} (target ${result.expectedVersion}, mode ${result.dependencyMode})`)
  if (result.changes.length === 0) {
    console.log('- no consumer package or lockfile changes needed')
  } else {
    for (const change of result.changes) console.log(`- ${change}`)
  }
  for (const warning of result.warnings) console.warn(`WARN ${warning}`)
  for (const error of result.errors) console.error(`ERROR ${error}`)
  if (!result.ok) process.exit(1)
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}
