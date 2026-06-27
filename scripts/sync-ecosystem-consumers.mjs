#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CURRENT_HIVERELAY_VERSION,
  EXPECTED_CURRENT_CONSUMERS,
  EXPECTED_STALE_CONSUMERS,
  checkConsumerState,
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
  node scripts/sync-ecosystem-consumers.mjs [--workspace-root <path>] [--expected-version <semver>] [--check] [--dry-run]

Updates the known direct ecosystem app consumers so their default
p2p-hiverelay* package links point at the current local Hiverelay workspace
packages, then refreshes package-lock linked-package metadata to the current
Hiverelay version. Use --check in CI to fail if a consumer would be changed.
`

if (isMain()) main()

export function syncEcosystemConsumers (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedVersion = opts.expectedVersion || CURRENT_HIVERELAY_VERSION
  const expectedCurrent = opts.expectedCurrent || EXPECTED_CURRENT_CONSUMERS
  const dryRun = Boolean(opts.dryRun || opts.check)
  const changes = []
  const errors = []

  for (const consumer of expectedCurrent) {
    try {
      changes.push(...syncConsumerManifest({
        workspaceRoot,
        consumer,
        dryRun
      }))
      changes.push(...syncConsumerLockfile({
        workspaceRoot,
        consumer,
        expectedVersion,
        dryRun
      }))
    } catch (err) {
      errors.push(`${consumer.path}: ${err.message}`)
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

  return {
    ok: errors.length === 0,
    check: Boolean(opts.check),
    dryRun,
    workspaceRoot,
    expectedVersion,
    changes,
    errors,
    warnings: summary.warnings,
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
  console.log(`HiveRelay ecosystem consumer ${mode} (target ${result.expectedVersion})`)
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
