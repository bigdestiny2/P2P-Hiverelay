#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const hiverelayRoot = path.resolve(here, '..')
const workspaceRootDefault = path.resolve(hiverelayRoot, '..', '..')
export const CURRENT_HIVERELAY_VERSION = readJson(path.join(hiverelayRoot, 'package.json')).version

const HIVERELAY_DEPS = [
  'p2p-hiverelay',
  'p2p-hiverelay-client',
  'p2p-hiverelay-verifier'
]

const DEP_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies'
]

const SKIP_DIRS = new Set([
  '.git',
  '.forge-cache',
  '.gradle',
  '.next',
  '.turbo',
  'build',
  'coverage',
  'dist',
  'node_modules',
  'out'
])

const IGNORED_PREFIXES = [
  '00-core/hiverelay/',
  '00-core/hr-acct/',
  '00-core/hr-fleet/',
  '00-core/hr-release/'
]

export const EXPECTED_CURRENT_SNAPSHOT_ROOTS = [
  {
    path: '00-core/hr-acct',
    role: 'accounting release snapshot'
  },
  {
    path: '00-core/hr-fleet',
    role: 'fleet release snapshot'
  },
  {
    path: '00-core/hr-release',
    role: 'release promotion snapshot'
  }
]

const SNAPSHOT_PACKAGE_SPECS = [
  {
    file: 'package.json',
    lockKey: '',
    name: 'p2p-hiverelay-monorepo'
  },
  {
    file: 'packages/core/package.json',
    lockKey: 'packages/core',
    name: 'p2p-hiverelay'
  },
  {
    file: 'packages/client/package.json',
    lockKey: 'packages/client',
    name: 'p2p-hiverelay-client',
    coreRange: true
  },
  {
    file: 'packages/services/package.json',
    lockKey: 'packages/services',
    name: 'p2p-hiveservices',
    coreRange: true
  },
  {
    file: 'packages/verifier/package.json',
    lockKey: 'packages/verifier',
    name: 'p2p-hiverelay-verifier'
  }
]

export const EXPECTED_CURRENT_CONSUMERS = [
  {
    path: '01-browser/pearbrowser-desktop/package.json',
    role: 'release-critical bundled PearBrowser desktop',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client',
      'p2p-hiverelay-verifier': 'file:../../00-core/hiverelay/packages/verifier'
    },
    sourceChecks: [
      {
        file: '01-browser/pearbrowser-desktop/catalog-source/pearbrowser-network.catalog.json',
        label: 'PearBrowser catalog advertises the current Hiverelay app release',
        termTemplate: '"version": "{version}"',
        rejectTerms: [
          '"version": "0.16.3"'
        ]
      },
      {
        file: '01-browser/pearbrowser-desktop/backend/catalogue-seed.js',
        label: 'PearBrowser bundled catalog seed advertises the current Hiverelay app release',
        termTemplate: '"version": "{version}"',
        rejectTerms: [
          '"version": "0.16.3"'
        ]
      },
      {
        file: '01-browser/pearbrowser-desktop/docs/HIVERELAY-BACKBONE-HANDOVER.md',
        label: 'PearBrowser backbone handover names the current Hiverelay workspace line',
        termTemplate: '`p2p-hiverelay` `{version}` from the local HiveRelay workspace',
        rejectTerms: [
          'npm v0.8.12',
          '^0.8.12'
        ]
      }
    ]
  },
  {
    path: '02-apps/pearpaste/package.json',
    role: 'customer encrypted-availability app',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    },
    sourceChecks: [
      {
        file: '02-apps/pearpaste/docs/RECOVERY_DESIGN.md',
        label: 'recovery design uses local 0.20.2 workspace package guidance',
        term: '"p2p-hiverelay": "file:../../00-core/hiverelay/packages/core"',
        rejectTerms: [
          '"p2p-hiverelay-client": "^0.9.2"',
          'Blocked on upstream npm publish',
          'Other 0.8.x',
          'changes we\'d pick up'
        ]
      },
      {
        file: '02-apps/pearpaste/docs/PEARPASTE_TECHNICAL_SPEC.md',
        label: 'technical spec names current Hiverelay package integration',
        termTemplate: 'HiveRelay `{version}` local workspace packages by default',
        rejectTerms: [
          'Integrate `p2p-hiverelay-client` `0.8.13`'
        ]
      },
      {
        file: '02-apps/pearpaste/REVIEW.md',
        label: 'customer relay review names the current split-client package line',
        termTemplate: 'p2p-hiverelay-client@{version}',
        rejectTerms: [
          'p2p-hiverelay-client@0.9.2',
          'Real 0.9.2 API match',
          'real 0.9.2 client'
        ]
      },
      {
        file: '02-apps/pearpaste/scripts/probe-circuit.mjs',
        label: 'circuit probe asks for current fleet capability, not a stale release line',
        term: 'current HiveRelay fleet',
        rejectTerms: [
          'v0.8.14',
          '0.8.14'
        ]
      }
    ]
  },
  {
    path: '02-apps/pear-pos/package.json',
    role: 'local app consumer',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    },
    sourceChecks: [
      {
        file: '02-apps/pear-pos/app/backend/hiverelay-client.js',
        label: 'POS CJS bridge comment names the current split-client package line',
        termTemplate: 'p2p-hiverelay-client@{version}',
        rejectTerms: [
          'p2p-hiverelay-client@0.16.3'
        ]
      },
      {
        file: '02-apps/pear-pos/app/backend/hiverelay-sync.js',
        label: 'POS seed lifecycle comment names the current release line',
        termTemplate: 'Seed lifecycle (v{version})',
        rejectTerms: [
          'Seed lifecycle (v0.16.3)'
        ]
      },
      {
        file: '02-apps/pear-pos/ARCHITECTURE.md',
        label: 'POS architecture note names the current split-client package line',
        termTemplate: 'p2p-hiverelay-client@{version}',
        rejectTerms: [
          'p2p-hiverelay-client@0.16.3'
        ]
      },
      {
        file: '02-apps/pear-pos/PLAN.md',
        label: 'POS plan names current Hiverelay workspace package defaults',
        termTemplate: 'current HiveRelay {version} split packages',
        rejectTerms: [
          'v0.16.3',
          'p2p-hiverelay-client@0.16.3'
        ]
      },
      {
        file: '02-apps/pear-pos/RESEARCH.md',
        label: 'POS research note names the current split-client package line',
        termTemplate: 'p2p-hiverelay-client@{version}',
        rejectTerms: [
          'p2p-hiverelay-client@0.16.3'
        ]
      }
    ]
  },
  {
    path: '02-apps/pear-tickets/package.json',
    role: 'local app consumer',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    }
  },
  {
    path: '03-sites/pearbrowser-publishers/src/p2pbuilders/package.json',
    role: 'publisher-site consumer',
    deps: {
      'p2p-hiverelay': 'file:../../../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../../../00-core/hiverelay/packages/client'
    }
  },
  {
    path: '04-experiments/Opengit/packages/opengit-relay/package.json',
    role: 'optional Opengit blind-relay bridge',
    deps: {
      'p2p-hiverelay': 'file:../../../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../../../00-core/hiverelay/packages/client'
    },
    sourceChecks: [
      {
        file: '04-experiments/Opengit/HIVERELAY-INTEGRATION.md',
        label: 'Opengit integration note names current workspace defaults',
        term: 'Current package default',
        rejectTerms: [
          'npm-publish lag',
          '0.7.3',
          'v0.8.x',
          '0.8.0',
          '0.8.1',
          '^0.8',
          '^0.7.3'
        ]
      }
    ]
  },
  {
    path: '04-experiments/anongpt-native/package.json',
    role: 'customer relay/onion AI app',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core'
    }
  },
  {
    path: '04-experiments/hiverelay-test/package.json',
    role: 'local experiment consumer',
    deps: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    }
  }
]

export const EXPECTED_STALE_CONSUMERS = [
]

const usage = `
Usage:
  node scripts/audit-ecosystem-consumers.mjs [--workspace-root <path>] [--expected-version <semver>] [--json] [--check]

Scans package.json files outside the Hiverelay source tree and verifies the
known direct p2p-hiverelay consumers plus local release snapshot defaults. The
command fails on new unclassified pins, stale local package metadata, or
inventory/source-plan drift.
`

if (isMain()) main()

export function scanHiverelayConsumers (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const packageFiles = findPackageFiles(workspaceRoot)
  const rows = []

  for (const file of packageFiles) {
    const relPath = slash(path.relative(workspaceRoot, file))
    const pkg = readJson(file)
    const deps = collectHiverelayDeps(pkg)
    if (Object.keys(deps).length === 0) continue

    rows.push({
      path: relPath,
      name: typeof pkg.name === 'string' ? pkg.name : '',
      deps,
      ignored: IGNORED_PREFIXES.some(prefix => relPath.startsWith(prefix))
    })
  }

  rows.sort((a, b) => a.path.localeCompare(b.path))
  return rows
}

export function checkConsumerState (rows, opts = {}) {
  const expectedVersion = opts.expectedVersion || '0.0.0'
  const expectedCurrent = opts.expectedCurrent || EXPECTED_CURRENT_CONSUMERS
  const expectedStale = opts.expectedStale || EXPECTED_STALE_CONSUMERS
  const sourceChecks = opts.sourceChecks || []
  const lockChecks = opts.lockChecks || []
  const snapshotChecks = opts.snapshotChecks || []
  const errors = []
  const warnings = []
  const byPath = new Map(rows.map(row => [row.path, row]))
  const expectedPaths = new Set([
    ...expectedCurrent.map(row => row.path),
    ...expectedStale.map(row => row.path)
  ])

  for (const expected of expectedCurrent) {
    const row = byPath.get(expected.path)
    if (!row) {
      errors.push(`Missing expected current Hiverelay consumer: ${expected.path}`)
      continue
    }
    compareDeps(errors, row, expected.deps, 'current local consumer')
  }

  for (const expected of expectedStale) {
    const row = byPath.get(expected.path)
    if (!row) {
      errors.push(`Known stale Hiverelay consumer disappeared or moved; update the inventory: ${expected.path}`)
      continue
    }
    compareDeps(errors, row, expected.deps, 'known stale consumer')
  }

  const activeRows = rows.filter(row => !row.ignored)
  for (const row of activeRows) {
    if (expectedPaths.has(row.path)) continue
    errors.push(`Unclassified Hiverelay package consumer: ${row.path} (${formatDeps(row.deps)})`)
  }

  const staleRows = expectedStale
    .map(expected => byPath.get(expected.path))
    .filter(Boolean)
  if (staleRows.length > 0) {
    warnings.push(`Known stale non-bundled consumers need separate ${expectedVersion} upgrade loops: ${staleRows.map(row => row.path).join(', ')}`)
  }

  for (const check of sourceChecks) {
    if (!check.present) {
      errors.push(`Missing expected source-level migration marker for ${check.consumerPath}: ${check.file} (${check.label})`)
    }
    if (check.rejectedTermsFound?.length > 0) {
      errors.push(`Disallowed source-level migration marker found for ${check.consumerPath}: ${check.file} (${check.label}) includes ${check.rejectedTermsFound.map(term => JSON.stringify(term)).join(', ')}`)
    }
  }

  for (const check of lockChecks) {
    if (!check.ok) errors.push(check.error)
  }

  for (const check of snapshotChecks) {
    if (!check.ok) errors.push(check.error)
  }

  return {
    ok: errors.length === 0,
    expectedVersion,
    errors,
    warnings,
    current: expectedCurrent.map(expected => decorateExpectedRow(byPath.get(expected.path), expected)).filter(Boolean),
    stale: expectedStale.map(expected => decorateExpectedRow(byPath.get(expected.path), expected)).filter(Boolean),
    sourceChecks,
    lockChecks,
    snapshotChecks,
    ignored: rows.filter(row => row.ignored)
  }
}

export function scanCurrentConsumerLockChecks (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedCurrent = opts.expectedCurrent || EXPECTED_CURRENT_CONSUMERS
  const expectedVersion = opts.expectedVersion || '0.0.0'
  const checks = []

  for (const consumer of expectedCurrent) {
    const packageFile = path.join(workspaceRoot, consumer.path)
    const packageDir = path.dirname(packageFile)
    const lockFile = findNearestLockfile(packageDir, workspaceRoot)
    if (!lockFile) {
      checks.push({
        ok: false,
        consumerPath: consumer.path,
        lockFile: null,
        label: 'package-lock exists',
        error: `${consumer.path} current local consumer has no package-lock.json to pin local Hiverelay package metadata`
      })
      continue
    }

    let lock
    try {
      lock = readJson(lockFile)
    } catch (err) {
      checks.push({
        ok: false,
        consumerPath: consumer.path,
        lockFile: slash(path.relative(workspaceRoot, lockFile)),
        label: 'package-lock parses',
        error: `${slash(path.relative(workspaceRoot, lockFile))} cannot be parsed for ${consumer.path}: ${err.message}`
      })
      continue
    }

    const relLockFile = slash(path.relative(workspaceRoot, lockFile))
    const lockRoot = path.dirname(lockFile)
    const packageKey = slash(path.relative(lockRoot, packageDir))
    const packageEntryKey = packageKey === '' ? '' : packageKey
    const packageEntry = lock.packages?.[packageEntryKey]
    if (!packageEntry) {
      checks.push({
        ok: false,
        consumerPath: consumer.path,
        lockFile: relLockFile,
        label: 'consumer package entry',
        error: `${relLockFile} is missing the package-lock entry for ${consumer.path}`
      })
      continue
    }

    const lockDeps = collectHiverelayDeps(packageEntry)
    for (const [dep, expectedValue] of Object.entries(consumer.deps).sort(([a], [b]) => a.localeCompare(b))) {
      if (lockDeps[dep] !== expectedValue) {
        checks.push({
          ok: false,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} lock dependency`,
          error: `${relLockFile} has ${consumer.path} lock dependency ${dep}=${JSON.stringify(lockDeps[dep])}; expected ${JSON.stringify(expectedValue)}`
        })
      } else {
        checks.push({
          ok: true,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} lock dependency`
        })
      }

      if (!expectedValue.startsWith('file:')) continue
      const target = path.resolve(packageDir, expectedValue.slice('file:'.length))
      const targetKey = slash(path.relative(lockRoot, target))
      const targetEntry = lock.packages?.[targetKey]
      if (!targetEntry) {
        checks.push({
          ok: false,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} linked package entry`,
          error: `${relLockFile} is missing linked package metadata for ${dep} at ${targetKey}`
        })
        continue
      }
      if (targetEntry.name !== dep) {
        checks.push({
          ok: false,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} linked package name`,
          error: `${relLockFile} linked package ${targetKey} is named ${JSON.stringify(targetEntry.name)}; expected ${JSON.stringify(dep)}`
        })
        continue
      }
      if (targetEntry.version !== expectedVersion) {
        checks.push({
          ok: false,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} linked package version`,
          error: `${relLockFile} linked package ${targetKey} has ${dep}@${targetEntry.version}; expected ${expectedVersion}`
        })
      } else {
        checks.push({
          ok: true,
          consumerPath: consumer.path,
          lockFile: relLockFile,
          label: `${dep} linked package version`
        })
      }
    }

    for (const issue of findStaleLockEntries(lock, relLockFile, expectedVersion)) {
      checks.push({
        ok: false,
        consumerPath: consumer.path,
        lockFile: relLockFile,
        label: 'stale Hiverelay lock entry',
        error: issue
      })
    }
  }

  checks.sort((a, b) => `${a.consumerPath}\0${a.lockFile || ''}\0${a.label}`.localeCompare(`${b.consumerPath}\0${b.lockFile || ''}\0${b.label}`))
  return checks
}

export function scanSnapshotVersionChecks (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedVersion = opts.expectedVersion || '0.0.0'
  const snapshotRoots = opts.snapshotRoots || EXPECTED_CURRENT_SNAPSHOT_ROOTS
  const checks = []

  for (const snapshot of snapshotRoots) {
    const rootPath = typeof snapshot === 'string' ? snapshot : snapshot.path
    const role = typeof snapshot === 'string' ? null : snapshot.role
    for (const spec of SNAPSHOT_PACKAGE_SPECS) {
      checks.push(...checkSnapshotPackage({
        workspaceRoot,
        rootPath,
        role,
        spec,
        expectedVersion
      }))
    }
  }

  checks.sort((a, b) => `${a.rootPath}\0${a.file}\0${a.label}`.localeCompare(`${b.rootPath}\0${b.file}\0${b.label}`))
  return checks
}

export function scanStaleConsumerSourceChecks (opts = {}) {
  return scanConsumerSourceChecks({
    ...opts,
    expectedCurrent: []
  })
}

export function scanConsumerSourceChecks (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedVersion = opts.expectedVersion || CURRENT_HIVERELAY_VERSION
  const expectedCurrent = opts.expectedCurrent || []
  const expectedStale = opts.expectedStale || EXPECTED_STALE_CONSUMERS
  const checks = []

  for (const consumer of [...expectedCurrent, ...expectedStale]) {
    for (const spec of consumer.sourceChecks || []) {
      const file = slash(spec.file)
      const abs = path.join(workspaceRoot, file)
      const term = renderSourceTerm(spec, expectedVersion)
      let text = ''
      let present = false
      let rejectedTermsFound = []
      try {
        text = fs.readFileSync(abs, 'utf8')
        present = text.includes(term)
        rejectedTermsFound = (spec.rejectTerms || []).filter(term => text.includes(term))
      } catch {
        present = false
      }
      checks.push({
        consumerPath: consumer.path,
        file,
        label: spec.label,
        term,
        present,
        rejectedTermsFound
      })
    }
  }

  checks.sort((a, b) => (a.consumerPath + a.file).localeCompare(b.consumerPath + b.file))
  return checks
}

function renderSourceTerm (spec, version) {
  if (typeof spec.termTemplate === 'string') {
    return spec.termTemplate.replaceAll('{version}', version)
  }
  return spec.term
}

export function formatConsumerReport (summary) {
  const lines = [
    `HiveRelay ecosystem consumer audit (expected ${summary.expectedVersion})`,
    ''
  ]

  lines.push('Current local consumers:')
  for (const row of summary.current) {
    const role = row.role ? ` [${row.role}]` : ''
    lines.push(`- ${row.path}${role}: ${formatDeps(row.deps)}`)
  }
  if (summary.current.length === 0) lines.push('- none')

  lines.push('', 'Known stale non-bundled consumers:')
  for (const row of summary.stale) {
    const action = row.action ? ` (${row.action})` : ''
    lines.push(`- ${row.path}: ${formatDeps(row.deps)}${action}`)
  }
  if (summary.stale.length === 0) lines.push('- none')

  lines.push('', 'Direct-consumer scan exclusions:')
  const ignoredRoots = Array.from(new Set(summary.ignored.map(row => row.path.split('/').slice(0, 2).join('/')))).sort()
  for (const root of ignoredRoots) lines.push(`- ${root}`)
  if (ignoredRoots.length === 0) lines.push('- none')

  if (summary.warnings.length > 0) {
    lines.push('', 'Warnings:')
    for (const warning of summary.warnings) lines.push(`- ${warning}`)
  }

  if (summary.sourceChecks.length > 0) {
    lines.push('', 'Source-level migration checks:')
    for (const check of summary.sourceChecks) {
      const status = check.present ? 'found' : 'missing'
      const rejected = check.rejectedTermsFound?.length > 0
        ? `, rejected terms found: ${check.rejectedTermsFound.map(term => JSON.stringify(term)).join(', ')}`
        : ''
      lines.push(`- ${check.file}: ${check.label} (${status}${rejected})`)
    }
  }

  if (summary.lockChecks.length > 0) {
    lines.push('', 'Lockfile migration checks:')
    const failed = summary.lockChecks.filter(check => !check.ok)
    if (failed.length === 0) {
      const lockfiles = Array.from(new Set(summary.lockChecks.map(check => check.lockFile).filter(Boolean))).sort()
      for (const lockfile of lockfiles) lines.push(`- ${lockfile}: ok`)
    } else {
      for (const check of failed) lines.push(`- ${check.lockFile || check.consumerPath}: ${check.label} (failed)`)
    }
  }

  if (summary.snapshotChecks.length > 0) {
    lines.push('', 'Snapshot/default version checks:')
    const failed = summary.snapshotChecks.filter(check => !check.ok)
    if (failed.length === 0) {
      const roots = Array.from(new Map(summary.snapshotChecks.map(check => [check.rootPath, check])).values())
      for (const check of roots) {
        const role = check.role ? ` [${check.role}]` : ''
        lines.push(`- ${check.rootPath}${role}: ok`)
      }
    } else {
      for (const check of failed) lines.push(`- ${check.file}: ${check.label} (failed)`)
    }
  }

  if (summary.errors.length > 0) {
    lines.push('', 'Errors:')
    for (const error of summary.errors) lines.push(`- ${error}`)
  }

  return lines.join('\n')
}

function decorateExpectedRow (row, expected) {
  if (!row) return null
  return {
    ...row,
    role: expected.role || null,
    action: expected.action || null
  }
}

function compareDeps (errors, row, expectedDeps, label) {
  const actual = row.deps
  const actualKeys = Object.keys(actual).sort()
  const expectedKeys = Object.keys(expectedDeps).sort()
  if (actualKeys.join('\0') !== expectedKeys.join('\0')) {
    errors.push(`${row.path} ${label} has Hiverelay deps ${actualKeys.join(', ') || '(none)'}; expected ${expectedKeys.join(', ') || '(none)'}`)
    return
  }

  for (const key of expectedKeys) {
    if (actual[key] !== expectedDeps[key]) {
      errors.push(`${row.path} ${label} has ${key}=${JSON.stringify(actual[key])}; expected ${JSON.stringify(expectedDeps[key])}`)
    }
  }
}

function collectHiverelayDeps (pkg) {
  const out = {}
  for (const section of DEP_SECTIONS) {
    const deps = pkg?.[section]
    if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue
    for (const dep of HIVERELAY_DEPS) {
      if (typeof deps[dep] === 'string') out[dep] = deps[dep]
    }
  }
  return out
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

function findStaleLockEntries (lock, relLockFile, expectedVersion) {
  const issues = []
  for (const [entryPath, entry] of Object.entries(lock.packages || {})) {
    if (!entry || typeof entry !== 'object') continue
    const isHiverelayPath = entryPath.includes('00-core/hiverelay')
    const isHiverelayPackage = HIVERELAY_DEPS.includes(entry.name)
    const isOldRootPackage = entry.name === 'p2p-hiverelay-monorepo' && isHiverelayPath

    if (isOldRootPackage) {
      issues.push(`${relLockFile} contains stale monorepo-root Hiverelay lock entry ${entryPath}@${entry.version}; current apps must link packages/core, packages/client, or packages/verifier directly`)
      continue
    }

    if (isHiverelayPackage && entry.version !== expectedVersion) {
      issues.push(`${relLockFile} contains ${entry.name}@${entry.version} at ${entryPath}; expected ${expectedVersion}`)
    }

    const deps = collectHiverelayDeps(entry)
    for (const [dep, value] of Object.entries(deps)) {
      if (value.startsWith('file:')) continue
      const expectedRange = `^${expectedVersion}`
      if (value !== expectedRange) {
        issues.push(`${relLockFile} contains ${entryPath} dependency ${dep}=${JSON.stringify(value)}; expected ${JSON.stringify(expectedRange)} or a local file: link`)
      }
    }
  }
  return issues
}

function checkSnapshotPackage ({ workspaceRoot, rootPath, role, spec, expectedVersion }) {
  const checks = []
  const file = slash(path.join(rootPath, spec.file))
  const abs = path.join(workspaceRoot, file)
  let pkg

  try {
    pkg = readJson(abs)
  } catch (err) {
    checks.push({
      ok: false,
      rootPath,
      role,
      file,
      label: 'package manifest exists',
      error: `${file} cannot be read as JSON: ${err.message}`
    })
    return checks
  }

  checks.push(checkSnapshotPackageEntry({
    rootPath,
    role,
    file,
    label: 'package manifest',
    entry: pkg,
    spec,
    expectedVersion
  }))

  const lockFile = slash(path.join(rootPath, 'package-lock.json'))
  const absLockFile = path.join(workspaceRoot, lockFile)
  let lock
  try {
    lock = readJson(absLockFile)
  } catch (err) {
    checks.push({
      ok: false,
      rootPath,
      role,
      file: lockFile,
      label: 'package lock exists',
      error: `${lockFile} cannot be read as JSON: ${err.message}`
    })
    return checks
  }

  const lockEntry = lock.packages?.[spec.lockKey]
  if (!lockEntry) {
    checks.push({
      ok: false,
      rootPath,
      role,
      file: lockFile,
      label: `${spec.lockKey || 'root'} lock entry`,
      error: `${lockFile} is missing snapshot lock entry ${JSON.stringify(spec.lockKey)} for ${spec.name}`
    })
    return checks
  }

  checks.push(checkSnapshotPackageEntry({
    rootPath,
    role,
    file: lockFile,
    label: `${spec.lockKey || 'root'} lock entry`,
    entry: lockEntry,
    spec,
    expectedVersion
  }))

  return checks
}

function checkSnapshotPackageEntry ({ rootPath, role, file, label, entry, spec, expectedVersion }) {
  if (entry.name !== spec.name) {
    return {
      ok: false,
      rootPath,
      role,
      file,
      label,
      error: `${file} ${label} is named ${JSON.stringify(entry.name)}; expected ${JSON.stringify(spec.name)}`
    }
  }

  if (entry.version !== expectedVersion) {
    return {
      ok: false,
      rootPath,
      role,
      file,
      label,
      error: `${file} ${label} has ${spec.name}@${entry.version}; expected ${expectedVersion}`
    }
  }

  if (spec.coreRange) {
    const expectedRange = `^${expectedVersion}`
    const deps = collectHiverelayDeps(entry)
    if (deps['p2p-hiverelay'] !== expectedRange) {
      return {
        ok: false,
        rootPath,
        role,
        file,
        label,
        error: `${file} ${label} has p2p-hiverelay=${JSON.stringify(deps['p2p-hiverelay'])}; expected ${JSON.stringify(expectedRange)}`
      }
    }
  }

  return {
    ok: true,
    rootPath,
    role,
    file,
    label
  }
}

function findPackageFiles (root) {
  const out = []
  walk(root, out)
  return out
}

function walk (dir, out) {
  let entries
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }

  for (const entry of entries) {
    if (entry.name === 'package.json' && entry.isFile()) {
      out.push(path.join(dir, entry.name))
      continue
    }
    if (!entry.isDirectory()) continue
    if (SKIP_DIRS.has(entry.name)) continue
    walk(path.join(dir, entry.name), out)
  }
}

function readJson (file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function formatDeps (deps) {
  return Object.entries(deps)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `${name}@${value}`)
    .join(', ')
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
    if (arg === '--json') {
      out.json = true
      continue
    }
    if (arg === '--check') {
      out.check = true
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

  const rootPackage = readJson(path.join(hiverelayRoot, 'package.json'))
  const expectedVersion = args.expectedVersion || rootPackage.version
  const workspaceRoot = args.workspaceRoot || workspaceRootDefault
  const rows = scanHiverelayConsumers({ workspaceRoot })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot,
    expectedVersion,
    expectedCurrent: EXPECTED_CURRENT_CONSUMERS,
    expectedStale: EXPECTED_STALE_CONSUMERS
  })
  const lockChecks = scanCurrentConsumerLockChecks({ workspaceRoot, expectedVersion })
  const snapshotChecks = scanSnapshotVersionChecks({ workspaceRoot, expectedVersion })
  const summary = checkConsumerState(rows, { expectedVersion, sourceChecks, lockChecks, snapshotChecks })

  if (args.json) {
    console.log(JSON.stringify({ rows, summary }, null, 2))
  } else {
    console.log(formatConsumerReport(summary))
  }

  if (!summary.ok) process.exit(1)
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}
