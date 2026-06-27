import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  DEFAULT_DEPENDENCY_MODE,
  EXPECTED_CURRENT_CONSUMERS,
  checkConsumerState,
  formatConsumerReport,
  getExpectedCurrentConsumers,
  scanConsumerSourceChecks,
  scanCurrentConsumerLockChecks,
  scanHiverelayConsumers,
  scanSnapshotVersionChecks,
  scanStaleConsumerSourceChecks
} from '../../scripts/audit-ecosystem-consumers.mjs'
import { syncEcosystemConsumers } from '../../scripts/sync-ecosystem-consumers.mjs'

test('ecosystem consumer audit classifies current, stale, and ignored consumers', (t) => {
  const root = fixtureWorkspace()
  const expectedCurrentPaths = [
    '01-browser/pearbrowser-desktop/package.json',
    '02-apps/pearpaste/package.json',
    '02-apps/pear-pos/package.json',
    '02-apps/pear-tickets/package.json',
    '03-sites/pearbrowser-publishers/src/p2pbuilders/package.json',
    '04-experiments/Opengit/packages/opengit-relay/package.json',
    '04-experiments/anongpt-native/package.json',
    '04-experiments/hiverelay-test/package.json'
  ]
  for (const consumerPath of expectedCurrentPaths) {
    t.ok(
      EXPECTED_CURRENT_CONSUMERS.some(consumer => consumer.path === consumerPath),
      `${consumerPath} remains in the current-consumer inventory`
    )
  }
  writeExpectedConsumerPackages(root, EXPECTED_CURRENT_CONSUMERS)
  writePackage(root, '00-core/hiverelay/packages/client/package.json', {
    dependencies: {
      'p2p-hiverelay': '^0.20.2'
    }
  })
  writePackage(root, '00-core/hr-fleet/packages/client/package.json', {
    dependencies: {
      'p2p-hiverelay': '^0.19.0'
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: EXPECTED_CURRENT_CONSUMERS,
    expectedStale: []
  })
  const report = formatConsumerReport(summary)

  t.ok(summary.ok)
  t.is(summary.current.length, expectedCurrentPaths.length)
  t.is(summary.stale.length, 0)
  t.is(summary.ignored.length, 2)
  t.ok(report.includes('02-apps/pear-pos/package.json'))
  t.ok(report.includes('02-apps/pear-tickets/package.json'))
  t.ok(report.includes('04-experiments/hiverelay-test/package.json'))
  t.ok(report.includes('Known stale non-bundled consumers:\n- none'))
  t.ok(report.includes('Direct-consumer scan exclusions:'))
})

test('ecosystem consumer audit fails on unclassified Hiverelay pins', (t) => {
  const root = fixtureWorkspace()
  writePackage(root, '02-apps/unknown/package.json', {
    dependencies: {
      'p2p-hiverelay-client': '^0.8.0'
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale: []
  })

  t.absent(summary.ok)
  t.ok(summary.errors[0].includes('Unclassified Hiverelay package consumer'))
})

test('ecosystem consumer audit fails when the known stale inventory changes', (t) => {
  const root = fixtureWorkspace()
  writePackage(root, '02-apps/pearpaste/package.json', {
    dependencies: {
      'p2p-hiverelay-client': '^0.20.2'
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale: [{
      path: '02-apps/pearpaste/package.json',
      deps: {
        'p2p-hiverelay-client': '^0.9.2'
      }
    }]
  })

  t.absent(summary.ok)
  t.ok(summary.errors[0].includes('known stale consumer has p2p-hiverelay-client'))
})

test('ecosystem consumer audit reports source-level migration markers', (t) => {
  const root = fixtureWorkspace()
  writePackage(root, '03-sites/pearbrowser-publishers/src/p2pbuilders/package.json', {
    dependencies: {
      'p2p-hiverelay': '^0.4.2'
    }
  })
  writeFile(root, '03-sites/pearbrowser-publishers/src/p2pbuilders/scripts/publish.js', `
    const { HiveRelayClient } = await import('p2p-hiverelay/client')
  `)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const expectedStale = [{
    path: '03-sites/pearbrowser-publishers/src/p2pbuilders/package.json',
    deps: {
      'p2p-hiverelay': '^0.4.2'
    },
    sourceChecks: [{
      file: '03-sites/pearbrowser-publishers/src/p2pbuilders/scripts/publish.js',
      label: 'legacy client subpath',
      term: 'p2p-hiverelay/client'
    }]
  }]
  const sourceChecks = scanStaleConsumerSourceChecks({ workspaceRoot: root, expectedStale })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale,
    sourceChecks
  })

  t.ok(summary.ok)
  t.is(summary.sourceChecks.length, 1)
  t.ok(summary.sourceChecks[0].present)
  t.ok(formatConsumerReport(summary).includes('Source-level migration checks'))
})

test('ecosystem consumer audit guards PearPaste current Hiverelay docs', (t) => {
  const root = fixtureWorkspace()
  const pearpaste = EXPECTED_CURRENT_CONSUMERS.find(consumer => consumer.path === '02-apps/pearpaste/package.json')
  writeExpectedConsumerPackages(root, [pearpaste])
  writeFile(root, '02-apps/pearpaste/docs/RECOVERY_DESIGN.md', `
    "p2p-hiverelay": "file:../../00-core/hiverelay/packages/core",
    "p2p-hiverelay-client": "file:../../00-core/hiverelay/packages/client"
  `)
  writeFile(root, '02-apps/pearpaste/docs/PEARPASTE_TECHNICAL_SPEC.md', `
    Integrate the HiveRelay \`0.20.2\` local workspace packages by default.
  `)
  writeFile(root, '02-apps/pearpaste/REVIEW.md', `
    current p2p-hiverelay-client@0.20.2 split-client package line
  `)
  writeFile(root, '02-apps/pearpaste/scripts/probe-circuit.mjs', `
    // current HiveRelay fleet
  `)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [pearpaste],
    expectedStale: []
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [pearpaste],
    expectedStale: [],
    sourceChecks
  })

  t.ok(summary.ok)

  writeFile(root, '02-apps/pearpaste/docs/RECOVERY_DESIGN.md', `
    Blocked on upstream npm publish
    "p2p-hiverelay-client": "^0.9.2"
  `)
  const failedChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [pearpaste],
    expectedStale: []
  })
  const failedSummary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [pearpaste],
    expectedStale: [],
    sourceChecks: failedChecks
  })

  t.absent(failedSummary.ok)
  t.ok(failedSummary.errors.some(error => error.includes('Disallowed source-level migration marker found')))
})

test('ecosystem consumer audit guards PearBrowser and POS current Hiverelay source defaults', (t) => {
  const root = fixtureWorkspace()
  const expectedCurrent = EXPECTED_CURRENT_CONSUMERS.filter(consumer => [
    '01-browser/pearbrowser-desktop/package.json',
    '02-apps/pear-pos/package.json'
  ].includes(consumer.path))
  const pearbrowser = expectedCurrent.find(consumer => consumer.path === '01-browser/pearbrowser-desktop/package.json')
  writeExpectedConsumerPackages(root, expectedCurrent)
  writeSourceCheckTerms(root, pearbrowser, '0.20.2')
  writeFile(root, '02-apps/pear-pos/app/backend/hiverelay-client.js', `
    // ESM -> CJS bridge for p2p-hiverelay-client@0.20.2
  `)
  writeFile(root, '02-apps/pear-pos/app/backend/hiverelay-sync.js', `
    // Seed lifecycle (v0.20.2)
  `)
  writeFile(root, '02-apps/pear-pos/ARCHITECTURE.md', `
    p2p-hiverelay-client@0.20.2
  `)
  writeFile(root, '02-apps/pear-pos/PLAN.md', `
    current HiveRelay 0.20.2 split packages
  `)
  writeFile(root, '02-apps/pear-pos/RESEARCH.md', `
    SDK: \`p2p-hiverelay-client@0.20.2\`
  `)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent,
    expectedStale: []
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent,
    expectedStale: [],
    sourceChecks
  })

  t.ok(summary.ok)

  writeSourceCheckTerms(root, pearbrowser, '0.16.3')
  const failedChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent,
    expectedStale: []
  })
  const failedSummary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent,
    expectedStale: [],
    sourceChecks: failedChecks
  })

  t.absent(failedSummary.ok)
  t.ok(failedSummary.errors.some(error => error.includes('PearBrowser bundled catalog seed')))
})

test('ecosystem consumer audit fails when source-level migration markers move', (t) => {
  const root = fixtureWorkspace()
  writePackage(root, '04-experiments/Opengit/packages/opengit-relay/package.json', {
    optionalDependencies: {
      'p2p-hiverelay-client': '^0.8.13'
    }
  })
  writeFile(root, '04-experiments/Opengit/packages/opengit-relay/lib/relay.js', `
    async function loadClient () { return import('p2p-hiverelay-client') }
  `)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const expectedStale = [{
    path: '04-experiments/Opengit/packages/opengit-relay/package.json',
    deps: {
      'p2p-hiverelay-client': '^0.8.13'
    },
    sourceChecks: [{
      file: '04-experiments/Opengit/packages/opengit-relay/lib/relay.js',
      label: 'CommonJS client load',
      term: "require('p2p-hiverelay-client')"
    }]
  }]
  const sourceChecks = scanStaleConsumerSourceChecks({ workspaceRoot: root, expectedStale })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale,
    sourceChecks
  })

  t.absent(summary.ok)
  t.ok(summary.errors[0].includes('Missing expected source-level migration marker'))
})

test('ecosystem consumer audit verifies lockfile local package metadata', (t) => {
  const root = fixtureWorkspace()
  const deps = {
    'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
    'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
  }
  writePackage(root, '02-apps/pear-pos/package.json', {
    optionalDependencies: deps
  })
  writePackageLock(root, '02-apps/pear-pos/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: deps
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.20.2',
        dependencies: {
          'p2p-hiverelay': '^0.20.2'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.20.2'
      },
      'node_modules/p2p-hiverelay': {
        resolved: '../../00-core/hiverelay/packages/core',
        link: true
      },
      'node_modules/p2p-hiverelay-client': {
        resolved: '../../00-core/hiverelay/packages/client',
        link: true
      }
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const expectedCurrent = [{
    path: '02-apps/pear-pos/package.json',
    deps
  }]
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent,
    expectedStale: [],
    lockChecks
  })

  t.ok(summary.ok)
  t.ok(formatConsumerReport(summary).includes('Lockfile migration checks:'))
})

test('ecosystem consumer audit rejects stale lockfile Hiverelay entries', (t) => {
  const root = fixtureWorkspace()
  const deps = {
    'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
    'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
  }
  writePackage(root, '02-apps/pear-pos/package.json', {
    optionalDependencies: deps
  })
  writePackageLock(root, '02-apps/pear-pos/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: deps
      },
      '../../00-core/hiverelay': {
        name: 'p2p-hiverelay-monorepo',
        version: '0.16.3'
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.20.2',
        dependencies: {
          'p2p-hiverelay': '^0.16.3'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.20.2'
      }
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const expectedCurrent = [{
    path: '02-apps/pear-pos/package.json',
    deps
  }]
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent,
    expectedStale: [],
    lockChecks
  })

  t.absent(summary.ok)
  t.ok(summary.errors.some(error => error.includes('stale monorepo-root Hiverelay lock entry')))
  t.ok(summary.errors.some(error => error.includes('p2p-hiverelay') && error.includes('^0.16.3')))
})

test('ecosystem consumer audit finds monorepo package lockfiles', (t) => {
  const root = fixtureWorkspace()
  const deps = {
    'p2p-hiverelay': 'file:../../../../00-core/hiverelay/packages/core',
    'p2p-hiverelay-client': 'file:../../../../00-core/hiverelay/packages/client'
  }
  writePackage(root, '04-experiments/Opengit/packages/opengit-relay/package.json', {
    optionalDependencies: deps
  })
  writePackageLock(root, '04-experiments/Opengit/package-lock.json', {
    packages: {
      'packages/opengit-relay': {
        optionalDependencies: deps
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.20.2',
        dependencies: {
          'p2p-hiverelay': '^0.20.2'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.20.2'
      }
    }
  })

  const expectedCurrent = [{
    path: '04-experiments/Opengit/packages/opengit-relay/package.json',
    deps
  }]
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent
  })

  t.ok(lockChecks.every(check => check.ok))
})

test('ecosystem sync updates app defaults and linked package lock metadata', (t) => {
  const root = fixtureWorkspace()
  const consumerPath = '02-apps/pearpaste/package.json'
  const deps = {
    'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
    'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
  }
  const expectedCurrent = [{
    path: consumerPath,
    deps
  }]

  writePackage(root, consumerPath, {
    optionalDependencies: {
      'p2p-hiverelay': '^0.16.3',
      'p2p-hiverelay-client': '^0.16.3'
    }
  })
  writePackageLock(root, '02-apps/pearpaste/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: {
          'p2p-hiverelay': '^0.16.3',
          'p2p-hiverelay-client': '^0.16.3'
        }
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.16.3',
        dependencies: {
          'p2p-hiverelay': '^0.16.3'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.16.3'
      }
    }
  })

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent,
    dependencyMode: 'local',
    snapshotChecks: false
  })

  t.ok(result.ok)
  t.ok(result.changes.some(change => change.includes('02-apps/pearpaste/package.json')))
  t.ok(result.changes.some(change => change.includes('version -> 0.20.2')))

  const pkg = readPackage(root, consumerPath)
  t.is(pkg.optionalDependencies['p2p-hiverelay'], deps['p2p-hiverelay'])
  t.is(pkg.optionalDependencies['p2p-hiverelay-client'], deps['p2p-hiverelay-client'])

  const lock = readPackage(root, '02-apps/pearpaste/package-lock.json')
  t.is(lock.packages[''].optionalDependencies['p2p-hiverelay'], deps['p2p-hiverelay'])
  t.is(lock.packages[''].optionalDependencies['p2p-hiverelay-client'], deps['p2p-hiverelay-client'])
  t.is(lock.packages['../../00-core/hiverelay/packages/core'].version, '0.20.2')
  t.is(lock.packages['../../00-core/hiverelay/packages/client'].version, '0.20.2')
  t.is(lock.packages['../../00-core/hiverelay/packages/client'].dependencies['p2p-hiverelay'], '^0.20.2')

  const check = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent,
    dependencyMode: 'local',
    snapshotChecks: false,
    check: true
  })
  t.ok(check.ok)
  t.is(check.changes.length, 0)
})

test('ecosystem consumer helpers default published apps to npm latest', (t) => {
  const consumers = getExpectedCurrentConsumers()
  const pearpaste = consumers.find(consumer => consumer.path === '02-apps/pearpaste/package.json')

  t.is(DEFAULT_DEPENDENCY_MODE, 'npm-latest')
  t.ok(pearpaste)
  t.is(pearpaste.dependencyMode, 'npm-latest')
  t.is(pearpaste.deps['p2p-hiverelay'], 'latest')
  t.is(pearpaste.deps['p2p-hiverelay-client'], 'latest')
  t.ok(pearpaste.sourceChecks.some(check => check.termTemplate === 'HiveRelay `{version}` packages through npm `latest` by default'))
  t.ok(pearpaste.sourceChecks.some(check => check.term === '"p2p-hiverelay": "latest"'))

  const local = getExpectedCurrentConsumers({ dependencyMode: 'local' })
    .find(consumer => consumer.path === '02-apps/pearpaste/package.json')
  t.is(local.dependencyMode, 'local')
  t.ok(local.deps['p2p-hiverelay'].startsWith('file:'))
  t.ok(local.sourceChecks.some(check => check.termTemplate === 'HiveRelay `{version}` local workspace packages by default'))
  t.ok(local.sourceChecks.some(check => check.term === '"p2p-hiverelay": "file:../../00-core/hiverelay/packages/core"'))
})

test('ecosystem sync default npm-latest path refuses stale registry latest', (t) => {
  const root = fixtureWorkspace()
  const consumer = {
    ...getExpectedCurrentConsumers().find(consumer => consumer.path === '02-apps/pearpaste/package.json'),
    sourceChecks: []
  }

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    npmLatestVersions: {
      'p2p-hiverelay': '0.9.2',
      'p2p-hiverelay-client': '0.20.2'
    },
    snapshotChecks: false
  })

  t.absent(result.ok)
  t.is(result.dependencyMode, 'npm-latest')
  t.ok(result.errors.some(error => error.includes('p2p-hiverelay npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.is(result.changes.length, 0, 'default npm latest mode blocks before writing app files')
})

test('ecosystem sync refuses npm-latest defaults when npm latest would downgrade', (t) => {
  const root = fixtureWorkspace()
  const consumer = getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
    .find(consumer => consumer.path === '02-apps/pearpaste/package.json')

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: {
      'p2p-hiverelay': '0.9.2',
      'p2p-hiverelay-client': '0.20.2'
    },
    snapshotChecks: false
  })

  t.absent(result.ok)
  t.ok(result.errors.some(error => error.includes('p2p-hiverelay npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.is(result.changes.length, 0, 'stale npm latest blocks before writing app files')
})

test('ecosystem consumer audit accepts npm-latest manifests with current npm lock metadata', (t) => {
  const root = fixtureWorkspace()
  const consumer = {
    ...getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
      .find(consumer => consumer.path === '02-apps/pearpaste/package.json'),
    sourceChecks: []
  }

  writePackage(root, consumer.path, {
    optionalDependencies: consumer.deps
  })
  writePackageLock(root, '02-apps/pearpaste/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: consumer.deps
      },
      'node_modules/p2p-hiverelay': {
        version: '0.20.2',
        resolved: 'https://registry.npmjs.org/p2p-hiverelay/-/p2p-hiverelay-0.20.2.tgz',
        integrity: 'sha512-test'
      },
      'node_modules/p2p-hiverelay-client': {
        version: '0.20.2',
        resolved: 'https://registry.npmjs.org/p2p-hiverelay-client/-/p2p-hiverelay-client-0.20.2.tgz',
        integrity: 'sha512-test',
        dependencies: {
          'p2p-hiverelay': '^0.20.2'
        }
      }
    }
  })

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer]
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    expectedStale: [],
    lockChecks
  })
  const syncCheck = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: {
      'p2p-hiverelay': '0.20.2',
      'p2p-hiverelay-client': '0.20.2'
    },
    snapshotChecks: false,
    check: true
  })

  t.ok(summary.ok)
  t.ok(lockChecks.every(check => check.ok))
  t.ok(syncCheck.ok)
  t.is(syncCheck.changes.length, 0)
  t.ok(syncCheck.warnings.some(warning => warning.includes('npm latest dist-tags verified')))
})

test('ecosystem sync updates versioned app source markers', (t) => {
  const root = fixtureWorkspace()
  const consumer = EXPECTED_CURRENT_CONSUMERS.find(consumer => consumer.path === '01-browser/pearbrowser-desktop/package.json')
  writeExpectedConsumerPackages(root, [consumer])
  writePackageLock(root, '01-browser/pearbrowser-desktop/package-lock.json', {
    packages: {
      '': {
        dependencies: consumer.deps
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.16.3',
        dependencies: {
          'p2p-hiverelay': '^0.16.3'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.16.3'
      },
      '../../00-core/hiverelay/packages/verifier': {
        name: 'p2p-hiverelay-verifier',
        version: '0.16.3'
      }
    }
  })
  writeSourceCheckTerms(root, consumer, '0.16.3')

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'local',
    snapshotChecks: false
  })

  t.ok(result.ok)
  t.ok(result.changes.some(change => change.includes('catalog-source/pearbrowser-network.catalog.json')))
  t.ok(result.changes.some(change => change.includes('backend/catalogue-seed.js')))
  t.ok(result.changes.some(change => change.includes('docs/HIVERELAY-BACKBONE-HANDOVER.md')))
  t.ok(fs.readFileSync(path.join(root, '01-browser/pearbrowser-desktop/catalog-source/pearbrowser-network.catalog.json'), 'utf8').includes('"version": "0.20.2"'))
  t.ok(fs.readFileSync(path.join(root, '01-browser/pearbrowser-desktop/backend/catalogue-seed.js'), 'utf8').includes('"version": "0.20.2"'))
  t.ok(fs.readFileSync(path.join(root, '01-browser/pearbrowser-desktop/docs/HIVERELAY-BACKBONE-HANDOVER.md'), 'utf8').includes('`p2p-hiverelay` `0.20.2`'))

  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    expectedStale: []
  })
  t.ok(sourceChecks.every(check => check.present))
  t.ok(sourceChecks.every(check => check.rejectedTermsFound.length === 0))
})

test('ecosystem consumer audit guards local release snapshot defaults', (t) => {
  const root = fixtureWorkspace()
  writeSnapshot(root, '00-core/hr-fleet', '0.20.2')

  const snapshotRoots = [{
    path: '00-core/hr-fleet',
    role: 'fleet release snapshot'
  }]
  const snapshotChecks = scanSnapshotVersionChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    snapshotRoots
  })
  const summary = checkConsumerState([], {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale: [],
    snapshotChecks
  })

  t.ok(summary.ok)
  t.ok(formatConsumerReport(summary).includes('Snapshot/default version checks:'))

  writePackage(root, '00-core/hr-fleet/packages/client/package.json', {
    name: 'p2p-hiverelay-client',
    version: '0.20.2',
    dependencies: {
      'p2p-hiverelay': '^0.20.0'
    }
  })
  const failedChecks = scanSnapshotVersionChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    snapshotRoots
  })
  const failedSummary = checkConsumerState([], {
    expectedVersion: '0.20.2',
    expectedCurrent: [],
    expectedStale: [],
    snapshotChecks: failedChecks
  })

  t.absent(failedSummary.ok)
  t.ok(failedSummary.errors.some(error => error.includes('p2p-hiverelay') && error.includes('^0.20.2')))
})

function fixtureWorkspace () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-ecosystem-consumers-'))
}

function writePackage (root, relPath, body) {
  const file = path.join(root, relPath)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify({ name: path.basename(path.dirname(file)), ...body }, null, 2))
}

function writeExpectedConsumerPackages (root, consumers) {
  for (const consumer of consumers) {
    writePackage(root, consumer.path, {
      dependencies: consumer.deps
    })
  }
}

function writeFile (root, relPath, body) {
  const file = path.join(root, relPath)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, body)
}

function writeSourceCheckTerms (root, consumer, version) {
  for (const spec of consumer.sourceChecks || []) {
    const term = typeof spec.termTemplate === 'string'
      ? spec.termTemplate.replaceAll('{version}', version)
      : spec.term
    writeFile(root, spec.file, `${term}\n`)
  }
}

function writePackageLock (root, relPath, body) {
  const file = path.join(root, relPath)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify({
    name: path.basename(path.dirname(file)),
    version: '0.0.0',
    lockfileVersion: 3,
    requires: true,
    ...body
  }, null, 2))
}

function readPackage (root, relPath) {
  return JSON.parse(fs.readFileSync(path.join(root, relPath), 'utf8'))
}

function writeSnapshot (root, snapshotRoot, version) {
  const coreRange = `^${version}`
  writePackage(root, `${snapshotRoot}/package.json`, {
    name: 'p2p-hiverelay-monorepo',
    version
  })
  writePackage(root, `${snapshotRoot}/packages/core/package.json`, {
    name: 'p2p-hiverelay',
    version
  })
  writePackage(root, `${snapshotRoot}/packages/client/package.json`, {
    name: 'p2p-hiverelay-client',
    version,
    dependencies: {
      'p2p-hiverelay': coreRange
    }
  })
  writePackage(root, `${snapshotRoot}/packages/services/package.json`, {
    name: 'p2p-hiveservices',
    version,
    dependencies: {
      'p2p-hiverelay': coreRange
    }
  })
  writePackage(root, `${snapshotRoot}/packages/verifier/package.json`, {
    name: 'p2p-hiverelay-verifier',
    version
  })
  writePackageLock(root, `${snapshotRoot}/package-lock.json`, {
    name: 'p2p-hiverelay-monorepo',
    version,
    packages: {
      '': {
        name: 'p2p-hiverelay-monorepo',
        version
      },
      'packages/client': {
        name: 'p2p-hiverelay-client',
        version,
        dependencies: {
          'p2p-hiverelay': coreRange
        }
      },
      'packages/core': {
        name: 'p2p-hiverelay',
        version
      },
      'packages/services': {
        name: 'p2p-hiveservices',
        version,
        dependencies: {
          'p2p-hiverelay': coreRange
        }
      },
      'packages/verifier': {
        name: 'p2p-hiverelay-verifier',
        version
      }
    }
  })
}
