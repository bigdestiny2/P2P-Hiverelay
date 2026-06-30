import test from 'brittle'
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import {
  DEFAULT_DEPENDENCY_MODE,
  EXPECTED_CURRENT_CONSUMERS,
  HIVERELAY_DEPS,
  checkConsumerState,
  formatConsumerReport,
  getExpectedCurrentConsumers,
  scanConsumerSourceChecks,
  scanCurrentConsumerLockChecks,
  scanHiverelayConsumers,
  scanSnapshotVersionChecks,
  scanStaleConsumerSourceChecks,
  verifyNpmLatestDistTags
} from '../../scripts/audit-ecosystem-consumers.mjs'
import { checkEcosystemWorkspace } from '../../scripts/check-ecosystem-workspace.mjs'
import { commitEcosystemConsumers } from '../../scripts/commit-ecosystem-consumers.mjs'
import { syncEcosystemConsumers } from '../../scripts/sync-ecosystem-consumers.mjs'

function npmLatestVersions (version, overrides = {}) {
  return {
    ...Object.fromEntries(HIVERELAY_DEPS.map(dep => [dep, version])),
    ...overrides
  }
}

test('ecosystem consumer audit classifies current, stale, and ignored consumers', (t) => {
  const root = fixtureWorkspace()
  const expectedCurrentPaths = [
    '01-browser/pearbrowser-desktop/package.json',
    '02-apps/pearpaste/package.json',
    '02-apps/pear-pos/package.json',
    '02-apps/pear-tickets/package.json',
    '02-apps/peerit/package.json',
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
  t.ok(report.includes('02-apps/peerit/package.json'))
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
  writeFile(root, '02-apps/pearpaste/test/unit/hiverelay-upgrade.test.js', `
    test('HiveRelay customer path uses npm latest defaults', async (t) => {
      t.is(pkg.optionalDependencies['p2p-hiverelay'], 'latest')
      t.is(pkg.optionalDependencies['p2p-hiverelay-client'], 'latest')
    })
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
  writeFile(root, '02-apps/pear-pos/scripts/validate-publish-surface.mjs', `
    failures.push('package.json optionalDependencies.p2p-hiverelay should default to npm latest')
    failures.push('package.json optionalDependencies.p2p-hiverelay-client should default to npm latest')
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

test('ecosystem consumer audit guards anonGPT live relay consumer source contract', (t) => {
  const root = fixtureWorkspace()
  const anongpt = EXPECTED_CURRENT_CONSUMERS.find(consumer => consumer.path === '04-experiments/anongpt-native/package.json')
  writeExpectedConsumerPackages(root, [anongpt])
  writeFile(root, '04-experiments/anongpt-native/docs/ARCHITECTURE.md', 'Network privacy (hide your IP) rides on **HiveRelay**\nrelays — relay (1 hop) or onion (2 hops).\n')
  writeFile(root, '04-experiments/anongpt-native/backend/forward-transport.js', `
    // routes inference through the production HiveRelay relays' forward service
  `)
  writeFile(root, '04-experiments/anongpt-native/test/hiverelay-upgrade.test.cjs', `
    test('HiveRelay customer transport path uses npm latest by default', async () => {
      assert.equal(pkg.dependencies['p2p-hiverelay'], 'latest')
    })
  `)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [anongpt],
    expectedStale: []
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [anongpt],
    expectedStale: [],
    sourceChecks
  })

  t.ok(summary.ok)

  writeFile(root, '04-experiments/anongpt-native/backend/forward-transport.js', `
    // local standalone forwarder only
  `)
  const failedChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [anongpt],
    expectedStale: []
  })
  const failedSummary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [anongpt],
    expectedStale: [],
    sourceChecks: failedChecks
  })

  t.absent(failedSummary.ok)
  t.ok(failedSummary.errors.some(error => error.includes('anonGPT forward transport targets production HiveRelay forward service')))
})

test('ecosystem consumer audit guards Peerit source-only publish client compatibility', (t) => {
  const root = fixtureWorkspace()
  const peerit = EXPECTED_CURRENT_CONSUMERS.find(consumer => consumer.path === '02-apps/peerit/package.json')
  writeExpectedConsumerPackages(root, [peerit])
  writeFile(root, '02-apps/peerit/publish.mjs', `
    const HIVERELAY_CLIENT_PACKAGE = 'p2p-hiverelay-client'
    const HIVERELAY_CLIENT_PATHS = [
      ['HIVERELAY_ROOT', process.env.HIVERELAY_ROOT]
    ]
    throw new Error(\`\${source} does not export HiveRelayClient\`)
  `)
  writeFile(root, '02-apps/peerit/README.md', [
    'The app itself has no install step and no runtime npm dependencies. Publishing is',
    'the only workflow that needs the HiveRelay client.',
    '',
    'The publisher loads `p2p-hiverelay-client` from an installed package, an explicit',
    'HiveRelay env path, or a discoverable sibling/workspace checkout.'
  ].join('\n'))

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const sourceChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [peerit],
    expectedStale: []
  })
  const lockChecks = scanCurrentConsumerLockChecks({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [peerit]
  })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [peerit],
    expectedStale: [],
    sourceChecks,
    lockChecks
  })

  t.ok(summary.ok)
  t.is(rows.length, 0, 'source-only peerit has no package-dependency scan row')
  t.is(lockChecks.length, 0, 'source-only peerit does not require a lockfile')
  t.ok(formatConsumerReport(summary).includes('no package deps; source-only compatibility guard'))

  writePackage(root, '02-apps/peerit/package.json', {
    dependencies: {
      'p2p-hiverelay-client': '^0.9.2'
    }
  })
  const pinnedSummary = checkConsumerState(scanHiverelayConsumers({ workspaceRoot: root }), {
    expectedVersion: '0.20.2',
    expectedCurrent: [peerit],
    expectedStale: [],
    sourceChecks
  })
  t.absent(pinnedSummary.ok)
  t.ok(pinnedSummary.errors.some(error => error.includes('expected (none)')))

  writePackage(root, '02-apps/peerit/package.json', {})
  writeFile(root, '02-apps/peerit/publish.mjs', `
    const legacy = 'p2p-hiverelay/client'
  `)
  const failedChecks = scanConsumerSourceChecks({
    workspaceRoot: root,
    expectedCurrent: [peerit],
    expectedStale: []
  })
  const failedSummary = checkConsumerState(scanHiverelayConsumers({ workspaceRoot: root }), {
    expectedVersion: '0.20.2',
    expectedCurrent: [peerit],
    expectedStale: [],
    sourceChecks: failedChecks
  })
  t.absent(failedSummary.ok)
  t.ok(failedSummary.errors.some(error => error.includes('Peerit publish path loads the split HiveRelay client package')))
  t.ok(failedSummary.errors.some(error => error.includes('Disallowed source-level migration marker found')))
})

test('ecosystem sync keeps Peerit source-only manifest dependency-free', (t) => {
  const root = fixtureWorkspace()
  const peerit = getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
    .find(consumer => consumer.path === '02-apps/peerit/package.json')
  writePackage(root, '02-apps/peerit/package.json', {
    optionalDependencies: {
      'p2p-hiverelay-client': '^0.9.2'
    }
  })
  writeFile(root, '02-apps/peerit/publish.mjs', `
    const HIVERELAY_CLIENT_PACKAGE = 'p2p-hiverelay-client'
    const HIVERELAY_CLIENT_PATHS = [
      ['HIVERELAY_ROOT', process.env.HIVERELAY_ROOT]
    ]
    throw new Error(\`\${source} does not export HiveRelayClient\`)
  `)
  writeFile(root, '02-apps/peerit/README.md', [
    'The app itself has no install step and no runtime npm dependencies. Publishing is',
    'the only workflow that needs the HiveRelay client.',
    '',
    'The publisher loads `p2p-hiverelay-client` from an installed package, an explicit',
    'HiveRelay env path, or a discoverable sibling/workspace checkout.'
  ].join('\n'))

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [peerit],
    dependencyMode: 'npm-latest',
    npmLatestVersions: npmLatestVersions('0.20.2'),
    snapshotChecks: false
  })

  t.ok(result.ok)
  t.ok(result.changes.some(change => change.includes('02-apps/peerit/package.json: p2p-hiverelay-client removed')))
  t.is(result.summary.lockChecks.length, 0)
  t.alike(readPackage(root, '02-apps/peerit/package.json').optionalDependencies, undefined)
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
  const anongpt = consumers.find(consumer => consumer.path === '04-experiments/anongpt-native/package.json')
  const peerit = consumers.find(consumer => consumer.path === '02-apps/peerit/package.json')

  t.is(DEFAULT_DEPENDENCY_MODE, 'npm-latest')
  t.ok(pearpaste)
  t.is(pearpaste.dependencyMode, 'npm-latest')
  t.is(pearpaste.deps['p2p-hiverelay'], 'latest')
  t.is(pearpaste.deps['p2p-hiverelay-client'], 'latest')
  t.ok(pearpaste.sourceChecks.some(check => check.termTemplate === 'HiveRelay `{version}` packages through npm `latest` by default'))
  t.ok(pearpaste.sourceChecks.some(check => check.term === '"p2p-hiverelay": "latest"'))
  t.ok(pearpaste.sourceChecks.some(check => check.label === 'PearPaste customer test asserts npm latest Hiverelay defaults'))
  t.ok(anongpt)
  t.is(anongpt.dependencyMode, 'npm-latest')
  t.is(anongpt.deps['p2p-hiverelay'], 'latest')
  t.ok(anongpt.sourceChecks.some(check => check.label === 'anonGPT architecture documents HiveRelay relay/onion transport'))
  t.ok(anongpt.sourceChecks.some(check => check.label === 'anonGPT forward transport targets production HiveRelay forward service'))
  t.ok(anongpt.sourceChecks.some(check => check.label === 'anonGPT customer test asserts npm latest Hiverelay defaults'))
  t.ok(peerit)
  t.ok(peerit.sourceOnly)
  t.alike(peerit.deps, {})
  t.ok(peerit.sourceChecks.some(check => check.label === 'Peerit publish path loads the split HiveRelay client package'))

  const local = getExpectedCurrentConsumers({ dependencyMode: 'local' })
    .find(consumer => consumer.path === '02-apps/pearpaste/package.json')
  t.is(local.dependencyMode, 'local')
  t.ok(local.deps['p2p-hiverelay'].startsWith('file:'))
  t.ok(local.sourceChecks.some(check => check.termTemplate === 'HiveRelay `{version}` local workspace packages by default'))
  t.ok(local.sourceChecks.some(check => check.term === '"p2p-hiverelay": "file:../../00-core/hiverelay/packages/core"'))
})

test('ecosystem consumer release scope includes only package-default release repos', (t) => {
  const consumers = getExpectedCurrentConsumers({ consumerScope: 'release' })
  const paths = consumers.map(consumer => consumer.path).sort()

  t.alike(paths, [
    '01-browser/pearbrowser-desktop/package.json',
    '02-apps/pearpaste/package.json',
    '03-sites/pearbrowser-publishers/src/p2pbuilders/package.json',
    '04-experiments/Opengit/packages/opengit-relay/package.json',
    '04-experiments/anongpt-native/package.json'
  ].sort())
  t.ok(consumers.every(consumer => consumer.release?.repository))
  t.absent(paths.includes('02-apps/pear-pos/package.json'))
  t.absent(paths.includes('02-apps/pear-tickets/package.json'))
  t.absent(paths.includes('02-apps/peerit/package.json'))
  t.absent(paths.includes('04-experiments/hiverelay-test/package.json'))
})

test('ecosystem consumer release scope still classifies local-only app consumers', (t) => {
  const root = fixtureWorkspace()
  const releaseConsumers = getExpectedCurrentConsumers({ dependencyMode: 'local', consumerScope: 'release' })
  const allConsumers = getExpectedCurrentConsumers({ dependencyMode: 'local', consumerScope: 'all' })
  writeExpectedConsumerPackages(root, allConsumers)

  const rows = scanHiverelayConsumers({ workspaceRoot: root })
  const summary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: releaseConsumers,
    expectedClassifiedCurrent: allConsumers,
    consumerScope: 'release',
    expectedStale: []
  })

  t.ok(summary.ok)
  t.is(summary.current.length, releaseConsumers.length)
  t.absent(summary.current.some(row => row.path === '02-apps/pear-pos/package.json'))
  t.ok(formatConsumerReport(summary).includes('scope release'))
})

test('ecosystem workspace check accepts all release-critical app consumers', (t) => {
  const root = fixtureWorkspace()
  writeExpectedConsumerPackages(root, EXPECTED_CURRENT_CONSUMERS)

  const result = checkEcosystemWorkspace({
    workspaceRoot: root,
    expectedCurrent: EXPECTED_CURRENT_CONSUMERS
  })

  t.ok(result.ok)
  t.is(result.present.length, EXPECTED_CURRENT_CONSUMERS.length)
  t.is(result.missing.length, 0)
})

test('ecosystem workspace check fails when full sibling workspace is absent', (t) => {
  const root = fixtureWorkspace()

  const result = checkEcosystemWorkspace({
    workspaceRoot: root,
    expectedCurrent: EXPECTED_CURRENT_CONSUMERS
  })

  t.absent(result.ok)
  t.is(result.present.length, 0)
  t.is(result.missing.length, EXPECTED_CURRENT_CONSUMERS.length)
  t.ok(result.errors.some(error => error.includes('full sibling workspace not found')))
})

test('ecosystem workspace check reports partial app workspaces', (t) => {
  const root = fixtureWorkspace()
  const [present, missing] = EXPECTED_CURRENT_CONSUMERS
  writeExpectedConsumerPackages(root, [present])

  const result = checkEcosystemWorkspace({
    workspaceRoot: root,
    expectedCurrent: [present, missing]
  })

  t.absent(result.ok)
  t.is(result.present.length, 1)
  t.is(result.missing.length, 1)
  t.ok(result.errors.some(error => error.includes(missing.path)))
})

test('ecosystem workspace check accepts release-managed consumer scope', (t) => {
  const root = fixtureWorkspace()
  const consumers = getExpectedCurrentConsumers({ dependencyMode: 'local', consumerScope: 'release' })
  writeExpectedConsumerPackages(root, consumers)

  const result = checkEcosystemWorkspace({
    workspaceRoot: root,
    consumerScope: 'release'
  })

  t.ok(result.ok)
  t.is(result.consumerScope, 'release')
  t.is(result.present.length, consumers.length)
})

test('ecosystem consumer commit helper commits changed release repos', (t) => {
  const root = fixtureWorkspace()
  const checkoutPath = '01-browser/pearbrowser-desktop'
  const repo = path.join(root, checkoutPath)
  fs.mkdirSync(repo, { recursive: true })
  git(repo, ['init'])
  git(repo, ['config', 'user.name', 'test'])
  git(repo, ['config', 'user.email', 'test@example.invalid'])
  writePackage(root, `${checkoutPath}/package.json`, {
    dependencies: {
      'p2p-hiverelay': 'latest'
    }
  })
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'initial'])

  writePackage(root, `${checkoutPath}/package.json`, {
    dependencies: {
      'p2p-hiverelay': 'latest',
      'p2p-hiverelay-client': 'latest'
    }
  })

  const result = commitEcosystemConsumers({
    workspaceRoot: root,
    version: 'v0.20.2',
    push: false,
    expectedCurrent: [{
      path: `${checkoutPath}/package.json`,
      release: {
        repository: 'bigdestiny2/pearbrowser-desktop',
        ref: 'main',
        checkoutPath
      },
      deps: {
        'p2p-hiverelay': 'latest',
        'p2p-hiverelay-client': 'latest'
      }
    }]
  })

  t.ok(result.ok)
  t.is(result.rows[0].status, 'committed')
  t.ok(git(repo, ['status', '--porcelain']).stdout.trim() === '')
  t.ok(git(repo, ['log', '-1', '--pretty=%s']).stdout.includes('chore: sync HiveRelay defaults v0.20.2'))
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
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiverelay': '0.9.2'
    }),
    snapshotChecks: false
  })

  t.absent(result.ok)
  t.is(result.dependencyMode, 'npm-latest')
  t.ok(result.errors.some(error => error.includes('p2p-hiverelay npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.is(result.changes.length, 0, 'default npm latest mode blocks before writing app files')
})

test('ecosystem audit CLI defaults to npm-latest mode', (t) => {
  const root = fixtureWorkspace()
  const result = spawnSync(process.execPath, [
    'scripts/audit-ecosystem-consumers.mjs',
    '--workspace-root', root,
    '--expected-version', '0.20.2',
    '--consumer-scope', 'release',
    '--check'
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_NPM_LATEST_JSON: JSON.stringify(npmLatestVersions('0.20.2'))
    }
  })

  t.is(result.status, 1)
  t.ok(result.stdout.includes('mode npm-latest'), 'direct CLI uses the published-app default')
  t.ok(result.stdout.includes('Current npm-latest consumers:'))
  t.absent(result.stdout.includes('mode local'))
})

test('ecosystem sync default npm-latest path verifies the full package line', (t) => {
  const root = fixtureWorkspace()
  const consumer = {
    ...getExpectedCurrentConsumers().find(consumer => consumer.path === '02-apps/pearpaste/package.json'),
    sourceChecks: []
  }

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiveservices': '0.9.2'
    }),
    snapshotChecks: false
  })

  t.absent(result.ok)
  t.ok(result.errors.some(error => error.includes('p2p-hiveservices npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.is(result.changes.length, 0, 'stale services package blocks app default writes even when the app does not list it directly')
})

test('ecosystem sync refuses npm-latest defaults when npm latest would downgrade', (t) => {
  const root = fixtureWorkspace()
  const consumer = getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
    .find(consumer => consumer.path === '02-apps/pearpaste/package.json')
  writePackage(root, consumer.path, {
    optionalDependencies: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    }
  })

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiverelay': '0.9.2'
    }),
    snapshotChecks: false
  })

  t.absent(result.ok)
  t.ok(result.errors.some(error => error.includes('p2p-hiverelay npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.ok(result.changes.some(change => change.includes('02-apps/pearpaste/package.json: p2p-hiverelay -> latest')))
  t.ok(result.warnings.some(warning => warning.includes('pending manifest/source changes are shown for release planning only')))
  const pkg = readPackage(root, consumer.path)
  t.is(pkg.optionalDependencies['p2p-hiverelay'], 'file:../../00-core/hiverelay/packages/core', 'stale npm latest still blocks writes')
  t.is(pkg.optionalDependencies['p2p-hiverelay-client'], 'file:../../00-core/hiverelay/packages/client')
})

test('ecosystem sync can prepare latest app defaults before npm latest is promoted', (t) => {
  const root = fixtureWorkspace()
  const consumer = {
    ...getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
      .find(consumer => consumer.path === '02-apps/pearpaste/package.json'),
    sourceChecks: []
  }

  writePackage(root, consumer.path, {
    optionalDependencies: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    }
  })
  writePackageLock(root, '02-apps/pearpaste/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: {
          'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
          'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
        }
      },
      '../../00-core/hiverelay/packages/core': {
        name: 'p2p-hiverelay',
        version: '0.20.2'
      },
      '../../00-core/hiverelay/packages/client': {
        name: 'p2p-hiverelay-client',
        version: '0.20.2'
      }
    }
  })

  const result = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiverelay': '0.9.2'
    }),
    prepareLatestDefaults: true,
    snapshotChecks: false
  })

  t.ok(result.ok)
  t.ok(result.prepareLatestDefaults)
  t.ok(result.changes.some(change => change.includes('02-apps/pearpaste/package.json: p2p-hiverelay -> latest')))
  t.ok(result.warnings.some(warning => warning.includes('prepare-latest-defaults skipped registry proof')))
  t.ok(result.warnings.some(warning => warning.includes('without lockfile refresh')))

  const pkg = readPackage(root, consumer.path)
  const lock = readPackage(root, '02-apps/pearpaste/package-lock.json')
  t.is(pkg.optionalDependencies['p2p-hiverelay'], 'latest')
  t.is(pkg.optionalDependencies['p2p-hiverelay-client'], 'latest')
  t.is(lock.packages[''].optionalDependencies['p2p-hiverelay'], 'file:../../00-core/hiverelay/packages/core')
  t.is(lock.packages[''].optionalDependencies['p2p-hiverelay-client'], 'file:../../00-core/hiverelay/packages/client')
})

test('ecosystem prepare-latest check verifies staged defaults without writing', (t) => {
  const root = fixtureWorkspace()
  const consumer = {
    ...getExpectedCurrentConsumers({ dependencyMode: 'npm-latest' })
      .find(consumer => consumer.path === '02-apps/pearpaste/package.json'),
    sourceChecks: []
  }

  writePackage(root, consumer.path, {
    optionalDependencies: {
      'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
      'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
    }
  })
  writePackageLock(root, '02-apps/pearpaste/package-lock.json', {
    packages: {
      '': {
        optionalDependencies: {
          'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
          'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client'
        }
      }
    }
  })

  const pending = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiverelay': '0.9.2'
    }),
    prepareLatestDefaults: true,
    snapshotChecks: false,
    check: true
  })

  t.absent(pending.ok)
  t.ok(pending.check)
  t.ok(pending.prepareLatestDefaults)
  t.ok(pending.changes.some(change => change.includes('02-apps/pearpaste/package.json: p2p-hiverelay -> latest')))
  t.ok(pending.errors.some(error => error.includes('ecosystem consumer file(s) need default-version sync')))
  t.is(readPackage(root, consumer.path).optionalDependencies['p2p-hiverelay'], 'file:../../00-core/hiverelay/packages/core')

  writePackage(root, consumer.path, {
    optionalDependencies: consumer.deps
  })

  const ready = syncEcosystemConsumers({
    workspaceRoot: root,
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    dependencyMode: 'npm-latest',
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiverelay': '0.9.2'
    }),
    prepareLatestDefaults: true,
    snapshotChecks: false,
    check: true
  })

  t.ok(ready.ok)
  t.ok(ready.check)
  t.is(ready.changes.length, 0)
  t.ok(ready.warnings.some(warning => warning.includes('prepare-latest-defaults skipped registry proof')))
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
    npmLatestVersions: npmLatestVersions('0.20.2'),
    snapshotChecks: false,
    check: true
  })

  t.ok(summary.ok)
  t.ok(lockChecks.every(check => check.ok))
  t.ok(syncCheck.ok)
  t.is(syncCheck.changes.length, 0)
  t.ok(syncCheck.warnings.some(warning => warning.includes('p2p-hiveservices')))

  const staleLatest = verifyNpmLatestDistTags({
    expectedCurrent: [consumer],
    expectedVersion: '0.20.2',
    npmLatestVersions: npmLatestVersions('0.20.2', {
      'p2p-hiveservices': '0.9.2'
    })
  })
  const latestSummary = checkConsumerState(rows, {
    expectedVersion: '0.20.2',
    expectedCurrent: [consumer],
    expectedStale: [],
    lockChecks,
    npmLatestChecks: staleLatest.checks,
    npmLatestWarnings: staleLatest.warnings
  })

  t.absent(latestSummary.ok)
  t.ok(latestSummary.errors.some(error => error.includes('p2p-hiveservices npm latest dist-tag is 0.9.2; expected 0.20.2')))
  t.ok(formatConsumerReport(latestSummary).includes('NPM latest dist-tag checks:'))
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
  writeFile(
    root,
    '01-browser/pearbrowser-desktop/docs/HIVERELAY-BACKBONE-HANDOVER.md',
    '- Relay core: `p2p-hiverelay` (npm v0.8.12) — `core/index.js`\n'
  )

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
  const handover = fs.readFileSync(path.join(root, '01-browser/pearbrowser-desktop/docs/HIVERELAY-BACKBONE-HANDOVER.md'), 'utf8')
  t.ok(handover.includes('`p2p-hiverelay` `0.20.2`'))
  t.absent(handover.includes('npm v0.8.12'))

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

function git (cwd, argv) {
  const result = spawnSync('git', argv, {
    cwd,
    encoding: 'utf8'
  })
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `git ${argv.join(' ')} failed`)
  }
  return result
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
