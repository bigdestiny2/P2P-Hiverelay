import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { EXPECTED_CURRENT_CONSUMERS } from '../../scripts/audit-ecosystem-consumers.mjs'

const DIGEST = 'sha256:' + 'a'.repeat(64)

function runPrepare (argv, script = 'scripts/prepare-release.mjs') {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...argv], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH || '' },
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

test('prepare-release defaults prerelease channel to none', async (t) => {
  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--image-digest', DIGEST,
    '--check'
  ])

  t.is(res.status, 1, 'future prerelease reports expected drift')
  t.ok(res.stderr.includes('Release surfaces are out of sync:'))
  t.absent(res.stderr.includes('fleet/channels.json'), 'implicit prerelease does not bump fleet channels')
  t.absent(res.stderr.includes('blindspark-umbrel-store'), 'implicit prerelease does not sync the community store checkout')
  t.absent(res.stderr.includes('hiverelay-blindspark'), 'implicit prerelease does not sync community store package files')
})

test('prepare-release defaults full release channel to both', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-both-fixture-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  const res = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const channels = JSON.parse(await readFile(path.join(repo, 'fleet', 'channels.json'), 'utf8'))
  t.is(channels.canary, 'v9.9.9', 'implicit full release bumps canary')
  t.is(channels.stable, 'v9.9.9', 'implicit full release bumps stable')

  const startosManifest = await readFile(path.join(repo, 'startos', 'manifest.yaml'), 'utf8')
  t.absent(startosManifest.includes('metadata.license'), 'StartOS release-notes block keeps the following key on a new line')
  t.ok(startosManifest.includes('metadata.\nlicense: apache-2.0'), 'StartOS release-notes block is newline-terminated')
})

test('prepare-release syncs sibling ecosystem consumer defaults', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-ecosystem-fixture-'))
  t.teardown(async () => {
    await rm(root, { recursive: true, force: true })
  })
  const repo = path.join(root, '00-core', 'hiverelay')
  await writeMinimalReleaseFixture(repo)
  await writeEcosystemConsumerFixture(root, '0.16.3')

  const res = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  t.ok(res.stdout.includes('ecosystem/01-browser/pearbrowser-desktop/package.json'))

  const pearbrowser = JSON.parse(await readFile(path.join(root, '01-browser', 'pearbrowser-desktop', 'package.json'), 'utf8'))
  t.is(pearbrowser.dependencies['p2p-hiverelay'], 'file:../../00-core/hiverelay/packages/core')
  t.is(pearbrowser.dependencies['p2p-hiverelay-client'], 'file:../../00-core/hiverelay/packages/client')
  t.is(pearbrowser.dependencies['p2p-hiverelay-verifier'], 'file:../../00-core/hiverelay/packages/verifier')

  const lock = JSON.parse(await readFile(path.join(root, '01-browser', 'pearbrowser-desktop', 'package-lock.json'), 'utf8'))
  t.is(lock.packages['../../00-core/hiverelay/packages/core'].version, '9.9.9')
  t.is(lock.packages['../../00-core/hiverelay/packages/client'].dependencies['p2p-hiverelay'], '^9.9.9')

  const catalog = await readFile(path.join(root, '01-browser', 'pearbrowser-desktop', 'catalog-source', 'pearbrowser-network.catalog.json'), 'utf8')
  const handover = await readFile(path.join(root, '01-browser', 'pearbrowser-desktop', 'docs', 'HIVERELAY-BACKBONE-HANDOVER.md'), 'utf8')
  t.ok(catalog.includes('"version": "9.9.9"'))
  t.ok(handover.includes('`p2p-hiverelay` `9.9.9`'))
})

test('prepare-release rejects explicit prerelease channel promotion', async (t) => {
  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--channel', 'canary',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--check'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Pre-release v9.9.9-beta.1 cannot promote fleet/app-store channel "canary"'))
})

test('prepare-release rejects explicit prerelease community-store sync', async (t) => {
  const store = await mkdtemp(path.join(tmpdir(), 'hiverelay-prerelease-store-'))
  t.teardown(async () => {
    await rm(store, { recursive: true, force: true })
  })

  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--umbrel-store', store,
    '--image-digest', DIGEST,
    '--check'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Pre-release v9.9.9-beta.1 cannot sync the community Umbrel store'))
})

test('prepare-release rejects invalid ecosystem dependency mode', async (t) => {
  const res = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--ecosystem-dependency-mode', 'floating'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Invalid --ecosystem-dependency-mode "floating"'))
})

test('prepare-release rejects secret-looking release notes before metadata sync', async (t) => {
  const res = await runPrepare([
    'v0.16.3',
    '--channel', 'none',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--release-notes', 'Release candidate Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
    '--check'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('release notes must not expose authorization header'))
  t.absent(res.stderr.includes('Release surfaces are out of sync'))
})

test('prepare-release rejects unsafe release-note control characters before metadata sync', async (t) => {
  const res = await runPrepare([
    'v0.16.3',
    '--channel', 'none',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--release-notes', 'Safe text\u001b[31m',
    '--check'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('release notes must not contain unsafe control characters'))
  t.absent(res.stderr.includes('Release surfaces are out of sync'))
})

test('prepare-release removes local-only README status suffix for public releases', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-fixture-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  const res = await runPrepare([
    'v9.9.9',
    '--channel', 'none',
    '--image-digest', DIGEST,
    '--no-umbrel-store'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const readme = await readFile(path.join(repo, 'README.md'), 'utf8')
  t.ok(readme.includes('Status: v9.9.9**'))
  t.absent(readme.includes('packages; main has unreleased upgrades'))
})

async function writeMinimalReleaseFixture (repo) {
  await writeText(path.join(repo, 'scripts', 'prepare-release.mjs'), await readFile('scripts/prepare-release.mjs', 'utf8'))
  await writeText(path.join(repo, 'scripts', 'audit-ecosystem-consumers.mjs'), await readFile('scripts/audit-ecosystem-consumers.mjs', 'utf8'))
  await writeText(path.join(repo, 'scripts', 'sync-ecosystem-consumers.mjs'), await readFile('scripts/sync-ecosystem-consumers.mjs', 'utf8'))
  await writeJson(path.join(repo, 'package.json'), { name: 'p2p-hiverelay-monorepo', version: '0.16.3' })
  await writeJson(path.join(repo, 'packages', 'core', 'package.json'), { name: 'p2p-hiverelay', version: '0.16.3' })
  await writeJson(path.join(repo, 'packages', 'services', 'package.json'), { name: 'p2p-hiveservices', version: '0.16.3' })
  await writeJson(path.join(repo, 'packages', 'client', 'package.json'), { name: 'p2p-hiverelay-client', version: '0.16.3', dependencies: { 'p2p-hiverelay': '^0.16.3' } })
  await writeJson(path.join(repo, 'packages', 'verifier', 'package.json'), { name: 'p2p-hiverelay-verifier', version: '0.16.3', dependencies: { 'p2p-hiverelay': '^0.16.3' } })
  await writeJson(path.join(repo, 'package-lock.json'), {
    name: 'p2p-hiverelay-monorepo',
    version: '0.16.3',
    lockfileVersion: 3,
    packages: {
      '': { version: '0.16.3' },
      'packages/core': { version: '0.16.3' },
      'packages/services': { version: '0.16.3' },
      'packages/client': { version: '0.16.3', dependencies: { 'p2p-hiverelay': '^0.16.3' } },
      'packages/verifier': { version: '0.16.3', dependencies: { 'p2p-hiverelay': '^0.16.3' } }
    }
  })
  await writeText(path.join(repo, 'README.md'), '# HiveRelay\n\n**Status: v0.16.3 packages; main has unreleased upgrades**\n')
  await writeJson(path.join(repo, 'fleet', 'channels.json'), { canary: 'v0.16.3', stable: 'v0.16.3' })
  await writeText(path.join(repo, 'umbrel-app', 'docker-compose.yml'), 'services:\n  app:\n    image: ghcr.io/bigdestiny2/p2p-hiverelay:0.16.3@sha256:' + 'b'.repeat(64) + '\n')
  await writeText(path.join(repo, 'umbrel-app', 'umbrel-app.yml'), 'version: "0.16.3"\nreleaseNotes: "old"\n')
  await writeText(path.join(repo, 'startos', 'manifest.yaml'), 'id: blindspark\nversion: 0.16.3\nrelease-notes: |\n  old\nlicense: apache-2.0\n')
  await writeText(path.join(repo, 'startos', 'Makefile'), 'VERSION ?= $(shell sed -n \'s/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p\' ../package.json | head -n 1)\n')
  await writeText(path.join(repo, 'startos', 'README.md'), 'Status: v0.16.3, one-page dashboard\n')
}

async function writeEcosystemConsumerFixture (root, oldVersion) {
  const sourceTermsByFile = new Map()
  for (const consumer of EXPECTED_CURRENT_CONSUMERS) {
    const packageFile = path.join(root, consumer.path)
    const packageDir = path.dirname(packageFile)
    const lockRoot = consumer.path.includes('/packages/opengit-relay/')
      ? path.join(root, '04-experiments', 'Opengit')
      : packageDir
    const packageEntryKey = path.relative(lockRoot, packageDir).split(path.sep).join('/')
    const oldDeps = Object.fromEntries(Object.keys(consumer.deps).map(dep => [dep, `^${oldVersion}`]))
    await writeJson(packageFile, {
      name: path.basename(packageDir),
      version: '0.0.0',
      dependencies: oldDeps
    })

    const packages = {
      [packageEntryKey === '' ? '' : packageEntryKey]: {
        dependencies: oldDeps
      }
    }
    for (const dep of Object.keys(consumer.deps)) {
      const target = path.resolve(packageDir, consumer.deps[dep].slice('file:'.length))
      const targetKey = path.relative(lockRoot, target).split(path.sep).join('/')
      packages[targetKey] = {
        name: dep,
        version: oldVersion
      }
      if (dep === 'p2p-hiverelay-client') {
        packages[targetKey].dependencies = {
          'p2p-hiverelay': `^${oldVersion}`
        }
      }
    }

    await writeJson(path.join(lockRoot, 'package-lock.json'), {
      name: path.basename(lockRoot),
      version: '0.0.0',
      lockfileVersion: 3,
      requires: true,
      packages
    })

    for (const spec of consumer.sourceChecks || []) {
      const term = typeof spec.termTemplate === 'string'
        ? spec.termTemplate.replaceAll('{version}', oldVersion)
        : spec.term
      if (typeof term === 'string') {
        const terms = sourceTermsByFile.get(spec.file) || []
        terms.push(term)
        sourceTermsByFile.set(spec.file, terms)
      }
    }
  }

  for (const [file, terms] of sourceTermsByFile) {
    await writeText(path.join(root, file), `${terms.join('\n')}\n`)
  }
}

async function writeJson (file, value) {
  await writeText(file, JSON.stringify(value, null, 2) + '\n')
}

async function writeText (file, text) {
  await mkdir(path.dirname(file), { recursive: true })
  await writeFile(file, text)
}
