import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { EXPECTED_CURRENT_CONSUMERS } from '../../scripts/audit-ecosystem-consumers.mjs'

const DIGEST = 'sha256:' + 'a'.repeat(64)

function runPrepare (argv, script = 'scripts/prepare-release.mjs', extraEnv = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...argv], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH || '', ...extraEnv },
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

test('prepare-release local bypass preserves an existing immutable Umbrel pin', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-preserve-pin-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  const composePath = path.join(repo, 'umbrel-app', 'docker-compose.yml')
  const before = await readFile(composePath, 'utf8')
  const immutableRef = before.match(/ghcr\.io\/bigdestiny2\/p2p-hiverelay:[^\s]+/)[0]
  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--channel', 'none',
    '--allow-unpinned-image',
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const after = await readFile(composePath, 'utf8')
  t.ok(after.includes(immutableRef), 'existing immutable Umbrel ref is retained')
  t.ok(res.stdout.includes('is not bound to 9.9.9-beta.1 and is not release-ready'))
  t.absent(after.includes('p2p-hiverelay:9.9.9-beta.1\n'), 'local bypass does not weaken the pin to a tag')
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
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const channels = JSON.parse(await readFile(path.join(repo, 'fleet', 'channels.json'), 'utf8'))
  t.is(channels.canary, 'v9.9.9', 'implicit full release bumps canary')
  t.is(channels.stable, 'v9.9.9', 'implicit full release bumps stable')

  const startosManifest = await readFile(path.join(repo, 'startos', 'manifest.yaml'), 'utf8')
  t.absent(startosManifest.includes('metadata.license'), 'StartOS release-notes block keeps the following key on a new line')
  t.ok(startosManifest.includes('HexOS.\nlicense: apache-2.0'), 'StartOS release-notes block is newline-terminated')
  const startosReadme = await readFile(path.join(repo, 'startos', 'README.md'), 'utf8')
  t.ok(startosReadme.includes('Status: `v9.9.9`, one-page dashboard'), 'backticked StartOS status is parsed and canonicalized')
  const startos04Version = await readFile(path.join(repo, 'startos-0.4', 'startos', 'versions', 'current.ts'), 'utf8')
  const startos04Manifest = await readFile(path.join(repo, 'startos-0.4', 'startos', 'manifest', 'index.ts'), 'utf8')
  t.ok(startos04Version.includes("version: '9.9.9:1'"), 'StartOS 0.4 package version is synchronized')
  t.ok(startos04Manifest.includes("'ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9'"), 'StartOS 0.4 authoring image fallback is synchronized')
  t.ok(startos04Manifest.includes('source: { dockerTag: releaseImageRef }'), 'StartOS 0.4 release image override remains wired')

  const truenasManifest = await readFile(path.join(repo, 'truenas-app', 'app.yaml'), 'utf8')
  const truenasImages = await readFile(path.join(repo, 'truenas-app', 'ix_values.yaml'), 'utf8')
  const truenasReadme = await readFile(path.join(repo, 'truenas-app', 'README.md'), 'utf8')
  t.ok(truenasManifest.includes('app_version: 9.9.9'), 'TrueNAS upstream version is synchronized')
  t.ok(truenasManifest.includes('version: 1.0.1'), 'TrueNAS catalog revision is bumped once')
  t.ok(truenasImages.includes('tag: 9.9.9'), 'TrueNAS image tag is synchronized')
  t.ok(truenasReadme.includes('Upstream HiveRelay release: `9.9.9`'), 'TrueNAS README is synchronized')

  const unraidTemplate = await readFile(path.join(repo, 'unraid-app', 'templates', 'blindspark.xml'), 'utf8')
  t.ok(unraidTemplate.includes(`ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@${DIGEST}`), 'Unraid image digest is synchronized')
  t.ok(unraidTemplate.includes('<Changes>HiveRelay 9.9.9</Changes>'), 'Unraid release metadata is synchronized')

  const zimaCompose = await readFile(path.join(repo, 'zimaos-app', 'Apps', 'Blindspark', 'docker-compose.yml'), 'utf8')
  t.ok(zimaCompose.includes(`ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@${DIGEST}`), 'ZimaOS image digest is synchronized')
  t.ok(zimaCompose.includes('  version: "9.9.9"'), 'ZimaOS upstream version is synchronized')

  const runtipiConfig = JSON.parse(await readFile(path.join(repo, 'runtipi-app', 'apps', 'blindspark', 'config.json'), 'utf8'))
  const runtipiCompose = await readFile(path.join(repo, 'runtipi-app', 'apps', 'blindspark', 'docker-compose.yml'), 'utf8')
  t.is(runtipiConfig.version, '9.9.9', 'Runtipi upstream version is synchronized')
  t.is(runtipiConfig.tipi_version, 2, 'Runtipi package revision is bumped once')
  t.ok(runtipiCompose.includes(`ghcr.io/bigdestiny2/p2p-hiverelay:9.9.9@${DIGEST}`), 'Runtipi image digest is synchronized')

  const hexos = JSON.parse(await readFile(path.join(repo, 'hexos-app', 'blindspark.json'), 'utf8'))
  t.is(hexos.script.version, '1.0.1', 'HexOS curation revision is bumped once')
  t.is(hexos.script.changeLog, 'Sync Blindspark for HiveRelay 9.9.9', 'HexOS upstream version is synchronized')
})

test('prepare-release cannot move fleet channels for an enabled public gateway release', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-gateway-fixture-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)
  await writeJson(path.join(repo, 'fleet', 'public-hive-gateway-release.json'), {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: 'v9.9.9'
  })

  const blocked = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(blocked.status, 1)
  t.ok(blocked.stderr.includes('cannot move fleet channel "both"'))
  t.ok(blocked.stderr.includes('use --channel none'))
  const channels = JSON.parse(await readFile(path.join(repo, 'fleet', 'channels.json'), 'utf8'))
  t.is(channels.canary, 'v0.16.3')
  t.is(channels.stable, 'v0.16.3')
})

test('prepare-release requires sibling ecosystem workspace for stable app-default sync', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-missing-ecosystem-fixture-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  const res = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Cannot sync ecosystem consumer defaults'))
  t.ok(res.stderr.includes('full sibling workspace not found'))
  t.ok(res.stderr.includes('--no-ecosystem-consumers'))
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
    '--no-umbrel-store',
    '--ecosystem-dependency-mode', 'local'
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

test('prepare-release defaults sibling ecosystem consumer checks to npm latest', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-ecosystem-latest-fixture-'))
  t.teardown(async () => {
    await rm(root, { recursive: true, force: true })
  })
  const repo = path.join(root, '00-core', 'hiverelay')
  await writeMinimalReleaseFixture(repo)
  await writeEcosystemConsumerFixture(root, '0.16.3')

  const npmLatest = JSON.stringify({
    'p2p-hiverelay': '9.9.9',
    'p2p-hiverelay-client': '9.9.9',
    'p2p-hiverelay-verifier': '9.9.9',
    'p2p-hiveservices': '9.9.9'
  })
  const res = await runPrepare([
    'v9.9.9',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--check'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'), {
    HIVERELAY_NPM_LATEST_JSON: npmLatest
  })

  t.is(res.status, 1, 'check mode reports app default drift')
  t.ok(res.stderr.includes('Ecosystem consumer default sync failed:'))
  t.ok(res.stderr.includes('ecosystem consumer file(s) need default-version sync'))
  t.ok(res.stderr.includes('expected "latest"'))
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

test('prepare-release syncs the community store for a prerelease with an explicit target', async (t) => {
  // The community Umbrel store must auto-sync on EVERY release, prereleases
  // included, so it never lags the fleet. A prerelease that passes an explicit
  // --umbrel-store target is no longer rejected; it syncs the store (bumps the
  // version and re-pins the image digest) just like a full release.
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-prerelease-store-repo-'))
  const store = await mkdtemp(path.join(tmpdir(), 'hiverelay-prerelease-store-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
    await rm(store, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)
  await writeCommunityStoreFixture(store, '0.16.3')

  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--umbrel-store', store,
    '--image-digest', DIGEST,
    '--no-ecosystem-consumers',
    '--check'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 1, res.stderr)
  t.ok(res.stderr.includes('Release surfaces are out of sync:'))
  t.ok(res.stderr.includes('hiverelay-blindspark/docker-compose.yml'), 'prerelease re-pins the community store compose image')
  t.absent(res.stderr.includes('cannot sync the community Umbrel store'), 'prerelease with explicit store target is no longer rejected')
  t.absent(res.stderr.includes('fleet/channels.json'), 'prerelease still does not bump fleet channels')
})

test('prepare-release syncs a community store that has no package.json', async (t) => {
  // The live blindspark-umbrel-store repo is an Umbrel app repo, not an npm
  // package — it has no root package.json. The sync must not require one
  // (a hard ENOENT killed the v0.25.0-rc.9 release run's metadata sync).
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-store-nopkg-repo-'))
  const store = await mkdtemp(path.join(tmpdir(), 'hiverelay-store-nopkg-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
    await rm(store, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)
  await writeCommunityStoreFixture(store, '0.16.3')
  // Match the live store layout: no package.json, no index.html, and a
  // README without an image-version line.
  await rm(path.join(store, 'package.json'))
  await rm(path.join(store, 'index.html'))
  await writeText(path.join(store, 'README.md'), '# HiveRelay Community App Store for Umbrel\n')

  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--umbrel-store', store,
    '--image-digest', DIGEST,
    '--no-ecosystem-consumers',
    '--check'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 1, res.stderr)
  t.ok(res.stderr.includes('Release surfaces are out of sync:'))
  t.ok(res.stderr.includes('hiverelay-blindspark/docker-compose.yml'), 'compose re-pin still detected without a store package.json')
  t.absent(res.stderr.includes('ENOENT'), 'no crash on the absent store package.json')
})

test('prepare-release skips the community store for an implicit prerelease', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-prerelease-implicit-repo-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  const res = await runPrepare([
    'v9.9.9-beta.1',
    '--image-digest', DIGEST,
    '--no-ecosystem-consumers',
    '--check'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 1, res.stderr)
  t.absent(res.stderr.includes('hiverelay-blindspark'), 'implicit prerelease without --umbrel-store does not sync the community store')
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

test('prepare-release rejects overbroad release promise claims before metadata sync', async (t) => {
  const res = await runPrepare([
    'v0.16.3',
    '--channel', 'none',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--release-notes', 'Ship AI poker custody as the public release story.',
    '--check'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('release notes must stay scoped to Core Availability / Blindspark'))
  t.ok(res.stderr.includes('AI/QVAC/Ollama product claim'))
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
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const readme = await readFile(path.join(repo, 'README.md'), 'utf8')
  t.ok(readme.includes('Status: v9.9.9**'))
  t.absent(readme.includes('packages; main has unreleased upgrades'))
})

test('prepare-release leaves the blind-substrate lane on its own version line', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-blind-fixture-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  // The blind-* workspaces are the isolated replacement track. Their generated
  // v1 artifacts are byte-frozen by blind-protocol-v1-compatibility-floor.test.js,
  // and the blind-client browser artifact manifest embeds the package version —
  // so moving them with the product line rewrites bytes a live guard declares
  // frozen and invalidates the Chromium/cross-host evidence bound to that hash.
  const blind = ['blind-protocol', 'blind-ipc', 'blind-client']
  for (const name of blind) {
    await writeJson(path.join(repo, 'packages', name, 'package.json'), {
      name: `@hiverelay/${name}`,
      version: '1.0.0-rc.1',
      private: true,
      ...(name === 'blind-protocol'
        ? {}
        : { dependencies: { '@hiverelay/blind-protocol': '1.0.0-rc.1' } })
    })
  }

  const res = await runPrepare([
    'v9.9.9',
    '--channel', 'none',
    '--image-digest', DIGEST,
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  for (const name of blind) {
    const pkg = JSON.parse(await readFile(path.join(repo, 'packages', name, 'package.json'), 'utf8'))
    t.is(pkg.version, '1.0.0-rc.1', `${name} kept its own version line`)
    if (name !== 'blind-protocol') {
      t.is(pkg.dependencies['@hiverelay/blind-protocol'], '1.0.0-rc.1', `${name} kept its internal pin`)
    }
  }
  const core = JSON.parse(await readFile(path.join(repo, 'packages', 'core', 'package.json'), 'utf8'))
  t.is(core.version, '9.9.9', 'the product line still moved')
})

test('prepare-release retargets internal product dependencies', async (t) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-internal-deps-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await writeMinimalReleaseFixture(repo)

  // Bumping a workspace version while leaving a dependency on it behind is not a
  // cosmetic mismatch: npm stops matching the workspace, falls through to the
  // public registry, and `npm ci` dies.
  const res = await runPrepare([
    'v9.9.9-rc.1',
    '--channel', 'none',
    '--allow-unpinned-image',
    '--no-umbrel-store',
    '--no-ecosystem-consumers'
  ], path.join(repo, 'scripts', 'prepare-release.mjs'))

  t.is(res.status, 0, res.stderr)
  const client = JSON.parse(await readFile(path.join(repo, 'packages', 'client', 'package.json'), 'utf8'))
  // A caret range cannot resolve a prerelease under node-semver, so a prerelease
  // pins its internal dependencies exactly.
  t.is(client.dependencies['p2p-hiverelay'], '9.9.9-rc.1')
  const lock = await readFile(path.join(repo, 'package-lock.json'), 'utf8')
  t.absent(lock.includes('0.16.3'), 'lockfile carries no stale internal reference')
})

test('prepare-release accepts only bare or paired StartOS status backticks', async (t) => {
  const cases = [
    { name: 'bare', status: 'Status: v0.16.3, one-page dashboard\n', expected: 0 },
    { name: 'opening-only', status: 'Status: `v0.16.3, one-page dashboard\n', expected: 1 },
    { name: 'closing-only', status: 'Status: v0.16.3`, one-page dashboard\n', expected: 1 }
  ]

  for (const fixture of cases) {
    const repo = await mkdtemp(path.join(tmpdir(), `hiverelay-startos-${fixture.name}-`))
    t.teardown(async () => {
      await rm(repo, { recursive: true, force: true })
    })
    await writeMinimalReleaseFixture(repo)
    await writeText(path.join(repo, 'startos', 'README.md'), fixture.status)

    const res = await runPrepare([
      'v9.9.9',
      '--channel', 'none',
      '--image-digest', DIGEST,
      '--no-umbrel-store',
      '--no-ecosystem-consumers'
    ], path.join(repo, 'scripts', 'prepare-release.mjs'))

    t.is(res.status, fixture.expected, `${fixture.name} delimiter shape has the expected status`)
    if (fixture.expected === 0) {
      const readme = await readFile(path.join(repo, 'startos', 'README.md'), 'utf8')
      t.is(readme, 'Status: `v9.9.9`, one-page dashboard\n', 'bare status is canonicalized to paired backticks')
    } else {
      t.ok(res.stderr.includes('Could not find StartOS README status version.'), `${fixture.name} delimiter shape fails closed`)
    }
  }
})

async function writeMinimalReleaseFixture (repo) {
  await writeText(path.join(repo, 'scripts', 'prepare-release.mjs'), await readFile('scripts/prepare-release.mjs', 'utf8'))
  await writeText(path.join(repo, 'scripts', 'lib', 'release-promise-scope.mjs'), await readFile('scripts/lib/release-promise-scope.mjs', 'utf8'))
  await writeText(path.join(repo, 'scripts', 'audit-ecosystem-consumers.mjs'), await readFile('scripts/audit-ecosystem-consumers.mjs', 'utf8'))
  await writeText(path.join(repo, 'scripts', 'check-ecosystem-workspace.mjs'), await readFile('scripts/check-ecosystem-workspace.mjs', 'utf8'))
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
  await writeText(path.join(repo, 'startos', 'README.md'), 'Status: `v0.16.3`, one-page dashboard\n')
  await writeText(path.join(repo, 'startos-0.4', 'startos', 'versions', 'current.ts'), "export const current = { version: '0.16.3:1' }\n")
  await writeText(
    path.join(repo, 'startos-0.4', 'startos', 'manifest', 'index.ts'),
    "const releaseImageRef = process.env.HIVERELAY_STARTOS_04_IMAGE_REF || 'ghcr.io/bigdestiny2/p2p-hiverelay:0.16.3'\nsource: { dockerTag: releaseImageRef }\n"
  )
  await writeText(path.join(repo, 'truenas-app', 'app.yaml'), 'app_version: 0.16.3\nversion: 1.0.0\n')
  await writeText(path.join(repo, 'truenas-app', 'ix_values.yaml'), 'images:\n  image:\n    repository: ghcr.io/bigdestiny2/p2p-hiverelay\n    tag: 0.16.3\n')
  await writeText(path.join(repo, 'truenas-app', 'README.md'), '- Upstream HiveRelay release: `0.16.3`\n')
  await writeText(path.join(repo, 'unraid-app', 'templates', 'blindspark.xml'), '<Repository>ghcr.io/bigdestiny2/p2p-hiverelay:0.16.3</Repository>\n<Changes>HiveRelay 0.16.3</Changes>\n<Date>2026-01-01</Date>\n')
  await writeText(path.join(repo, 'zimaos-app', 'Apps', 'Blindspark', 'docker-compose.yml'), 'services:\n  blindspark:\n    image: ghcr.io/bigdestiny2/p2p-hiverelay:0.16.3\nx-casaos:\n  version: "0.16.3"\n  update_at: "2026-01-01"\n  release_notes:\n    en_US: HiveRelay 0.16.3 package\n')
  await writeJson(path.join(repo, 'runtipi-app', 'apps', 'blindspark', 'config.json'), { id: 'blindspark', version: '0.16.3', tipi_version: 1, updated_at: 1 })
  await writeText(path.join(repo, 'runtipi-app', 'apps', 'blindspark', 'docker-compose.yml'), 'services:\n  blindspark:\n    image: ghcr.io/bigdestiny2/p2p-hiverelay:0.16.3\n')
  await writeJson(path.join(repo, 'hexos-app', 'blindspark.json'), { version: 4, script: { version: '1.0.0', changeLog: 'Sync Blindspark for HiveRelay 0.16.3' } })
}

async function writeCommunityStoreFixture (store, oldVersion) {
  await writeJson(path.join(store, 'package.json'), { id: 'hiverelay-blindspark-store', version: oldVersion })
  await writeText(
    path.join(store, 'hiverelay-blindspark', 'docker-compose.yml'),
    'services:\n  app:\n    image: ghcr.io/bigdestiny2/p2p-hiverelay:' + oldVersion + '@sha256:' + 'c'.repeat(64) + '\n'
  )
  await writeText(
    path.join(store, 'hiverelay-blindspark', 'umbrel-app.yml'),
    'version: "' + oldVersion + '"\nreleaseNotes: >-\n  old\n'
  )
  await writeText(path.join(store, 'README.md'), 'Image: `ghcr.io/bigdestiny2/p2p-hiverelay:' + oldVersion + '`\n')
  await writeText(path.join(store, 'index.html'), '<p>ghcr.io/bigdestiny2/p2p-hiverelay:' + oldVersion + '</p>\n')
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
