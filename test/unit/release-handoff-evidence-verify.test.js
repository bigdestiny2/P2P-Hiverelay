import test from 'brittle'
import { execFile } from 'node:child_process'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const TAG_SHA = 'a'.repeat(40)
const IMAGE_DIGEST = 'sha256:' + 'b'.repeat(64)
const IMAGE_AMD64_DIGEST = 'sha256:' + 'a'.repeat(64)
const IMAGE_ARM64_DIGEST = 'sha256:' + 'c'.repeat(64)
const REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const RUN_ID = '12345'
const WORKFLOW_URL = `https://github.com/${REPOSITORY}/actions/runs/${RUN_ID}`
const RELEASE_BASE = `https://github.com/${REPOSITORY}/releases/download/v9.9.9`
const PR_URL = 'https://github.com/getumbrel/umbrel-apps/pull/123'
const REGISTRY_URL = 'https://registry.start9.com/startos'
const REGISTRY_PACKAGE_URL = `${REGISTRY_URL}/blindspark`
const EXPECTED_SMOKE_SERVICE_PLUGINS = ['poker', 'vrf', 'arbitration', 'zk', 'ai']
const VERIFY_RELEASE_HANDOFF_EVIDENCE_SCRIPT = path.join(process.cwd(), 'scripts/verify-release-handoff-evidence.mjs')
const FLEET_INVENTORY_SHA = crypto.createHash('sha256').update(readFileSync('fleet/relays.json')).digest('hex')
const FLEET_CHANNEL_CONFIG_SHA = '3'.repeat(64)
const FLEET_RELAYS = Object.freeze([
  ['utah', 'canary'],
  ['utah-us', 'stable'],
  ['utah-2gb-a', 'stable'],
  ['utah-0.5gb', 'canary'],
  ['utah-8gb', 'stable'],
  ['sing-1', 'stable'],
  ['sing-2', 'stable'],
  ['bern', 'canary'],
  ['dubai', 'stable']
])

function runVerify (argv) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['scripts/verify-release-handoff-evidence.mjs', ...argv], {
      cwd: process.cwd(),
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}

async function writeJson (file, body) {
  await writeFile(file, jsonForHash(body))
}

async function sha256File (file) {
  return crypto.createHash('sha256').update(await readFile(file)).digest('hex')
}

test('release handoff verifier hashes StartOS package artifacts as a stream', async (t) => {
  const script = await readFile(VERIFY_RELEASE_HANDOFF_EVIDENCE_SCRIPT, 'utf8')
  const packageVerifier = script.match(/function verifyStartosRegistryHandoff[\s\S]*?StartOS handoff package hash[\s\S]*?\)/)
  t.ok(packageVerifier, 'StartOS handoff package verifier is present')
  t.ok(script.includes("await sha256LargeFile(packageFile, 'StartOS package')"), 'handoff package verifier uses the streaming helper')
  t.ok(script.includes('fs.createReadStream(file)'), 'handoff package hash check streams the .s9pk')
  t.absent((packageVerifier?.[0] || '').includes('sha256File(packageFile'), 'handoff package verifier does not use the bounded JSON file hash helper')
})

function jsonForHash (body) {
  return JSON.stringify(body, null, 2) + '\n'
}

function sha256Json (body) {
  return crypto.createHash('sha256').update(jsonForHash(body)).digest('hex')
}

async function fixtureDir (t, opts = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-handoff-evidence-'))
  await writeJson(path.join(dir, 'release-image-manifest-evidence.json'), releaseImageManifestEvidence())
  await writeJson(path.join(dir, 'release-image-smoke-evidence.json'), releaseImageSmokeEvidence())
  await writeJson(path.join(dir, 'umbrel-package-smoke-evidence.json'), umbrelSmokeEvidence())
  if (!opts.prerelease) {
    await writeJson(path.join(dir, 'fleet-rollout-evidence.json'), fleetRolloutEvidence())
  }
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

function releaseEvidence (opts = {}) {
  const prerelease = Boolean(opts.prerelease)
  const version = prerelease ? 'v9.9.9-beta.1' : 'v9.9.9'
  const semver = version.slice(1)
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    release: {
      version,
      semver,
      channel: prerelease ? 'none' : 'both',
      prerelease,
      tagSha: TAG_SHA,
      metadataSha: TAG_SHA,
      workflow: {
        status: 'success',
        repository: REPOSITORY,
        runId: RUN_ID,
        runAttempt: '2',
        runUrl: WORKFLOW_URL
      }
    },
    image: {
      name: IMAGE_NAME,
      digest: IMAGE_DIGEST,
      ref: `${IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`
    },
    artifacts: {
      startosPackage: {
        path: 'startos/blindspark.s9pk',
        sha256: opts.startosSha || 'c'.repeat(64)
      }
    },
    gates: {
      auditAndUnit: 'passed',
      distributionPreflight: prerelease ? 'skipped' : 'passed',
      imageManifest: 'passed',
      imageManifestEvidence: {
        path: 'release-image-manifest-evidence.json',
        sha256: opts.imageManifestSha || sha256Json(releaseImageManifestEvidence({ prerelease }))
      },
      pushedImageSmoke: 'passed',
      pushedImageSmokeEvidence: {
        path: 'release-image-smoke-evidence.json',
        sha256: opts.imageSmokeSha || sha256Json(releaseImageSmokeEvidence({ prerelease }))
      },
      umbrelPackageSmoke: 'passed',
      umbrelPackageSmokeEvidence: {
        path: 'umbrel-package-smoke-evidence.json',
        sha256: opts.umbrelSmokeSha || sha256Json(umbrelSmokeEvidence({ prerelease }))
      },
      startosVerify: 'passed'
    },
    surfaces: {
      metadataCommit: prerelease ? 'skipped' : 'committed',
      startosReleaseAsset: 'uploaded',
      fleetRollout: prerelease ? 'skipped' : 'verified',
      fleetRolloutChannel: prerelease ? '' : 'both',
      fleetRolloutEvidence: {
        path: prerelease ? '' : 'fleet-rollout-evidence.json',
        sha256: prerelease ? '' : opts.fleetSha || sha256Json(fleetRolloutEvidence())
      },
      fleetChannelConfig: {
        path: prerelease ? '' : 'fleet/channels.json',
        sha256: prerelease ? '' : FLEET_CHANNEL_CONFIG_SHA
      },
      startosRegistry: prerelease ? 'skipped' : 'published',
      startosRegistryUrl: prerelease ? '' : REGISTRY_URL,
      startosRegistryPackageUrl: prerelease ? '' : REGISTRY_PACKAGE_URL,
      startosPackageId: prerelease ? '' : 'blindspark',
      startosRegistryEvidence: {
        path: prerelease ? '' : 'startos-registry-evidence.json',
        sha256: prerelease ? '' : opts.startosRegistrySha || sha256Json(startosRegistryEvidence(opts.startosSha || 'c'.repeat(64)))
      },
      umbrelOfficial: {
        status: prerelease ? 'skipped' : 'draft-pr-ready',
        prUrl: prerelease ? '' : PR_URL,
        head: prerelease ? '' : 'bigdestiny2:blindspark-v9.9.9',
        headSha: prerelease ? '' : TAG_SHA,
        state: prerelease ? '' : 'OPEN',
        isDraft: prerelease ? null : true,
        base: prerelease ? '' : 'master',
        headOwner: prerelease ? '' : 'bigdestiny2',
        headRef: prerelease ? '' : 'blindspark-v9.9.9',
        headOid: prerelease ? '' : TAG_SHA
      },
      umbrelCommunityStore: {
        validation: prerelease ? 'skipped' : 'passed',
        publish: prerelease ? 'skipped' : 'pushed',
        commit: prerelease ? '' : TAG_SHA,
        commitUrl: prerelease ? '' : `https://github.com/bigdestiny2/blindspark-umbrel-store/commit/${TAG_SHA}`
      }
    }
  }
}

function releaseImageManifestEvidence (opts = {}) {
  const prerelease = Boolean(opts.prerelease)
  const semver = prerelease ? '9.9.9-beta.1' : '9.9.9'
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'release-image-manifest',
    status: 'verified',
    image: {
      name: IMAGE_NAME,
      tag: semver,
      digest: IMAGE_DIGEST,
      ref: `${IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`
    },
    requiredPlatforms: ['linux/amd64', 'linux/arm64'],
    platforms: [
      { os: 'linux', architecture: 'amd64', variant: '', digest: IMAGE_AMD64_DIGEST },
      { os: 'linux', architecture: 'arm64', variant: 'v8', digest: IMAGE_ARM64_DIGEST }
    ],
    manifest: {
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifestCount: 2
    }
  }
}

function fleetRolloutEvidence (opts = {}) {
  const channel = opts.channel || 'both'
  const relays = FLEET_RELAYS
    .filter(([, relayChannel]) => channel === 'both' || relayChannel === channel)
    .map(([name, relayChannel]) => fleetRelay({ name, channel: relayChannel }))
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    status: 'verified',
    target: {
      tag: 'v9.9.9',
      version: '9.9.9',
      sha: TAG_SHA,
      channel
    },
    inventory: {
      path: 'fleet/relays.json',
      sha256: FLEET_INVENTORY_SHA,
      relayNames: relays.map((relay) => relay.name)
    },
    channelConfig: {
      path: 'fleet/channels.json',
      sha256: FLEET_CHANNEL_CONFIG_SHA,
      targets: channel === 'both'
        ? { canary: 'v9.9.9', stable: 'v9.9.9' }
        : { [channel]: 'v9.9.9' }
    },
    probes: {
      timeoutMs: 1800000,
      intervalMs: 30000,
      sshTimeoutMs: 25000,
      service: 'hiverelay',
      api: 'http://127.0.0.1:9100'
    },
    summary: {
      total: relays.length,
      updated: relays.length,
      packageVersionMatches: relays.length,
      healthy: relays.length,
      runtimeVersionMatches: relays.length
    },
    relays
  }
}

function fleetRelay ({ name, channel }) {
  return {
    name,
    channel,
    packageVersion: 'v9.9.9',
    headSha: TAG_SHA,
    targetSha: TAG_SHA,
    healthVersion: '9.9.9',
    observedAt: '2026-06-22T00:00:00.000Z',
    updated: true,
    packageVersionMatches: true,
    healthy: true,
    runtimeVersionMatches: true,
    note: 'ok'
  }
}

function releaseImageSmokeEvidence (opts = {}) {
  const prerelease = Boolean(opts.prerelease)
  const semver = prerelease ? '9.9.9-beta.1' : '9.9.9'
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'release-image-smoke',
    imageRef: `${IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`,
    imageName: IMAGE_NAME,
    imageTag: semver,
    imageDigest: IMAGE_DIGEST,
    checks: [
      { name: 'health', status: 'passed', version: semver },
      { name: 'dashboard', status: 'passed', serviceManager: true, walletControls: true, tokenMeta: true, walletBusyState: true, serviceActionState: true, aiModelAddState: true },
      { name: 'setupWizard', status: 'passed', editMode: true, statusRegion: true, actionLock: true },
      { name: 'dashboardToken', status: 'passed', exposedViaMeta: true },
      { name: 'dashboardWebSocket', status: 'passed', queryTokenRejected: true, inBandAuth: true, updateReceived: true },
      { name: 'usageTelemetry', status: 'passed', bandwidth: { enabled: true, count: 0, bytes: 0, bandwidthBytes: 0 }, poker: { enabled: false, tables: 0, appends: 0, seats: 0 } },
      { name: 'acceptModeDefault', status: 'passed', mode: 'review' },
      { name: 'serviceCatalog', status: 'passed', builtIns: ['poker', 'vrf'], bundles: ['poker'] },
      { name: 'walletWrite', status: 'passed', destinationSaved: true },
      { name: 'servicesSave', status: 'passed', plugins: EXPECTED_SMOKE_SERVICE_PLUGINS, restartRequired: true }
    ]
  }
}

function umbrelSmokeEvidence (opts = {}) {
  const prerelease = Boolean(opts.prerelease)
  const semver = prerelease ? '9.9.9-beta.1' : '9.9.9'
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'umbrel-package-smoke',
    imageRef: `${IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`,
    imageName: IMAGE_NAME,
    imageTag: semver,
    imageDigest: IMAGE_DIGEST,
    composePath: 'umbrel-app/docker-compose.yml',
    checks: [
      { name: 'composeSafety', status: 'passed', composePath: 'umbrel-app/docker-compose.yml' },
      { name: 'firstBoot', status: 'passed', dashboard: true, setup: true, serviceCatalog: true, dashboardUiHardening: true, setupUiHardening: true, acceptMode: 'review', healthVersion: semver },
      { name: 'dashboardWebSocket', status: 'passed', queryTokenRejected: true, inBandAuth: true, updateReceived: true },
      { name: 'acceptModeDefault', status: 'passed', mode: 'review' },
      { name: 'usageTelemetry', status: 'passed', bandwidth: { enabled: true, count: 0, bytes: 0, bandwidthBytes: 0 }, poker: { enabled: false, tables: 0, appends: 0, seats: 0 } },
      { name: 'walletWrite', status: 'passed', destinationSaved: true },
      { name: 'servicesSave', status: 'passed', plugins: EXPECTED_SMOKE_SERVICE_PLUGINS, restartRequired: true },
      { name: 'secondBoot', status: 'passed', dashboard: true, setup: true, serviceCatalog: true, dashboardUiHardening: true, setupUiHardening: true, acceptMode: 'review', healthVersion: semver },
      { name: 'identityPersistence', status: 'passed', publicKeyStable: true },
      { name: 'walletPersistence', status: 'passed', destinationPersisted: true },
      {
        name: 'servicesPersistence',
        status: 'passed',
        selectedServicesActive: true,
        plugins: EXPECTED_SMOKE_SERVICE_PLUGINS,
        active: EXPECTED_SMOKE_SERVICE_PLUGINS
      }
    ]
  }
}

function officialUmbrelPrEvidence (overrides = {}) {
  const body = {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'official-umbrel-pr',
    status: 'updated',
    release: {
      version: 'v9.9.9',
      semver: '9.9.9'
    },
    pr: {
      url: PR_URL,
      number: '123',
      head: 'bigdestiny2:blindspark-v9.9.9',
      headSha: TAG_SHA,
      state: 'OPEN',
      isDraft: true,
      base: 'master',
      headOwner: 'bigdestiny2',
      headRef: 'blindspark-v9.9.9',
      headOid: TAG_SHA
    },
    workflow: {
      repository: REPOSITORY,
      runId: RUN_ID,
      runAttempt: '2',
      runUrl: WORKFLOW_URL
    },
    runtimeReview: {
      status: 'pending-real-device-review',
      evidenceFile: 'umbrel-runtime-review-evidence.json',
      verifier: 'npm run umbrel:verify-runtime-review'
    },
    evidenceLinks: {
      releaseEvidence: `${RELEASE_BASE}/release-evidence.json`,
      releaseImageManifest: `${RELEASE_BASE}/release-image-manifest-evidence.json`,
      releaseImageSmoke: `${RELEASE_BASE}/release-image-smoke-evidence.json`,
      umbrelPackageSmoke: `${RELEASE_BASE}/umbrel-package-smoke-evidence.json`,
      fleetRollout: `${RELEASE_BASE}/fleet-rollout-evidence.json`,
      startosPackage: `${RELEASE_BASE}/blindspark.s9pk`,
      startosRegistryPackage: REGISTRY_PACKAGE_URL,
      startosRegistry: `${RELEASE_BASE}/startos-registry-evidence.json`,
      workflow: WORKFLOW_URL
    }
  }

  return {
    ...body,
    ...overrides,
    release: { ...body.release, ...overrides.release },
    pr: { ...body.pr, ...overrides.pr },
    workflow: { ...body.workflow, ...overrides.workflow },
    runtimeReview: { ...body.runtimeReview, ...overrides.runtimeReview },
    evidenceLinks: { ...body.evidenceLinks, ...overrides.evidenceLinks }
  }
}

function umbrelRuntimeReviewEvidence (overrides = {}) {
  const body = {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'umbrel-runtime-review',
    status: 'passed',
    release: {
      version: 'v9.9.9',
      semver: '9.9.9'
    },
    platform: {
      name: 'umbrel',
      device: 'Umbrel Home test appliance',
      umbrelVersion: '1.3.0'
    },
    review: {
      testedBy: 'bigdestiny2'
    },
    identity: {
      publicKeySha256: 'd'.repeat(64),
      publicKeyBeforeSha256: 'd'.repeat(64),
      publicKeyAfterSha256: 'd'.repeat(64)
    },
    officialUmbrelPr: {
      url: PR_URL
    },
    checks: [
      'installedThroughUmbrel',
      'dashboardProxyLoads',
      'liveFeedInBandAuth',
      'noWebSocketUrlTokens',
      'wizardCompletes',
      'setupActionLockObserved',
      'addWalletPersists',
      'walletBusyStateObserved',
      'managementActionsPersist',
      'serviceActionStateObserved',
      'serviceRestartPendingObserved',
      'aiModelAddStateObserved',
      'reviewModeDefault',
      'dataWritableUid999',
      'reinstallPreservesPublicKey'
    ].map((name) => ({ name, status: 'passed' }))
  }

  return {
    ...body,
    ...overrides,
    release: { ...body.release, ...overrides.release },
    platform: { ...body.platform, ...overrides.platform },
    review: { ...body.review, ...overrides.review },
    identity: { ...body.identity, ...overrides.identity },
    officialUmbrelPr: { ...body.officialUmbrelPr, ...overrides.officialUmbrelPr },
    checks: overrides.checks || body.checks
  }
}

function startosRegistryEvidence (sha, overrides = {}) {
  const body = {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'startos-registry-publication',
    status: 'published',
    release: {
      version: 'v9.9.9',
      semver: '9.9.9'
    },
    package: {
      id: 'blindspark',
      path: 'startos/blindspark.s9pk',
      sha256: sha,
      url: REGISTRY_PACKAGE_URL
    },
    registry: {
      url: REGISTRY_URL
    },
    workflow: {
      repository: REPOSITORY,
      runId: RUN_ID,
      runAttempt: '2',
      runUrl: WORKFLOW_URL
    },
    evidenceLinks: {
      releaseEvidence: `${RELEASE_BASE}/release-evidence.json`,
      releaseImageManifest: `${RELEASE_BASE}/release-image-manifest-evidence.json`,
      releaseImageSmoke: `${RELEASE_BASE}/release-image-smoke-evidence.json`,
      startosPackage: `${RELEASE_BASE}/blindspark.s9pk`,
      registryPackage: REGISTRY_PACKAGE_URL,
      workflow: WORKFLOW_URL
    }
  }

  return {
    ...body,
    ...overrides,
    release: { ...body.release, ...overrides.release },
    package: { ...body.package, ...overrides.package },
    registry: { ...body.registry, ...overrides.registry },
    workflow: { ...body.workflow, ...overrides.workflow },
    evidenceLinks: { ...body.evidenceLinks, ...overrides.evidenceLinks }
  }
}

test('release handoff package scripts expose the review-ready Umbrel gate', (t) => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'))

  t.is(
    pkg.scripts['release:verify-review-ready-handoff'],
    'node scripts/verify-release-handoff-evidence.mjs --require-umbrel-runtime-review'
  )
})

test('release handoff verifier validates a full-release handoff bundle', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  const res = await runVerify(['--bundle-dir', dir])

  t.ok(res.stdout.includes('Release handoff evidence verified: v9.9.9'))
})

test('release handoff verifier rejects unsupported release certificate fields', async (t) => {
  const cases = [
    ['top-level', release => { release.marketplacePublished = true }, 'release evidence has unsupported fields: marketplacePublished'],
    ['release', release => { release.release.marketplaceReady = true }, 'release evidence release has unsupported fields: marketplaceReady'],
    ['gates', release => { release.gates.appStoreReview = 'passed' }, 'release evidence gates has unsupported fields: appStoreReview'],
    ['surfaces', release => { release.surfaces.umbrelRuntimeReview = 'passed' }, 'release evidence surfaces has unsupported fields: umbrelRuntimeReview'],
    ['official Umbrel PR', release => { release.surfaces.umbrelOfficial.reviewReady = true }, 'release evidence official Umbrel PR has unsupported fields: reviewReady']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const startosDir = path.join(dir, 'startos')
    const s9pkFile = path.join(startosDir, 'blindspark.s9pk')

    await mkdir(startosDir)
    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    const release = releaseEvidence({ startosSha: s9pkSha })
    mutate(release)
    await writeJson(path.join(dir, 'release-evidence.json'), release)
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release handoff verifier rejects StartOS registry sidecar hash drift', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    startosRegistrySha: '0'.repeat(64)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry evidence hash'))
})

test('release handoff verifier rejects symlinked evidence sidecars', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')
  const realOfficialFile = path.join(dir, 'real-official-umbrel-pr-evidence.json')
  const officialFile = path.join(dir, 'official-umbrel-pr-evidence.json')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(realOfficialFile, officialUmbrelPrEvidence())
  await symlink(realOfficialFile, officialFile)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff evidence file must not be a symlink'))
})

test('release handoff verifier rejects oversized evidence sidecars before parsing', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')
  const officialFile = path.join(dir, 'official-umbrel-pr-evidence.json')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeFile(officialFile, 'x'.repeat(2 * 1024 * 1024 + 1))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff evidence file must be 2097152 bytes or smaller'))
})

test('release handoff verifier rejects future image-manifest sidecar timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')
  const imageManifest = releaseImageManifestEvidence()
  imageManifest.generatedAt = '2026-06-22T00:00:00.001Z'

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-image-manifest-evidence.json'), imageManifest)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    imageManifestSha: sha256Json(imageManifest)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest generatedAt must not be after release generatedAt'))
})

test('release handoff verifier rejects duplicate image-manifest platform entries', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')
  const imageManifest = releaseImageManifestEvidence()
  imageManifest.platforms.push({
    os: 'linux',
    architecture: 'amd64',
    variant: '',
    digest: 'sha256:' + 'd'.repeat(64)
  })
  imageManifest.manifest.manifestCount = imageManifest.platforms.length

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-image-manifest-evidence.json'), imageManifest)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    imageManifestSha: sha256Json(imageManifest)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest evidence has duplicate platform linux/amd64'))
})

test('release handoff verifier rejects unsupported image-manifest sidecar fields', async (t) => {
  const cases = [
    ['top-level', sidecar => { sidecar.registryPublished = true }, 'release image manifest evidence has unsupported fields: registryPublished'],
    ['image', sidecar => { sidecar.image.repoDigest = sidecar.image.ref }, 'release image manifest image has unsupported fields: repoDigest'],
    ['platform', sidecar => { sidecar.platforms[0].annotations = { reviewer: 'ok' } }, 'release image manifest platform linux/amd64 has unsupported fields: annotations'],
    ['manifest', sidecar => { sidecar.manifest.attestations = 2 }, 'release image manifest manifest has unsupported fields: attestations']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const startosDir = path.join(dir, 'startos')
    const s9pkFile = path.join(startosDir, 'blindspark.s9pk')
    const imageManifest = releaseImageManifestEvidence()
    mutate(imageManifest)

    await mkdir(startosDir)
    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(path.join(dir, 'release-image-manifest-evidence.json'), imageManifest)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      imageManifestSha: sha256Json(imageManifest)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release handoff verifier rejects mismatched StartOS registry package URLs', async (t) => {
  const dir = await fixtureDir(t)
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, {
    package: {
      url: 'https://registry.start9.com/startos/other'
    },
    evidenceLinks: {
      registryPackage: 'https://registry.start9.com/startos/other'
    }
  }))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry handoff package URL') ||
    err.stderr.includes('StartOS handoff package URL'))
})

test('release handoff verifier rejects non-canonical release workflow repository', async (t) => {
  const dir = await fixtureDir(t)
  const release = releaseEvidence()
  release.release.workflow.repository = 'attacker/P2P-Hiverelay'
  release.release.workflow.runUrl = `https://github.com/${release.release.workflow.repository}/actions/runs/${RUN_ID}`
  await writeJson(path.join(dir, 'release-evidence.json'), release)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes(`release workflow repository must be "${REPOSITORY}"`))
})

test('release handoff verifier rejects non-canonical release image names', async (t) => {
  const dir = await fixtureDir(t)
  const release = releaseEvidence()
  release.image.name = 'ghcr.io/attacker/p2p-hiverelay'
  release.image.ref = `${release.image.name}:${release.release.semver}@${IMAGE_DIGEST}`
  await writeJson(path.join(dir, 'release-evidence.json'), release)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes(`image.name must be "${IMAGE_NAME}"`))
})

test('release handoff verifier rejects missing fleet rollout evidence', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await rm(path.join(dir, 'fleet-rollout-evidence.json'), { force: true })
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout evidence file is required'))
})

test('release handoff verifier rejects stale fleet rollout evidence', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const fleet = fleetRolloutEvidence()
  fleet.relays[0].healthy = false

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'fleet-rollout-evidence.json'), fleet)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    fleetSha: await sha256File(path.join(dir, 'fleet-rollout-evidence.json'))
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout relay utah healthy'))
})

test('release handoff verifier rejects unsafe fleet rollout probe timing', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const fleet = fleetRolloutEvidence()
  fleet.probes.timeoutMs = 1

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(fleetFile, fleet)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    fleetSha: await sha256File(fleetFile)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout timeoutMs must be an integer between 600000 and 14400000'))
})

test('release handoff verifier rejects non-loopback fleet rollout probe API URLs', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  for (const api of ['https://relay.example.com:9100', 'http://128.0.0.1:9100']) {
    const fleet = fleetRolloutEvidence()
    fleet.probes.api = api

    await writeJson(fleetFile, fleet)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      fleetSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, api)
    t.ok(err.stderr.includes('fleet rollout API URL must be a loopback http(s) base URL'), api)
  }
})

test('release handoff verifier rejects unsupported fleet rollout sidecar fields', async (t) => {
  const cases = [
    ['top-level', fleet => { fleet.marketplacePublished = true }, 'fleet rollout evidence has unsupported fields: marketplacePublished'],
    ['target', fleet => { fleet.target.reviewReady = true }, 'fleet rollout target has unsupported fields: reviewReady'],
    ['inventory', fleet => { fleet.inventory.hosts = ['10.0.0.1'] }, 'fleet rollout inventory has unsupported fields: hosts'],
    ['channel config', fleet => { fleet.channelConfig.notes = 'ok' }, 'fleet rollout channel config has unsupported fields: notes'],
    ['targets', fleet => { fleet.channelConfig.targets.beta = 'v9.9.9' }, 'fleet rollout channel config targets has unsupported fields: beta'],
    ['probes', fleet => { fleet.probes.gateway = 'https://relay.example.com' }, 'fleet rollout probes has unsupported fields: gateway'],
    ['summary', fleet => { fleet.summary.marketplaceReady = fleet.relays.length }, 'fleet rollout summary has unsupported fields: marketplaceReady'],
    ['relay', fleet => { fleet.relays[0].region = 'utah' }, 'fleet rollout relay utah has unsupported fields: region']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const fleet = fleetRolloutEvidence()

    mutate(fleet)

    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(fleetFile, fleet)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      fleetSha: await sha256File(fleetFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release handoff verifier rejects incomplete fleet package-version convergence proof', async (t) => {
  const cases = [
    {
      label: 'fleet rollout summary packageVersionMatches',
      mutate: (fleet) => { fleet.summary.packageVersionMatches = fleet.relays.length - 1 }
    },
    {
      label: 'fleet rollout relay utah packageVersionMatches',
      mutate: (fleet) => { fleet.relays[0].packageVersionMatches = false }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const fleet = fleetRolloutEvidence()

    mutate(fleet)
    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(fleetFile, fleet)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      fleetSha: await sha256File(fleetFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects fleet inventory proof drift', async (t) => {
  const dir = await fixtureDir(t)
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const fleet = fleetRolloutEvidence()
  fleet.inventory.relayNames = fleet.inventory.relayNames.slice(0, 2)
  await writeJson(fleetFile, fleet)

  const s9pkFile = path.join(dir, 'startos/blindspark.s9pk')
  await mkdir(path.dirname(s9pkFile), { recursive: true })
  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    fleetSha: await sha256File(fleetFile)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout inventory relay names'))
})

test('release handoff verifier rejects fleet channel config proof drift', async (t) => {
  const cases = [
    {
      label: 'fleet rollout channel config path',
      mutate: (fleet) => { fleet.channelConfig.path = 'other-channels.json' }
    },
    {
      label: 'fleet rollout channel config SHA-256',
      mutate: (fleet) => { fleet.channelConfig.sha256 = '4'.repeat(64) }
    },
    {
      label: 'fleet rollout channel stable target',
      mutate: (fleet) => { fleet.channelConfig.targets.stable = 'v9.9.8' }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const fleet = fleetRolloutEvidence()
    mutate(fleet)
    await writeJson(fleetFile, fleet)

    const s9pkFile = path.join(dir, 'startos/blindspark.s9pk')
    await mkdir(path.dirname(s9pkFile), { recursive: true })
    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      fleetSha: await sha256File(fleetFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects stale fleet relay observation timestamps', async (t) => {
  const cases = [
    {
      label: 'fleet rollout relay utah observedAt',
      mutate: (fleet) => { delete fleet.relays[0].observedAt }
    },
    {
      label: 'observedAt must not be after fleet rollout generatedAt',
      mutate: (fleet) => { fleet.relays[0].observedAt = '2026-06-22T00:00:00.001Z' }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const fleet = fleetRolloutEvidence()

    mutate(fleet)
    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(fleetFile, fleet)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      fleetSha: await sha256File(fleetFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects stale Umbrel smoke restart proof', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const umbrelSmoke = umbrelSmokeEvidence()
  umbrelSmoke.checks.find(check => check.name === 'servicesPersistence').active = ['vrf', 'arbitration', 'zk', 'ai']

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'umbrel-package-smoke-evidence.json'), umbrelSmoke)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    umbrelSmokeSha: await sha256File(path.join(dir, 'umbrel-package-smoke-evidence.json'))
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('umbrel-package-smoke servicesPersistence active must be ["poker","vrf","arbitration","zk","ai"]'))
})

test('release handoff verifier rejects duplicate smoke evidence checks', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const umbrelSmoke = umbrelSmokeEvidence()
  umbrelSmoke.checks.push({ ...umbrelSmoke.checks.find(check => check.name === 'walletWrite') })

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(umbrelSmokeFile, umbrelSmoke)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    umbrelSmokeSha: await sha256File(umbrelSmokeFile)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('umbrel-package-smoke evidence has duplicate check walletWrite'))
})

test('release handoff verifier rejects unsupported smoke evidence fields', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  const cases = [
    ['top-level', smoke => { smoke.reviewReady = true }, 'umbrel-package-smoke evidence has unsupported fields: reviewReady'],
    ['check field', smoke => { smoke.checks.find(check => check.name === 'servicesPersistence').note = 'reviewed' }, 'umbrel-package-smoke check servicesPersistence has unsupported fields: note'],
    ['unsupported check', smoke => { smoke.checks.push({ name: 'marketplacePublished', status: 'passed' }) }, 'umbrel-package-smoke evidence has unsupported check marketplacePublished'],
    ['nested telemetry', smoke => { smoke.checks.find(check => check.name === 'usageTelemetry').poker.extraCount = 1 }, 'umbrel-package-smoke usageTelemetry poker has unsupported fields: extraCount']
  ]

  for (const [name, mutate, expected] of cases) {
    const umbrelSmoke = umbrelSmokeEvidence()
    mutate(umbrelSmoke)
    await writeJson(umbrelSmokeFile, umbrelSmoke)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      umbrelSmokeSha: await sha256File(umbrelSmokeFile)
    }))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release handoff verifier rejects stale critical smoke proof details', async (t) => {
  const cases = [
    {
      label: 'release-image-smoke dashboardWebSocket inBandAuth',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'dashboardWebSocket').inBandAuth = false
      }
    },
    {
      label: 'release-image-smoke health version',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'health').version = '9.9.8'
      }
    },
    {
      label: 'release-image-smoke walletWrite destinationSaved',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'walletWrite').destinationSaved = false
      }
    },
    {
      label: 'release-image-smoke dashboard walletBusyState',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'dashboard').walletBusyState = false
      }
    },
    {
      label: 'release-image-smoke setupWizard actionLock',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'setupWizard').actionLock = false
      }
    },
    {
      label: 'release-image-smoke usageTelemetry bandwidth bandwidthBytes',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'usageTelemetry').bandwidth.bandwidthBytes = -1
      }
    },
    {
      label: 'umbrel-package-smoke firstBoot acceptMode',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'firstBoot').acceptMode = 'open'
      }
    },
    {
      label: 'umbrel-package-smoke secondBoot healthVersion',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'secondBoot').healthVersion = '9.9.8'
      }
    },
    {
      label: 'umbrel-package-smoke firstBoot dashboardUiHardening',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'firstBoot').dashboardUiHardening = false
      }
    },
    {
      label: 'umbrel-package-smoke secondBoot setupUiHardening',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'secondBoot').setupUiHardening = false
      }
    },
    {
      label: 'umbrel-package-smoke walletPersistence destinationPersisted',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'walletPersistence').destinationPersisted = false
      }
    },
    {
      label: 'umbrel-package-smoke usageTelemetry poker enabled',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => {
        smoke.checks.find(check => check.name === 'usageTelemetry').poker.enabled = 'no'
      }
    }
  ]

  for (const { label, smokePath, releaseShaKey, mutate } of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const smokeFile = path.join(dir, smokePath)
    const smoke = smokePath === 'release-image-smoke-evidence.json'
      ? releaseImageSmokeEvidence()
      : umbrelSmokeEvidence()
    mutate(smoke)

    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(smokeFile, smoke)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      [releaseShaKey]: await sha256File(smokeFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects smoke image provenance drift', async (t) => {
  const cases = [
    {
      label: 'release-image-smoke imageName',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => { smoke.imageName = 'ghcr.io/bigdestiny2/p2p-hiverelay-stale' }
    },
    {
      label: 'umbrel-package-smoke imageDigest',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => { smoke.imageDigest = 'sha256:' + 'c'.repeat(64) }
    }
  ]

  for (const { label, smokePath, releaseShaKey, mutate } of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const smokeFile = path.join(dir, smokePath)
    const smoke = smokePath === 'release-image-smoke-evidence.json'
      ? releaseImageSmokeEvidence()
      : umbrelSmokeEvidence()
    mutate(smoke)

    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(smokeFile, smoke)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      [releaseShaKey]: await sha256File(smokeFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects stale smoke evidence timestamps', async (t) => {
  const cases = [
    {
      label: 'release-image-smoke generatedAt',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => { delete smoke.generatedAt }
    },
    {
      label: 'release-image-smoke generatedAt must not be before release image manifest generatedAt',
      smokePath: 'release-image-smoke-evidence.json',
      releaseShaKey: 'imageSmokeSha',
      mutate: (smoke) => { smoke.generatedAt = '2026-06-21T23:59:59.999Z' }
    },
    {
      label: 'umbrel-package-smoke generatedAt must not be after release generatedAt',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => { smoke.generatedAt = '2026-06-22T00:00:00.001Z' }
    },
    {
      label: 'umbrel-package-smoke generatedAt must not be before release image manifest generatedAt',
      smokePath: 'umbrel-package-smoke-evidence.json',
      releaseShaKey: 'umbrelSmokeSha',
      mutate: (smoke) => { smoke.generatedAt = '2026-06-21T23:59:59.999Z' }
    }
  ]

  for (const { label, smokePath, releaseShaKey, mutate } of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const smokeFile = path.join(dir, smokePath)
    const smoke = smokePath === 'release-image-smoke-evidence.json'
      ? releaseImageSmokeEvidence()
      : umbrelSmokeEvidence()
    mutate(smoke)

    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(smokeFile, smoke)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
      startosSha: s9pkSha,
      [releaseShaKey]: await sha256File(smokeFile)
    }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release handoff verifier rejects official Umbrel PR URL drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    pr: { url: 'https://github.com/getumbrel/umbrel-apps/pull/456', number: '456' }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR URL'))

  const zeroPrRelease = releaseEvidence({ startosSha: s9pkSha })
  zeroPrRelease.surfaces.umbrelOfficial.prUrl = 'https://github.com/getumbrel/umbrel-apps/pull/0'
  await writeJson(path.join(dir, 'release-evidence.json'), zeroPrRelease)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    pr: { url: 'https://github.com/getumbrel/umbrel-apps/pull/0', number: '0' }
  }))

  let zeroPrErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    zeroPrErr = e
  }

  t.ok(zeroPrErr)
  t.ok(zeroPrErr.stderr.includes('official Umbrel PR URL'))
})

test('release handoff verifier rejects unsupported official Umbrel PR handoff fields', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  const cases = [
    ['top-level', sidecar => { sidecar.reviewReady = true }, 'official Umbrel PR handoff has unsupported fields: reviewReady'],
    ['pr', sidecar => { sidecar.pr.mergeable = true }, 'official Umbrel PR handoff pr has unsupported fields: mergeable'],
    ['runtime review', sidecar => { sidecar.runtimeReview.device = 'Umbrel Home' }, 'official Umbrel PR handoff runtimeReview has unsupported fields: device'],
    ['evidence links', sidecar => { sidecar.evidenceLinks.marketplace = 'https://apps.umbrel.com/blindspark' }, 'official Umbrel PR handoff evidenceLinks has unsupported fields: marketplace']
  ]

  for (const [name, mutate, expected] of cases) {
    const sidecar = officialUmbrelPrEvidence()
    mutate(sidecar)
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), sidecar)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release handoff verifier rejects official Umbrel PR handoff URL number mismatch', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    pr: { url: 'https://github.com/getumbrel/umbrel-apps/pull/456' }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff number matches URL'))
})

test('release handoff verifier rejects official Umbrel PR state drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const official = officialUmbrelPrEvidence()
  official.pr.isDraft = false
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff draft'))
})

test('release handoff verifier rejects official Umbrel release evidence head-ref drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.surfaces.umbrelOfficial.headRef = 'wrong-branch'
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR head ref matches head branch'))
})

test('release handoff verifier rejects official Umbrel PR head owner and OID drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const official = officialUmbrelPrEvidence()
  official.pr.headOwner = 'attacker'
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let ownerErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    ownerErr = e
  }

  t.ok(ownerErr)
  t.ok(ownerErr.stderr.includes('official Umbrel PR handoff head owner'))

  official.pr.headOwner = 'bigdestiny2'
  official.pr.headOid = 'b'.repeat(40)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)

  let oidErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    oidErr = e
  }

  t.ok(oidErr)
  t.ok(oidErr.stderr.includes('official Umbrel PR handoff head OID'))
})

test('release handoff verifier rejects malformed official Umbrel PR GitHub owner names', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  for (const owner of ['bad_owner', 'bad.owner', '-bad', 'getumbrel', 'GetUmbrel']) {
    const release = releaseEvidence({ startosSha: s9pkSha })
    release.surfaces.umbrelOfficial.head = `${owner}:blindspark-v9.9.9`
    release.surfaces.umbrelOfficial.headOwner = owner
    await writeJson(path.join(dir, 'release-evidence.json'), release)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, owner)
    t.ok(err.stderr.includes('official Umbrel PR head owner must be a normal GitHub owner name'), owner)
  }
})

test('release handoff verifier rejects malformed official Umbrel PR GitHub head refs', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  for (const ref of ['bad..ref', '.bad-ref', 'bad/ref.lock']) {
    const release = releaseEvidence({ startosSha: s9pkSha })
    release.surfaces.umbrelOfficial.head = `bigdestiny2:${ref}`
    release.surfaces.umbrelOfficial.headRef = ref
    await writeJson(path.join(dir, 'release-evidence.json'), release)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, ref)
    t.ok(err.stderr.includes('official Umbrel PR head ref must be a normal GitHub branch name'), ref)
  }
})

test('release handoff verifier rejects malformed official Umbrel PR handoff owner names', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  for (const owner of ['bad_owner', 'bad.owner', '-bad', 'getumbrel', 'GetUmbrel']) {
    const official = officialUmbrelPrEvidence()
    official.pr.head = `${owner}:blindspark-v9.9.9`
    official.pr.headOwner = owner
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, owner)
    t.ok(err.stderr.includes('official Umbrel PR handoff head owner must be a normal GitHub owner name'), owner)
  }
})

test('release handoff verifier rejects malformed official Umbrel PR handoff head refs', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  for (const ref of ['bad..ref', '.bad-ref', 'bad/ref.lock']) {
    const official = officialUmbrelPrEvidence()
    official.pr.head = `bigdestiny2:${ref}`
    official.pr.headRef = ref
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, ref)
    t.ok(err.stderr.includes('official Umbrel PR handoff head ref must be a normal GitHub branch name'), ref)
  }
})

test('release handoff verifier rejects StartOS package hash drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const expectedSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: expectedSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(expectedSha))
  await writeFile(s9pkFile, 'tampered-s9pk')

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS handoff package hash'))
})

test('release handoff verifier rejects official Umbrel evidence link drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    evidenceLinks: {
      releaseEvidence: `${RELEASE_BASE}/release-evidence.json`,
      releaseImageManifest: `${RELEASE_BASE}/release-image-manifest-evidence.json`,
      releaseImageSmoke: `${RELEASE_BASE}/release-image-smoke-evidence.json`,
      umbrelPackageSmoke: `${RELEASE_BASE}/umbrel-package-smoke-evidence.json`,
      fleetRollout: `${RELEASE_BASE}/fleet-rollout-evidence.json`,
      startosPackage: `${RELEASE_BASE}/wrong.s9pk`,
      startosRegistry: `${RELEASE_BASE}/startos-registry-evidence.json`,
      workflow: WORKFLOW_URL
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR StartOS package link'))
})

test('release handoff verifier rejects official Umbrel image manifest link drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    evidenceLinks: {
      releaseImageManifest: `${RELEASE_BASE}/wrong-release-image-manifest-evidence.json`
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR image manifest link'))
})

test('release handoff verifier rejects official Umbrel runtime review drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    runtimeReview: {
      status: 'passed'
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR runtime review status'))

  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    runtimeReview: {
      status: 'pending-real-device-review',
      verifier: 'npm run something-else'
    }
  }))

  let verifierErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    verifierErr = e
  }

  t.ok(verifierErr)
  t.ok(verifierErr.stderr.includes('official Umbrel PR runtime review verifier'))
})

test('release handoff verifier validates optional real Umbrel runtime review evidence', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  const res = await runVerify(['--bundle-dir', dir])

  t.ok(res.stdout.includes('Release handoff evidence verified: v9.9.9'))
})

test('release handoff verifier requires real Umbrel runtime review evidence when requested', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let missingErr = null
  try {
    await runVerify(['--bundle-dir', dir, '--require-umbrel-runtime-review'])
  } catch (e) {
    missingErr = e
  }

  t.ok(missingErr)
  t.ok(missingErr.stderr.includes('Umbrel runtime review handoff evidence is required'))

  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence())
  const res = await runVerify(['--bundle-dir', dir, '--require-umbrel-runtime-review'])

  t.ok(res.stdout.includes('Release handoff evidence verified: v9.9.9'))
})

test('release handoff verifier rejects unsupported optional Umbrel runtime review evidence fields', async (t) => {
  const cases = [
    ['top-level', evidence => { evidence.marketplacePublished = true }, 'Umbrel runtime review handoff evidence has unsupported fields: marketplacePublished'],
    ['platform', evidence => { evidence.platform.extraReviewClaim = 'reviewed' }, 'Umbrel runtime review platform has unsupported fields: extraReviewClaim'],
    ['check field', evidence => { evidence.checks.find(check => check.name === 'installedThroughUmbrel').notes = 'reviewed' }, 'Umbrel runtime review check installedThroughUmbrel has unsupported fields: notes']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const s9pkFile = path.join(dir, 'blindspark.s9pk')

    await writeFile(s9pkFile, 'fake-s9pk')
    const s9pkSha = await sha256File(s9pkFile)
    await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
    await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

    const evidence = umbrelRuntimeReviewEvidence()
    mutate(evidence)
    await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), evidence)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release handoff verifier rejects optional Umbrel runtime review evidence drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    officialUmbrelPr: {
      url: 'https://github.com/getumbrel/umbrel-apps/pull/124'
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let prErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    prErr = e
  }

  t.ok(prErr)
  t.ok(prErr.stderr.includes('Umbrel runtime review PR URL'))

  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    release: {
      version: 'v9.9.8',
      semver: '9.9.8'
    }
  }))

  let releaseErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    releaseErr = e
  }

  t.ok(releaseErr)
  t.ok(releaseErr.stderr.includes('Umbrel runtime review release version'))

  const futureRelease = releaseEvidence({ startosSha: s9pkSha })
  futureRelease.generatedAt = '2026-06-22T00:00:00.001Z'
  await writeJson(path.join(dir, 'release-evidence.json'), futureRelease)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    generatedAt: futureRelease.generatedAt
  }))
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence())

  let releaseTimeErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    releaseTimeErr = e
  }

  t.ok(releaseTimeErr)
  t.ok(releaseTimeErr.stderr.includes('Umbrel runtime review generatedAt must not be before release generatedAt'))

  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    generatedAt: '2026-06-22T00:00:00.001Z'
  }))
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence())

  let officialTimeErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    officialTimeErr = e
  }

  t.ok(officialTimeErr)
  t.ok(officialTimeErr.stderr.includes('Umbrel runtime review generatedAt must not be before official Umbrel PR handoff generatedAt'))

  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    generatedAt: new Date(Date.now() + 60 * 60 * 1000).toISOString()
  }))

  let futureTimeErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    futureTimeErr = e
  }

  t.ok(futureTimeErr)
  t.ok(futureTimeErr.stderr.includes('Umbrel runtime review generatedAt must not be in the future'))

  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    identity: {
      publicKeySha256: 'd'.repeat(64),
      publicKeyBeforeSha256: 'd'.repeat(64),
      publicKeyAfterSha256: 'e'.repeat(64)
    }
  }))

  let hashErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    hashErr = e
  }

  t.ok(hashErr)
  t.ok(hashErr.stderr.includes('Umbrel runtime review public key hash after reinstall'))

  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    checks: umbrelRuntimeReviewEvidence().checks.filter(check => check.name !== 'aiModelAddStateObserved')
  }))

  let missingUiCheckErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    missingUiCheckErr = e
  }

  t.ok(missingUiCheckErr)
  t.ok(missingUiCheckErr.stderr.includes('Missing Umbrel runtime review checks: aiModelAddStateObserved'))

  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), umbrelRuntimeReviewEvidence({
    identity: {
      publicKey: 'd'.repeat(64)
    }
  }))

  let rawKeyErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    rawKeyErr = e
  }

  t.ok(rawKeyErr)
  t.ok(rawKeyErr.stderr.includes('must not expose raw public key fields'))
})

test('release handoff verifier requires Umbrel runtime review upstream PR binding', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  const runtimeReview = umbrelRuntimeReviewEvidence()
  delete runtimeReview.officialUmbrelPr
  await writeJson(path.join(dir, 'umbrel-runtime-review-evidence.json'), runtimeReview)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir, '--require-umbrel-runtime-review'])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('Umbrel runtime review officialUmbrelPr must be an object') || err.stderr.includes('Umbrel runtime review PR URL'))
})

test('release handoff verifier rejects official Umbrel registry package link drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    evidenceLinks: {
      startosRegistryPackage: 'https://registry.start9.com/startos/other'
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR StartOS registry package link'))
})

test('release handoff verifier rejects official Umbrel PR head SHA drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    pr: {
      url: PR_URL,
      number: '123',
      head: 'bigdestiny2:blindspark-v9.9.9',
      headSha: 'b'.repeat(40),
      state: 'OPEN',
      isDraft: true,
      base: 'master',
      headOwner: 'bigdestiny2',
      headRef: 'blindspark-v9.9.9',
      headOid: 'b'.repeat(40)
    }
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR head SHA'))
})

test('release handoff verifier rejects official Umbrel workflow attempt drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const official = officialUmbrelPrEvidence()
  official.workflow.runAttempt = '3'
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR workflow run attempt'))
})

test('release handoff verifier rejects stale official Umbrel PR handoff timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.generatedAt = '2026-06-22T00:00:00.001Z'
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, {
    generatedAt: release.generatedAt
  }))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff generatedAt must not be before release generatedAt'))
})

test('release handoff verifier rejects malformed release workflow attempt even when sidecars agree', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  const official = officialUmbrelPrEvidence()
  const startos = startosRegistryEvidence(s9pkSha)
  release.release.workflow.runAttempt = 'not-a-number'
  official.workflow.runAttempt = 'not-a-number'
  startos.workflow.runAttempt = 'not-a-number'
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startos)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release workflow run attempt'))

  const zeroRunId = releaseEvidence({ startosSha: s9pkSha })
  const zeroRunIdOfficial = officialUmbrelPrEvidence()
  const zeroRunIdStartos = startosRegistryEvidence(s9pkSha)
  zeroRunId.release.workflow.runId = '0'
  zeroRunId.release.workflow.runUrl = `https://github.com/${REPOSITORY}/actions/runs/0`
  zeroRunIdOfficial.workflow.runId = '0'
  zeroRunIdOfficial.workflow.runUrl = `https://github.com/${REPOSITORY}/actions/runs/0`
  zeroRunIdStartos.workflow.runId = '0'
  zeroRunIdStartos.workflow.runUrl = `https://github.com/${REPOSITORY}/actions/runs/0`
  await writeJson(path.join(dir, 'release-evidence.json'), zeroRunId)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), zeroRunIdOfficial)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), zeroRunIdStartos)

  let zeroRunIdErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    zeroRunIdErr = e
  }

  t.ok(zeroRunIdErr)
  t.ok(zeroRunIdErr.stderr.includes('release workflow run id'))

  const zeroAttempt = releaseEvidence({ startosSha: s9pkSha })
  const zeroAttemptOfficial = officialUmbrelPrEvidence()
  const zeroAttemptStartos = startosRegistryEvidence(s9pkSha)
  zeroAttempt.release.workflow.runAttempt = '0'
  zeroAttemptOfficial.workflow.runAttempt = '0'
  zeroAttemptStartos.workflow.runAttempt = '0'
  await writeJson(path.join(dir, 'release-evidence.json'), zeroAttempt)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), zeroAttemptOfficial)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), zeroAttemptStartos)

  let zeroAttemptErr = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    zeroAttemptErr = e
  }

  t.ok(zeroAttemptErr)
  t.ok(zeroAttemptErr.stderr.includes('release workflow run attempt'))
})

test('release handoff verifier rejects non-canonical release workflow URL even when sidecars agree', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const badWorkflowUrl = `https://github.com/${REPOSITORY}/actions/runs/99999`
  const release = releaseEvidence({ startosSha: s9pkSha })
  const official = officialUmbrelPrEvidence({
    workflow: {
      repository: REPOSITORY,
      runId: RUN_ID,
      runAttempt: '2',
      runUrl: badWorkflowUrl
    },
    evidenceLinks: {
      releaseEvidence: `${RELEASE_BASE}/release-evidence.json`,
      releaseImageManifest: `${RELEASE_BASE}/release-image-manifest-evidence.json`,
      releaseImageSmoke: `${RELEASE_BASE}/release-image-smoke-evidence.json`,
      umbrelPackageSmoke: `${RELEASE_BASE}/umbrel-package-smoke-evidence.json`,
      fleetRollout: `${RELEASE_BASE}/fleet-rollout-evidence.json`,
      startosPackage: `${RELEASE_BASE}/blindspark.s9pk`,
      startosRegistry: `${RELEASE_BASE}/startos-registry-evidence.json`,
      workflow: badWorkflowUrl
    }
  })
  const startos = startosRegistryEvidence(s9pkSha, {
    workflow: {
      repository: REPOSITORY,
      runId: RUN_ID,
      runAttempt: '2',
      runUrl: badWorkflowUrl
    },
    evidenceLinks: {
      releaseEvidence: `${RELEASE_BASE}/release-evidence.json`,
      startosPackage: `${RELEASE_BASE}/blindspark.s9pk`,
      workflow: badWorkflowUrl
    }
  })
  release.release.workflow.runUrl = badWorkflowUrl
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), official)
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startos)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release workflow canonical URL'))
})

test('release handoff verifier rejects release evidence without metadata SHA', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.release.metadataSha = ''
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release.metadataSha'))
})

test('release handoff verifier rejects StartOS registry workflow attempt drift', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const startos = startosRegistryEvidence(s9pkSha)
  startos.workflow.runAttempt = '3'
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startos)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry workflow run attempt'))
})

test('release handoff verifier rejects future StartOS registry handoff timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, {
    generatedAt: '2026-06-22T00:00:00.001Z'
  }))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry handoff generatedAt must not be after release generatedAt'))
})

test('release handoff verifier rejects malformed StartOS registry handoff package facts', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())

  const cases = [
    ['generatedAt', { generatedAt: '' }, 'StartOS registry handoff generatedAt'],
    ['id', { package: { id: 'Bad_ID' } }, 'StartOS registry handoff package id'],
    ['path', { package: { path: 'wrong.s9pk' } }, 'StartOS registry handoff package path'],
    ['sha', { package: { sha256: 'not-a-sha' } }, 'StartOS registry handoff package SHA-256']
  ]

  for (const [name, overrides, expected] of cases) {
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, overrides))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release handoff verifier rejects unsupported StartOS registry handoff fields', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())

  const cases = [
    ['top-level', sidecar => { sidecar.marketplacePublished = true }, 'StartOS registry handoff has unsupported fields: marketplacePublished'],
    ['package', sidecar => { sidecar.package.extraClaim = 'published' }, 'StartOS registry handoff package has unsupported fields: extraClaim'],
    ['evidence links', sidecar => { sidecar.evidenceLinks.marketplace = `${REGISTRY_URL}/blindspark` }, 'StartOS registry handoff evidenceLinks has unsupported fields: marketplace']
  ]

  for (const [name, mutate, expected] of cases) {
    const sidecar = startosRegistryEvidence(s9pkSha)
    mutate(sidecar)
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), sidecar)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release handoff verifier rejects unsafe StartOS registry handoff URLs', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())

  for (const url of [
    'http://registry.start9.com/startos',
    'https://registry.example/startos',
    'https://user:pass@registry.start9.com/startos'
  ]) {
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, {
      registry: { url }
    }))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, url)
    t.ok(err.stderr.includes('StartOS registry handoff URL'), url)
  }
})

test('release handoff verifier rejects inconsistent StartOS registry handoff links', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())

  const cases = [
    ['workflow URL', { workflow: { runUrl: `https://github.com/${REPOSITORY}/actions/runs/99999` } }, 'StartOS registry handoff workflow URL'],
    ['image manifest link', { evidenceLinks: { releaseImageManifest: `${RELEASE_BASE}/wrong-manifest.json` } }, 'StartOS registry handoff image manifest link'],
    ['image smoke link', { evidenceLinks: { releaseImageSmoke: `${RELEASE_BASE}/wrong-smoke.json` } }, 'StartOS registry handoff image smoke link'],
    ['package link', { evidenceLinks: { startosPackage: `${RELEASE_BASE}/wrong.s9pk` } }, 'StartOS registry handoff package link']
  ]

  for (const [name, overrides, expected] of cases) {
    await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha, overrides))

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release handoff verifier rejects credentialed registry URLs', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.surfaces.startosRegistryUrl = 'https://user:pass@registry.start9.com/startos'
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not expose URL credentials'))
})

test('release handoff verifier rejects placeholder registry hosts', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.surfaces.startosRegistryUrl = 'https://registry.example/startos'
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('reserved/local hostnames') || err.stderr.includes('StartOS registry URL'))
})

test('release handoff verifier rejects secret-looking handoff evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    note: 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456'
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff evidence must not expose'))
  t.ok(err.stderr.includes('authorization header') || err.stderr.includes('GitHub token'))
})

test('release handoff verifier rejects hyphenated API-key handoff evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    note: 'sk-test_key-with-dashes_1234567890'
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff evidence must not expose API key'))
})

test('release handoff verifier rejects control-character handoff evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ startosSha: s9pkSha }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence({
    note: 'line-one\nline-two'
  }))
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR handoff evidence must not contain control characters'))
})

test('release handoff verifier rejects secret-looking release evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const release = releaseEvidence({ startosSha: s9pkSha })
  release.image.name = `${IMAGE_NAME} Authorization: Bearer abcdefghijklmnopqrstuvwxyz`
  await writeJson(path.join(dir, 'release-evidence.json'), release)
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not expose authorization header'))
})

test('release handoff verifier rejects env-style secret smoke sidecar values', async (t) => {
  const dir = await fixtureDir(t)
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  const s9pkSha = await sha256File(s9pkFile)
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks[0].note = 'HIVERELAY_API_KEY=super-secret-key'

  await writeJson(path.join(dir, 'release-image-smoke-evidence.json'), imageSmoke)
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({
    startosSha: s9pkSha,
    imageSmokeSha: sha256Json(imageSmoke)
  }))
  await writeJson(path.join(dir, 'official-umbrel-pr-evidence.json'), officialUmbrelPrEvidence())
  await writeJson(path.join(dir, 'startos-registry-evidence.json'), startosRegistryEvidence(s9pkSha))

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not expose API key'))
})

test('release handoff verifier accepts prerelease bundles without store handoffs', async (t) => {
  const dir = await fixtureDir(t, { prerelease: true })
  await writeJson(path.join(dir, 'release-evidence.json'), releaseEvidence({ prerelease: true }))

  const res = await runVerify(['--bundle-dir', dir])

  t.ok(res.stdout.includes('Release handoff evidence verified: v9.9.9-beta.1'))
})

test('release handoff verifier rejects promoted prerelease bundles', async (t) => {
  const dir = await fixtureDir(t, { prerelease: true })
  const release = releaseEvidence({ prerelease: true })
  release.release.channel = 'canary'
  release.surfaces.fleetRollout = 'verified'
  release.surfaces.fleetRolloutChannel = 'canary'
  release.surfaces.fleetRolloutEvidence = {
    path: 'fleet-rollout-evidence.json',
    sha256: 'f'.repeat(64)
  }
  await writeJson(path.join(dir, 'release-evidence.json'), release)

  let err = null
  try {
    await runVerify(['--bundle-dir', dir])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('prerelease release channel'))
})

test('release handoff verifier rejects malformed prerelease boundary facts', async (t) => {
  const cases = [
    ['non-boolean prerelease flag', release => { release.release.prerelease = 'true' }, 'release.prerelease must be a boolean'],
    ['registry URL', release => { release.surfaces.startosRegistryUrl = REGISTRY_URL }, 'prerelease StartOS registry URL'],
    ['package id', release => { release.surfaces.startosPackageId = 'blindspark' }, 'prerelease StartOS package id'],
    ['registry evidence path', release => { release.surfaces.startosRegistryEvidence.path = 'startos-registry-evidence.json' }, 'prerelease StartOS registry evidence path'],
    ['official PR URL', release => { release.surfaces.umbrelOfficial.prUrl = PR_URL }, 'prerelease official Umbrel PR URL'],
    ['official PR draft', release => { release.surfaces.umbrelOfficial.isDraft = false }, 'prerelease official Umbrel PR draft'],
    ['community commit', release => { release.surfaces.umbrelCommunityStore.commit = TAG_SHA }, 'prerelease Umbrel community commit']
  ]

  for (const [name, mutate, expectedError] of cases) {
    const dir = await fixtureDir(t, { prerelease: true })
    const release = releaseEvidence({ prerelease: true })
    mutate(release)
    await writeJson(path.join(dir, 'release-evidence.json'), release)

    let err = null
    try {
      await runVerify(['--bundle-dir', dir])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expectedError), name)
  }
})
