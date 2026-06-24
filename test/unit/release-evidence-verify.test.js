import test from 'brittle'
import { execFile } from 'node:child_process'
import crypto from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const TAG_SHA = 'a'.repeat(40)
const IMAGE_DIGEST = 'sha256:' + 'b'.repeat(64)
const IMAGE_AMD64_DIGEST = 'sha256:' + 'a'.repeat(64)
const IMAGE_ARM64_DIGEST = 'sha256:' + 'c'.repeat(64)
const EXPECTED_SMOKE_SERVICE_PLUGINS = ['poker', 'vrf', 'arbitration', 'zk', 'ai']
const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const EXPECTED_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const STARTOS_REGISTRY_URL = 'https://registry.start9.com/startos'
const STARTOS_REGISTRY_PACKAGE_URL = `${STARTOS_REGISTRY_URL}/blindspark`
const FLEET_INVENTORY_SHA = crypto.createHash('sha256').update(readFileSync('fleet/relays.json')).digest('hex')
const FLEET_CHANNEL_CONFIG_SHA = '3'.repeat(64)
const VERIFY_RELEASE_EVIDENCE_SCRIPT = path.join(process.cwd(), 'scripts/verify-release-evidence.mjs')
const FLEET_RELAYS = Object.freeze([
  ['utah', 'canary', '42%'],
  ['utah-us', 'stable', '51%'],
  ['utah-2gb-a', 'stable', '50%'],
  ['utah-0.5gb', 'canary', '49%'],
  ['utah-8gb', 'stable', '48%'],
  ['sing-1', 'stable', '52%'],
  ['sing-2', 'stable', '53%'],
  ['bern', 'canary', '54%'],
  ['dubai', 'stable', '47%']
])

function runVerify (argv) {
  ensureImageManifestSidecar(argv)
  ensureStartosRegistrySidecar(argv)
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['scripts/verify-release-evidence.mjs', ...argv], {
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
  await writeFile(file, JSON.stringify(body, null, 2) + '\n')
}

function writeJsonSync (file, body) {
  writeFileSync(file, JSON.stringify(body, null, 2) + '\n')
}

function sha256Json (body) {
  return crypto.createHash('sha256').update(JSON.stringify(body, null, 2) + '\n').digest('hex')
}

async function sha256File (file) {
  return crypto.createHash('sha256').update(await readFile(file)).digest('hex')
}

test('release evidence verifier hashes StartOS package artifacts as a stream', async (t) => {
  const script = await readFile(VERIFY_RELEASE_EVIDENCE_SCRIPT, 'utf8')
  const packageVerifier = script.match(/if \(opts\.startosPackageFile\) \{[\s\S]*?requireEqual\('StartOS package hash'/)
  t.ok(packageVerifier, 'StartOS package verifier is present')
  t.ok(script.includes("await sha256LargeFile(opts.startosPackageFile, 'StartOS package')"), 'release package verifier uses the streaming helper')
  t.ok(script.includes('fs.createReadStream(file)'), 'release package hash check streams the .s9pk')
  t.absent((packageVerifier?.[0] || '').includes('sha256File(opts.startosPackageFile'), 'release package verifier does not use the bounded JSON file hash helper')
})

function ensureImageManifestSidecar (argv) {
  const releaseFlag = argv.indexOf('--release')
  const bundleFlag = argv.indexOf('--bundle-dir')
  const explicitFlag = argv.indexOf('--release-image-manifest')
  let releaseFile = ''
  if (releaseFlag !== -1) {
    releaseFile = argv[releaseFlag + 1]
  } else if (bundleFlag !== -1) {
    releaseFile = path.join(argv[bundleFlag + 1], 'release-evidence.json')
  }
  if (!releaseFile || explicitFlag !== -1 || !existsSync(releaseFile)) return
  const release = JSON.parse(readFileSync(releaseFile, 'utf8'))
  if (release.release?.workflow?.status !== 'success') return
  const sidecarPath = path.join(path.dirname(releaseFile), release.gates?.imageManifestEvidence?.path || 'release-image-manifest-evidence.json')
  if (existsSync(sidecarPath)) return
  writeJsonSync(sidecarPath, releaseImageManifestEvidence({ release }))
}

function ensureStartosRegistrySidecar (argv) {
  const releaseFlag = argv.indexOf('--release')
  const bundleFlag = argv.indexOf('--bundle-dir')
  const explicitFlag = argv.indexOf('--startos-registry')
  let releaseFile = ''
  if (releaseFlag !== -1) {
    releaseFile = argv[releaseFlag + 1]
  } else if (bundleFlag !== -1) {
    releaseFile = path.join(argv[bundleFlag + 1], 'release-evidence.json')
  }
  if (!releaseFile || explicitFlag !== -1 || !existsSync(releaseFile)) return
  const release = JSON.parse(readFileSync(releaseFile, 'utf8'))
  if (release.release?.prerelease || release.release?.workflow?.status !== 'success') return
  const sidecarPath = path.join(path.dirname(releaseFile), release.surfaces?.startosRegistryEvidence?.path || 'startos-registry-evidence.json')
  if (existsSync(sidecarPath)) return
  writeJsonSync(sidecarPath, startosRegistryEvidence({ release }))
}

function releaseEvidence (opts) {
  const prerelease = Boolean(opts.prerelease)
  const version = prerelease ? 'v9.9.9-beta.1' : 'v9.9.9'
  const semver = version.slice(1)
  let startosRegistryEvidenceSha = ''
  if (!prerelease) {
    startosRegistryEvidenceSha = opts.startosRegistrySha || sha256Json(startosRegistryEvidence({
      release: {
        release: { version, semver, workflow: { repository: EXPECTED_REPOSITORY, runId: '123', runAttempt: '1', runUrl: `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/123` } },
        artifacts: { startosPackage: { path: 'startos/blindspark.s9pk', sha256: opts.startosSha } },
        surfaces: {
          startosPackageId: 'blindspark',
          startosRegistryUrl: STARTOS_REGISTRY_URL,
          startosRegistryPackageUrl: STARTOS_REGISTRY_PACKAGE_URL
        }
      }
    }))
  }

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
        repository: EXPECTED_REPOSITORY,
        runId: '123',
        runAttempt: '1',
        runUrl: `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/123`
      }
    },
    image: {
      name: EXPECTED_IMAGE_NAME,
      digest: IMAGE_DIGEST,
      ref: `${EXPECTED_IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`
    },
    artifacts: {
      startosPackage: {
        path: 'startos/blindspark.s9pk',
        sha256: opts.startosSha
      }
    },
    gates: {
      auditAndUnit: 'passed',
      distributionPreflight: prerelease ? 'skipped' : 'passed',
      imageManifest: 'passed',
      imageManifestEvidence: {
        path: 'release-image-manifest-evidence.json',
        sha256: opts.imageManifestSha || sha256Json(releaseImageManifestEvidence({
          release: {
            release: { semver },
            image: {
              name: EXPECTED_IMAGE_NAME,
              digest: IMAGE_DIGEST,
              ref: `${EXPECTED_IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`
            }
          }
        }))
      },
      pushedImageSmoke: 'passed',
      pushedImageSmokeEvidence: {
        path: 'release-image-smoke-evidence.json',
        sha256: opts.imageSmokeSha
      },
      umbrelPackageSmoke: 'passed',
      umbrelPackageSmokeEvidence: {
        path: 'umbrel-package-smoke-evidence.json',
        sha256: opts.umbrelSmokeSha
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
        sha256: prerelease ? '' : opts.rolloutSha
      },
      fleetChannelConfig: {
        path: prerelease ? '' : 'fleet/channels.json',
        sha256: prerelease ? '' : FLEET_CHANNEL_CONFIG_SHA
      },
      startosRegistry: prerelease ? 'skipped' : 'published',
      startosRegistryUrl: prerelease ? '' : STARTOS_REGISTRY_URL,
      startosRegistryPackageUrl: prerelease ? '' : STARTOS_REGISTRY_PACKAGE_URL,
      startosPackageId: prerelease ? '' : 'blindspark',
      startosRegistryEvidence: {
        path: prerelease ? '' : 'startos-registry-evidence.json',
        sha256: startosRegistryEvidenceSha
      },
      umbrelOfficial: {
        status: prerelease ? 'skipped' : 'draft-pr-ready',
        prUrl: prerelease ? '' : 'https://github.com/getumbrel/umbrel-apps/pull/123',
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

function releaseImageManifestEvidence ({ release }) {
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'release-image-manifest',
    status: 'verified',
    image: {
      name: release.image.name,
      tag: release.release.semver,
      digest: release.image.digest,
      ref: release.image.ref
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

function startosRegistryEvidence ({ release }) {
  const releaseBase = `https://github.com/${release.release.workflow.repository}/releases/download/${release.release.version}`
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'startos-registry-publication',
    status: 'published',
    release: {
      version: release.release.version,
      semver: release.release.semver
    },
    package: {
      id: release.surfaces.startosPackageId,
      path: release.artifacts.startosPackage.path,
      sha256: release.artifacts.startosPackage.sha256,
      url: release.surfaces.startosRegistryPackageUrl
    },
    registry: {
      url: release.surfaces.startosRegistryUrl
    },
    workflow: {
      repository: release.release.workflow.repository,
      runId: release.release.workflow.runId,
      runAttempt: release.release.workflow.runAttempt,
      runUrl: release.release.workflow.runUrl
    },
    evidenceLinks: {
      releaseEvidence: `${releaseBase}/release-evidence.json`,
      releaseImageManifest: `${releaseBase}/release-image-manifest-evidence.json`,
      releaseImageSmoke: `${releaseBase}/release-image-smoke-evidence.json`,
      startosPackage: `${releaseBase}/blindspark.s9pk`,
      registryPackage: release.surfaces.startosRegistryPackageUrl,
      workflow: release.release.workflow.runUrl
    }
  }
}

function releaseImageSmokeEvidence (opts = {}) {
  const prerelease = Boolean(opts.prerelease)
  const semver = prerelease ? '9.9.9-beta.1' : '9.9.9'
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    kind: 'release-image-smoke',
    imageRef: `${EXPECTED_IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`,
    imageName: EXPECTED_IMAGE_NAME,
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
    imageRef: `${EXPECTED_IMAGE_NAME}:${semver}@${IMAGE_DIGEST}`,
    imageName: EXPECTED_IMAGE_NAME,
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

function fleetEvidence (overrides = {}) {
  const relays = FLEET_RELAYS.map(([name, channel, disk]) => fleetRelay(name, channel, disk))
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-22T00:00:00.000Z',
    status: 'verified',
    target: {
      tag: 'v9.9.9',
      version: '9.9.9',
      sha: TAG_SHA,
      channel: 'both'
    },
    inventory: {
      path: 'fleet/relays.json',
      sha256: FLEET_INVENTORY_SHA,
      relayNames: FLEET_RELAYS.map(([name]) => name)
    },
    channelConfig: {
      path: 'fleet/channels.json',
      sha256: FLEET_CHANNEL_CONFIG_SHA,
      targets: {
        canary: 'v9.9.9',
        stable: 'v9.9.9'
      }
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
    relays,
    ...overrides
  }
}

function fleetRelay (name, channel, disk) {
  return {
    name,
    channel,
    packageVersion: 'v9.9.9',
    healthVersion: '9.9.9',
    observedAt: '2026-06-22T00:00:00.000Z',
    headSha: TAG_SHA,
    targetSha: TAG_SHA,
    updated: true,
    packageVersionMatches: true,
    healthy: true,
    runtimeVersionMatches: true,
    disk,
    note: 'ok',
    error: ''
  }
}

async function fixtureDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-verify-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

test('release evidence verifier validates full-release sidecars and hashes', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  const res = await runVerify([
    '--release', releaseFile,
    '--release-image-smoke', releaseImageSmokeFile,
    '--umbrel-package-smoke', umbrelSmokeFile,
    '--fleet-rollout', fleetFile,
    '--startos-package', s9pkFile
  ])

  t.ok(res.stdout.includes('Release evidence verified: v9.9.9'))
})

test('release evidence verifier rejects unsupported release certificate fields', async (t) => {
  const cases = [
    ['top-level', release => { release.marketplacePublished = true }, 'release evidence has unsupported fields: marketplacePublished'],
    ['release', release => { release.release.marketplaceReady = true }, 'release evidence release has unsupported fields: marketplaceReady'],
    ['gates', release => { release.gates.appStoreReview = 'passed' }, 'release evidence gates has unsupported fields: appStoreReview'],
    ['surfaces', release => { release.surfaces.umbrelRuntimeReview = 'passed' }, 'release evidence surfaces has unsupported fields: umbrelRuntimeReview'],
    ['official Umbrel PR', release => { release.surfaces.umbrelOfficial.reviewReady = true }, 'release evidence official Umbrel PR has unsupported fields: reviewReady']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
    await writeJson(fleetFile, fleetEvidence())
    const release = releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    })
    mutate(release)
    await writeJson(releaseFile, release)

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

test('release evidence verifier auto-discovers a downloaded release bundle directory', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosDir = path.join(dir, 'startos')
  const s9pkFile = path.join(startosDir, 'blindspark.s9pk')

  await mkdir(startosDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  const res = await runVerify(['--bundle-dir', dir])

  t.ok(res.stdout.includes('Release evidence verified: v9.9.9'))
})

test('release evidence verifier rejects symlinked evidence sidecars', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const realSmokeFile = path.join(dir, 'real-release-image-smoke-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(realSmokeFile, releaseImageSmokeEvidence())
  await symlink(realSmokeFile, releaseImageSmokeFile)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(realSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const sidecar = startosRegistryEvidence({ release })
  release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
  await writeJson(startosRegistryFile, sidecar)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-registry', startosRegistryFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release-image-smoke evidence file must not be a symlink'))
})

test('release evidence verifier rejects oversized evidence sidecars before hashing', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeFile(releaseImageSmokeFile, 'x'.repeat(2 * 1024 * 1024 + 1))
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: '0'.repeat(64),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const sidecar = startosRegistryEvidence({ release })
  release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
  await writeJson(startosRegistryFile, sidecar)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-registry', startosRegistryFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release-image-smoke evidence file must be 2097152 bytes or smaller'))
})

test('release evidence verifier rejects mismatched fleet sidecar hash', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: 'd'.repeat(64)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout evidence hash'))
})

test('release evidence verifier rejects unsafe fleet rollout probe timing', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const fleet = fleetEvidence()
  fleet.probes.timeoutMs = 1

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleet)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout timeoutMs must be an integer between 600000 and 14400000'))
})

test('release evidence verifier rejects non-loopback fleet rollout probe API URLs', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())

  for (const api of ['https://relay.example.com:9100', 'http://128.0.0.1:9100']) {
    const fleet = fleetEvidence()
    fleet.probes.api = api

    await writeJson(fleetFile, fleet)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, api)
    t.ok(err.stderr.includes('fleet rollout API URL must be a loopback http(s) base URL'), api)
  }
})

test('release evidence verifier rejects unsupported fleet rollout sidecar fields', async (t) => {
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
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const fleet = fleetEvidence()

    mutate(fleet)

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
    await writeJson(fleetFile, fleet)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release evidence verifier rejects credentialed registry URLs', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const release = releaseEvidence({})
  release.surfaces.startosRegistryUrl = 'https://user:pass@registry.start9.com/startos'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  release.artifacts.startosPackage.sha256 = await sha256File(s9pkFile)
  release.gates.pushedImageSmokeEvidence.sha256 = await sha256File(releaseImageSmokeFile)
  release.gates.umbrelPackageSmokeEvidence.sha256 = await sha256File(umbrelSmokeFile)
  release.surfaces.fleetRolloutEvidence.sha256 = await sha256File(fleetFile)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('URL credentials') || err.stderr.includes('without embedded credentials'))
})

test('release evidence verifier rejects placeholder registry hosts', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const release = releaseEvidence({})
  release.surfaces.startosRegistryUrl = 'https://registry.example/startos'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  release.artifacts.startosPackage.sha256 = await sha256File(s9pkFile)
  release.gates.pushedImageSmokeEvidence.sha256 = await sha256File(releaseImageSmokeFile)
  release.gates.umbrelPackageSmokeEvidence.sha256 = await sha256File(umbrelSmokeFile)
  release.surfaces.fleetRolloutEvidence.sha256 = await sha256File(fleetFile)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('reserved/local hostnames'))
})

test('release evidence verifier rejects mismatched registry package URLs', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const release = releaseEvidence({})
  release.surfaces.startosRegistryPackageUrl = 'https://registry.start9.com/startos/other'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  release.artifacts.startosPackage.sha256 = await sha256File(s9pkFile)
  release.gates.pushedImageSmokeEvidence.sha256 = await sha256File(releaseImageSmokeFile)
  release.gates.umbrelPackageSmokeEvidence.sha256 = await sha256File(umbrelSmokeFile)
  release.surfaces.fleetRolloutEvidence.sha256 = await sha256File(fleetFile)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry package URL'))
})

test('release evidence verifier rejects StartOS registry sidecar hash drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile),
    startosRegistrySha: '0'.repeat(64)
  })
  await writeJson(startosRegistryFile, startosRegistryEvidence({ release }))
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-registry', startosRegistryFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry evidence hash'))
})

test('release evidence verifier honors explicit StartOS registry sidecar paths', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const sidecarDir = path.join(dir, 'sidecars')
  const startosRegistryFile = path.join(sidecarDir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await mkdir(sidecarDir)
  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const sidecar = startosRegistryEvidence({ release })
  release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
  await writeJson(startosRegistryFile, sidecar)
  await writeJson(releaseFile, release)

  const res = await runVerify([
    '--release', releaseFile,
    '--release-image-smoke', releaseImageSmokeFile,
    '--umbrel-package-smoke', umbrelSmokeFile,
    '--fleet-rollout', fleetFile,
    '--startos-registry', startosRegistryFile,
    '--startos-package', s9pkFile
  ])

  t.ok(res.stdout.includes('Release evidence verified: v9.9.9'))
})

test('release evidence verifier rejects unsupported StartOS registry sidecar fields', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())

  const cases = [
    ['top-level', sidecar => { sidecar.marketplacePublished = true }, 'StartOS registry evidence has unsupported fields: marketplacePublished'],
    ['package', sidecar => { sidecar.package.extraClaim = 'published' }, 'StartOS registry evidence package has unsupported fields: extraClaim'],
    ['evidence links', sidecar => { sidecar.evidenceLinks.marketplace = `${STARTOS_REGISTRY_URL}/blindspark` }, 'StartOS registry evidence evidenceLinks has unsupported fields: marketplace']
  ]

  for (const [name, mutate, expected] of cases) {
    const release = releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    })
    const sidecar = startosRegistryEvidence({ release })
    mutate(sidecar)
    release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
    await writeJson(startosRegistryFile, sidecar)
    await writeJson(releaseFile, release)

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-registry', startosRegistryFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release evidence verifier rejects StartOS registry sidecar package drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const sidecar = startosRegistryEvidence({ release })
  sidecar.package.url = `${STARTOS_REGISTRY_URL}/other`
  release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
  await writeJson(startosRegistryFile, sidecar)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-registry', startosRegistryFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry evidence package URL'))
})

test('release evidence verifier rejects StartOS registry sidecar image evidence link drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const cases = [
    ['manifest', { releaseImageManifest: `https://github.com/${EXPECTED_REPOSITORY}/releases/download/v9.9.9/wrong-manifest.json` }, 'StartOS registry evidence image manifest link'],
    ['smoke', { releaseImageSmoke: `https://github.com/${EXPECTED_REPOSITORY}/releases/download/v9.9.9/wrong-smoke.json` }, 'StartOS registry evidence image smoke link']
  ]

  for (const [name, links, expected] of cases) {
    const sidecar = startosRegistryEvidence({ release })
    Object.assign(sidecar.evidenceLinks, links)
    release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
    await writeJson(startosRegistryFile, sidecar)
    await writeJson(releaseFile, release)

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-registry', startosRegistryFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release evidence verifier rejects future image-manifest sidecar timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageManifestFile = path.join(dir, 'release-image-manifest-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  const imageManifest = releaseImageManifestEvidence({
    release: {
      release: { semver: '9.9.9' },
      image: {
        name: EXPECTED_IMAGE_NAME,
        digest: IMAGE_DIGEST,
        ref: `${EXPECTED_IMAGE_NAME}:9.9.9@${IMAGE_DIGEST}`
      }
    }
  })
  imageManifest.generatedAt = '2026-06-22T00:00:00.001Z'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageManifestFile, imageManifest)
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageManifestSha: sha256Json(imageManifest),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-manifest', releaseImageManifestFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest generatedAt must not be after release generatedAt'))
})

test('release evidence verifier rejects duplicate image-manifest platform entries', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageManifestFile = path.join(dir, 'release-image-manifest-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  const imageManifest = releaseImageManifestEvidence({
    release: {
      release: { semver: '9.9.9' },
      image: {
        name: EXPECTED_IMAGE_NAME,
        digest: IMAGE_DIGEST,
        ref: `${EXPECTED_IMAGE_NAME}:9.9.9@${IMAGE_DIGEST}`
      }
    }
  })
  imageManifest.platforms.push({
    os: 'linux',
    architecture: 'amd64',
    variant: '',
    digest: 'sha256:' + 'd'.repeat(64)
  })
  imageManifest.manifest.manifestCount = imageManifest.platforms.length

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageManifestFile, imageManifest)
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageManifestSha: sha256Json(imageManifest),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-manifest', releaseImageManifestFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image manifest evidence has duplicate platform linux/amd64'))
})

test('release evidence verifier rejects unsupported image-manifest sidecar fields', async (t) => {
  const cases = [
    ['top-level', sidecar => { sidecar.registryPublished = true }, 'release image manifest evidence has unsupported fields: registryPublished'],
    ['image', sidecar => { sidecar.image.repoDigest = sidecar.image.ref }, 'release image manifest image has unsupported fields: repoDigest'],
    ['platform', sidecar => { sidecar.platforms[0].annotations = { reviewer: 'ok' } }, 'release image manifest platform linux/amd64 has unsupported fields: annotations'],
    ['manifest', sidecar => { sidecar.manifest.attestations = 2 }, 'release image manifest manifest has unsupported fields: attestations']
  ]

  for (const [name, mutate, message] of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageManifestFile = path.join(dir, 'release-image-manifest-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const imageManifest = releaseImageManifestEvidence({
      release: {
        release: { semver: '9.9.9' },
        image: {
          name: EXPECTED_IMAGE_NAME,
          digest: IMAGE_DIGEST,
          ref: `${EXPECTED_IMAGE_NAME}:9.9.9@${IMAGE_DIGEST}`
        }
      }
    })
    mutate(imageManifest)

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageManifestFile, imageManifest)
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
    await writeJson(fleetFile, fleetEvidence())
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageManifestSha: sha256Json(imageManifest),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-manifest', releaseImageManifestFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(message), name)
  }
})

test('release evidence verifier rejects future StartOS registry sidecar timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const startosRegistryFile = path.join(dir, 'startos-registry-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  const sidecar = startosRegistryEvidence({ release })
  sidecar.generatedAt = '2026-06-22T00:00:00.001Z'
  release.surfaces.startosRegistryEvidence.sha256 = sha256Json(sidecar)
  await writeJson(startosRegistryFile, sidecar)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-registry', startosRegistryFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS registry evidence generatedAt must not be after release generatedAt'))
})

test('release evidence verifier rejects stale official Umbrel PR state facts', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const baseRelease = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  baseRelease.image.name = 'ghcr.io/attacker/p2p-hiverelay'
  baseRelease.image.ref = `ghcr.io/attacker/p2p-hiverelay:9.9.9@${IMAGE_DIGEST}`
  await writeJson(releaseFile, baseRelease)

  let imageErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    imageErr = e
  }

  t.ok(imageErr)
  t.ok(imageErr.stderr.includes(`image.name must be "${EXPECTED_IMAGE_NAME}"`))
  await rm(path.join(dir, 'release-image-manifest-evidence.json'), { force: true })

  const zeroPrRelease = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  zeroPrRelease.surfaces.umbrelOfficial.prUrl = 'https://github.com/getumbrel/umbrel-apps/pull/0'
  await writeJson(releaseFile, zeroPrRelease)

  let zeroPrErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    zeroPrErr = e
  }

  t.ok(zeroPrErr)
  t.ok(zeroPrErr.stderr.includes('official Umbrel PR URL'))

  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.surfaces.umbrelOfficial.isDraft = false
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('official Umbrel PR draft'))
})

test('release evidence verifier rejects official Umbrel PR head owner and OID drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const wrongRepoRelease = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  wrongRepoRelease.release.workflow.repository = 'attacker/P2P-Hiverelay'
  wrongRepoRelease.release.workflow.runUrl = 'https://github.com/attacker/P2P-Hiverelay/actions/runs/123'
  await writeJson(releaseFile, wrongRepoRelease)

  let repoErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    repoErr = e
  }

  t.ok(repoErr)
  t.ok(repoErr.stderr.includes(`successful release workflow repository must be "${EXPECTED_REPOSITORY}"`))

  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.surfaces.umbrelOfficial.headOwner = 'attacker'
  await writeJson(releaseFile, release)

  let ownerErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    ownerErr = e
  }

  t.ok(ownerErr)
  t.ok(ownerErr.stderr.includes('official Umbrel PR head owner matches head owner'))

  release.surfaces.umbrelOfficial.headOwner = 'bigdestiny2'
  release.surfaces.umbrelOfficial.headOid = 'b'.repeat(40)
  await writeJson(releaseFile, release)

  let oidErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    oidErr = e
  }

  t.ok(oidErr)
  t.ok(oidErr.stderr.includes('official Umbrel PR head OID matches head SHA'))
})

test('release evidence verifier rejects malformed official Umbrel PR GitHub owner names', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())

  for (const owner of ['bad_owner', 'bad.owner', '-bad', 'getumbrel', 'GetUmbrel']) {
    const release = releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    })
    release.surfaces.umbrelOfficial.head = `${owner}:blindspark-v9.9.9`
    release.surfaces.umbrelOfficial.headOwner = owner
    await writeJson(releaseFile, release)

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, owner)
    t.ok(err.stderr.includes('official Umbrel PR head owner must be a normal GitHub owner name'), owner)
  }
})

test('release evidence verifier rejects malformed official Umbrel PR GitHub head refs', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())

  for (const ref of ['bad..ref', '.bad-ref', 'bad/ref.lock']) {
    const release = releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    })
    release.surfaces.umbrelOfficial.head = `bigdestiny2:${ref}`
    release.surfaces.umbrelOfficial.headRef = ref
    await writeJson(releaseFile, release)

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, ref)
    t.ok(err.stderr.includes('official Umbrel PR head ref must be a normal GitHub branch name'), ref)
  }
})

test('release evidence verifier rejects image digest and ref drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.image.digest = 'sha256:' + 'c'.repeat(64)
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('image.ref matches image name, release semver, and digest'))
})

test('release evidence verifier rejects smoke image provenance drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(fleetFile, fleetEvidence())

  const cases = [
    {
      label: 'release-image-smoke imageDigest',
      mutate: (imageSmoke) => { imageSmoke.imageDigest = 'sha256:' + 'c'.repeat(64) }
    },
    {
      label: 'umbrel-package-smoke imageTag',
      mutate: (_imageSmoke, umbrelSmoke) => { umbrelSmoke.imageTag = '9.9.8' }
    }
  ]

  for (const { label, mutate } of cases) {
    const imageSmoke = releaseImageSmokeEvidence()
    const umbrelSmoke = umbrelSmokeEvidence()
    mutate(imageSmoke, umbrelSmoke)
    await writeJson(releaseImageSmokeFile, imageSmoke)
    await writeJson(umbrelSmokeFile, umbrelSmoke)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects stale smoke evidence timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(fleetFile, fleetEvidence())

  const cases = [
    {
      label: 'release-image-smoke generatedAt',
      mutate: (imageSmoke) => { delete imageSmoke.generatedAt }
    },
    {
      label: 'release-image-smoke generatedAt must not be before release image manifest generatedAt',
      mutate: (imageSmoke) => { imageSmoke.generatedAt = '2026-06-21T23:59:59.999Z' }
    },
    {
      label: 'umbrel-package-smoke generatedAt must not be after release generatedAt',
      mutate: (_imageSmoke, umbrelSmoke) => { umbrelSmoke.generatedAt = '2026-06-22T00:00:00.001Z' }
    },
    {
      label: 'umbrel-package-smoke generatedAt must not be before release image manifest generatedAt',
      mutate: (_imageSmoke, umbrelSmoke) => { umbrelSmoke.generatedAt = '2026-06-21T23:59:59.999Z' }
    }
  ]

  for (const { label, mutate } of cases) {
    const imageSmoke = releaseImageSmokeEvidence()
    const umbrelSmoke = umbrelSmokeEvidence()
    mutate(imageSmoke, umbrelSmoke)
    await writeJson(releaseImageSmokeFile, imageSmoke)
    await writeJson(umbrelSmokeFile, umbrelSmoke)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects malformed successful workflow identity', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.release.workflow.runUrl = 'https://github.com/attacker/hiverelay/actions/runs/123'
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('successful release workflow URL'))

  const zeroRunIdRelease = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  zeroRunIdRelease.release.workflow.runId = '0'
  zeroRunIdRelease.release.workflow.runUrl = `https://github.com/${zeroRunIdRelease.release.workflow.repository}/actions/runs/0`
  await writeJson(releaseFile, zeroRunIdRelease)

  let zeroRunIdErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    zeroRunIdErr = e
  }

  t.ok(zeroRunIdErr)
  t.ok(zeroRunIdErr.stderr.includes('successful release workflow run id'))

  const zeroAttemptRelease = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  zeroAttemptRelease.release.workflow.runAttempt = '0'
  await writeJson(releaseFile, zeroAttemptRelease)

  let zeroAttemptErr = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    zeroAttemptErr = e
  }

  t.ok(zeroAttemptErr)
  t.ok(zeroAttemptErr.stderr.includes('successful release workflow run attempt'))
})

test('release evidence verifier rejects successful evidence without metadata SHA', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.release.metadataSha = ''
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release.metadataSha'))
})

test('release evidence verifier rejects StartOS package path drift', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  const release = releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  })
  release.artifacts.startosPackage.path = 'wrong/blindspark.s9pk'
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package path'))
})

test('release evidence verifier rejects failed workflow evidence by default', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const release = releaseEvidence({})
  release.release.workflow.status = 'failure'

  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify(['--release', releaseFile])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release workflow status must be "success"'))
})

test('release evidence verifier accepts failed workflow evidence only as an explicit diagnostic', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const release = releaseEvidence({})
  release.release.workflow.status = 'failure'
  release.image.digest = ''
  release.image.ref = ''
  release.artifacts.startosPackage.sha256 = ''
  release.surfaces.fleetRolloutEvidence = { path: '', sha256: '' }

  await writeJson(releaseFile, release)

  const res = await runVerify(['--release', releaseFile, '--allow-failed-diagnostic'])

  t.ok(res.stdout.includes('Diagnostic release evidence verified: v9.9.9'))
})

test('release evidence verifier rejects unsafe diagnostic fleet evidence sidecars', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const body = fleetEvidence()
  body.relays[0].error = 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456'

  await writeJson(fleetFile, body)
  const release = releaseEvidence({
    rolloutSha: await sha256File(fleetFile)
  })
  release.release.workflow.status = 'failure'
  release.image.digest = ''
  release.image.ref = ''
  release.artifacts.startosPackage.sha256 = ''
  release.surfaces.fleetRolloutEvidence = {
    path: 'fleet-rollout-evidence.json',
    sha256: await sha256File(fleetFile)
  }
  await writeJson(releaseFile, release)

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--fleet-rollout', fleetFile,
      '--allow-failed-diagnostic'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout evidence must not expose authorization header') ||
    err.stderr.includes('fleet rollout evidence must not expose GitHub token'))
})

test('release evidence verifier rejects fleet evidence that exposes host data', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays[0].host = '10.0.0.1'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not expose host'))
})

test('release evidence verifier rejects stale fleet package versions', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays[0].packageVersion = 'v9.9.8'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('package version'))
})

test('release evidence verifier rejects incomplete fleet package-version convergence proof', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())

  const cases = [
    {
      label: 'fleet rollout summary packageVersionMatches',
      mutate: (body) => { body.summary.packageVersionMatches = body.relays.length - 1 }
    },
    {
      label: 'fleet rollout relay utah packageVersionMatches',
      mutate: (body) => { body.relays[0].packageVersionMatches = false }
    }
  ]

  for (const { label, mutate } of cases) {
    const body = fleetEvidence()
    mutate(body)
    await writeJson(fleetFile, body)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects stale fleet relay observation timestamps', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())

  const cases = [
    {
      label: 'fleet rollout relay utah observedAt',
      mutate: (body) => { delete body.relays[0].observedAt }
    },
    {
      label: 'observedAt must not be after fleet rollout generatedAt',
      mutate: (body) => { body.relays[0].observedAt = '2026-06-22T00:00:00.001Z' }
    }
  ]

  for (const { label, mutate } of cases) {
    const body = fleetEvidence()
    mutate(body)
    await writeJson(fleetFile, body)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects incomplete fleet evidence for the authoritative inventory', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays = body.relays.filter((relay) => relay.channel === 'canary')
  body.summary.total = body.relays.length
  body.summary.updated = body.relays.length
  body.summary.packageVersionMatches = body.relays.length
  body.summary.healthy = body.relays.length
  body.summary.runtimeVersionMatches = body.relays.length

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout relay names'))
})

test('release evidence verifier rejects fleet inventory proof drift', async (t) => {
  const cases = [
    {
      label: 'fleet rollout inventory path',
      mutate: (body) => { body.inventory.path = 'other-relays.json' }
    },
    {
      label: 'fleet rollout inventory SHA-256',
      mutate: (body) => { body.inventory.sha256 = 'f'.repeat(64) }
    },
    {
      label: 'fleet rollout inventory relay names',
      mutate: (body) => { body.inventory.relayNames = body.inventory.relayNames.slice(0, 2) }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const body = fleetEvidence()
    mutate(body)

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
    await writeJson(fleetFile, body)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects fleet channel config proof drift', async (t) => {
  const cases = [
    {
      label: 'fleet rollout channel config path',
      mutate: (body) => { body.channelConfig.path = 'other-channels.json' }
    },
    {
      label: 'fleet rollout channel config SHA-256',
      mutate: (body) => { body.channelConfig.sha256 = '4'.repeat(64) }
    },
    {
      label: 'fleet rollout channel canary target',
      mutate: (body) => { body.channelConfig.targets.canary = 'v9.9.8' }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const body = fleetEvidence()
    mutate(body)

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
    await writeJson(fleetFile, body)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects duplicate fleet relay names', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays[1].name = body.relays[0].name

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('duplicate relay name'))
})

test('release evidence verifier rejects secret-looking smoke evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks[0].note = 'Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz123456'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not expose'))
  t.ok(err.stderr.includes('authorization header') || err.stderr.includes('GitHub token'))
})

test('release evidence verifier rejects hyphenated API-key smoke evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks[0].note = 'sk-test_key-with-dashes_1234567890'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not expose API key'))
})

test('release evidence verifier rejects env-style secret smoke evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks[0].note = 'APP_SEED=super-secret-seed'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not expose APP_SEED'))
})

test('release evidence verifier rejects control-character public evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks[0].note = 'line-one\nline-two'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('must not contain control characters'))
})

test('release evidence verifier rejects secret-looking fleet evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays[0].error = 'Bearer ghp_abcdefghijklmnopqrstuvwxyz123456'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout evidence must not expose'))
  t.ok(err.stderr.includes('bearer token') || err.stderr.includes('GitHub token'))
})

test('release evidence verifier rejects env-style secret fleet evidence values', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const body = fleetEvidence()
  body.relays[0].error = 'HIVERELAY_API_KEY=super-secret-key'

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, body)
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout evidence must not expose API key'))
})

test('release evidence verifier accepts successful prereleases without fleet sidecar', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence({ prerelease: true }))
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence({ prerelease: true }))
  await writeJson(releaseFile, releaseEvidence({
    prerelease: true,
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: ''
  }))

  const res = await runVerify([
    '--release', releaseFile,
    '--release-image-smoke', releaseImageSmokeFile,
    '--umbrel-package-smoke', umbrelSmokeFile,
    '--startos-package', s9pkFile
  ])

  t.ok(res.stdout.includes('Release evidence verified: v9.9.9-beta.1'))
})

test('release evidence verifier rejects malformed prerelease boundary facts', async (t) => {
  const cases = [
    ['non-boolean prerelease flag', release => { release.release.prerelease = 'true' }, 'release.prerelease must be a boolean'],
    ['registry URL', release => { release.surfaces.startosRegistryUrl = STARTOS_REGISTRY_URL }, 'prerelease StartOS registry URL'],
    ['package id', release => { release.surfaces.startosPackageId = 'blindspark' }, 'prerelease StartOS package id'],
    ['official PR URL', release => { release.surfaces.umbrelOfficial.prUrl = 'https://github.com/getumbrel/umbrel-apps/pull/123' }, 'prerelease official Umbrel PR URL'],
    ['official PR draft', release => { release.surfaces.umbrelOfficial.isDraft = false }, 'prerelease official Umbrel PR draft'],
    ['community commit', release => { release.surfaces.umbrelCommunityStore.commit = TAG_SHA }, 'prerelease Umbrel community commit']
  ]

  for (const [name, mutate, expectedError] of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, `${name.replaceAll(' ', '-')}.json`)
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence({ prerelease: true }))
    await writeJson(umbrelSmokeFile, umbrelSmokeEvidence({ prerelease: true }))
    const release = releaseEvidence({
      prerelease: true,
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: ''
    })
    mutate(release)
    await writeJson(releaseFile, release)

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expectedError), name)
  }
})

test('release evidence verifier rejects stale service smoke plugin lists', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks.find(check => check.name === 'servicesSave').plugins = ['vrf', 'arbitration', 'zk', 'ai']

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release-image-smoke servicesSave plugins must be ["poker","vrf","arbitration","zk","ai"]'))
})

test('release evidence verifier rejects stale Umbrel restart service proof', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const umbrelSmoke = umbrelSmokeEvidence()
  umbrelSmoke.checks.find(check => check.name === 'servicesPersistence').active = ['vrf', 'arbitration', 'zk', 'ai']

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmoke)
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('umbrel-package-smoke servicesPersistence active must be ["poker","vrf","arbitration","zk","ai"]'))
})

test('release evidence verifier rejects incomplete smoke evidence', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks = imageSmoke.checks.filter(check => check.name !== 'walletWrite')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release-image-smoke evidence is missing required check walletWrite'))
})

test('release evidence verifier rejects duplicate smoke evidence checks', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const imageSmoke = releaseImageSmokeEvidence()
  imageSmoke.checks.push({ ...imageSmoke.checks.find(check => check.name === 'walletWrite') })

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, imageSmoke)
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release-image-smoke evidence has duplicate check walletWrite'))
})

test('release evidence verifier rejects unsupported smoke evidence fields', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(umbrelSmokeFile, umbrelSmokeEvidence())
  await writeJson(fleetFile, fleetEvidence())

  const cases = [
    ['top-level', smoke => { smoke.marketplacePublished = true }, 'release-image-smoke evidence has unsupported fields: marketplacePublished'],
    ['check field', smoke => { smoke.checks.find(check => check.name === 'walletWrite').note = 'reviewed' }, 'release-image-smoke check walletWrite has unsupported fields: note'],
    ['unsupported check', smoke => { smoke.checks.push({ name: 'marketplacePublished', status: 'passed' }) }, 'release-image-smoke evidence has unsupported check marketplacePublished'],
    ['nested telemetry', smoke => { smoke.checks.find(check => check.name === 'usageTelemetry').bandwidth.extraCount = 1 }, 'release-image-smoke usageTelemetry bandwidth has unsupported fields: extraCount']
  ]

  for (const [name, mutate, expected] of cases) {
    const imageSmoke = releaseImageSmokeEvidence()
    mutate(imageSmoke)
    await writeJson(releaseImageSmokeFile, imageSmoke)
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, name)
    t.ok(err.stderr.includes(expected), name)
  }
})

test('release evidence verifier rejects stale critical smoke proof details', async (t) => {
  const cases = [
    {
      label: 'release-image-smoke dashboardWebSocket inBandAuth',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'dashboardWebSocket').inBandAuth = false
      }
    },
    {
      label: 'release-image-smoke health version',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'health').version = '9.9.8'
      }
    },
    {
      label: 'release-image-smoke walletWrite destinationSaved',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'walletWrite').destinationSaved = false
      }
    },
    {
      label: 'release-image-smoke dashboard walletBusyState',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'dashboard').walletBusyState = false
      }
    },
    {
      label: 'release-image-smoke setupWizard actionLock',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'setupWizard').actionLock = false
      }
    },
    {
      label: 'release-image-smoke usageTelemetry bandwidth bandwidthBytes',
      mutate: (imageSmoke) => {
        imageSmoke.checks.find(check => check.name === 'usageTelemetry').bandwidth.bandwidthBytes = -1
      }
    },
    {
      label: 'umbrel-package-smoke firstBoot acceptMode',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'firstBoot').acceptMode = 'open'
      }
    },
    {
      label: 'umbrel-package-smoke secondBoot healthVersion',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'secondBoot').healthVersion = '9.9.8'
      }
    },
    {
      label: 'umbrel-package-smoke firstBoot dashboardUiHardening',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'firstBoot').dashboardUiHardening = false
      }
    },
    {
      label: 'umbrel-package-smoke secondBoot setupUiHardening',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'secondBoot').setupUiHardening = false
      }
    },
    {
      label: 'umbrel-package-smoke walletPersistence destinationPersisted',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'walletPersistence').destinationPersisted = false
      }
    },
    {
      label: 'umbrel-package-smoke usageTelemetry poker enabled',
      mutate: (_imageSmoke, umbrelSmoke) => {
        umbrelSmoke.checks.find(check => check.name === 'usageTelemetry').poker.enabled = 'no'
      }
    }
  ]

  for (const { label, mutate } of cases) {
    const dir = await fixtureDir(t)
    const releaseFile = path.join(dir, 'release-evidence.json')
    const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
    const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
    const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
    const s9pkFile = path.join(dir, 'blindspark.s9pk')
    const imageSmoke = releaseImageSmokeEvidence()
    const umbrelSmoke = umbrelSmokeEvidence()
    mutate(imageSmoke, umbrelSmoke)

    await writeFile(s9pkFile, 'fake-s9pk')
    await writeJson(releaseImageSmokeFile, imageSmoke)
    await writeJson(umbrelSmokeFile, umbrelSmoke)
    await writeJson(fleetFile, fleetEvidence())
    await writeJson(releaseFile, releaseEvidence({
      startosSha: await sha256File(s9pkFile),
      imageSmokeSha: await sha256File(releaseImageSmokeFile),
      umbrelSmokeSha: await sha256File(umbrelSmokeFile),
      rolloutSha: await sha256File(fleetFile)
    }))

    let err = null
    try {
      await runVerify([
        '--release', releaseFile,
        '--release-image-smoke', releaseImageSmokeFile,
        '--umbrel-package-smoke', umbrelSmokeFile,
        '--fleet-rollout', fleetFile,
        '--startos-package', s9pkFile
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, label)
    t.ok(err.stderr.includes(label), label)
  }
})

test('release evidence verifier rejects smoke evidence without dashboard WebSocket proof', async (t) => {
  const dir = await fixtureDir(t)
  const releaseFile = path.join(dir, 'release-evidence.json')
  const releaseImageSmokeFile = path.join(dir, 'release-image-smoke-evidence.json')
  const umbrelSmokeFile = path.join(dir, 'umbrel-package-smoke-evidence.json')
  const fleetFile = path.join(dir, 'fleet-rollout-evidence.json')
  const s9pkFile = path.join(dir, 'blindspark.s9pk')
  const umbrelSmoke = umbrelSmokeEvidence()
  umbrelSmoke.checks = umbrelSmoke.checks.filter(check => check.name !== 'dashboardWebSocket')

  await writeFile(s9pkFile, 'fake-s9pk')
  await writeJson(releaseImageSmokeFile, releaseImageSmokeEvidence())
  await writeJson(umbrelSmokeFile, umbrelSmoke)
  await writeJson(fleetFile, fleetEvidence())
  await writeJson(releaseFile, releaseEvidence({
    startosSha: await sha256File(s9pkFile),
    imageSmokeSha: await sha256File(releaseImageSmokeFile),
    umbrelSmokeSha: await sha256File(umbrelSmokeFile),
    rolloutSha: await sha256File(fleetFile)
  }))

  let err = null
  try {
    await runVerify([
      '--release', releaseFile,
      '--release-image-smoke', releaseImageSmokeFile,
      '--umbrel-package-smoke', umbrelSmokeFile,
      '--fleet-rollout', fleetFile,
      '--startos-package', s9pkFile
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('umbrel-package-smoke evidence is missing required check dashboardWebSocket'))
})
