#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

const usage = `
Usage:
  node scripts/verify-release-handoff-evidence.mjs --release release-evidence.json --release-image-smoke release-image-smoke-evidence.json --umbrel-package-smoke umbrel-package-smoke-evidence.json --official-umbrel-pr official-umbrel-pr-evidence.json --startos-registry startos-registry-evidence.json --startos-package startos/blindspark.s9pk
  node scripts/verify-release-handoff-evidence.mjs --bundle-dir <downloaded-assets-dir>

Options:
  --release <path>              Release evidence JSON to verify against
  --release-image-manifest <path> Release image manifest/platform evidence JSON
  --release-image-smoke <path>  Release image smoke evidence JSON
  --umbrel-package-smoke <path> Umbrel package smoke evidence JSON
  --fleet-rollout <path>        Fleet rollout evidence JSON
  --official-umbrel-pr <path>   Official Umbrel PR handoff evidence JSON
  --umbrel-runtime-review <path> Optional real Umbrel UI runtime review evidence JSON
  --startos-registry <path>     StartOS registry publication evidence JSON
  --startos-package <path>      StartOS .s9pk artifact to hash-check
  --bundle-dir <path>           Directory containing downloaded release assets
  --require-umbrel-runtime-review
                                Require the real Umbrel UI runtime review sidecar
`

const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]

const RELEASE_IMAGE_SMOKE_CHECKS = Object.freeze([
  'health',
  'dashboard',
  'setupWizard',
  'dashboardToken',
  'dashboardWebSocket',
  'usageTelemetry',
  'acceptModeDefault',
  'serviceCatalog',
  'walletWrite',
  'servicesSave'
])

const UMBREL_PACKAGE_SMOKE_CHECKS = Object.freeze([
  'composeSafety',
  'firstBoot',
  'dashboardWebSocket',
  'acceptModeDefault',
  'usageTelemetry',
  'walletWrite',
  'servicesSave',
  'secondBoot',
  'identityPersistence',
  'walletPersistence',
  'servicesPersistence'
])

const UMBREL_RUNTIME_REVIEW_CHECKS = Object.freeze([
  'installedThroughUmbrel',
  'dashboardProxyLoads',
  'liveFeedInBandAuth',
  'noWebSocketUrlTokens',
  'wizardCompletes',
  'setupActionLockObserved',
  'addWalletPersists',
  'dynamicPayoutControlsObserved',
  'walletBusyStateObserved',
  'managementActionsPersist',
  'serviceActionStateObserved',
  'serviceRestartPendingObserved',
  'aiModelAddStateObserved',
  'reviewModeDefault',
  'dataWritableUid999',
  'reinstallPreservesPublicKey'
])

const EXPECTED_SMOKE_SERVICE_PLUGINS = Object.freeze(['poker', 'vrf', 'arbitration', 'zk', 'ai'])
const REQUIRED_IMAGE_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])
const IMAGE_INDEX_MEDIA_TYPES = new Set([
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.index.v1+json'
])
const EXPECTED_RELEASE_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const GITHUB_ACTIONS_RUN_URL_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/[1-9][0-9]*$/
const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/
const LOCAL_ADDRESS_PATTERN = /\b(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.\d{1,3}){2}|[a-z0-9-]+\.local)\b/i
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024
const MAX_GENERATED_AT_FUTURE_SKEW_MS = 5 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MIN_MS = 10 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MAX_MS = 4 * 60 * 60 * 1000
const FLEET_ROLLOUT_INTERVAL_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_INTERVAL_MAX_MS = 5 * 60 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS = 2 * 60 * 1000
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')
const FLEET_RELAYS_PATH = path.join(repoRoot, 'fleet', 'relays.json')

const args = parseArgs(process.argv.slice(2))
const inputs = resolveInputs(args)

if (!inputs.releaseFile || args.help) {
  console.log(usage.trim())
  process.exit(args.help ? 0 : 1)
}

const release = readJson(inputs.releaseFile, 'release evidence')
verifyReleaseBasics(release)
await verifyReleaseHandoffs(release, inputs)

console.log(`Release handoff evidence verified: ${release.release.version}`)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--release') {
      out.release = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--release-image-smoke') {
      out.releaseImageSmoke = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--release-image-manifest') {
      out.releaseImageManifest = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--umbrel-package-smoke') {
      out.umbrelPackageSmoke = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--fleet-rollout') {
      out.fleetRollout = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--official-umbrel-pr') {
      out.officialUmbrelPr = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--umbrel-runtime-review') {
      out.umbrelRuntimeReview = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--startos-registry') {
      out.startosRegistry = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--startos-package') {
      out.startosPackage = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--bundle-dir') {
      out.bundleDir = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--require-umbrel-runtime-review') {
      out.requireUmbrelRuntimeReview = true
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function resolveInputs (args) {
  if (!args.bundleDir) {
    return {
      releaseFile: args.release,
      releaseImageManifestFile: args.releaseImageManifest,
      releaseImageSmokeFile: args.releaseImageSmoke,
      umbrelPackageSmokeFile: args.umbrelPackageSmoke,
      fleetRolloutFile: args.fleetRollout,
      officialUmbrelPrFile: args.officialUmbrelPr,
      umbrelRuntimeReviewFile: args.umbrelRuntimeReview,
      startosRegistryFile: args.startosRegistry,
      startosPackageFile: args.startosPackage,
      requireUmbrelRuntimeReview: Boolean(args.requireUmbrelRuntimeReview)
    }
  }

  const bundleDir = path.resolve(args.bundleDir)
  return {
    releaseFile: args.release || path.join(bundleDir, 'release-evidence.json'),
    releaseImageManifestFile: args.releaseImageManifest || path.join(bundleDir, 'release-image-manifest-evidence.json'),
    releaseImageSmokeFile: args.releaseImageSmoke || path.join(bundleDir, 'release-image-smoke-evidence.json'),
    umbrelPackageSmokeFile: args.umbrelPackageSmoke || path.join(bundleDir, 'umbrel-package-smoke-evidence.json'),
    fleetRolloutFile: args.fleetRollout || path.join(bundleDir, 'fleet-rollout-evidence.json'),
    officialUmbrelPrFile: args.officialUmbrelPr || path.join(bundleDir, 'official-umbrel-pr-evidence.json'),
    umbrelRuntimeReviewFile: args.umbrelRuntimeReview || firstExisting([
      path.join(bundleDir, 'umbrel-runtime-review-evidence.json')
    ]),
    startosRegistryFile: args.startosRegistry || path.join(bundleDir, 'startos-registry-evidence.json'),
    startosPackageFile: args.startosPackage || firstExisting([
      path.join(bundleDir, 'startos', 'blindspark.s9pk'),
      path.join(bundleDir, 'blindspark.s9pk')
    ]) || path.join(bundleDir, 'startos', 'blindspark.s9pk'),
    requireUmbrelRuntimeReview: Boolean(args.requireUmbrelRuntimeReview)
  }
}

function firstExisting (files) {
  for (const file of files) {
    if (fs.existsSync(file)) return file
  }
  return ''
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function verifyReleaseBasics (body) {
  assertPublicSafe(body, 'release evidence')
  assertReleaseEvidenceSchema(body)
  requireEqual('release evidence schemaVersion', body.schemaVersion, 1)
  requireIsoTimestamp('release generatedAt', body.generatedAt)
  requirePattern('release.version', body.release?.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release.semver', body.release?.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  requireBoolean('release.prerelease', body.release?.prerelease)
  if (body.release?.candidate != null) {
    requireBoolean('release.candidate', body.release.candidate)
  }
  if (body.release?.candidate === true && body.release.prerelease !== true) {
    die('release.candidate requires release.prerelease=true')
  }
  requirePattern('release.tagSha', body.release?.tagSha, /^[a-f0-9]{40}$/i)
  validatePublicGatewayBinding(body)
  requirePattern('release.metadataSha', body.release?.metadataSha, /^[a-f0-9]{40}$/i)
  requireEqual('release workflow status', body.release.workflow?.status, 'success')
  requirePattern('release workflow repository', body.release.workflow?.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requireEqual('release workflow repository', body.release.workflow.repository, EXPECTED_RELEASE_REPOSITORY)
  requirePattern('release workflow run id', body.release.workflow?.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('release workflow run attempt', body.release.workflow?.runAttempt, POSITIVE_INTEGER_PATTERN)
  requirePattern('release workflow URL', body.release.workflow?.runUrl, GITHUB_ACTIONS_RUN_URL_PATTERN)
  requireEqual(
    'release workflow canonical URL',
    body.release.workflow.runUrl,
    `https://github.com/${body.release.workflow.repository}/actions/runs/${body.release.workflow.runId}`
  )
  requirePattern('image.name', body.image?.name, /^ghcr\.io\/[A-Za-z0-9_.-]+\/[A-Za-z0-9._/-]+$/)
  requireEqual('image.name', body.image.name, EXPECTED_RELEASE_IMAGE_NAME)
  requirePattern('image.digest', body.image?.digest, /^sha256:[a-f0-9]{64}$/i)
  requireEqual('image.ref matches image name, release semver, and digest', body.image?.ref, expectedImageRef(body))
}

function assertReleaseEvidenceSchema (body) {
  requireOnlyKeys('release evidence', body, [
    'schemaVersion',
    'generatedAt',
    'release',
    'image',
    'artifacts',
    'gates',
    'surfaces'
  ])
  requireOnlyKeys('release evidence release', body.release, [
    'version',
    'semver',
    'channel',
    'prerelease',
    'candidate',
    'tagSha',
    'metadataSha',
    'publicGateway',
    'workflow'
  ])
  if (body.release.publicGateway != null) {
    requireOnlyKeys('release evidence public gateway binding', body.release.publicGateway, [
      'enabled',
      'manifestStatus',
      'manifestPath',
      'manifestSha256',
      'releaseTarget',
      'commitSha',
      'admissionProfile',
      'cohortSize'
    ])
  }
  requireOnlyKeys('release evidence workflow', body.release.workflow, [
    'status',
    'repository',
    'runId',
    'runAttempt',
    'runUrl'
  ])
  requireOnlyKeys('release evidence image', body.image, ['name', 'digest', 'ref'])
  requireOnlyKeys('release evidence artifacts', body.artifacts, ['startosPackage'])
  requireOnlyKeys('release evidence StartOS package artifact', body.artifacts.startosPackage, ['path', 'sha256'])
  requireOnlyKeys('release evidence gates', body.gates, [
    'auditAndUnit',
    'distributionPreflight',
    'imageManifest',
    'imageManifestEvidence',
    'pushedImageSmoke',
    'pushedImageSmokeEvidence',
    'umbrelPackageSmoke',
    'umbrelPackageSmokeEvidence',
    'startosVerify'
  ])
  requireOnlyKeys('release evidence image manifest ref', body.gates.imageManifestEvidence, ['path', 'sha256'])
  requireOnlyKeys('release evidence image smoke ref', body.gates.pushedImageSmokeEvidence, ['path', 'sha256'])
  requireOnlyKeys('release evidence Umbrel smoke ref', body.gates.umbrelPackageSmokeEvidence, ['path', 'sha256'])
  requireOnlyKeys('release evidence surfaces', body.surfaces, [
    'metadataCommit',
    'npmPackages',
    'startosReleaseAsset',
    'fleetRollout',
    'fleetRolloutChannel',
    'fleetRolloutEvidence',
    'fleetChannelConfig',
    'startosRegistry',
    'startosRegistryUrl',
    'startosRegistryPackageUrl',
    'startosPackageId',
    'startosRegistryEvidence',
    'umbrelOfficial',
    'umbrelCommunityStore'
  ])
  requireOnlyKeys('release evidence fleet rollout ref', body.surfaces.fleetRolloutEvidence, ['path', 'sha256'])
  requireOnlyKeys('release evidence fleet channel config ref', body.surfaces.fleetChannelConfig, ['path', 'sha256'])
  requireOnlyKeys('release evidence StartOS registry ref', body.surfaces.startosRegistryEvidence, ['path', 'sha256'])
  requireOnlyKeys('release evidence official Umbrel PR', body.surfaces.umbrelOfficial, [
    'status',
    'prUrl',
    'head',
    'headSha',
    'state',
    'isDraft',
    'base',
    'headOwner',
    'headRef',
    'headOid'
  ])
  requireOnlyKeys('release evidence Umbrel community store', body.surfaces.umbrelCommunityStore, [
    'validation',
    'publish',
    'commit',
    'commitUrl'
  ])
}

async function verifyReleaseHandoffs (release, inputs) {
  if (release.release.prerelease) {
    verifyPrereleaseSkips(release)
    forbidPresent('fleet rollout handoff evidence', inputs.fleetRolloutFile)
    forbidPresent('official Umbrel PR handoff evidence', inputs.officialUmbrelPrFile)
    forbidPresent('StartOS registry handoff evidence', inputs.startosRegistryFile)
    return
  }

  const publicGatewayRelease = isEnabledPublicGatewayRelease(release)
  requireOneOf('release.channel', release.release.channel, publicGatewayRelease ? ['none'] : ['canary', 'stable', 'both'])
  requireOneOf('npm packages', release.surfaces?.npmPackages, ['published', 'current'])
  requireOneOf('official Umbrel PR status', release.surfaces?.umbrelOfficial?.status, ['draft-pr-ready'])
  requirePattern('official Umbrel PR URL', release.surfaces.umbrelOfficial.prUrl, OFFICIAL_UMBREL_PR_URL_PATTERN)
  requirePattern('official Umbrel PR head', release.surfaces.umbrelOfficial.head, /^[A-Za-z0-9_.-]+:[A-Za-z0-9._/-]{1,128}$/)
  requirePattern('official Umbrel PR head SHA', release.surfaces.umbrelOfficial.headSha, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR state', release.surfaces.umbrelOfficial.state, 'OPEN')
  requireEqual('official Umbrel PR draft', release.surfaces.umbrelOfficial.isDraft, true)
  requireEqual('official Umbrel PR base', release.surfaces.umbrelOfficial.base, 'master')
  requireGitHubOwnerName('official Umbrel PR head owner', release.surfaces.umbrelOfficial.headOwner)
  requireEqual('official Umbrel PR head owner matches head owner', release.surfaces.umbrelOfficial.headOwner, headOwnerFromHead(release.surfaces.umbrelOfficial.head))
  requireGitHubHeadRefName('official Umbrel PR head ref', release.surfaces.umbrelOfficial.headRef)
  requireEqual('official Umbrel PR head ref matches head branch', release.surfaces.umbrelOfficial.headRef, headRefFromHead(release.surfaces.umbrelOfficial.head))
  requirePattern('official Umbrel PR head OID', release.surfaces.umbrelOfficial.headOid, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR head OID matches head SHA', release.surfaces.umbrelOfficial.headOid, release.surfaces.umbrelOfficial.headSha)
  requireOneOf('StartOS registry status', release.surfaces?.startosRegistry, ['published'])
  requirePublicHttpsUrl('StartOS registry URL', release.surfaces.startosRegistryUrl)
  requirePattern('StartOS package id', release.surfaces.startosPackageId, /^[a-z0-9][a-z0-9-]{1,63}$/)
  requireRegistryPackageUrl('StartOS registry package URL', release.surfaces.startosRegistryPackageUrl, release.surfaces.startosRegistryUrl, release.surfaces.startosPackageId)
  requireEqual('StartOS package path', release.artifacts?.startosPackage?.path, 'startos/blindspark.s9pk')
  requirePattern('StartOS package SHA-256', release.artifacts.startosPackage.sha256, /^[a-f0-9]{64}$/i)
  if (publicGatewayRelease) {
    requireOneOf('public gateway fleet rollout status', release.surfaces?.fleetRollout, ['deferred-gateway-canary-gated'])
    requireOneOf('public gateway fleet rollout channel', release.surfaces?.fleetRolloutChannel || 'deferred', ['deferred'])
    requireOneOf('public gateway fleet rollout evidence path', release.surfaces?.fleetRolloutEvidence?.path || 'deferred', ['deferred'])
    requireOneOf('public gateway fleet rollout evidence hash', release.surfaces?.fleetRolloutEvidence?.sha256 || 'deferred', ['deferred'])
    requireOneOf('public gateway fleet channel config path', release.surfaces?.fleetChannelConfig?.path || 'deferred', ['deferred'])
    requireOneOf('public gateway fleet channel config hash', release.surfaces?.fleetChannelConfig?.sha256 || 'deferred', ['deferred'])
  } else {
    requireOneOf('fleet rollout status', release.surfaces?.fleetRollout, ['verified'])
    requireEqual('fleet rollout channel', release.surfaces.fleetRolloutChannel, release.release.channel)
    requireEqual('fleet rollout evidence path', release.surfaces.fleetRolloutEvidence?.path, 'fleet-rollout-evidence.json')
    requirePattern('fleet rollout evidence SHA-256', release.surfaces.fleetRolloutEvidence?.sha256, /^[a-f0-9]{64}$/i)
    requireEqual('fleet channel config path', release.surfaces.fleetChannelConfig?.path, 'fleet/channels.json')
    requirePattern('fleet channel config SHA-256', release.surfaces.fleetChannelConfig?.sha256, /^[a-f0-9]{64}$/i)
  }
  requireOneOf('release image manifest gate', release.gates?.imageManifest, ['passed'])
  requireEqual('release image manifest evidence path', release.gates?.imageManifestEvidence?.path, 'release-image-manifest-evidence.json')
  requirePattern('release image manifest evidence SHA-256', release.gates?.imageManifestEvidence?.sha256, /^[a-f0-9]{64}$/i)

  const official = readRequiredJson(inputs.officialUmbrelPrFile, 'official Umbrel PR handoff evidence')
  const startos = readRequiredJson(inputs.startosRegistryFile, 'StartOS registry handoff evidence')
  const imageManifestFile = requireFile(inputs.releaseImageManifestFile, 'release image manifest evidence')
  const fleetRolloutFile = publicGatewayRelease ? '' : requireFile(inputs.fleetRolloutFile, 'fleet rollout evidence')
  const packageFile = requireFile(inputs.startosPackageFile, 'StartOS package')

  const imageManifestGeneratedAtMs = verifyImageManifestSidecar(release, imageManifestFile)
  verifySmokeSidecar(
    release,
    release.gates?.pushedImageSmokeEvidence,
    inputs.releaseImageSmokeFile,
    'release-image-smoke',
    RELEASE_IMAGE_SMOKE_CHECKS,
    imageManifestGeneratedAtMs
  )
  verifySmokeSidecar(
    release,
    release.gates?.umbrelPackageSmokeEvidence,
    inputs.umbrelPackageSmokeFile,
    'umbrel-package-smoke',
    UMBREL_PACKAGE_SMOKE_CHECKS,
    imageManifestGeneratedAtMs
  )
  if (!publicGatewayRelease) verifyFleetRolloutSidecar(release, fleetRolloutFile)
  verifyOfficialUmbrelPrHandoff(release, official)
  if (inputs.requireUmbrelRuntimeReview && !inputs.umbrelRuntimeReviewFile) {
    die('Umbrel runtime review handoff evidence is required when --require-umbrel-runtime-review is set')
  }
  verifyOptionalUmbrelRuntimeReviewHandoff(release, official, inputs.umbrelRuntimeReviewFile)
  await verifyStartosRegistryHandoff(release, startos, packageFile, inputs.startosRegistryFile)
}

function verifyPrereleaseSkips (release) {
  requireOneOf('prerelease release channel', release.release?.channel, ['none'])
  requireOneOf('prerelease distribution preflight', release.gates?.distributionPreflight, ['skipped'])
  requireOneOf('prerelease metadata surfaces', release.surfaces?.metadataCommit, ['skipped'])
  requireOneOf('prerelease npm packages', release.surfaces?.npmPackages, release.release?.candidate ? ['skipped'] : ['published-next', 'current-next'])
  requireOneOf('prerelease fleet rollout', release.surfaces?.fleetRollout, ['skipped'])
  requireOneOf('prerelease fleet rollout channel', release.surfaces?.fleetRolloutChannel || 'skipped', ['skipped'])
  requireOneOf('prerelease fleet rollout evidence path', release.surfaces?.fleetRolloutEvidence?.path || 'skipped', ['skipped'])
  requireOneOf('prerelease fleet rollout evidence hash', release.surfaces?.fleetRolloutEvidence?.sha256 || 'skipped', ['skipped'])
  requireOneOf('prerelease fleet channel config path', release.surfaces?.fleetChannelConfig?.path || 'skipped', ['skipped'])
  requireOneOf('prerelease fleet channel config hash', release.surfaces?.fleetChannelConfig?.sha256 || 'skipped', ['skipped'])
  requireOneOf('prerelease StartOS registry', release.surfaces?.startosRegistry, ['skipped'])
  requireOneOf('prerelease StartOS registry URL', release.surfaces?.startosRegistryUrl || 'skipped', ['skipped'])
  requireOneOf('prerelease StartOS registry package URL', release.surfaces?.startosRegistryPackageUrl || 'skipped', ['skipped'])
  requireOneOf('prerelease StartOS package id', release.surfaces?.startosPackageId || 'skipped', ['skipped'])
  requireOneOf('prerelease StartOS registry evidence path', release.surfaces?.startosRegistryEvidence?.path || 'skipped', ['skipped'])
  requireOneOf('prerelease StartOS registry evidence hash', release.surfaces?.startosRegistryEvidence?.sha256 || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR', release.surfaces?.umbrelOfficial?.status, ['skipped'])
  requireOneOf('prerelease official Umbrel PR URL', release.surfaces?.umbrelOfficial?.prUrl || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR head', release.surfaces?.umbrelOfficial?.head || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR head SHA', release.surfaces?.umbrelOfficial?.headSha || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR state', release.surfaces?.umbrelOfficial?.state || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR draft', release.surfaces?.umbrelOfficial?.isDraft == null ? 'skipped' : String(release.surfaces.umbrelOfficial.isDraft), ['skipped'])
  requireOneOf('prerelease official Umbrel PR base', release.surfaces?.umbrelOfficial?.base || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR head owner', release.surfaces?.umbrelOfficial?.headOwner || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR head ref', release.surfaces?.umbrelOfficial?.headRef || 'skipped', ['skipped'])
  requireOneOf('prerelease official Umbrel PR head OID', release.surfaces?.umbrelOfficial?.headOid || 'skipped', ['skipped'])
  // Community store is the deliberate prerelease exception: it syncs on
  // every release, so the prerelease carries full store facts.
  requireOneOf('prerelease Umbrel community validation', release.surfaces?.umbrelCommunityStore?.validation, ['passed', 'skipped-no-manifest', 'skipped'])
  requireOneOf('prerelease Umbrel community publish', release.surfaces?.umbrelCommunityStore?.publish, ['pushed', 'current', 'skipped'])
  if (release.surfaces?.umbrelCommunityStore?.publish !== 'skipped') {
    requirePattern('prerelease Umbrel community commit', release.surfaces?.umbrelCommunityStore?.commit, /^[a-f0-9]{40}$/i)
    requirePattern('prerelease Umbrel community commit URL', release.surfaces?.umbrelCommunityStore?.commitUrl, /^https:\/\/github\.com\/bigdestiny2\/blindspark-umbrel-store\/commit\/[a-f0-9]{40}$/i)
  } else {
    requireOneOf('prerelease Umbrel community commit', release.surfaces?.umbrelCommunityStore?.commit || 'skipped', ['skipped'])
    requireOneOf('prerelease Umbrel community commit URL', release.surfaces?.umbrelCommunityStore?.commitUrl || 'skipped', ['skipped'])
  }
}

function verifyImageManifestSidecar (release, file) {
  const body = readJson(file, 'release image manifest evidence')
  assertPublicSafe(body, 'release image manifest evidence')
  requireEqual('release image manifest evidence hash', sha256File(file, 'release image manifest evidence', MAX_EVIDENCE_JSON_BYTES), release.gates.imageManifestEvidence.sha256)
  assertImageManifestSidecarSchema(body)
  requireEqual('release image manifest schemaVersion', body.schemaVersion, 1)
  requireEqual('release image manifest kind', body.kind, 'release-image-manifest')
  requireEqual('release image manifest status', body.status, 'verified')
  const generatedAtMs = requireIsoTimestamp('release image manifest generatedAt', body.generatedAt)
  const releaseGeneratedAtMs = requireIsoTimestamp('release generatedAt', release.generatedAt)
  if (generatedAtMs > releaseGeneratedAtMs) {
    die('release image manifest generatedAt must not be after release generatedAt')
  }
  requireEqual('release image manifest image name', body.image?.name, release.image.name)
  requireEqual('release image manifest image tag', body.image?.tag, release.release.semver)
  requireEqual('release image manifest image digest', body.image?.digest, release.image.digest)
  requireEqual('release image manifest image ref', body.image?.ref, release.image.ref)
  requireArrayEqual('release image manifest required platforms', body.requiredPlatforms, REQUIRED_IMAGE_PLATFORMS)
  if (!IMAGE_INDEX_MEDIA_TYPES.has(body.manifest?.mediaType)) {
    die(`release image manifest media type must be an image index; got ${JSON.stringify(body.manifest?.mediaType)}`)
  }
  const platforms = Array.isArray(body.platforms) ? body.platforms : []
  if (platforms.length === 0) die('release image manifest evidence must include platform entries')
  if (!Number.isSafeInteger(body.manifest?.manifestCount) || body.manifest.manifestCount < platforms.length) {
    die('release image manifest manifestCount is malformed')
  }
  const labels = new Set()
  for (const platform of platforms) {
    requirePattern('release image manifest platform os', platform.os, /^[a-z0-9._-]{1,32}$/)
    requirePattern('release image manifest platform architecture', platform.architecture, /^[a-z0-9._-]{1,32}$/)
    if (platform.variant) requirePattern('release image manifest platform variant', platform.variant, /^[A-Za-z0-9._-]{1,32}$/)
    requirePattern('release image manifest platform digest', platform.digest, /^sha256:[a-f0-9]{64}$/i)
    const label = `${platform.os}/${platform.architecture}`
    if (labels.has(label)) die(`release image manifest evidence has duplicate platform ${label}`)
    labels.add(label)
  }
  for (const required of REQUIRED_IMAGE_PLATFORMS) {
    if (!labels.has(required)) die(`release image manifest evidence is missing required platform ${required}`)
  }
  return generatedAtMs
}

function assertImageManifestSidecarSchema (body) {
  requireOnlyKeys('release image manifest evidence', body, [
    'schemaVersion',
    'generatedAt',
    'kind',
    'status',
    'image',
    'requiredPlatforms',
    'platforms',
    'manifest'
  ])
  requireOnlyKeys('release image manifest image', body.image, ['name', 'tag', 'digest', 'ref'])
  if (Array.isArray(body.platforms)) {
    for (const platform of body.platforms) {
      requireOnlyKeys(`release image manifest platform ${platform?.os || ''}/${platform?.architecture || ''}`, platform, [
        'os',
        'architecture',
        'variant',
        'digest'
      ])
    }
  }
  requireOnlyKeys('release image manifest manifest', body.manifest, ['mediaType', 'manifestCount'])
}

function verifyFleetRolloutSidecar (release, file) {
  const rollout = readJson(file, 'fleet rollout evidence')
  assertPublicSafe(rollout, 'fleet rollout evidence')
  requireEqual('fleet rollout evidence hash', sha256File(file, 'fleet rollout evidence', MAX_EVIDENCE_JSON_BYTES), release.surfaces.fleetRolloutEvidence.sha256)
  assertFleetRolloutSidecarSchema(rollout)
  requireEqual('fleet rollout schemaVersion', rollout.schemaVersion, 1)
  requireEqual('fleet rollout status', rollout.status, 'verified')
  const generatedAtMs = requireIsoTimestamp('fleet rollout generatedAt', rollout.generatedAt)
  requireEqual('fleet rollout target tag', rollout.target?.tag, release.release.version)
  requireEqual('fleet rollout target version', rollout.target?.version, release.release.semver)
  requireEqual('fleet rollout target sha', rollout.target?.sha, release.release.tagSha)
  requireEqual('fleet rollout target channel', rollout.target?.channel, release.release.channel)

  const relays = Array.isArray(rollout.relays) ? rollout.relays : []
  if (relays.length === 0) die('fleet rollout evidence must include at least one relay')
  const expectedFleet = expectedFleetRollout(release.release.channel)
  requireEqual('fleet rollout inventory path', rollout.inventory?.path, 'fleet/relays.json')
  requireEqual('fleet rollout inventory SHA-256', rollout.inventory?.sha256, expectedFleet.sha256)
  requireArrayEqual('fleet rollout inventory relay names', rollout.inventory?.relayNames, expectedFleet.relayNames)
  requireEqual('fleet rollout channel config path', rollout.channelConfig?.path, release.surfaces.fleetChannelConfig.path)
  requireEqual('fleet rollout channel config SHA-256', rollout.channelConfig?.sha256, release.surfaces.fleetChannelConfig.sha256)
  verifyFleetChannelTargets(rollout.channelConfig?.targets, release.release.channel, release.release.version)
  verifyFleetRolloutProbeConfig(rollout.probes)
  requireEqual('fleet rollout summary total', rollout.summary?.total, relays.length)
  requireEqual('fleet rollout summary updated', rollout.summary?.updated, relays.length)
  requireEqual('fleet rollout summary packageVersionMatches', rollout.summary?.packageVersionMatches, relays.length)
  requireEqual('fleet rollout summary healthy', rollout.summary?.healthy, relays.length)
  requireEqual('fleet rollout summary runtimeVersionMatches', rollout.summary?.runtimeVersionMatches, relays.length)

  const seenRelayNames = new Set()
  const seenChannels = new Set()
  for (const relay of relays) {
    if (!relay || typeof relay !== 'object') die('fleet rollout evidence contains malformed relay')
    if (Object.prototype.hasOwnProperty.call(relay, 'host')) die(`fleet rollout relay ${relay.name || '(unnamed)'} must not expose host`)
    if (Object.prototype.hasOwnProperty.call(relay, 'sshKey')) die(`fleet rollout relay ${relay.name || '(unnamed)'} must not expose sshKey`)
    requirePattern('fleet rollout relay name', relay.name, /^[A-Za-z0-9._-]{1,64}$/)
    if (seenRelayNames.has(relay.name)) die(`fleet rollout evidence has duplicate relay name ${relay.name}`)
    seenRelayNames.add(relay.name)
    const observedAtMs = requireIsoTimestamp(`fleet rollout relay ${relay.name} observedAt`, relay.observedAt)
    if (observedAtMs > generatedAtMs) die(`fleet rollout relay ${relay.name} observedAt must not be after fleet rollout generatedAt`)
    requireAllowedChannel('fleet rollout relay channel', relay.channel, release.release.channel)
    seenChannels.add(relay.channel)
    requireEqual(`fleet rollout relay ${relay.name} package version`, relay.packageVersion, release.release.version)
    requireEqual(`fleet rollout relay ${relay.name} head`, relay.headSha, release.release.tagSha)
    requireEqual(`fleet rollout relay ${relay.name} target`, relay.targetSha, release.release.tagSha)
    requireEqual(`fleet rollout relay ${relay.name} health version`, relay.healthVersion, release.release.semver)
    requireEqual(`fleet rollout relay ${relay.name} updated`, relay.updated, true)
    requireEqual(`fleet rollout relay ${relay.name} packageVersionMatches`, relay.packageVersionMatches, true)
    requireEqual(`fleet rollout relay ${relay.name} healthy`, relay.healthy, true)
    requireEqual(`fleet rollout relay ${relay.name} runtimeVersionMatches`, relay.runtimeVersionMatches, true)
    requireEqual(`fleet rollout relay ${relay.name} note`, relay.note, 'ok')
  }

  requireArrayEqual('fleet rollout relay names', [...seenRelayNames], expectedFleet.relayNames)

  if (release.release.channel === 'both' && (!seenChannels.has('canary') || !seenChannels.has('stable'))) {
    die('fleet rollout evidence for channel both must include canary and stable relays')
  }
}

function assertFleetRolloutSidecarSchema (rollout) {
  requireOnlyKeys('fleet rollout evidence', rollout, [
    'schemaVersion',
    'generatedAt',
    'status',
    'target',
    'inventory',
    'channelConfig',
    'probes',
    'summary',
    'relays',
    'error'
  ])
  requireOnlyKeys('fleet rollout target', rollout.target, ['tag', 'version', 'sha', 'channel'])
  requireOnlyKeys('fleet rollout inventory', rollout.inventory, ['path', 'sha256', 'relayNames'])
  requireOnlyKeys('fleet rollout channel config', rollout.channelConfig, ['path', 'sha256', 'targets'])
  requireOnlyKeys('fleet rollout channel config targets', rollout.channelConfig.targets, ['canary', 'stable'])
  requireOnlyKeys('fleet rollout probes', rollout.probes, ['timeoutMs', 'intervalMs', 'sshTimeoutMs', 'service', 'api'])
  requireOnlyKeys('fleet rollout summary', rollout.summary, [
    'total',
    'updated',
    'packageVersionMatches',
    'healthy',
    'runtimeVersionMatches'
  ])
  if (Array.isArray(rollout.relays)) {
    for (const relay of rollout.relays) {
      requireOnlyKeys(`fleet rollout relay ${relay?.name || '(unnamed)'}`, relay, [
        'name',
        'channel',
        'packageVersion',
        'healthVersion',
        'observedAt',
        'headSha',
        'targetSha',
        'updated',
        'packageVersionMatches',
        'healthy',
        'runtimeVersionMatches',
        'disk',
        'note',
        'error',
        'host',
        'sshKey'
      ])
    }
  }
}

function verifyFleetRolloutProbeConfig (probes) {
  if (!probes || typeof probes !== 'object' || Array.isArray(probes)) {
    die('fleet rollout probes must be an object')
  }
  requireIntegerRange('fleet rollout timeoutMs', probes.timeoutMs, FLEET_ROLLOUT_TIMEOUT_MIN_MS, FLEET_ROLLOUT_TIMEOUT_MAX_MS)
  requireIntegerRange('fleet rollout intervalMs', probes.intervalMs, FLEET_ROLLOUT_INTERVAL_MIN_MS, FLEET_ROLLOUT_INTERVAL_MAX_MS)
  requireIntegerRange('fleet rollout sshTimeoutMs', probes.sshTimeoutMs, FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS, FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS)
  requireLoopbackApiBase('fleet rollout API URL', probes.api)
}

function expectedFleetRollout (channel) {
  const body = readJson(FLEET_RELAYS_PATH, 'fleet inventory')
  const relays = Array.isArray(body.relays) ? body.relays : []
  const relayNames = []
  for (const relay of relays) {
    const relayChannel = relay?.channel || 'stable'
    if (
      channel === relayChannel ||
      (channel === 'both' && (relayChannel === 'canary' || relayChannel === 'stable'))
    ) {
      relayNames.push(relay.name)
    }
  }
  if (relayNames.length === 0) die(`fleet inventory has no relays for channel ${JSON.stringify(channel)}`)
  return {
    sha256: sha256File(FLEET_RELAYS_PATH),
    relayNames
  }
}

function verifyFleetChannelTargets (targets, releaseChannel, releaseVersion) {
  if (!targets || typeof targets !== 'object' || Array.isArray(targets)) {
    die('fleet rollout channel config targets must be an object')
  }
  const required = releaseChannel === 'both' ? ['canary', 'stable'] : [releaseChannel]
  requireArrayEqual('fleet rollout channel config target names', Object.keys(targets).sort(), required.slice().sort())
  for (const name of required) {
    requireEqual(`fleet rollout channel ${name} target`, targets[name], releaseVersion)
  }
}

function verifyOfficialUmbrelPrHandoff (release, body) {
  assertPublicSafe(body, 'official Umbrel PR handoff evidence')
  assertOfficialUmbrelPrSidecarSchema(body, 'official Umbrel PR handoff')
  requireEqual('official Umbrel PR handoff schemaVersion', body.schemaVersion, 1)
  requireEqual('official Umbrel PR handoff kind', body.kind, 'official-umbrel-pr')
  requireEqual('official Umbrel PR handoff status', body.status, 'updated')
  const generatedAtMs = requireIsoTimestamp('official Umbrel PR handoff generatedAt', body.generatedAt)
  const releaseGeneratedAtMs = requireIsoTimestamp('release generatedAt', release.generatedAt)
  if (generatedAtMs < releaseGeneratedAtMs) {
    die('official Umbrel PR handoff generatedAt must not be before release generatedAt')
  }
  verifyOfficialUmbrelPrSidecarShape(body)
  requireEqual('official Umbrel PR handoff version', body.release?.version, release.release.version)
  requireEqual('official Umbrel PR handoff semver', body.release?.semver, release.release.semver)
  requireEqual('official Umbrel PR URL', body.pr?.url, release.surfaces.umbrelOfficial.prUrl)
  requireEqual('official Umbrel PR number', body.pr?.number, prNumberFromUrl(release.surfaces.umbrelOfficial.prUrl))
  requireEqual('official Umbrel PR head', body.pr?.head, release.surfaces.umbrelOfficial.head)
  requireEqual('official Umbrel PR head SHA', body.pr?.headSha, release.surfaces.umbrelOfficial.headSha)
  requireEqual('official Umbrel PR state', body.pr?.state, release.surfaces.umbrelOfficial.state)
  requireEqual('official Umbrel PR draft', body.pr?.isDraft, release.surfaces.umbrelOfficial.isDraft)
  requireEqual('official Umbrel PR base', body.pr?.base, release.surfaces.umbrelOfficial.base)
  requireEqual('official Umbrel PR head owner', body.pr?.headOwner, release.surfaces.umbrelOfficial.headOwner)
  requireEqual('official Umbrel PR head ref', body.pr?.headRef, release.surfaces.umbrelOfficial.headRef)
  requireEqual('official Umbrel PR head OID', body.pr?.headOid, release.surfaces.umbrelOfficial.headOid)
  requireEqual('official Umbrel PR workflow repository', body.workflow?.repository, release.release.workflow.repository)
  requireEqual('official Umbrel PR workflow run id', body.workflow?.runId, release.release.workflow.runId)
  requireEqual('official Umbrel PR workflow run attempt', body.workflow?.runAttempt, release.release.workflow.runAttempt)
  requireEqual('official Umbrel PR workflow URL', body.workflow?.runUrl, release.release.workflow.runUrl)
  requireEqual('official Umbrel PR runtime review status', body.runtimeReview?.status, 'pending-real-device-review')
  requireEqual('official Umbrel PR runtime review evidence file', body.runtimeReview?.evidenceFile, 'umbrel-runtime-review-evidence.json')
  requireEqual('official Umbrel PR runtime review verifier', body.runtimeReview?.verifier, 'npm run umbrel:verify-runtime-review')

  const releaseBase = releaseBaseUrl(release)
  requireEqual('official Umbrel PR release evidence link', body.evidenceLinks?.releaseEvidence, `${releaseBase}/release-evidence.json`)
  requireEqual('official Umbrel PR image manifest link', body.evidenceLinks?.releaseImageManifest, `${releaseBase}/release-image-manifest-evidence.json`)
  requireEqual('official Umbrel PR image smoke link', body.evidenceLinks?.releaseImageSmoke, `${releaseBase}/release-image-smoke-evidence.json`)
  requireEqual('official Umbrel PR Umbrel smoke link', body.evidenceLinks?.umbrelPackageSmoke, `${releaseBase}/umbrel-package-smoke-evidence.json`)
  requireEqual(
    'official Umbrel PR fleet rollout link',
    body.evidenceLinks?.fleetRollout,
    isEnabledPublicGatewayRelease(release) ? '' : `${releaseBase}/fleet-rollout-evidence.json`
  )
  requireEqual('official Umbrel PR StartOS package link', body.evidenceLinks?.startosPackage, `${releaseBase}/blindspark.s9pk`)
  requireEqual('official Umbrel PR StartOS registry package link', body.evidenceLinks?.startosRegistryPackage, release.surfaces.startosRegistryPackageUrl)
  requireEqual('official Umbrel PR StartOS registry link', body.evidenceLinks?.startosRegistry, `${releaseBase}/startos-registry-evidence.json`)
  requireEqual('official Umbrel PR workflow link', body.evidenceLinks?.workflow, release.release.workflow.runUrl)
}

function assertOfficialUmbrelPrSidecarSchema (body, label) {
  requireOnlyKeys(label, body, [
    'schemaVersion',
    'generatedAt',
    'kind',
    'status',
    'release',
    'pr',
    'workflow',
    'runtimeReview',
    'evidenceLinks'
  ])
  requireOnlyKeys(`${label} release`, body.release, ['version', 'semver'])
  requireOnlyKeys(`${label} pr`, body.pr, [
    'url',
    'number',
    'head',
    'headSha',
    'state',
    'isDraft',
    'base',
    'headOwner',
    'headRef',
    'headOid'
  ])
  requireOnlyKeys(`${label} workflow`, body.workflow, ['repository', 'runId', 'runAttempt', 'runUrl'])
  requireOnlyKeys(`${label} runtimeReview`, body.runtimeReview, ['status', 'evidenceFile', 'verifier'])
  requireOnlyKeys(`${label} evidenceLinks`, body.evidenceLinks, [
    'releaseEvidence',
    'releaseImageManifest',
    'releaseImageSmoke',
    'umbrelPackageSmoke',
    'fleetRollout',
    'startosPackage',
    'startosRegistryPackage',
    'startosRegistry',
    'workflow'
  ])
}

function verifyOfficialUmbrelPrSidecarShape (body) {
  requirePattern('official Umbrel PR handoff URL', body.pr?.url, OFFICIAL_UMBREL_PR_URL_PATTERN)
  requirePattern('official Umbrel PR handoff number', body.pr?.number, POSITIVE_INTEGER_PATTERN)
  requireEqual('official Umbrel PR handoff number matches URL', body.pr?.number, prNumberFromUrl(body.pr?.url))
  requirePattern('official Umbrel PR handoff head', body.pr?.head, /^[A-Za-z0-9_.-]+:[A-Za-z0-9._/-]{1,128}$/)
  requirePattern('official Umbrel PR handoff head SHA', body.pr?.headSha, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR handoff state', body.pr?.state, 'OPEN')
  requireEqual('official Umbrel PR handoff draft', body.pr?.isDraft, true)
  requireEqual('official Umbrel PR handoff base', body.pr?.base, 'master')
  requireGitHubOwnerName('official Umbrel PR handoff head owner', body.pr?.headOwner)
  requireEqual('official Umbrel PR handoff head owner matches head owner', body.pr?.headOwner, headOwnerFromHead(body.pr?.head))
  requireGitHubHeadRefName('official Umbrel PR handoff head ref', body.pr?.headRef)
  requireEqual('official Umbrel PR handoff head ref matches head branch', body.pr?.headRef, headRefFromHead(body.pr?.head))
  requirePattern('official Umbrel PR handoff head OID', body.pr?.headOid, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR handoff head OID matches head SHA', body.pr?.headOid, body.pr?.headSha)
  requirePattern('official Umbrel PR handoff workflow repository', body.workflow?.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requirePattern('official Umbrel PR handoff workflow run id', body.workflow?.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('official Umbrel PR handoff workflow run attempt', body.workflow?.runAttempt, POSITIVE_INTEGER_PATTERN)
  requireEqual('official Umbrel PR handoff workflow URL', body.workflow?.runUrl, `https://github.com/${body.workflow?.repository}/actions/runs/${body.workflow?.runId}`)
}

function verifyOptionalUmbrelRuntimeReviewHandoff (release, official, file) {
  if (!file) return
  if (!fs.existsSync(file)) die(`Umbrel runtime review handoff evidence file was provided but does not exist: ${file}`)
  const body = readJson(file, 'Umbrel runtime review handoff evidence')
  assertPublicSafe(body, 'Umbrel runtime review handoff evidence')
  assertNoRawPublicKeyFields(body, 'Umbrel runtime review handoff evidence')
  assertUmbrelRuntimeReviewHandoffSchema(body)
  requireEqual('Umbrel runtime review schemaVersion', body.schemaVersion, 1)
  const generatedAtMs = requireIsoTimestamp('Umbrel runtime review generatedAt', body.generatedAt)
  if (generatedAtMs > Date.now() + MAX_GENERATED_AT_FUTURE_SKEW_MS) {
    die('Umbrel runtime review generatedAt must not be in the future')
  }
  const releaseGeneratedAtMs = requireIsoTimestamp('release generatedAt', release.generatedAt)
  const officialGeneratedAtMs = requireIsoTimestamp('official Umbrel PR handoff generatedAt', official.generatedAt)
  if (generatedAtMs < releaseGeneratedAtMs) {
    die('Umbrel runtime review generatedAt must not be before release generatedAt')
  }
  if (generatedAtMs < officialGeneratedAtMs) {
    die('Umbrel runtime review generatedAt must not be before official Umbrel PR handoff generatedAt')
  }
  requireEqual('Umbrel runtime review kind', body.kind, 'umbrel-runtime-review')
  requireEqual('Umbrel runtime review status', body.status, 'passed')
  requireEqual('Umbrel runtime review release version', body.release?.version, release.release.version)
  requireEqual('Umbrel runtime review release semver', body.release?.semver, release.release.semver)
  requireEqual('Umbrel runtime review platform', body.platform?.name, 'umbrel')
  requireSafePublicLabel('Umbrel runtime review device', body.platform?.device)
  requirePattern('Umbrel runtime review Umbrel version', body.platform?.umbrelVersion, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/)
  requireSafePublicLabel('Umbrel runtime reviewer', body.review?.testedBy)
  verifyUmbrelRuntimeReviewIdentityHashes(body.identity)
  requirePattern('Umbrel runtime review PR URL', body.officialUmbrelPr?.url, OFFICIAL_UMBREL_PR_URL_PATTERN)
  requireEqual('Umbrel runtime review PR URL', body.officialUmbrelPr?.url, official.pr?.url)
  verifyUmbrelRuntimeReviewChecks(body.checks)
}

function assertUmbrelRuntimeReviewHandoffSchema (body) {
  requireOnlyKeys('Umbrel runtime review handoff evidence', body, [
    'schemaVersion',
    'generatedAt',
    'kind',
    'status',
    'release',
    'platform',
    'review',
    'identity',
    'checks',
    'officialUmbrelPr'
  ])
  requireOnlyKeys('Umbrel runtime review release', body.release, ['version', 'semver'])
  requireOnlyKeys('Umbrel runtime review platform', body.platform, ['name', 'device', 'umbrelVersion'])
  requireOnlyKeys('Umbrel runtime review reviewer', body.review, ['testedBy'])
  requireOnlyKeys('Umbrel runtime review identity', body.identity, [
    'publicKeySha256',
    'publicKeyBeforeSha256',
    'publicKeyAfterSha256'
  ])
  requireOnlyKeys('Umbrel runtime review officialUmbrelPr', body.officialUmbrelPr, ['url'])
  if (Array.isArray(body.checks)) {
    for (const check of body.checks) {
      requireOnlyKeys(`Umbrel runtime review check ${check?.name || ''}`.trim(), check, ['name', 'status'])
    }
  }
}

function verifyUmbrelRuntimeReviewIdentityHashes (identity = {}) {
  requirePattern('Umbrel runtime review public key hash', identity.publicKeySha256, /^[a-f0-9]{64}$/)
  requirePattern('Umbrel runtime review public key before hash', identity.publicKeyBeforeSha256, /^[a-f0-9]{64}$/)
  requirePattern('Umbrel runtime review public key after hash', identity.publicKeyAfterSha256, /^[a-f0-9]{64}$/)
  requireEqual('Umbrel runtime review public key hash matches before hash', identity.publicKeySha256, identity.publicKeyBeforeSha256)
  requireEqual('Umbrel runtime review public key hash after reinstall', identity.publicKeyAfterSha256, identity.publicKeyBeforeSha256)
}

function verifyUmbrelRuntimeReviewChecks (checks) {
  if (!Array.isArray(checks)) die('Umbrel runtime review checks must be an array')
  const seen = new Set()
  for (const check of checks) {
    requirePattern('Umbrel runtime review check name', check?.name, /^[A-Za-z][A-Za-z0-9]*$/)
    if (!UMBREL_RUNTIME_REVIEW_CHECKS.includes(check.name)) die(`Unknown Umbrel runtime review check: ${check.name}`)
    if (seen.has(check.name)) die(`Duplicate Umbrel runtime review check: ${check.name}`)
    seen.add(check.name)
    requireEqual(`Umbrel runtime review check ${check.name}`, check.status, 'passed')
  }
  const missing = UMBREL_RUNTIME_REVIEW_CHECKS.filter((check) => !seen.has(check))
  if (missing.length > 0) die(`Missing Umbrel runtime review checks: ${missing.join(', ')}`)
}

async function verifyStartosRegistryHandoff (release, body, packageFile, file) {
  assertStartosRegistrySidecarSchema(body, 'StartOS registry handoff')
  requireEqual('StartOS registry handoff schemaVersion', body.schemaVersion, 1)
  requireEqual('StartOS registry handoff kind', body.kind, 'startos-registry-publication')
  requireEqual('StartOS registry handoff status', body.status, 'published')
  const generatedAtMs = requireIsoTimestamp('StartOS registry handoff generatedAt', body.generatedAt)
  const releaseGeneratedAtMs = requireIsoTimestamp('release generatedAt', release.generatedAt)
  if (generatedAtMs > releaseGeneratedAtMs) {
    die('StartOS registry handoff generatedAt must not be after release generatedAt')
  }
  verifyStartosRegistrySidecarShape(body)
  requireEqual('StartOS registry handoff version', body.release?.version, release.release.version)
  requireEqual('StartOS registry handoff semver', body.release?.semver, release.release.semver)
  requireEqual('StartOS handoff package id', body.package?.id, release.surfaces.startosPackageId)
  requireEqual('StartOS handoff package path', body.package?.path, release.artifacts.startosPackage.path)
  requireEqual('StartOS handoff package SHA-256', body.package?.sha256, release.artifacts.startosPackage.sha256)
  requireEqual('StartOS handoff package URL', body.package?.url, release.surfaces.startosRegistryPackageUrl)
  requireEqual('StartOS handoff package hash', await sha256LargeFile(packageFile, 'StartOS package'), body.package.sha256)
  requireEqual('StartOS registry URL', body.registry?.url, release.surfaces.startosRegistryUrl)
  requireEqual('StartOS registry workflow repository', body.workflow?.repository, release.release.workflow.repository)
  requireEqual('StartOS registry workflow run id', body.workflow?.runId, release.release.workflow.runId)
  requireEqual('StartOS registry workflow run attempt', body.workflow?.runAttempt, release.release.workflow.runAttempt)
  requireEqual('StartOS registry workflow URL', body.workflow?.runUrl, release.release.workflow.runUrl)

  const releaseBase = releaseBaseUrl(release)
  requireEqual('StartOS registry release evidence link', body.evidenceLinks?.releaseEvidence, `${releaseBase}/release-evidence.json`)
  requireEqual('StartOS registry image manifest link', body.evidenceLinks?.releaseImageManifest, `${releaseBase}/release-image-manifest-evidence.json`)
  requireEqual('StartOS registry image smoke link', body.evidenceLinks?.releaseImageSmoke, `${releaseBase}/release-image-smoke-evidence.json`)
  requireEqual('StartOS registry package link', body.evidenceLinks?.startosPackage, `${releaseBase}/blindspark.s9pk`)
  requireEqual('StartOS registry package registry link', body.evidenceLinks?.registryPackage, body.package.url)
  requireEqual('StartOS registry workflow link', body.evidenceLinks?.workflow, release.release.workflow.runUrl)
  assertPublicSafe(body, 'StartOS registry handoff evidence')
  requireEqual('StartOS registry evidence path', release.surfaces.startosRegistryEvidence?.path, 'startos-registry-evidence.json')
  requirePattern('StartOS registry evidence SHA-256', release.surfaces.startosRegistryEvidence?.sha256, /^[a-f0-9]{64}$/i)
  requireEqual('StartOS registry evidence hash', sha256File(file, 'StartOS registry evidence', MAX_EVIDENCE_JSON_BYTES), release.surfaces.startosRegistryEvidence.sha256)
}

function assertStartosRegistrySidecarSchema (body, label) {
  requireOnlyKeys(label, body, [
    'schemaVersion',
    'generatedAt',
    'kind',
    'status',
    'release',
    'package',
    'registry',
    'workflow',
    'evidenceLinks'
  ])
  requireOnlyKeys(`${label} release`, body.release, ['version', 'semver'])
  requireOnlyKeys(`${label} package`, body.package, ['id', 'path', 'sha256', 'url'])
  requireOnlyKeys(`${label} registry`, body.registry, ['url'])
  requireOnlyKeys(`${label} workflow`, body.workflow, ['repository', 'runId', 'runAttempt', 'runUrl'])
  requireOnlyKeys(`${label} evidenceLinks`, body.evidenceLinks, [
    'releaseEvidence',
    'releaseImageManifest',
    'releaseImageSmoke',
    'startosPackage',
    'registryPackage',
    'workflow'
  ])
}

function verifyStartosRegistrySidecarShape (body) {
  requirePattern('StartOS registry handoff release version', body.release?.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('StartOS registry handoff release semver', body.release?.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('StartOS registry handoff semver matches version', body.release.semver, body.release.version.slice(1))
  requirePattern('StartOS registry handoff package id', body.package?.id, /^[a-z0-9][a-z0-9-]{1,63}$/)
  requireEqual('StartOS registry handoff package path', body.package?.path, 'startos/blindspark.s9pk')
  requirePattern('StartOS registry handoff package SHA-256', body.package?.sha256, /^[a-f0-9]{64}$/i)
  requirePublicHttpsUrl('StartOS registry handoff URL', body.registry?.url)
  requireRegistryPackageUrl('StartOS registry handoff package URL', body.package?.url, body.registry?.url, body.package?.id)
  requirePattern('StartOS registry handoff workflow repository', body.workflow?.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requireEqual('StartOS registry handoff workflow repository', body.workflow.repository, EXPECTED_RELEASE_REPOSITORY)
  requirePattern('StartOS registry handoff workflow run id', body.workflow?.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('StartOS registry handoff workflow run attempt', body.workflow?.runAttempt, POSITIVE_INTEGER_PATTERN)
  requireEqual('StartOS registry handoff workflow URL', body.workflow?.runUrl, `https://github.com/${body.workflow?.repository}/actions/runs/${body.workflow?.runId}`)

  const releaseBase = `https://github.com/${body.workflow.repository}/releases/download/${body.release.version}`
  requireEqual('StartOS registry handoff release evidence link', body.evidenceLinks?.releaseEvidence, `${releaseBase}/release-evidence.json`)
  requireEqual('StartOS registry handoff image manifest link', body.evidenceLinks?.releaseImageManifest, `${releaseBase}/release-image-manifest-evidence.json`)
  requireEqual('StartOS registry handoff image smoke link', body.evidenceLinks?.releaseImageSmoke, `${releaseBase}/release-image-smoke-evidence.json`)
  requireEqual('StartOS registry handoff package link', body.evidenceLinks?.startosPackage, `${releaseBase}/blindspark.s9pk`)
  requireEqual('StartOS registry handoff registry package link', body.evidenceLinks?.registryPackage, body.package.url)
  requireEqual('StartOS registry handoff workflow link', body.evidenceLinks?.workflow, body.workflow.runUrl)
}

function verifySmokeSidecar (release, ref, file, kind, requiredChecks, imageManifestGeneratedAtMs) {
  requireEqual(`${kind} evidence path`, ref?.path, `${kind}-evidence.json`)
  requirePattern(`${kind} evidence SHA-256`, ref?.sha256, /^[a-f0-9]{64}$/i)
  const smoke = readRequiredJson(file, `${kind} evidence`)
  requireEqual(`${kind} evidence hash`, sha256File(file, `${kind} evidence`, MAX_EVIDENCE_JSON_BYTES), ref.sha256)
  requireEqual(`${kind} schemaVersion`, smoke.schemaVersion, 1)
  requireEqual(`${kind} kind`, smoke.kind, kind)
  const releaseGeneratedAtMs = requireIsoTimestamp('release generatedAt', release.generatedAt)
  const smokeGeneratedAtMs = requireIsoTimestamp(`${kind} generatedAt`, smoke.generatedAt)
  if (smokeGeneratedAtMs > releaseGeneratedAtMs) die(`${kind} generatedAt must not be after release generatedAt`)
  if (smokeGeneratedAtMs < imageManifestGeneratedAtMs) die(`${kind} generatedAt must not be before release image manifest generatedAt`)
  requireEqual(`${kind} imageRef`, smoke.imageRef, release.image?.ref)
  requireEqual(`${kind} imageName`, smoke.imageName, release.image?.name)
  requireEqual(`${kind} imageTag`, smoke.imageTag, release.release?.semver)
  requireEqual(`${kind} imageDigest`, smoke.imageDigest, release.image?.digest)
  assertPublicSafe(smoke, `${kind} evidence`)
  assertSmokeSidecarSchema(smoke, kind, requiredChecks)

  const checks = Array.isArray(smoke.checks) ? smoke.checks : []
  if (checks.length === 0) die(`${kind} evidence must include checks`)
  const byName = new Map()
  for (const check of checks) {
    if (!check || typeof check !== 'object') die(`${kind} evidence contains malformed check`)
    requirePattern(`${kind} check name`, check.name, /^[A-Za-z][A-Za-z0-9.-]{0,63}$/)
    if (!requiredChecks.includes(check.name)) die(`${kind} evidence has unsupported check ${check.name}`)
    if (byName.has(check.name)) die(`${kind} evidence has duplicate check ${check.name}`)
    requireEqual(`${kind} check ${check.name} status`, check.status, 'passed')
    byName.set(check.name, check)
  }
  for (const name of requiredChecks) {
    if (!byName.has(name)) die(`${kind} evidence is missing required check ${name}`)
  }
  verifySmokeCriticalChecks(kind, byName, release.release.semver)
  verifySmokeServiceChecks(kind, byName)
}

function assertSmokeSidecarSchema (smoke, kind, allowedChecks) {
  const topLevel = [
    'schemaVersion',
    'generatedAt',
    'kind',
    'imageRef',
    'imageName',
    'imageTag',
    'imageDigest',
    'checks'
  ]
  if (kind === 'umbrel-package-smoke') topLevel.push('composePath')
  requireOnlyKeys(`${kind} evidence`, smoke, topLevel)
  const checks = Array.isArray(smoke.checks) ? smoke.checks : []
  const allowed = new Set(allowedChecks)
  for (const check of checks) {
    if (!check || typeof check !== 'object' || Array.isArray(check)) die(`${kind} evidence contains malformed check`)
    requirePattern(`${kind} check name`, check.name, /^[A-Za-z][A-Za-z0-9.-]{0,63}$/)
    if (!allowed.has(check.name)) die(`${kind} evidence has unsupported check ${check.name}`)
    requireOnlyKeys(`${kind} check ${check.name}`, check, smokeCheckKeys(check.name))
    if (check.name === 'usageTelemetry') {
      requireOnlyKeys(`${kind} usageTelemetry bandwidth`, check.bandwidth, ['enabled', 'count', 'bytes', 'bandwidthBytes'])
      requireOnlyKeys(`${kind} usageTelemetry poker`, check.poker, ['enabled', 'tables', 'appends', 'seats'])
    }
  }
}

function smokeCheckKeys (name) {
  switch (name) {
    case 'health': return ['name', 'status', 'version']
    case 'dashboard': return ['name', 'status', 'serviceManager', 'walletControls', 'tokenMeta', 'walletBusyState', 'dynamicPayoutControls', 'serviceActionState', 'serviceInlinePlanState', 'aiModelAddState', 'appProxyWrites', 'leasePollingBounded', 'staticMarkupSafe']
    case 'setupWizard': return ['name', 'status', 'editMode', 'statusRegion', 'actionLock', 'dashboardLinkAppPath', 'staticMarkupSafe']
    case 'dashboardToken': return ['name', 'status', 'exposedViaMeta']
    case 'dashboardWebSocket': return ['name', 'status', 'queryTokenRejected', 'inBandAuth', 'updateReceived']
    case 'usageTelemetry': return ['name', 'status', 'bandwidth', 'poker']
    case 'acceptModeDefault': return ['name', 'status', 'mode']
    case 'serviceCatalog': return ['name', 'status', 'builtIns', 'bundles']
    case 'walletWrite': return ['name', 'status', 'destinationSaved']
    case 'servicesSave': return ['name', 'status', 'plugins', 'restartRequired']
    case 'composeSafety': return ['name', 'status', 'composePath']
    case 'firstBoot': return ['name', 'status', 'dashboard', 'setup', 'serviceCatalog', 'dashboardUiHardening', 'dynamicPayoutControls', 'serviceInlinePlanState', 'appProxyWrites', 'leasePollingBounded', 'dashboardStaticMarkupSafe', 'setupUiHardening', 'dashboardLinkAppPath', 'setupStaticMarkupSafe', 'acceptMode', 'healthVersion']
    case 'secondBoot': return ['name', 'status', 'dashboard', 'setup', 'serviceCatalog', 'dashboardUiHardening', 'dynamicPayoutControls', 'serviceInlinePlanState', 'appProxyWrites', 'leasePollingBounded', 'dashboardStaticMarkupSafe', 'setupUiHardening', 'dashboardLinkAppPath', 'setupStaticMarkupSafe', 'acceptMode', 'healthVersion']
    case 'identityPersistence': return ['name', 'status', 'publicKeyStable']
    case 'walletPersistence': return ['name', 'status', 'destinationPersisted']
    case 'servicesPersistence': return ['name', 'status', 'selectedServicesActive', 'plugins', 'active']
    default: return ['name', 'status']
  }
}

function verifySmokeCriticalChecks (kind, byName, expectedVersion) {
  requireSmokeBoolean(kind, byName, 'dashboardWebSocket', 'queryTokenRejected')
  requireSmokeBoolean(kind, byName, 'dashboardWebSocket', 'inBandAuth')
  requireSmokeBoolean(kind, byName, 'dashboardWebSocket', 'updateReceived')
  requireSmokeValue(kind, byName, 'acceptModeDefault', 'mode', 'review')
  requireSmokeBoolean(kind, byName, 'walletWrite', 'destinationSaved')
  verifySmokeUsageTelemetry(kind, byName)

  if (kind === 'release-image-smoke') {
    requireSmokeBoolean(kind, byName, 'dashboard', 'serviceManager')
    requireSmokeBoolean(kind, byName, 'dashboard', 'walletControls')
    requireSmokeBoolean(kind, byName, 'dashboard', 'tokenMeta')
    requireSmokeBoolean(kind, byName, 'dashboard', 'walletBusyState')
    requireSmokeBoolean(kind, byName, 'dashboard', 'dynamicPayoutControls')
    requireSmokeBoolean(kind, byName, 'dashboard', 'serviceActionState')
    requireSmokeBoolean(kind, byName, 'dashboard', 'serviceInlinePlanState')
    requireSmokeBoolean(kind, byName, 'dashboard', 'aiModelAddState')
    requireSmokeBoolean(kind, byName, 'dashboard', 'appProxyWrites')
    requireSmokeBoolean(kind, byName, 'dashboard', 'leasePollingBounded')
    requireSmokeBoolean(kind, byName, 'dashboard', 'staticMarkupSafe')
    requireSmokeBoolean(kind, byName, 'setupWizard', 'editMode')
    requireSmokeBoolean(kind, byName, 'setupWizard', 'statusRegion')
    requireSmokeBoolean(kind, byName, 'setupWizard', 'actionLock')
    requireSmokeBoolean(kind, byName, 'setupWizard', 'dashboardLinkAppPath')
    requireSmokeBoolean(kind, byName, 'setupWizard', 'staticMarkupSafe')
    requireSmokeBoolean(kind, byName, 'dashboardToken', 'exposedViaMeta')
    requireSmokeValue(kind, byName, 'health', 'version', expectedVersion)
    return
  }

  if (kind !== 'umbrel-package-smoke') return
  requireSmokeValue(kind, byName, 'composeSafety', 'composePath', 'umbrel-app/docker-compose.yml')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'dashboard')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'setup')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'serviceCatalog')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'dashboardUiHardening')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'dynamicPayoutControls')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'serviceInlinePlanState')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'appProxyWrites')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'leasePollingBounded')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'dashboardStaticMarkupSafe')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'setupUiHardening')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'dashboardLinkAppPath')
  requireSmokeBoolean(kind, byName, 'firstBoot', 'setupStaticMarkupSafe')
  requireSmokeValue(kind, byName, 'firstBoot', 'acceptMode', 'review')
  requireSmokeValue(kind, byName, 'firstBoot', 'healthVersion', expectedVersion)
  requireSmokeBoolean(kind, byName, 'secondBoot', 'dashboard')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'setup')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'serviceCatalog')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'dashboardUiHardening')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'dynamicPayoutControls')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'serviceInlinePlanState')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'appProxyWrites')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'leasePollingBounded')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'dashboardStaticMarkupSafe')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'setupUiHardening')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'dashboardLinkAppPath')
  requireSmokeBoolean(kind, byName, 'secondBoot', 'setupStaticMarkupSafe')
  requireSmokeValue(kind, byName, 'secondBoot', 'acceptMode', 'review')
  requireSmokeValue(kind, byName, 'secondBoot', 'healthVersion', expectedVersion)
  requireSmokeBoolean(kind, byName, 'identityPersistence', 'publicKeyStable')
  requireSmokeBoolean(kind, byName, 'walletPersistence', 'destinationPersisted')
}

function requireSmokeBoolean (kind, byName, checkName, field) {
  const check = byName.get(checkName)
  if (!check) return
  requireEqual(`${kind} ${checkName} ${field}`, check[field], true)
}

function requireSmokeValue (kind, byName, checkName, field, expected) {
  const check = byName.get(checkName)
  if (!check) return
  requireEqual(`${kind} ${checkName} ${field}`, check[field], expected)
}

function verifySmokeUsageTelemetry (kind, byName) {
  const check = byName.get('usageTelemetry')
  if (!check) return
  requireBoolean(`${kind} usageTelemetry bandwidth enabled`, check.bandwidth?.enabled)
  requireNonNegativeNumber(`${kind} usageTelemetry bandwidth count`, check.bandwidth?.count)
  requireNonNegativeNumber(`${kind} usageTelemetry bandwidth bytes`, check.bandwidth?.bytes)
  requireNonNegativeNumber(`${kind} usageTelemetry bandwidth bandwidthBytes`, check.bandwidth?.bandwidthBytes)
  requireBoolean(`${kind} usageTelemetry poker enabled`, check.poker?.enabled)
  requireNonNegativeNumber(`${kind} usageTelemetry poker tables`, check.poker?.tables)
  requireNonNegativeNumber(`${kind} usageTelemetry poker appends`, check.poker?.appends)
  requireNonNegativeNumber(`${kind} usageTelemetry poker seats`, check.poker?.seats)
}

function verifySmokeServiceChecks (kind, byName) {
  const servicesSave = byName.get('servicesSave')
  if (!servicesSave) return
  requireEqual(`${kind} servicesSave restartRequired`, servicesSave.restartRequired, true)
  requireArrayEqual(`${kind} servicesSave plugins`, servicesSave.plugins, EXPECTED_SMOKE_SERVICE_PLUGINS)

  const serviceCatalog = byName.get('serviceCatalog')
  if (serviceCatalog) {
    requireArrayIncludes(`${kind} serviceCatalog builtIns`, serviceCatalog.builtIns, ['poker', 'vrf'])
    requireArrayIncludes(`${kind} serviceCatalog bundles`, serviceCatalog.bundles, ['poker'])
  }

  if (kind !== 'umbrel-package-smoke') return
  const servicesPersistence = byName.get('servicesPersistence')
  if (!servicesPersistence) return
  requireEqual(`${kind} servicesPersistence selectedServicesActive`, servicesPersistence.selectedServicesActive, true)
  requireArrayEqual(`${kind} servicesPersistence plugins`, servicesPersistence.plugins, EXPECTED_SMOKE_SERVICE_PLUGINS)
  requireArrayEqual(`${kind} servicesPersistence active`, servicesPersistence.active, EXPECTED_SMOKE_SERVICE_PLUGINS)
}

function releaseBaseUrl (release) {
  return `https://github.com/${release.release.workflow.repository}/releases/download/${release.release.version}`
}

function expectedImageRef (body) {
  return `${body.image.name}:${body.release.semver}@${body.image.digest}`
}

function prNumberFromUrl (value) {
  const match = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/([1-9][0-9]*)$/.exec(value)
  return match ? match[1] : ''
}

function headRefFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(index + 1)
}

function headOwnerFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(0, index)
}

function requireGitHubOwnerName (label, value) {
  if (isGitHubOwnerName(value)) return
  die(`${label} must be a normal GitHub owner name and must not be getumbrel; got ${JSON.stringify(value)}`)
}

function isGitHubOwnerName (value) {
  return typeof value === 'string' &&
    value.toLowerCase() !== 'getumbrel' &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value)
}

function requireGitHubHeadRefName (label, value) {
  if (isGitHubHeadRefName(value)) return
  die(`${label} must be a normal GitHub branch name; got ${JSON.stringify(value)}`)
}

function isGitHubHeadRefName (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false
  if (!/^[A-Za-z0-9._/-]+$/.test(value)) return false
  if (value === '@' || value.startsWith('/') || value.endsWith('/') || value.startsWith('-') || value.endsWith('.')) return false
  if (value.includes('//') || value.includes('..') || value.includes('@{')) return false
  const parts = value.split('/')
  return parts.every(part => part && !part.startsWith('.') && !part.startsWith('-') && !part.endsWith('.lock'))
}

function forbidPresent (label, file) {
  if (!file || !fs.existsSync(file)) return
  die(`Prerelease bundle must not include ${label}: ${file}`)
}

function readRequiredJson (file, label) {
  requireFile(file, label)
  return readJson(file, label)
}

function requireFile (file, label) {
  if (file && fs.existsSync(file)) {
    assertRegularFile(file, label)
    return file
  }
  die(`${label} file is required; got ${JSON.stringify(file || '')}`)
}

function assertPublicSafe (value, label) {
  const forbiddenKeys = new Set([
    'authorization',
    'bearer',
    'gh_token',
    'password',
    'pem',
    'privatekey',
    'secret',
    'sshkey',
    'token'
  ])
  visit(value)

  function visit (node) {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (const item of node) visit(item)
      return
    }
    for (const [key, child] of Object.entries(node)) {
      if (forbiddenKeys.has(key.toLowerCase())) die(`${label} must not expose ${key}`)
      assertPublicSafeString(child, label, key)
      visit(child)
    }
  }
}

function assertNoRawPublicKeyFields (body, label) {
  visit(body, '$')

  function visit (node, at) {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    for (const [key, child] of Object.entries(node)) {
      if (/publicKey/i.test(key) && !isAllowedPublicKeyHashField(key)) {
        die(`${label} must not expose raw public key fields at ${at}.${key}`)
      }
      visit(child, `${at}.${key}`)
    }
  }
}

function isAllowedPublicKeyHashField (key) {
  return key === 'publicKeySha256' ||
    key === 'publicKeyBeforeSha256' ||
    key === 'publicKeyAfterSha256'
}

function assertPublicSafeString (value, label, at) {
  if (typeof value !== 'string') return
  if (hasControlChars(value)) die(`${label} must not contain control characters at ${at}`)
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) die(`${label} must not expose ${name} at ${at}`)
  }
  if (!/^https?:\/\//i.test(value)) return
  try {
    const url = new URL(value)
    if (url.username || url.password) die(`${label} must not expose URL credentials at ${at}`)
  } catch (_) {}
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 32 || code === 127) return true
  }
  return false
}

function readJson (file, label) {
  try {
    return JSON.parse(readRegularFile(file, label, 'utf8', MAX_EVIDENCE_JSON_BYTES))
  } catch (err) {
    die(`Could not read ${label} from ${file}: ${err.message}`)
  }
}

function sha256File (file, label = 'hashed file', maxBytes = Infinity) {
  try {
    return crypto.createHash('sha256').update(readRegularFile(file, label, undefined, maxBytes)).digest('hex')
  } catch (err) {
    die(`Could not hash ${file}: ${err.message}`)
  }
}

async function sha256LargeFile (file, label = 'hashed file') {
  try {
    assertRegularFile(file, label)
    return await sha256FileStream(file)
  } catch (err) {
    die(`Could not hash ${file}: ${err.message}`)
  }
}

function sha256FileStream (file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(file)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('error', reject)
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

function readRegularFile (file, label, encoding, maxBytes = Infinity) {
  assertRegularFile(file, label)
  const stat = fs.lstatSync(file)
  if (stat.size > maxBytes) die(`${label} file must be ${maxBytes} bytes or smaller: ${file} is ${stat.size} bytes`)
  return fs.readFileSync(file, encoding)
}

function assertRegularFile (file, label) {
  const stat = fs.lstatSync(file)
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${file}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${file}`)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function requireBoolean (label, actual) {
  if (typeof actual === 'boolean') return
  die(`${label} must be a boolean; got ${JSON.stringify(actual)}`)
}

function validatePublicGatewayBinding (body) {
  const gateway = body.release?.publicGateway
  if (gateway == null) return false
  requireBoolean('release public gateway enabled', gateway.enabled)
  requireOneOf('release public gateway manifest status', gateway.manifestStatus, [
    'enabled',
    'disabled',
    'missing',
    'not-applicable'
  ])
  requireEqual('release public gateway manifest path', gateway.manifestPath, 'fleet/public-hive-gateway-release.json')
  requireEqual('release public gateway target', gateway.releaseTarget, body.release.version)
  requireEqual('release public gateway commit', gateway.commitSha, body.release.tagSha)

  if (gateway.enabled) {
    requireEqual('enabled release public gateway manifest status', gateway.manifestStatus, 'enabled')
    requirePattern('enabled release public gateway manifest SHA-256', gateway.manifestSha256, /^[a-f0-9]{64}$/)
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(gateway.admissionProfile || '') ||
        gateway.admissionProfile.startsWith('transitional-')) {
      die('enabled release public gateway admission profile must be bounded and frozen')
    }
    requireIntegerRange('enabled release public gateway cohort size', gateway.cohortSize, 1, 128)
    return true
  }

  requireOneOf('disabled release public gateway manifest status', gateway.manifestStatus, [
    'disabled',
    'missing',
    'not-applicable'
  ])
  if (gateway.manifestStatus === 'disabled') {
    requirePattern('disabled release public gateway manifest SHA-256', gateway.manifestSha256, /^[a-f0-9]{64}$/)
  } else {
    requireEqual('absent release public gateway manifest SHA-256', gateway.manifestSha256, '')
  }
  requireEqual('disabled release public gateway admission profile', gateway.admissionProfile, '')
  requireEqual('disabled release public gateway cohort size', gateway.cohortSize, 0)
  return false
}

function isEnabledPublicGatewayRelease (body) {
  return body.release?.publicGateway?.enabled === true
}

function requireNonNegativeNumber (label, actual) {
  if (typeof actual === 'number' && Number.isFinite(actual) && actual >= 0) return
  die(`${label} must be a non-negative number; got ${JSON.stringify(actual)}`)
}

function requireIntegerRange (label, actual, min, max) {
  if (Number.isSafeInteger(actual) && actual >= min && actual <= max) return
  die(`${label} must be an integer between ${min} and ${max}; got ${JSON.stringify(actual)}`)
}

function requireLoopbackApiBase (label, value) {
  if (typeof value !== 'string' || !value) {
    die(`${label} must be a loopback http(s) base URL; got ${JSON.stringify(value)}`)
  }
  try {
    const url = new URL(value)
    if ((url.protocol === 'http:' || url.protocol === 'https:') &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      isLoopbackHostname(url.hostname)) {
      return
    }
  } catch (_) {}
  die(`${label} must be a loopback http(s) base URL; got ${JSON.stringify(value)}`)
}

function isLoopbackHostname (hostname) {
  const host = String(hostname || '').toLowerCase()
  return host === 'localhost' ||
    host === '::1' ||
    host === '[::1]' ||
    host === '0:0:0:0:0:0:0:1' ||
    isLoopbackIpv4(host)
}

function isLoopbackIpv4 (host) {
  const parts = host.split('.')
  return parts.length === 4 &&
    parts[0] === '127' &&
    parts.slice(1).every((part) => /^[0-9]{1,3}$/.test(part) && Number(part) <= 255)
}

function requireArrayEqual (label, actual, expected) {
  if (Array.isArray(actual) && actual.length === expected.length && actual.every((value, index) => value === expected[index])) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireArrayIncludes (label, actual, expected) {
  if (Array.isArray(actual) && expected.every(value => actual.includes(value))) return
  die(`${label} must include ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireOneOf (label, value, allowed) {
  if (allowed.includes(value)) return
  die(`${label} must be ${allowed.join(' or ')}; got ${JSON.stringify(value)}`)
}

function requireAllowedChannel (label, value, releaseChannel) {
  if (releaseChannel === 'both') {
    requireOneOf(label, value, ['canary', 'stable'])
    return
  }
  requireOneOf(label, value, [releaseChannel])
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
  die(`${label} is required and malformed; got ${JSON.stringify(value)}`)
}

function requireSafePublicLabel (label, value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 120) {
    die(`${label} is required and must be 1-120 public-safe characters; got ${JSON.stringify(value)}`)
  }
  if (LOCAL_ADDRESS_PATTERN.test(value)) {
    die(`${label} must not include local hostnames or LAN addresses; got ${JSON.stringify(value)}`)
  }
}

function requireIsoTimestamp (label, value) {
  requirePattern(label, value, ISO_TIMESTAMP_PATTERN)
  const timestamp = Date.parse(value)
  if (Number.isFinite(timestamp)) return timestamp
  die(`${label} must be a valid ISO timestamp; got ${JSON.stringify(value)}`)
}

function requirePublicHttpsUrl (label, value) {
  if (isPublicHttpsUrl(value)) return
  die(`${label} must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames; got ${JSON.stringify(value)}`)
}

function requireRegistryPackageUrl (label, value, registryUrl, packageId) {
  if (isRegistryPackageUrl(value, registryUrl, packageId)) return
  die(`${label} must be the public registry URL plus the StartOS package id; got ${JSON.stringify(value)}`)
}

function registryPackageUrl (registryUrl, packageId) {
  if (!registryUrl || !packageId) return ''
  try {
    const url = new URL(registryUrl)
    const basePath = url.pathname.replace(/\/+$/, '')
    url.pathname = `${basePath}/${packageId}`
    url.search = ''
    url.hash = ''
    return url.toString()
  } catch (_) {
    return ''
  }
}

function isRegistryPackageUrl (value, registryUrl, packageId) {
  if (!isPublicHttpsUrl(value) || !isPublicHttpsUrl(registryUrl)) return false
  if (typeof packageId !== 'string' || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(packageId)) return false
  try {
    const actual = new URL(value)
    const expected = new URL(registryPackageUrl(registryUrl, packageId))
    return actual.href === expected.href
  } catch (_) {
    return false
  }
}

function isPublicHttpsUrl (value) {
  if (typeof value !== 'string' || !value || value.trim() !== value) return false
  try {
    const url = new URL(value)
    return url.protocol === 'https:' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      isPublicHostname(url.hostname)
  } catch (_) {
    return false
  }
}

function isPublicHostname (hostname) {
  const host = String(hostname || '').toLowerCase()
  if (!/^[a-z0-9.-]+$/.test(host)) return false
  if (!host.includes('.')) return false
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false

  const labels = host.split('.')
  if (labels.some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return false
  const tld = labels[labels.length - 1]
  if (!/^[a-z]{2,63}$/.test(tld)) return false

  const reservedHosts = new Set(['localhost', 'example.com', 'example.net', 'example.org'])
  if (reservedHosts.has(host)) return false
  const reservedSuffixes = ['.localhost', '.local', '.internal', '.test', '.example', '.invalid', '.example.com', '.example.net', '.example.org']
  return !reservedSuffixes.some(suffix => host.endsWith(suffix))
}

function die (message) {
  console.error(message)
  process.exit(1)
}
