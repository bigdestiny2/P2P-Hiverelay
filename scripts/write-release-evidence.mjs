#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const usage = `
Usage:
  node scripts/write-release-evidence.mjs [--out release-evidence.json]
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
const EXPECTED_RELEASE_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const GITHUB_ACTIONS_RUN_URL_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/[1-9][0-9]*$/
const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')
const args = parseArgs(process.argv.slice(2))
const outFile = path.resolve(args.out || process.env.HIVERELAY_RELEASE_EVIDENCE || 'release-evidence.json')

const version = env('HIVERELAY_RELEASE_VERSION')
const semver = env('HIVERELAY_RELEASE_SEMVER') || version.replace(/^v/, '')
const imageName = env('HIVERELAY_IMAGE_NAME') || env('IMAGE_NAME')
const imageDigest = env('HIVERELAY_IMAGE_DIGEST')
const releaseSha = env('HIVERELAY_RELEASE_SHA')
const metadataSha = env('HIVERELAY_RELEASE_SURFACES_SHA') || gitRevParse('HEAD')
const repository = env('GITHUB_REPOSITORY')
const runId = env('GITHUB_RUN_ID')
const fleetChannelConfigPath = env('HIVERELAY_FLEET_CHANNEL_CONFIG') ||
  (env('HIVERELAY_RELEASE_CHANNEL') && env('HIVERELAY_RELEASE_CHANNEL') !== 'none' ? 'fleet/channels.json' : '')

const evidence = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  release: {
    version,
    semver,
    channel: env('HIVERELAY_RELEASE_CHANNEL'),
    prerelease: env('HIVERELAY_RELEASE_PRERELEASE') === 'true',
    tagSha: releaseSha,
    metadataSha,
    workflow: {
      status: env('HIVERELAY_WORKFLOW_STATUS') || env('JOB_STATUS') || 'unknown',
      repository,
      runId,
      runAttempt: env('GITHUB_RUN_ATTEMPT'),
      runUrl: repository && runId
        ? `${env('GITHUB_SERVER_URL') || 'https://github.com'}/${repository}/actions/runs/${runId}`
        : ''
    }
  },
  image: {
    name: imageName,
    digest: imageDigest,
    ref: imageName && semver && imageDigest ? `${imageName}:${semver}@${imageDigest}` : ''
  },
  artifacts: {
    startosPackage: {
      path: 'startos/blindspark.s9pk',
      sha256: env('HIVERELAY_STARTOS_PACKAGE_SHA256')
    }
  },
  gates: {
    auditAndUnit: status('HIVERELAY_RELEASE_GATE_STATUS'),
    distributionPreflight: status('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS'),
    imageManifest: status('HIVERELAY_RELEASE_IMAGE_MANIFEST_STATUS'),
    imageManifestEvidence: {
      path: env('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE'),
      sha256: env('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256')
    },
    pushedImageSmoke: status('HIVERELAY_RELEASE_IMAGE_SMOKE_STATUS'),
    pushedImageSmokeEvidence: {
      path: env('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE'),
      sha256: env('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256')
    },
    umbrelPackageSmoke: status('HIVERELAY_UMBREL_SMOKE_STATUS'),
    umbrelPackageSmokeEvidence: {
      path: env('HIVERELAY_UMBREL_SMOKE_EVIDENCE'),
      sha256: env('HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256')
    },
    startosVerify: status('HIVERELAY_STARTOS_VERIFY_STATUS')
  },
  surfaces: {
    metadataCommit: status('HIVERELAY_RELEASE_SURFACES_STATUS'),
    startosReleaseAsset: status('HIVERELAY_STARTOS_RELEASE_ASSET_STATUS'),
    fleetRollout: status('HIVERELAY_FLEET_ROLLOUT_STATUS'),
    fleetRolloutChannel: env('HIVERELAY_FLEET_ROLLOUT_CHANNEL'),
    fleetRolloutEvidence: {
      path: env('HIVERELAY_FLEET_ROLLOUT_EVIDENCE'),
      sha256: env('HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256')
    },
    fleetChannelConfig: {
      path: fleetChannelConfigPath,
      sha256: env('HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256') || sha256FileIfPresent(fleetChannelConfigPath)
    },
    startosRegistry: status('HIVERELAY_STARTOS_REGISTRY_STATUS'),
    startosRegistryUrl: env('HIVERELAY_STARTOS_REGISTRY_URL') || env('STARTOS_REGISTRY_URL'),
    startosRegistryPackageUrl: env('HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL') || env('STARTOS_REGISTRY_PACKAGE_URL'),
    startosPackageId: env('HIVERELAY_STARTOS_PACKAGE_ID'),
    startosRegistryEvidence: {
      path: env('HIVERELAY_STARTOS_REGISTRY_EVIDENCE'),
      sha256: env('HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256')
    },
    umbrelOfficial: {
      status: status('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS'),
      prUrl: env('HIVERELAY_UMBREL_OFFICIAL_PR_URL'),
      head: env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD'),
      headSha: env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA'),
      state: env('HIVERELAY_UMBREL_OFFICIAL_PR_STATE'),
      isDraft: booleanEnv('HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT'),
      base: env('HIVERELAY_UMBREL_OFFICIAL_PR_BASE'),
      headOwner: env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER'),
      headRef: env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF'),
      headOid: env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID')
    },
    umbrelCommunityStore: {
      validation: status('HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS'),
      publish: status('HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS'),
      commit: env('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT'),
      commitUrl: env('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT_URL')
    }
  }
}

await validateEvidence(evidence)
writeJson(outFile, evidence)
console.log(`Release evidence written to ${outFile}`)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--out') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) die('Missing value for --out')
      out.out = value
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function env (name) {
  return String(process.env[name] ?? '')
}

function status (name) {
  return env(name) || 'unknown'
}

function booleanEnv (name) {
  const value = env(name)
  if (!value) return null
  if (value === 'true') return true
  if (value === 'false') return false
  die(`${name} must be true or false when set`)
}

function gitRevParse (ref) {
  const result = spawnSync('git', ['rev-parse', ref], {
    cwd: repoRoot,
    encoding: 'utf8'
  })
  if (result.status !== 0) return ''
  return result.stdout.trim()
}

async function validateEvidence (body) {
  assertPublicSafeValues(body, 'release evidence')
  requireEqual('release evidence schemaVersion', body.schemaVersion, 1)
  requirePattern('release evidence generatedAt', body.generatedAt, ISO_TIMESTAMP_PATTERN)
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(body.release.version)) {
    die('HIVERELAY_RELEASE_VERSION must be a v-prefixed semver tag')
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(body.release.semver)) {
    die('HIVERELAY_RELEASE_SEMVER must be semver')
  }
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  if (body.release.tagSha && !/^[a-f0-9]{40}$/i.test(body.release.tagSha)) {
    die('HIVERELAY_RELEASE_SHA must be a 40-character commit SHA')
  }
  if (body.release.metadataSha && !/^[a-f0-9]{40}$/i.test(body.release.metadataSha)) {
    die('HIVERELAY_RELEASE_SURFACES_SHA must be a 40-character commit SHA')
  }
  if (body.image.digest && !/^sha256:[a-f0-9]{64}$/i.test(body.image.digest)) {
    die('HIVERELAY_IMAGE_DIGEST must be sha256:<64 hex chars>')
  }
  if (body.artifacts.startosPackage.sha256 && !/^[a-f0-9]{64}$/i.test(body.artifacts.startosPackage.sha256)) {
    die('HIVERELAY_STARTOS_PACKAGE_SHA256 must be 64 hex characters')
  }
  if (body.gates.pushedImageSmokeEvidence.sha256 && !/^[a-f0-9]{64}$/i.test(body.gates.pushedImageSmokeEvidence.sha256)) {
    die('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256 must be 64 hex characters')
  }
  if (body.gates.imageManifestEvidence.sha256 && !/^[a-f0-9]{64}$/i.test(body.gates.imageManifestEvidence.sha256)) {
    die('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256 must be 64 hex characters')
  }
  if (body.gates.umbrelPackageSmokeEvidence.sha256 && !/^[a-f0-9]{64}$/i.test(body.gates.umbrelPackageSmokeEvidence.sha256)) {
    die('HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256 must be 64 hex characters')
  }
  if (body.surfaces.fleetRolloutEvidence.sha256 && !/^[a-f0-9]{64}$/i.test(body.surfaces.fleetRolloutEvidence.sha256)) {
    die('HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256 must be 64 hex characters')
  }
  if (body.surfaces.fleetChannelConfig.sha256 && !/^[a-f0-9]{64}$/i.test(body.surfaces.fleetChannelConfig.sha256)) {
    die('HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256 must be 64 hex characters')
  }
  if (body.surfaces.startosRegistryEvidence.sha256 && !/^[a-f0-9]{64}$/i.test(body.surfaces.startosRegistryEvidence.sha256)) {
    die('HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256 must be 64 hex characters')
  }
  if (body.surfaces.umbrelOfficial.headSha && !/^[a-f0-9]{40}$/i.test(body.surfaces.umbrelOfficial.headSha)) {
    die('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA must be a 40-character commit SHA')
  }
  if (body.surfaces.umbrelCommunityStore.commit && !/^[a-f0-9]{40}$/i.test(body.surfaces.umbrelCommunityStore.commit)) {
    die('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT must be a 40-character commit SHA')
  }
  if (body.surfaces.startosRegistryUrl && !isPublicHttpsUrl(body.surfaces.startosRegistryUrl)) {
    die('HIVERELAY_STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames')
  }
  if (body.surfaces.startosRegistryPackageUrl && !isRegistryPackageUrl(body.surfaces.startosRegistryPackageUrl, body.surfaces.startosRegistryUrl, body.surfaces.startosPackageId)) {
    die('HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL must be the public registry URL plus the StartOS package id')
  }
  await validateSuccessfulRun(body)
}

async function validateSuccessfulRun (body) {
  if (body.release.workflow.status !== 'success') return

  requirePattern('successful release workflow repository', body.release.workflow.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requireEqual('successful release workflow repository', body.release.workflow.repository, EXPECTED_RELEASE_REPOSITORY)
  requirePattern('successful release workflow run id', body.release.workflow.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('successful release workflow run attempt', body.release.workflow.runAttempt, POSITIVE_INTEGER_PATTERN)
  requirePattern('successful release workflow URL', body.release.workflow.runUrl, GITHUB_ACTIONS_RUN_URL_PATTERN)
  requirePattern('successful release tag SHA', body.release.tagSha, /^[a-f0-9]{40}$/i)
  requirePattern('successful release metadata SHA', body.release.metadataSha, /^[a-f0-9]{40}$/i)
  requirePattern('successful release image name', body.image.name, /^ghcr\.io\/[A-Za-z0-9_.-]+\/[A-Za-z0-9._/-]+$/)
  requireEqual('successful release image name', body.image.name, EXPECTED_RELEASE_IMAGE_NAME)
  requirePattern('successful release image digest', body.image.digest, /^sha256:[a-f0-9]{64}$/i)
  requireEqual('successful release image ref', body.image.ref, expectedImageRef(body))
  requireEqual('successful release StartOS package path', body.artifacts.startosPackage.path, 'startos/blindspark.s9pk')
  requirePattern('successful release StartOS package SHA-256', body.artifacts.startosPackage.sha256, /^[a-f0-9]{64}$/i)
  await verifyPresentStartosPackage(body)
  requireOneOf('successful release audit/unit gate', body.gates.auditAndUnit, ['passed'])
  requireOneOf('successful release image manifest gate', body.gates.imageManifest, ['passed'])
  requireOneOf('successful release image manifest evidence path', body.gates.imageManifestEvidence.path, ['release-image-manifest-evidence.json'])
  requirePattern('successful release image manifest evidence SHA-256', body.gates.imageManifestEvidence.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful release image smoke gate', body.gates.pushedImageSmoke, ['passed'])
  requireOneOf('successful release image smoke evidence path', body.gates.pushedImageSmokeEvidence.path, ['release-image-smoke-evidence.json'])
  requirePattern('successful release image smoke evidence SHA-256', body.gates.pushedImageSmokeEvidence.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful release Umbrel package smoke gate', body.gates.umbrelPackageSmoke, ['passed'])
  requireOneOf('successful release Umbrel package smoke evidence path', body.gates.umbrelPackageSmokeEvidence.path, ['umbrel-package-smoke-evidence.json'])
  requirePattern('successful release Umbrel package smoke evidence SHA-256', body.gates.umbrelPackageSmokeEvidence.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful release StartOS verify gate', body.gates.startosVerify, ['passed'])
  requireOneOf('successful release StartOS GitHub Release asset', body.surfaces.startosReleaseAsset, ['uploaded'])

  if (body.release.prerelease) {
    requireOneOf('successful prerelease channel', body.release.channel, ['none'])
    requireOneOf('successful prerelease distribution preflight', body.gates.distributionPreflight, ['skipped'])
    requireOneOf('successful prerelease metadata surfaces', body.surfaces.metadataCommit, ['skipped'])
    requireOneOf('successful prerelease fleet rollout', body.surfaces.fleetRollout, ['skipped'])
    requireOneOf('successful prerelease fleet rollout channel', body.surfaces.fleetRolloutChannel || 'skipped', ['skipped'])
    requireOneOf('successful prerelease fleet rollout evidence path', body.surfaces.fleetRolloutEvidence.path || 'skipped', ['skipped'])
    requireOneOf('successful prerelease fleet rollout evidence hash', body.surfaces.fleetRolloutEvidence.sha256 || 'skipped', ['skipped'])
    requireOneOf('successful prerelease fleet channel config path', body.surfaces.fleetChannelConfig.path || 'skipped', ['skipped'])
    requireOneOf('successful prerelease fleet channel config hash', body.surfaces.fleetChannelConfig.sha256 || 'skipped', ['skipped'])
    requireOneOf('successful prerelease StartOS registry publish', body.surfaces.startosRegistry, ['skipped'])
    requireOneOf('successful prerelease StartOS registry URL', body.surfaces.startosRegistryUrl || 'skipped', ['skipped'])
    requireOneOf('successful prerelease StartOS registry package URL', body.surfaces.startosRegistryPackageUrl || 'skipped', ['skipped'])
    requireOneOf('successful prerelease StartOS package id', body.surfaces.startosPackageId || 'skipped', ['skipped'])
    requireOneOf('successful prerelease StartOS registry evidence path', body.surfaces.startosRegistryEvidence.path || 'skipped', ['skipped'])
    requireOneOf('successful prerelease StartOS registry evidence hash', body.surfaces.startosRegistryEvidence.sha256 || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR', body.surfaces.umbrelOfficial.status, ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR URL', body.surfaces.umbrelOfficial.prUrl || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR head', body.surfaces.umbrelOfficial.head || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR head SHA', body.surfaces.umbrelOfficial.headSha || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR state', body.surfaces.umbrelOfficial.state || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR draft', body.surfaces.umbrelOfficial.isDraft == null ? 'skipped' : String(body.surfaces.umbrelOfficial.isDraft), ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR base', body.surfaces.umbrelOfficial.base || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR head owner', body.surfaces.umbrelOfficial.headOwner || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR head ref', body.surfaces.umbrelOfficial.headRef || 'skipped', ['skipped'])
    requireOneOf('successful prerelease official Umbrel PR head OID', body.surfaces.umbrelOfficial.headOid || 'skipped', ['skipped'])
    requireOneOf('successful prerelease Umbrel community-store validation', body.surfaces.umbrelCommunityStore.validation, ['skipped'])
    requireOneOf('successful prerelease Umbrel community-store publish', body.surfaces.umbrelCommunityStore.publish, ['skipped'])
    requireOneOf('successful prerelease Umbrel community-store commit', body.surfaces.umbrelCommunityStore.commit || 'skipped', ['skipped'])
    requireOneOf('successful prerelease Umbrel community-store commit URL', body.surfaces.umbrelCommunityStore.commitUrl || 'skipped', ['skipped'])
    await verifyPresentEvidenceFiles(body, false)
    return
  }

  requireOneOf('successful full release channel', body.release.channel, ['canary', 'stable', 'both'])
  requireOneOf('successful full release distribution preflight', body.gates.distributionPreflight, ['passed'])
  requireOneOf('successful full release metadata surfaces', body.surfaces.metadataCommit, ['committed', 'current'])
  requireOneOf('successful full release fleet rollout', body.surfaces.fleetRollout, ['verified'])
  requireOneOf('successful full release fleet rollout channel', body.surfaces.fleetRolloutChannel, [body.release.channel])
  requireOneOf('successful full release fleet rollout evidence path', body.surfaces.fleetRolloutEvidence.path, ['fleet-rollout-evidence.json'])
  requirePattern('successful full release fleet rollout evidence SHA-256', body.surfaces.fleetRolloutEvidence.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful full release fleet channel config path', body.surfaces.fleetChannelConfig.path, ['fleet/channels.json'])
  requirePattern('successful full release fleet channel config SHA-256', body.surfaces.fleetChannelConfig.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful full release StartOS registry publish', body.surfaces.startosRegistry, ['published'])
  requirePublicHttpsUrl('successful full release StartOS registry URL', body.surfaces.startosRegistryUrl)
  requirePattern('successful full release StartOS package id', body.surfaces.startosPackageId, /^[a-z0-9][a-z0-9-]{1,63}$/)
  requireRegistryPackageUrl('successful full release StartOS registry package URL', body.surfaces.startosRegistryPackageUrl, body.surfaces.startosRegistryUrl, body.surfaces.startosPackageId)
  requireOneOf('successful full release StartOS registry evidence path', body.surfaces.startosRegistryEvidence.path, ['startos-registry-evidence.json'])
  requirePattern('successful full release StartOS registry evidence SHA-256', body.surfaces.startosRegistryEvidence.sha256, /^[a-f0-9]{64}$/i)
  requireOneOf('successful full release official Umbrel PR', body.surfaces.umbrelOfficial.status, ['draft-pr-ready'])
  requirePattern('successful full release official Umbrel PR head', body.surfaces.umbrelOfficial.head, /^[A-Za-z0-9_.-]+:[A-Za-z0-9._/-]{1,128}$/)
  requirePattern('successful full release official Umbrel PR head SHA', body.surfaces.umbrelOfficial.headSha, /^[a-f0-9]{40}$/i)
  requireEqual('successful full release official Umbrel PR state', body.surfaces.umbrelOfficial.state, 'OPEN')
  requireEqual('successful full release official Umbrel PR draft', body.surfaces.umbrelOfficial.isDraft, true)
  requireEqual('successful full release official Umbrel PR base', body.surfaces.umbrelOfficial.base, 'master')
  requireGitHubOwnerName('successful full release official Umbrel PR head owner', body.surfaces.umbrelOfficial.headOwner)
  requireEqual('successful full release official Umbrel PR head owner matches head owner', body.surfaces.umbrelOfficial.headOwner, headOwnerFromHead(body.surfaces.umbrelOfficial.head))
  requireGitHubHeadRefName('successful full release official Umbrel PR head ref', body.surfaces.umbrelOfficial.headRef)
  requireEqual('successful full release official Umbrel PR head ref matches head branch', body.surfaces.umbrelOfficial.headRef, headRefFromHead(body.surfaces.umbrelOfficial.head))
  requirePattern('successful full release official Umbrel PR head OID', body.surfaces.umbrelOfficial.headOid, /^[a-f0-9]{40}$/i)
  requireEqual('successful full release official Umbrel PR head OID matches head SHA', body.surfaces.umbrelOfficial.headOid, body.surfaces.umbrelOfficial.headSha)
  requireOneOf('successful full release Umbrel community-store validation', body.surfaces.umbrelCommunityStore.validation, ['passed'])
  requireOneOf('successful full release Umbrel community-store publish', body.surfaces.umbrelCommunityStore.publish, ['pushed', 'current'])
  requirePattern('successful full release Umbrel community-store commit', body.surfaces.umbrelCommunityStore.commit, /^[a-f0-9]{40}$/i)
  requirePattern('successful full release Umbrel community-store commit URL', body.surfaces.umbrelCommunityStore.commitUrl, /^https:\/\/github\.com\/bigdestiny2\/blindspark-umbrel-store\/commit\/[a-f0-9]{40}$/i)

  const prUrl = body.surfaces.umbrelOfficial.prUrl
  if (!OFFICIAL_UMBREL_PR_URL_PATTERN.test(prUrl)) {
    die('successful full release official Umbrel PR URL must point to getumbrel/umbrel-apps')
  }
  await verifyPresentEvidenceFiles(body, true)
}

function headRefFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(index + 1)
}

function headOwnerFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(0, index)
}

function requireOneOf (label, value, allowed) {
  if (allowed.includes(value)) return
  die(`${label} must be ${allowed.join(' or ')}; got ${JSON.stringify(value)}`)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requirePattern (label, value, pattern) {
  if (pattern.test(value)) return
  die(`${label} is required and malformed; got ${JSON.stringify(value)}`)
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

function expectedImageRef (body) {
  return `${body.image.name}:${body.release.semver}@${body.image.digest}`
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

function assertPublicSafeValues (value, label) {
  visit(value, '$')

  function visit (node, at) {
    assertPublicSafeString(node, label, at)
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
  }
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

async function verifyPresentEvidenceFiles (body, fullRelease) {
  const sidecars = [
    ['release image manifest evidence', body.gates.imageManifestEvidence],
    ['release image smoke evidence', body.gates.pushedImageSmokeEvidence],
    ['Umbrel package smoke evidence', body.gates.umbrelPackageSmokeEvidence]
  ]
  if (fullRelease) {
    sidecars.push(
      ['fleet rollout evidence', body.surfaces.fleetRolloutEvidence],
      ['StartOS registry evidence', body.surfaces.startosRegistryEvidence]
    )
  }
  for (const [label, evidenceFile] of sidecars) {
    await verifyPresentEvidenceFile(label, evidenceFile.path, evidenceFile.sha256)
  }
}

async function verifyPresentStartosPackage (body) {
  const artifact = body.artifacts.startosPackage
  if (!artifact?.path || !artifact?.sha256) return
  if (artifact.path !== 'startos/blindspark.s9pk') {
    die(`StartOS package path must be startos/blindspark.s9pk; got ${JSON.stringify(artifact.path)}`)
  }
  await verifyPresentArtifactFile('StartOS package', artifact.path, artifact.sha256)
}

async function verifyPresentArtifactFile (label, relativePath, expectedSha256) {
  const file = localEvidenceFile(label, relativePath)
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (e) {
    if (e && e.code === 'ENOENT') die(`${label} file is required before writing successful release evidence: ${relativePath}`)
    throw e
  }
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${relativePath}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${relativePath}`)
  const actualSha256 = await sha256File(file)
  if (actualSha256 !== expectedSha256) {
    die(`${label} SHA-256 does not match ${relativePath}; expected ${expectedSha256}, got ${actualSha256}`)
  }
}

function sha256File (file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(file)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('error', reject)
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

async function verifyPresentEvidenceFile (label, relativePath, expectedSha256) {
  if (!relativePath || !expectedSha256) return
  const file = localEvidenceFile(label, relativePath)
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (e) {
    if (e && e.code === 'ENOENT') die(`${label} file is required before writing successful release evidence: ${relativePath}`)
    throw e
  }
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${relativePath}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${relativePath}`)
  if (stat.size > MAX_EVIDENCE_JSON_BYTES) {
    die(`${label} file must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller: ${relativePath} is ${stat.size} bytes`)
  }
  assertPublicSafeValues(readPublicEvidenceJson(label, file), label)
  const actualSha256 = await sha256File(file)
  if (actualSha256 !== expectedSha256) {
    die(`${label} SHA-256 does not match ${relativePath}; expected ${expectedSha256}, got ${actualSha256}`)
  }
}

function readPublicEvidenceJson (label, file) {
  try {
    const body = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (body == null || typeof body !== 'object' || Array.isArray(body)) {
      die(`${label} file must contain a JSON object`)
    }
    return body
  } catch (err) {
    if (err && err.name === 'SyntaxError') die(`${label} file must contain valid JSON: ${err.message}`)
    throw err
  }
}

function localEvidenceFile (label, relativePath) {
  if (
    typeof relativePath !== 'string' ||
    !relativePath ||
    path.isAbsolute(relativePath) ||
    path.normalize(relativePath) !== relativePath ||
    relativePath === '..' ||
    relativePath.startsWith(`..${path.sep}`)
  ) {
    die(`${label} path must be a plain relative path; got ${JSON.stringify(relativePath)}`)
  }
  return path.resolve(process.cwd(), relativePath)
}

function sha256FileIfPresent (relativePath) {
  if (!relativePath) return ''
  if (relativePath !== 'fleet/channels.json') {
    die(`fleet channel config path must be fleet/channels.json; got ${JSON.stringify(relativePath)}`)
  }
  const file = path.resolve(process.cwd(), relativePath)
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (e) {
    if (e && e.code === 'ENOENT') return ''
    throw e
  }
  if (stat.isSymbolicLink()) die(`fleet channel config file must not be a symlink: ${relativePath}`)
  if (!stat.isFile()) die(`fleet channel config file must be a regular file: ${relativePath}`)
  if (stat.size > MAX_EVIDENCE_JSON_BYTES) {
    die(`fleet channel config file must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller: ${relativePath} is ${stat.size} bytes`)
  }
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

function writeJson (file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n')
  fs.renameSync(tmp, file)
}

function die (message) {
  console.error(message)
  process.exit(1)
}
