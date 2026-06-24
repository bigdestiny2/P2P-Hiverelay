#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'

const usage = `
Usage:
  node scripts/write-official-umbrel-pr-evidence.mjs --out official-umbrel-pr-evidence.json
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

const EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const GITHUB_ACTIONS_RUN_URL_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/[1-9][0-9]*$/
const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024

const args = parseArgs(process.argv.slice(2))
const outFile = path.resolve(args.out || 'official-umbrel-pr-evidence.json')

const serverUrl = env('GITHUB_SERVER_URL') || 'https://github.com'
const repository = env('GITHUB_REPOSITORY')
const runId = env('GITHUB_RUN_ID')
const version = env('HIVERELAY_RELEASE_VERSION')
const semver = env('HIVERELAY_RELEASE_SEMVER') || version.replace(/^v/, '')
const prUrl = env('HIVERELAY_UMBREL_OFFICIAL_PR_URL')
const prHead = env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD')
const prHeadSha = env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA')
const prState = env('HIVERELAY_UMBREL_OFFICIAL_PR_STATE')
const prIsDraft = booleanEnv('HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT')
const prBase = env('HIVERELAY_UMBREL_OFFICIAL_PR_BASE')
const prHeadOwner = env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER')
const prHeadRef = env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF')
const prHeadOid = env('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID')
const startosRegistryPackageUrl = env('HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL') || env('STARTOS_REGISTRY_PACKAGE_URL')
const releaseBaseUrl = repository && version ? `${serverUrl}/${repository}/releases/download/${version}` : ''
const workflowUrl = repository && runId ? `${serverUrl}/${repository}/actions/runs/${runId}` : ''

const body = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  kind: 'official-umbrel-pr',
  status: 'updated',
  release: {
    version,
    semver
  },
  pr: {
    url: prUrl,
    number: prNumberFromUrl(prUrl),
    head: prHead,
    headSha: prHeadSha,
    state: prState,
    isDraft: prIsDraft,
    base: prBase,
    headOwner: prHeadOwner,
    headRef: prHeadRef,
    headOid: prHeadOid
  },
  workflow: {
    repository,
    runId,
    runAttempt: env('GITHUB_RUN_ATTEMPT'),
    runUrl: workflowUrl
  },
  runtimeReview: {
    status: 'pending-real-device-review',
    evidenceFile: 'umbrel-runtime-review-evidence.json',
    verifier: 'npm run umbrel:verify-runtime-review'
  },
  evidenceLinks: {
    releaseEvidence: `${releaseBaseUrl}/release-evidence.json`,
    releaseImageManifest: `${releaseBaseUrl}/release-image-manifest-evidence.json`,
    releaseImageSmoke: `${releaseBaseUrl}/release-image-smoke-evidence.json`,
    umbrelPackageSmoke: `${releaseBaseUrl}/umbrel-package-smoke-evidence.json`,
    fleetRollout: `${releaseBaseUrl}/fleet-rollout-evidence.json`,
    startosPackage: `${releaseBaseUrl}/blindspark.s9pk`,
    startosRegistryPackage: startosRegistryPackageUrl,
    startosRegistry: `${releaseBaseUrl}/startos-registry-evidence.json`,
    workflow: workflowUrl
  }
}

await validate(body)
writeJson(outFile, body)
console.log(`Official Umbrel PR evidence written to ${outFile}`)

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

async function validate (body) {
  assertPublicSafeValues(body, 'official Umbrel PR evidence')
  assertOfficialUmbrelPrEvidenceSchema(body)
  requireEqual('official Umbrel PR evidence schemaVersion', body.schemaVersion, 1)
  requirePattern('official Umbrel PR evidence generatedAt', body.generatedAt, ISO_TIMESTAMP_PATTERN)
  requireEqual('official Umbrel PR evidence kind', body.kind, 'official-umbrel-pr')
  requireEqual('official Umbrel PR evidence status', body.status, 'updated')
  requirePattern('release.version', body.release.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release.semver', body.release.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  requirePattern('official Umbrel PR URL', body.pr.url, OFFICIAL_UMBREL_PR_URL_PATTERN)
  requirePattern('official Umbrel PR number', body.pr.number, POSITIVE_INTEGER_PATTERN)
  requirePattern('official Umbrel PR head', body.pr.head, /^[A-Za-z0-9_.-]+:[A-Za-z0-9._/-]{1,128}$/)
  requirePattern('official Umbrel PR head SHA', body.pr.headSha, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR state', body.pr.state, 'OPEN')
  requireEqual('official Umbrel PR draft', body.pr.isDraft, true)
  requireEqual('official Umbrel PR base', body.pr.base, 'master')
  requireGitHubOwnerName('official Umbrel PR head owner', body.pr.headOwner)
  requireEqual('official Umbrel PR head owner matches head owner', body.pr.headOwner, headOwnerFromHead(body.pr.head))
  requireGitHubHeadRefName('official Umbrel PR head ref', body.pr.headRef)
  requireEqual('official Umbrel PR head ref matches head branch', body.pr.headRef, headRefFromHead(body.pr.head))
  requirePattern('official Umbrel PR head OID', body.pr.headOid, /^[a-f0-9]{40}$/i)
  requireEqual('official Umbrel PR head OID matches head SHA', body.pr.headOid, body.pr.headSha)
  requirePattern('workflow repository', body.workflow.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requireEqual('workflow repository', body.workflow.repository, EXPECTED_RELEASE_REPOSITORY)
  requirePattern('workflow run id', body.workflow.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('workflow run attempt', body.workflow.runAttempt, POSITIVE_INTEGER_PATTERN)
  requirePattern('workflow URL', body.workflow.runUrl, GITHUB_ACTIONS_RUN_URL_PATTERN)
  requireEqual('workflow URL matches repository and run id', body.workflow.runUrl, `https://github.com/${body.workflow.repository}/actions/runs/${body.workflow.runId}`)
  requireEqual('runtime review status', body.runtimeReview?.status, 'pending-real-device-review')
  requireEqual('runtime review evidence file', body.runtimeReview?.evidenceFile, 'umbrel-runtime-review-evidence.json')
  requireEqual('runtime review verifier', body.runtimeReview?.verifier, 'npm run umbrel:verify-runtime-review')
  const releaseBase = `https://github.com/${body.workflow.repository}/releases/download/${body.release.version}`
  requireEqual('release evidence link', body.evidenceLinks.releaseEvidence, `${releaseBase}/release-evidence.json`)
  requireEqual('release image manifest evidence link', body.evidenceLinks.releaseImageManifest, `${releaseBase}/release-image-manifest-evidence.json`)
  requireEqual('release image smoke evidence link', body.evidenceLinks.releaseImageSmoke, `${releaseBase}/release-image-smoke-evidence.json`)
  requireEqual('Umbrel package smoke evidence link', body.evidenceLinks.umbrelPackageSmoke, `${releaseBase}/umbrel-package-smoke-evidence.json`)
  requireEqual('fleet rollout evidence link', body.evidenceLinks.fleetRollout, `${releaseBase}/fleet-rollout-evidence.json`)
  requireEqual('StartOS package evidence link', body.evidenceLinks.startosPackage, `${releaseBase}/blindspark.s9pk`)
  requirePublicHttpsUrl('StartOS registry package link', body.evidenceLinks.startosRegistryPackage)
  requireEqual('StartOS registry evidence link', body.evidenceLinks.startosRegistry, `${releaseBase}/startos-registry-evidence.json`)
  requireEqual('workflow evidence link', body.evidenceLinks.workflow, body.workflow.runUrl)
  await verifyLinkedEvidenceArtifacts(body)
}

function assertOfficialUmbrelPrEvidenceSchema (body) {
  requireOnlyKeys('official Umbrel PR evidence', body, [
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
  requireOnlyKeys('official Umbrel PR release', body.release, ['version', 'semver'])
  requireOnlyKeys('official Umbrel PR facts', body.pr, [
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
  requireOnlyKeys('official Umbrel PR workflow', body.workflow, ['repository', 'runId', 'runAttempt', 'runUrl'])
  requireOnlyKeys('official Umbrel PR runtime review', body.runtimeReview, ['status', 'evidenceFile', 'verifier'])
  requireOnlyKeys('official Umbrel PR evidence links', body.evidenceLinks, [
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

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

async function verifyLinkedEvidenceArtifacts (body) {
  const release = readLinkedReleaseEvidence()
  verifyReleaseEvidenceAlignment(body, release)
  await verifyLinkedEvidenceHash('release image manifest evidence', release.gates?.imageManifestEvidence, 'release-image-manifest-evidence.json')
  await verifyLinkedEvidenceHash('release image smoke evidence', release.gates?.pushedImageSmokeEvidence, 'release-image-smoke-evidence.json')
  await verifyLinkedEvidenceHash('Umbrel package smoke evidence', release.gates?.umbrelPackageSmokeEvidence, 'umbrel-package-smoke-evidence.json')
  await verifyLinkedEvidenceHash('fleet rollout evidence', release.surfaces?.fleetRolloutEvidence, 'fleet-rollout-evidence.json')
  await verifyLinkedEvidenceHash('StartOS registry evidence', release.surfaces?.startosRegistryEvidence, 'startos-registry-evidence.json')
  await verifyLinkedArtifactHash('StartOS package', release.artifacts?.startosPackage, path.join('startos', 'blindspark.s9pk'))
}

function readLinkedReleaseEvidence () {
  const file = 'release-evidence.json'
  requireRegularEvidenceFile(file)
  let body
  try {
    body = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (err) {
    die(`linked release evidence must be valid JSON: ${err.message}`)
  }
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    die('linked release evidence must be a JSON object')
  }
  assertPublicSafeValues(body, 'linked release evidence')
  return body
}

function verifyReleaseEvidenceAlignment (body, release) {
  requireEqual('release evidence schemaVersion', release.schemaVersion, 1)
  requireEqual('release evidence release version', release.release?.version, body.release.version)
  requireEqual('release evidence release semver', release.release?.semver, body.release.semver)
  requireEqual('release evidence workflow status', release.release?.workflow?.status, 'success')
  requireEqual('release evidence workflow repository', release.release?.workflow?.repository, body.workflow.repository)
  requireEqual('release evidence workflow run id', release.release?.workflow?.runId, body.workflow.runId)
  requireEqual('release evidence workflow run attempt', release.release?.workflow?.runAttempt, body.workflow.runAttempt)
  requireEqual('release evidence workflow URL', release.release?.workflow?.runUrl, body.workflow.runUrl)
  requireEqual('release evidence official Umbrel PR status', release.surfaces?.umbrelOfficial?.status, 'draft-pr-ready')
  requireEqual('release evidence official Umbrel PR URL', release.surfaces?.umbrelOfficial?.prUrl, body.pr.url)
  requireEqual('release evidence official Umbrel PR head', release.surfaces?.umbrelOfficial?.head, body.pr.head)
  requireEqual('release evidence official Umbrel PR head SHA', release.surfaces?.umbrelOfficial?.headSha, body.pr.headSha)
  requireEqual('release evidence official Umbrel PR state', release.surfaces?.umbrelOfficial?.state, body.pr.state)
  requireEqual('release evidence official Umbrel PR draft', release.surfaces?.umbrelOfficial?.isDraft, body.pr.isDraft)
  requireEqual('release evidence official Umbrel PR base', release.surfaces?.umbrelOfficial?.base, body.pr.base)
  requireEqual('release evidence official Umbrel PR head owner', release.surfaces?.umbrelOfficial?.headOwner, body.pr.headOwner)
  requireEqual('release evidence official Umbrel PR head ref', release.surfaces?.umbrelOfficial?.headRef, body.pr.headRef)
  requireEqual('release evidence official Umbrel PR head OID', release.surfaces?.umbrelOfficial?.headOid, body.pr.headOid)
  requireEqual('release evidence StartOS registry package URL', release.surfaces?.startosRegistryPackageUrl, body.evidenceLinks.startosRegistryPackage)
}

async function verifyLinkedEvidenceHash (label, ref, expectedFile) {
  requireReleaseEvidenceRef(label, ref, expectedFile)
  requireRegularEvidenceFile(expectedFile)
  const actual = await sha256File(expectedFile)
  requireEqual(`linked ${label} SHA-256 does not match ${expectedFile}`, actual, ref.sha256.toLowerCase())
}

async function verifyLinkedArtifactHash (label, ref, expectedFile) {
  requireReleaseEvidenceRef(label, ref, expectedFile)
  requireRegularFile(label, expectedFile)
  const actual = await sha256File(expectedFile)
  requireEqual(`linked ${label} SHA-256 does not match ${expectedFile}`, actual, ref.sha256.toLowerCase())
}

function requireReleaseEvidenceRef (label, ref, expectedFile) {
  requireOnlyKeys(`release evidence ${label} ref`, ref, ['path', 'sha256'])
  requireEqual(`release evidence ${label} path`, ref.path, expectedFile)
  requirePattern(`release evidence ${label} SHA-256`, ref.sha256, /^[a-f0-9]{64}$/i)
}

function requireRegularEvidenceFile (file) {
  const stat = requireRegularFile('linked evidence artifact', file)
  if (stat.size > MAX_EVIDENCE_JSON_BYTES) {
    die(`linked evidence artifact ${file} must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller`)
  }
}

function requireRegularFile (label, file) {
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (err) {
    if (err && err.code === 'ENOENT') die(`${label} is required before writing official Umbrel PR evidence: ${file}`)
    throw err
  }
  if (stat.isSymbolicLink()) die(`${label} must not be a symlink: ${file}`)
  if (!stat.isFile()) die(`${label} must be a regular file: ${file}`)
  return stat
}

function sha256File (file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = fs.createReadStream(file)
    stream.on('error', reject)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

function prNumberFromUrl (value) {
  const match = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/([1-9][0-9]*)$/.exec(value)
  return match ? match[1] : ''
}

function env (name) {
  return String(process.env[name] ?? '')
}

function booleanEnv (name) {
  const value = env(name)
  if (!value) return null
  if (value === 'true') return true
  if (value === 'false') return false
  die(`${name} must be true or false when set`)
}

function headRefFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(index + 1)
}

function headOwnerFromHead (head) {
  const index = typeof head === 'string' ? head.indexOf(':') : -1
  return index === -1 ? '' : head.slice(0, index)
}

function writeJson (file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n')
  fs.renameSync(tmp, file)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
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

function requirePublicHttpsUrl (label, value) {
  if (isPublicHttpsUrl(value)) return
  die(`${label} must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames; got ${JSON.stringify(value)}`)
}

function isGitHubHeadRefName (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false
  if (!/^[A-Za-z0-9._/-]+$/.test(value)) return false
  if (value === '@' || value.startsWith('/') || value.endsWith('/') || value.startsWith('-') || value.endsWith('.')) return false
  if (value.includes('//') || value.includes('..') || value.includes('@{')) return false
  const parts = value.split('/')
  return parts.every(part => part && !part.startsWith('.') && !part.startsWith('-') && !part.endsWith('.lock'))
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
    if (node == null) return
    if (typeof node === 'string') {
      if (hasControlChars(node)) die(`${label} must not contain control characters at ${at}`)
      for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
        if (pattern.test(node)) die(`${label} must not contain ${name} at ${at}`)
      }
      try {
        const url = new URL(node)
        if (url.username || url.password) die(`${label} must not expose URL credentials at ${at}`)
      } catch (_) {}
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
    }
  }
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 32 || code === 127) return true
  }
  return false
}

function die (message) {
  console.error(message)
  process.exit(1)
}
