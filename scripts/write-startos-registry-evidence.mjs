#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

const usage = `
Usage:
  node scripts/write-startos-registry-evidence.mjs --out startos-registry-evidence.json
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
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024

const args = parseArgs(process.argv.slice(2))
const outFile = path.resolve(args.out || 'startos-registry-evidence.json')

const serverUrl = env('GITHUB_SERVER_URL') || 'https://github.com'
const repository = env('GITHUB_REPOSITORY')
const runId = env('GITHUB_RUN_ID')
const version = env('HIVERELAY_RELEASE_VERSION')
const semver = env('HIVERELAY_RELEASE_SEMVER') || version.replace(/^v/, '')
const releaseBaseUrl = repository && version ? `${serverUrl}/${repository}/releases/download/${version}` : ''
const workflowUrl = repository && runId ? `${serverUrl}/${repository}/actions/runs/${runId}` : ''
const packageId = env('HIVERELAY_STARTOS_PACKAGE_ID')
const registryUrl = env('HIVERELAY_STARTOS_REGISTRY_URL') || env('STARTOS_REGISTRY_URL')
const packageUrl = env('HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL') ||
  env('STARTOS_REGISTRY_PACKAGE_URL') ||
  registryPackageUrl(registryUrl, packageId)

const body = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  kind: 'startos-registry-publication',
  status: 'published',
  release: {
    version,
    semver
  },
  package: {
    id: packageId,
    path: 'startos/blindspark.s9pk',
    sha256: env('HIVERELAY_STARTOS_PACKAGE_SHA256'),
    url: packageUrl
  },
  registry: {
    url: registryUrl
  },
  workflow: {
    repository,
    runId,
    runAttempt: env('GITHUB_RUN_ATTEMPT'),
    runUrl: workflowUrl
  },
  evidenceLinks: {
    releaseEvidence: `${releaseBaseUrl}/release-evidence.json`,
    releaseImageManifest: `${releaseBaseUrl}/release-image-manifest-evidence.json`,
    releaseImageSmoke: `${releaseBaseUrl}/release-image-smoke-evidence.json`,
    startosPackage: `${releaseBaseUrl}/blindspark.s9pk`,
    registryPackage: packageUrl,
    workflow: workflowUrl
  }
}

await validate(body)
writeJson(outFile, body)
console.log(`StartOS registry evidence written to ${outFile}`)

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
  assertPublicSafeValues(body, 'StartOS registry evidence')
  assertStartosRegistryEvidenceSchema(body)
  requireEqual('StartOS registry evidence schemaVersion', body.schemaVersion, 1)
  requirePattern('StartOS registry evidence generatedAt', body.generatedAt, ISO_TIMESTAMP_PATTERN)
  requireEqual('StartOS registry evidence kind', body.kind, 'startos-registry-publication')
  requireEqual('StartOS registry evidence status', body.status, 'published')
  requirePattern('release.version', body.release.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release.semver', body.release.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  requirePattern('StartOS package id', body.package.id, /^[a-z0-9][a-z0-9-]{1,63}$/)
  requirePattern('StartOS package SHA-256', body.package.sha256, /^[a-f0-9]{64}$/i)
  await verifyPresentStartosPackage(body)
  requirePublicHttpsUrl('StartOS registry URL', body.registry.url)
  requireRegistryPackageUrl('StartOS registry package URL', body.package.url, body.registry.url, body.package.id)
  requirePattern('workflow repository', body.workflow.repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
  requireEqual('workflow repository', body.workflow.repository, EXPECTED_RELEASE_REPOSITORY)
  requirePattern('workflow run id', body.workflow.runId, POSITIVE_INTEGER_PATTERN)
  requirePattern('workflow run attempt', body.workflow.runAttempt, POSITIVE_INTEGER_PATTERN)
  requirePattern('workflow URL', body.workflow.runUrl, GITHUB_ACTIONS_RUN_URL_PATTERN)
  requireEqual('workflow URL matches repository and run id', body.workflow.runUrl, `https://github.com/${body.workflow.repository}/actions/runs/${body.workflow.runId}`)
  await verifyLinkedReleaseImageEvidence()
  const releaseBase = `https://github.com/${body.workflow.repository}/releases/download/${body.release.version}`
  requireEqual('release evidence link', body.evidenceLinks.releaseEvidence, `${releaseBase}/release-evidence.json`)
  requireEqual('release image manifest link', body.evidenceLinks.releaseImageManifest, `${releaseBase}/release-image-manifest-evidence.json`)
  requireEqual('release image smoke link', body.evidenceLinks.releaseImageSmoke, `${releaseBase}/release-image-smoke-evidence.json`)
  requireEqual('StartOS package evidence link', body.evidenceLinks.startosPackage, `${releaseBase}/blindspark.s9pk`)
  requireEqual('StartOS registry package link', body.evidenceLinks.registryPackage, body.package.url)
  requireEqual('workflow evidence link', body.evidenceLinks.workflow, body.workflow.runUrl)
}

function assertStartosRegistryEvidenceSchema (body) {
  requireOnlyKeys('StartOS registry evidence', body, [
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
  requireOnlyKeys('StartOS registry release', body.release, ['version', 'semver'])
  requireOnlyKeys('StartOS registry package', body.package, ['id', 'path', 'sha256', 'url'])
  requireOnlyKeys('StartOS registry registry', body.registry, ['url'])
  requireOnlyKeys('StartOS registry workflow', body.workflow, ['repository', 'runId', 'runAttempt', 'runUrl'])
  requireOnlyKeys('StartOS registry evidence links', body.evidenceLinks, [
    'releaseEvidence',
    'releaseImageManifest',
    'releaseImageSmoke',
    'startosPackage',
    'registryPackage',
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

function env (name) {
  return String(process.env[name] ?? '')
}

async function verifyPresentStartosPackage (body) {
  if (body.package.path !== 'startos/blindspark.s9pk') {
    die(`StartOS package path must be startos/blindspark.s9pk; got ${JSON.stringify(body.package.path)}`)
  }
  const file = path.resolve(process.cwd(), body.package.path)
  requireRegularFile('StartOS package', file, body.package.path)
  const actualSha256 = await sha256File(file)
  if (actualSha256 !== body.package.sha256) {
    die(`StartOS package SHA-256 does not match ${body.package.path}; expected ${body.package.sha256}, got ${actualSha256}`)
  }
}

async function verifyLinkedReleaseImageEvidence () {
  await verifyLinkedEvidenceFile(
    'release image manifest evidence',
    env('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE'),
    env('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256'),
    'release-image-manifest-evidence.json',
    'release-image-manifest'
  )
  await verifyLinkedEvidenceFile(
    'release image smoke evidence',
    env('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE'),
    env('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256'),
    'release-image-smoke-evidence.json',
    'release-image-smoke'
  )
}

async function verifyLinkedEvidenceFile (label, configuredPath, configuredSha256, expectedPath, expectedKind) {
  requireEqual(`${label} path`, configuredPath, expectedPath)
  requirePattern(`${label} SHA-256`, configuredSha256, /^[a-f0-9]{64}$/i)
  const file = requireRegularEvidenceFile(label, expectedPath)
  const body = readLinkedEvidenceJson(label, file)
  assertPublicSafeValues(body, label)
  requireEqual(`${label} kind`, body.kind, expectedKind)
  const actualSha256 = await sha256File(file)
  requireEqual(`${label} SHA-256 does not match ${expectedPath}`, actualSha256, configuredSha256.toLowerCase())
}

function requireRegularEvidenceFile (label, relativePath) {
  const file = path.resolve(process.cwd(), relativePath)
  const stat = requireRegularFile(label, file, relativePath)
  if (stat.size > MAX_EVIDENCE_JSON_BYTES) {
    die(`${label} file must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller: ${relativePath} is ${stat.size} bytes`)
  }
  return file
}

function requireRegularFile (label, file, displayPath) {
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      die(`${label} file is required before writing registry evidence: ${displayPath}`)
    }
    throw e
  }
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${displayPath}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${displayPath}`)
  return stat
}

function readLinkedEvidenceJson (label, file) {
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

function sha256File (file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(file)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('error', reject)
    stream.on('end', () => resolve(hash.digest('hex')))
  })
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
