#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const usage = `
Usage:
  node scripts/write-umbrel-runtime-review-evidence.mjs --out umbrel-runtime-review-evidence.json \\
    --release v0.20.2 --device "Umbrel Home" --umbrel-version 1.3.0 \\
    --tested-by <public-name> --public-key-before <hex> --public-key-after <hex> \\
    --checks installedThroughUmbrel,dashboardProxyLoads,liveFeedInBandAuth,noWebSocketUrlTokens,wizardCompletes,setupActionLockObserved,addWalletPersists,dynamicPayoutControlsObserved,walletBusyStateObserved,managementActionsPersist,serviceActionStateObserved,serviceRestartPendingObserved,aiModelAddStateObserved,reviewModeDefault,dataWritableUid999,reinstallPreservesPublicKey \\
    --official-pr-url https://github.com/getumbrel/umbrel-apps/pull/<number>

Writes a public-safe manual evidence artifact after real Umbrel UI/lifecycle
review. The artifact intentionally stores a hash of the relay public key rather
than the key itself and rejects local URLs, LAN IPs, APP_SEED values, API keys,
and credential-looking strings.
`

const REQUIRED_CHECKS = [
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
]

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

const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/
const LOCAL_ADDRESS_PATTERN = /\b(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.\d{1,3}){2}|[a-z0-9-]+\.local)\b/i
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

const args = parseArgs(process.argv.slice(2))
const outFile = path.resolve(args.out || 'umbrel-runtime-review-evidence.json')
const releaseVersion = args.release || env('HIVERELAY_RELEASE_VERSION')
const semver = semverFromRelease(releaseVersion)
const publicKeyBefore = normalizePublicKey(args.publicKeyBefore || env('HIVERELAY_UMBREL_PUBLIC_KEY_BEFORE'))
const publicKeyAfter = normalizePublicKey(args.publicKeyAfter || env('HIVERELAY_UMBREL_PUBLIC_KEY_AFTER'))
const publicKeyBeforeSha256 = sha256Hex(publicKeyBefore)
const publicKeyAfterSha256 = sha256Hex(publicKeyAfter)
const checks = parseChecks(args.checks || env('HIVERELAY_UMBREL_RUNTIME_CHECKS'))
const officialPrUrl = args.officialPrUrl || env('HIVERELAY_UMBREL_OFFICIAL_PR_URL')

const body = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  kind: 'umbrel-runtime-review',
  status: 'passed',
  release: {
    version: releaseVersion,
    semver
  },
  platform: {
    name: 'umbrel',
    device: args.device || env('HIVERELAY_UMBREL_REVIEW_DEVICE'),
    umbrelVersion: args.umbrelVersion || env('HIVERELAY_UMBREL_VERSION')
  },
  review: {
    testedBy: args.testedBy || env('HIVERELAY_UMBREL_TESTED_BY')
  },
  identity: {
    publicKeySha256: publicKeyBeforeSha256,
    publicKeyBeforeSha256,
    publicKeyAfterSha256
  },
  officialUmbrelPr: {
    url: officialPrUrl
  },
  checks: REQUIRED_CHECKS.map((name) => ({
    name,
    status: checks.has(name) ? 'passed' : 'missing'
  }))
}

validate(body, publicKeyBefore, publicKeyAfter)
writeJson(outFile, body)
console.log(`Umbrel runtime review evidence written to ${outFile}`)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--out' ||
      arg === '--release' ||
      arg === '--device' ||
      arg === '--umbrel-version' ||
      arg === '--tested-by' ||
      arg === '--public-key-before' ||
      arg === '--public-key-after' ||
      arg === '--checks' ||
      arg === '--official-pr-url') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
      out[camel(arg.slice(2))] = value
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function validate (body, publicKeyBefore, publicKeyAfter) {
  assertPublicSafeValues(body, 'Umbrel runtime review evidence')
  assertRuntimeReviewEvidenceSchema(body)
  requireEqual('Umbrel runtime review evidence schemaVersion', body.schemaVersion, 1)
  requirePattern('Umbrel runtime review evidence generatedAt', body.generatedAt, ISO_TIMESTAMP_PATTERN)
  requireEqual('Umbrel runtime review evidence kind', body.kind, 'umbrel-runtime-review')
  requireEqual('Umbrel runtime review evidence status', body.status, 'passed')
  requirePattern('release.version', body.release.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release.semver', body.release.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  requireSafePublicLabel('Umbrel review device', body.platform.device)
  requirePattern('Umbrel version', body.platform.umbrelVersion, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/)
  requireSafePublicLabel('Umbrel runtime reviewer', body.review.testedBy)
  requirePattern('relay public key before reinstall', publicKeyBefore, /^[a-f0-9]{64}$/)
  requirePattern('relay public key after reinstall', publicKeyAfter, /^[a-f0-9]{64}$/)
  requireEqual('relay public key after reinstall', publicKeyAfter, publicKeyBefore)
  requirePattern('relay public key hash', body.identity.publicKeySha256, /^[a-f0-9]{64}$/)
  requirePattern('relay public key before hash', body.identity.publicKeyBeforeSha256, /^[a-f0-9]{64}$/)
  requirePattern('relay public key after hash', body.identity.publicKeyAfterSha256, /^[a-f0-9]{64}$/)
  requireEqual('relay public key hash matches before hash', body.identity.publicKeySha256, body.identity.publicKeyBeforeSha256)
  requireEqual('relay public key hash after reinstall', body.identity.publicKeyAfterSha256, body.identity.publicKeyBeforeSha256)
  requirePattern('official Umbrel PR URL', body.officialUmbrelPr?.url, OFFICIAL_UMBREL_PR_URL_PATTERN)
  for (const check of body.checks) {
    requireOneOf(`Umbrel runtime check ${check.name}`, check.status, ['passed'])
  }
}

function assertRuntimeReviewEvidenceSchema (body) {
  requireOnlyKeys('Umbrel runtime review evidence', body, [
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

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function parseChecks (value) {
  const values = String(value || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
  const set = new Set(values)
  const required = new Set(REQUIRED_CHECKS)
  for (const item of set) {
    if (!required.has(item)) die(`Unknown Umbrel runtime check: ${item}`)
  }
  const missing = REQUIRED_CHECKS.filter((item) => !set.has(item))
  if (missing.length > 0) die(`Missing Umbrel runtime checks: ${missing.join(', ')}`)
  return set
}

function semverFromRelease (version) {
  if (!version) return ''
  return version.replace(/^v/, '')
}

function normalizePublicKey (value) {
  return String(value || '').trim().toLowerCase()
}

function sha256Hex (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function env (name) {
  return String(process.env[name] || '').trim()
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

function requireOneOf (label, actual, expected) {
  if (expected.includes(actual)) return
  die(`${label} must be one of ${expected.map(value => JSON.stringify(value)).join(', ')}; got ${JSON.stringify(actual)}`)
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
        if (!isAllowedPublicUrl(url)) die(`${label} must not contain non-public URL at ${at}`)
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

function isAllowedPublicUrl (url) {
  if (url.protocol !== 'https:') return false
  if (url.search || url.hash) return false
  return isPublicHostname(url.hostname)
}

function isPublicHostname (hostname) {
  const host = String(hostname || '').toLowerCase()
  if (!/^[a-z0-9.-]+$/.test(host)) return false
  if (!host.includes('.')) return false
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return false
  if (LOCAL_ADDRESS_PATTERN.test(host)) return false

  const labels = host.split('.')
  if (labels.some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return false
  const tld = labels[labels.length - 1]
  if (!/^[a-z]{2,63}$/.test(tld)) return false

  const reservedHosts = new Set(['localhost', 'example.com', 'example.net', 'example.org'])
  if (reservedHosts.has(host)) return false
  const reservedSuffixes = ['.localhost', '.local', '.internal', '.test', '.example', '.invalid', '.example.com', '.example.net', '.example.org']
  return !reservedSuffixes.some(suffix => host.endsWith(suffix))
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 32 || code === 127) return true
  }
  return false
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function die (message) {
  console.error(message)
  process.exit(1)
}
