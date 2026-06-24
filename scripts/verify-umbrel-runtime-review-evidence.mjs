#!/usr/bin/env node

import fs from 'node:fs'

const usage = `
Usage:
  node scripts/verify-umbrel-runtime-review-evidence.mjs --evidence umbrel-runtime-review-evidence.json [options]

Options:
  --evidence <path>         Umbrel runtime review evidence JSON to verify
  --release <version>       Optional release version that must match, e.g. v0.16.3
  --official-pr-url <url>   Optional expected upstream getumbrel/umbrel-apps PR URL that must match
`

const REQUIRED_CHECKS = Object.freeze([
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
])

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

const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/
const LOCAL_ADDRESS_PATTERN = /\b(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.\d{1,3}){2}|[a-z0-9-]+\.local)\b/i
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024
const MAX_GENERATED_AT_FUTURE_SKEW_MS = 5 * 60 * 1000

const args = parseArgs(process.argv.slice(2))
if (args.help || !args.evidence) {
  console.log(usage.trim())
  process.exit(args.help ? 0 : 1)
}

const body = readJson(args.evidence)
verifyEvidence(body, args)
console.log(`Umbrel runtime review evidence verified: ${body.release.version}`)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--evidence' || arg === '--release' || arg === '--official-pr-url') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
      out[camel(arg.slice(2))] = value
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function verifyEvidence (body, opts) {
  assertPublicSafeValues(body, 'Umbrel runtime review evidence')
  assertNoRawIdentityFields(body)
  assertRuntimeReviewSchema(body)
  requireEqual('schemaVersion', body.schemaVersion, 1)
  const generatedAtMs = requireIsoTimestamp('generatedAt', body.generatedAt)
  if (generatedAtMs > Date.now() + MAX_GENERATED_AT_FUTURE_SKEW_MS) {
    die('generatedAt must not be in the future')
  }
  requireEqual('kind', body.kind, 'umbrel-runtime-review')
  requireEqual('status', body.status, 'passed')
  requirePattern('release.version', body.release?.version, /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release.semver', body.release?.semver, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requireEqual('release semver matches version', body.release.semver, body.release.version.slice(1))
  if (opts.release) requireEqual('release.version', body.release.version, opts.release)
  requireEqual('platform.name', body.platform?.name, 'umbrel')
  requireSafePublicLabel('Umbrel review device', body.platform?.device)
  requirePattern('Umbrel version', body.platform?.umbrelVersion, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/)
  requireSafePublicLabel('Umbrel runtime reviewer', body.review?.testedBy)
  verifyIdentityHashes(body.identity)
  requirePattern('official Umbrel PR URL', body.officialUmbrelPr?.url, OFFICIAL_UMBREL_PR_URL_PATTERN)
  if (opts.officialPrUrl) requireEqual('official Umbrel PR URL', body.officialUmbrelPr.url, opts.officialPrUrl)
  verifyChecks(body.checks)
}

function assertRuntimeReviewSchema (body) {
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
  requireOnlyKeys('release', body.release, ['version', 'semver'])
  requireOnlyKeys('platform', body.platform, ['name', 'device', 'umbrelVersion'])
  requireOnlyKeys('review', body.review, ['testedBy'])
  requireOnlyKeys('identity', body.identity, ['publicKeySha256', 'publicKeyBeforeSha256', 'publicKeyAfterSha256'])
  requireOnlyKeys('officialUmbrelPr', body.officialUmbrelPr, ['url'])
  if (Array.isArray(body.checks)) {
    for (const check of body.checks) requireOnlyKeys(`Umbrel runtime check ${check?.name || ''}`.trim(), check, ['name', 'status'])
  }
}

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) {
    die(`${label} has unsupported fields: ${extra.join(', ')}`)
  }
}

function verifyChecks (checks) {
  if (!Array.isArray(checks)) die('checks must be an array')
  const seen = new Set()
  for (const check of checks) {
    requirePattern('Umbrel runtime check name', check?.name, /^[A-Za-z][A-Za-z0-9]*$/)
    if (!REQUIRED_CHECKS.includes(check.name)) die(`Unknown Umbrel runtime check: ${check.name}`)
    if (seen.has(check.name)) die(`Duplicate Umbrel runtime check: ${check.name}`)
    seen.add(check.name)
    requireEqual(`Umbrel runtime check ${check.name}`, check.status, 'passed')
  }
  const missing = REQUIRED_CHECKS.filter((check) => !seen.has(check))
  if (missing.length > 0) die(`Missing Umbrel runtime checks: ${missing.join(', ')}`)
}

function assertNoRawIdentityFields (body) {
  visit(body, '$')

  function visit (node, at) {
    if (node == null || typeof node !== 'object') return
    for (const [key, value] of Object.entries(node)) {
      if (/publicKey/i.test(key) && !isAllowedPublicKeyHashField(key)) {
        die(`Umbrel runtime review evidence must not expose raw public key fields at ${at}.${key}`)
      }
      visit(value, `${at}.${key}`)
    }
  }
}

function verifyIdentityHashes (identity = {}) {
  requirePattern('relay public key hash', identity.publicKeySha256, /^[a-f0-9]{64}$/)
  requirePattern('relay public key before hash', identity.publicKeyBeforeSha256, /^[a-f0-9]{64}$/)
  requirePattern('relay public key after hash', identity.publicKeyAfterSha256, /^[a-f0-9]{64}$/)
  requireEqual('relay public key hash matches before hash', identity.publicKeySha256, identity.publicKeyBeforeSha256)
  requireEqual('relay public key hash after reinstall', identity.publicKeyAfterSha256, identity.publicKeyBeforeSha256)
}

function isAllowedPublicKeyHashField (key) {
  return key === 'publicKeySha256' ||
    key === 'publicKeyBeforeSha256' ||
    key === 'publicKeyAfterSha256'
}

function readJson (file) {
  try {
    return JSON.parse(readRegularFile(file, 'Umbrel runtime review evidence', 'utf8', MAX_EVIDENCE_JSON_BYTES))
  } catch (err) {
    die(`Could not read Umbrel runtime review evidence from ${file}: ${err.message}`)
  }
}

function readRegularFile (file, label, encoding, maxBytes = Infinity) {
  const stat = fs.lstatSync(file)
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${file}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${file}`)
  if (stat.size > maxBytes) die(`${label} file must be ${maxBytes} bytes or smaller: ${file} is ${stat.size} bytes`)
  return fs.readFileSync(file, encoding)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
  die(`${label} is required and malformed; got ${JSON.stringify(value)}`)
}

function requireIsoTimestamp (label, value) {
  requirePattern(label, value, ISO_TIMESTAMP_PATTERN)
  const ms = Date.parse(value)
  if (!Number.isFinite(ms)) die(`${label} is required and malformed; got ${JSON.stringify(value)}`)
  return ms
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
