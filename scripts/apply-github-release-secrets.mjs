#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { readEnvFile } from './lib/release-env-file.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')

const REQUIRED_SECRETS = [
  'FLEET_SSH_PRIVATE_KEY',
  'UMBREL_STORE_TOKEN',
  'UMBREL_OFFICIAL_PR_TOKEN',
  'ECOSYSTEM_CONSUMER_TOKEN',
  'UMBREL_OFFICIAL_FORK',
  'NPM_TOKEN',
  'STARTOS_DEVELOPER_KEY_PEM',
  'STARTOS_REGISTRY_URL'
]

const OPTIONAL_VARIABLES = [
  'FLEET_ROLLOUT_TIMEOUT_MS'
]

const ISSUE_120_REPAIR_SECRETS = [
  'UMBREL_STORE_TOKEN',
  'UMBREL_OFFICIAL_PR_TOKEN',
  'UMBREL_OFFICIAL_FORK',
  'STARTOS_REGISTRY_URL'
]

const usage = `
Usage:
  node scripts/apply-github-release-secrets.mjs --repo owner/name --env-file <path> [--gh gh] [--channel both] [--prerelease false] [--dry-run] [--issue-120-repair]

Validates a local release-value candidate file with
scripts/check-release-distribution-env.mjs, then writes the validated masked
release values to GitHub Secrets using gh. UMBREL_OFFICIAL_FORK and
STARTOS_REGISTRY_URL are canonicalized before writing. Values are sent through
stdin and are never printed. ECOSYSTEM_CONSUMER_TOKEN is required so full
releases can push app consumer default updates after npm latest is promoted.
NPM_TOKEN is required so full releases can publish the workspace packages
before app consumers follow npm latest.
FLEET_ROLLOUT_TIMEOUT_MS, when present, is the only GitHub Variable.
Use --issue-120-repair to validate and apply only the four malformed masked
values called out by issue #120: UMBREL_STORE_TOKEN, UMBREL_OFFICIAL_PR_TOKEN,
UMBREL_OFFICIAL_FORK, and STARTOS_REGISTRY_URL.
`

const args = parseArgs(process.argv.slice(2))
const repo = args.repo || process.env.HIVERELAY_RELEASE_REPO || 'bigdestiny2/P2P-Hiverelay'
const gh = args.gh || process.env.HIVERELAY_GH || 'gh'
const channel = args.channel || 'both'
const prerelease = args.prerelease || 'false'

if (!args.envFile) die('Missing --env-file')
if (!isRepoFullName(repo)) die('Invalid --repo. Expected owner/name.')
if (prerelease !== 'false') die('release:apply-github-secrets only validates full-release secret values; use --prerelease false.')

const secretNames = args.issue120Repair ? ISSUE_120_REPAIR_SECRETS : REQUIRED_SECRETS
const values = normalizeApplyValues(safeReadEnvFile(args.envFile))
validateCandidateFile(args.envFile, channel, prerelease, args.issue120Repair)

if (args.dryRun) {
  console.log(`Release value candidate file is valid for ${repo}.`)
  console.log(`Would set masked GitHub release values as Secrets: ${secretNames.join(', ')}`)
  const variables = args.issue120Repair ? [] : OPTIONAL_VARIABLES.filter(name => values[name])
  if (args.issue120Repair) console.log('Issue #120 repair mode; no GitHub Variables would be changed.')
  else if (variables.length > 0) console.log(`Would set GitHub Variables: ${variables.join(', ')}`)
  else console.log('No optional GitHub Variables present in candidate file.')
  console.log('Dry run only; no GitHub release values or Variables were changed.')
  printNextSteps(repo, channel, { afterApply: true })
  process.exit(0)
}

for (const name of secretNames) {
  runGh(gh, ['secret', 'set', name, '--repo', repo], values[name], `secret ${name}`)
  console.log(`Set masked GitHub release value ${name} as a Secret.`)
}

if (!args.issue120Repair) {
  for (const name of OPTIONAL_VARIABLES) {
    if (!values[name]) continue
    runGh(gh, ['variable', 'set', name, '--repo', repo, '--body', values[name]], '', `variable ${name}`)
    console.log(`Set GitHub Variable ${name}.`)
  }
}

console.log('GitHub release values applied.')
printNextSteps(repo, channel)

function validateCandidateFile (envFile, channel, prerelease, issue120Repair) {
  const argv = [
    path.join(here, 'check-release-distribution-env.mjs'),
    '--env-file',
    envFile
  ]
  if (issue120Repair) argv.push('--issue-120-repair')
  else {
    argv.push(
      '--channel',
      channel,
      '--prerelease',
      prerelease
    )
  }
  const result = spawnSync(process.execPath, argv, {
    cwd: root,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH || ''
    },
    maxBuffer: 1024 * 1024
  })

  if (result.error) die(`Failed to validate candidate env file: ${result.error.message}`)
  if (result.status !== 0) {
    if (result.stdout) process.stdout.write(result.stdout)
    if (result.stderr) process.stderr.write(result.stderr)
    process.exit(result.status || 1)
  }
}

function safeReadEnvFile (file) {
  try {
    return readEnvFile(file)
  } catch (err) {
    die(err.message || 'Unable to read env file')
  }
}

function runGh (gh, argv, input, label) {
  const result = spawnSync(gh, argv, {
    input,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })

  if (result.error) die(`Failed to run ${gh} for ${label}: ${result.error.message}`)
  if (result.status !== 0) {
    const details = sanitizeGhError(result.stderr || result.stdout || `exit ${result.status}`, [input])
    die(`gh ${argv.slice(0, 2).join(' ')} failed for ${label}: ${details}`)
  }
}

function printNextSteps (repo, channel, opts = {}) {
  console.log(opts.afterApply ? 'After applying the candidate file, run:' : 'Next steps:')
  console.log(`npm run release:check-github-setup -- --repo ${repo}`)
  console.log(`gh workflow run release-distribution-preflight.yml --repo ${repo} -f channel=${channel} -f prerelease=false`)
}

function parseArgs (argv) {
  const out = {
    dryRun: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--repo') {
      out.repo = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--env-file') {
      out.envFile = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--gh') {
      out.gh = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--channel') {
      out.channel = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--prerelease') {
      out.prerelease = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--dry-run') {
      out.dryRun = true
      continue
    }
    if (arg === '--issue-120-repair') {
      out.issue120Repair = true
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function isRepoFullName (value) {
  if (typeof value !== 'string' || value.trim() !== value || hasControlChars(value)) return false
  const parts = value.split('/')
  if (parts.length !== 2) return false
  return isGitHubName(parts[0]) && isGitHubName(parts[1])
}

function isGitHubName (value) {
  return /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/.test(value)
}

function normalizeApplyValues (values) {
  const out = { ...values }
  const fork = normalizeOfficialUmbrelForkSlug(values.UMBREL_OFFICIAL_FORK)
  if (fork) out.UMBREL_OFFICIAL_FORK = fork
  const registryUrl = normalizePublicHttpsUrl(values.STARTOS_REGISTRY_URL)
  if (registryUrl) out.STARTOS_REGISTRY_URL = registryUrl
  return out
}

function normalizeOfficialUmbrelForkSlug (value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed || hasControlChars(trimmed)) return null
  let slug = trimmed
  const httpsUrl = /^https:\/\/github\.com\/([^/\s]+)\/([^/\s?#]+)\/?$/i.exec(slug)
  if (httpsUrl) slug = `${httpsUrl[1]}/${httpsUrl[2]}`
  const sshUrl = /^git@github\.com:([^/\s]+)\/([^/\s]+)$/.exec(slug)
  if (sshUrl) slug = `${sshUrl[1]}/${sshUrl[2]}`
  slug = slug.replace(/\.git$/i, '').replace(/\/+$/, '')
  const parts = slug.split('/')
  if (parts.length !== 2) return null
  const [owner, repo] = parts
  if (!isGitHubOwnerName(owner) || owner.toLowerCase() === 'getumbrel' || repo.toLowerCase() !== 'umbrel-apps') return null
  return `${owner}/umbrel-apps`
}

function normalizePublicHttpsUrl (value) {
  if (typeof value !== 'string' || !value) return null
  const trimmed = value.trim()
  if (!trimmed || hasControlChars(trimmed)) return null
  try {
    const url = new URL(trimmed)
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !isPublicHostname(url.hostname)) return null
    return `${url.origin}${normalizeUrlPath(url.pathname)}`
  } catch (_) {
    return null
  }
}

function normalizeUrlPath (pathname) {
  const value = String(pathname || '')
  if (!value || value === '/') return ''
  return value.replace(/\/+$/, '')
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

function isGitHubOwnerName (value) {
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value)
}

function sanitizeGhError (value, redactions = []) {
  return redactSecretLikeValues(String(value), redactions)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500)
}

function redactSecretLikeValues (value, redactions = []) {
  let out = value
  for (const item of redactions) {
    if (!item) continue
    out = out.split(String(item)).join('[redacted-secret]')
  }
  return out
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, '[redacted-private-key]')
    .replace(/(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, '[redacted-github-token]')
    .replace(/npm_[A-Za-z0-9]{20,}/g, '[redacted-npm-token]')
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function die (message) {
  console.error(message)
  process.exit(1)
}
