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
  'UMBREL_OFFICIAL_FORK',
  'STARTOS_DEVELOPER_KEY_PEM',
  'STARTOS_REGISTRY_URL'
]

const OPTIONAL_VARIABLES = [
  'FLEET_ROLLOUT_TIMEOUT_MS'
]

const usage = `
Usage:
  node scripts/apply-github-release-secrets.mjs --repo owner/name --env-file <path> [--gh gh] [--channel both] [--prerelease false] [--dry-run]

Validates a local release secret candidate file with
scripts/check-release-distribution-env.mjs, then writes the exact same values
to GitHub Secrets using gh. Secret values are sent through stdin and are never
printed.
`

const args = parseArgs(process.argv.slice(2))
const repo = args.repo || process.env.HIVERELAY_RELEASE_REPO || 'bigdestiny2/P2P-Hiverelay'
const gh = args.gh || process.env.HIVERELAY_GH || 'gh'
const channel = args.channel || 'both'
const prerelease = args.prerelease || 'false'

if (!args.envFile) die('Missing --env-file')
if (!isRepoFullName(repo)) die('Invalid --repo. Expected owner/name.')
if (prerelease !== 'false') die('release:apply-github-secrets only validates full-release secret values; use --prerelease false.')

const values = safeReadEnvFile(args.envFile)
validateCandidateFile(args.envFile, channel, prerelease)

if (args.dryRun) {
  console.log(`Release secret candidate file is valid for ${repo}.`)
  console.log(`Would set GitHub Secrets: ${REQUIRED_SECRETS.join(', ')}`)
  const variables = OPTIONAL_VARIABLES.filter(name => values[name])
  if (variables.length > 0) console.log(`Would set GitHub Variables: ${variables.join(', ')}`)
  else console.log('No optional GitHub Variables present in candidate file.')
  console.log('Dry run only; no GitHub Secrets or Variables were changed.')
  process.exit(0)
}

for (const name of REQUIRED_SECRETS) {
  runGh(gh, ['secret', 'set', name, '--repo', repo], values[name], `secret ${name}`)
  console.log(`Set GitHub Secret ${name}.`)
}

for (const name of OPTIONAL_VARIABLES) {
  if (!values[name]) continue
  runGh(gh, ['variable', 'set', name, '--repo', repo, '--body', values[name]], '', `variable ${name}`)
  console.log(`Set GitHub Variable ${name}.`)
}

console.log('GitHub release secrets applied. Run release:check-github-setup and the Release distribution preflight workflow next.')

function validateCandidateFile (envFile, channel, prerelease) {
  const result = spawnSync(process.execPath, [
    path.join(here, 'check-release-distribution-env.mjs'),
    '--env-file',
    envFile,
    '--channel',
    channel,
    '--prerelease',
    prerelease
  ], {
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
