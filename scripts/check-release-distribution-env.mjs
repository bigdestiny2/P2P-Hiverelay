#!/usr/bin/env node

import fs from 'node:fs'

const FLEET_ROLLOUT_TIMEOUT_MIN_MS = 10 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MAX_MS = 4 * 60 * 60 * 1000
const MAX_ENV_FILE_BYTES = 64 * 1024
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]*$/
const ENV_HEREDOC_DELIMITER_RE = /^[A-Za-z0-9_.-]{1,64}$/

const usage = `
Usage:
  node scripts/check-release-distribution-env.mjs --channel <canary|stable|both|none> --prerelease <true|false> [--env-file <path>] [--github-env <path>]

Defaults:
  --channel defaults to both for full releases and none for prereleases when HIVERELAY_RELEASE_CHANNEL is unset.

Local candidate validation:
  --env-file reads NAME=value and NAME<<DELIM blocks so operators can validate
  multiline release secrets before writing them to GitHub Secrets.
`

const args = parseArgs(process.argv.slice(2))
const sourceEnv = args.envFile
  ? { ...process.env, ...readEnvFile(args.envFile) }
  : process.env
const prerelease = readBoolean(args.prerelease ?? sourceEnv.HIVERELAY_RELEASE_PRERELEASE)
const channel = args.channel || sourceEnv.HIVERELAY_RELEASE_CHANNEL || (prerelease ? 'none' : 'both')
const githubEnv = args.githubEnv || process.env.GITHUB_ENV || ''
const result = checkReleaseDistributionEnv({ channel, prerelease, env: sourceEnv })

appendGithubEnv(githubEnv, result.envUpdates)

if (!result.ok) {
  console.error('Release distribution preflight failed:')
  for (const item of result.missing) console.error(`- ${item}`)
  process.exit(1)
}

if (result.skipped) {
  console.log('Distribution credential preflight skipped for prerelease.')
} else {
  console.log('Stable release distribution preflight passed.')
}

function checkReleaseDistributionEnv ({ channel, prerelease, env }) {
  if (!['canary', 'stable', 'both', 'none'].includes(channel)) {
    return {
      ok: false,
      skipped: false,
      missing: [`invalid channel "${channel}"`],
      envUpdates: {
        HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'failed',
        HIVERELAY_RELEASE_SURFACES_STATUS: 'blocked'
      }
    }
  }

  if (prerelease) {
    if (channel !== 'none') {
      return {
        ok: false,
        skipped: false,
        missing: [`pre-release channel must be none; got "${channel}"`],
        envUpdates: {
          HIVERELAY_RELEASE_EFFECTIVE_CHANNEL: channel,
          HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'failed',
          HIVERELAY_RELEASE_SURFACES_STATUS: 'blocked',
          HIVERELAY_FLEET_ROLLOUT_STATUS: 'blocked-prerelease-promotion'
        }
      }
    }
    return {
      ok: true,
      skipped: true,
      missing: [],
      envUpdates: {
        HIVERELAY_RELEASE_EFFECTIVE_CHANNEL: channel,
        HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'skipped'
      }
    }
  }

  const missing = []
  const envUpdates = {
    HIVERELAY_RELEASE_EFFECTIVE_CHANNEL: channel,
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'passed'
  }

  const requireSecret = (name, statusNames, opts = {}) => {
    const value = String(env[name] || '')
    if (!value.trim()) {
      missing.push(name)
      for (const statusName of statusNames) envUpdates[statusName] = 'missing-secret'
      return
    }
    if (!opts.validate || opts.validate(value)) return
    missing.push(`${name} ${opts.message}`)
    for (const statusName of statusNames) envUpdates[statusName] = opts.status || 'invalid-secret'
  }

  const requireGitHubToken = (name, statusNames) => requireSecret(name, statusNames, {
    validate: isGitHubToken,
    status: 'invalid-token',
    message: 'must be a GitHub token without whitespace or control characters'
  })

  const requirePrivateKey = (name, statusNames) => requireSecret(name, statusNames, {
    validate: isPrivateKeyBlock,
    status: 'invalid-secret',
    message: 'must be a private key block'
  })

  const requireOptionalFleetTimeout = () => {
    const value = String(env.FLEET_ROLLOUT_TIMEOUT_MS || '')
    if (!value) return
    if (!isIntegerInRange(value, FLEET_ROLLOUT_TIMEOUT_MIN_MS, FLEET_ROLLOUT_TIMEOUT_MAX_MS)) {
      missing.push(`FLEET_ROLLOUT_TIMEOUT_MS must be an integer between ${FLEET_ROLLOUT_TIMEOUT_MIN_MS} and ${FLEET_ROLLOUT_TIMEOUT_MAX_MS} milliseconds without whitespace or control characters`)
      envUpdates.HIVERELAY_FLEET_ROLLOUT_STATUS = 'invalid-timeout'
    }
  }

  if (channel === 'none') {
    missing.push('release channel must be canary, stable, or both')
    envUpdates.HIVERELAY_FLEET_ROLLOUT_STATUS = 'missing-channel'
  } else {
    requirePrivateKey('FLEET_SSH_PRIVATE_KEY', ['HIVERELAY_FLEET_ROLLOUT_STATUS'])
    requireOptionalFleetTimeout()
  }

  requireGitHubToken('UMBREL_STORE_TOKEN', [
    'HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS',
    'HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS'
  ])
  requireGitHubToken('UMBREL_OFFICIAL_PR_TOKEN', ['HIVERELAY_UMBREL_OFFICIAL_PR_STATUS'])
  requireSecret('UMBREL_OFFICIAL_FORK', ['HIVERELAY_UMBREL_OFFICIAL_PR_STATUS'])
  if (String(env.UMBREL_OFFICIAL_FORK || '').trim() && !isOfficialUmbrelForkSlug(env.UMBREL_OFFICIAL_FORK)) {
    missing.push('UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug with a normal owner name and must not be getumbrel/umbrel-apps')
    envUpdates.HIVERELAY_UMBREL_OFFICIAL_PR_STATUS = 'invalid-fork'
  }
  requirePrivateKey('STARTOS_DEVELOPER_KEY_PEM', ['HIVERELAY_STARTOS_REGISTRY_STATUS'])
  requireSecret('STARTOS_REGISTRY_URL', ['HIVERELAY_STARTOS_REGISTRY_STATUS'])
  if (String(env.STARTOS_REGISTRY_URL || '').trim() && !isPublicHttpsUrl(env.STARTOS_REGISTRY_URL)) {
    missing.push('STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames')
    envUpdates.HIVERELAY_STARTOS_REGISTRY_STATUS = 'invalid-registry-url'
  }

  if (missing.length > 0) {
    envUpdates.HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS = 'failed'
    envUpdates.HIVERELAY_RELEASE_SURFACES_STATUS = 'blocked'
  }

  return {
    ok: missing.length === 0,
    skipped: false,
    missing,
    envUpdates
  }
}

function isGitHubToken (value) {
  return typeof value === 'string' &&
    value.trim() === value &&
    !hasControlChars(value) &&
    /^(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})$/.test(value)
}

function isPrivateKeyBlock (value) {
  if (typeof value !== 'string' || value.trim() !== value) return false
  if (hasPrivateKeyControlChars(value)) return false
  const normalized = value.replace(/\r\n/g, '\n')
  const match = /^-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----\n[\s\S]+\n-----END \1-----$/.exec(normalized)
  return Boolean(match)
}

function isIntegerInRange (value, min, max) {
  if (typeof value !== 'string' || value.trim() !== value) return false
  if (hasControlChars(value)) return false
  if (!/^[1-9][0-9]*$/.test(value)) return false
  const n = Number(value)
  return Number.isSafeInteger(n) && n >= min && n <= max
}

function hasPrivateKeyControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code === 10 || code === 13) continue
    if (code <= 31 || code === 127) return true
  }
  return false
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--channel') {
      out.channel = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--prerelease') {
      out.prerelease = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--github-env') {
      out.githubEnv = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--env-file') {
      out.envFile = readValue(argv, ++i, arg)
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function readEnvFile (file) {
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (err) {
    die(`Unable to read env file: ${sanitizeFileError(err)}`)
  }
  if (stat.isSymbolicLink()) die('Refusing to read symlinked env file')
  if (!stat.isFile()) die('Refusing to read env file because it is not a regular file')
  if (stat.size > MAX_ENV_FILE_BYTES) {
    die(`Refusing to read env file larger than ${MAX_ENV_FILE_BYTES} bytes`)
  }

  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (err) {
    die(`Unable to read env file: ${sanitizeFileError(err)}`)
  }
  return parseEnvFile(text)
}

function parseEnvFile (text) {
  if (text.includes('\u0000')) die('Env file contains a NUL byte')
  const env = {}
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (!line.trim() || line.trimStart().startsWith('#')) continue

    const heredoc = /^([A-Z_][A-Z0-9_]*)<<([A-Za-z0-9_.-]+)$/.exec(line)
    if (heredoc) {
      const [, name, delimiter] = heredoc
      assertEnvName(name, i + 1)
      if (!ENV_HEREDOC_DELIMITER_RE.test(delimiter)) {
        die(`Malformed env-file heredoc delimiter on line ${i + 1}`)
      }
      assertEnvKeyUnset(env, name)
      const valueLines = []
      let closed = false
      for (i = i + 1; i < lines.length; i++) {
        if (lines[i] === delimiter) {
          closed = true
          break
        }
        valueLines.push(lines[i])
      }
      if (!closed) die(`Unterminated env-file heredoc for ${name}`)
      env[name] = valueLines.join('\n')
      continue
    }

    const assignment = /^([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line)
    if (!assignment) die(`Malformed env-file line ${i + 1}`)
    const [, name, value] = assignment
    assertEnvName(name, i + 1)
    assertEnvKeyUnset(env, name)
    env[name] = value
  }

  return env
}

function assertEnvName (name, lineNumber) {
  if (!ENV_NAME_RE.test(name)) die(`Malformed env-file variable name on line ${lineNumber}`)
}

function assertEnvKeyUnset (env, name) {
  if (Object.hasOwn(env, name)) die(`Duplicate env-file variable: ${name}`)
}

function sanitizeFileError (err) {
  return err && err.code ? String(err.code) : 'unknown error'
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function readBoolean (value) {
  const normalized = String(value || 'false').trim().toLowerCase()
  if (normalized === 'true') return true
  if (normalized === 'false') return false
  die(`Invalid --prerelease "${value}". Expected true or false.`)
}

function isPublicHttpsUrl (value) {
  if (typeof value !== 'string' || !value || value.trim() !== value) return false
  if (hasControlChars(value)) return false
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

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function isOfficialUmbrelForkSlug (value) {
  if (typeof value !== 'string' || value.trim() !== value) return false
  if (hasControlChars(value)) return false
  const parts = value.split('/')
  if (parts.length !== 2) return false
  const [owner, repo] = parts
  return isGitHubOwnerName(owner) &&
    owner.toLowerCase() !== 'getumbrel' &&
    repo === 'umbrel-apps'
}

function isGitHubOwnerName (value) {
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value)
}

function appendGithubEnv (file, updates) {
  if (!file) return
  const lines = []
  for (const [name, value] of Object.entries(updates)) {
    lines.push(formatGithubEnvLine(name, value))
  }
  fs.appendFileSync(file, lines.join('\n') + '\n')
}

function formatGithubEnvLine (name, value) {
  if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
    die(`Refusing to write malformed GitHub environment variable name: ${JSON.stringify(name)}`)
  }
  const stringValue = String(value)
  if (hasControlChars(stringValue)) {
    die(`Refusing to write multi-line or control-character value for ${name} to GitHub environment file`)
  }
  return `${name}=${stringValue}`
}

function die (message) {
  console.error(message)
  process.exit(1)
}
