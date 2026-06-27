#!/usr/bin/env node

import { spawnSync } from 'node:child_process'

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

const OPTIONAL_VARIABLES = new Set([
  'FLEET_ROLLOUT_TIMEOUT_MS'
])

const FLEET_ROLLOUT_TIMEOUT_MIN_MS = 10 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MAX_MS = 4 * 60 * 60 * 1000

const usage = `
Usage:
  node scripts/check-github-release-setup.mjs [--repo owner/name] [--gh gh]

Checks that the GitHub repository exposes the masked release-value Secret names
and optional variable names needed before a full HiveRelay release can publish
the npm packages, update the raw fleet, Umbrel stores, and StartOS registry.

GitHub does not expose repository secret values through gh, so this command
checks secret presence and placement only. Run the manual
"Release distribution preflight" workflow after setting or rotating secrets to
validate the masked secret values without publishing release surfaces.
`

const args = parseArgs(process.argv.slice(2))
const repo = args.repo || process.env.HIVERELAY_RELEASE_REPO || 'bigdestiny2/P2P-Hiverelay'
const gh = args.gh || process.env.HIVERELAY_GH || 'gh'

if (!isRepoFullName(repo)) {
  die('Invalid --repo. Expected owner/name.')
}

const result = checkGithubReleaseSetup({ gh, repo })

if (!result.ok) {
  console.error('GitHub release setup check failed:')
  for (const item of result.errors) console.error(`- ${item}`)
  console.error('')
  console.error(formatRepairPath({ repo }))
  process.exit(1)
}

console.log(`GitHub release setup presence check passed for ${repo}.`)
console.log(`Required masked release values stored as GitHub Secrets: ${REQUIRED_SECRETS.length}/${REQUIRED_SECRETS.length}`)
if (result.optionalVariables.length > 0) {
  console.log(`Optional release variables: ${result.optionalVariables.join(', ')}`)
}
console.log('Secret values are not readable through gh; this is not a live-release proof.')
console.log('Run the "Release distribution preflight" GitHub Actions workflow to validate masked secret values before tagging.')

function checkGithubReleaseSetup ({ gh, repo }) {
  const errors = []
  const secretRows = runGhJson(gh, ['secret', 'list', '--repo', repo, '--json', 'name'])
  const variableRows = runGhJson(gh, ['variable', 'list', '--repo', repo, '--json', 'name,value'])

  if (!secretRows.ok) errors.push(secretRows.error)
  if (!variableRows.ok) errors.push(variableRows.error)
  if (errors.length > 0) return { ok: false, errors, optionalVariables: [] }

  const secretNames = new Set(secretRows.value.map(row => row && row.name).filter(Boolean))
  const variableMap = new Map(variableRows.value
    .filter(row => row && row.name)
    .map(row => [row.name, typeof row.value === 'string' ? row.value : '']))

  for (const name of REQUIRED_SECRETS) {
    if (!secretNames.has(name)) errors.push(`Missing repository secret ${name}`)
    if (variableMap.has(name)) {
      errors.push(`Required secret ${name} is configured as a repository variable; move it to GitHub Secrets`)
    }
  }

  for (const [name, value] of variableMap) {
    if (!OPTIONAL_VARIABLES.has(name)) continue
    if (name === 'FLEET_ROLLOUT_TIMEOUT_MS' && !isIntegerInRange(value, FLEET_ROLLOUT_TIMEOUT_MIN_MS, FLEET_ROLLOUT_TIMEOUT_MAX_MS)) {
      errors.push(`Repository variable FLEET_ROLLOUT_TIMEOUT_MS must be an integer between ${FLEET_ROLLOUT_TIMEOUT_MIN_MS} and ${FLEET_ROLLOUT_TIMEOUT_MAX_MS} milliseconds without whitespace or control characters`)
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    optionalVariables: [...variableMap.keys()].filter(name => OPTIONAL_VARIABLES.has(name))
  }
}

function runGhJson (gh, argv) {
  const result = spawnSync(gh, argv, {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })

  if (result.error) {
    return { ok: false, error: `Failed to run ${gh}: ${result.error.message}` }
  }

  if (result.status !== 0) {
    const details = sanitizeGhError(result.stderr || result.stdout || `exit ${result.status}`)
    return { ok: false, error: `gh ${argv.slice(0, 2).join(' ')} failed: ${details}` }
  }

  try {
    const value = JSON.parse(result.stdout || '[]')
    if (!Array.isArray(value)) throw new Error('expected JSON array')
    return { ok: true, value }
  } catch (err) {
    return { ok: false, error: `gh ${argv.slice(0, 2).join(' ')} returned invalid JSON: ${err.message}` }
  }
}

function sanitizeGhError (value) {
  return String(value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500)
}

function isIntegerInRange (value, min, max) {
  if (typeof value !== 'string' || value.trim() !== value) return false
  if (hasControlChars(value)) return false
  if (!/^[1-9][0-9]*$/.test(value)) return false
  const n = Number(value)
  return Number.isSafeInteger(n) && n >= min && n <= max
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
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
    if (arg === '--repo') {
      out.repo = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--gh') {
      out.gh = readValue(argv, ++i, arg)
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

function formatRepairPath ({ repo }) {
  return [
    'Repair path:',
    '- Generate a local candidate file outside the repo: npm run release:write-secret-template -- --out /private/tmp/hiverelay-release-secrets.env',
    '- Replace every REPLACE_* placeholder with corrected release values.',
    '- Validate candidate values locally: npm run release:check-distribution-env -- --env-file /private/tmp/hiverelay-release-secrets.env --channel both --prerelease false',
    `- Apply through stdin after validation: npm run release:apply-github-secrets -- --repo ${repo} --env-file /private/tmp/hiverelay-release-secrets.env`,
    `- Re-run this presence check: npm run release:check-github-setup -- --repo ${repo}`,
    `- Re-run masked-value preflight: gh workflow run release-distribution-preflight.yml --repo ${repo} --ref main -f channel=both -f prerelease=false`
  ].join('\n')
}

function die (message) {
  console.error(message)
  process.exit(1)
}
