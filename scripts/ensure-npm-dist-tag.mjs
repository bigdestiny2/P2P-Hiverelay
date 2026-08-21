#!/usr/bin/env node

import { execFile as execFileCallback } from 'node:child_process'
import { setTimeout as sleepTimer } from 'node:timers/promises'
import { promisify } from 'node:util'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const execFile = promisify(execFileCallback)

export const DEFAULT_ATTEMPTS = 12
export const DEFAULT_INITIAL_DELAY_MS = 2000
export const DEFAULT_MAX_DELAY_MS = 15000
export const DEFAULT_COMMAND_TIMEOUT_MS = 30000

function positiveInteger (value, label) {
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${label} must be a positive integer`)
  }
  return parsed
}

function hasUnsafeWhitespace (value) {
  if (/\s/.test(value)) return true
  for (const char of value) {
    const codePoint = char.codePointAt(0)
    if (codePoint < 32 || codePoint === 127) return true
  }
  return false
}

function safePackageName (value) {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 214 &&
    !value.startsWith('-') &&
    !hasUnsafeWhitespace(value) &&
    /^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(value)
}

function safeVersion (value) {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 128 &&
    !value.startsWith('-') &&
    !hasUnsafeWhitespace(value)
}

function safeDistTag (value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9._-]*$/i.test(value)
}

function cleanOutput (value) {
  return String(value == null ? '' : value).trim()
}

function errorDetail (err) {
  if (err?.code === 'ETIMEDOUT') return cleanOutput(err?.message) || 'npm command timed out'
  const detail = cleanOutput(err?.stderr) || cleanOutput(err?.stdout) || cleanOutput(err?.message)
  return detail || 'unknown npm error'
}

function backoffDelay (attempt, initialDelayMs, maxDelayMs) {
  const exponent = Math.min(Math.max(attempt - 1, 0), 30)
  return Math.min(initialDelayMs * (2 ** exponent), maxDelayMs)
}

export async function execOutputWithTimeout (command, args, {
  timeoutMs = DEFAULT_COMMAND_TIMEOUT_MS
} = {}) {
  timeoutMs = positiveInteger(timeoutMs, 'timeoutMs')

  try {
    const { stdout } = await execFile(command, args, {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      timeout: timeoutMs,
      killSignal: 'SIGKILL'
    })
    return cleanOutput(stdout)
  } catch (err) {
    if (err?.killed || err?.signal === 'SIGKILL') {
      const timeoutError = new Error(`${command} command timed out after ${timeoutMs}ms`)
      timeoutError.code = 'ETIMEDOUT'
      timeoutError.stdout = err.stdout
      timeoutError.stderr = err.stderr
      throw timeoutError
    }
    throw err
  }
}

async function npmOutput (args, commandTimeoutMs) {
  return execOutputWithTimeout('npm', args, { timeoutMs: commandTimeoutMs })
}

async function defaultViewPackageVersion (packageName, version, commandTimeoutMs) {
  return npmOutput(['view', `${packageName}@${version}`, 'version'], commandTimeoutMs)
}

async function defaultViewDistTag (packageName, distTag, commandTimeoutMs) {
  return npmOutput(['view', packageName, `dist-tags.${distTag}`], commandTimeoutMs)
}

async function defaultAddDistTag (packageName, version, distTag, commandTimeoutMs) {
  await npmOutput(['dist-tag', 'add', `${packageName}@${version}`, distTag], commandTimeoutMs)
}

function npmPackageIsMissing (err) {
  if (err?.code === 'ETIMEDOUT') return false
  const detail = `${cleanOutput(err?.stderr)}\n${cleanOutput(err?.stdout)}`
  return /\bE404\b|\b404 Not Found\b|is not in this registry/i.test(detail)
}

export async function probeNpmPackageVersion ({
  packageName,
  version,
  commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
  viewPackageVersion
}) {
  if (!safePackageName(packageName)) throw new TypeError('packageName is invalid')
  if (!safeVersion(version)) throw new TypeError('version is invalid')
  commandTimeoutMs = positiveInteger(commandTimeoutMs, 'commandTimeoutMs')
  const readPackageVersion = viewPackageVersion || ((name, expected) => (
    defaultViewPackageVersion(name, expected, commandTimeoutMs)
  ))

  let observed
  try {
    observed = cleanOutput(await readPackageVersion(packageName, version))
  } catch (err) {
    if (npmPackageIsMissing(err)) return false
    throw new Error(`Could not determine whether ${packageName}@${version} already exists on npm: ${errorDetail(err)}`)
  }

  if (observed !== version) {
    throw new Error(`npm returned ${observed || '(empty)'} while probing ${packageName}@${version}; expected exact version ${version}`)
  }
  return true
}

async function waitForPackageVisibility ({
  packageName,
  version,
  attempts,
  initialDelayMs,
  maxDelayMs,
  viewPackageVersion,
  sleep,
  log
}) {
  let lastObserved = ''
  let lastError = ''

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      lastObserved = cleanOutput(await viewPackageVersion(packageName, version))
      lastError = ''
      if (lastObserved === version) return attempt
    } catch (err) {
      lastObserved = ''
      lastError = errorDetail(err)
    }

    if (attempt === attempts) break
    const delayMs = backoffDelay(attempt, initialDelayMs, maxDelayMs)
    const observation = lastError || lastObserved || '(missing)'
    log(`npm visibility attempt ${attempt}/${attempts} for ${packageName}@${version} returned ${observation}; retrying in ${delayMs}ms.`)
    await sleep(delayMs)
  }

  const observation = lastError || lastObserved || '(missing)'
  throw new Error(`npm package ${packageName}@${version} was not visible after ${attempts} attempts; last observation: ${observation}`)
}

export async function ensureNpmDistTag ({
  packageName,
  version,
  distTag,
  attempts = DEFAULT_ATTEMPTS,
  initialDelayMs = DEFAULT_INITIAL_DELAY_MS,
  maxDelayMs = DEFAULT_MAX_DELAY_MS,
  commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
  viewPackageVersion,
  viewDistTag,
  addDistTag,
  sleep = sleepTimer,
  log = console.log
}) {
  if (!safePackageName(packageName)) throw new TypeError('packageName is invalid')
  if (!safeVersion(version)) throw new TypeError('version is invalid')
  if (!safeDistTag(distTag)) throw new TypeError('distTag is invalid')
  attempts = positiveInteger(attempts, 'attempts')
  initialDelayMs = positiveInteger(initialDelayMs, 'initialDelayMs')
  maxDelayMs = positiveInteger(maxDelayMs, 'maxDelayMs')
  commandTimeoutMs = positiveInteger(commandTimeoutMs, 'commandTimeoutMs')
  if (maxDelayMs < initialDelayMs) throw new TypeError('maxDelayMs must be greater than or equal to initialDelayMs')
  const readPackageVersion = viewPackageVersion || ((name, expected) => (
    defaultViewPackageVersion(name, expected, commandTimeoutMs)
  ))
  const readDistTag = viewDistTag || ((name, tag) => (
    defaultViewDistTag(name, tag, commandTimeoutMs)
  ))
  const updateDistTag = addDistTag || ((name, expected, tag) => (
    defaultAddDistTag(name, expected, tag, commandTimeoutMs)
  ))

  const packageVisibilityAttempts = await waitForPackageVisibility({
    packageName,
    version,
    attempts,
    initialDelayMs,
    maxDelayMs,
    viewPackageVersion: readPackageVersion,
    sleep,
    log
  })

  let mutationSucceeded = false
  let lastObserved = ''
  let lastError = ''

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      lastObserved = cleanOutput(await readDistTag(packageName, distTag))
      lastError = ''
      if (lastObserved === version) {
        log(`Verified ${packageName} npm '${distTag}' dist-tag at ${version} after ${attempt} readback attempt(s).`)
        return {
          packageName,
          version,
          distTag,
          packageVisibilityAttempts,
          distTagReadbackAttempts: attempt,
          mutationRequested: mutationSucceeded
        }
      }
    } catch (err) {
      lastObserved = ''
      lastError = errorDetail(err)
    }

    if (!mutationSucceeded) {
      try {
        await updateDistTag(packageName, version, distTag)
        mutationSucceeded = true
        log(`Requested npm '${distTag}' dist-tag ${packageName}@${version}; waiting for registry readback.`)
      } catch (err) {
        lastError = errorDetail(err)
        log(`npm dist-tag update attempt ${attempt}/${attempts} for ${packageName}@${version} failed: ${lastError}`)
      }
    }

    if (attempt === attempts) break
    const delayMs = backoffDelay(attempt, initialDelayMs, maxDelayMs)
    const observation = lastError || lastObserved || '(missing)'
    log(`npm '${distTag}' readback attempt ${attempt}/${attempts} for ${packageName} returned ${observation}; retrying in ${delayMs}ms.`)
    await sleep(delayMs)
  }

  const observation = lastError || lastObserved || '(missing)'
  throw new Error(`${packageName} npm '${distTag}' dist-tag did not converge to ${version} after ${attempts} attempts; last observation: ${observation}`)
}

function parseArgs (argv) {
  const out = {
    attempts: DEFAULT_ATTEMPTS,
    initialDelayMs: DEFAULT_INITIAL_DELAY_MS,
    maxDelayMs: DEFAULT_MAX_DELAY_MS,
    commandTimeoutMs: DEFAULT_COMMAND_TIMEOUT_MS
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--package') out.packageName = argv[++i]
    else if (arg === '--version') out.version = argv[++i]
    else if (arg === '--tag') out.distTag = argv[++i]
    else if (arg === '--attempts') out.attempts = argv[++i]
    else if (arg === '--initial-delay-ms') out.initialDelayMs = argv[++i]
    else if (arg === '--max-delay-ms') out.maxDelayMs = argv[++i]
    else if (arg === '--command-timeout-ms') out.commandTimeoutMs = argv[++i]
    else if (arg === '--probe-only') out.probeOnly = true
    else if (arg === '--help' || arg === '-h') out.help = true
    else throw new Error(`Unknown argument: ${arg}`)
  }

  return out
}

function usage () {
  return `Usage:
  node scripts/ensure-npm-dist-tag.mjs --probe-only --package <name> --version <semver> [options]
  node scripts/ensure-npm-dist-tag.mjs --package <name> --version <semver> --tag <dist-tag> [options]

Waits for a newly published immutable package version to become visible, then
sets and verifies its npm dist-tag with bounded exponential backoff.

Options:
  --attempts <n>           Attempts per visibility/readback phase (default: ${DEFAULT_ATTEMPTS})
  --initial-delay-ms <ms>  First retry delay (default: ${DEFAULT_INITIAL_DELAY_MS})
  --max-delay-ms <ms>      Backoff ceiling (default: ${DEFAULT_MAX_DELAY_MS})
  --command-timeout-ms <ms>  Per-command timeout (default: ${DEFAULT_COMMAND_TIMEOUT_MS})
  --probe-only             Print visible or missing without changing a dist-tag`
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage())
    return
  }
  if (!args.packageName || !args.version) {
    throw new Error(`--package and --version are required\n${usage()}`)
  }
  if (args.probeOnly) {
    if (args.distTag) throw new Error('--tag cannot be used with --probe-only')
    const visible = await probeNpmPackageVersion(args)
    console.log(visible ? 'visible' : 'missing')
    return
  }
  if (!args.distTag) {
    throw new Error(`--tag is required unless --probe-only is used\n${usage()}`)
  }
  await ensureNpmDistTag(args)
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (isMain) {
  main().catch((err) => {
    console.error(err.message)
    process.exitCode = 1
  })
}
