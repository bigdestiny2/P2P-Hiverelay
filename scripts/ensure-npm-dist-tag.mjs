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
  const detail = cleanOutput(err?.stderr) || cleanOutput(err?.stdout) || cleanOutput(err?.message)
  return detail || 'unknown npm error'
}

function backoffDelay (attempt, initialDelayMs, maxDelayMs) {
  const exponent = Math.min(Math.max(attempt - 1, 0), 30)
  return Math.min(initialDelayMs * (2 ** exponent), maxDelayMs)
}

async function npmOutput (args) {
  const { stdout } = await execFile('npm', args, {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })
  return cleanOutput(stdout)
}

async function defaultViewPackageVersion (packageName, version) {
  return npmOutput(['view', `${packageName}@${version}`, 'version'])
}

async function defaultViewDistTag (packageName, distTag) {
  return npmOutput(['view', packageName, `dist-tags.${distTag}`])
}

async function defaultAddDistTag (packageName, version, distTag) {
  await npmOutput(['dist-tag', 'add', `${packageName}@${version}`, distTag])
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
  viewPackageVersion = defaultViewPackageVersion,
  viewDistTag = defaultViewDistTag,
  addDistTag = defaultAddDistTag,
  sleep = sleepTimer,
  log = console.log
}) {
  if (!safePackageName(packageName)) throw new TypeError('packageName is invalid')
  if (!safeVersion(version)) throw new TypeError('version is invalid')
  if (!safeDistTag(distTag)) throw new TypeError('distTag is invalid')
  attempts = positiveInteger(attempts, 'attempts')
  initialDelayMs = positiveInteger(initialDelayMs, 'initialDelayMs')
  maxDelayMs = positiveInteger(maxDelayMs, 'maxDelayMs')
  if (maxDelayMs < initialDelayMs) throw new TypeError('maxDelayMs must be greater than or equal to initialDelayMs')

  const packageVisibilityAttempts = await waitForPackageVisibility({
    packageName,
    version,
    attempts,
    initialDelayMs,
    maxDelayMs,
    viewPackageVersion,
    sleep,
    log
  })

  let mutationSucceeded = false
  let lastObserved = ''
  let lastError = ''

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      lastObserved = cleanOutput(await viewDistTag(packageName, distTag))
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
        await addDistTag(packageName, version, distTag)
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
    maxDelayMs: DEFAULT_MAX_DELAY_MS
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--package') out.packageName = argv[++i]
    else if (arg === '--version') out.version = argv[++i]
    else if (arg === '--tag') out.distTag = argv[++i]
    else if (arg === '--attempts') out.attempts = argv[++i]
    else if (arg === '--initial-delay-ms') out.initialDelayMs = argv[++i]
    else if (arg === '--max-delay-ms') out.maxDelayMs = argv[++i]
    else if (arg === '--help' || arg === '-h') out.help = true
    else throw new Error(`Unknown argument: ${arg}`)
  }

  return out
}

function usage () {
  return `Usage: node scripts/ensure-npm-dist-tag.mjs --package <name> --version <semver> --tag <dist-tag> [options]

Waits for a newly published immutable package version to become visible, then
sets and verifies its npm dist-tag with bounded exponential backoff.

Options:
  --attempts <n>           Attempts per visibility/readback phase (default: ${DEFAULT_ATTEMPTS})
  --initial-delay-ms <ms>  First retry delay (default: ${DEFAULT_INITIAL_DELAY_MS})
  --max-delay-ms <ms>      Backoff ceiling (default: ${DEFAULT_MAX_DELAY_MS})`
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage())
    return
  }
  if (!args.packageName || !args.version || !args.distTag) {
    throw new Error(`--package, --version, and --tag are required\n${usage()}`)
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
