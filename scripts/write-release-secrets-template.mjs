#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const defaultOut = '/private/tmp/hiverelay-release-secrets.env'

const usage = `
Usage:
  node scripts/write-release-secrets-template.mjs [--out <path>] [--force]

Writes a local candidate env-file template for release distribution values.
Most values are secrets; the Umbrel fork slug and StartOS registry URL are
also stored as GitHub Secrets so Actions masks them in logs. The template
contains placeholders only and is intended to live outside the repository. It
is written with owner-only permissions and refuses to overwrite an existing
file unless --force is passed.
`

const args = parseArgs(process.argv.slice(2))
const outFile = path.resolve(args.out || defaultOut)

if (isInsideRepo(outFile)) die('Refusing to write release secret template inside the repository. Use /private/tmp or another local private path.')

writeTemplate(outFile, args.force)

console.log(`Wrote release value candidate template: ${outFile}`)
console.log('Replace every REPLACE_* placeholder, then validate with:')
console.log(`npm run release:check-distribution-env -- --env-file ${outFile} --channel both --prerelease false`)

function writeTemplate (file, force) {
  const dir = path.dirname(file)
  let dirStat
  try {
    dirStat = fs.lstatSync(dir)
  } catch (err) {
    die(`Unable to access output directory: ${sanitizeFileError(err)}`)
  }
  if (!dirStat.isDirectory()) die('Output parent is not a directory')

  if (fs.existsSync(file)) {
    const stat = fs.lstatSync(file)
    if (stat.isSymbolicLink()) die('Refusing to overwrite symlinked output file')
    if (!stat.isFile()) die('Refusing to overwrite output path because it is not a regular file')
    if (!force) die(`Output file already exists: ${file}. Re-run with --force after reviewing it.`)
  }

  const flags = force ? 'w' : 'wx'
  fs.writeFileSync(file, templateBody(), { encoding: 'utf8', flag: flags, mode: 0o600 })
  fs.chmodSync(file, 0o600)
}

function templateBody () {
  return [
    '# HiveRelay release distribution values candidate.',
    '# This file is local-only. Do not commit it.',
    '# The fork slug and registry URL are stored as GitHub Secrets for log masking.',
    '# Replace every REPLACE_* placeholder, then run release:check-distribution-env.',
    '',
    'FLEET_SSH_PRIVATE_KEY<<FLEET_KEY',
    'REPLACE_WITH_FULL_FLEET_PRIVATE_KEY_BLOCK',
    'FLEET_KEY',
    'UMBREL_STORE_TOKEN=REPLACE_WITH_GITHUB_TOKEN_FOR_COMMUNITY_STORE',
    'UMBREL_OFFICIAL_PR_TOKEN=REPLACE_WITH_GITHUB_TOKEN_FOR_OFFICIAL_UMBREL_PR',
    'UMBREL_OFFICIAL_FORK=REPLACE_OWNER/umbrel-apps',
    'STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY',
    'REPLACE_WITH_FULL_STARTOS_DEVELOPER_PRIVATE_KEY_BLOCK',
    'STARTOS_KEY',
    'STARTOS_REGISTRY_URL=REPLACE_WITH_PUBLIC_HTTPS_REGISTRY_URL',
    '# Optional: 10 minutes to 4 hours, in milliseconds.',
    'FLEET_ROLLOUT_TIMEOUT_MS=1800000',
    ''
  ].join('\n')
}

function parseArgs (argv) {
  const out = {
    force: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--out') {
      out.out = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--force') {
      out.force = true
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

function isInsideRepo (file) {
  const rel = path.relative(repoRoot, file)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

function sanitizeFileError (err) {
  return err && err.code ? String(err.code) : 'unknown error'
}

function die (message) {
  console.error(message)
  process.exit(1)
}
