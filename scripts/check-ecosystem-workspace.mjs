#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { EXPECTED_CURRENT_CONSUMERS } from './audit-ecosystem-consumers.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const hiverelayRoot = path.resolve(here, '..')
const workspaceRootDefault = path.resolve(hiverelayRoot, '..', '..')

const usage = `
Usage:
  node scripts/check-ecosystem-workspace.mjs [--workspace-root <path>] [--required] [--optional]

Verifies that the full sibling Pear ecosystem app workspace is present before a
stable release attempts to move PearBrowser, PearPaste, anonGPT, and the other
direct app consumers to the Hiverelay npm latest release line.
`

if (isMain()) main()

export function checkEcosystemWorkspace (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const expectedCurrent = opts.expectedCurrent || EXPECTED_CURRENT_CONSUMERS
  const present = []
  const missing = []

  for (const consumer of expectedCurrent) {
    const file = path.join(workspaceRoot, consumer.path)
    const row = {
      path: consumer.path,
      role: consumer.role || null,
      file
    }
    if (fs.existsSync(file)) present.push(row)
    else missing.push(row)
  }

  const errors = []
  if (expectedCurrent.length === 0) {
    errors.push('no expected ecosystem consumers are configured')
  } else if (missing.length === expectedCurrent.length) {
    errors.push(`full sibling workspace not found; missing all ${missing.length} expected ecosystem consumers`)
  } else if (missing.length > 0) {
    errors.push(`missing ${missing.length} expected ecosystem consumer(s): ${missing.map(row => row.path).join(', ')}`)
  }

  return {
    ok: errors.length === 0,
    workspaceRoot,
    expected: expectedCurrent.length,
    present,
    missing,
    errors
  }
}

function parseArgs (argv) {
  const out = { required: true }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--required') {
      out.required = true
      continue
    }
    if (arg === '--optional') {
      out.required = false
      continue
    }
    if (arg === '--workspace-root') {
      out.workspaceRoot = readValue(argv, ++i, arg)
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`)
  return value
}

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    process.exit(1)
  }

  const result = checkEcosystemWorkspace(args)
  console.log(`HiveRelay ecosystem workspace check (${result.workspaceRoot})`)
  console.log(`- present ${result.present.length}/${result.expected} expected app consumers`)
  for (const row of result.present) {
    const role = row.role ? ` [${row.role}]` : ''
    console.log(`- ${row.path}${role}`)
  }
  for (const error of result.errors) console.error(`ERROR ${error}`)
  if (!result.ok && args.required) process.exit(1)
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}
