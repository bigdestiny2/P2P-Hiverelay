#!/usr/bin/env node

import { HIVERELAY_DEPS, CURRENT_HIVERELAY_VERSION, verifyNpmLatestDistTags } from './audit-ecosystem-consumers.mjs'

function parseArgs (argv) {
  const out = { expectedVersion: CURRENT_HIVERELAY_VERSION, json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--json') {
      out.json = true
      continue
    }
    if (arg === '--expected-version') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error('Missing value for --expected-version')
      out.expectedVersion = value
      continue
    }
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function usage () {
  return `Usage: node scripts/check-npm-latest.mjs [--expected-version <semver>] [--json]

Verifies that every HiveRelay npm package latest dist-tag resolves to the
expected release version. Set HIVERELAY_NPM_LATEST_JSON for offline fixtures.`
}

function formatReport (result) {
  const lines = [
    `HiveRelay npm latest dist-tag check (expected ${result.expectedVersion})`
  ]

  for (const check of result.checks) {
    const status = check.ok ? 'PASS' : 'FAIL'
    if (check.latest == null && check.error) {
      lines.push(`${status} ${check.name}: latest=unverified (${check.error})`)
    } else {
      const latest = check.latest || '(missing)'
      lines.push(`${status} ${check.name}: latest=${latest}`)
    }
  }

  if (result.ok) {
    lines.push('All HiveRelay npm latest dist-tags are promoted.')
  } else {
    lines.push('Blocked: app lockfiles and live consumer promotion must wait until npm latest points at this release.')
    lines.push('Publish or retag through release-surfaces.yml, then rerun this check and npm run ecosystem:sync -- --check.')
  }

  return lines.join('\n')
}

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    console.error(usage())
    process.exit(1)
  }

  if (args.help) {
    console.log(usage())
    return
  }

  const check = verifyNpmLatestDistTags({
    expectedCurrent: [],
    expectedVersion: args.expectedVersion
  })
  const result = {
    ok: check.ok,
    expectedVersion: args.expectedVersion,
    packages: HIVERELAY_DEPS,
    checks: check.checks,
    errors: check.errors,
    warnings: check.warnings
  }

  if (args.json) console.log(JSON.stringify(result, null, 2))
  else console.log(formatReport(result))

  if (!result.ok) process.exit(1)
}

main()
