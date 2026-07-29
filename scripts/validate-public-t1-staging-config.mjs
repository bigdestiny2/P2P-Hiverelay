#!/usr/bin/env node
/**
 * Phase-1 / staging foot-gun checker for public-t1-gateway configs.
 *
 * Thin CLI over inspectPublicHiveGatewayConfig (canary mode). Use this before
 * copying a config onto a staging VPS. Does not start a relay or touch fleet.
 *
 * Usage:
 *   node scripts/validate-public-t1-staging-config.mjs --config path/to.json
 *   node scripts/validate-public-t1-staging-config.mjs --config path/to.json --json
 *
 * Exit codes:
 *   0 — ok (warnings allowed)
 *   1 — validation errors
 *   2 — usage / IO failure
 */

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { inspectPublicHiveGatewayConfig } from './lib/public-hive-gateway-preflight.mjs'

function printUsage (stream = process.stderr) {
  stream.write(`Usage:
  node scripts/validate-public-t1-staging-config.mjs --config <path.json> [--json]

Checks (canary / staging posture):
  - productProfile should be public-t1-gateway (error if missing wrong profile for product)
  - exactly one hiveAppPublicKeys entry
  - custody.enabled must be false
  - finite gatewayMaxResponseBytes / transform / egress / lifetime pins
  - loopback apiHost + gatewayHost, trust proxy, physical enforcement
  - HIVERELAY_API_KEY presence is reported (set in env when validating for real deploys)

Does not authorize fleet mode, publish, or production DNS.
`)
}

function parseArgs (argv) {
  const args = { json: false, config: null }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--json') args.json = true
    else if (a === '--config' || a === '-c') {
      args.config = argv[++i]
      if (!args.config) throw new Error('--config requires a path')
    } else if (a === '--help' || a === '-h') args.help = true
    else throw new Error(`unknown argument: ${a}`)
  }
  return args
}

export function validateStagingConfigObject (config, opts = {}) {
  const apiKeyPresent = opts.apiKeyPresent !== undefined
    ? opts.apiKeyPresent
    : Boolean(process.env.HIVERELAY_API_KEY && String(process.env.HIVERELAY_API_KEY).length > 0)

  const result = inspectPublicHiveGatewayConfig(config, {
    mode: 'canary',
    apiKeyPresent,
    publicSuffixReady: false,
    explicitConfig: config
  })

  const errors = [...(result.errors || [])]
  const warnings = [...(result.warnings || [])]

  // Extra product-profile clarity for staging operators (preflight allows
  // relay-core in some fixtures; staging product track wants public-t1-gateway).
  if (config && config.productProfile !== 'public-t1-gateway') {
    errors.push('productProfile must be "public-t1-gateway" for the staging public distribution track')
  }

  if (!apiKeyPresent) {
    warnings.push('HIVERELAY_API_KEY is not set in this environment; set it before live preflight on the host')
  }

  return {
    ok: errors.length === 0,
    mode: 'canary',
    productTrack: 'public-t1-gateway',
    errors,
    warnings,
    normalized: result.normalized || null,
    footgunsChecked: [
      'exactly-one-public-app-key',
      'custody-disabled',
      'finite-max-response-bytes',
      'loopback-api-and-gateway-hosts',
      'require-physical-enforcement',
      'product-profile-public-t1-gateway'
    ]
  }
}

async function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    printUsage()
    console.error(err.message)
    process.exitCode = 2
    return
  }
  if (args.help || !args.config) {
    printUsage(args.help ? process.stdout : process.stderr)
    process.exitCode = args.help ? 0 : 2
    return
  }

  const path = resolve(args.config)
  let raw
  try {
    raw = await readFile(path, 'utf8')
  } catch (err) {
    console.error(`cannot read config: ${path}: ${err.message}`)
    process.exitCode = 2
    return
  }

  let config
  try {
    config = JSON.parse(raw)
  } catch (err) {
    console.error(`invalid JSON in ${path}: ${err.message}`)
    process.exitCode = 2
    return
  }

  const report = validateStagingConfigObject(config)
  if (args.json) {
    console.log(JSON.stringify({ configPath: path, ...report }, null, 2))
  } else {
    console.log(`public-t1 staging config: ${path}`)
    console.log(`status: ${report.ok ? 'PASS' : 'FAIL'}`)
    if (report.errors.length) {
      console.log('errors:')
      for (const e of report.errors) console.log(`  - ${e}`)
    }
    if (report.warnings.length) {
      console.log('warnings:')
      for (const w of report.warnings) console.log(`  - ${w}`)
    }
    if (report.ok) {
      console.log('footguns checked:', report.footgunsChecked.join(', '))
    }
  }
  process.exitCode = report.ok ? 0 : 1
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((err) => {
    console.error(err)
    process.exitCode = 2
  })
}
