#!/usr/bin/env node

import {
  readAndVerifyPublicHiveGatewayEvidence
} from './lib/public-hive-gateway-evidence.mjs'

const usage = `
Usage:
  node scripts/verify-public-hive-gateway-evidence.mjs \\
    --evidence </absolute/path/preflight-live.json> \\
    --release-target <vX.Y.Z> \\
    --release-sha <40-or-64-hex>

Options:
  --require-mode <fleet>                    Require the production posture
  --require-admission-profile <profile>     Require the frozen admission profile
  --expected-origin <https-origin>          Bind the exact public origin
  --expected-connect-address <IP>           Bind the probed node address
  --expected-app-key <64-hex>               Bind the canonical app key
  --expected-path </path>                   Bind the exact content path
  --expected-sha256 <64-hex>                Bind the exact content digest
  --expected-drive-version <decimal>        Bind the immutable drive checkout
  --expected-peer-fingerprint256 <AA:...>   Bind the node TLS certificate
  --expected-nginx-sha256 <64-hex>          Bind the complete active nginx -T dump
  --rollout-token                           Print base64url public verification JSON
  --digest-only                             Print only the evidence SHA-256
  --help                                    Show this help

The evidence file must be bounded, regular, and non-symlink. The command
requires evidence no older than 24 hours with at most five minutes of future
clock skew. It prints no API keys, response bodies, private paths, or other
secret material.`

try {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage.trim())
  } else {
    if (!args.evidence) throw new Error('--evidence is required')
    if (!args.releaseTarget) throw new Error('--release-target is required')
    if (!args.releaseSha) throw new Error('--release-sha is required')
    const result = await readAndVerifyPublicHiveGatewayEvidence({
      file: args.evidence,
      releaseTarget: args.releaseTarget,
      releaseSha: args.releaseSha,
      requireMode: args.requireMode,
      requireAdmissionProfile: args.requireAdmissionProfile,
      expectedOrigin: args.expectedOrigin,
      expectedConnectAddress: args.expectedConnectAddress,
      expectedAppKey: args.expectedAppKey,
      expectedPath: args.expectedPath,
      expectedSha256: args.expectedSha256,
      expectedDriveVersion: args.expectedDriveVersion,
      expectedPeerFingerprint256: args.expectedPeerFingerprint256,
      expectedNginxSha256: args.expectedNginxSha256
    })
    const publicResult = { ...result }
    delete publicResult.evidencePath
    if (args.digestOnly) {
      console.log(result.evidenceSha256)
    } else if (args.rolloutToken) {
      console.log(Buffer.from(JSON.stringify(publicResult)).toString('base64url'))
    } else {
      console.log(JSON.stringify(publicResult))
    }
  }
} catch (err) {
  console.error(`public gateway evidence: ${safeError(err)}`)
  process.exitCode = 1
}

function parseArgs (argv) {
  const out = {}
  const values = new Set([
    'evidence',
    'release-target',
    'release-sha',
    'require-mode',
    'require-admission-profile',
    'expected-origin',
    'expected-connect-address',
    'expected-app-key',
    'expected-path',
    'expected-sha256',
    'expected-drive-version',
    'expected-peer-fingerprint256',
    'expected-nginx-sha256'
  ])
  const booleans = new Set(['digest-only', 'rollout-token', 'help'])
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('duplicate --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`unexpected argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!values.has(name) && !booleans.has(name)) throw new Error(`unknown option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate option --${name}`)
    seen.add(name)
    const key = camel(name)
    if (booleans.has(name)) {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${name}`)
    out[key] = value
  }
  if (out.digestOnly && out.rolloutToken) throw new Error('--digest-only and --rollout-token are mutually exclusive')
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}

function safeError (err) {
  const value = err instanceof Error ? err.message : String(err)
  return value.replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}
