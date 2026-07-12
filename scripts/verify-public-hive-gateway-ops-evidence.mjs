#!/usr/bin/env node

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { isUtf8 } from 'node:buffer'
import { isAbsolute, resolve } from 'node:path'
import {
  verifyPublicHiveGatewayOpsEvidence
} from './lib/public-hive-gateway-ops.mjs'

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log(`Usage:
  node scripts/verify-public-hive-gateway-ops-evidence.mjs \\
    --evidence <ops.json> --contract <operator.json> \\
    --release-manifest <manifest.json> --release-sha <verified-tag-commit> \\
    --relay <name> --expected-contract-sha256 <64-hex>

Verifies a fresh fleet-mode artifact against the canonical signed cohort and
prints only a public summary. It proves no independent timestamp, blind G2/G3,
or organizational control.`)
  process.exit(0)
}

const required = ['evidence', 'contract', 'releaseManifest', 'releaseSha', 'relay', 'expectedContractSha256']
for (const name of required) if (!args[name]) throw new Error(`--${kebab(name)} is required`)
const evidenceBytes = await readBounded(requiredAbsolutePath(args.evidence, '--evidence'), 'operator readiness evidence', 2 * 1024 * 1024)
const contractBytes = await readBounded(requiredAbsolutePath(args.contract, '--contract'), 'operator readiness contract', 256 * 1024)
const manifestBytes = await readBounded(requiredAbsolutePath(args.releaseManifest, '--release-manifest'), 'public gateway release manifest', 2 * 1024 * 1024)
const result = verifyPublicHiveGatewayOpsEvidence(
  parseJson(evidenceBytes, 'operator readiness evidence'),
  {
    contract: parseJson(contractBytes, 'operator readiness contract'),
    manifest: parseJson(manifestBytes, 'public gateway release manifest'),
    releaseSha: args.releaseSha,
    relay: args.relay,
    expectedContractSha256: args.expectedContractSha256,
    contractFileSha256: createHash('sha256').update(contractBytes).digest('hex'),
    releaseManifestSha256: createHash('sha256').update(manifestBytes).digest('hex')
  }
)
console.log(JSON.stringify(result, null, 2))

function parseArgs (argv) {
  const out = {}
  const allowed = new Set([
    'evidence', 'contract', 'release-manifest', 'release-sha', 'relay',
    'expected-contract-sha256', 'help'
  ])
  const seen = new Set()
  for (let index = 0; index < argv.length; index++) {
    const raw = argv[index]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('Duplicate option: --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`Unexpected argument: ${raw}`)
    const name = raw.slice(2)
    if (!allowed.has(name)) throw new Error(`Unknown option: --${name}`)
    if (seen.has(name)) throw new Error(`Duplicate option: --${name}`)
    seen.add(name)
    if (name === 'help') {
      out.help = true
      continue
    }
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for --${name}`)
    out[camel(name)] = value
  }
  return out
}

async function readBounded (value, label, maximum) {
  const file = resolve(value)
  let handle
  try {
    if (typeof constants.O_NOFOLLOW !== 'number') throw new Error('safe no-follow opens are unavailable')
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) {
      throw new Error(`${label} must be a bounded single-link regular file`)
    }
    const buffer = Buffer.allocUnsafe(maximum + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    if (length > maximum || BigInt(length) !== after.size || !sameSnapshot(before, after)) {
      throw new Error(`${label} changed while being read`)
    }
    return buffer.subarray(0, length)
  } catch (err) {
    if (err?.message?.startsWith(label)) throw err
    throw new Error(`${label} must be a readable non-symlink file`)
  } finally {
    await handle?.close()
  }
}

function parseJson (buffer, label) {
  if (!isUtf8(buffer)) throw new Error(`${label} must be UTF-8 JSON`)
  let value
  try { value = JSON.parse(buffer.toString('utf8')) } catch { throw new Error(`${label} must be valid JSON`) }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must contain a JSON object`)
  return value
}

function requiredAbsolutePath (value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new Error(`${label} must be a bounded absolute path`)
  }
  return value
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}

function kebab (value) {
  return value.replace(/[A-Z]/g, character => `-${character.toLowerCase()}`)
}
