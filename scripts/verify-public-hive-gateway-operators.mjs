#!/usr/bin/env node

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'
import {
  verifyPublicHiveGatewayOperatorSet
} from './lib/public-hive-gateway-ops.mjs'

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log(`Usage:
  node scripts/verify-public-hive-gateway-operators.mjs \\
    --mode <rehearsal|fleet> --evidence <operator-a.json> --evidence <operator-b.json> [...]

The verifier requires the same app bytes, drive version, and signed release,
plus distinct relay/operator identities, asserted registrable domains, app
suffixes, certificate fingerprints/SPKIs, and disjoint public address sets.
Organizational independence and registrable-domain ownership remain external
review inputs; rehearsal artifacts never support a production claim.`)
  process.exit(0)
}
if (args.mode !== 'rehearsal' && args.mode !== 'fleet') throw new Error('--mode must be rehearsal or fleet')
if (!Array.isArray(args.evidence) || args.evidence.length < 2) throw new Error('at least two --evidence files are required')

const evidences = []
for (const file of args.evidence) {
  const buffer = await readEvidence(requiredAbsolutePath(resolve(file), '--evidence'))
  try {
    evidences.push(JSON.parse(buffer.toString('utf8')))
  } catch {
    throw new Error(`operator readiness evidence is not valid JSON: ${file}`)
  }
}
console.log(JSON.stringify(verifyPublicHiveGatewayOperatorSet(evidences, { mode: args.mode }), null, 2))

function parseArgs (argv) {
  const out = { evidence: [] }
  for (let index = 0; index < argv.length; index++) {
    const raw = argv[index]
    if (raw === '-h' || raw === '--help') {
      out.help = true
      continue
    }
    if (raw !== '--mode' && raw !== '--evidence') throw new Error(`Unknown option: ${raw}`)
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${raw}`)
    if (raw === '--mode') {
      if (out.mode) throw new Error('Duplicate option: --mode')
      out.mode = value
    } else {
      if (out.evidence.includes(value)) throw new Error(`Duplicate operator evidence path: ${value}`)
      out.evidence.push(value)
    }
  }
  return out
}

async function readEvidence (file) {
  let handle
  try {
    if (typeof constants.O_NOFOLLOW !== 'number') throw new Error('safe no-follow opens are unavailable')
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    const maximum = 2 * 1024 * 1024
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximum)) throw new Error('invalid evidence file')
    const buffer = Buffer.allocUnsafe(maximum + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    if (length > maximum || BigInt(length) !== after.size || !sameSnapshot(before, after)) throw new Error('evidence changed')
    return buffer.subarray(0, length)
  } catch {
    throw new Error(`operator readiness evidence must be a bounded non-symlink regular file: ${file}`)
  } finally {
    await handle?.close()
  }
}

function requiredAbsolutePath (value, label) {
  if (!isAbsolute(value) || value.length > 4096 || /[\r\n\0]/.test(value)) throw new Error(`${label} must be a bounded absolute path`)
  return value
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
}
