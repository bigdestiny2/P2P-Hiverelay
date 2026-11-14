#!/usr/bin/env node

import {
  closeSync,
  constants as FS_CONSTANTS,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync
} from 'node:fs'
import { dirname, isAbsolute, normalize, resolve } from 'node:path'
import {
  adaptHc11TriggerToPearMigrateRecord,
  hc11PearMigrateRecordBytes,
  parseExactCanonicalJsonBytes
} from './lib/hc11-pear-migrate-adapter.mjs'

const args = parseArgs(process.argv.slice(2))
const triggerReceiptBytes = readRegular(args.triggerReceipt, 'HC11 trigger receipt')
const evidenceBytes = readRegular(args.evidence, 'HC11 adapter evidence')
const record = adaptHc11TriggerToPearMigrateRecord({
  triggerReceipt: parseExactCanonicalJsonBytes(triggerReceiptBytes, 'HC11 trigger receipt'),
  triggerReceiptBytes,
  evidence: parseExactCanonicalJsonBytes(evidenceBytes, 'HC11 adapter evidence'),
  evidenceBytes
})
const output = hc11PearMigrateRecordBytes(record)
mkdirSync(dirname(args.out), { recursive: true })
writeFileSync(args.out, output, { flag: 'wx', mode: 0o600 })
process.stdout.write(`${args.out}\n`)

function readRegular (file, label) {
  let descriptor
  try {
    const lstat = lstatSync(file)
    if (lstat.isSymbolicLink()) throw new Error(`${label} must not be a symlink`)
    descriptor = openSync(file, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW || 0))
    const stat = fstatSync(descriptor)
    if (!stat.isFile() || stat.size < 2 || stat.size > 2 * 1024 * 1024) {
      throw new Error(`${label} must be a regular file containing 2..2097152 bytes`)
    }
    const bytes = readFileSync(descriptor)
    if (bytes.byteLength !== stat.size) throw new Error(`${label} changed while it was read`)
    return bytes
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--trigger-receipt') out.triggerReceipt = canonical(argv[++i], arg)
    else if (arg === '--evidence') out.evidence = canonical(argv[++i], arg)
    else if (arg === '--out') out.out = canonical(argv[++i], arg)
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write('Usage: node scripts/adapt-pear-migrate-hc11-trigger.mjs --trigger-receipt <canonical.json> --evidence <canonical.json> --out <record.json>\n')
      process.exit(0)
    } else throw new Error(`unknown argument: ${arg}`)
  }
  for (const field of ['triggerReceipt', 'evidence', 'out']) {
    if (!out[field]) throw new Error(`missing required ${field}`)
  }
  if (new Set([out.triggerReceipt, out.evidence, out.out]).size !== 3) throw new Error('input and output paths must be distinct')
  return out
}

function canonical (value, flag) {
  if (typeof value !== 'string' || !isAbsolute(value) || normalize(value) !== value || value.includes('\0')) {
    throw new Error(`${flag} requires a canonical absolute path`)
  }
  return resolve(value)
}
