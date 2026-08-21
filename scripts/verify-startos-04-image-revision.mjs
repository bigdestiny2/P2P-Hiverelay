#!/usr/bin/env node

import fs from 'node:fs'
import { verifyStartos04ImageRevision } from './lib/startos-04-release-evidence.mjs'

const MAX_IMAGE_JSON_BYTES = 2 * 1024 * 1024

try {
  const args = parseArgs(process.argv.slice(2))
  const raw = fs.readFileSync(0)
  if (raw.length === 0 || raw.length > MAX_IMAGE_JSON_BYTES) {
    throw new Error(`release image child JSON must be between 1 and ${MAX_IMAGE_JSON_BYTES} bytes`)
  }
  let image
  try {
    image = JSON.parse(raw.toString('utf8'))
  } catch (err) {
    throw new Error(`release image child must be JSON: ${err.message}`)
  }
  verifyStartos04ImageRevision({
    image,
    expectedOs: required(args, 'os'),
    expectedArchitecture: required(args, 'architecture'),
    expectedRevision: required(args, 'revision')
  })
  console.log(`Verified ${args.os}/${args.architecture} release image revision ${args.revision}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--os', 'os'],
    ['--architecture', 'architecture'],
    ['--revision', 'revision']
  ])
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const name = names.get(argv[i])
    if (!name) throw new Error(`Unknown argument: ${argv[i]}`)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${argv[i - 1]}`)
    out[name] = value
  }
  return out
}

function required (args, name) {
  const value = args[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}
