#!/usr/bin/env node

import fs from 'node:fs'
import {
  verifyStartos04AuthoringManifest,
  verifyStartos04PackedManifest
} from './lib/startos-04-release-evidence.mjs'

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024

try {
  const args = parseArgs(process.argv.slice(2))
  const raw = fs.readFileSync(0)
  if (raw.length === 0 || raw.length > MAX_MANIFEST_BYTES) {
    throw new Error(`StartOS 0.4 package manifest must be between 1 and ${MAX_MANIFEST_BYTES} bytes`)
  }
  let manifest
  try {
    manifest = JSON.parse(raw.toString('utf8'))
  } catch (err) {
    throw new Error(`StartOS 0.4 package manifest must be JSON: ${err.message}`)
  }
  const kind = required(args, 'manifestKind')
  if (!['authoring', 'packed'].includes(kind)) throw new Error('--manifest-kind must be authoring or packed')
  if (kind === 'packed' && args.imageRef) throw new Error('--image-ref is forbidden for a packed manifest')
  const common = {
    manifest,
    expectedTag: required(args, 'tag'),
    expectedReleaseSha: required(args, 'releaseSha'),
    expectedPackageVersion: required(args, 'packageVersion')
  }
  const identity = kind === 'authoring'
    ? verifyStartos04AuthoringManifest({ ...common, expectedImageRef: required(args, 'imageRef') })
    : verifyStartos04PackedManifest(common)
  const binding = kind === 'authoring'
    ? `digest-bound authoring ref ${identity.runtimeImage.ref}`
    : 'embedded packed runtime image'
  console.log(`Verified ${identity.id}@${identity.version} ${binding}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--manifest-kind', 'manifestKind'],
    ['--tag', 'tag'],
    ['--release-sha', 'releaseSha'],
    ['--package-version', 'packageVersion'],
    ['--image-ref', 'imageRef']
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
