#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  resolveStartos04ReleaseBinding,
  verifyPublishedStartos04ReleaseAssets
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: required(args, 'tag'),
    tagSha: required(args, 'tagSha'),
    releaseSurfacesRunId: required(args, 'releaseSurfacesRunId'),
    releaseEvidencePath: required(args, 'releaseEvidence'),
    imageManifestEvidencePath: required(args, 'imageManifestEvidence')
  })
  verifyPublishedStartos04ReleaseAssets({
    evidencePath: required(args, 'startos04Evidence'),
    binding,
    packagePath: required(args, 'package')
  })
  console.log(`Published StartOS 0.4 handoff verified for ${binding.tag}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
    ['--release-surfaces-run-id', 'releaseSurfacesRunId'],
    ['--release-evidence', 'releaseEvidence'],
    ['--image-manifest-evidence', 'imageManifestEvidence'],
    ['--package', 'package'],
    ['--startos-0.4-evidence', 'startos04Evidence']
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
