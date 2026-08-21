#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  appendGitHubEnv,
  resolveReusableStartos04ReleaseBinding
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  const binding = resolveReusableStartos04ReleaseBinding({
    repoRoot,
    tag: required(args, 'tag'),
    tagSha: required(args, 'tagSha'),
    releaseEvidencePath: required(args, 'releaseEvidence'),
    imageManifestEvidencePath: required(args, 'imageManifestEvidence')
  })
  appendGitHubEnv(required(args, 'githubEnv'), {
    HIVERELAY_IMAGE_DIGEST: binding.imageDigest
  })
  console.log(`Reusing source-bound release image ${binding.imageRef} from successful run ${binding.releaseSurfacesRunId}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
    ['--release-evidence', 'releaseEvidence'],
    ['--image-manifest-evidence', 'imageManifestEvidence'],
    ['--github-env', 'githubEnv']
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
