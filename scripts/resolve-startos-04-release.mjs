#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  appendGitHubEnv,
  resolveStartos04ReleaseBinding
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: required(args, 'tag'),
    tagSha: required(args, 'tagSha'),
    releaseSurfacesRunId: required(args, 'releaseSurfacesRunId'),
    expectedReleaseSurfacesRunAttempt: required(args, 'releaseSurfacesRunAttempt'),
    releaseEvidencePath: required(args, 'releaseEvidence'),
    imageManifestEvidencePath: required(args, 'imageManifestEvidence')
  })
  appendGitHubEnv(required(args, 'githubEnv'), {
    HIVERELAY_RELEASE_SURFACES_RUN_ID: binding.releaseSurfacesRunId,
    HIVERELAY_RELEASE_SURFACES_RUN_ATTEMPT: binding.releaseSurfacesRunAttempt,
    HIVERELAY_IMAGE_NAME: binding.imageName,
    HIVERELAY_IMAGE_DIGEST: binding.imageDigest,
    HIVERELAY_STARTOS_04_IMAGE_REF: binding.imageRef,
    HIVERELAY_STARTOS_04_PACKAGE_VERSION: binding.packageVersion,
    HIVERELAY_IMAGE_AMD64_DIGEST: binding.platforms.find(platform => platform.architecture === 'amd64').digest,
    HIVERELAY_IMAGE_ARM64_DIGEST: binding.platforms.find(platform => platform.architecture === 'arm64').digest
  })
  console.log(`Resolved StartOS 0.4 release image ${binding.imageRef} for ${binding.tag}@${binding.tagSha}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
    ['--release-surfaces-run-id', 'releaseSurfacesRunId'],
    ['--release-surfaces-run-attempt', 'releaseSurfacesRunAttempt'],
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
