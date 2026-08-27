#!/usr/bin/env node

import fs from 'node:fs'
import {
  appendGitHubEnv,
  selectReusableReleaseImageArtifact
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))

try {
  const response = JSON.parse(fs.readFileSync(required(args, 'artifacts'), 'utf8'))
  const artifact = selectReusableReleaseImageArtifact({
    response,
    expectedTag: required(args, 'tag'),
    expectedTagSha: required(args, 'tagSha')
  })
  const env = {
    HIVERELAY_REUSABLE_ARTIFACT_FOUND: artifact.found ? 'true' : 'false',
    HIVERELAY_REUSABLE_ARTIFACT_NAME: artifact.name
  }
  if (artifact.found) {
    Object.assign(env, {
      HIVERELAY_REUSABLE_ARTIFACT_ID: artifact.id,
      HIVERELAY_REUSABLE_ARTIFACT_DIGEST: artifact.digest,
      HIVERELAY_REUSABLE_ARTIFACT_SIZE: String(artifact.sizeInBytes),
      HIVERELAY_REUSABLE_ARTIFACT_ARCHIVE_URL: artifact.archiveUrl,
      HIVERELAY_REUSABLE_ARTIFACT_SOURCE_RUN_ID: artifact.sourceRunId
    })
  }
  appendGitHubEnv(required(args, 'githubEnv'), env)
  console.log(artifact.found
    ? `Selected immutable reusable image authority artifact ${artifact.id} from run ${artifact.sourceRunId}`
    : `No live immutable reusable image authority artifact named ${artifact.name} exists`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--artifacts', 'artifacts'],
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
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
