#!/usr/bin/env node

import fs from 'node:fs'
import {
  appendGitHubEnv,
  selectStartos04ReleaseImageAuthorityArtifact
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))

try {
  const response = JSON.parse(fs.readFileSync(required(args, 'artifacts'), 'utf8'))
  const artifact = selectStartos04ReleaseImageAuthorityArtifact({
    response,
    expectedTag: required(args, 'tag'),
    expectedTagSha: required(args, 'tagSha'),
    expectedRunId: required(args, 'runId'),
    expectedRunAttempt: required(args, 'runAttempt'),
    expectedArtifactId: required(args, 'artifactId')
  })
  appendGitHubEnv(required(args, 'githubEnv'), {
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_ID: artifact.id,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_NAME: artifact.name,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_DIGEST: artifact.digest,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_SIZE: String(artifact.sizeInBytes),
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_ARCHIVE_URL: artifact.archiveUrl,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_SOURCE_RUN_ID: artifact.sourceRunId,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_SOURCE_RUN_ATTEMPT: artifact.sourceRunAttempt,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_SOURCE_HEAD_REF: artifact.sourceHeadRef,
    HIVERELAY_STARTOS_IMAGE_AUTHORITY_SOURCE_HEAD_SHA: artifact.sourceHeadSha
  })
  console.log(`Selected exact StartOS image authority artifact ${artifact.id}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--artifacts', 'artifacts'],
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
    ['--run-id', 'runId'],
    ['--run-attempt', 'runAttempt'],
    ['--artifact-id', 'artifactId'],
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
