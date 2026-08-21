#!/usr/bin/env node

import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import {
  resolveStartos04ReleaseBinding,
  verifyPublishedReleaseClosureEvidence,
  verifyStartos04ClosureArtifact,
  verifyStartos04ClosureChildRun
} from './lib/startos-04-release-evidence.mjs'

const EXPECTED_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const PACKAGE_NAME = 'blindspark-startos-0.4.s9pk'
const STARTOS_EVIDENCE_NAME = 'startos-0.4-release-evidence.json'
const RELEASE_FILES = Object.freeze([
  'release-evidence.json',
  'release-image-manifest-evidence.json',
  PACKAGE_NAME,
  STARTOS_EVIDENCE_NAME,
  'release-closure-evidence.json'
])
const MAX_JSON_BYTES = 2 * 1024 * 1024
const MAX_COMMAND_OUTPUT = 16 * 1024 * 1024
const MAX_COMMAND_TIMEOUT_MS = 60 * 1000
const requestedTimeout = Number(process.env.HIVERELAY_LIVE_VERIFY_COMMAND_TIMEOUT_MS || '')
const COMMAND_TIMEOUT_MS = Number.isSafeInteger(requestedTimeout) && requestedTimeout > 0
  ? Math.min(requestedTimeout, MAX_COMMAND_TIMEOUT_MS)
  : MAX_COMMAND_TIMEOUT_MS
const RUN_ID_PATTERN = /^[1-9][0-9]*$/
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/
const SHA_PATTERN = /^[a-f0-9]{40}$/

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
let tempRoot = ''

try {
  const bundleDir = path.resolve(required(args, 'bundleDir'))
  const local = verifyBundleStructure(bundleDir)
  if (!args.liveGithub) {
    throw new Error(
      'Offline JSON-only release closure verification is non-authoritative and cannot clear stable/GA. ' +
      'Re-run with --live-github and GH_TOKEN to bind the current GitHub Release, exact child run attempt, and exact REST artifact digest/bytes.'
    )
  }
  if (!process.env.GH_TOKEN) {
    throw new Error('--live-github requires GH_TOKEN for authenticated GitHub Release, run, and artifact verification')
  }
  if (process.env.GITHUB_REPOSITORY && process.env.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY) {
    throw new Error(`GITHUB_REPOSITORY must be ${EXPECTED_REPOSITORY}; got ${process.env.GITHUB_REPOSITORY}`)
  }
  if (args.expectedPrerelease !== undefined && local.release.prerelease !== args.expectedPrerelease) {
    throw new Error(
      `Release evidence prerelease=${local.release.prerelease} does not match requested closure policy prerelease=${args.expectedPrerelease}`
    )
  }

  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-live-closure-'))
  const liveBundleDir = path.join(tempRoot, 'release')
  const artifactDir = path.join(tempRoot, 'artifact')
  fs.mkdirSync(liveBundleDir, { mode: 0o700 })
  fs.mkdirSync(artifactDir, { mode: 0o700 })

  const live = downloadCurrentReleaseBundle({
    tag: local.binding.tag,
    expectedPrerelease: local.release.prerelease,
    outDir: liveBundleDir
  })
  verifyCurrentTagCommit(local.binding.tag, local.binding.tagSha)
  for (const name of RELEASE_FILES) {
    compareRegularFiles(local.files[name], live.files[name], `local bundle ${name} matches the current GitHub Release asset`)
  }

  const liveVerified = verifyBundleStructure(liveBundleDir)
  const closure = readJson(live.files['release-closure-evidence.json'], 'live release closure evidence')
  const recordedRunId = String(closure?.startos04?.childWorkflow?.runId || '')
  const recordedRunAttempt = String(closure?.startos04?.childWorkflow?.runAttempt || '')
  const recordedArtifactId = String(closure?.startos04?.immutableArtifact?.id || '')
  requirePattern('recorded StartOS 0.4 child run id', recordedRunId, RUN_ID_PATTERN)
  requirePattern('recorded StartOS 0.4 child run attempt', recordedRunAttempt, RUN_ID_PATTERN)
  requirePattern('recorded StartOS 0.4 child artifact id', recordedArtifactId, RUN_ID_PATTERN)

  const rawRun = ghJson(`repos/${EXPECTED_REPOSITORY}/actions/runs/${recordedRunId}/attempts/${recordedRunAttempt}`)
  const childRun = verifyStartos04ClosureChildRun({
    run: rawRun,
    expectedChildRunId: recordedRunId,
    binding: liveVerified.binding
  })
  if (!isDeepStrictEqual(childRun, closure.startos04.childWorkflow)) {
    throw new Error('Live StartOS 0.4 child run identity differs from the published closure certificate')
  }

  const rawArtifact = ghJson(`repos/${EXPECTED_REPOSITORY}/actions/artifacts/${recordedArtifactId}`)
  const artifact = verifyStartos04ClosureArtifact({ artifact: rawArtifact, childRun })
  if (!isDeepStrictEqual(artifact, closure.startos04.immutableArtifact)) {
    throw new Error('Live StartOS 0.4 REST artifact identity differs from the published closure certificate')
  }

  const archive = path.join(tempRoot, 'child-artifact.zip')
  ghDownload(`repos/${EXPECTED_REPOSITORY}/actions/artifacts/${recordedArtifactId}/zip`, archive)
  verifyDownloadedFile(archive, artifact.sizeInBytes, artifact.digest, 'StartOS 0.4 child artifact ZIP')
  extractExactChildArtifact(archive, artifactDir)
  compareRegularFiles(
    path.join(artifactDir, PACKAGE_NAME),
    live.files[PACKAGE_NAME],
    'exact immutable child artifact package matches the current GitHub Release package'
  )
  compareRegularFiles(
    path.join(artifactDir, STARTOS_EVIDENCE_NAME),
    live.files[STARTOS_EVIDENCE_NAME],
    'exact immutable child artifact evidence matches the current GitHub Release sidecar'
  )
  verifyCurrentReleaseInventory({
    tag: liveVerified.binding.tag,
    expectedPrerelease: liveVerified.release.prerelease,
    expectedRelease: live.release,
    expectedRecords: live.records
  })
  verifyCurrentArtifactRecord({
    artifactId: recordedArtifactId,
    expectedArtifact: artifact,
    childRun
  })
  verifyCurrentTagCommit(liveVerified.binding.tag, liveVerified.binding.tagSha)

  console.log(
    `Live GitHub release closure verified for ${liveVerified.binding.tag} ` +
    `(child run ${childRun.runId} attempt ${childRun.runAttempt}, artifact ${artifact.id})`
  )
} catch (err) {
  console.error(err.message)
  process.exitCode = 1
} finally {
  if (tempRoot) fs.rmSync(tempRoot, { recursive: true, force: true })
}

function verifyBundleStructure (bundleDir) {
  const files = {
    'release-evidence.json': path.join(bundleDir, 'release-evidence.json'),
    'release-image-manifest-evidence.json': path.join(bundleDir, 'release-image-manifest-evidence.json'),
    [PACKAGE_NAME]: firstPath(bundleDir, [PACKAGE_NAME, `startos-0.4/${PACKAGE_NAME}`]),
    [STARTOS_EVIDENCE_NAME]: path.join(bundleDir, STARTOS_EVIDENCE_NAME),
    'release-closure-evidence.json': path.join(bundleDir, 'release-closure-evidence.json')
  }
  const release = readIdentity(files['release-evidence.json'])
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: release.tag,
    tagSha: release.tagSha,
    releaseSurfacesRunId: release.runId,
    releaseEvidencePath: files['release-evidence.json'],
    imageManifestEvidencePath: files['release-image-manifest-evidence.json']
  })
  verifyPublishedReleaseClosureEvidence({
    evidencePath: files['release-closure-evidence.json'],
    binding,
    sourceReleaseEvidencePath: files['release-evidence.json'],
    imageManifestEvidencePath: files['release-image-manifest-evidence.json'],
    releasePackagePath: files[PACKAGE_NAME],
    releaseStartosEvidencePath: files[STARTOS_EVIDENCE_NAME]
  })
  return { binding, files, release }
}

function downloadCurrentReleaseBundle ({ tag, expectedPrerelease, outDir }) {
  const release = readCurrentRelease(tag, expectedPrerelease)
  const records = readCurrentReleaseAssetRecords(release.id)
  const files = {}
  for (const name of RELEASE_FILES) {
    const asset = records[name]
    const file = path.join(outDir, name)
    ghDownload(`repos/${EXPECTED_REPOSITORY}/releases/assets/${asset.id}`, file, true)
    verifyDownloadedFile(file, asset.size, asset.digest, `current GitHub Release asset ${name}`)
    files[name] = file
  }
  return { release, records, files }
}

function verifyCurrentReleaseInventory ({ tag, expectedPrerelease, expectedRelease, expectedRecords }) {
  const release = readCurrentRelease(tag, expectedPrerelease)
  if (!isDeepStrictEqual(release, expectedRelease)) {
    throw new Error('Current GitHub Release identity changed during live closure verification')
  }
  const records = readCurrentReleaseAssetRecords(release.id)
  if (!isDeepStrictEqual(records, expectedRecords)) {
    throw new Error('Current GitHub Release asset inventory changed during live closure verification')
  }
}

function readCurrentRelease (tag, expectedPrerelease) {
  const raw = ghJson(`repos/${EXPECTED_REPOSITORY}/releases/tags/${tag}`)
  const id = String(raw?.id || '')
  const release = {
    id,
    tagName: raw?.tag_name,
    draft: raw?.draft,
    prerelease: raw?.prerelease,
    url: raw?.url,
    htmlUrl: raw?.html_url
  }
  if (release.tagName !== tag || !RUN_ID_PATTERN.test(id) || release.draft !== false ||
      release.prerelease !== expectedPrerelease ||
      release.url !== `https://api.github.com/repos/${EXPECTED_REPOSITORY}/releases/${id}` ||
      release.htmlUrl !== `https://github.com/${EXPECTED_REPOSITORY}/releases/tag/${tag}`) {
    throw new Error(
      `GitHub Release identity does not match exact tag ${tag} and prerelease=${expectedPrerelease} policy`
    )
  }
  return release
}

function verifyCurrentArtifactRecord ({ artifactId, expectedArtifact, childRun }) {
  const rawArtifact = ghJson(`repos/${EXPECTED_REPOSITORY}/actions/artifacts/${artifactId}`)
  const artifact = verifyStartos04ClosureArtifact({ artifact: rawArtifact, childRun })
  if (!isDeepStrictEqual(artifact, expectedArtifact)) {
    throw new Error('Live StartOS 0.4 REST artifact identity changed during closure verification')
  }
}

function readCurrentReleaseAssetRecords (releaseId) {
  const pages = ghJson(`repos/${EXPECTED_REPOSITORY}/releases/${releaseId}/assets?per_page=100`, ['--paginate', '--slurp'])
  if (!Array.isArray(pages) || !pages.every(Array.isArray)) {
    throw new Error('GitHub Release assets response must be an array of REST pages')
  }
  const assets = pages.flat()
  const records = {}
  for (const name of RELEASE_FILES) {
    const matches = assets.filter(asset => asset?.name === name)
    if (matches.length !== 1) {
      throw new Error(`Current GitHub Release must contain exactly one asset named ${name}; got ${matches.length}`)
    }
    const asset = matches[0]
    const id = String(asset?.id || '')
    const size = Number(asset?.size)
    const digest = asset?.digest
    if (!RUN_ID_PATTERN.test(id) || asset?.state !== 'uploaded' || !Number.isSafeInteger(size) || size < 1 || !DIGEST_PATTERN.test(digest || '')) {
      throw new Error(`Current GitHub Release asset ${name} is not a complete digest-bearing REST upload`)
    }
    const expectedUrl = `https://api.github.com/repos/${EXPECTED_REPOSITORY}/releases/assets/${id}`
    if (asset?.url !== expectedUrl) {
      throw new Error(`Current GitHub Release asset ${name} has an unexpected REST URL`)
    }
    records[name] = { id, name, state: 'uploaded', size, digest, url: expectedUrl }
  }
  return records
}

function verifyCurrentTagCommit (tag, expectedSha) {
  const ref = ghJson(`repos/${EXPECTED_REPOSITORY}/git/ref/tags/${tag}`)
  if (ref?.ref !== `refs/tags/${tag}`) throw new Error(`Current GitHub tag ref does not match ${tag}`)
  let object = ref?.object
  for (let depth = 0; depth < 4; depth++) {
    if (!SHA_PATTERN.test(object?.sha || '')) throw new Error('Current GitHub tag object SHA is malformed')
    if (object.type === 'commit') {
      if (object.sha !== expectedSha) {
        throw new Error(`Current GitHub tag ${tag} resolves to ${object.sha}, not release source ${expectedSha}`)
      }
      return
    }
    if (object.type !== 'tag') throw new Error(`Current GitHub tag object type is unsupported: ${object?.type}`)
    object = ghJson(`repos/${EXPECTED_REPOSITORY}/git/tags/${object.sha}`)?.object
  }
  throw new Error('Current GitHub tag annotation chain exceeds four objects')
}

function extractExactChildArtifact (archive, outDir) {
  const listed = runCommand('unzip', ['-Z1', archive]).stdout
  const entries = listed.split(/\r?\n/).filter(Boolean).sort()
  const expected = [PACKAGE_NAME, STARTOS_EVIDENCE_NAME].sort()
  if (!isDeepStrictEqual(entries, expected)) {
    throw new Error(`StartOS 0.4 child artifact ZIP entries must be exactly ${expected.join(', ')}`)
  }
  runCommand('unzip', ['-q', archive, '-d', outDir])
  for (const name of expected) regularFile(path.join(outDir, name), `extracted child artifact ${name}`)
}

function ghJson (endpoint, extraArgs = []) {
  const result = runCommand('gh', ['api', ...extraArgs, endpoint])
  try {
    return JSON.parse(result.stdout)
  } catch (err) {
    throw new Error(`GitHub API ${endpoint} returned invalid JSON: ${err.message}`)
  }
}

function ghDownload (endpoint, file, octetStream = false) {
  const fd = fs.openSync(file, 'wx', 0o600)
  try {
    const argv = ['api']
    if (octetStream) argv.push('-H', 'Accept: application/octet-stream')
    argv.push(endpoint)
    const result = spawnSync('gh', argv, {
      cwd: repoRoot,
      env: process.env,
      stdio: ['ignore', fd, 'pipe'],
      maxBuffer: MAX_COMMAND_OUTPUT,
      timeout: COMMAND_TIMEOUT_MS,
      killSignal: 'SIGTERM'
    })
    if (result.error || result.status !== 0) {
      const detail = result.error?.message || Buffer.from(result.stderr || '').toString('utf8').trim() || `exit ${result.status}`
      throw new Error(`GitHub API download ${endpoint} failed: ${detail}`)
    }
  } finally {
    fs.closeSync(fd)
  }
}

function runCommand (command, argv) {
  const result = spawnSync(command, argv, {
    cwd: repoRoot,
    env: process.env,
    encoding: 'utf8',
    maxBuffer: MAX_COMMAND_OUTPUT,
    timeout: COMMAND_TIMEOUT_MS,
    killSignal: 'SIGTERM'
  })
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || result.stderr?.trim() || `exit ${result.status}`
    throw new Error(`${command} ${argv.join(' ')} failed: ${detail}`)
  }
  return result
}

function verifyDownloadedFile (file, expectedSize, expectedDigest, label) {
  const stat = regularFile(file, label)
  if (stat.size !== expectedSize) {
    throw new Error(`${label} size ${stat.size} does not match REST size ${expectedSize}`)
  }
  const digest = `sha256:${sha256File(file)}`
  if (digest !== expectedDigest) {
    throw new Error(`${label} digest ${digest} does not match REST digest ${expectedDigest}`)
  }
}

function compareRegularFiles (left, right, label) {
  const leftStat = regularFile(left, `${label} (left)`)
  const rightStat = regularFile(right, `${label} (right)`)
  if (leftStat.size !== rightStat.size || sha256File(left) !== sha256File(right)) {
    throw new Error(`${label}: bytes differ`)
  }
}

function sha256File (file) {
  const hash = crypto.createHash('sha256')
  const buffer = Buffer.allocUnsafe(1024 * 1024)
  const fd = fs.openSync(file, 'r')
  try {
    let count
    do {
      count = fs.readSync(fd, buffer, 0, buffer.length, null)
      if (count > 0) hash.update(buffer.subarray(0, count))
    } while (count > 0)
  } finally {
    fs.closeSync(fd)
  }
  return hash.digest('hex')
}

function regularFile (file, label) {
  const stat = fs.lstatSync(path.resolve(file))
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular file, not a symlink`)
  return stat
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--live-github') {
      out.liveGithub = true
      continue
    }
    if (argv[i] === '--expected-prerelease') {
      const value = argv[++i]
      if (value !== 'true' && value !== 'false') {
        throw new Error('--expected-prerelease must be true or false')
      }
      out.expectedPrerelease = value === 'true'
      continue
    }
    if (argv[i] !== '--bundle-dir') throw new Error(`Unknown argument: ${argv[i]}`)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error('Missing value for --bundle-dir')
    out.bundleDir = value
  }
  return out
}

function required (body, name) {
  const value = body[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}

function readIdentity (file) {
  const body = readJson(file, 'release checkpoint evidence')
  if (typeof body.release?.prerelease !== 'boolean') {
    throw new Error('release checkpoint evidence release.prerelease must be a boolean')
  }
  return {
    tag: body.release?.version,
    tagSha: body.release?.tagSha,
    runId: String(body.release?.workflow?.runId || ''),
    prerelease: body.release.prerelease
  }
}

function readJson (file, label) {
  const stat = regularFile(file, label)
  if (stat.size < 1 || stat.size > MAX_JSON_BYTES) {
    throw new Error(`${label} must be a nonempty regular JSON file no larger than 2 MiB`)
  }
  const body = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'))
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error(`${label} must be a JSON object`)
  return body
}

function requirePattern (label, value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`${label} is missing or malformed`)
}

function firstPath (root, candidates) {
  for (const candidate of candidates) {
    const file = path.join(root, candidate)
    if (fs.existsSync(file)) return file
  }
  return path.join(root, candidates[0])
}
