import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { isDeepStrictEqual } from 'node:util'

export const STARTOS_04_RELEASE_ASSET = 'blindspark-startos-0.4.s9pk'
export const STARTOS_04_RELEASE_EVIDENCE = 'startos-0.4-release-evidence.json'
export const STARTOS_04_PACKAGE_ID = 'blindspark'
export const STARTOS_04_SETUP_ACTION_SHA = '21507e89e717a303cb1064ac4c853d28b96d323b'
export const STARTOS_04_START_CLI_VERSION = '1.1.0'
export const STARTOS_04_START_CLI_SHA256 = '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'
export const STARTOS_04_START_SDK_VERSION = '2.0.1'
export const STARTOS_04_START_SDK_INTEGRITY = 'sha512-h0CBfS501KpQ0FX3GoYhxyt1mZYRYgvIYBygWek1kZ7Yl1LHi2uUMzp00Jln38HhB9cJWya3AM9zlGqR91uRdw=='

const EXPECTED_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const REQUIRED_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])
const IMAGE_INDEX_MEDIA_TYPES = new Set([
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.index.v1+json'
])
const TAG_PATTERN = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const SHA_PATTERN = /^[a-f0-9]{40}$/
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const RUN_ID_PATTERN = /^[1-9][0-9]*$/
const MAX_JSON_BYTES = 2 * 1024 * 1024
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
const MAX_COMMITMENT_BYTES = 4096
const MAX_PACKAGE_MANIFEST_BYTES = 2 * 1024 * 1024

export function resolveStartos04ReleaseBinding ({
  repoRoot,
  tag,
  tagSha,
  releaseSurfacesRunId,
  releaseEvidencePath,
  imageManifestEvidencePath
}) {
  requirePattern('release tag', tag, TAG_PATTERN)
  requirePattern('release tag SHA', tagSha, SHA_PATTERN)
  requirePattern('release-surfaces run id', releaseSurfacesRunId, RUN_ID_PATTERN)

  const rootPackage = readJson(path.join(repoRoot, 'package.json'), 'root package manifest')
  requireEqual('release tag matches package.json version', tag, `v${rootPackage.version}`)
  const startosPackage = readJson(
    path.join(repoRoot, 'startos-0.4', 'package.json'),
    'StartOS 0.4 package manifest'
  )
  requireEqual(
    'StartOS 0.4 source SDK dependency',
    startosPackage.dependencies?.['@start9labs/start-sdk'],
    STARTOS_04_START_SDK_VERSION
  )
  const startosLock = readJson(
    path.join(repoRoot, 'startos-0.4', 'package-lock.json'),
    'StartOS 0.4 package lock'
  )
  requireEqual('StartOS 0.4 lockfile root name', startosLock.packages?.['']?.name, startosPackage.name)
  requireEqual(
    'StartOS 0.4 lockfile root SDK dependency',
    startosLock.packages?.['']?.dependencies?.['@start9labs/start-sdk'],
    STARTOS_04_START_SDK_VERSION
  )
  const lockedSdk = startosLock.packages?.['node_modules/@start9labs/start-sdk']
  requireEqual('StartOS 0.4 locked SDK version', lockedSdk?.version, STARTOS_04_START_SDK_VERSION)
  requireEqual(
    'StartOS 0.4 locked SDK source',
    lockedSdk?.resolved,
    `https://registry.npmjs.org/@start9labs/start-sdk/-/start-sdk-${STARTOS_04_START_SDK_VERSION}.tgz`
  )
  requireEqual('StartOS 0.4 locked SDK integrity', lockedSdk?.integrity, STARTOS_04_START_SDK_INTEGRITY)
  const packageVersionSource = readRegularFile(
    path.join(repoRoot, 'startos-0.4', 'startos', 'versions', 'current.ts'),
    'StartOS 0.4 authored version',
    MAX_JSON_BYTES
  ).toString('utf8')
  const packageVersion = /version:\s*'([^']+)'/.exec(packageVersionSource)?.[1]
  const escapedSemver = tag.slice(1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  requirePattern('StartOS 0.4 authored package version', packageVersion, new RegExp(`^${escapedSemver}:[0-9]+$`))

  const releaseEvidence = readJson(releaseEvidencePath, 'release evidence')
  requireEqual('release evidence schemaVersion', releaseEvidence.schemaVersion, 1)
  requireEqual('release evidence version', releaseEvidence.release?.version, tag)
  requireEqual('release evidence semver', releaseEvidence.release?.semver, tag.slice(1))
  requireEqual('release evidence candidate status', releaseEvidence.release?.candidate, false)
  requireEqual('release evidence tag SHA', releaseEvidence.release?.tagSha, tagSha)
  requireEqual('release evidence workflow status', releaseEvidence.release?.workflow?.status, 'success')
  requireEqual('release evidence repository', releaseEvidence.release?.workflow?.repository, EXPECTED_REPOSITORY)
  requireEqual('release evidence source run id', String(releaseEvidence.release?.workflow?.runId || ''), releaseSurfacesRunId)
  requireEqual(
    'release evidence source run URL',
    releaseEvidence.release?.workflow?.runUrl,
    `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/${releaseSurfacesRunId}`
  )
  requireEqual('release image name', releaseEvidence.image?.name, EXPECTED_IMAGE_NAME)
  requirePattern('release image digest', releaseEvidence.image?.digest, DIGEST_PATTERN)
  const imageRef = `${EXPECTED_IMAGE_NAME}:${tag.slice(1)}@${releaseEvidence.image.digest}`
  requireEqual('release image ref', releaseEvidence.image?.ref, imageRef)
  requireEqual('release image manifest gate', releaseEvidence.gates?.imageManifest, 'passed')
  requireEqual('release image smoke gate', releaseEvidence.gates?.pushedImageSmoke, 'passed')
  requireEqual('legacy StartOS verification gate', releaseEvidence.gates?.startosVerify, 'passed')
  requireEqual('legacy StartOS release asset status', releaseEvidence.surfaces?.startosReleaseAsset, 'uploaded')
  requireEqual(
    'release image manifest evidence path',
    releaseEvidence.gates?.imageManifestEvidence?.path,
    'release-image-manifest-evidence.json'
  )
  requirePattern(
    'release image manifest evidence SHA-256',
    releaseEvidence.gates?.imageManifestEvidence?.sha256,
    SHA256_PATTERN
  )
  requireEqual(
    'release image manifest evidence SHA-256',
    sha256File(imageManifestEvidencePath, 'release image manifest evidence', MAX_JSON_BYTES),
    releaseEvidence.gates.imageManifestEvidence.sha256
  )

  const imageManifest = readJson(imageManifestEvidencePath, 'release image manifest evidence')
  requireEqual('image manifest schemaVersion', imageManifest.schemaVersion, 1)
  requireEqual('image manifest kind', imageManifest.kind, 'release-image-manifest')
  requireEqual('image manifest status', imageManifest.status, 'verified')
  requireEqual('image manifest image name', imageManifest.image?.name, EXPECTED_IMAGE_NAME)
  requireEqual('image manifest image tag', imageManifest.image?.tag, tag.slice(1))
  requireEqual('image manifest image digest', imageManifest.image?.digest, releaseEvidence.image.digest)
  requireEqual('image manifest image ref', imageManifest.image?.ref, imageRef)
  requireArrayEqual('image manifest required platforms', imageManifest.requiredPlatforms, REQUIRED_PLATFORMS)
  if (!IMAGE_INDEX_MEDIA_TYPES.has(imageManifest.manifest?.mediaType)) {
    fail(`image manifest media type must be a multi-arch index; got ${JSON.stringify(imageManifest.manifest?.mediaType)}`)
  }
  const platforms = Array.isArray(imageManifest.platforms) ? imageManifest.platforms : []
  const labels = new Set()
  const requiredPlatformEntries = new Map()
  for (const platform of platforms) {
    const label = `${platform?.os || ''}/${platform?.architecture || ''}`
    if (labels.has(label)) fail(`image manifest has duplicate platform ${label}`)
    labels.add(label)
    requirePattern(`image manifest platform ${label} digest`, platform?.digest, DIGEST_PATTERN)
    if (REQUIRED_PLATFORMS.includes(label)) {
      requiredPlatformEntries.set(label, {
        os: platform.os,
        architecture: platform.architecture,
        digest: platform.digest,
        revision: tagSha
      })
    }
  }
  for (const required of REQUIRED_PLATFORMS) {
    if (!labels.has(required)) fail(`image manifest is missing required platform ${required}`)
  }

  return {
    repository: EXPECTED_REPOSITORY,
    tag,
    tagSha,
    semver: tag.slice(1),
    packageVersion,
    releaseSurfacesRunId,
    imageName: EXPECTED_IMAGE_NAME,
    imageDigest: releaseEvidence.image.digest,
    imageRef,
    requiredPlatforms: [...REQUIRED_PLATFORMS],
    platforms: REQUIRED_PLATFORMS.map(label => requiredPlatformEntries.get(label))
  }
}

export function resolveReusableStartos04ReleaseBinding ({
  repoRoot,
  tag,
  tagSha,
  releaseEvidencePath,
  imageManifestEvidencePath
}) {
  const releaseEvidence = readJson(releaseEvidencePath, 'reusable release evidence')
  const releaseSurfacesRunId = String(releaseEvidence.release?.workflow?.runId || '')
  requirePattern('reusable release-surfaces run id', releaseSurfacesRunId, RUN_ID_PATTERN)
  return resolveStartos04ReleaseBinding({
    repoRoot,
    tag,
    tagSha,
    releaseSurfacesRunId,
    releaseEvidencePath,
    imageManifestEvidencePath
  })
}

export function readPackageCommitment (commitmentPath) {
  const value = readRegularFile(commitmentPath, 'StartOS package commitment', MAX_COMMITMENT_BYTES).toString('utf8').trim()
  return normalizePackageCommitment(value)
}

function normalizePackageCommitment (value) {
  if (typeof value !== 'string') {
    fail(`StartOS package commitment must be a string no larger than ${MAX_COMMITMENT_BYTES} bytes`)
  }
  if (!value) fail('StartOS package commitment must not be empty')
  if (Buffer.byteLength(value, 'utf8') > MAX_COMMITMENT_BYTES) {
    fail(`StartOS package commitment must be a string no larger than ${MAX_COMMITMENT_BYTES} bytes`)
  }
  if (value.includes('\r') || value.includes(String.fromCharCode(27)) || value.includes(String.fromCharCode(0))) {
    fail('StartOS package commitment contains unsupported control bytes')
  }
  return {
    output: value,
    sha256: sha256(Buffer.from(`${value}\n`))
  }
}

export function verifyStartos04ImageRevision ({ image, expectedOs, expectedArchitecture, expectedRevision }) {
  requirePattern('expected image OS', expectedOs, /^[a-z0-9._-]{1,32}$/)
  requirePattern('expected image architecture', expectedArchitecture, /^[a-z0-9._-]{1,32}$/)
  requirePattern('expected image revision', expectedRevision, SHA_PATTERN)
  requireEqual('release image child OS', image?.os, expectedOs)
  requireEqual('release image child architecture', image?.architecture, expectedArchitecture)
  requireEqual(
    'release image child org.opencontainers.image.revision label',
    image?.config?.Labels?.['org.opencontainers.image.revision'],
    expectedRevision
  )
}

export function verifyStartos04PackageManifest ({ manifest, expectedTag, expectedPackageVersion, expectedImageRef }) {
  requirePattern('expected StartOS 0.4 release tag', expectedTag, TAG_PATTERN)
  requireEqual('StartOS 0.4 package id', manifest?.id, STARTOS_04_PACKAGE_ID)
  const semver = expectedTag.slice(1)
  const escapedSemver = semver.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  requirePattern('expected StartOS 0.4 package version', expectedPackageVersion, new RegExp(`^${escapedSemver}:[0-9]+$`))
  requireEqual('StartOS 0.4 package version', manifest?.version, expectedPackageVersion)
  const images = manifest?.images
  if (!isPlainObject(images)) fail('StartOS 0.4 package images must be an object')
  requireArrayEqual('StartOS 0.4 package image ids', Object.keys(images).sort(), [STARTOS_04_PACKAGE_ID])
  const image = images[STARTOS_04_PACKAGE_ID]
  requireEqual('StartOS 0.4 package runtime image ref', image?.source?.dockerTag, expectedImageRef)
  const architectures = Array.isArray(image?.arch) ? [...image.arch].sort() : image?.arch
  requireArrayEqual('StartOS 0.4 package runtime image architectures', architectures, ['aarch64', 'x86_64'])
  return {
    id: manifest.id,
    version: manifest.version,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      ref: expectedImageRef,
      architectures
    }
  }
}

export function readStartos04PackageManifest ({ manifestPath, expectedTag, expectedPackageVersion, expectedImageRef }) {
  const manifest = readJson(manifestPath, 'StartOS 0.4 inspected package manifest', MAX_PACKAGE_MANIFEST_BYTES)
  return verifyStartos04PackageManifest({ manifest, expectedTag, expectedPackageVersion, expectedImageRef })
}

export function buildStartos04ReleaseEvidence ({ binding, packagePath, commitmentPath, packageManifestPath }) {
  const packageStat = regularFileStat(packagePath, 'StartOS 0.4 package')
  if (packageStat.size === 0 || packageStat.size > MAX_PACKAGE_BYTES) {
    fail(`StartOS 0.4 package size must be between 1 and ${MAX_PACKAGE_BYTES} bytes`)
  }
  if (path.basename(packagePath) !== STARTOS_04_RELEASE_ASSET) {
    fail(`StartOS 0.4 package filename must be ${STARTOS_04_RELEASE_ASSET}`)
  }
  const commitment = readPackageCommitment(commitmentPath)
  const packageManifest = readStartos04PackageManifest({
    manifestPath: packageManifestPath,
    expectedTag: binding.tag,
    expectedPackageVersion: binding.packageVersion,
    expectedImageRef: binding.imageRef
  })
  return buildStartos04ReleaseEvidenceBody({ binding, packagePath, commitment, packageManifest })
}

function buildStartos04ReleaseEvidenceBody ({ binding, packagePath, commitment, packageManifest }) {
  const releaseBase = `https://github.com/${binding.repository}/releases/download/${binding.tag}`
  return {
    schemaVersion: 1,
    kind: 'startos-0.4-release',
    status: 'verified',
    release: {
      version: binding.tag,
      tagSha: binding.tagSha
    },
    image: {
      name: binding.imageName,
      digest: binding.imageDigest,
      ref: binding.imageRef,
      requiredPlatforms: binding.requiredPlatforms,
      platforms: binding.platforms
    },
    toolchain: {
      evidenceSemantics: 'declared-source-build-contract-and-current-inspection-runtime',
      artifactBuildProvenance: {
        status: 'not-embedded-or-verifiable-from-s9pk',
        claim: 'source-and-workflow-contract-only'
      },
      setupAction: {
        ref: `Start9Labs/start-technologies/.github/actions/setup-build-env@${STARTOS_04_SETUP_ACTION_SHA}`,
        commit: STARTOS_04_SETUP_ACTION_SHA,
        evidenceRole: 'workflow-build-and-inspection-contract'
      },
      startCli: {
        version: STARTOS_04_START_CLI_VERSION,
        sha256: STARTOS_04_START_CLI_SHA256,
        evidenceRole: 'workflow-build-and-current-inspection-contract'
      },
      startSdk: {
        version: STARTOS_04_START_SDK_VERSION,
        integrity: STARTOS_04_START_SDK_INTEGRITY,
        evidenceRole: 'source-lockfile-build-contract'
      }
    },
    artifact: {
      name: STARTOS_04_RELEASE_ASSET,
      format: 'startos-0.4',
      sha256: sha256File(packagePath, 'StartOS 0.4 package', MAX_PACKAGE_BYTES),
      commitment,
      manifest: packageManifest,
      signerIdentity: {
        status: 'not-exposed-by-start-cli-1.1.0',
        value: ''
      },
      url: `${releaseBase}/${STARTOS_04_RELEASE_ASSET}`
    },
    evidenceLinks: {
      release: `${releaseBase}/release-evidence.json`,
      imageManifest: `${releaseBase}/release-image-manifest-evidence.json`
    }
  }
}

export function verifyPublishedStartos04ReleaseAssets ({ evidencePath, binding, packagePath }) {
  const actual = readJson(evidencePath, 'published StartOS 0.4 release evidence')
  const commitment = normalizePackageCommitment(actual?.artifact?.commitment?.output)
  requireEqual('published StartOS 0.4 commitment SHA-256', actual?.artifact?.commitment?.sha256, commitment.sha256)
  const manifest = actual?.artifact?.manifest
  requireEqual('published StartOS 0.4 package id', manifest?.id, STARTOS_04_PACKAGE_ID)
  requireEqual('published StartOS 0.4 package version', manifest?.version, binding.packageVersion)
  const packageManifest = {
    id: STARTOS_04_PACKAGE_ID,
    version: manifest.version,
    runtimeImage: {
      id: STARTOS_04_PACKAGE_ID,
      ref: binding.imageRef,
      architectures: ['aarch64', 'x86_64']
    }
  }
  const expected = buildStartos04ReleaseEvidenceBody({ binding, packagePath, commitment, packageManifest })
  if (!isDeepStrictEqual(actual, expected)) {
    fail('Published StartOS 0.4 assets do not match the exact source run, image, toolchain, manifest identity, commitment, and package bytes')
  }
  return actual
}

export function verifyStartos04ReleaseEvidence ({ evidencePath, binding, packagePath, commitmentPath, packageManifestPath }) {
  const actual = readJson(evidencePath, 'StartOS 0.4 release evidence')
  const expected = buildStartos04ReleaseEvidence({ binding, packagePath, commitmentPath, packageManifestPath })
  if (!isDeepStrictEqual(actual, expected)) {
    fail('StartOS 0.4 release evidence does not match the exact tag, image, toolchain, manifest identity, commitment, and package bytes')
  }
  return actual
}

export function writeJsonAtomic (file, body) {
  const resolved = path.resolve(file)
  fs.mkdirSync(path.dirname(resolved), { recursive: true })
  const tmp = `${resolved}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 })
  fs.renameSync(tmp, resolved)
}

export function appendGitHubEnv (file, values) {
  const lines = []
  for (const [name, value] of Object.entries(values)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) fail(`invalid GitHub environment variable name: ${name}`)
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) fail(`invalid GitHub environment value for ${name}`)
    lines.push(`${name}=${value}`)
  }
  fs.appendFileSync(path.resolve(file), `${lines.join('\n')}\n`)
}

function readJson (file, label, maxBytes = MAX_JSON_BYTES) {
  const raw = readRegularFile(file, label, maxBytes)
  try {
    return JSON.parse(raw.toString('utf8'))
  } catch (err) {
    fail(`${label} must be JSON: ${err.message}`)
  }
}

function readRegularFile (file, label, maxBytes) {
  const stat = regularFileStat(file, label)
  if (stat.size > maxBytes) fail(`${label} must be ${maxBytes} bytes or smaller`)
  return fs.readFileSync(path.resolve(file))
}

function regularFileStat (file, label) {
  const resolved = path.resolve(file)
  let stat
  try {
    stat = fs.lstatSync(resolved)
  } catch (err) {
    fail(`${label} is not readable: ${err.message}`)
  }
  if (stat.isSymbolicLink() || !stat.isFile()) fail(`${label} must be a regular non-symlink file`)
  return stat
}

function sha256File (file, label, maxBytes) {
  const resolved = path.resolve(file)
  const stat = regularFileStat(resolved, label)
  if (stat.size > maxBytes) fail(`${label} must be ${maxBytes} bytes or smaller`)
  const hash = crypto.createHash('sha256')
  const buffer = Buffer.allocUnsafe(1024 * 1024)
  const fd = fs.openSync(resolved, 'r')
  try {
    let bytesRead
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null)
      if (bytesRead > 0) hash.update(buffer.subarray(0, bytesRead))
    } while (bytesRead > 0)
  } finally {
    fs.closeSync(fd)
  }
  return hash.digest('hex')
}

function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
  fail(`${label} is required and malformed; got ${JSON.stringify(value)}`)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  fail(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireArrayEqual (label, actual, expected) {
  if (Array.isArray(actual) && actual.length === expected.length && actual.every((item, index) => item === expected[index])) return
  fail(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function isPlainObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function fail (message) {
  throw new Error(message)
}
