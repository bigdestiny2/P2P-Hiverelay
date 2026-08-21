import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

export const LOCAL_RELEASE_MANIFEST_KIND = 'hiverelay-local-release-candidate-manifest'
export const LOCAL_RELEASE_CLAIM_CLASS = 'LOCAL_OFFLINE_DRAFT_ONLY'

const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const PUBLIC_PACKAGE_PATHS = Object.freeze([
  'packages/core/package.json',
  'packages/client/package.json',
  'packages/verifier/package.json',
  'packages/services/package.json'
])
const BLIND_PACKAGE_PATHS = Object.freeze([
  'packages/blind-protocol/package.json',
  'packages/blind-ipc/package.json',
  'packages/blind-client/package.json',
  'packages/blind-peercred/package.json',
  'packages/blind-edge/package.json',
  'packages/blind-daemon/package.json'
])
const RELEASE_INPUT_PATHS = Object.freeze([
  '.dockerignore',
  '.github/workflows/release-surfaces.yml',
  'Dockerfile',
  'package.json',
  'package-lock.json',
  ...PUBLIC_PACKAGE_PATHS,
  ...BLIND_PACKAGE_PATHS,
  'fleet/channels.json',
  'fleet/relays.json',
  'fleet/public-hive-gateway-release.json',
  'packages/blind-ipc/hiverelay-blind-private-ipc-authority-v2.json',
  'packages/blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json',
  'scripts/check-release-blockers.mjs',
  'scripts/check-release-image-manifest.mjs',
  'scripts/lib/local-release-candidate-manifest.mjs',
  'scripts/prepare-release.mjs',
  'scripts/verify-local-release-candidate-manifest.mjs',
  'scripts/verify-release-evidence.mjs',
  'scripts/write-local-release-candidate-manifest.mjs',
  'scripts/write-release-evidence.mjs',
  'startos/Makefile',
  'startos/check-web.sh',
  'startos/docker_entrypoint.sh',
  'startos/manifest.yaml',
  'startos-0.4/startos/manifest/index.ts',
  'startos-0.4/startos/versions/current.ts',
  'umbrel-app/docker-compose.yml',
  'umbrel-app/umbrel-app.yml'
].sort())
const COMMUNITY_STORE_INPUT_PATHS = Object.freeze([
  'package.json',
  'hiverelay-blindspark/docker-compose.yml',
  'hiverelay-blindspark/umbrel-app.yml'
])
const REQUIRED_EXTERNAL_EVIDENCE = Object.freeze([
  'canonical-protocol-freeze',
  'component-and-cross-runtime-conformance',
  'cohort-and-soak',
  'source-bound-multiarch-image',
  'oci-sbom-attestation-verification',
  'oci-provenance-attestation-verification',
  'npm-package-tarball-hashes',
  'community-umbrel-store-source-and-package-binding',
  'release-image-manifest-evidence.json',
  'release-image-smoke-evidence.json',
  'umbrel-package-smoke-evidence.json',
  'startos/blindspark.s9pk',
  'real-umbrel-lifecycle-review',
  'real-startos-lifecycle-review',
  'fleet-rollout-evidence.json',
  'distribution-and-marketplace-review'
])
const BLOCKER_PATTERN = /^[A-Z][A-Z0-9_]{2,127}$/
const IMAGE_REF_PATTERN = /^(ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9._/-]+):(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)@(sha256:[a-f0-9]{64})$/

const CHECK_BLOCKERS = Object.freeze({
  'source.release-candidate-identity': 'SOURCE_VERSION_TAG_NOT_EXACT',
  'packages.public-version-aligned': 'PUBLIC_PACKAGE_VERSION_DRIFT',
  'packages.blind-internal-version-aligned': 'BLIND_PACKAGE_RELEASE_BOUNDARY_DRIFT',
  'appliances.umbrel-version-aligned': 'UMBREL_VERSION_DRIFT',
  'appliances.startos-version-aligned': 'STARTOS_VERSION_DRIFT',
  'appliances.startos04-version-aligned': 'STARTOS_04_VERSION_DRIFT',
  'appliances.startos04-image-aligned': 'STARTOS_04_IMAGE_DRIFT',
  'appliances.umbrel-image-pin': 'UMBREL_IMAGE_PIN_INVALID',
  'image.source-bound': 'PINNED_IMAGE_NOT_SOURCE_BOUND',
  'container.base-images-digest-pinned': 'CONTAINER_BASE_IMAGE_DIGESTS_UNPINNED',
  'workflow.multiarch': 'RELEASE_WORKFLOW_MULTIARCH_MISSING',
  'workflow.sbom': 'RELEASE_WORKFLOW_SBOM_MISSING',
  'workflow.provenance': 'RELEASE_WORKFLOW_PROVENANCE_MISSING',
  'workflow.source-binding': 'RELEASE_WORKFLOW_SOURCE_BINDING_MISSING',
  'workflow.single-source': 'RELEASE_WORKFLOW_SPLIT_SOURCE',
  'fleet.channels-version-aligned': 'FLEET_CHANNEL_VERSION_DRIFT',
  'umbrel.official-submission-recorded': 'UMBREL_OFFICIAL_SUBMISSION_PENDING'
})

export function collectLocalReleaseSnapshot (repoRoot, options = {}) {
  const root = path.resolve(repoRoot)
  const dirty = git(root, ['status', '--porcelain=v1', '--untracked-files=all'])
  if (dirty) {
    throw new Error(`local release manifest requires a clean worktree; found:\n${dirty}`)
  }

  const sourceCommit = git(root, ['rev-parse', 'HEAD'])
  const sourceTree = git(root, ['rev-parse', 'HEAD^{tree}'])
  const committed = new Map()
  const inputs = []

  for (const relativePath of RELEASE_INPUT_PATHS) {
    const blob = git(root, ['rev-parse', `HEAD:${relativePath}`])
    const bytes = gitBuffer(root, ['cat-file', 'blob', blob])
    committed.set(relativePath, bytes)
    inputs.push({
      path: relativePath,
      bytes: bytes.length,
      sha256: sha256(bytes),
      gitBlob: blob
    })
  }

  const rootPackage = parseJson(committed.get('package.json'), 'package.json')
  const publicPackages = packageSurfaces(committed, PUBLIC_PACKAGE_PATHS)
  const blindPackages = packageSurfaces(committed, BLIND_PACKAGE_PATHS)
  const umbrelManifest = text(committed, 'umbrel-app/umbrel-app.yml')
  const umbrelCompose = text(committed, 'umbrel-app/docker-compose.yml')
  const startosManifest = text(committed, 'startos/manifest.yaml')
  const startos04Manifest = text(committed, 'startos-0.4/startos/manifest/index.ts')
  const startos04VersionSource = text(committed, 'startos-0.4/startos/versions/current.ts')
  const dockerfile = text(committed, 'Dockerfile')
  const releaseWorkflow = text(committed, '.github/workflows/release-surfaces.yml')
  const fleetChannels = parseJson(committed.get('fleet/channels.json'), 'fleet/channels.json')
  const semver = requireSemver(rootPackage.version, 'package.json version')
  const expectedVersionTag = `v${semver}`
  const versionTagCommit = gitOptional(root, ['rev-parse', '--verify', `${expectedVersionTag}^{commit}`]) || null
  const tagsAtSource = git(root, ['tag', '--points-at', 'HEAD'])
    .split('\n')
    .filter(Boolean)
    .sort()
  const imageRef = yamlImageRef(umbrelCompose)
  const parsedImage = parseImageRef(imageRef)

  return {
    source: {
      repository: 'bigdestiny2/P2P-Hiverelay',
      commit: sourceCommit,
      tree: sourceTree,
      describe: git(root, ['describe', '--tags', '--always', '--long', 'HEAD']),
      dirty: false,
      expectedVersionTag,
      versionTagCommit,
      tagsAtSource
    },
    semver,
    publicPackages,
    blindPackages,
    appliances: {
      umbrel: {
        version: yamlScalar(umbrelManifest, 'version'),
        imageRef,
        image: parsedImage,
        submission: yamlScalar(umbrelManifest, 'submission')
      },
      startos: {
        id: yamlScalar(startosManifest, 'id'),
        version: yamlScalar(startosManifest, 'version'),
        packageFormat: 'startos-0.3.5.x',
        artifactName: 'blindspark.s9pk'
      },
      startos04: {
        version: tsSingleQuotedValue(startos04VersionSource, 'version').split(':')[0],
        versionWithRevision: tsSingleQuotedValue(startos04VersionSource, 'version'),
        imageRef: parseStartos04AuthoringImageRef(startos04Manifest),
        packageFormat: 'startos-0.4',
        artifactName: 'blindspark-startos-0.4.s9pk'
      }
    },
    fleetChannels: {
      stable: String(fleetChannels.stable || ''),
      canary: String(fleetChannels.canary || '')
    },
    build: {
      imageName: EXPECTED_IMAGE_NAME,
      platforms: releaseWorkflow.includes('--platform linux/amd64,linux/arm64')
        ? ['linux/amd64', 'linux/arm64']
        : [],
      baseImages: dockerBaseImages(dockerfile),
      sbomConfigured: releaseWorkflow.includes('--sbom=true'),
      provenanceConfigured: releaseWorkflow.includes('--provenance=mode=max'),
      sourceBindingConfigured: releaseWorkflow.includes('--build-arg "SOURCE_COMMIT=$HIVERELAY_RELEASE_SHA"') &&
        dockerfile.includes('LABEL org.opencontainers.image.revision="$SOURCE_COMMIT"'),
      splitSourceWorkflow: releaseWorkflow.indexOf('git checkout -B main origin/main') >
        releaseWorkflow.indexOf('Build and push multi-arch image')
    },
    communityStore: options.umbrelStoreRoot
      ? collectCommunityStoreSnapshot(options.umbrelStoreRoot)
      : null,
    inputs
  }
}

export function buildLocalReleaseCandidateManifest (snapshot, options = {}) {
  const declaredBlockers = normalizeDeclaredBlockers(options.declaredBlockers || [])
  const checks = []
  const addCheck = (id, scope, passed, detail) => {
    checks.push({ id, scope, status: passed ? 'passed' : 'blocked', detail })
  }
  const exactTag = snapshot.source.versionTagCommit === snapshot.source.commit
  const prerelease = snapshot.semver.includes('-')
  const cleanPretagCandidate = prerelease && snapshot.source.versionTagCommit == null
  const releaseCandidateIdentity = exactTag || cleanPretagCandidate
  const publicVersionsAligned = snapshot.publicPackages.length === PUBLIC_PACKAGE_PATHS.length &&
    snapshot.publicPackages.every(pkg => pkg.version === snapshot.semver)
  const blindInternalVersionsAligned = snapshot.blindPackages.length === BLIND_PACKAGE_PATHS.length &&
    snapshot.blindPackages.every(pkg => pkg.version === snapshot.semver && pkg.private === true)
  const image = snapshot.appliances.umbrel.image
  const imagePinValid = image != null && image.name === EXPECTED_IMAGE_NAME && image.tag === snapshot.semver
  const allBaseImagesPinned = snapshot.build.baseImages.length > 0 &&
    snapshot.build.baseImages.every(base => base.digestPinned)
  const channelsAligned = snapshot.fleetChannels.stable === `v${snapshot.semver}` &&
    snapshot.fleetChannels.canary === `v${snapshot.semver}`
  const umbrelSubmissionRecorded = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(snapshot.appliances.umbrel.submission)
  const splitSourceWorkflow = Boolean(snapshot.build.splitSourceWorkflow)
  const communityStoreAttached = snapshot.communityStore != null
  const communityStoreExactPair = communityStoreAttached &&
    snapshot.communityStore.packageVersion === snapshot.semver &&
    snapshot.communityStore.umbrelVersion === snapshot.semver &&
    snapshot.communityStore.imageRef === snapshot.appliances.umbrel.imageRef

  addCheck(
    'source.release-candidate-identity',
    'local',
    releaseCandidateIdentity,
    exactTag
      ? `${snapshot.source.expectedVersionTag} resolves to the exact source commit`
      : cleanPretagCandidate
        ? `${snapshot.source.expectedVersionTag} is absent; the clean pre-tag candidate is bound to ${snapshot.source.commit}`
        : `${snapshot.source.expectedVersionTag} resolves to ${snapshot.source.versionTagCommit || 'no commit'}, not ${snapshot.source.commit}`
  )
  addCheck(
    'packages.public-version-aligned',
    'local',
    publicVersionsAligned,
    publicVersionsAligned
      ? `all four public packages equal ${snapshot.semver}`
      : 'one or more public package versions differ from the root package version'
  )
  addCheck(
    'packages.blind-internal-version-aligned',
    'local',
    blindInternalVersionsAligned,
    blindInternalVersionsAligned
      ? `all six private Blind workspaces are frozen at ${snapshot.semver}`
      : 'Blind workspaces must remain private and use the exact release-candidate version'
  )
  addCheck(
    'appliances.umbrel-version-aligned',
    'local',
    snapshot.appliances.umbrel.version === snapshot.semver,
    `Umbrel version is ${snapshot.appliances.umbrel.version}`
  )
  addCheck(
    'appliances.startos-version-aligned',
    'local',
    snapshot.appliances.startos.version === snapshot.semver,
    `StartOS version is ${snapshot.appliances.startos.version}`
  )
  addCheck(
    'appliances.startos04-version-aligned',
    'local',
    snapshot.appliances.startos04.version === snapshot.semver,
    `StartOS 0.4 version is ${snapshot.appliances.startos04.versionWithRevision}`
  )
  addCheck(
    'appliances.startos04-image-aligned',
    'external',
    snapshot.appliances.startos04.imageRef === `${EXPECTED_IMAGE_NAME}:${snapshot.semver}`,
    `StartOS 0.4 image is ${snapshot.appliances.startos04.imageRef}`
  )
  addCheck(
    'appliances.umbrel-image-pin',
    'external',
    imagePinValid,
    imagePinValid
      ? `Umbrel metadata pins ${image.ref}`
      : `Umbrel image ref is not a digest-pinned ${EXPECTED_IMAGE_NAME}:${snapshot.semver} reference`
  )
  addCheck(
    'image.source-bound',
    'external',
    false,
    imagePinValid && exactTag
      ? 'version metadata aligns, but external OCI provenance proving the digest was built from this commit is not attached'
      : 'local metadata cannot bind the pinned image digest to this source commit'
  )
  addCheck(
    'container.base-images-digest-pinned',
    'local',
    allBaseImagesPinned,
    allBaseImagesPinned
      ? 'every Dockerfile base image is digest-pinned'
      : 'one or more Dockerfile base images use a mutable tag without a digest'
  )
  addCheck(
    'workflow.multiarch',
    'local',
    arrayEqual(snapshot.build.platforms, ['linux/amd64', 'linux/arm64']),
    snapshot.build.platforms.length > 0
      ? 'release workflow requests linux/amd64 and linux/arm64'
      : 'release workflow does not declare the required multi-arch platform pair'
  )
  addCheck(
    'workflow.sbom',
    'local',
    snapshot.build.sbomConfigured,
    snapshot.build.sbomConfigured
      ? 'release workflow configuration explicitly requests an OCI SBOM attestation; no attestation bytes are proved here'
      : 'release build does not explicitly request an OCI SBOM attestation'
  )
  addCheck(
    'workflow.provenance',
    'local',
    snapshot.build.provenanceConfigured,
    snapshot.build.provenanceConfigured
      ? 'release workflow configuration explicitly requests max-mode provenance; no attestation bytes are proved here'
      : 'release build does not explicitly request max-mode provenance'
  )
  addCheck(
    'workflow.source-binding',
    'local',
    snapshot.build.sourceBindingConfigured,
    snapshot.build.sourceBindingConfigured
      ? 'release workflow passes the exact release commit into the OCI revision label'
      : 'release workflow does not bind the image revision label to the exact release commit'
  )
  addCheck(
    'workflow.single-source',
    'local',
    !splitSourceWorkflow,
    splitSourceWorkflow
      ? 'workflow builds from the release checkout, then switches to origin/main for metadata surfaces; the future metadata commit is unbound here'
      : 'workflow keeps build and metadata surfaces on one source checkout'
  )
  addCheck(
    'fleet.channels-version-aligned',
    'external',
    channelsAligned,
    `fleet channels are stable=${snapshot.fleetChannels.stable}, canary=${snapshot.fleetChannels.canary}`
  )
  addCheck(
    'umbrel.official-submission-recorded',
    'external',
    umbrelSubmissionRecorded,
    umbrelSubmissionRecorded
      ? `official Umbrel submission is ${snapshot.appliances.umbrel.submission}`
      : 'official Umbrel submission URL is still pending'
  )
  addCheck(
    'community-store.source-bound',
    'external',
    communityStoreAttached,
    communityStoreAttached
      ? `community store is bound to commit ${snapshot.communityStore.source.commit} and tree ${snapshot.communityStore.source.tree}`
      : 'no clean community-store source commit/tree was supplied'
  )
  addCheck(
    'community-store.exact-pair',
    'external',
    communityStoreExactPair,
    communityStoreExactPair
      ? 'community-store package version and exact image ref match the Hive appliance metadata'
      : communityStoreAttached
        ? `community-store ${snapshot.communityStore.packageVersion} / ${snapshot.communityStore.imageRef} does not match Hive ${snapshot.semver} / ${snapshot.appliances.umbrel.imageRef}`
        : 'community-store exact-pair evidence is not attached'
  )

  const automaticBlockers = checks
    .filter(check => check.status === 'blocked')
    .map(check => CHECK_BLOCKERS[check.id])
    .filter(Boolean)
  automaticBlockers.push(
    communityStoreAttached
      ? (communityStoreExactPair ? null : 'COMMUNITY_UMBREL_STORE_EXACT_PAIR_MISMATCH')
      : 'COMMUNITY_UMBREL_STORE_NOT_BOUND'
  )
  const blockers = [...new Set([
    ...automaticBlockers.filter(Boolean),
    'EXTERNAL_RELEASE_EVIDENCE_NOT_ATTACHED',
    'LOCAL_MANIFEST_NO_PROMOTION_AUTHORITY',
    'NPM_TARBALL_ARTIFACTS_NOT_ATTACHED',
    'APPLIANCE_BINARY_ARTIFACTS_NOT_ATTACHED',
    'OCI_SBOM_PROVENANCE_ARTIFACTS_NOT_ATTACHED',
    ...declaredBlockers
  ])].sort()
  const localChecksPassed = checks
    .filter(check => check.scope === 'local')
    .every(check => check.status === 'passed')
  const localPreflight = localChecksPassed ? 'passed' : 'blocked'

  const body = {
    schemaVersion: 1,
    kind: LOCAL_RELEASE_MANIFEST_KIND,
    claimClass: LOCAL_RELEASE_CLAIM_CLASS,
    manifestDigest: '',
    source: {
      ...snapshot.source,
      metadataSurfaces: splitSourceWorkflow
        ? { mode: 'origin-main-after-build', commit: null, tree: null, bound: false }
        : { mode: 'same-source-checkout', commit: snapshot.source.commit, tree: snapshot.source.tree, bound: true }
    },
    release: {
      version: `v${snapshot.semver}`,
      semver: snapshot.semver,
      localPreflight,
      releaseReady: false,
      promotionAuthority: false,
      authorizesRelease: false
    },
    image: {
      name: EXPECTED_IMAGE_NAME,
      metadataRef: snapshot.appliances.umbrel.imageRef,
      tag: image?.tag || null,
      digest: image?.digest || null,
      metadataVersionAligned: Boolean(imagePinValid && releaseCandidateIdentity),
      sourceBound: false,
      sourceBindingPending: true
    },
    packages: {
      public: snapshot.publicPackages,
      blindInternal: snapshot.blindPackages
    },
    appliances: {
      ...snapshot.appliances,
      communityStore: communityStoreAttached
        ? { attached: true, ...snapshot.communityStore }
        : { attached: false }
    },
    fleetChannels: snapshot.fleetChannels,
    build: snapshot.build,
    inputs: snapshot.inputs,
    checks,
    declaredBlockers,
    blockers,
    requiredExternalEvidence: REQUIRED_EXTERNAL_EVIDENCE.map(id => ({
      id,
      status: id === 'community-umbrel-store-source-and-package-binding'
        ? (communityStoreExactPair ? 'attached-and-aligned' : communityStoreAttached ? 'attached-mismatched' : 'not-attached')
        : 'not-attached'
    })),
    migration: {
      performed: false,
      rule: 'After the first blind-only write, rollback is only to a blind-plus-legacy dual-read build.'
    },
    rollback: {
      performed: false,
      rule: 'No artifact was promoted. Discard only this generated local manifest or regenerate it from an exact clean reviewed source commit.'
    }
  }
  body.manifestDigest = calculateManifestDigest(body)
  return body
}

export function calculateManifestDigest (manifest) {
  const digestable = structuredClone(manifest)
  delete digestable.manifestDigest
  return `sha256:${sha256(Buffer.from(canonicalJson(digestable)))}`
}

export function verifyLocalReleaseManifestDigest (manifest) {
  if (manifest == null || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('local release manifest must be a JSON object')
  }
  if (manifest.schemaVersion !== 1 || manifest.kind !== LOCAL_RELEASE_MANIFEST_KIND) {
    throw new Error('local release manifest has an unsupported schema or kind')
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest.manifestDigest || '')) {
    throw new Error('local release manifest digest is missing or malformed')
  }
  const expected = calculateManifestDigest(manifest)
  if (manifest.manifestDigest !== expected) {
    throw new Error(`local release manifest digest mismatch: expected ${expected}`)
  }
  return true
}

export function normalizeDeclaredBlockers (values) {
  if (!Array.isArray(values)) throw new Error('declared blockers must be an array')
  const out = []
  for (const value of values) {
    const blocker = String(value || '').trim()
    if (!BLOCKER_PATTERN.test(blocker)) {
      throw new Error(`invalid declared blocker ${JSON.stringify(value)}; use an uppercase identifier`)
    }
    out.push(blocker)
  }
  return [...new Set(out)].sort()
}

function collectCommunityStoreSnapshot (storeRoot) {
  const root = path.resolve(storeRoot)
  const dirty = git(root, ['status', '--porcelain=v1', '--untracked-files=all'])
  if (dirty) {
    throw new Error(`community Umbrel store binding requires a clean worktree; found:\n${dirty}`)
  }
  const committed = new Map()
  const inputs = []
  for (const relativePath of COMMUNITY_STORE_INPUT_PATHS) {
    const blob = git(root, ['rev-parse', `HEAD:${relativePath}`])
    const bytes = gitBuffer(root, ['cat-file', 'blob', blob])
    committed.set(relativePath, bytes)
    inputs.push({
      path: relativePath,
      bytes: bytes.length,
      sha256: sha256(bytes),
      gitBlob: blob
    })
  }
  const packageBody = parseJson(committed.get('package.json'), 'community store package.json')
  const umbrelManifest = text(committed, 'hiverelay-blindspark/umbrel-app.yml')
  const imageRef = yamlImageRef(text(committed, 'hiverelay-blindspark/docker-compose.yml'))
  return {
    source: {
      repository: 'bigdestiny2/blindspark-umbrel-store',
      commit: git(root, ['rev-parse', 'HEAD']),
      tree: git(root, ['rev-parse', 'HEAD^{tree}']),
      dirty: false
    },
    packageVersion: String(packageBody.version || ''),
    umbrelVersion: yamlScalar(umbrelManifest, 'version'),
    imageRef,
    image: parseImageRef(imageRef),
    inputs
  }
}

function packageSurfaces (committed, paths) {
  return paths.map(relativePath => {
    const body = parseJson(committed.get(relativePath), relativePath)
    return {
      path: relativePath,
      name: String(body.name || ''),
      version: String(body.version || ''),
      private: body.private === true
    }
  })
}

function parseImageRef (value) {
  const match = IMAGE_REF_PATTERN.exec(value)
  if (!match) return null
  return {
    ref: value,
    name: match[1],
    tag: match[2],
    digest: match[3]
  }
}

function dockerBaseImages (dockerfile) {
  const seen = new Set()
  const images = []
  for (const line of dockerfile.split('\n')) {
    const match = /^FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$/i.exec(line.trim())
    if (!match || seen.has(match[1])) continue
    seen.add(match[1])
    images.push({
      ref: match[1],
      digestPinned: /@sha256:[a-f0-9]{64}$/i.test(match[1])
    })
  }
  return images
}

function yamlImageRef (value) {
  const match = /^\s*image:\s*([^\s#]+)\s*(?:#.*)?$/m.exec(value)
  return match ? match[1] : ''
}

function yamlScalar (value, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = new RegExp(`^${escaped}:\\s*(?:"([^"]*)"|'([^']*)'|([^#\\n]*?))\\s*(?:#.*)?$`, 'm').exec(value)
  if (!match) return ''
  return String(match[1] ?? match[2] ?? match[3] ?? '').trim()
}

function tsSingleQuotedValue (value, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = new RegExp(`${escaped}:\\s*'([^']+)'`).exec(value)
  return match ? match[1] : ''
}

export function parseStartos04AuthoringImageRef (value) {
  const overrideFallback = /const\s+releaseImageRef\s*=\s*process\.env\.HIVERELAY_STARTOS_04_IMAGE_REF\s*\|\|\s*'([^']+)'/.exec(value)
  if (overrideFallback) return overrideFallback[1]
  return tsSingleQuotedValue(value, 'dockerTag')
}

function requireSemver (value, label) {
  const semver = String(value || '')
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(semver)) {
    throw new Error(`${label} must be a semantic version; got ${JSON.stringify(value)}`)
  }
  return semver
}

function parseJson (buffer, label) {
  try {
    return JSON.parse(buffer.toString('utf8'))
  } catch (err) {
    throw new Error(`${label} must contain valid JSON: ${err.message}`)
  }
}

function text (committed, relativePath) {
  return committed.get(relativePath).toString('utf8')
}

function git (cwd, args) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024
  })
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${String(result.stderr || result.stdout || '').trim()}`)
  }
  return result.stdout.trim()
}

function gitOptional (cwd, args) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024
  })
  if (result.status !== 0) return ''
  return result.stdout.trim()
}

function gitBuffer (cwd, args) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024
  })
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${String(result.stderr || result.stdout || '').trim()}`)
  }
  return result.stdout
}

function canonicalJson (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const keys = Object.keys(value).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
}

function sha256 (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function arrayEqual (a, b) {
  return Array.isArray(a) && a.length === b.length && a.every((value, index) => value === b[index])
}

export function writeJsonAtomic (file, body) {
  const resolved = path.resolve(file)
  if (fs.existsSync(resolved)) {
    const stat = fs.lstatSync(resolved)
    if (stat.isSymbolicLink()) throw new Error(`refusing to overwrite symlink ${resolved}`)
    if (!stat.isFile()) throw new Error(`output must be a regular file ${resolved}`)
  }
  fs.mkdirSync(path.dirname(resolved), { recursive: true })
  const tmp = `${resolved}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 })
  fs.renameSync(tmp, resolved)
}
