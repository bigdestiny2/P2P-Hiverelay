import test from 'brittle'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const SHA = 'a'.repeat(40)
const DIGEST = 'sha256:' + 'b'.repeat(64)
const FLEET_CHANNEL_CONFIG_SHA = '3'.repeat(64)
const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const EXPECTED_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const STARTOS_REGISTRY_URL = 'https://registry.start9.com/startos'
const STARTOS_REGISTRY_PACKAGE_URL = `${STARTOS_REGISTRY_URL}/blindspark`
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const WRITE_RELEASE_EVIDENCE_SCRIPT = path.join(process.cwd(), 'scripts/write-release-evidence.mjs')
const S9PK_BYTES = 'startos package\n'

function scrubbedBaseEnv () {
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('HIVERELAY_'))
  )
}
const IMAGE_MANIFEST_BYTES = '{"kind":"release-image-manifest"}\n'
const IMAGE_SMOKE_BYTES = '{"kind":"release-image-smoke"}\n'
const UMBREL_SMOKE_BYTES = '{"kind":"umbrel-package-smoke"}\n'
const ROLLOUT_BYTES = '{"kind":"fleet-rollout"}\n'
const STARTOS_REGISTRY_EVIDENCE_BYTES = '{"kind":"startos-registry-publication"}\n'
const S9PK_SHA = sha256(S9PK_BYTES)
const ROLLOUT_SHA = sha256(ROLLOUT_BYTES)
const IMAGE_MANIFEST_SHA = sha256(IMAGE_MANIFEST_BYTES)
const IMAGE_SMOKE_SHA = sha256(IMAGE_SMOKE_BYTES)
const UMBREL_SMOKE_SHA = sha256(UMBREL_SMOKE_BYTES)
const STARTOS_REGISTRY_EVIDENCE_SHA = sha256(STARTOS_REGISTRY_EVIDENCE_BYTES)

function completeFullReleaseEnv (overrides = {}) {
  const env = {
    HIVERELAY_RELEASE_VERSION: 'v9.9.9',
    HIVERELAY_RELEASE_SEMVER: '9.9.9',
    HIVERELAY_RELEASE_CHANNEL: 'both',
    HIVERELAY_RELEASE_PRERELEASE: 'false',
    HIVERELAY_RELEASE_SHA: SHA,
    HIVERELAY_RELEASE_SURFACES_SHA: SHA,
    HIVERELAY_IMAGE_NAME: EXPECTED_IMAGE_NAME,
    HIVERELAY_IMAGE_DIGEST: DIGEST,
    HIVERELAY_WORKFLOW_STATUS: 'success',
    GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: EXPECTED_REPOSITORY,
    GITHUB_RUN_ID: '12345',
    GITHUB_RUN_ATTEMPT: '2',
    HIVERELAY_RELEASE_GATE_STATUS: 'passed',
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'passed',
    HIVERELAY_RELEASE_IMAGE_MANIFEST_STATUS: 'passed',
    HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: 'release-image-manifest-evidence.json',
    HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256: IMAGE_MANIFEST_SHA,
    HIVERELAY_RELEASE_IMAGE_SMOKE_STATUS: 'passed',
    HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE: 'release-image-smoke-evidence.json',
    HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: IMAGE_SMOKE_SHA,
    HIVERELAY_UMBREL_SMOKE_STATUS: 'passed',
    HIVERELAY_UMBREL_SMOKE_EVIDENCE: 'umbrel-package-smoke-evidence.json',
    HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256: UMBREL_SMOKE_SHA,
    HIVERELAY_STARTOS_VERIFY_STATUS: 'passed',
    HIVERELAY_STARTOS_PACKAGE_SHA256: S9PK_SHA,
    HIVERELAY_RELEASE_SURFACES_STATUS: 'committed',
    HIVERELAY_NPM_PUBLISH_STATUS: 'published',
    HIVERELAY_STARTOS_RELEASE_ASSET_STATUS: 'uploaded',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'verified',
    HIVERELAY_FLEET_ROLLOUT_CHANNEL: 'both',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE: 'fleet-rollout-evidence.json',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: ROLLOUT_SHA,
    HIVERELAY_FLEET_CHANNEL_CONFIG: 'fleet/channels.json',
    HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256: FLEET_CHANNEL_CONFIG_SHA,
    HIVERELAY_STARTOS_REGISTRY_STATUS: 'published',
    HIVERELAY_STARTOS_REGISTRY_URL: STARTOS_REGISTRY_URL,
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: STARTOS_REGISTRY_PACKAGE_URL,
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE: 'startos-registry-evidence.json',
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: STARTOS_REGISTRY_EVIDENCE_SHA,
    HIVERELAY_STARTOS_PACKAGE_ID: 'blindspark',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'draft-pr-ready',
    HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/getumbrel/umbrel-apps/pull/123',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: 'bigdestiny2:blindspark-v9.9.9',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: SHA,
    HIVERELAY_UMBREL_OFFICIAL_PR_STATE: 'OPEN',
    HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: 'true',
    HIVERELAY_UMBREL_OFFICIAL_PR_BASE: 'master',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: 'bigdestiny2',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: 'blindspark-v9.9.9',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: SHA,
    HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS: 'passed',
    HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS: 'pushed',
    HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT: SHA,
    HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT_URL: `https://github.com/bigdestiny2/blindspark-umbrel-store/commit/${SHA}`,
    ...overrides
  }
  if (!Object.prototype.hasOwnProperty.call(overrides, 'HIVERELAY_FLEET_ROLLOUT_CHANNEL')) {
    env.HIVERELAY_FLEET_ROLLOUT_CHANNEL = env.HIVERELAY_RELEASE_PRERELEASE === 'true'
      ? ''
      : env.HIVERELAY_RELEASE_CHANNEL
  }
  if (env.HIVERELAY_RELEASE_PRERELEASE === 'true') {
    if (!Object.prototype.hasOwnProperty.call(overrides, 'HIVERELAY_NPM_PUBLISH_STATUS')) {
      env.HIVERELAY_NPM_PUBLISH_STATUS = env.HIVERELAY_RELEASE_CANDIDATE === 'true'
        ? 'skipped'
        : 'published-next'
    }
    if (!Object.prototype.hasOwnProperty.call(overrides, 'HIVERELAY_FLEET_CHANNEL_CONFIG')) {
      env.HIVERELAY_FLEET_CHANNEL_CONFIG = ''
    }
    if (!Object.prototype.hasOwnProperty.call(overrides, 'HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256')) {
      env.HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256 = ''
    }
  }
  return env
}

function partialFailedReleaseEnv (overrides = {}) {
  return {
    HIVERELAY_RELEASE_VERSION: 'v9.9.9',
    HIVERELAY_RELEASE_SEMVER: '9.9.9',
    HIVERELAY_RELEASE_CHANNEL: 'canary',
    HIVERELAY_RELEASE_PRERELEASE: 'false',
    HIVERELAY_RELEASE_SHA: SHA,
    HIVERELAY_IMAGE_NAME: EXPECTED_IMAGE_NAME,
    HIVERELAY_WORKFLOW_STATUS: 'failure',
    HIVERELAY_RELEASE_GATE_STATUS: 'passed',
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'failed',
    HIVERELAY_RELEASE_IMAGE_SMOKE_STATUS: 'pending',
    HIVERELAY_UMBREL_SMOKE_STATUS: 'pending',
    HIVERELAY_STARTOS_VERIFY_STATUS: 'pending',
    HIVERELAY_RELEASE_SURFACES_STATUS: 'pending',
    HIVERELAY_NPM_PUBLISH_STATUS: 'pending',
    HIVERELAY_STARTOS_RELEASE_ASSET_STATUS: 'pending',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'skipped',
    HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS: 'skipped',
    ...overrides
  }
}

async function runEvidence (outFile, env, opts = {}) {
  const cwd = opts.cwd || path.dirname(path.resolve(outFile))
  if (opts.linkedArtifacts !== false) await writeReleaseArtifacts(cwd, opts.linkedArtifacts || {})
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [WRITE_RELEASE_EVIDENCE_SCRIPT, '--out', outFile], {
      cwd,
      // The release gate runs this suite with the real release's HIVERELAY_*
      // surfaces exported (gateway target, version, statuses). Fixtures must
      // see only their own values, or the writer cross-checks fixture data
      // against the live release and fails closed.
      env: { ...scrubbedBaseEnv(), ...env },
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}

async function writeReleaseArtifacts (dir, overrides = {}) {
  const files = {
    'release-image-manifest-evidence.json': IMAGE_MANIFEST_BYTES,
    'release-image-smoke-evidence.json': IMAGE_SMOKE_BYTES,
    'umbrel-package-smoke-evidence.json': UMBREL_SMOKE_BYTES,
    'fleet-rollout-evidence.json': ROLLOUT_BYTES,
    'startos-registry-evidence.json': STARTOS_REGISTRY_EVIDENCE_BYTES,
    'startos/blindspark.s9pk': S9PK_BYTES
  }
  for (const [file, defaultBytes] of Object.entries(files)) {
    if (overrides[file] === false) continue
    await writeIfMissing(path.join(dir, file), overrides[file] || defaultBytes)
  }
}

async function writeIfMissing (file, bytes) {
  try {
    await lstat(file)
    return
  } catch (e) {
    if (!e || e.code !== 'ENOENT') throw e
  }
  await mkdir(path.dirname(file), { recursive: true })
  await writeFile(file, bytes)
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

test('release evidence writer records digest, gates, and external surfaces', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, completeFullReleaseEnv({
    HIVERELAY_RELEASE_CHANNEL: 'canary'
  }))

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.schemaVersion, 1)
  t.ok(ISO_TIMESTAMP_PATTERN.test(body.generatedAt), 'release evidence generatedAt is an ISO timestamp')
  t.is(body.release.version, 'v9.9.9')
  t.is(body.release.channel, 'canary')
  t.is(body.release.candidate, false)
  t.is(body.release.workflow.runUrl, `https://github.com/${EXPECTED_REPOSITORY}/actions/runs/12345`)
  t.is(body.image.ref, `${EXPECTED_IMAGE_NAME}:9.9.9@${DIGEST}`)
  t.is(body.artifacts.startosPackage.sha256, S9PK_SHA)
  t.is(body.gates.auditAndUnit, 'passed')
  t.is(body.gates.distributionPreflight, 'passed')
  t.is(body.gates.imageManifest, 'passed')
  t.is(body.gates.imageManifestEvidence.path, 'release-image-manifest-evidence.json')
  t.is(body.gates.imageManifestEvidence.sha256, IMAGE_MANIFEST_SHA)
  t.is(body.gates.pushedImageSmokeEvidence.path, 'release-image-smoke-evidence.json')
  t.is(body.gates.pushedImageSmokeEvidence.sha256, IMAGE_SMOKE_SHA)
  t.is(body.gates.umbrelPackageSmokeEvidence.path, 'umbrel-package-smoke-evidence.json')
  t.is(body.gates.umbrelPackageSmokeEvidence.sha256, UMBREL_SMOKE_SHA)
  t.is(body.surfaces.npmPackages, 'published')
  t.is(body.surfaces.fleetRollout, 'verified')
  t.is(body.surfaces.fleetRolloutChannel, 'canary')
  t.is(body.surfaces.fleetRolloutEvidence.path, 'fleet-rollout-evidence.json')
  t.is(body.surfaces.fleetRolloutEvidence.sha256, ROLLOUT_SHA)
  t.is(body.surfaces.fleetChannelConfig.path, 'fleet/channels.json')
  t.is(body.surfaces.fleetChannelConfig.sha256, FLEET_CHANNEL_CONFIG_SHA)
  t.is(body.surfaces.startosRegistry, 'published')
  t.is(body.surfaces.startosRegistryUrl, STARTOS_REGISTRY_URL)
  t.is(body.surfaces.startosRegistryPackageUrl, STARTOS_REGISTRY_PACKAGE_URL)
  t.is(body.surfaces.startosRegistryEvidence.path, 'startos-registry-evidence.json')
  t.is(body.surfaces.startosRegistryEvidence.sha256, STARTOS_REGISTRY_EVIDENCE_SHA)
  t.is(body.surfaces.startosPackageId, 'blindspark')
  t.is(body.surfaces.umbrelOfficial.prUrl, 'https://github.com/getumbrel/umbrel-apps/pull/123')
  t.is(body.surfaces.umbrelOfficial.head, 'bigdestiny2:blindspark-v9.9.9')
  t.is(body.surfaces.umbrelOfficial.headSha, SHA)
  t.is(body.surfaces.umbrelOfficial.state, 'OPEN')
  t.is(body.surfaces.umbrelOfficial.isDraft, true)
  t.is(body.surfaces.umbrelOfficial.base, 'master')
  t.is(body.surfaces.umbrelOfficial.headOwner, 'bigdestiny2')
  t.is(body.surfaces.umbrelOfficial.headRef, 'blindspark-v9.9.9')
  t.is(body.surfaces.umbrelOfficial.headOid, SHA)
  t.is(body.surfaces.umbrelCommunityStore.publish, 'pushed')
  t.is(body.surfaces.umbrelCommunityStore.commit, SHA)
  t.is(body.surfaces.umbrelCommunityStore.commitUrl, `https://github.com/bigdestiny2/blindspark-umbrel-store/commit/${SHA}`)
})

test('release evidence writer records public gateway fleet rollout as canary-gated deferred work', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, completeFullReleaseEnv({
    HIVERELAY_RELEASE_CHANNEL: 'none',
    HIVERELAY_PUBLIC_GATEWAY_RELEASE_ENABLED: 'true',
    HIVERELAY_PUBLIC_GATEWAY_MANIFEST_STATUS: 'enabled',
    HIVERELAY_PUBLIC_GATEWAY_MANIFEST_PATH: 'fleet/public-hive-gateway-release.json',
    HIVERELAY_PUBLIC_GATEWAY_MANIFEST_SHA256: '4'.repeat(64),
    HIVERELAY_PUBLIC_GATEWAY_RELEASE_TARGET: 'v9.9.9',
    HIVERELAY_PUBLIC_GATEWAY_COMMIT_SHA: SHA,
    HIVERELAY_PUBLIC_GATEWAY_ADMISSION_PROFILE: 'blind-substrate-public-v1',
    HIVERELAY_PUBLIC_GATEWAY_COHORT_SIZE: '3',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'deferred-gateway-canary-gated',
    HIVERELAY_FLEET_ROLLOUT_CHANNEL: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: '',
    HIVERELAY_FLEET_CHANNEL_CONFIG: '',
    HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256: ''
  }), {
    linkedArtifacts: { 'fleet-rollout-evidence.json': false }
  })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.release.channel, 'none')
  t.alike(body.release.publicGateway, {
    enabled: true,
    manifestStatus: 'enabled',
    manifestPath: 'fleet/public-hive-gateway-release.json',
    manifestSha256: '4'.repeat(64),
    releaseTarget: 'v9.9.9',
    commitSha: SHA,
    admissionProfile: 'blind-substrate-public-v1',
    cohortSize: 3
  })
  t.is(body.surfaces.fleetRollout, 'deferred-gateway-canary-gated')
  t.is(body.surfaces.fleetRolloutEvidence.path, '')
  t.is(body.surfaces.fleetChannelConfig.path, '')
})

test('release evidence writer rejects symlinked present sidecars before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await writeFile(path.join(dir, 'release-image-smoke-target.json'), '{}\n')
  await symlink('release-image-smoke-target.json', path.join(dir, 'release-image-smoke-evidence.json'))

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image smoke evidence file must not be a symlink'))
})

test('release evidence writer rejects oversized present sidecars before hashing', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await writeFile(path.join(dir, 'release-image-smoke-evidence.json'), Buffer.alloc(2 * 1024 * 1024 + 1, 'x'))

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image smoke evidence file must be 2097152 bytes or smaller'))
})

test('release evidence writer rejects present sidecar hash drift', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const smokeEvidence = '{"kind":"release-image-smoke"}\n'
  await writeFile(path.join(dir, 'release-image-smoke-evidence.json'), smokeEvidence)

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: '0'.repeat(64)
    }), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release image smoke evidence SHA-256 does not match release-image-smoke-evidence.json'))
  t.ok(err.stderr.includes(sha256(smokeEvidence)), 'reports the actual present sidecar hash')
})

test('release evidence writer rejects unsafe or malformed present sidecars before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const unsafeSmoke = '{"kind":"release-image-smoke","token":"Bearer abcdefghijklmnopqrstuvwxyz"}\n'
  const unsafeFile = path.join(dir, 'unsafe-sidecar.json')
  let unsafeErr = null
  try {
    await runEvidence(unsafeFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: sha256(unsafeSmoke)
    }), {
      cwd: dir,
      linkedArtifacts: {
        'release-image-smoke-evidence.json': unsafeSmoke
      }
    })
  } catch (e) {
    unsafeErr = e
  }
  t.ok(unsafeErr)
  t.ok(unsafeErr.stderr.includes('release image smoke evidence must not expose bearer token'))

  const malformedDir = path.join(dir, 'malformed')
  const malformedFile = path.join(malformedDir, 'malformed-sidecar.json')
  let malformedErr = null
  try {
    await runEvidence(malformedFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: sha256('not-json\n')
    }), {
      cwd: malformedDir,
      linkedArtifacts: {
        'release-image-smoke-evidence.json': 'not-json\n'
      }
    })
  } catch (e) {
    malformedErr = e
  }
  t.ok(malformedErr)
  t.ok(malformedErr.stderr.includes('release image smoke evidence file must contain valid JSON'))
})

test('release evidence writer hashes public sidecars as streams', async (t) => {
  const script = await readFile(WRITE_RELEASE_EVIDENCE_SCRIPT, 'utf8')
  const evidenceVerifier = script.match(/async function verifyPresentEvidenceFile \(label, relativePath, expectedSha256\)[\s\S]*?\n}\n\nfunction readPublicEvidenceJson/)
  t.ok(evidenceVerifier, 'sidecar verifier is present')
  t.ok(script.includes('await verifyPresentEvidenceFiles(body, true)'), 'full release validation waits for sidecar preflight')
  t.ok(script.includes('assertPublicSafeValues(readPublicEvidenceJson(label, file), label)'), 'sidecar verifier scans public JSON before writing')
  t.ok((evidenceVerifier?.[0] || '').includes('const actualSha256 = await sha256File(file)'), 'sidecar verifier uses the streaming hash helper')
  t.absent((evidenceVerifier?.[0] || '').includes('readFileSync(file))'), 'sidecar verifier does not hash by buffering the sidecar')
})

test('release evidence writer requires successful release sidecars and package before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const missingSidecarFile = path.join(dir, 'missing-sidecar.json')
  let sidecarErr = null
  try {
    await runEvidence(missingSidecarFile, completeFullReleaseEnv(), {
      cwd: dir,
      linkedArtifacts: { 'release-image-manifest-evidence.json': false }
    })
  } catch (e) {
    sidecarErr = e
  }

  t.ok(sidecarErr)
  t.ok(sidecarErr.stderr.includes('release image manifest evidence file is required before writing successful release evidence: release-image-manifest-evidence.json'))

  const missingPackageDir = path.join(dir, 'missing-package')
  const missingPackageFile = path.join(missingPackageDir, 'release-evidence.json')
  let packageErr = null
  try {
    await runEvidence(missingPackageFile, completeFullReleaseEnv(), {
      cwd: missingPackageDir,
      linkedArtifacts: { 'startos/blindspark.s9pk': false }
    })
  } catch (e) {
    packageErr = e
  }

  t.ok(packageErr)
  t.ok(packageErr.stderr.includes('StartOS package file is required before writing successful release evidence: startos/blindspark.s9pk'))
})

test('release evidence writer verifies present StartOS package artifacts before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const packageBytes = 'startos package\n'
  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/blindspark.s9pk'), packageBytes)

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, completeFullReleaseEnv({
    HIVERELAY_STARTOS_PACKAGE_SHA256: sha256(packageBytes)
  }), { cwd: dir })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.artifacts.startosPackage.path, 'startos/blindspark.s9pk')
  t.is(body.artifacts.startosPackage.sha256, sha256(packageBytes))
})

test('release evidence writer hashes present StartOS package artifacts as a stream', async (t) => {
  const script = await readFile(WRITE_RELEASE_EVIDENCE_SCRIPT, 'utf8')
  const artifactVerifier = script.match(/async function verifyPresentArtifactFile[\s\S]*?\n}\n\nfunction sha256File/)
  t.ok(artifactVerifier, 'artifact verifier is present')
  t.ok(script.includes('await verifyPresentStartosPackage(body)'), 'successful release validation waits for package preflight')
  t.ok(script.includes('const actualSha256 = await sha256File(file)'), 'artifact verifier uses the streaming helper')
  t.ok(script.includes('fs.createReadStream(file)'), 'package hash check streams the .s9pk')
  t.absent((artifactVerifier?.[0] || '').includes('readFileSync'), 'artifact verifier does not load the whole .s9pk into memory')
})

test('release evidence writer rejects symlinked present StartOS package artifacts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/package-target.s9pk'), 'startos package\n')
  await symlink('package-target.s9pk', path.join(dir, 'startos/blindspark.s9pk'))

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package file must not be a symlink'))
})

test('release evidence writer rejects non-regular present StartOS package artifacts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'startos/blindspark.s9pk'), { recursive: true })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package file must be a regular file'))
})

test('release evidence writer rejects present StartOS package artifact hash drift', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const packageBytes = 'stale startos package\n'
  await mkdir(path.join(dir, 'startos'), { recursive: true })
  await writeFile(path.join(dir, 'startos/blindspark.s9pk'), packageBytes)

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_STARTOS_PACKAGE_SHA256: '0'.repeat(64)
    }), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('StartOS package SHA-256 does not match startos/blindspark.s9pk'))
  t.ok(err.stderr.includes(sha256(packageBytes)), 'reports the actual present package hash')
})

test('release evidence writer hashes canonical fleet channel config fallbacks from the release workspace', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const channels = '{"canary":{"target":"v9.9.9"}}\n'
  await mkdir(path.join(dir, 'fleet'), { recursive: true })
  await writeFile(path.join(dir, 'fleet/channels.json'), channels)

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, partialFailedReleaseEnv(), { cwd: dir })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.surfaces.fleetChannelConfig.path, 'fleet/channels.json')
  t.is(body.surfaces.fleetChannelConfig.sha256, sha256(channels))
})

test('release evidence writer rejects non-canonical fleet channel config hash fallback paths', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, partialFailedReleaseEnv({
      HIVERELAY_FLEET_CHANNEL_CONFIG: '../channels.json'
    }), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet channel config path must be fleet/channels.json'))
})

test('release evidence writer rejects symlinked fleet channel config hash fallbacks', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'fleet'), { recursive: true })
  await writeFile(path.join(dir, 'fleet/channels-target.json'), '{}\n')
  await symlink('channels-target.json', path.join(dir, 'fleet/channels.json'))

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, partialFailedReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet channel config file must not be a symlink'))
})

test('release evidence writer rejects oversized fleet channel config hash fallbacks', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  await mkdir(path.join(dir, 'fleet'), { recursive: true })
  await writeFile(path.join(dir, 'fleet/channels.json'), Buffer.alloc(2 * 1024 * 1024 + 1, 'x'))

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, partialFailedReleaseEnv(), { cwd: dir })
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet channel config file must be 2097152 bytes or smaller'))
})

test('release evidence writer rejects successful full releases with incomplete distribution proof', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('successful full release StartOS registry publish'))
})

test('release evidence writer rejects successful full releases with stale official Umbrel PR state', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const closedFile = path.join(dir, 'closed-official-pr.json')
  let closedErr = null
  try {
    await runEvidence(closedFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_STATE: 'CLOSED'
    }))
  } catch (e) {
    closedErr = e
  }
  t.ok(closedErr)
  t.ok(closedErr.stderr.includes('successful full release official Umbrel PR state'))

  const zeroPrFile = path.join(dir, 'zero-official-pr.json')
  let zeroPrErr = null
  try {
    await runEvidence(zeroPrFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/getumbrel/umbrel-apps/pull/0'
    }))
  } catch (e) {
    zeroPrErr = e
  }
  t.ok(zeroPrErr)
  t.ok(zeroPrErr.stderr.includes('successful full release official Umbrel PR URL'))

  const readyFile = path.join(dir, 'ready-official-pr.json')
  let draftErr = null
  try {
    await runEvidence(readyFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: 'false'
    }))
  } catch (e) {
    draftErr = e
  }
  t.ok(draftErr)
  t.ok(draftErr.stderr.includes('successful full release official Umbrel PR draft'))

  const baseFile = path.join(dir, 'wrong-official-pr-base.json')
  let baseErr = null
  try {
    await runEvidence(baseFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_BASE: 'main'
    }))
  } catch (e) {
    baseErr = e
  }
  t.ok(baseErr)
  t.ok(baseErr.stderr.includes('successful full release official Umbrel PR base'))

  const headRefFile = path.join(dir, 'wrong-official-pr-head-ref.json')
  let headRefErr = null
  try {
    await runEvidence(headRefFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: 'other-branch'
    }))
  } catch (e) {
    headRefErr = e
  }
  t.ok(headRefErr)
  t.ok(headRefErr.stderr.includes('successful full release official Umbrel PR head ref matches head branch'))

  const headOwnerFile = path.join(dir, 'wrong-official-pr-head-owner.json')
  let headOwnerErr = null
  try {
    await runEvidence(headOwnerFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: 'attacker'
    }))
  } catch (e) {
    headOwnerErr = e
  }
  t.ok(headOwnerErr)
  t.ok(headOwnerErr.stderr.includes('successful full release official Umbrel PR head owner matches head owner'))

  const headOidFile = path.join(dir, 'wrong-official-pr-head-oid.json')
  let headOidErr = null
  try {
    await runEvidence(headOidFile, completeFullReleaseEnv({
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: 'b'.repeat(40)
    }))
  } catch (e) {
    headOidErr = e
  }
  t.ok(headOidErr)
  t.ok(headOidErr.stderr.includes('successful full release official Umbrel PR head OID matches head SHA'))
})

test('release evidence writer rejects credentialed StartOS registry URLs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_URL: 'https://user:pass@registry.start9.com/startos'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not expose URL credentials at $.surfaces.startosRegistryUrl'))
})

test('release evidence writer rejects malformed official Umbrel PR GitHub owner names', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  for (const owner of ['bad_owner', 'bad.owner', '-bad', 'getumbrel', 'GetUmbrel']) {
    let err = null
    try {
      await runEvidence(path.join(dir, `${owner}-release-evidence.json`), completeFullReleaseEnv({
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: `${owner}:blindspark-v9.9.9`,
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: owner
      }))
    } catch (e) {
      err = e
    }
    t.ok(err, owner)
    t.ok(err.stderr.includes('successful full release official Umbrel PR head owner must be a normal GitHub owner name'), owner)
  }
})

test('release evidence writer rejects malformed official Umbrel PR GitHub head refs', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  for (const ref of ['bad..ref', '.bad-ref', 'bad/ref.lock']) {
    let err = null
    try {
      await runEvidence(path.join(dir, `${ref.replace(/\//g, '-')}-release-evidence.json`), completeFullReleaseEnv({
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: `bigdestiny2:${ref}`,
        HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: ref
      }))
    } catch (e) {
      err = e
    }
    t.ok(err, ref)
    t.ok(err.stderr.includes('successful full release official Umbrel PR head ref must be a normal GitHub branch name'), ref)
  }
})

test('release evidence writer rejects placeholder StartOS registry hosts', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_URL: 'https://registry.example/startos'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('reserved/local hostnames'))
})

test('release evidence writer rejects unsafe public values before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_IMAGE_NAME: `${EXPECTED_IMAGE_NAME} Authorization: Bearer abcdefghijklmnopqrstuvwxyz`
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not expose authorization header'))
  let wroteEvidence = true
  try {
    await readFile(outFile, 'utf8')
  } catch (e) {
    if (e && e.code === 'ENOENT') wroteEvidence = false
    else throw e
  }
  t.is(wroteEvidence, false)
})

test('release evidence writer rejects env-style secret public values before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_IMAGE_NAME: `${EXPECTED_IMAGE_NAME} APP_SEED=super-secret-seed`
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not expose APP_SEED'))
  let wroteEvidence = true
  try {
    await readFile(outFile, 'utf8')
  } catch (e) {
    if (e && e.code === 'ENOENT') wroteEvidence = false
    else throw e
  }
  t.is(wroteEvidence, false)
})

test('release evidence writer rejects control-character public values before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_IMAGE_NAME: `${EXPECTED_IMAGE_NAME}\nrelease`
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('release evidence must not contain control characters'))
  let wroteEvidence = true
  try {
    await readFile(outFile, 'utf8')
  } catch (e) {
    if (e && e.code === 'ENOENT') wroteEvidence = false
    else throw e
  }
  t.is(wroteEvidence, false)
})

test('release evidence writer rejects successful releases with malformed workflow identity', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      GITHUB_RUN_ID: 'not-a-number'
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('successful release workflow run id'))

  const zeroRunIdFile = path.join(dir, 'zero-run-id.json')
  let zeroRunIdErr = null
  try {
    await runEvidence(zeroRunIdFile, completeFullReleaseEnv({
      GITHUB_RUN_ID: '0'
    }))
  } catch (e) {
    zeroRunIdErr = e
  }

  t.ok(zeroRunIdErr)
  t.ok(zeroRunIdErr.stderr.includes('successful release workflow run id'))

  const zeroAttemptFile = path.join(dir, 'zero-run-attempt.json')
  let zeroAttemptErr = null
  try {
    await runEvidence(zeroAttemptFile, completeFullReleaseEnv({
      GITHUB_RUN_ATTEMPT: '0'
    }))
  } catch (e) {
    zeroAttemptErr = e
  }

  t.ok(zeroAttemptErr)
  t.ok(zeroAttemptErr.stderr.includes('successful release workflow run attempt'))

  const wrongRepoFile = path.join(dir, 'wrong-repository.json')
  let wrongRepoErr = null
  try {
    await runEvidence(wrongRepoFile, completeFullReleaseEnv({
      GITHUB_REPOSITORY: 'attacker/P2P-Hiverelay'
    }))
  } catch (e) {
    wrongRepoErr = e
  }

  t.ok(wrongRepoErr)
  t.ok(wrongRepoErr.stderr.includes(`successful release workflow repository must be "${EXPECTED_REPOSITORY}"`))
})

test('release evidence writer rejects whitespace-normalized metadata before write', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const cases = [
    ['padded-version', { HIVERELAY_RELEASE_VERSION: 'v9.9.9 ' }, 'HIVERELAY_RELEASE_VERSION must be a v-prefixed semver tag'],
    ['padded-tag-sha', { HIVERELAY_RELEASE_SHA: `${SHA} ` }, 'HIVERELAY_RELEASE_SHA must be a 40-character commit SHA'],
    ['padded-run-id', { GITHUB_RUN_ID: '12345 ' }, 'successful release workflow run id'],
    ['padded-run-attempt', { GITHUB_RUN_ATTEMPT: '2 ' }, 'successful release workflow run attempt'],
    ['padded-workflow-server', { GITHUB_SERVER_URL: 'https://github.com ' }, 'successful release workflow URL'],
    ['padded-image-digest', { HIVERELAY_IMAGE_DIGEST: `${DIGEST} ` }, 'HIVERELAY_IMAGE_DIGEST must be sha256:<64 hex chars>'],
    ['padded-sidecar-path', { HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE: 'release-image-smoke-evidence.json ' }, 'successful release image smoke evidence path'],
    ['padded-registry-url', { HIVERELAY_STARTOS_REGISTRY_URL: `${STARTOS_REGISTRY_URL} ` }, 'HIVERELAY_STARTOS_REGISTRY_URL must be a public https URL'],
    ['padded-umbrel-pr-url', { HIVERELAY_UMBREL_OFFICIAL_PR_URL: 'https://github.com/getumbrel/umbrel-apps/pull/123 ' }, 'successful full release official Umbrel PR URL must point to getumbrel/umbrel-apps']
  ]

  for (const [name, overrides, expectedError] of cases) {
    const outFile = path.join(dir, `${name}.json`)
    let err = null
    try {
      await runEvidence(outFile, completeFullReleaseEnv(overrides))
    } catch (e) {
      err = e
    }

    t.ok(err, `${name} is rejected`)
    t.ok(err.stderr.includes(expectedError), `${name} reports the malformed raw field`)
    let wroteEvidence = true
    try {
      await readFile(outFile, 'utf8')
    } catch (e) {
      if (e && e.code === 'ENOENT') wroteEvidence = false
      else throw e
    }
    t.is(wroteEvidence, false, `${name} does not write release evidence`)
  }
})

test('release evidence writer rejects internally inconsistent release identity', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const semverFile = path.join(dir, 'bad-semver.json')
  let semverErr = null
  try {
    await runEvidence(semverFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_SEMVER: '9.9.8'
    }))
  } catch (e) {
    semverErr = e
  }
  t.ok(semverErr)
  t.ok(semverErr.stderr.includes('release semver matches version'))

  const malformedImageFile = path.join(dir, 'malformed-image.json')
  let malformedImageErr = null
  try {
    await runEvidence(malformedImageFile, completeFullReleaseEnv({
      HIVERELAY_IMAGE_NAME: 'example/hiverelay'
    }))
  } catch (e) {
    malformedImageErr = e
  }
  t.ok(malformedImageErr)
  t.ok(malformedImageErr.stderr.includes('successful release image name'))

  const wrongImageFile = path.join(dir, 'wrong-image.json')
  let wrongImageErr = null
  try {
    await runEvidence(wrongImageFile, completeFullReleaseEnv({
      HIVERELAY_IMAGE_NAME: 'ghcr.io/attacker/p2p-hiverelay'
    }))
  } catch (e) {
    wrongImageErr = e
  }
  t.ok(wrongImageErr)
  t.ok(wrongImageErr.stderr.includes(`successful release image name must be "${EXPECTED_IMAGE_NAME}"`))

  const metadataFile = path.join(dir, 'bad-metadata.json')
  let metadataErr = null
  try {
    await runEvidence(metadataFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_SURFACES_SHA: 'not-a-sha'
    }))
  } catch (e) {
    metadataErr = e
  }
  t.ok(metadataErr)
  t.ok(metadataErr.stderr.includes('HIVERELAY_RELEASE_SURFACES_SHA'))
})

test('release evidence writer rejects successful full releases without artifact or rollout-channel proof', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const missingArtifact = path.join(dir, 'missing-artifact.json')
  let artifactErr = null
  try {
    await runEvidence(missingArtifact, completeFullReleaseEnv({
      HIVERELAY_STARTOS_PACKAGE_SHA256: ''
    }))
  } catch (e) {
    artifactErr = e
  }
  t.ok(artifactErr)
  t.ok(artifactErr.stderr.includes('successful release StartOS package SHA-256'))

  const mismatchedChannel = path.join(dir, 'mismatched-channel.json')
  let channelErr = null
  try {
    await runEvidence(mismatchedChannel, completeFullReleaseEnv({
      HIVERELAY_RELEASE_CHANNEL: 'stable',
      HIVERELAY_FLEET_ROLLOUT_CHANNEL: 'canary'
    }))
  } catch (e) {
    channelErr = e
  }
  t.ok(channelErr)
  t.ok(channelErr.stderr.includes('successful full release fleet rollout channel'))

  const missingRolloutEvidence = path.join(dir, 'missing-rollout-evidence.json')
  let rolloutEvidenceErr = null
  try {
    await runEvidence(missingRolloutEvidence, completeFullReleaseEnv({
      HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: ''
    }))
  } catch (e) {
    rolloutEvidenceErr = e
  }
  t.ok(rolloutEvidenceErr)
  t.ok(rolloutEvidenceErr.stderr.includes('successful full release fleet rollout evidence SHA-256'))

  const malformedFleetChannels = path.join(dir, 'malformed-fleet-channels.json')
  let fleetChannelsErr = null
  try {
    await runEvidence(malformedFleetChannels, completeFullReleaseEnv({
      HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256: 'not-a-sha'
    }))
  } catch (e) {
    fleetChannelsErr = e
  }
  t.ok(fleetChannelsErr)
  t.ok(fleetChannelsErr.stderr.includes('HIVERELAY_FLEET_CHANNEL_CONFIG_SHA256'))

  const missingImageSmokeEvidence = path.join(dir, 'missing-image-smoke-evidence.json')
  let imageSmokeEvidenceErr = null
  try {
    await runEvidence(missingImageSmokeEvidence, completeFullReleaseEnv({
      HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256: ''
    }))
  } catch (e) {
    imageSmokeEvidenceErr = e
  }
  t.ok(imageSmokeEvidenceErr)
  t.ok(imageSmokeEvidenceErr.stderr.includes('successful release image smoke evidence SHA-256'))

  const missingUmbrelSmokeEvidence = path.join(dir, 'missing-umbrel-smoke-evidence.json')
  let umbrelSmokeEvidenceErr = null
  try {
    await runEvidence(missingUmbrelSmokeEvidence, completeFullReleaseEnv({
      HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256: ''
    }))
  } catch (e) {
    umbrelSmokeEvidenceErr = e
  }
  t.ok(umbrelSmokeEvidenceErr)
  t.ok(umbrelSmokeEvidenceErr.stderr.includes('successful release Umbrel package smoke evidence SHA-256'))

  const missingStartosRegistryUrl = path.join(dir, 'missing-startos-registry-url.json')
  let startosRegistryUrlErr = null
  try {
    await runEvidence(missingStartosRegistryUrl, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_URL: '',
      HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: ''
    }))
  } catch (e) {
    startosRegistryUrlErr = e
  }
  t.ok(startosRegistryUrlErr)
  t.ok(startosRegistryUrlErr.stderr.includes('successful full release StartOS registry URL'))

  const missingStartosRegistryPackageUrl = path.join(dir, 'missing-startos-registry-package-url.json')
  let startosRegistryPackageUrlErr = null
  try {
    await runEvidence(missingStartosRegistryPackageUrl, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: ''
    }))
  } catch (e) {
    startosRegistryPackageUrlErr = e
  }
  t.ok(startosRegistryPackageUrlErr)
  t.ok(startosRegistryPackageUrlErr.stderr.includes('successful full release StartOS registry package URL'))

  const missingStartosRegistryEvidencePath = path.join(dir, 'missing-startos-registry-evidence-path.json')
  let startosRegistryEvidencePathErr = null
  try {
    await runEvidence(missingStartosRegistryEvidencePath, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_EVIDENCE: '',
      HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: ''
    }))
  } catch (e) {
    startosRegistryEvidencePathErr = e
  }
  t.ok(startosRegistryEvidencePathErr)
  t.ok(startosRegistryEvidencePathErr.stderr.includes('successful full release StartOS registry evidence path'))

  const missingStartosRegistryEvidence = path.join(dir, 'missing-startos-registry-evidence-hash.json')
  let startosRegistryEvidenceErr = null
  try {
    await runEvidence(missingStartosRegistryEvidence, completeFullReleaseEnv({
      HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: ''
    }))
  } catch (e) {
    startosRegistryEvidenceErr = e
  }
  t.ok(startosRegistryEvidenceErr)
  t.ok(startosRegistryEvidenceErr.stderr.includes('successful full release StartOS registry evidence SHA-256'))

  const missingUmbrelCommit = path.join(dir, 'missing-umbrel-commit.json')
  let umbrelCommitErr = null
  try {
    await runEvidence(missingUmbrelCommit, completeFullReleaseEnv({
      HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT: ''
    }))
  } catch (e) {
    umbrelCommitErr = e
  }
  t.ok(umbrelCommitErr)
  t.ok(umbrelCommitErr.stderr.includes('successful full release Umbrel community-store commit'))
})

test('release evidence writer allows successful prereleases to skip distribution surfaces', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, completeFullReleaseEnv({
    HIVERELAY_RELEASE_VERSION: 'v9.9.9-beta.1',
    HIVERELAY_RELEASE_SEMVER: '9.9.9-beta.1',
    HIVERELAY_RELEASE_CHANNEL: 'none',
    HIVERELAY_RELEASE_PRERELEASE: 'true',
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'skipped',
    HIVERELAY_RELEASE_SURFACES_STATUS: 'skipped',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'skipped',
    HIVERELAY_FLEET_ROLLOUT_CHANNEL: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: '',
    HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped',
    HIVERELAY_STARTOS_REGISTRY_URL: '',
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: '',
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE: '',
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: '',
    HIVERELAY_STARTOS_PACKAGE_ID: '',
    STARTOS_REGISTRY_URL,
    STARTOS_REGISTRY_PACKAGE_URL,
    HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'skipped',
    HIVERELAY_UMBREL_OFFICIAL_PR_URL: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATE: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_BASE: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: ''
  }))

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.release.prerelease, true)
  t.is(body.gates.distributionPreflight, 'skipped')
  t.is(body.surfaces.npmPackages, 'published-next')
  t.is(body.surfaces.startosReleaseAsset, 'uploaded')
  t.is(body.surfaces.fleetRollout, 'skipped')
  // The community store is the deliberate prerelease exception: it syncs
  // on every release, so the prerelease carries full store facts.
  t.is(body.surfaces.umbrelCommunityStore.validation, 'passed')
  t.is(body.surfaces.umbrelCommunityStore.publish, 'pushed')
  t.is(body.surfaces.umbrelCommunityStore.commit, SHA)
})

test('release evidence writer allows branch candidates to skip release asset publication', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, completeFullReleaseEnv({
    HIVERELAY_RELEASE_VERSION: 'v9.9.9-ship.20260624.abcdef123456',
    HIVERELAY_RELEASE_SEMVER: '9.9.9-ship.20260624.abcdef123456',
    HIVERELAY_RELEASE_CHANNEL: 'none',
    HIVERELAY_RELEASE_PRERELEASE: 'true',
    HIVERELAY_RELEASE_CANDIDATE: 'true',
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'skipped',
    HIVERELAY_RELEASE_SURFACES_STATUS: 'skipped',
    HIVERELAY_STARTOS_RELEASE_ASSET_STATUS: 'skipped',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'skipped',
    HIVERELAY_FLEET_ROLLOUT_CHANNEL: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE: '',
    HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: '',
    HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped',
    HIVERELAY_STARTOS_REGISTRY_URL: '',
    HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: '',
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE: '',
    HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: '',
    HIVERELAY_STARTOS_PACKAGE_ID: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'skipped',
    HIVERELAY_UMBREL_OFFICIAL_PR_URL: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATE: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_BASE: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: '',
    HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: '',
    HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT: '',
    HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT_URL: ''
  }))

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.release.prerelease, true)
  t.is(body.release.candidate, true)
  t.is(body.surfaces.npmPackages, 'skipped')
  t.is(body.surfaces.startosReleaseAsset, 'skipped')
  t.is(body.surfaces.startosRegistryUrl, '')
  t.is(body.surfaces.startosRegistryPackageUrl, '')
  t.is(body.surfaces.fleetRollout, 'skipped')
})

test('release evidence writer rejects successful prereleases with promotion channels', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  let err = null
  try {
    await runEvidence(outFile, completeFullReleaseEnv({
      HIVERELAY_RELEASE_VERSION: 'v9.9.9-beta.1',
      HIVERELAY_RELEASE_SEMVER: '9.9.9-beta.1',
      HIVERELAY_RELEASE_CHANNEL: 'canary',
      HIVERELAY_RELEASE_PRERELEASE: 'true',
      HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'skipped',
      HIVERELAY_RELEASE_SURFACES_STATUS: 'skipped',
      HIVERELAY_FLEET_ROLLOUT_STATUS: 'skipped',
      HIVERELAY_FLEET_ROLLOUT_CHANNEL: '',
      HIVERELAY_FLEET_ROLLOUT_EVIDENCE: '',
      HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256: '',
      HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped',
      HIVERELAY_STARTOS_REGISTRY_URL: '',
      HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL: '',
      HIVERELAY_STARTOS_REGISTRY_EVIDENCE: '',
      HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256: '',
      HIVERELAY_STARTOS_PACKAGE_ID: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'skipped',
      HIVERELAY_UMBREL_OFFICIAL_PR_URL: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_STATE: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_BASE: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF: '',
      HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID: '',
      HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS: 'skipped',
      HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS: 'skipped',
      HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT: '',
      HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT_URL: ''
    }))
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('successful prerelease channel'))
})

test('release evidence writer supports partial failed-run evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-evidence-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outFile = path.join(dir, 'release-evidence.json')
  await runEvidence(outFile, {
    HIVERELAY_RELEASE_VERSION: 'v9.9.9',
    HIVERELAY_RELEASE_SEMVER: '9.9.9',
    HIVERELAY_RELEASE_CHANNEL: 'canary',
    HIVERELAY_RELEASE_PRERELEASE: 'false',
    HIVERELAY_RELEASE_SHA: SHA,
    HIVERELAY_IMAGE_NAME: EXPECTED_IMAGE_NAME,
    HIVERELAY_WORKFLOW_STATUS: 'failure',
    HIVERELAY_RELEASE_GATE_STATUS: 'passed',
    HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'failed',
    HIVERELAY_RELEASE_IMAGE_SMOKE_STATUS: 'pending',
    HIVERELAY_UMBREL_SMOKE_STATUS: 'pending',
    HIVERELAY_STARTOS_VERIFY_STATUS: 'pending',
    HIVERELAY_RELEASE_SURFACES_STATUS: 'pending',
    HIVERELAY_STARTOS_RELEASE_ASSET_STATUS: 'pending',
    HIVERELAY_FLEET_ROLLOUT_STATUS: 'skipped',
    HIVERELAY_STARTOS_REGISTRY_STATUS: 'skipped',
    HIVERELAY_UMBREL_OFFICIAL_PR_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_VALIDATE_STATUS: 'skipped',
    HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS: 'skipped'
  })

  const body = JSON.parse(await readFile(outFile, 'utf8'))
  t.is(body.release.workflow.status, 'failure')
  t.is(body.image.digest, '')
  t.is(body.image.ref, '')
  t.is(body.gates.auditAndUnit, 'passed')
  t.is(body.gates.distributionPreflight, 'failed')
  t.is(body.gates.pushedImageSmoke, 'pending')
  t.is(body.surfaces.metadataCommit, 'pending')
  t.is(body.surfaces.fleetRollout, 'skipped')
})
