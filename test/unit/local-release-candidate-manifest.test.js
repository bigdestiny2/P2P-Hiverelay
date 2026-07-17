import test from 'brittle'
import { readFile } from 'node:fs/promises'
import {
  buildLocalReleaseCandidateManifest,
  calculateManifestDigest,
  normalizeDeclaredBlockers,
  verifyLocalReleaseManifestDigest
} from '../../scripts/lib/local-release-candidate-manifest.mjs'

const SOURCE_COMMIT = 'a'.repeat(40)
const SOURCE_TREE = 'b'.repeat(40)
const IMAGE_DIGEST = 'sha256:' + 'c'.repeat(64)
const BASE_DIGEST = 'sha256:' + 'd'.repeat(64)

test('local release candidate manifest is deterministic, content-addressed, and never release-ready', (t) => {
  const snapshot = fixtureSnapshot()
  const first = buildLocalReleaseCandidateManifest(snapshot, {
    declaredBlockers: ['GLOBAL_PG2_IN_PROGRESS', 'D6_STORE_FORMAT_BLOCKED', 'GLOBAL_PG2_IN_PROGRESS']
  })
  const second = buildLocalReleaseCandidateManifest(snapshot, {
    declaredBlockers: ['D6_STORE_FORMAT_BLOCKED', 'GLOBAL_PG2_IN_PROGRESS']
  })

  t.alike(first, second)
  t.is(first.release.localPreflight, 'blocked')
  t.is(first.release.releaseReady, false)
  t.is(first.release.promotionAuthority, false)
  t.is(first.release.authorizesRelease, false)
  t.is(first.claimClass, 'LOCAL_OFFLINE_DRAFT_ONLY')
  t.is(first.image.metadataVersionAligned, true)
  t.is(first.image.sourceBound, false)
  t.is(first.image.sourceBindingPending, true)
  t.alike(first.declaredBlockers, ['D6_STORE_FORMAT_BLOCKED', 'GLOBAL_PG2_IN_PROGRESS'])
  t.ok(first.blockers.includes('BLIND_WORKSPACES_DRAFT_ONLY'))
  t.ok(first.blockers.includes('EXTERNAL_RELEASE_EVIDENCE_NOT_ATTACHED'))
  t.ok(first.blockers.includes('LOCAL_MANIFEST_NO_PROMOTION_AUTHORITY'))
  t.ok(first.blockers.includes('PINNED_IMAGE_NOT_SOURCE_BOUND'))
  t.is(first.appliances.communityStore.attached, true)
  t.is(first.manifestDigest, calculateManifestDigest(first))
  t.ok(verifyLocalReleaseManifestDigest(first))
})

test('local release candidate manifest fails closed on tag, image, base, workflow, and Umbrel gaps', (t) => {
  const snapshot = fixtureSnapshot()
  snapshot.source.versionTagCommit = 'e'.repeat(40)
  snapshot.build.baseImages[0].digestPinned = false
  snapshot.build.baseImages[0].ref = 'node:22-bookworm-slim'
  snapshot.build.sbomConfigured = false
  snapshot.build.provenanceConfigured = false
  snapshot.build.splitSourceWorkflow = true
  snapshot.appliances.umbrel.submission = 'https://github.com/getumbrel/umbrel-apps/pull/PENDING'
  snapshot.communityStore.packageVersion = '9.9.8'

  const manifest = buildLocalReleaseCandidateManifest(snapshot)

  t.is(manifest.release.localPreflight, 'blocked')
  t.is(manifest.release.releaseReady, false)
  t.is(manifest.image.sourceBound, false)
  for (const blocker of [
    'SOURCE_VERSION_TAG_NOT_EXACT',
    'PINNED_IMAGE_NOT_SOURCE_BOUND',
    'CONTAINER_BASE_IMAGE_DIGESTS_UNPINNED',
    'RELEASE_WORKFLOW_SBOM_MISSING',
    'RELEASE_WORKFLOW_PROVENANCE_MISSING',
    'RELEASE_WORKFLOW_SPLIT_SOURCE',
    'UMBREL_OFFICIAL_SUBMISSION_PENDING',
    'COMMUNITY_UMBREL_STORE_EXACT_PAIR_MISMATCH'
  ]) {
    t.ok(manifest.blockers.includes(blocker), blocker)
  }
})

test('local release candidate manifest digest rejects tampering', (t) => {
  const manifest = buildLocalReleaseCandidateManifest(fixtureSnapshot())
  manifest.source.commit = 'f'.repeat(40)

  t.exception(() => verifyLocalReleaseManifestDigest(manifest), /digest mismatch/)
})

test('local release candidate manifest validates declared blocker identifiers', (t) => {
  t.alike(
    normalizeDeclaredBlockers(['Z_BLOCKER', 'A_BLOCKER', 'Z_BLOCKER']),
    ['A_BLOCKER', 'Z_BLOCKER']
  )
  t.exception(() => normalizeDeclaredBlockers(['not-safe']), /uppercase identifier/)
})

test('local release candidate manifest blocks when community-store source is not attached', (t) => {
  const snapshot = fixtureSnapshot()
  snapshot.communityStore = null
  const manifest = buildLocalReleaseCandidateManifest(snapshot)
  const binding = manifest.requiredExternalEvidence.find(item => item.id === 'community-umbrel-store-source-and-package-binding')

  t.is(manifest.appliances.communityStore.attached, false)
  t.ok(manifest.blockers.includes('COMMUNITY_UMBREL_STORE_NOT_BOUND'))
  t.is(binding.status, 'not-attached')
})

test('release workflow explicitly requests SBOM and max-mode provenance attestations', async (t) => {
  const workflow = await readFile('.github/workflows/release-surfaces.yml', 'utf8')
  t.ok(workflow.includes('--sbom=true'))
  t.ok(workflow.includes('--provenance=mode=max'))
  t.ok(workflow.includes('--platform linux/amd64,linux/arm64'))
})

function fixtureSnapshot () {
  const semver = '9.9.9'
  return {
    source: {
      repository: 'bigdestiny2/P2P-Hiverelay',
      commit: SOURCE_COMMIT,
      tree: SOURCE_TREE,
      describe: 'v9.9.9-0-gaaaaaaa',
      dirty: false,
      expectedVersionTag: 'v9.9.9',
      versionTagCommit: SOURCE_COMMIT,
      tagsAtSource: ['v9.9.9']
    },
    semver,
    publicPackages: [
      ['packages/core/package.json', 'p2p-hiverelay'],
      ['packages/client/package.json', 'p2p-hiverelay-client'],
      ['packages/verifier/package.json', 'p2p-hiverelay-verifier'],
      ['packages/services/package.json', 'p2p-hiveservices']
    ].map(([path, name]) => ({ path, name, version: semver })),
    blindPackages: [
      'blind-protocol',
      'blind-ipc',
      'blind-client',
      'blind-peercred',
      'blind-edge',
      'blind-daemon'
    ].map(name => ({
      path: `packages/${name}/package.json`,
      name: `@hiverelay/${name}`,
      version: '0.0.0-draft.1'
    })),
    appliances: {
      umbrel: {
        version: semver,
        imageRef: `ghcr.io/bigdestiny2/p2p-hiverelay:${semver}@${IMAGE_DIGEST}`,
        image: {
          ref: `ghcr.io/bigdestiny2/p2p-hiverelay:${semver}@${IMAGE_DIGEST}`,
          name: 'ghcr.io/bigdestiny2/p2p-hiverelay',
          tag: semver,
          digest: IMAGE_DIGEST
        },
        submission: 'https://github.com/getumbrel/umbrel-apps/pull/123'
      },
      startos: {
        id: 'blindspark',
        version: semver,
        packageFormat: 'startos-0.3.5.x',
        artifactName: 'blindspark.s9pk'
      }
    },
    fleetChannels: {
      stable: `v${semver}`,
      canary: `v${semver}`
    },
    build: {
      imageName: 'ghcr.io/bigdestiny2/p2p-hiverelay',
      platforms: ['linux/amd64', 'linux/arm64'],
      baseImages: [{ ref: `node:22-bookworm-slim@${BASE_DIGEST}`, digestPinned: true }],
      sbomConfigured: true,
      provenanceConfigured: true,
      splitSourceWorkflow: false
    },
    communityStore: {
      source: {
        repository: 'bigdestiny2/blindspark-umbrel-store',
        commit: '3'.repeat(40),
        tree: '4'.repeat(40),
        dirty: false
      },
      packageVersion: semver,
      umbrelVersion: semver,
      imageRef: `ghcr.io/bigdestiny2/p2p-hiverelay:${semver}@${IMAGE_DIGEST}`,
      image: {
        ref: `ghcr.io/bigdestiny2/p2p-hiverelay:${semver}@${IMAGE_DIGEST}`,
        name: 'ghcr.io/bigdestiny2/p2p-hiverelay',
        tag: semver,
        digest: IMAGE_DIGEST
      },
      inputs: [{
        path: 'package.json',
        bytes: 42,
        sha256: '5'.repeat(64),
        gitBlob: '6'.repeat(40)
      }]
    },
    inputs: [
      {
        path: 'package.json',
        bytes: 123,
        sha256: '1'.repeat(64),
        gitBlob: '2'.repeat(40)
      }
    ]
  }
}
