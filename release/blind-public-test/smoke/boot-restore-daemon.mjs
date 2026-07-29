// FLEET-DURABILITY-P1-1 boot-restore smoke, run INSIDE the daemon image:
// expired genesis + middle chain links, intact sealed store, MAC-verified
// manifest floor at the fresh head -> the genuine production boot (release
// gate + assembly, no test seams) must restore from the floor and come up
// READY with zero baseline exclusions. Mirrors the accepted regression suite
// packages/blind-daemon/test/production-vnext-boot-restore.test.js scenario (a)
// without the brittle runner. Invocation: see release-gate-daemon.mjs header,
// same mounts plus this file at /tmp/boot-restore-daemon.mjs.
import fs from 'node:fs/promises'
const PKG = '/opt/hiverelay/daemon/node_modules/@hiverelay/blind-daemon'
const NM = '/opt/hiverelay/daemon/node_modules'
const b4a = (await import(`${NM}/b4a/index.js`)).default
const {
  blindServiceDescriptorV1,
  blake2b256,
  decodeCanonical
} = await import(`${NM}/@hiverelay/blind-protocol/index.js`)
const {
  BASELINE_COMPLETENESS_EXCLUSIONS,
  assembleProductionBlindDaemon,
  bindStoreIdentity,
  bootstrapVnextStoreGenerationFloor,
  encodeRuntimeBinding,
  loadProductionRuntimeConfig,
  productionReleaseGateFor
} = await import(`${PKG}/production-runtime.js`)
const {
  deriveVnextBucketMapHash,
  runVnextStoreGenesisCeremony
} = await import(`${PKG}/production-vnext-profile.js`)
const { loadDaemonBootstrapConfig } = await import(`${PKG}/bootstrap-config.js`)
const {
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} = await import(`${PKG}/production-entrypoint.js`)
const { vnextSealedFixture } = await import(`${PKG}/test/production-vnext-profile-fixture.js`)

const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000

function check (condition, message) {
  if (!condition) {
    console.error('BOOT_RESTORE_FAIL:', message)
    process.exit(1)
  }
}

const fixture = await vnextSealedFixture({
  functionalAdmission: true,
  chainWindows: [[-6, -2], [-4, -1], [-2, 2]]
})

let runtime = null
try {
  // Same bind -> store-genesis ceremony -> generation-floor bootstrap the
  // accepted serving e2e drives (manifest floor binds one exact chain head).
  const environment = fixture.environment
  const storeRoot = environment.HIVERELAY_BLIND_STORE_ROOT
  const manifestKey = await fs.readFile(environment.HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE)
  const ownerFenceTokenHash = await fs.readFile(environment.HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE)
  try {
    const descriptorCanonicalBytes = await fs.readFile(fixture.successorDescriptorFile)
    const descriptor = decodeCanonical(blindServiceDescriptorV1, descriptorCanonicalBytes, { copyBytes: true })
    const mapGeneration = 1n
    const binding = encodeRuntimeBinding(descriptor, mapGeneration, ownerFenceTokenHash, manifestKey)
    await bindStoreIdentity(storeRoot, binding)
    await runVnextStoreGenesisCeremony({
      storeRoot,
      descriptor,
      descriptorCanonicalBytes,
      manifestKey,
      ownerFenceTokenHash,
      partitionKey: blake2b256(b4a.concat([
        b4a.from('hiverelay.blind.partition-key.v1', 'ascii'), descriptor.storeId, manifestKey])),
      bucketMapHash: deriveVnextBucketMapHash(descriptor.storeId, mapGeneration),
      mapGeneration
    })
    await bootstrapVnextStoreGenerationFloor({
      storeRoot, descriptor, manifestKey, ownerFenceTokenHash, mapGeneration
    })
  } finally {
    manifestKey.fill(0)
    ownerFenceTokenHash.fill(0)
  }

  // Drill preconditions: genesis AND middle links expired, head inside window.
  const nowEpoch = Math.floor(Date.now() / SIX_HOURS_MILLIS)
  const genesis = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(fixture.chainFiles[0]))
  const middle = decodeCanonical(blindServiceDescriptorV1, await fs.readFile(fixture.chainFiles[1]))
  check(genesis.expiresEpoch <= nowEpoch, 'precondition failed: genesis link not expired')
  check(middle.expiresEpoch <= nowEpoch, 'precondition failed: middle link not expired')

  // Genuine production boot, exactly as cli.js assembles the vNext profile.
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const entrypointConfig = loadProductionEntrypointConfig(environment)
  const productionAdmission = await loadProductionAdmissionAdapter(entrypointConfig, bootstrap)
  runtime = await assembleProductionBlindDaemon({
    bootstrap,
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    releaseGate: productionReleaseGateFor(environment),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: input => productionAdmission.resolveAdmissionAdapter(input),
    requireCompleteAdmissionCapture: true,
    requireManifestFloor: true
  })

  const status = runtime.status()
  check(status.descriptorRestoredFromFloor === true, 'boot did not restore from the MAC-verified floor')
  check(status.descriptorSequence === 2n, `restored head is not the chain head (got ${status.descriptorSequence})`)
  check(b4a.equals(status.descriptorHash, fixture.chainHashes[2]), 'restored descriptor hash mismatch')
  check(status.manifestFloor.descriptorSequenceFloor === 2n, 'manifest floor is not the chain head')
  check(b4a.equals(status.manifestFloor.descriptorHashFloor, fixture.chainHashes[2]), 'manifest floor hash mismatch')
  check(status.storage.state === 'READY', `store not READY (got ${status.storage.state})`)
  const surviving = BASELINE_COMPLETENESS_EXCLUSIONS.filter(name => status.exclusions.includes(name))
  check(surviving.length === 0, `baseline exclusions survived: ${surviving.join(',')}`)
  console.log('BOOT_RESTORE_PASS FLEET-DURABILITY-P1-1 restored-from-floor head=seq2 store=READY zero-baseline-exclusions', fixture.directory)
} finally {
  if (runtime) await runtime.close().catch(() => {})
  await fs.rm(fixture.directory, { recursive: true, force: true }).catch(() => {})
}
