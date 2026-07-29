// Daemon release-gate smoke: proves the daemon image's own production release
// gate (assertProductionRuntimeReleaseReady) passes against a sealed vNext
// fixture for LIMITED_PUBLIC_TEST_V1. Run INSIDE the daemon image with the
// accepted test fixtures bind-mounted into the installed package:
//   docker run --rm --platform linux/<arch> \
//     -v $PWD/packages/blind-daemon/test:/opt/hiverelay/daemon/node_modules/@hiverelay/blind-daemon/test:ro \
//     -v $PWD/test:/opt/hiverelay/daemon/node_modules/test:ro \
//     -v $PWD/release/blind-public-test/smoke/release-gate-daemon.mjs:/tmp/release-gate-daemon.mjs:ro \
//     --entrypoint node hiverelay/blind-daemon:1.0.0-rc.1.public-test.1 /tmp/release-gate-daemon.mjs
const PKG = '/opt/hiverelay/daemon/node_modules/@hiverelay/blind-daemon'
const { vnextSealedFixture } = await import(`${PKG}/test/production-vnext-profile-fixture.js`)
const { assertProductionRuntimeReleaseReady } = await import(`${PKG}/production-runtime.js`)
const fixture = await vnextSealedFixture()
try {
  await assertProductionRuntimeReleaseReady(fixture.environment)
  console.log('DAEMON_RELEASE_GATE_PASS LIMITED_PUBLIC_TEST_V1', fixture.directory)
} catch (failure) {
  console.error('DAEMON_RELEASE_GATE_FAIL', failure && failure.message)
  process.exit(1)
}
