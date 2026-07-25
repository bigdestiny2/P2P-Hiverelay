import test from 'brittle'
import fs from 'node:fs/promises'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { PRODUCTION_RUNTIME_EXCLUSIONS, assertProductionRuntimeReleaseReady } from '../production-runtime.js'
import { loadVnextForwardConfig } from '../production-vnext-profile.js'
import { vnextSealedFixture } from './production-vnext-profile-fixture.js'

const [
  LOCAL_BINDING,
  TWO_SLOT_MANIFEST,
  REFRESH_FLOOR,
  CELL_EXEC,
  INBOX_EXEC,
  CORE_EXEC,
  FORWARD_EXEC,
  PRIVATE_STREAM,
  ADMISSION_ADAPTER,
  PROFILE2_WITNESS
] = PRODUCTION_RUNTIME_EXCLUSIONS

async function cleanup (directory) {
  await fs.rm(directory, { recursive: true, force: true }).catch(() => {})
}

async function gateError (environment) {
  let error = null
  try {
    await assertProductionRuntimeReleaseReady(environment)
  } catch (failure) {
    error = failure
  }
  return error
}

test('vNext gate genuinely assembles the runtime line and binding, honestly keeps the rest', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', 'gate still fails closed while exclusions remain')

  // Genuinely assembled and therefore cleared (validated by real code paths):
  // the profile/descriptor/identity binding, the CELL/INBOX/CORE public
  // execution line, the private content stream and the admission redemption
  // adapter are all wired by the profile and proven against the sealed fixture.
  for (const cleared of [LOCAL_BINDING, CELL_EXEC, INBOX_EXEC, CORE_EXEC, PRIVATE_STREAM, ADMISSION_ADAPTER]) {
    t.absent(error.message.includes(cleared), `${cleared} is genuinely assembled, not merely filtered`)
  }
  // Honestly still unassembled until their serving wiring is delivered: the
  // two-slot manifest floor, the persisted refresh floor, the bounded FORWARD
  // class and the profile-2 external journal witness keep the gate closed.
  for (const kept of [TWO_SLOT_MANIFEST, REFRESH_FLOOR, FORWARD_EXEC, PROFILE2_WITNESS]) {
    t.ok(error.message.includes(kept), `${kept} stays honestly unassembled`)
  }
})

test('vNext gate fails closed on a forged relay identity binding', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  // Replace the sealed relay secret with a different key: the descriptor no
  // longer matches, so FINAL_BUILD_PROFILE_LOCAL_BINDING must fail closed.
  const forgedSecret = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES, 0x5a)
  await fs.writeFile(fixture.environment.HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE, forgedSecret, { mode: 0o600 })
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_RUNTIME_SIGNING_KEY_MISMATCH')
})

test('vNext gate fails closed on a descriptor outside the baseline public-test mask', async t => {
  // A descriptor that does not carry exactly the baseline 0x0001ffff mask
  // (here narrowed to the DESCRIBE-only bits) is refused by the binding check:
  // the public-test profile requires the full baseline and never a FORWARD bit.
  const narrowed = await vnextSealedFixture({ operationBits: 0x00000007 })
  t.teardown(() => cleanup(narrowed.directory))
  const narrowedError = await gateError(narrowed.environment)
  t.is(narrowedError && narrowedError.code, 'BLIND_RUNTIME_DESCRIPTOR_UNSUPPORTED')

  // A durability profile-2 descriptor cannot even be constructed without its
  // nonzero external journal witness topology: the sealed public-test material
  // carries no profile-2 witness, so the profile genuinely stays profile 1.
  let buildError = null
  try {
    await vnextSealedFixture({ durabilityProfileId: 2 })
  } catch (failure) {
    buildError = failure
  }
  t.ok(buildError != null, 'profile-2 descriptor demands an external journal witness tuple')
  t.ok(/external journal/.test(buildError.message), 'profile-2 witness topology is genuinely absent')
})

test('vNext gate fails closed when the admission adapter script is unconfigured', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  delete fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE
  delete fixture.environment.HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256
  // A CELL-line profile requires the sealed adapter script; its absence is a
  // fail-closed entrypoint config error before any exclusion list is computed.
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID',
    'unconfigured redemption adapter is refused fail-closed')
})

test('non-vNext profiles keep the strict static completeness gate', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  for (const profile of ['DESCRIBE_ONLY_V1', 'CELL_V1', 'CELL_INBOX_V1', 'CELL_INBOX_CORE_V1']) {
    const environment = { ...fixture.environment, HIVERELAY_BLIND_RUNTIME_PROFILE: profile }
    const error = await gateError(environment)
    t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', `${profile} keeps the static gate`)
    t.ok(error.message.includes(LOCAL_BINDING), `${profile} still lists every shipped exclusion`)
    t.ok(error.message.includes(PROFILE2_WITNESS), `${profile} lists all 10 shipped exclusions`)
  }
})

test('configuring the bounded FORWARD class clears its exclusion at the gate', async t => {
  const without = await vnextSealedFixture()
  t.teardown(() => cleanup(without.directory))
  t.is(loadVnextForwardConfig(without.environment), null, 'absent FORWARD material is not assembled')

  const withForward = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(withForward.directory))
  const forwardConfig = loadVnextForwardConfig(withForward.environment)
  t.ok(forwardConfig && forwardConfig.storage && typeof forwardConfig.storage.root === 'string',
    'complete FORWARD storage identity parses')
  const error = await gateError(withForward.environment)
  t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE')
  t.absent(error.message.includes(FORWARD_EXEC), 'configured FORWARD class is assembled')
  t.absent(error.message.includes(PROFILE2_WITNESS), 'FORWARD journal witness is assembled with the class')
  t.ok(error.message.includes(TWO_SLOT_MANIFEST), 'manifest floor still honestly unassembled')
  t.ok(error.message.includes(REFRESH_FLOOR), 'refresh floor still honestly unassembled')
})

test('a half-configured FORWARD class fails closed instead of assembling partially', async t => {
  const fixture = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(fixture.directory))
  delete fixture.environment.HIVERELAY_BLIND_FORWARD_ATREST_KEY_FILE
  let error = null
  try {
    loadVnextForwardConfig(fixture.environment)
  } catch (failure) {
    error = failure
  }
  t.is(error && error.code, 'BLIND_VNEXT_FORWARD_CONFIG_INVALID')
})
