import test from 'brittle'
import fs from 'node:fs/promises'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  BASELINE_COMPLETENESS_EXCLUSIONS,
  PROFILE2_COMPLETENESS_EXCLUSIONS,
  PRODUCTION_RUNTIME_EXCLUSIONS,
  assertProductionRuntimeReleaseReady
} from '../production-runtime.js'
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

test('vNext gate genuinely assembles the baseline line and binding, scoped to baseline items', async t => {
  const fixture = await vnextSealedFixture()
  t.teardown(() => cleanup(fixture.directory))
  const error = await gateError(fixture.environment)
  t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', 'gate still fails closed while baseline exclusions remain')

  // Genuinely assembled and therefore cleared (validated by real code paths):
  // the profile/descriptor/identity binding, the CELL/INBOX/CORE public
  // execution line, the private content stream and the admission redemption
  // adapter are all wired by the profile and proven against the sealed fixture.
  for (const cleared of [LOCAL_BINDING, CELL_EXEC, INBOX_EXEC, CORE_EXEC, PRIVATE_STREAM, ADMISSION_ADAPTER]) {
    t.absent(error.message.includes(cleared), `${cleared} is genuinely assembled, not merely filtered`)
  }
  // Honestly still unassembled until their serving wiring is delivered: the
  // two-slot manifest floor and the persisted refresh floor keep the baseline
  // gate closed.
  for (const kept of [TWO_SLOT_MANIFEST, REFRESH_FLOOR]) {
    t.ok(error.message.includes(kept), `${kept} stays honestly unassembled`)
  }
  // FORWARD serving and the profile-2 journal witness are profile-2 items: out
  // of scope for the baseline, they never appear in its completeness set.
  for (const profile2 of [FORWARD_EXEC, PROFILE2_WITNESS]) {
    t.absent(error.message.includes(profile2), `${profile2} is profile-2 scoped, not a baseline item`)
  }
  // The baseline remaining set is exactly the two genuine blockers, nothing else.
  const listed = PRODUCTION_RUNTIME_EXCLUSIONS.filter(name => error.message.includes(name))
  t.alike(listed, [TWO_SLOT_MANIFEST, REFRESH_FLOOR], 'baseline remaining set is exactly #2/#3')
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

test('completeness scope is frozen: baseline never evaluates profile-2 items, even with FORWARD configured', async t => {
  // The frozen scope: baseline = the 8 baseline exclusions, never FORWARD or
  // the profile-2 witness; profile-2 = exactly those two.
  t.is(BASELINE_COMPLETENESS_EXCLUSIONS.length, 8)
  t.absent(BASELINE_COMPLETENESS_EXCLUSIONS.includes(FORWARD_EXEC))
  t.absent(BASELINE_COMPLETENESS_EXCLUSIONS.includes(PROFILE2_WITNESS))
  t.alike([...PROFILE2_COMPLETENESS_EXCLUSIONS], [FORWARD_EXEC, PROFILE2_WITNESS])

  // With no FORWARD material the baseline gate reports only the genuine #2/#3.
  const without = await vnextSealedFixture()
  t.teardown(() => cleanup(without.directory))
  t.is(loadVnextForwardConfig(without.environment), null, 'absent FORWARD material parses as unconfigured')
  const withoutError = await gateError(without.environment)
  t.alike(PRODUCTION_RUNTIME_EXCLUSIONS.filter(name => withoutError.message.includes(name)),
    [TWO_SLOT_MANIFEST, REFRESH_FLOOR], 'baseline reports exactly #2/#3 with no FORWARD material')

  // Even with a complete FORWARD storage identity configured, the baseline gate
  // still does not evaluate profile-2 items; its set stays exactly #2/#3.
  const withForward = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(withForward.directory))
  t.ok(loadVnextForwardConfig(withForward.environment), 'complete FORWARD storage identity parses')
  const withError = await gateError(withForward.environment)
  t.is(withError && withError.code, 'BLIND_RUNTIME_INCOMPLETE')
  t.absent(withError.message.includes(FORWARD_EXEC), 'FORWARD is never a baseline exclusion')
  t.absent(withError.message.includes(PROFILE2_WITNESS), 'profile-2 witness is never a baseline exclusion')
  t.alike(PRODUCTION_RUNTIME_EXCLUSIONS.filter(name => withError.message.includes(name)),
    [TWO_SLOT_MANIFEST, REFRESH_FLOOR], 'baseline reports exactly #2/#3 even with FORWARD configured')
})

test('the profile-2 acceptance profile stays fail-closed (static gate, FORWARD bits zero)', async t => {
  const fixture = await vnextSealedFixture({ forward: true })
  t.teardown(() => cleanup(fixture.directory))
  // Selecting the profile-2 one-hop FORWARD profile does not enter the baseline
  // path; it falls through to the strict static completeness gate and lists all
  // 10 shipped exclusions. FORWARD has no independent acceptance yet, so it can
  // never pass here.
  const environment = {
    ...fixture.environment,
    HIVERELAY_BLIND_RUNTIME_PROFILE: 'LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1'
  }
  const error = await gateError(environment)
  t.is(error && error.code, 'BLIND_RUNTIME_INCOMPLETE', 'profile-2 keeps the strict static gate')
  t.ok(error.message.includes(FORWARD_EXEC), 'profile-2 profile still lists FORWARD as unassembled')
  t.ok(error.message.includes(PROFILE2_WITNESS), 'profile-2 profile still lists the journal witness')
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
