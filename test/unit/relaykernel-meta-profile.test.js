import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  RELAYKERNEL_META_DIRECTORY_TOPIC,
  RELAYKERNEL_META_KERNEL_CHANNELS,
  RELAYKERNEL_META_PROFILE_KIND,
  RELAYKERNEL_META_RESERVED_APP_CAPABILITIES,
  RELAYKERNEL_META_RESERVED_APP_CAPABILITY_PREFIXES,
  buildRelayKernelMetaProfile,
  validateRelayKernelMetaProfile
} from 'p2p-hiverelay/core/protocol/relaykernel-meta-profile.js'

const VECTOR_URL = new URL(
  '../fixtures/relaykernel-profile/relaykernel-meta-profile-v1-opt-in-directory.json',
  import.meta.url
)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function hex32 (byte) {
  return byte.repeat(32)
}

test('RelayKernel meta profile vector pins opt-in directory and layer-2 capability separation', async (t) => {
  const vector = await loadVector()
  const profile = buildRelayKernelMetaProfile(vector.input)
  const verdict = validateRelayKernelMetaProfile(profile)

  t.alike(profile, vector.profile, 'meta profile matches fixture')
  t.alike(verdict, vector.verdict, 'meta verdict matches fixture')
  t.is(profile.kind, RELAYKERNEL_META_PROFILE_KIND)
  t.is(profile.directory.topic, RELAYKERNEL_META_DIRECTORY_TOPIC)
  t.is(profile.directory.publicEnumerable, true, 'directory is enumerable only after opt-in')
  t.alike(profile.meta.kernelChannels, [...RELAYKERNEL_META_KERNEL_CHANNELS])
  t.alike(profile.meta.reservedAppCapabilityPrefixes, [...RELAYKERNEL_META_RESERVED_APP_CAPABILITY_PREFIXES])
  t.alike(profile.meta.reservedAppCapabilities, [...RELAYKERNEL_META_RESERVED_APP_CAPABILITIES])
  t.ok(profile.meta.advertisedCapabilities.includes('custody-v1'), 'app capability is advertised')
  t.absent(profile.meta.kernelChannels.includes('custody-v1'), 'app capability is not a kernel channel')
  t.is(profile.directory.record.domain.channel, 'rk-meta')
  t.is(profile.directory.record.domain.messageType, 'directory-record')
})

test('RelayKernel meta directory defaults to private and rejects supplied records without opt-in', (t) => {
  const profile = buildRelayKernelMetaProfile({
    relayPubkey: hex32('aa'),
    directoryRecord: { endpoint: 'relay.example:49737' }
  })
  const verdict = validateRelayKernelMetaProfile(profile)

  t.is(profile.directory.optIn, false)
  t.is(profile.directory.topic, null)
  t.is(profile.directory.publicEnumerable, false)
  t.is(profile.directory.record, null)
  t.is(profile.directory.providedRecordIgnored, true)
  t.absent(verdict.valid)
  t.ok(verdict.errors.includes('directory record supplied while opt-in is false'))
})

test('RelayKernel meta profile accepts private relays with separated app capabilities', (t) => {
  const profile = buildRelayKernelMetaProfile({
    relayPubkey: hex32('bb'),
    appCapabilities: [
      { name: 'custody-v1', channel: 'custody-v1', version: 1, owner: 'custody-app' }
    ]
  })
  const verdict = validateRelayKernelMetaProfile(profile)

  t.ok(verdict.valid, 'private non-enumerable profile is valid')
  t.is(profile.directory.publicEnumerable, false)
  t.ok(profile.meta.advertisedCapabilities.includes('custody-v1'))
  t.absent(profile.meta.kernelChannels.includes('custody-v1'))
  t.ok(verdict.warnings.includes('capability document is not signed'))
})

test('RelayKernel meta profile rejects app capabilities in kernel channel inventory', (t) => {
  const profile = buildRelayKernelMetaProfile({
    relayPubkey: hex32('cc'),
    kernelChannels: [...RELAYKERNEL_META_KERNEL_CHANNELS, 'custody-v1'],
    appCapabilities: [
      { name: 'custody-v1', channel: 'rk-seed', version: 1, owner: 'custody-app' }
    ]
  })
  const verdict = validateRelayKernelMetaProfile(profile)

  t.absent(verdict.valid)
  t.ok(verdict.errors.includes('non-kernel capability in kernelChannels: custody-v1'))
  t.ok(verdict.errors.includes('app capability channel collides with kernel channel: rk-seed'))
  t.ok(verdict.errors.includes('layer-2 capabilities are not separated from kernel channels'))
})

test('RelayKernel meta profile rejects app capabilities that squat on reserved kernel namespaces', (t) => {
  const profile = buildRelayKernelMetaProfile({
    relayPubkey: hex32('ee'),
    appCapabilities: [
      { name: 'rk-wallet', channel: 'wallet-v1', version: 1, owner: 'wallet-app' },
      { name: 'seed-request-v1', channel: 'wallet-v2', version: 1, owner: 'wallet-app' },
      { name: 'vault-v1', channel: 'hiverelay-forward', version: 1, owner: 'vault-app' },
      { name: 'witness-v1', channel: 't2-witness', version: 1, owner: 'witness-app' }
    ]
  })
  const verdict = validateRelayKernelMetaProfile(profile)

  t.absent(verdict.valid)
  t.absent(profile.meta.layer2CapabilitiesSeparated)
  t.ok(verdict.errors.includes('app capability name uses reserved kernel namespace: rk-wallet'))
  t.ok(verdict.errors.includes('app capability name uses reserved kernel namespace: seed-request-v1'))
  t.ok(verdict.errors.includes('app capability channel uses reserved kernel namespace: hiverelay-forward'))
  t.ok(verdict.errors.includes('app capability channel uses reserved kernel namespace: t2-witness'))
})

test('RelayKernel meta opt-in directory clamps announcement interval to ten minutes', (t) => {
  const profile = buildRelayKernelMetaProfile({
    relayPubkey: hex32('dd'),
    directoryOptIn: true,
    directoryRateLimitSeconds: 1,
    endpoint: 'relay.example:49737'
  })
  const verdict = validateRelayKernelMetaProfile(profile)

  t.is(profile.directory.rateLimitSeconds, 600)
  t.ok(verdict.valid)
})
