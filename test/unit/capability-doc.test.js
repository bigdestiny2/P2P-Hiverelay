import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { buildCapabilityDoc, verifyCapabilityDoc, CAPABILITY_DOC_SCHEMA_VERSION } from 'p2p-hiverelay/core/capability-doc.js'
import {
  RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
  RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
  RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND,
  RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
  RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
  RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS
} from 'p2p-hiverelay/core/protocol/relaykernel-circuit-limits-profile.js'

function makeKeyPair () {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

// We test buildCapabilityDoc purely — no swarm, no HTTP server, no
// filesystem. The builder accepts a partial relay-shaped object, so every
// test constructs just enough to exercise one branch.

test('builds with no relay at all (safe default)', async (t) => {
  const doc = buildCapabilityDoc({})
  t.is(doc.schemaVersion, CAPABILITY_DOC_SCHEMA_VERSION)
  t.is(doc.name, null)
  t.is(doc.pubkey, null)
  t.is(doc.software, 'https://github.com/bigdestiny2/p2p-hiverelay')
  t.ok(Array.isArray(doc.supported_transports))
  t.ok(Array.isArray(doc.features))
  t.ok(doc.features.includes('capability-doc'), 'always advertises capability-doc feature')
  t.is(doc.limitation.accept_mode, 'review', 'default mode is review when no config')
  t.is(doc.federation, null)
  t.is(doc.catalog, null)
  t.is(doc.fees, null)
})

test('extracts accept_mode + limits from relay config', async (t) => {
  const relay = {
    config: {
      acceptMode: 'allowlist',
      maxPendingRequests: 5000,
      maxConnections: 256,
      maxStorageBytes: 50 * 1024 * 1024 * 1024,
      maxRelayBandwidthMbps: 100,
      regions: ['eu-west-1']
    }
  }
  const doc = buildCapabilityDoc({ relay, version: '0.5.1' })
  t.is(doc.version, '0.5.1')
  t.is(doc.region, 'eu-west-1')
  t.is(doc.limitation.accept_mode, 'allowlist')
  t.is(doc.limitation.max_pending_requests, 5000)
  t.is(doc.limitation.max_connections, 256)
  t.is(doc.limitation.max_storage_bytes, 50 * 1024 * 1024 * 1024)
  t.is(doc.limitation.max_relay_bandwidth_mbps, 100)
})

test('detects transports from runtime state', async (t) => {
  const relay = {
    config: {
      discovery: { dht: true, mdns: true }
    },
    dhtRelayWs: { running: true },
    torTransport: { running: true },
    holesailTransport: {}
  }
  const doc = buildCapabilityDoc({ relay })
  t.ok(doc.supported_transports.includes('hyperswarm'))
  t.ok(doc.supported_transports.includes('mdns'))
  t.ok(doc.supported_transports.includes('dht-relay-ws'))
  t.ok(doc.supported_transports.includes('tor'))
  t.ok(doc.supported_transports.includes('holesail'))
})

test('features list is sorted and reflects wired subsystems', async (t) => {
  const relay = {
    config: {},
    federation: {},
    _checkDelegation: () => {},
    _revokedCertSignatures: new Map(),
    seedingRegistry: {},
    reputation: {}
  }
  const doc = buildCapabilityDoc({ relay })
  const sorted = [...doc.features].sort()
  t.alike(doc.features, sorted, 'features sorted alphabetically')
  t.ok(doc.features.includes('federation'))
  t.ok(doc.features.includes('delegation-certs'))
  t.ok(doc.features.includes('delegation-revocation'))
  t.ok(doc.features.includes('seeding-registry'))
  t.ok(doc.features.includes('reputation'))
  t.ok(doc.features.includes('capability-doc'))
  t.ok(doc.features.includes('seed-signature-domain-v3'))
  t.is(doc.protocol_profile.signature_domains.seed_request.preferred, 'hiverelay.seed-request.v3')
  t.alike(doc.protocol_profile.signature_domains.seed_request.accepted, [
    'hiverelay.seed-request.v3',
    'hiverelay.seed-request.replay-v1',
    'legacy-v2',
    'legacy-v1'
  ])
  t.is(doc.protocol_profile.signature_domains.seed_request.replay_protection.domain, 'hiverelay.seed-request.replay-v1')
})

test('capability doc advertises notify and outboxlog service profiles when running', async (t) => {
  const relay = {
    config: { enableServices: true },
    serviceRegistry: {
      services: new Map([
        ['notify', { status: 'running', version: '0.1.0' }],
        ['outboxlog', { status: 'running', version: '0.1.0' }]
      ]),
      catalog: () => [
        { name: 'notify', version: '0.1.0' },
        { name: 'outboxlog', version: '0.1.0' }
      ]
    }
  }

  const doc = buildCapabilityDoc({ relay })
  t.ok(doc.features.includes('notify-v1'))
  t.ok(doc.features.includes('outboxlog-v1'))
  t.is(doc.protocol_profile.services.notify.version, '0.1.0')
  t.is(doc.protocol_profile.services.notify.payload.plaintext_allowed, false)
  t.is(doc.protocol_profile.services.outboxlog.model, 'single-writer-signed-outbox')
})

test('relaykernel capability doc advertises only active kernel-compatible surfaces', async (t) => {
  const kp = makeKeyPair()
  const relay = {
    mode: 'relaykernel',
    config: {
      productProfile: 'relaykernel',
      enableRelay: true,
      enableSeeding: true,
      enableAPI: true,
      enableServices: false,
      custody: { enabled: false },
      federation: { enabled: false },
      signedDirectory: { enabled: false },
      lease: { enabled: false },
      subsidy: { enabled: false },
      payment: { enabled: false },
      fees: { storage: 1 }
    },
    swarm: { keyPair: kp },
    appRegistry: { catalog: () => [] },
    federation: { snapshot: () => ({ followed: [{ url: 'https://relay.example' }] }) },
    serviceRegistry: { catalog: () => [{ name: 'identity' }] },
    paymentManager: { paymentProvider: {} },
    _signedDirectory: { getStats: () => ({ entries: 1 }) },
    _publishProtocol: {},
    relay: {
      maxCircuitDuration: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      maxCircuitBytes: RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
      maxCircuitsPerPeer: RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
      maxCircuitRateBytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
      recordCircuitBytes () {}
    },
    _circuitRelay: {
      maxCircuitDuration: RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS,
      maxCircuitBytes: RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP,
      maxCircuitsPerPeer: RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP,
      maxCircuitRateBytesPerSecond: RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS,
      maxDataMsgBytes: RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP,
      _maxPendingConnects: 100,
      _maxReservesPerMin: 5
    },
    createAccountingReceipt () {}
  }

  const doc = buildCapabilityDoc({ relay, runtime: 'node' })
  t.ok(verifyCapabilityDoc(doc).valid, 'signed relaykernel doc verifies')
  t.is(doc.protocol_profile.name, 'relaykernel')
  t.is(doc.protocol_profile.relaykernel_compatible, true)
  t.ok(doc.protocol_profile.kernel_surfaces.includes('proof-of-retrievability'))
  t.ok(doc.protocol_profile.kernel_surfaces.includes('accounting-receipts'))
  t.alike(doc.protocol_profile.app_surfaces, [])
  t.ok(doc.features.includes('retrievability-proof-http'))
  t.ok(doc.features.includes('retrievability-proof-domain-v1'))
  t.ok(doc.features.includes('accounting-receipts'))
  t.ok(doc.features.includes('seed-signature-domain-v3'))
  t.ok(doc.features.includes('circuit-limits-profile-v1'))
  t.is(doc.protocol_profile.circuit_limits.kind, RELAYKERNEL_CIRCUIT_LIMITS_PROFILE_KIND)
  t.is(doc.protocol_profile.circuit_limits.verdict.valid, true)
  t.is(doc.protocol_profile.circuit_limits.limits.maxSessionMs, RELAYKERNEL_CIRCUIT_SESSION_HARD_CAP_MS)
  t.is(doc.protocol_profile.circuit_limits.limits.maxBytes, RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP)
  t.is(doc.protocol_profile.circuit_limits.limits.maxCircuitsPerPeer, RELAYKERNEL_CIRCUIT_MAX_PER_PEER_HARD_CAP)
  t.is(doc.protocol_profile.circuit_limits.limits.maxFrameBytes, RELAYKERNEL_CIRCUIT_FRAME_HARD_CAP)
  t.is(doc.protocol_profile.circuit_limits.limits.rateCapBytesPerSecond, RELAYKERNEL_CIRCUIT_RECOMMENDED_RATE_CAP_BPS)
  t.is(doc.protocol_profile.circuit_limits.limitChecks.pendingConnectsBounded, true)
  t.is(doc.protocol_profile.circuit_limits.securityChecks.silentDropUnknownCircuit, true)
  t.is(doc.protocol_profile.signature_domains.seed_request.preferred, 'hiverelay.seed-request.v3')
  t.is(doc.protocol_profile.signature_domains.seed_request.legacy_accepted, true)
  t.is(doc.protocol_profile.signature_domains.seed_request.replay_protection.nonce_bytes, 16)
  t.is(doc.protocol_profile.signature_domains.seed_request.replay_protection.replay_window_ms, 60 * 60 * 1000)
  t.is(doc.protocol_profile.signature_domains.retrievability_proof.preferred, 'hiverelay.retrievability-proof.v1')
  t.alike(doc.protocol_profile.signature_domains.retrievability_proof.signature_profiles, [
    'retrievability-proof-v1',
    'storage-proof-legacy-v1'
  ])
  t.is(doc.protocol_profile.signature_domains.retrievability_proof.http_opt_in, true)
  t.absent(doc.features.includes('federation'))
  t.absent(doc.features.includes('publish-channel-v1'))
  t.is(doc.federation, null)
  t.is(doc.limitation.payment_required, false)
  t.is(doc.fees, null)
  t.is(doc.directory_privacy.mode, 'relaykernel-private')
  t.is(doc.directory_privacy.global_enumerable, false)
  t.is(doc.directory_privacy.relaykernel_private_by_default, true)
  t.is(doc.directory_privacy.signed_directory_enabled, false)
})

test('directory_privacy distinguishes public catalog from global directory opt-in', async (t) => {
  const doc = buildCapabilityDoc({
    relay: {
      config: {},
      appRegistry: { catalog: () => [] }
    },
    gatewayUrl: 'https://relay.example',
    indexRoom: 'pear://index-room'
  })

  t.is(doc.directory_privacy.mode, 'catalog-public')
  t.is(doc.directory_privacy.catalog_public, true)
  t.is(doc.directory_privacy.gateway_url_advertised, true)
  t.is(doc.directory_privacy.index_room_advertised, true)
  t.is(doc.directory_privacy.global_enumerable, false)
  t.is(doc.directory_privacy.global_enumerable_reason, null)
})

test('directory_privacy marks signed-directory as explicit global opt-in', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({
    relay: {
      config: {},
      swarm: { keyPair: kp },
      _signedDirectory: { getStats: () => ({ entries: 1 }) }
    }
  })

  t.is(doc.directory_privacy.mode, 'global-directory-opt-in')
  t.is(doc.directory_privacy.global_enumerable, true)
  t.is(doc.directory_privacy.global_enumerable_reason, 'signed-directory-enabled')
  t.is(doc.directory_privacy.signed_directory_enabled, true)
  t.ok(verifyCapabilityDoc(doc).valid, 'directory privacy posture is signed')

  doc.directory_privacy.global_enumerable = false
  t.absent(verifyCapabilityDoc(doc).valid, 'tampering directory posture invalidates signature')
})

test('federation snapshot is summarized, not leaked', async (t) => {
  const relay = {
    config: {},
    federation: {
      snapshot: () => ({
        followed: [{ url: 'http://a' }, { url: 'http://b' }],
        mirrored: [{ url: 'http://c' }],
        republished: []
      })
    }
  }
  const doc = buildCapabilityDoc({ relay })
  t.alike(doc.federation, { followed: 2, mirrored: 1, republished: 0 })
})

test('federation snapshot failure is tolerated (null not throw)', async (t) => {
  const relay = {
    config: {},
    federation: {
      snapshot: () => { throw new Error('boom') }
    }
  }
  const doc = buildCapabilityDoc({ relay })
  t.is(doc.federation, null)
})

test('catalog counts are computed from appRegistry.catalog()', async (t) => {
  const relay = {
    config: {},
    appRegistry: {
      catalog: () => [
        { type: 'app' },
        { type: 'app' },
        { type: 'drive' },
        { type: 'drive', parentKey: 'pk1' },
        { type: 'dataset' },
        { type: 'media' }
      ]
    }
  }
  const doc = buildCapabilityDoc({ relay })
  t.is(doc.catalog.total, 6)
  t.is(doc.catalog.apps, 2)
  t.is(doc.catalog.drives, 1)
  t.is(doc.catalog.resources, 1)
  t.is(doc.catalog.datasets, 1)
  t.is(doc.catalog.media, 1)
})

test('payment_required flips when paymentProvider is set', async (t) => {
  const docWithout = buildCapabilityDoc({ relay: { config: {} } })
  t.is(docWithout.limitation.payment_required, false)
  const docWith = buildCapabilityDoc({
    relay: {
      config: {},
      paymentManager: { paymentProvider: {} }
    }
  })
  t.is(docWith.limitation.payment_required, true)
})

test('operator metadata flows through when provided', async (t) => {
  const doc = buildCapabilityDoc({
    relay: { config: {} },
    name: 'HiveRelay NYC',
    description: 'Public relay for NYC users',
    contact: 'mailto:admin@example.com',
    termsOfService: 'https://example.com/tos',
    icon: 'https://example.com/icon.png'
  })
  t.is(doc.name, 'HiveRelay NYC')
  t.is(doc.description, 'Public relay for NYC users')
  t.is(doc.contact, 'mailto:admin@example.com')
  t.is(doc.terms_of_service, 'https://example.com/tos')
  t.is(doc.icon, 'https://example.com/icon.png')
})

test('explicit runtime override respected', async (t) => {
  const doc = buildCapabilityDoc({ relay: { config: {} }, runtime: 'bare' })
  t.is(doc.runtime, 'bare')
})

// ─── Signature tests (Concern 4 fix) ──────────────────────────────

test('builder signs the doc when relay has a swarm.keyPair', async (t) => {
  const kp = makeKeyPair()
  const relay = {
    config: {},
    swarm: { keyPair: kp }
  }
  const doc = buildCapabilityDoc({ relay })
  t.ok(doc.signature, 'signature attached')
  t.is(doc.signature.v, 1)
  t.is(doc.signature.sig.length, 128, '64-byte hex signature')
  t.is(doc.pubkey, b4a.toString(kp.publicKey, 'hex'), 'pubkey matches signing key')
})

test('builder ships unsigned doc when no secret key is available', async (t) => {
  const doc = buildCapabilityDoc({ relay: { config: {} } })
  t.absent(doc.signature, 'no secret key → no signature')
})

test('verifyCapabilityDoc accepts a freshly-signed doc', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp } } })
  const check = verifyCapabilityDoc(doc)
  t.ok(check.valid)
})

test('verifyCapabilityDoc rejects unsigned doc', async (t) => {
  const doc = buildCapabilityDoc({ relay: { config: {} } })
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
  t.ok(check.reason.includes('no signature'))
})

test('onionGatewayUrl uses the ready onion read vport, and the doc still verifies', async (t) => {
  const kp = makeKeyPair()
  const relay = {
    config: { apiPort: 9100 },
    swarm: { keyPair: kp },
    torTransport: {
      running: true,
      health: 'ready',
      onionAddress: 'abcdefghijklmnop.onion',
      clientAuthKeys: [],
      _effectiveVports: () => [{ vport: 80, targetPort: 9100 }]
    }
  }
  const doc = buildCapabilityDoc({ relay })
  t.is(doc.onionGatewayUrl, 'http://abcdefghijklmnop.onion', 'external vport 80, not local target 9100, is advertised')
  t.ok(doc.supported_transports.includes('tor'))
  // The new field must not break signing/verification (it is covered by the
  // canonical signer, so an old verifier running the same logic still validates).
  t.ok(verifyCapabilityDoc(doc).valid, 'signed doc with onion field verifies')
})

test('onionGatewayUrl is health-gated and preserves a non-default read vport', async (t) => {
  const kp = makeKeyPair()
  const torTransport = {
    running: true,
    health: 'degraded',
    onionAddress: 'abcdefghijklmnop.onion',
    clientAuthKeys: [],
    _effectiveVports: () => [{ vport: 8080, targetPort: 9100 }]
  }
  const degraded = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp }, torTransport } })
  t.is(degraded.onionGatewayUrl, null, 'degraded onion ingress is not advertised')

  torTransport.health = 'ready'
  const ready = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp }, torTransport } })
  t.is(ready.onionGatewayUrl, 'http://abcdefghijklmnop.onion:8080')
  t.ok(verifyCapabilityDoc(ready).valid)
})

test('onionGatewayUrl is null when Tor is not running', async (t) => {
  const doc = buildCapabilityDoc({ relay: { config: { apiPort: 9100 }, swarm: { keyPair: makeKeyPair() } } })
  t.is(doc.onionGatewayUrl, null)
  t.ok(verifyCapabilityDoc(doc).valid)
})

test('verifyCapabilityDoc detects field tampering', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: { acceptMode: 'review' }, swarm: { keyPair: kp } } })
  // Tamper a field after signing
  doc.limitation.accept_mode = 'open'
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
  t.is(check.reason, 'signature verification failed')
})

test('verifyCapabilityDoc detects seed signature domain tampering', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp } } })
  doc.protocol_profile.signature_domains.seed_request.preferred = 'legacy-v2'
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
  t.is(check.reason, 'signature verification failed')
})

test('verifyCapabilityDoc detects retrievability proof signature profile tampering', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({
    relay: {
      config: {},
      appRegistry: { catalog: () => [] },
      swarm: { keyPair: kp }
    },
    runtime: 'node'
  })
  doc.protocol_profile.signature_domains.retrievability_proof.signature_profiles.push('unsafe-profile')
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
  t.is(check.reason, 'signature verification failed')
})

test('verifyCapabilityDoc detects circuit limit posture tampering', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({
    relay: {
      config: {},
      appRegistry: { catalog: () => [] },
      swarm: { keyPair: kp }
    },
    runtime: 'node'
  })
  t.is(doc.protocol_profile.circuit_limits.verdict.valid, true, 'fixture starts with a valid circuit limit profile')
  doc.protocol_profile.circuit_limits.limits.maxBytes = RELAYKERNEL_CIRCUIT_BYTES_HARD_CAP + 1
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
  t.is(check.reason, 'signature verification failed')
})

test('verifyCapabilityDoc detects pubkey tampering', async (t) => {
  const kp = makeKeyPair()
  const other = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp } } })
  doc.pubkey = b4a.toString(other.publicKey, 'hex')
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid)
})

test('verify survives JSON roundtrip (real over-the-wire scenario)', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp } } })
  const roundtripped = JSON.parse(JSON.stringify(doc))
  const check = verifyCapabilityDoc(roundtripped)
  t.ok(check.valid, 'JSON roundtrip preserves signature validity')
})

test('verifyCapabilityDoc rejects malformed inputs gracefully', async (t) => {
  t.absent(verifyCapabilityDoc(null).valid)
  t.absent(verifyCapabilityDoc({}).valid)
  t.absent(verifyCapabilityDoc({ signature: { v: 1, sig: 'not-hex' }, pubkey: 'a'.repeat(64) }).valid)
  t.absent(verifyCapabilityDoc({ signature: { v: 999, sig: 'a'.repeat(128) }, pubkey: 'a'.repeat(64) }).valid)
})

// ─── attestedAt timestamp tests (closes stale-doc replay) ─────────

test('builder includes attestedAt timestamp', async (t) => {
  const before = Date.now()
  const doc = buildCapabilityDoc({ relay: { config: {} } })
  const after = Date.now()
  t.ok(typeof doc.attestedAt === 'number')
  t.ok(doc.attestedAt >= before && doc.attestedAt <= after)
})

test('attestedAt is covered by the signature', async (t) => {
  const kp = makeKeyPair()
  const doc = buildCapabilityDoc({ relay: { config: {}, swarm: { keyPair: kp } } })
  // Tamper with attestedAt only
  doc.attestedAt = doc.attestedAt - 1000
  const check = verifyCapabilityDoc(doc)
  t.absent(check.valid, 'tampering attestedAt invalidates signature')
})

test('verifyCapabilityDoc freshness window rejects stale signed docs when requested', async (t) => {
  const kp = makeKeyPair()
  const now = 1782753600000
  const doc = buildCapabilityDoc({
    relay: { config: {}, swarm: { keyPair: kp } },
    attestedAt: now - 10 * 60 * 1000
  })

  t.ok(verifyCapabilityDoc(doc).valid, 'default verification remains signature-only')
  t.ok(verifyCapabilityDoc(doc, { now, maxAgeMs: 15 * 60 * 1000 }).valid, 'fresh enough doc verifies')

  const stale = verifyCapabilityDoc(doc, { now, maxAgeMs: 5 * 60 * 1000 })
  t.absent(stale.valid, 'stale signed doc fails under strict freshness')
  t.is(stale.reason, 'capability doc attestation expired')
})

test('verifyCapabilityDoc freshness window rejects future attestations beyond skew', async (t) => {
  const kp = makeKeyPair()
  const now = 1782753600000
  const doc = buildCapabilityDoc({
    relay: { config: {}, swarm: { keyPair: kp } },
    attestedAt: now + 10 * 60 * 1000
  })

  const future = verifyCapabilityDoc(doc, {
    now,
    requireFresh: true,
    maxAgeMs: 60 * 60 * 1000,
    maxFutureSkewMs: 5 * 60 * 1000
  })
  t.absent(future.valid, 'future signed doc fails beyond skew')
  t.is(future.reason, 'capability doc attestation too far in future')
})

test('opts.attestedAt override works for deterministic tests', async (t) => {
  const fixedTime = 1729571234000
  const doc = buildCapabilityDoc({ relay: { config: {} }, attestedAt: fixedTime })
  t.is(doc.attestedAt, fixedTime)
})

// --- privacyTransports (hiverelay.onion/1, RA-03) ---

function relayWithTor (torTransport, config = {}) {
  return {
    config: { custody: { enabled: true }, tor: {}, ...config },
    serviceRegistry: { services: new Map() },
    torTransport
  }
}

function readyTor (overrides = {}) {
  return {
    running: true,
    health: 'ready',
    onionAddress: 'b'.repeat(56) + '.onion',
    startedAtMs: 1784323200000,
    endpointKeyId: null,
    rosterFile: null,
    clientAuthKeys: [],
    pow: null,
    ...overrides
  }
}

test('privacyTransports — omitted without tor transport (signable shape preserved)', async (t) => {
  const doc = buildCapabilityDoc({ relay: { config: {} } })
  t.is(doc.privacyTransports, undefined)
  t.absent('privacyTransports' in doc)
  t.absent(doc.features.includes('privacy-transports-v1'))
})

test('privacyTransports — health-gated: omitted unless ready', async (t) => {
  for (const health of ['tor-starting', 'key-loaded', 'descriptor-uploaded', 'degraded']) {
    const doc = buildCapabilityDoc({ relay: relayWithTor(readyTor({ health })) })
    t.absent('privacyTransports' in doc, `health=${health} must not advertise`)
    t.is(doc.onionGatewayUrl, null, `health=${health} must not advertise an onion gateway URL`)
  }
})

test('privacyTransports — ready onion entry shape and labels', async (t) => {
  const doc = buildCapabilityDoc({ relay: relayWithTor(readyTor({ endpointKeyId: 'onion-2026-07-a' })) })
  t.is(doc.privacyTransports.length, 1)
  t.ok(doc.features.includes('privacy-transports-v1'))
  const entry = doc.privacyTransports[0]
  t.is(entry.id, 'tor-v3-onion-v1')
  t.is(entry.network, 'tor')
  t.is(entry.protocol, 'hiverelay.onion/1')
  t.is(entry.relayLocation, 'hidden-onion')
  t.is(entry.exposure, 'dual')
  t.is(entry.addresses.length, 1)
  t.is(entry.addresses[0].address, 'b'.repeat(56) + '.onion')
  t.is(entry.addresses[0].keyId, 'onion-2026-07-a')
  t.is(entry.addresses[0].notBefore, 1784323200000)
  t.is(entry.addresses[0].notAfter, 1784323200000 + 90 * 24 * 60 * 60 * 1000)
  t.is(entry.addresses[0].priority, 10)
  t.alike(entry.vports, [80])
  t.is(entry.vportRoles.readPlane, 80)
  t.is(entry.auth.mode, 'none')
  t.is(entry.pow.enabled, false)
  t.ok(entry.supports.includes('catalog.read'))
  t.ok(entry.supports.includes('replication.sync'))
  t.ok(entry.supports.includes('custody.commit'))
  t.absent(entry.supports.includes('notify.send')) // no notify service in stub
})

test('privacyTransports — client-auth mode from roster/keys; custody off drops custody kinds', async (t) => {
  const withRoster = buildCapabilityDoc({ relay: relayWithTor(readyTor({ rosterFile: '/x/roster.json' })) })
  t.is(withRoster.privacyTransports[0].auth.mode, 'client-auth-v3')
  t.alike(withRoster.privacyTransports[0].auth.enrollment, ['pairing-channel'])

  const withKeys = buildCapabilityDoc({ relay: relayWithTor(readyTor({ clientAuthKeys: ['a'.repeat(52)] })) })
  t.is(withKeys.privacyTransports[0].auth.mode, 'client-auth-v3')

  const emptyButRestricted = buildCapabilityDoc({
    relay: relayWithTor(readyTor({ isRestrictedDiscoveryActive: () => true }))
  })
  t.is(emptyButRestricted.privacyTransports[0].auth.mode, 'client-auth-v3')
  t.alike(emptyButRestricted.privacyTransports[0].auth.enrollment, ['pairing-channel'])

  const noCustody = buildCapabilityDoc({ relay: relayWithTor(readyTor(), { custody: { enabled: false } }) })
  t.absent(noCustody.privacyTransports[0].supports.includes('custody.commit'))
})

test('privacyTransports — dual vports map to roles; pow reported', async (t) => {
  const tt = readyTor({
    pow: { enabled: true },
    _effectiveVports: () => [{ vport: 80 }, { vport: 19737 }]
  })
  const doc = buildCapabilityDoc({ relay: relayWithTor(tt) })
  const entry = doc.privacyTransports[0]
  t.alike(entry.vports, [80, 19737])
  t.is(entry.vportRoles.readPlane, 80)
  t.is(entry.vportRoles.peer, 19737)
  t.is(entry.pow.enabled, true)
})
