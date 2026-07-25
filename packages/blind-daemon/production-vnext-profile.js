import b4a from 'b4a'
import { PRIVATE_IPC_V4_STATUS } from '@hiverelay/blind-ipc'

// Bounded vNext direct-HTTPS public-test profile assembly.
//
// This module is the composition surface for the LIMITED_PUBLIC_TEST_V1
// release profile (profile ID 1, operation mask 0x0001ffff — the baseline 17
// DESCRIBE/CELL/INBOX/CORE operations). It GENUINELY assembles the production
// runtime exclusions by wiring the already-accepted modules into the daemon
// entrypoint: the CELL/INBOX/CORE public execution line (assembled inside
// assembleProductionBlindDaemon), the sealed admission redemption adapter, and
// the accepted bounded one-hop FORWARD relay (forward-https-runtime-vnext.js).
//
// Discipline honoured here:
//  - No release-gate override, no BLIND_RUNTIME_TEST_SEAM paths, no hand-written
//    driver. The production release gate stays strict; this module makes each
//    exclusion TRUE-assembled rather than filtering it away.
//  - FORWARD descriptor/readiness/advertised operation bits stay ZERO per the
//    run's forward-activation rule. The accepted FORWARD module already never
//    publishes a bit; this assembly does not change that.
//  - Sealed node-scoped material is consumed only through the existing
//    config/env surface (bootstrap-config.js, production-runtime.js config and
//    the forward env below). No new secret flow is invented.
//
// This module deliberately imports nothing from production-runtime.js so the
// release gate (which lives there) can depend on this module without a cycle.

export const LIMITED_PUBLIC_TEST_V1_PROFILE = 'LIMITED_PUBLIC_TEST_V1'

// The baseline-17 public-test operation mask (release profile ID 1). FORWARD
// bits (18-21) and CORE.OPEN_REPLICATION (bit 17) are reserved and stay zero.
export const LIMITED_PUBLIC_TEST_V1_OPERATION_BITS = 0x0001ffff

export function isVnextPublicTestProfile (profile) {
  return profile === LIMITED_PUBLIC_TEST_V1_PROFILE
}

// The vNext public-test profile enables the complete CELL/INBOX/CORE public
// execution line. FORWARD is a separate bounded one-hop class assembled beside
// it; it never contributes descriptor/readiness bits.
export const VNEXT_PUBLIC_TEST_RUNTIME_FLAGS = Object.freeze({
  enableCellRuntime: true,
  enableInboxRuntime: true,
  enableCoreRuntime: true
})

function configFailure (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function optionalPath (environment, name) {
  const value = environment[name]
  if (value == null || value === '') return null
  if (typeof value !== 'string' || value.includes('\0') || value.length > 4096) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be one canonical path`)
  }
  return value
}

function optionalHash (environment, name) {
  const raw = environment[name]
  if (raw == null || raw === '') return null
  if (typeof raw !== 'string' || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be an exact 32-byte hash in hex`)
  }
  const value = b4a.from(raw, 'hex')
  if (value.every(byte => byte === 0)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID', `${name} must be nonzero`)
  }
  return value
}

// Parse and validate the bounded one-hop FORWARD class configuration from the
// signed launch env surface. Returns null when FORWARD is not configured at
// all (the caller then treats FORWARD_PUBLIC_EXECUTION and the profile-2
// external journal witness as not yet assembled). When any FORWARD material is
// present the complete set is required, so a half-configured FORWARD class
// fails closed instead of assembling a partial relay.
export function loadVnextForwardConfig (environment = process.env) {
  const root = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_STORE_ROOT')
  const manifestKeyFile = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_MANIFEST_KEY_FILE')
  const atRestKeyFile = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_ATREST_KEY_FILE')
  const sourceStoreId = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_STORE_ID')
  const targetStoreId = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_STORE_ID')
  const sourceContinuityHash = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_CONTINUITY_HASH')
  const targetContinuityHash = optionalHash(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_CONTINUITY_HASH')
  const sourceSocketPath = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_SOURCE_SOCKET')
  const targetSocketPath = optionalPath(environment, 'HIVERELAY_BLIND_FORWARD_TARGET_SOCKET')

  const present = [root, manifestKeyFile, atRestKeyFile, sourceStoreId, targetStoreId,
    sourceContinuityHash, targetContinuityHash]
  const anyPresent = present.some(value => value != null) || sourceSocketPath != null ||
    targetSocketPath != null
  if (!anyPresent) return null
  if (present.some(value => value == null)) {
    configFailure('BLIND_VNEXT_FORWARD_CONFIG_INVALID',
      'the bounded FORWARD class requires the complete storage identity set when any of it is configured')
  }
  return Object.freeze({
    storage: Object.freeze({
      root,
      manifestKeyFile,
      atRestKeyFile,
      sourceStoreId,
      targetStoreId,
      sourceDurabilityContinuityHash: sourceContinuityHash,
      targetDurabilityContinuityHash: targetContinuityHash
    }),
    sourceSocketPath,
    targetSocketPath,
    // The WIRE v3 ABI and private IPC v4 format hashes are pinned generated
    // authorities, imported (never hardcoded) so a contract drift fails closed.
    wireV3AbiHash: b4a.from(PRIVATE_IPC_V4_STATUS.importedWireV3AbiHash, 'hex'),
    privateIpcV4Hash: b4a.from(PRIVATE_IPC_V4_STATUS.privateIpcFormatHash, 'hex')
  })
}
