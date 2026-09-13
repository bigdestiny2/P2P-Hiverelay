// Test-only helper extraction from core-runtime-checkpoint-v1.test.js.
// Real persisted engine transitions; synthetic upstream payloads do not qualify Hypercore cryptography.
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { FAMILY, blake2b256, coreMirrorRequestCommitment, coreServeRequestCommitment } from '@hiverelay/blind-protocol'
import { BlindCoreRuntimeAdapter } from '../core-runtime-adapter.js'
import { fixtureRelayBinding } from './stream-fixtures.js'

const EPOCH_MILLIS = 21600000n

const PARTITION_KEY = b4a.alloc(32, 0x81)

const FENCE_HASH = b4a.alloc(32, 0x91)

const CONTINUITY_HASH = b4a.alloc(32, 0x92)

function signingAuthority () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey,
    signer: {
      async sign ({ payload }) {
        const signature = b4a.alloc(sodium.crypto_sign_BYTES)
        sodium.crypto_sign_detached(signature, payload, secretKey)
        return signature
      }
    }
  }
}

function clock () {
  return {
    epoch: 1000,
    millis: 1000n * EPOCH_MILLIS,
    nowEpoch () { return this.epoch },
    nowUnixMillis () { return this.millis }
  }
}

function storageOptions (root, time, relayPublicKey, overrides = {}) {
  return {
    root,
    relayPublicKey,
    partitionKey: PARTITION_KEY,
    ownerFenceTokenHash: FENCE_HASH,
    durabilityContinuityHash: CONTINUITY_HASH,
    nowEpoch: () => time.nowEpoch(),
    nowUnixMillis: () => time.nowUnixMillis(),
    maximumCorpusBytes: 1024 * 1024,
    maximumSponsoredCoreLength: 1_000_000n,
    ...overrides
  }
}

function admission (requestCommitment, spendByte, leaseClass, resourceClass = 1) {
  return {
    spendTag: b4a.alloc(32, spendByte),
    requestCommitment: b4a.from(requestCommitment),
    profileId: 1,
    schemeId: 1,
    parameterHash: b4a.alloc(32, 0xc7),
    costClass: { resourceClass, leaseClass, costUnits: 1n },
    walCommitRecord: b4a.alloc(48, spendByte ^ 0xff)
  }
}

function mirrorRequest (relayPublicKey, overrides = {}) {
  const request = {
    version: 1,
    corePublicKey: overrides.corePublicKey || b4a.alloc(32, 0x31),
    fork: overrides.fork == null ? 0n : overrides.fork,
    length: overrides.length == null ? 4n : overrides.length,
    signedHeadHash: overrides.signedHeadHash || b4a.alloc(32, 0x41),
    leaseClass: overrides.leaseClass == null ? 1 : overrides.leaseClass,
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x51),
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0xc7),
      token: b4a.alloc(32, 0xc8)
    }
  }
  const requestCommitment = coreMirrorRequestCommitment({ ...request, relayPublicKey })
  return { request, requestCommitment }
}

function proveRequest (relayPublicKey, mirror, overrides = {}) {
  const request = {
    version: 1,
    corePublicKey: b4a.from(mirror.request.corePublicKey),
    fork: mirror.request.fork,
    length: mirror.request.length,
    signedHeadHash: b4a.from(mirror.request.signedHeadHash),
    blockIndices: overrides.blockIndices || [0n, mirror.request.length - 1n],
    clientNonce: overrides.clientNonce || b4a.alloc(32, 0x61),
    admission: overrides.admission === false
      ? null
      : {
          profileId: 1,
          schemeId: 1,
          parameterHash: b4a.alloc(32, 0xc7),
          token: b4a.alloc(32, 0xc9)
        }
  }
  const requestCommitment = coreServeRequestCommitment({ ...request, relayPublicKey })
  return { request, requestCommitment }
}

function descriptorAuthority (relayPublicKey) {
  let binding = fixtureRelayBinding(relayPublicKey)
  return {
    resultBinding () { return binding },
    refresh (overrides) { binding = fixtureRelayBinding(relayPublicKey, overrides) },
    binding () { return binding }
  }
}

function upstreamAuthority () {
  let activations = 0
  let serves = 0
  let tamper = false
  let invalidHeadByte = null
  let unavailableAttempts = 0
  function proof ({ generation, blockIndices, corpus }) {
    const indices = b4a.alloc(blockIndices.length * 8)
    let offset = 0
    for (let index of blockIndices) {
      for (let byte = 7; byte >= 0; byte--) {
        indices[offset + byte] = Number(index & 0xffn)
        index >>= 8n
      }
      offset += 8
    }
    const output = b4a.concat([
      b4a.from([generation.signedHeadHash[0]]),
      indices,
      corpus.subarray(0, 64)
    ])
    if (tamper) output[output.byteLength - 1] ^= 1
    return output
  }
  return {
    async activateMirror ({ request }) {
      activations++
      if (unavailableAttempts > 0) {
        unavailableAttempts--
        throw new Error('injected upstream unavailability')
      }
      if (invalidHeadByte != null && request.signedHeadHash[0] === invalidHeadByte) {
        return { verified: false }
      }
      const corpus = b4a.alloc(4096, request.signedHeadHash[0])
      return {
        verified: true,
        corpus,
        corpusByteLength: corpus.byteLength,
        corpusHash: blake2b256(corpus)
      }
    },
    async serveProof (input) {
      serves++
      return proof(input)
    },
    async estimateProofBytes ({ request }) {
      return 1 + request.blockIndices.length * 8 + 64
    },
    setTamper (value) { tamper = value },
    setInvalidHeadByte (value) { invalidHeadByte = value },
    setUnavailableAttempts (value) { unavailableAttempts = value },
    activations: () => activations,
    serves: () => serves
  }
}

function adapterHarness (storage, keys, descriptor, upstream) {
  return new BlindCoreRuntimeAdapter({
    storage,
    descriptorState: descriptor,
    signer: keys.signer,
    upstream
  })
}

function executionInput (operationId, request, requestCommitment, preparedAdmission = null) {
  return {
    profile: { familyId: FAMILY.CORE, operationId },
    request,
    requestCommitment,
    preparedAdmission,
    descriptorSnapshot: Object.freeze({}),
    signal: new AbortController().signal
  }
}

export { signingAuthority, clock, storageOptions, admission, mirrorRequest, proveRequest, descriptorAuthority, upstreamAuthority, adapterHarness, executionInput }
