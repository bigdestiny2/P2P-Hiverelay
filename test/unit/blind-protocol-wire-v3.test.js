import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import { decodeCanonical, encodeCanonical } from '../../packages/blind-protocol/codec.js'
import { blake2b256, hashAbi } from '../../packages/blind-protocol/hashes.js'
import { decodeWireAbiV3 } from '../../packages/blind-protocol/abi-registry-v3.js'
import {
  FORWARD_HTTPS_DOMAIN_V3,
  FORWARD_HTTPS_REQUEST_KIND_V1,
  FORWARD_HTTPS_REQUEST_ROLE_V1,
  FORWARD_HTTPS_RESPONSE_KIND_V1,
  FORWARD_HTTPS_RESULT_ROLE_V1,
  FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3,
  FORWARD_HTTPS_V3_LIMITS,
  FORWARD_HTTPS_V3_RESULT_MATRIX,
  ForwardHttpsDefinitiveResultCacheV1,
  ForwardHttpsOriginSessionContractV1,
  ForwardHttpsTransportBudgetV1,
  WIRE_V3_SCHEMA,
  assertForwardHttpsForwardedRequestAuthorityV1,
  assertForwardHttpsResultForOriginRequestV1,
  assertForwardHttpsResultForRequestV1,
  assertForwardHttpsSourceTransformationV1,
  assertForwardHttpsTargetResultForForwardedRequestV1,
  assertForwardHttpsV2UnselectableV3,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsCapabilityPrefixHashV1,
  forwardHttpsOriginRequestCommitmentV1,
  forwardHttpsParentCapabilityPrefixHashV1,
  forwardHttpsResultSignaturePayloadV1,
  forwardHttpsSourceTransformSignaturePayloadV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  forwardHttpsTlsExporterBindingHashV1,
  forwardHttpsTlsExporterContextV1,
  verifyForwardHttpsParentCapabilitySignatureV1,
  verifyForwardHttpsResultSignatureV1,
  verifyForwardHttpsSourceTransformSignatureV1
} from '../../packages/blind-protocol/wire-v3.js'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..')
const read = relative => fs.readFileSync(path.join(root, relative))
const vector = name => read(`packages/blind-protocol/vectors-v3/wire/${name}`)
const decodeRequest = bytes => decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, bytes, { copyBytes: true })
const decodeResult = bytes => decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, bytes, { copyBytes: true })

function length64 (length) {
  let value = BigInt(length)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function errorFrom (fn) {
  try {
    fn()
  } catch (error) {
    return error
  }
  throw new Error('expected function to throw')
}

function openedSession (options = {}) {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const target = vector('positive/open-target-result.bin')
  const session = new ForwardHttpsOriginSessionContractV1(decodeRequest(origin).stableSessionId, options)
  session.acceptOrigin(origin)
  session.recordForwarded(forwarded)
  session.complete(target)
  return session
}

test('WIRE v3 imports v2, allocates only IDs 76/77 and keeps successor readiness zero', t => {
  const abiBytes = read('packages/blind-protocol/hiverelay-blind-abi-v3.cenc')
  const abi = decodeWireAbiV3(abiBytes)
  const authority = JSON.parse(read('packages/blind-protocol/hiverelay-blind-wire-authority-v3.json'))
  t.alike(WIRE_V3_SCHEMA, {
    BlindForwardHttpsOriginForwardTurnRequestV1: 76,
    BlindForwardHttpsOriginForwardTurnResultV1: 77
  })
  t.is(b4a.toString(abi.baseWireV2AbiHash, 'hex'), 'cc1abb0e24bd4c75e0cb99b824e114cf50ad91270362f39d8594a826e29d5053')
  t.alike(abi.compatibilityOnlySchemaIds, [74, 75])
  t.alike(abi.additionalSchemas.map(value => value.schemaId), [76, 77])
  t.alike(abi.releaseProfiles.map(value => [value.profileId, value.canonicalName, value.operationBits, value.isDefault]), [
    [1, 'LIMITED_PUBLIC_TEST_V1', 131071, true],
    [2, 'LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1', 4063231, false]
  ])
  t.alike(abi.successorTransportVariants.map(value => value.requestKind), [1, 2, 3, 4])
  t.is(abi.forwardReadinessOperationBits, 0)
  t.is(authority.forwardDescriptorOperationBits, 0)
  t.is(authority.forwardAdvertisedOperationBits, 0)
  t.is(authority.forwardReadinessOperationBits, 0)
  t.is(authority.runtimeReady, false)
  t.is(authority.authorizesRelease, false)
  t.is(b4a.toString(hashAbi(abiBytes), 'hex'), authority.abiHash)
  t.exception(() => decodeWireAbiV3(b4a.concat([abiBytes, b4a.from([0])])), /trailing bytes/)
  t.exception(() => assertForwardHttpsV2UnselectableV3(74), /unselectable/)
  t.exception(() => assertForwardHttpsV2UnselectableV3(75), /unselectable/)
  t.ok(assertForwardHttpsV2UnselectableV3(76))
})

test('WIRE v3 HASH purpose and recipes are local to ABI v3 with exact domains', t => {
  const abi = decodeWireAbiV3(read('packages/blind-protocol/hiverelay-blind-abi-v3.cenc'))
  t.is(abi.hashDomainPurposeId, 4)
  t.alike(abi.hashRecipes.map(value => value.recipeId), [3, 4])
  t.alike(abi.additionalDomains.map(value => value.domainId), [18, 113, 114, 115, 215, 216, 217, 218, 219])
  for (const value of abi.additionalDomains.slice(5)) {
    t.is(value.purpose, 'HASH_DOMAIN')
    t.is(value.purposeId, 4)
  }
  t.is(FORWARD_HTTPS_DOMAIN_V3.STABLE_SESSION.recipeId, 4)
  t.is(FORWARD_HTTPS_DOMAIN_V3.TARGET_RESULT_CHAIN.recipeId, 3)
  t.is(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_CONTEXT.recipeId, 3)
  t.is(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_BINDING.recipeId, 4)
  t.is(FORWARD_HTTPS_SUCCESSOR_TRANSPORT_VARIANTS_V3.some(value => value.operation === 'POLL'), false)
})

test('origin request is causal without exporter or source signature and transforms by whitelist', t => {
  const originBytes = vector('positive/open-origin.bin')
  const forwardedBytes = vector('positive/open-forwarded.bin')
  const origin = decodeRequest(originBytes)
  const forwarded = decodeRequest(forwardedBytes)
  t.is(originBytes.byteLength, 65_536)
  t.is(origin.requestRole, FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE)
  t.ok(origin.parentCapability.tlsExporterBindingHash.every(value => value === 0))
  t.ok(origin.parentCapability.signature.every(value => value === 0))
  t.ok(origin.turnTlsExporterBindingHash.every(value => value === 0))
  t.ok(origin.originRequestCommitment.every(value => value === 0))
  t.ok(origin.sourceTransformSignature.every(value => value === 0))
  t.is(forwarded.requestRole, FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED)
  t.alike(forwarded.originRequestCommitment, forwardHttpsOriginRequestCommitmentV1(originBytes))
  t.ok(assertForwardHttpsSourceTransformationV1(originBytes, forwardedBytes))
  t.ok(verifyForwardHttpsParentCapabilitySignatureV1(forwarded.parentCapability))
  t.ok(verifyForwardHttpsSourceTransformSignatureV1(forwardedBytes))
  const mutable = new Set([7])
  for (let index = 440; index < 664; index++) mutable.add(index)
  const changed = []
  for (let index = 0; index < originBytes.byteLength; index++) if (originBytes[index] !== forwardedBytes[index]) changed.push(index)
  t.ok(changed.length > 0)
  t.ok(changed.every(index => mutable.has(index)))
  t.is(forwardHttpsSourceTransformSignaturePayloadV1(forwardedBytes).byteLength,
    FORWARD_HTTPS_DOMAIN_V3.SOURCE_TRANSFORM.exactAsciiBytes.length + 8 + 65_472)
})

test('stable session, request, TLS, result signature, and chain preimages are exact', t => {
  const originBytes = vector('positive/open-origin.bin')
  const forwardedBytes = vector('positive/open-forwarded.bin')
  const resultBytes = vector('positive/open-target-result.bin')
  const origin = decodeRequest(originBytes)
  const forwarded = decodeRequest(forwardedBytes)
  const result = decodeResult(resultBytes)
  t.alike(forwardHttpsStableSessionIdV1(origin.parentCapability, origin.clientSessionNonce), origin.stableSessionId)
  t.alike(forwarded.originRequestCommitment, forwardHttpsOriginRequestCommitmentV1(originBytes))
  t.alike(result.forwardedRequestCommitment, forwardHttpsForwardedRequestCommitmentV1(forwardedBytes))
  const context = forwardHttpsTlsExporterContextV1(origin.stableSessionId, origin.sequence, forwarded.originRequestCommitment)
  const manualContext = blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_CONTEXT.exactAsciiBytes, 'ascii'),
    origin.stableSessionId,
    b4a.alloc(8),
    forwarded.originRequestCommitment
  ]))
  t.alike(context, manualContext)
  const secret = b4a.alloc(32, 60)
  t.alike(forwardHttpsTlsExporterBindingHashV1(secret, context), blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.TLS_EXPORTER_BINDING.exactAsciiBytes, 'ascii'),
    length64(64), secret, context
  ])))
  t.is(forwardHttpsResultSignaturePayloadV1(resultBytes).byteLength,
    FORWARD_HTTPS_DOMAIN_V3.TARGET_RESULT.exactAsciiBytes.length + 8 + 65_472)
  t.ok(verifyForwardHttpsResultSignatureV1(resultBytes))
  t.alike(forwardHttpsTargetResultChainHashV1(resultBytes), blake2b256(b4a.concat([
    b4a.from(FORWARD_HTTPS_DOMAIN_V3.TARGET_RESULT_CHAIN.exactAsciiBytes, 'ascii'), resultBytes
  ])))
  t.is(forwardHttpsTlsExporterContextV1(origin.stableSessionId, origin.sequence, forwarded.originRequestCommitment).byteLength, 32)
})

test('all request roles, result roles, and legal target request/response pairs have golden vectors', t => {
  const requestNames = ['open', 'data', 'window', 'close', 'poll']
  const responseNames = new Map([
    [1, 'open-accept'], [2, 'ack'], [3, 'noop'], [4, 'data'], [5, 'window'], [6, 'close'], [7, 'error']
  ])
  for (const [index, name] of requestNames.entries()) {
    const requestKind = index + 1
    const origin = decodeRequest(vector(`positive/${name}-origin-role.bin`))
    const forwarded = decodeRequest(vector(`positive/${name}-forwarded-role.bin`))
    t.is(origin.requestRole, FORWARD_HTTPS_REQUEST_ROLE_V1.ORIGIN_TEMPLATE)
    t.is(forwarded.requestRole, FORWARD_HTTPS_REQUEST_ROLE_V1.FORWARDED)
    t.is(origin.requestKind, requestKind)
    for (const responseKind of FORWARD_HTTPS_V3_RESULT_MATRIX[requestKind]) {
      const result = decodeResult(vector(`positive/${name}-target-${responseNames.get(responseKind)}.bin`))
      t.is(result.resultRole, FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT)
      t.is(result.responseKind, responseKind)
      t.ok(verifyForwardHttpsResultSignatureV1(encodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, result)))
    }
    const sourceError = decodeResult(vector(`positive/${name}-source-pre-forward-error.bin`))
    const sourceAmbiguous = decodeResult(vector(`positive/${name}-source-post-forward-ambiguous.bin`))
    t.is(sourceError.resultRole, FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR)
    t.is(sourceError.responseKind, FORWARD_HTTPS_RESPONSE_KIND_V1.ERROR)
    t.is(sourceAmbiguous.resultRole, FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_POST_FORWARD_AMBIGUOUS)
    t.is(sourceAmbiguous.responseKind, FORWARD_HTTPS_RESPONSE_KIND_V1.AMBIGUOUS)
  }
})

test('WIRE v3 rejects exact-size, padding, DATA clamp, role, signature, and downgrade mutations', t => {
  t.exception(() => decodeRequest(vector('negative/origin-bad-magic.bin')), /magic/)
  t.exception(() => decodeRequest(vector('negative/origin-nonzero-padding.bin')), /padding/)
  const badTransform = vector('negative/forwarded-bad-transform-signature.bin')
  t.is(verifyForwardHttpsSourceTransformSignatureV1(badTransform), false)
  const badResult = vector('negative/result-bad-signature.bin')
  t.is(verifyForwardHttpsResultSignatureV1(badResult), false)
  t.exception(() => decodeResult(vector('negative/result-role-confusion.bin')), /result|role|signer|matrix/)
  t.exception(() => decodeRequest(vector('positive/open-origin.bin').subarray(0, 65_535)), /exactly 65536|truncated/)
  const data = decodeRequest(vector('positive/data-origin-max.bin'))
  t.is(data.inner.bytes.byteLength, 64_000)
  t.exception(() => encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, {
    ...data,
    inner: { ...data.inner, bytes: b4a.alloc(64_001) }
  }), /64000-byte clamp/)
})

test('target and source results bind exact request provenance with role-selected signatures', t => {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const result = vector('positive/open-target-result.bin')
  t.is(assertForwardHttpsResultForRequestV1(origin, forwarded, result).resultRole, FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT)
  t.alike(assertForwardHttpsForwardedRequestAuthorityV1(forwarded).requestBytes, forwarded)
  t.alike(assertForwardHttpsTargetResultForForwardedRequestV1(forwarded, result).resultBytes, result)
  const reconstructed = assertForwardHttpsResultForOriginRequestV1(origin, result)
  t.alike(reconstructed.forwardedBytes, forwarded)
  t.alike(reconstructed.targetResultChainHash, forwardHttpsTargetResultChainHashV1(result))
  t.is(reconstructed.normalClose, false)
  t.is(reconstructed.targetFin, false)
  for (const name of ['open-source-pre-forward-error.bin', 'open-source-post-forward-ambiguous.bin']) {
    const source = assertForwardHttpsResultForOriginRequestV1(origin, vector(`positive/${name}`))
    t.is(source.targetResultChainHash, null)
    t.is(source.normalClose, false)
  }
  const pollClose = assertForwardHttpsResultForOriginRequestV1(
    vector('positive/poll-origin-role.bin'),
    vector('positive/poll-target-close.bin')
  )
  t.is(pollClose.targetFin, true)
  t.is(pollClose.normalClose, false)
  const close = assertForwardHttpsResultForOriginRequestV1(
    vector('positive/close-origin-role.bin'),
    vector('positive/close-target-close.bin')
  )
  t.is(close.targetFin, true)
  t.is(close.normalClose, true)
  const prefix = forwardHttpsCapabilityPrefixHashV1(origin)
  t.alike(prefix, forwardHttpsParentCapabilityPrefixHashV1(decodeRequest(origin).parentCapability))
  t.alike(prefix, blake2b256(origin.subarray(146, 440)))
  const malformedOrigin = b4a.from(origin)
  malformedOrigin[0] ^= 1
  t.exception(() => forwardHttpsCapabilityPrefixHashV1(malformedOrigin), /magic/)
  t.exception(() => assertForwardHttpsResultForOriginRequestV1(origin, b4a.alloc(65_536)), /magic/)
  t.exception(() => assertForwardHttpsResultForOriginRequestV1(vector('positive/data-origin-role.bin'), result), /bind|canonical|transform|commitment/)
  t.exception(() => assertForwardHttpsTargetResultForForwardedRequestV1(forwarded, vector('positive/data-target-ack.bin')), /bind|provenance/)
  t.exception(() => assertForwardHttpsForwardedRequestAuthorityV1(vector('negative/forwarded-bad-transform-signature.bin')), /signature/)
  const badTargetSignature = b4a.from(result)
  badTargetSignature[705] ^= 1
  t.exception(() => assertForwardHttpsTargetResultForForwardedRequestV1(forwarded, badTargetSignature), /signature/)
  const substituted = b4a.from(result)
  substituted[633] ^= 1
  t.exception(() => assertForwardHttpsResultForRequestV1(origin, forwarded, substituted), /signer|signature/)
  const changedOrigin = b4a.from(origin)
  changedOrigin[82] ^= 1
  t.exception(() => assertForwardHttpsResultForRequestV1(changedOrigin, forwarded, result), /origin|canonical|session|commitment|transform/)
  t.exception(() => forwardHttpsTargetResultChainHashV1(vector('positive/open-source-pre-forward-error.bin')), /TARGET_RESULT/)
})

test('origin session state handles exact retry, nondefinitive source result, chain advance, and terminal close', t => {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const target = vector('positive/open-target-result.bin')
  const sourceError = vector('positive/open-source-pre-forward-error.bin')
  const session = new ForwardHttpsOriginSessionContractV1(decodeRequest(origin).stableSessionId)
  t.is(session.acceptOrigin(origin).disposition, 'ACCEPTED')
  t.is(session.budget.reserved, 131_072)
  t.is(session.recordForwarded(forwarded).disposition, 'PREPARED')
  t.is(session.complete(sourceError).disposition, 'NONDEFINITIVE_PRE_FORWARD_ERROR')
  t.is(session.nextSequence, 0n)
  t.ok(session.outstanding)
  t.is(session.acceptOrigin(origin).disposition, 'EXACT_RETRY')
  t.is(session.budget.reserved, 262_144)
  t.is(session.recordForwarded(forwarded).disposition, 'PREPARED')
  t.is(session.complete(target).disposition, 'DEFINITIVE_TARGET_RESULT')
  t.is(session.nextSequence, 1n)
  t.is(session.acceptOrigin(origin).disposition, 'CACHED_TARGET_RESULT')
  t.is(session.budget.reserved, 393_216)
  const changed = b4a.from(origin)
  changed[82] ^= 1
  t.is(errorFrom(() => session.acceptOrigin(changed)).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(session.budget.reserved, 393_216)
})

test('origin session accepts DATA to ACK and POLL to either NOOP or DATA as definitive turns', t => {
  const data = openedSession()
  t.is(data.acceptOrigin(vector('positive/data-origin-role.bin')).disposition, 'ACCEPTED')
  t.is(data.recordForwarded(vector('positive/data-forwarded-role.bin')).disposition, 'PREPARED')
  t.is(data.complete(vector('positive/data-target-ack.bin')).disposition, 'DEFINITIVE_TARGET_RESULT')
  t.is(data.nextSequence, 2n)
  t.is(data.closed, false)

  for (const response of ['noop', 'data']) {
    const poll = openedSession()
    t.is(poll.acceptOrigin(vector('positive/poll-origin-role.bin')).disposition, 'ACCEPTED')
    t.is(poll.recordForwarded(vector('positive/poll-forwarded-role.bin')).disposition, 'PREPARED')
    const completion = poll.complete(vector(`positive/poll-target-${response}.bin`))
    t.is(completion.disposition, 'DEFINITIVE_TARGET_RESULT')
    t.is(completion.result.responseKind, response === 'noop' ? FORWARD_HTTPS_RESPONSE_KIND_V1.NOOP : FORWARD_HTTPS_RESPONSE_KIND_V1.DATA)
    t.is(poll.nextSequence, 2n)
    t.is(poll.closed, false)
  }
})

test('origin session CLOSE is terminal and sequence gaps or outstanding byte changes reserve no exchange', t => {
  const closing = openedSession()
  const closeOrigin = vector('positive/close-origin-role.bin')
  const closeForwarded = vector('positive/close-forwarded-role.bin')
  const closeResult = vector('positive/close-target-close.bin')
  t.is(closing.acceptOrigin(closeOrigin).disposition, 'ACCEPTED')
  closing.recordForwarded(closeForwarded)
  closing.complete(closeResult)
  t.is(closing.closed, true)
  t.is(closing.nextSequence, 2n)
  t.is(closing.acceptOrigin(closeOrigin).disposition, 'CACHED_TARGET_RESULT')
  const postClose = decodeRequest(vector('positive/data-origin-role.bin'))
  postClose.sequence = 2n
  postClose.previousTargetResultHash = forwardHttpsTargetResultChainHashV1(closeResult)
  t.is(errorFrom(() => closing.acceptOrigin(encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, postClose))).code, 'TERMINAL_FORWARD_HTTPS_SESSION')

  const gap = openedSession()
  const gapBudget = gap.budget.reserved
  const skipped = decodeRequest(vector('positive/data-origin-role.bin'))
  skipped.sequence = 2n
  t.is(errorFrom(() => gap.acceptOrigin(encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, skipped))).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(gap.budget.reserved, gapBudget)

  const origin = vector('positive/open-origin.bin')
  const changed = decodeRequest(origin)
  changed.requestNonce = b4a.from(changed.requestNonce)
  changed.requestNonce[0] ^= 1
  const outstanding = new ForwardHttpsOriginSessionContractV1(decodeRequest(origin).stableSessionId)
  outstanding.acceptOrigin(origin)
  const outstandingBudget = outstanding.budget.reserved
  t.is(errorFrom(() => outstanding.acceptOrigin(encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, changed))).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(outstanding.budget.reserved, outstandingBudget)
})

test('source correctness terminal absorbs forwarding, completion, cache and clock rollback', t => {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const target = vector('positive/open-target-result.bin')
  const session = new ForwardHttpsOriginSessionContractV1(decodeRequest(origin).stableSessionId)
  session.acceptOrigin(origin)
  const changed = decodeRequest(origin)
  changed.requestNonce = b4a.from(changed.requestNonce)
  changed.requestNonce[0] ^= 1
  t.is(errorFrom(() => session.acceptOrigin(encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, changed))).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  const before = session.outstanding
  t.is(errorFrom(() => session.recordForwarded(forwarded)).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(errorFrom(() => session.complete(target)).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(session.nextSequence, 0n)
  t.alike(session.outstanding.originBytes, before.originBytes)
  t.is(session.completedCount, 0)

  const targetFin = openedSession()
  targetFin.acceptOrigin(vector('positive/poll-origin-role.bin'))
  targetFin.recordForwarded(vector('positive/poll-forwarded-role.bin'))
  targetFin.complete(vector('positive/poll-target-close.bin'))
  t.is(targetFin.targetFin, true)
  t.is(targetFin.closed, false)

  const clock = openedSession()
  t.is(clock.acceptOrigin(origin, { nowEpoch: 1_800_001_500 }).disposition, 'CACHED_TARGET_RESULT')
  t.is(errorFrom(() => clock.acceptOrigin(vector('positive/data-origin-role.bin'), { nowEpoch: 1_800_000_000 })).code, 'TERMINAL_FORWARD_HTTPS_SESSION')
  t.is(clock.nextSequence, 1n)

  const outstanding = new ForwardHttpsOriginSessionContractV1(decodeRequest(origin).stableSessionId)
  t.is(outstanding.acceptOrigin(origin, { nowEpoch: 1_800_000_000 }).disposition, 'ACCEPTED')
  t.is(outstanding.acceptOrigin(origin, { nowEpoch: 1_800_001_501 }).disposition, 'EXACT_RETRY')
  t.is(outstanding.terminal, false)
})

test('definitive cache authenticates before live checks and has inclusive expiry plus 900 retention', t => {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const result = vector('positive/open-target-result.bin')
  const expiry = 1_800_000_600
  for (const [role, request] of [['SOURCE', origin], ['TARGET', forwarded]]) {
    for (const now of [expiry - 1, expiry, expiry + 900]) {
      const cache = new ForwardHttpsDefinitiveResultCacheV1(role)
      cache.persist(request, result)
      t.alike(cache.lookup(request, now), result)
    }
  }
  const expired = new ForwardHttpsDefinitiveResultCacheV1('TARGET')
  expired.persist(forwarded, result)
  const error = errorFrom(() => expired.lookup(forwarded, expiry + 901))
  t.is(error.code, 'FORWARD_HTTPS_RECOVERY_GRACE_EXPIRED')
  t.is(expired.terminal, true)
  t.is(expired.budget.reserved, 0)
  t.is(errorFrom(() => expired.lookup(forwarded, expiry - 1)).code, 'FORWARD_HTTPS_RECOVERY_GRACE_EXPIRED')
  t.is(expired.budget.reserved, 0)
})

test('source and target cache budgets fail without mutation below 131072 and reserve once at boundary', t => {
  const origin = vector('positive/open-origin.bin')
  const forwarded = vector('positive/open-forwarded.bin')
  const result = vector('positive/open-target-result.bin')
  for (const role of ['SOURCE', 'TARGET']) {
    const request = role === 'SOURCE' ? origin : forwarded
    for (const remaining of [0, 131_071]) {
      const budget = new ForwardHttpsTransportBudgetV1(remaining)
      const cache = new ForwardHttpsDefinitiveResultCacheV1(role, budget)
      cache.persist(request, result)
      const record = cache.inspectRecord(request)
      const error = errorFrom(() => cache.lookup(request, 1_800_000_600))
      t.is(error.code, 'FORWARD_HTTPS_BUDGET_EXHAUSTED')
      t.is(cache.terminal, true)
      t.is(cache.terminalReason, 'FORWARD_HTTPS_BUDGET_EXHAUSTED')
      t.is(budget.reserved, 0)
      t.alike(cache.inspectRecord(request), record)
      t.is(errorFrom(() => cache.lookup(request, 1_800_000_600)).code, 'FORWARD_HTTPS_BUDGET_EXHAUSTED')
    }
    const budget = new ForwardHttpsTransportBudgetV1(FORWARD_HTTPS_V3_LIMITS.TRANSPORT_EXCHANGE_BYTES)
    const cache = new ForwardHttpsDefinitiveResultCacheV1(role, budget)
    cache.persist(request, result)
    t.alike(cache.lookup(request, 1_800_000_600), result)
    t.is(budget.reserved, 131_072)
    const error = errorFrom(() => cache.lookup(request, 1_800_000_600))
    t.is(error.code, 'FORWARD_HTTPS_BUDGET_EXHAUSTED')
    t.is(budget.reserved, 131_072)
  }
})

test('definitive cache validates first write, is set-once, derives expiry and returns defensive copies', t => {
  for (const [role, request] of [
    ['SOURCE', vector('positive/open-origin.bin')],
    ['TARGET', vector('positive/open-forwarded.bin')]
  ]) {
    const result = vector('positive/open-target-result.bin')
    const cache = new ForwardHttpsDefinitiveResultCacheV1(role)
    t.exception(() => cache.persist(request, vector('positive/data-target-ack.bin')), /bind|provenance|commitment/)
    t.is(cache.recordCount, 0)
    cache.persist(request, result)
    t.alike(cache.persist(request, result), result)
    const first = cache.inspectRecord(request)
    t.is(first.expiresAtEpoch, 1_800_000_600)
    first.requestBytes[0] ^= 1
    first.resultBytes[0] ^= 1
    t.alike(cache.inspectRecord(request).resultBytes, result)
    const remint = errorFrom(() => cache.persist(request, vector('positive/open-target-error.bin')))
    t.is(remint.code, 'TERMINAL_FORWARD_HTTPS_CACHE')
    t.is(cache.terminal, true)
    t.alike(cache.inspectRecord(request).resultBytes, result)
    t.is(errorFrom(() => cache.lookup(request, 1_800_000_000)).code, 'TERMINAL_FORWARD_HTTPS_CACHE')
  }
})

test('WIRE v3 request and result fixed offsets remain exact', t => {
  const request = vector('positive/open-forwarded.bin')
  const result = vector('positive/open-target-result.bin')
  t.is(b4a.toString(request.subarray(0, 4), 'ascii'), 'HFOQ')
  t.is(request[7], 1)
  t.alike(request.subarray(568, 600), forwardHttpsOriginRequestCommitmentV1(vector('positive/open-origin.bin')))
  t.is(request.subarray(600, 664).byteLength, 64)
  t.is(result.byteLength, 65_536)
  t.is(b4a.toString(result.subarray(0, 4), 'ascii'), 'HFOS')
  t.is(result[7], 1)
  t.is(result.subarray(705, 769).byteLength, 64)
  t.is(FORWARD_HTTPS_REQUEST_KIND_V1.POLL, 5)
})
