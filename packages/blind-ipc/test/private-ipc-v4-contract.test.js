import test from 'brittle'
import b4a from 'b4a'
import fs from 'node:fs'
import path from 'node:path'
import {
  FORWARD_HTTPS_RESULT_ROLE_V1,
  blindForwardHttpsOriginForwardTurnRequestV1,
  forwardHttpsForwardedRequestCommitmentV1,
  forwardHttpsSourceTransformSignaturePayloadV1,
  forwardHttpsTargetResultChainHashV1
} from '@hiverelay/blind-protocol'
import { decodeCanonical, encodeCanonical } from '@hiverelay/blind-protocol/codec'
import sodium from '../../blind-protocol/crypto.js'
import { privateBlake2b256 } from '../private-hashes.js'
import {
  FORWARD_HTTPS_TARGET_TLS_EXPORTER_LABEL_V4,
  LOCAL_FORWARD_HTTPS_DIRECTION_V4,
  PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS,
  PRIVATE_IPC_V4_LIMITS,
  PRIVATE_IPC_V4_SCHEMA,
  LocalForwardHttpsReplayJournalModelV4,
  LocalForwardHttpsTargetClaimModelV4,
  LocalForwardHttpsTranscriptAccumulatorV4,
  assertLocalForwardHttpsResultTranscriptV4,
  assertLocalForwardHttpsSocketSeparationV4,
  decodeLocalForwardHttpsOriginAuthorityV4,
  decodeLocalForwardHttpsSourceOriginTranscriptV4,
  decodeLocalForwardHttpsTargetIngressTranscriptV4,
  decodeLocalForwardHttpsTargetIngressV4,
  decodeLocalForwardHttpsTurnV4,
  decodePrivateIpcV4Registry,
  encodeLocalForwardHttpsOriginAuthorityV4,
  encodeLocalForwardHttpsTargetIngressV4,
  forwardHttpsTargetTlsExporterBindingHashV4,
  forwardHttpsTargetTlsExporterContextV4,
  hashPrivateIpcV4Registry,
  hashPrivateIpcV4VectorManifest,
  localForwardHttpsExchangeIdV4,
  localForwardHttpsSourceReplayTupleV4,
  localForwardHttpsTargetReplayTupleV4,
  targetLocalForwardHttpsExchangeIdV4
} from '../private-ipc-v4-contract.js'
import { PRIVATE_IPC_V4_STATUS, assertPrivateIpcV4Status } from '../private-ipc-v4-status.js'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const read = relative => fs.readFileSync(path.join(root, relative))
const vector = name => read(`vectors-v4/${name}`)
const wireVector = name => read(`../blind-protocol/vectors-v3/wire/${name}`)

const sourcePublicKey = b4a.alloc(32)
const sourceSecretKey = b4a.alloc(64)
sodium.crypto_sign_seed_keypair(sourcePublicKey, sourceSecretKey, b4a.alloc(32, 41))

function resignForwarded (input, mutate) {
  const request = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, input, { copyBytes: true })
  mutate(request)
  request.sourceTransformSignature = b4a.alloc(64, 1)
  const provisional = encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, request)
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, forwardHttpsSourceTransformSignaturePayloadV1(provisional), sourceSecretKey)
  request.sourceTransformSignature = signature
  return encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, request)
}

function openedTargetClaims () {
  const claims = new LocalForwardHttpsTargetClaimModelV4()
  const open = wireVector('positive/open-forwarded-role.bin')
  const result = wireVector('positive/open-target-open-accept.bin')
  claims.claim(open)
  claims.persistResult(open, result)
  return claims
}

function length64 (length) {
  let value = BigInt(length)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function u64 (value) {
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

function journalSnapshot (value) {
  const payload = b4a.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8')
  const domain = b4a.from('hiverelay.blind.private-ipc-forward-journal-model.v4', 'ascii')
  return { payload, checksum: privateBlake2b256(b4a.concat([domain, length64(payload.byteLength), payload])) }
}

const restartOptions = (expectedNamespace, expectedCapacity, nowMonotonicMillis) => ({
  expectedNamespace,
  expectedCapacity,
  nowMonotonicMillis
})

test('private IPC v4 imports frozen IPC v3 and WIRE v3 and appends only IDs 16/17/18', t => {
  const registryBytes = read('hiverelay-blind-private-ipc-v4.cenc')
  const manifestBytes = read('vector-manifest-v4.cenc')
  const registry = decodePrivateIpcV4Registry(registryBytes)
  const authority = JSON.parse(read('hiverelay-blind-private-ipc-authority-v4.json'))
  t.alike(PRIVATE_IPC_V4_SCHEMA, {
    LocalForwardHttpsOriginAuthorityV4: 16,
    LocalForwardHttpsTurnV4: 17,
    LocalForwardHttpsTargetIngressV4: 18
  })
  t.is(registry.baseSchemaCount, 15)
  t.alike(registry.additionalSchemas.map(value => value.schemaId), [16, 17, 18])
  t.is(b4a.toString(registry.basePrivateIpcV3FormatHash, 'hex'), 'efb4fd8eae1a2338722deced991fdc907b465d7580acfe2bde8ad692dc1c8200')
  t.is(b4a.toString(registry.importedWireV3AbiHash, 'hex'), PRIVATE_IPC_V4_STATUS.importedWireV3AbiHash)
  t.is(b4a.toString(hashPrivateIpcV4Registry(registryBytes), 'hex'), authority.privateIpcFormatHash)
  t.is(b4a.toString(hashPrivateIpcV4VectorManifest(manifestBytes), 'hex'), authority.privateIpcVectorSetHash)
  t.is(registry.forwardReadinessOperationBits, 0)
  t.ok(assertPrivateIpcV4Status(authority))
  t.is(PRIVATE_IPC_V4_STATUS.runtimeReady, false)
  t.is(PRIVATE_IPC_V4_STATUS.releaseReady, false)
  t.is(PRIVATE_IPC_V4_STATUS.authorizesRelease, false)
  t.exception(() => decodePrivateIpcV4Registry(b4a.concat([registryBytes, b4a.from([0])])), /canonical/)
})

test('private IPC v4 declaration bytes preserve exact name/fields order and ID18 semantic tail', t => {
  const registry = decodePrivateIpcV4Registry(read('hiverelay-blind-private-ipc-v4.cenc'))
  for (const [index, declaration] of PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS.entries()) {
    const expected = b4a.from(JSON.stringify({ name: declaration.schemaName, fields: declaration.fields }), 'utf8')
    t.alike(registry.additionalSchemas[index].canonicalDeclarationBytes, expected)
  }
  t.alike(PRIVATE_IPC_V4_ADDITIONAL_SCHEMAS[2].fields.slice(-6), [
    'targetTlsExporterLabel:ASCII(EXPORTER-HiveRelay-Blind-Forward-Target-v1)',
    'targetTlsExporterContext:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-tls-context.v4)||stableSessionId32||u64be(sequence)||forwardedRequestCommitment32)',
    'targetTlsExporterBindingHash:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-tls-binding.v4)||u64be(64)||targetTlsExporterSecret32||targetTlsExporterContext32)',
    'targetLocalExchangeId:BLAKE2b256(ASCII(hiverelay.blind.private-ipc-forward-target-exchange.v4)||u64be(260)||bytes[0:260])',
    'body:exact canonical WIRE ID76 requestRole FORWARDED; commitment/session/sequence match header; no origin/outer-envelope/native-stream/fallback form',
    'raw target TLS exporter, source address, URL, host, IP, cookies, authorization, credentials, and app metadata are unrepresentable'
  ])
})

test('source-origin transcript is exact ID16||ID17, requires EOF, and binds every duplicated field', t => {
  const transcript = vector('positive/source-origin-transcript-v4.bin')
  t.is(transcript.byteLength, 65_976)
  const decoded = decodeLocalForwardHttpsSourceOriginTranscriptV4(transcript, { eof: true })
  t.is(decoded.turn.direction, LOCAL_FORWARD_HTTPS_DIRECTION_V4.ORIGIN_REQUEST)
  t.is(decoded.turn.wireRole, 0)
  t.alike(decoded.authority.localExchangeId, localForwardHttpsExchangeIdV4(transcript.subarray(0, 260)))
  t.alike(encodeLocalForwardHttpsOriginAuthorityV4(decoded.authority), transcript.subarray(0, 292))
  t.exception(() => decodeLocalForwardHttpsSourceOriginTranscriptV4(transcript), /EOF/)
  t.exception(() => decodeLocalForwardHttpsSourceOriginTranscriptV4(vector('negative/source-origin-extra-record.bin'), { eof: true }), /exactly 65976/)
  t.exception(() => decodeLocalForwardHttpsSourceOriginTranscriptV4(vector('negative/source-origin-role-forwarded.bin'), { eof: true }), /role|body|canonical/i)
  t.exception(() => decodeLocalForwardHttpsSourceOriginTranscriptV4(vector('negative/source-origin-exchange-mismatch.bin'), { eof: true }), /bind/)
})

test('target ingress is exact composite ID18 with unchanged role-FORWARDED ID76 and target-only result', t => {
  const input = vector('positive/target-ingress-v4.bin')
  t.is(input.byteLength, 65_828)
  const ingress = decodeLocalForwardHttpsTargetIngressTranscriptV4(input, { eof: true })
  const request = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, ingress.body, { copyBytes: true })
  t.is(request.requestRole, 1)
  t.alike(ingress.forwardedRequestCommitment, forwardHttpsForwardedRequestCommitmentV1(ingress.body))
  t.alike(ingress.targetLocalExchangeId, targetLocalForwardHttpsExchangeIdV4(input))
  t.alike(encodeLocalForwardHttpsTargetIngressV4(ingress), input)
  const result = assertLocalForwardHttpsResultTranscriptV4(
    vector('positive/target-result-turn-v4.bin'), ingress, FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT)
  t.is(result.wireRole, FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT)
  t.exception(() => decodeLocalForwardHttpsTargetIngressTranscriptV4(input), /EOF/)
  t.exception(() => decodeLocalForwardHttpsTargetIngressV4(vector('negative/target-ingress-origin-role.bin')), /FORWARDED|commitment|canonical/)
  t.exception(() => decodeLocalForwardHttpsTargetIngressV4(vector('negative/target-ingress-bad-binding.bin')), /ExchangeId|canonical/)
  t.exception(() => decodeLocalForwardHttpsTargetIngressV4(vector('negative/target-ingress-bad-exchange.bin')), /ExchangeId|canonical/)
  t.exception(() => assertLocalForwardHttpsResultTranscriptV4(
    vector('positive/source-result-error-v4.bin'), ingress, FORWARD_HTTPS_RESULT_ROLE_V1.TARGET_RESULT), /result transcript/)
})

test('target TLS context, binding, exchange and replay use exact independent domains', t => {
  const ingress = decodeLocalForwardHttpsTargetIngressV4(vector('positive/target-ingress-v4.bin'))
  const context = forwardHttpsTargetTlsExporterContextV4(
    ingress.stableSessionId, ingress.sequence, ingress.forwardedRequestCommitment)
  t.is(FORWARD_HTTPS_TARGET_TLS_EXPORTER_LABEL_V4, 'EXPORTER-HiveRelay-Blind-Forward-Target-v1')
  t.alike(context, vector('positive/target-tls-context-v4.bin'))
  t.alike(context, privateBlake2b256(b4a.concat([
    b4a.from('hiverelay.blind.private-ipc-forward-target-tls-context.v4', 'ascii'),
    ingress.stableSessionId, u64(ingress.sequence), ingress.forwardedRequestCommitment
  ])))
  const secret = b4a.alloc(32, 75)
  t.alike(forwardHttpsTargetTlsExporterBindingHashV4(secret, context), privateBlake2b256(b4a.concat([
    b4a.from('hiverelay.blind.private-ipc-forward-target-tls-binding.v4', 'ascii'),
    length64(64), secret, context
  ])))
  t.alike(targetLocalForwardHttpsExchangeIdV4(vector('positive/target-ingress-v4.bin')), privateBlake2b256(b4a.concat([
    b4a.from('hiverelay.blind.private-ipc-forward-target-exchange.v4', 'ascii'),
    length64(260), vector('positive/target-ingress-v4.bin').subarray(0, 260)
  ])))
})

test('source and target replay tuples have exact 232-byte role-separated preimages', t => {
  const source = decodeLocalForwardHttpsOriginAuthorityV4(vector('positive/source-origin-authority-v4.bin'))
  const target = decodeLocalForwardHttpsTargetIngressV4(vector('positive/target-ingress-v4.bin'))
  const sourcePayload = b4a.concat([
    source.wireV3AbiHash, source.signedLaunchTopologyHash, source.edgeProcessNonce, source.localChannelNonce,
    source.originRequestCommitment, source.stableSessionId, u64(source.sequence), source.localExchangeId
  ])
  const targetPayload = b4a.concat([
    target.wireV3AbiHash, target.signedLaunchTopologyHash, target.edgeProcessNonce, target.localChannelNonce,
    target.forwardedRequestCommitment, target.stableSessionId, u64(target.sequence), target.targetLocalExchangeId
  ])
  t.is(sourcePayload.byteLength, 232)
  t.is(targetPayload.byteLength, 232)
  const sourceTuple = localForwardHttpsSourceReplayTupleV4(source)
  const targetTuple = localForwardHttpsTargetReplayTupleV4(target)
  t.alike(sourceTuple, privateBlake2b256(b4a.concat([
    b4a.from('hiverelay.blind.private-ipc-forward-replay.v4', 'ascii'), length64(232), sourcePayload
  ])))
  t.alike(targetTuple, privateBlake2b256(b4a.concat([
    b4a.from('hiverelay.blind.private-ipc-forward-target-replay.v4', 'ascii'), length64(232), targetPayload
  ])))
  t.not(sourceTuple, targetTuple)
  t.alike(sourceTuple, vector('positive/source-replay-tuple-v4.bin'))
  t.alike(targetTuple, vector('positive/target-replay-tuple-v4.bin'))
})

test('transcript accumulator accepts arbitrary split/coalesce but no short, extra, second, or pre-EOF response', t => {
  for (const [role, input] of [
    ['SOURCE_ORIGIN', vector('positive/source-origin-transcript-v4.bin')],
    ['TARGET_INGRESS', vector('positive/target-ingress-v4.bin')]
  ]) {
    const split = new LocalForwardHttpsTranscriptAccumulatorV4(role)
    t.ok(errorFrom(() => Object.assign(split, { role: 'TARGET_INGRESS', limit: 0, chunks: [input], length: input.byteLength, ended: true })) instanceof TypeError)
    t.ok(errorFrom(() => Object.defineProperty(split, 'responseAllowed', { value: true })) instanceof TypeError)
    const forgedPrototype = Object.create(Object.getPrototypeOf(split), {
      responseAllowed: { value: true, configurable: true }
    })
    t.ok(errorFrom(() => Object.setPrototypeOf(split, forgedPrototype)) instanceof TypeError)
    t.is(split.responseAllowed, false)
    for (let offset = 0; offset < input.byteLength; offset++) split.write(input.subarray(offset, offset + 1))
    t.is(split.responseAllowed, false)
    split.end()
    t.is(split.responseAllowed, true)
    t.exception(() => split.write(b4a.from([0])), /after EOF/)
    t.exception(() => split.end(), /only once/)

    const short = new LocalForwardHttpsTranscriptAccumulatorV4(role)
    short.write(input.subarray(0, input.byteLength - 1))
    t.exception(() => short.end(), /before its exact byte limit/)
    t.is(short.responseAllowed, false)

    const extra = new LocalForwardHttpsTranscriptAccumulatorV4(role)
    t.exception(() => extra.write(b4a.concat([input, b4a.from([0])])), /exceeds/)

    const malformed = new LocalForwardHttpsTranscriptAccumulatorV4(role)
    malformed.write(b4a.alloc(input.byteLength))
    t.exception(() => malformed.end())
    t.is(malformed.responseAllowed, false)
  }
})

test('source and target socket identities are non-aliasing and record families cannot cross sockets', t => {
  t.ok(assertLocalForwardHttpsSocketSeparationV4({
    sourceOrigin: 'inode:1',
    targetIngress: 'inode:2',
    genericUnary: 'inode:3',
    nativeV2Stream: 'inode:4'
  }))
  t.exception(() => assertLocalForwardHttpsSocketSeparationV4({
    sourceOrigin: 'inode:1',
    targetIngress: 'inode:1',
    genericUnary: 'inode:3',
    nativeV2Stream: 'inode:4'
  }), /must not alias/)
  t.exception(() => decodeLocalForwardHttpsSourceOriginTranscriptV4(vector('positive/target-ingress-v4.bin'), { eof: true }), /exactly 65976/)
  t.exception(() => decodeLocalForwardHttpsTargetIngressTranscriptV4(vector('positive/source-origin-authority-v4.bin'), { eof: true }), /exactly 65828/)
})

test('role-separated journal model covers replay, capacity, crash ambiguity, tamper, restart, and clock regression', t => {
  const tuple = vector('positive/source-replay-tuple-v4.bin')
  const journal = new LocalForwardHttpsReplayJournalModelV4('SOURCE_ORIGIN', { capacity: 1 })
  const key = journal.reserve(tuple, 1000n, 16_000n, 1000n)
  journal.commit(key)
  t.exception(() => journal.reserve(tuple, 1000n, 16_000n, 1001n), /already exists/)
  t.exception(() => journal.reserve(b4a.alloc(32, 99), 1000n, 16_000n, 1001n), /capacity/)
  const restarted = LocalForwardHttpsReplayJournalModelV4.restart(
    journal.crashSnapshot(),
    restartOptions('SOURCE_ORIGIN', 1, 1001n)
  )
  t.is(restarted.namespace, 'SOURCE_ORIGIN')
  t.is(restarted.quarantined, false)

  const pending = new LocalForwardHttpsReplayJournalModelV4('TARGET_INGRESS')
  pending.reserve(vector('positive/target-replay-tuple-v4.bin'), 2000n, 17_000n, 2000n)
  t.is(LocalForwardHttpsReplayJournalModelV4.restart(
    pending.crashSnapshot(),
    restartOptions('TARGET_INGRESS', 4096, 2000n)
  ).quarantined, true)

  const snapshot = journal.crashSnapshot()
  const tampered = { payload: b4a.from(snapshot.payload), checksum: snapshot.checksum }
  tampered.payload[0] ^= 1
  t.is(LocalForwardHttpsReplayJournalModelV4.restart(tampered, restartOptions('SOURCE_ORIGIN', 1, 1001n)).quarantined, true)

  const clock = new LocalForwardHttpsReplayJournalModelV4('SOURCE_ORIGIN')
  const first = clock.reserve(b4a.alloc(32, 1), 1000n, 16_000n, 2000n)
  t.is(errorFrom(() => clock.reserve(b4a.alloc(32, 2), 1000n, 16_000n, 1999n)).code, 'PRIVATE_IPC_V4_CLOCK_REGRESSION')
  t.is(clock.quarantined, true)
  const before = clock.inspectEntries()
  t.is(errorFrom(() => clock.commit(first)).code, 'PRIVATE_IPC_V4_JOURNAL_QUARANTINED')
  t.alike(clock.inspectEntries(), before)
  const persisted = LocalForwardHttpsReplayJournalModelV4.restart(
    clock.crashSnapshot(),
    restartOptions('SOURCE_ORIGIN', 4096, 2000n)
  )
  t.is(persisted.quarantined, true)
})

test('replay restart is total, role-bound, canonical, deadline-safe and defensive', t => {
  const base = {
    version: 1,
    namespace: 'SOURCE_ORIGIN',
    capacity: 2,
    lastMonotonicMillis: '2000',
    quarantined: false,
    records: [
      { key: '01'.repeat(32), accepted: '1000', deadline: '16000', state: 'CONSUMED' },
      { key: '02'.repeat(32), accepted: '1001', deadline: '16001', state: 'CONSUMED' }
    ]
  }
  const options = restartOptions('SOURCE_ORIGIN', 2, 2000n)
  const valid = LocalForwardHttpsReplayJournalModelV4.restart(journalSnapshot(base), options)
  t.is(valid.quarantined, false)
  t.is(valid.size, 2)
  const inspected = valid.inspectEntries()
  t.ok(Object.isFrozen(inspected))
  t.ok(Object.isFrozen(inspected[0]))
  t.is(valid.inspectEntries()[0].key, '01'.repeat(32))

  const malformed = [
    null,
    journalSnapshot('{'),
    journalSnapshot({ ...base, version: 2 }),
    journalSnapshot({ namespace: base.namespace, version: 1, capacity: 2, lastMonotonicMillis: '2000', quarantined: false, records: [] }),
    journalSnapshot({ ...base, namespace: 'TARGET_INGRESS' }),
    journalSnapshot({ ...base, capacity: 1 }),
    journalSnapshot({ ...base, lastMonotonicMillis: 'not-u64' }),
    journalSnapshot({ ...base, lastMonotonicMillis: '-1' }),
    journalSnapshot({ ...base, lastMonotonicMillis: ((1n << 64n) + 1n).toString() }),
    journalSnapshot({ ...base, lastMonotonicMillis: '2001' }),
    journalSnapshot({ ...base, quarantined: true }),
    journalSnapshot({ ...base, records: {} }),
    journalSnapshot({ ...base, records: [base.records[0], base.records[0]] }),
    journalSnapshot({ ...base, records: [...base.records].reverse() }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], key: 'GG'.repeat(32) }] }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], state: 'UNKNOWN' }] }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], state: 'PENDING' }] }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], deadline: '1000' }] }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], deadline: '16001' }] }),
    journalSnapshot({ ...base, records: [{ ...base.records[0], accepted: '2001' }] }),
    journalSnapshot({ ...base, records: [{ accepted: '1000', key: base.records[0].key, deadline: '16000', state: 'CONSUMED' }] })
  ]
  for (const snapshot of malformed) {
    const restarted = LocalForwardHttpsReplayJournalModelV4.restart(snapshot, options)
    t.is(restarted.namespace, 'SOURCE_ORIGIN')
    t.is(restarted.capacity, 2)
    t.is(restarted.quarantined, true)
  }
  const roleForged = LocalForwardHttpsReplayJournalModelV4.restart(
    journalSnapshot(base),
    restartOptions('TARGET_INGRESS', 2, 2000n)
  )
  t.is(roleForged.namespace, 'TARGET_INGRESS')
  t.is(roleForged.quarantined, true)
  const expired = LocalForwardHttpsReplayJournalModelV4.restart(
    journalSnapshot(base),
    restartOptions('SOURCE_ORIGIN', 2, 20_000n)
  )
  t.is(expired.quarantined, false)
  t.is(expired.size, 0)
})

test('replacement target TLS gets a new local tuple but reuses exact durable target claim and result', t => {
  const first = decodeLocalForwardHttpsTargetIngressV4(vector('positive/target-ingress-v4.bin'))
  const replacement = decodeLocalForwardHttpsTargetIngressV4(vector('positive/replacement-target-ingress-v4.bin'))
  t.alike(first.body, replacement.body)
  t.not(first.targetTlsExporterBindingHash, replacement.targetTlsExporterBindingHash)
  t.not(first.targetLocalExchangeId, replacement.targetLocalExchangeId)
  t.not(localForwardHttpsTargetReplayTupleV4(first), localForwardHttpsTargetReplayTupleV4(replacement))
  const claims = new LocalForwardHttpsTargetClaimModelV4()
  t.is(claims.claim(first.body).disposition, 'CLAIMED')
  const result = vector('positive/target-result-turn-v4.bin').subarray(148)
  claims.persistResult(first.body, result)
  const retry = claims.claim(replacement.body)
  t.is(retry.disposition, 'EXACT_RETRY')
  t.alike(retry.resultBytes, result)
})

test('target claim fail-closes DATA-before-OPEN and invalid capability or source signatures before mutation', t => {
  const open = wireVector('positive/open-forwarded-role.bin')
  const badCapability = b4a.from(open)
  badCapability[472] ^= 1
  const badSource = b4a.from(open)
  badSource[600] ^= 1
  for (const input of [
    wireVector('positive/data-forwarded-role.bin'),
    badCapability,
    badSource
  ]) {
    const claims = new LocalForwardHttpsTargetClaimModelV4()
    const error = errorFrom(() => claims.claim(input))
    t.is(error.code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
    t.is(claims.terminal, true)
    t.is(claims.terminalReason, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
    t.is(claims.claimCount, 0)
    t.is(claims.stableSessionId, null)
    t.is(errorFrom(() => claims.claim(open)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
    t.is(claims.claimCount, 0)
  }
})

test('target claim rejects second OPEN, sequence gaps, bad chains, forks and unresolved outstanding requests', t => {
  const open = wireVector('positive/open-forwarded-role.bin')
  const data = wireVector('positive/data-forwarded-role.bin')

  const secondOpen = resignForwarded(open, request => {
    request.requestNonce = b4a.from(request.requestNonce)
    request.requestNonce[0] ^= 1
  })
  const secondOpenClaims = openedTargetClaims()
  const originalOpen = secondOpenClaims.inspectClaim(open)
  t.is(errorFrom(() => secondOpenClaims.claim(secondOpen)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.alike(secondOpenClaims.inspectClaim(open), originalOpen)

  const gap = resignForwarded(data, request => { request.sequence = 2n })
  const gapClaims = openedTargetClaims()
  t.is(errorFrom(() => gapClaims.claim(gap)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.is(gapClaims.claimCount, 1)
  t.is(gapClaims.nextSequence, 1n)

  const badChain = resignForwarded(data, request => {
    request.previousTargetResultHash = b4a.from(request.previousTargetResultHash)
    request.previousTargetResultHash[0] ^= 1
  })
  const chainClaims = openedTargetClaims()
  t.is(errorFrom(() => chainClaims.claim(badChain)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.is(chainClaims.claimCount, 1)
  t.is(chainClaims.nextSequence, 1n)

  const forkClaims = openedTargetClaims()
  t.is(forkClaims.claim(data).disposition, 'CLAIMED')
  const originalData = forkClaims.inspectClaim(data)
  t.is(errorFrom(() => forkClaims.claim(wireVector('positive/window-forwarded-role.bin'))).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.alike(forkClaims.inspectClaim(data), originalData)
  t.is(forkClaims.claimCount, 2)

  const outstandingClaims = new LocalForwardHttpsTargetClaimModelV4()
  t.is(outstandingClaims.claim(open).disposition, 'CLAIMED')
  const outstandingOpen = outstandingClaims.inspectClaim(open)
  t.is(errorFrom(() => outstandingClaims.claim(data)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.alike(outstandingClaims.inspectClaim(open), outstandingOpen)
  t.is(outstandingClaims.claimCount, 1)
  t.is(outstandingClaims.nextSequence, 0n)
})

test('target result persistence rejects mismatch and invalid signatures without overwriting the original claim', t => {
  const open = wireVector('positive/open-forwarded-role.bin')
  const result = wireVector('positive/open-target-open-accept.bin')

  const mismatch = new LocalForwardHttpsTargetClaimModelV4()
  mismatch.claim(open)
  const beforeMismatch = mismatch.inspectClaim(open)
  t.is(errorFrom(() => mismatch.persistResult(open, wireVector('positive/data-target-ack.bin'))).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.alike(mismatch.inspectClaim(open), beforeMismatch)
  t.is(mismatch.nextSequence, 0n)
  t.is(errorFrom(() => mismatch.persistResult(open, result)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')

  const badSignature = b4a.from(result)
  badSignature[705] ^= 1
  const invalid = new LocalForwardHttpsTargetClaimModelV4()
  invalid.claim(open)
  const beforeInvalid = invalid.inspectClaim(open)
  t.is(errorFrom(() => invalid.persistResult(open, badSignature)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.alike(invalid.inspectClaim(open), beforeInvalid)
  t.is(invalid.nextSequence, 0n)

  const exact = new LocalForwardHttpsTargetClaimModelV4()
  exact.claim(open)
  t.alike(exact.persistResult(open, result), result)
  t.alike(exact.persistResult(open, result), result)
  const retry = exact.claim(open)
  t.is(retry.disposition, 'EXACT_RETRY')
  t.alike(retry.resultBytes, result)
  t.is(exact.claimCount, 1)
  t.is(exact.nextSequence, 1n)
})

test('target FIN is not normal close, while a CLOSE request closes only after its definitive result', t => {
  const poll = wireVector('positive/poll-forwarded-role.bin')
  const pollClose = wireVector('positive/poll-target-close.bin')
  const targetFin = openedTargetClaims()
  t.is(targetFin.claim(poll).disposition, 'CLAIMED')
  targetFin.persistResult(poll, pollClose)
  t.is(targetFin.targetFin, true)
  t.is(targetFin.closed, false)
  t.is(targetFin.nextSequence, 2n)
  const afterTargetFin = resignForwarded(poll, request => {
    request.sequence = 2n
    request.previousTargetResultHash = forwardHttpsTargetResultChainHashV1(pollClose)
  })
  t.is(targetFin.claim(afterTargetFin).disposition, 'CLAIMED')

  const close = wireVector('positive/close-forwarded-role.bin')
  const closeAck = wireVector('positive/close-target-ack.bin')
  const normalClose = openedTargetClaims()
  normalClose.claim(close)
  normalClose.persistResult(close, closeAck)
  t.is(normalClose.closed, true)
  t.is(normalClose.targetFin, false)
  t.is(normalClose.nextSequence, 2n)
  t.is(normalClose.claim(close).disposition, 'EXACT_RETRY')
  const postClose = resignForwarded(wireVector('positive/data-forwarded-role.bin'), request => {
    request.sequence = 2n
    request.previousTargetResultHash = forwardHttpsTargetResultChainHashV1(closeAck)
  })
  t.is(errorFrom(() => normalClose.claim(postClose)).code, 'TERMINAL_FORWARD_HTTPS_TARGET_CLAIM')
  t.is(normalClose.closed, true)
  t.is(normalClose.claimCount, 2)
})

test('target claim getters, inspections and completed retry results are defensive', t => {
  const open = wireVector('positive/open-forwarded-role.bin')
  const result = wireVector('positive/open-target-open-accept.bin')
  const claims = openedTargetClaims()
  const stable = claims.stableSessionId
  const stableExpected = b4a.from(stable)
  stable[0] ^= 1
  t.alike(claims.stableSessionId, stableExpected)
  const previous = claims.previousTargetResultHash
  const previousExpected = b4a.from(previous)
  previous[0] ^= 1
  t.alike(claims.previousTargetResultHash, previousExpected)

  const inspected = claims.inspectClaim(open)
  inspected.requestBytes[0] ^= 1
  inspected.commitment[0] ^= 1
  inspected.resultBytes[0] ^= 1
  const retained = claims.inspectClaim(open)
  t.alike(retained.requestBytes, open)
  t.alike(retained.resultBytes, result)

  const retry = claims.claim(open)
  retry.resultBytes[0] ^= 1
  t.alike(claims.claim(open).resultBytes, result)
  t.is(claims.claimCount, 1)
})

test('replacement source TLS authority cannot alter exact origin bytes or public commitment', t => {
  const first = decodeLocalForwardHttpsOriginAuthorityV4(vector('positive/source-origin-authority-v4.bin'))
  const replacement = decodeLocalForwardHttpsOriginAuthorityV4(vector('positive/replacement-source-authority-v4.bin'))
  t.not(first.tlsExporterBindingHash, replacement.tlsExporterBindingHash)
  t.not(first.localExchangeId, replacement.localExchangeId)
  t.alike(first.originRequestCommitment, replacement.originRequestCommitment)
  t.alike(first.stableSessionId, replacement.stableSessionId)
  t.is(first.sequence, replacement.sequence)
  t.not(localForwardHttpsSourceReplayTupleV4(first), localForwardHttpsSourceReplayTupleV4(replacement))
})

test('private IPC v4 exposes model-only authority and never claims runtime durability', t => {
  const authority = JSON.parse(read('hiverelay-blind-private-ipc-authority-v4.json'))
  t.is(authority.modelOnly, true)
  t.is(authority.runtimeReleaseReady, false)
  t.is(authority.authorizesRelease, false)
  t.is(authority.forwardDescriptorOperationBits, 0)
  t.is(authority.forwardAdvertisedOperationBits, 0)
  t.is(authority.forwardReadinessOperationBits, 0)
  t.is(PRIVATE_IPC_V4_LIMITS.REPLAY_CAPACITY, 4096)
  t.is(PRIVATE_IPC_V4_LIMITS.MAX_DEADLINE_MILLIS, 15_000)
  const target = decodeLocalForwardHttpsTargetIngressV4(vector('positive/target-ingress-v4.bin'))
  for (const forbidden of ['tlsExporter', 'sourceAddress', 'url', 'host', 'ip', 'cookies', 'authorization', 'credentials', 'appMetadata']) {
    t.absent(target[forbidden])
  }
  const turn = decodeLocalForwardHttpsTurnV4(vector('positive/source-result-error-v4.bin'))
  t.is(turn.direction, LOCAL_FORWARD_HTTPS_DIRECTION_V4.RESULT)
  t.is(turn.wireRole, FORWARD_HTTPS_RESULT_ROLE_V1.SOURCE_PRE_FORWARD_ERROR)
})
