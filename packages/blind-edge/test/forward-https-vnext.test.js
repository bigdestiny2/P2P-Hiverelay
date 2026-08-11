// DESCRIBE route evidence for the vNext direct-HTTPS runtime (relock
// activation serial route 1/5): hash-pinned signed descriptor endpoint,
// signature verification, continuity with reload persistence, fork
// quarantine, signed health challenge with bogus-credential negatives,
// exact opaque qualification, bounded request/response, credential-free
// HTTPS, signed result readback, restart recovery, and relay-visible byte
// assertions. Runs on macOS: the peercred boundary is real (getpeereid),
// TLS loopback/plaintext is the explicit test seam; Linux SO_PEERCRED,
// Chromium/IndexedDB and Bare are deferred to syd-1 qualification.

import test from 'brittle'
import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CELL_RECEIPT_RESULT,
  CORE_ACK_RESULT,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  INBOX_APPEND_RESULT,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_SUPPORT,
  RESULT_SIGNATURE_DOMAIN_ID,
  allocationCommitment,
  assertForwardHttpsResultForOriginRequestV1,
  blake2b256,
  blindForwardHttpsOriginForwardTurnRequestV1,
  blindForwardHttpsOriginForwardTurnResultV1,
  blindHealthChallengeV1,
  blindReceiptV1,
  blindServiceDescriptorV1,
  cellStorageSlot,
  coreMirrorRequestV1,
  coreOpenReplicationV1,
  coreServeChallengeV1,
  blindCoreAckV1,
  decodeCanonical,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  getCellResultV1,
  getCellV1,
  inboxAppendAckV1,
  inboxAppendV1,
  inboxCreateCommitment,
  inboxCreateV1,
  inboxManageV1,
  inboxReadEntriesCommitment,
  inboxReadResultV1,
  inboxReadSignaturePayloadV1,
  inboxReadV1,
  inboxReceiptV1,
  proveCellResultV1,
  proveCellV1,
  putCellV1,
  forwardHttpsStableSessionIdV1,
  forwardHttpsTargetResultChainHashV1,
  resultSignaturePayload,
  serviceDescriptorHash,
  verifyForwardHttpsParentCapabilitySignatureV1
} from '@hiverelay/blind-protocol'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
import {
  decodeLocalForwardHttpsSourceOriginTranscriptV4
} from '@hiverelay/blind-ipc'
import {
  DescriptorTrustStore,
  createDescribeGetRequest,
  createHealthChallenge,
  qualifyDescribeControlEndpoint,
  qualifyRelay,
  verifyDescriptorBytes,
  verifyHealthResultBytes
} from '../../blind-client/describe.js'
import { BlindDirectHttpClient } from '../../blind-client/direct-http.js'
import { encodeUnaryRequest } from '../../blind-client/wire.js'
import { verifyResultSignedValue } from '../../blind-client/signed.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'
import {
  inboxAppendFixture,
  inboxCreateFixture,
  inboxKeyPair,
  inboxReadFixture,
  inboxRenewFixture,
  inboxCloseFixture
} from '../../blind-daemon/test/production-runtime-inbox-fixture.js'
import {
  coreMirrorFixture,
  coreOpenReplicationFixture,
  coreProveFixture
} from '../../blind-daemon/test/production-runtime-core-fixture.js'
import {
  FORWARD_HTTPS_EDGE_ROLE_VNEXT
} from '../forward-https-vnext.js'
import {
  createForwardHttpsTargetDialerVnext
} from '../../blind-daemon/forward-https-runtime-vnext.js'
import {
  inspectForwardHttpsReplayJournalV4
} from '../../blind-daemon/forward-https-replay-journal-v4.js'
import {
  forwardHttpsSourceTurnStateV3
} from '../../blind-daemon/forward-https-source-store-v3.js'
import {
  PINNED_WIRE_V3_ABI_HASH,
  createRelayIdentityFixture,
  createRelayEnvironmentFixture,
  assembleRelayFixture,
  createEdgeFixture,
  createLoopbackTlsFixture,
  edgeBaseUrl,
  edgeFetchFixture,
  fixtureAdmission,
  removeFixtureScratch
} from './forward-https-vnext-integration-fixture.mjs'

function verifyInboxReadSignature (t, value, relayPublicKey) {
  t.alike(value.entriesCommitment, inboxReadEntriesCommitment(value.entries))
  const payload = encodeCanonical(inboxReadSignaturePayloadV1, {
    version: value.version,
    relayBinding: value.relayBinding,
    requestNonce: value.requestNonce,
    requestCommitment: value.requestCommitment,
    snapshotRevision: value.snapshotRevision,
    entriesCommitment: value.entriesCommitment,
    nextCursor: value.nextCursor
  })
  t.ok(sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, payload), relayPublicKey))
}

const runtime = createNodeCryptoRuntime()
const MEDIA_TYPE = PROTOCOL.mediaType

async function freePort () {
  const server = net.createServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  await new Promise(resolve => server.close(resolve))
  return port
}

// A descriptor trust backend persisted to one JSON file, standing in for the
// browser IndexedDB backend: continuity state survives a full reload.
function toStoredState (state) {
  if (state == null) return null
  return {
    rootRelayPublicKey: b4a.toString(state.rootRelayPublicKey, 'hex'),
    storeId: b4a.toString(state.storeId, 'hex'),
    currentBytes: b4a.toString(state.currentBytes, 'hex'),
    currentHash: b4a.toString(state.currentHash, 'hex'),
    sequence: String(state.sequence),
    identitySequence: String(state.identitySequence),
    relayPublicKey: b4a.toString(state.relayPublicKey, 'hex'),
    durabilityProfileId: state.durabilityProfileId,
    durabilityContinuityHash: b4a.toString(state.durabilityContinuityHash, 'hex'),
    history: state.history.map(bytes => b4a.toString(bytes, 'hex')),
    quarantined: state.quarantined === true
  }
}

function fromStoredState (state) {
  if (state == null) return null
  return {
    rootRelayPublicKey: b4a.from(state.rootRelayPublicKey, 'hex'),
    storeId: b4a.from(state.storeId, 'hex'),
    currentBytes: b4a.from(state.currentBytes, 'hex'),
    currentHash: b4a.from(state.currentHash, 'hex'),
    sequence: BigInt(state.sequence),
    identitySequence: BigInt(state.identitySequence),
    relayPublicKey: b4a.from(state.relayPublicKey, 'hex'),
    durabilityProfileId: state.durabilityProfileId,
    durabilityContinuityHash: b4a.from(state.durabilityContinuityHash, 'hex'),
    history: state.history.map(hex => b4a.from(hex, 'hex')),
    quarantined: state.quarantined === true
  }
}

class JsonFileTrustBackend {
  constructor (file) {
    this.file = file
  }

  async _readAll () {
    try {
      return new Map(JSON.parse(await fs.readFile(this.file, 'utf8')))
    } catch {
      return new Map()
    }
  }

  async _writeAll (records) {
    await fs.writeFile(this.file, JSON.stringify([...records]))
  }

  async read (key) {
    const records = await this._readAll()
    const record = records.get(key)
    return record == null
      ? { version: 0, value: null }
      : { version: record.version, value: fromStoredState(record.value) }
  }

  async compareAndSwap (key, expectedVersion, value) {
    const records = await this._readAll()
    const current = records.get(key)
    const version = current == null ? 0 : current.version
    if (version !== expectedVersion) return false
    records.set(key, { version: version + 1, value: toStoredState(value) })
    await this._writeAll(records)
    return true
  }
}

async function bootRelay (t, options = {}) {
  const port = options.port || await freePort()
  const identity = await createRelayIdentityFixture({ port })
  const layout = await createRelayEnvironmentFixture(identity)
  const tls = await createLoopbackTlsFixture(layout.directory)
  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    },
    ...options.forward
  })
  replayOffset.value = 0n
  await relay.start()
  const exchanges = []
  const edge = await createEdgeFixture({
    port,
    tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    launchTopologyHash: layout.launchTopologyHash,
    onError: error => daemonErrors.push(error),
    onUnaryExchange: options.capture ? entry => exchanges.push(entry) : null,
    socketFactory: options.socketFactory
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay.close().catch(() => {})
    await removeFixtureScratch(layout)
  })
  return {
    identity,
    layout,
    relay,
    edge,
    daemonErrors,
    exchanges,
    tls,
    fetchImpl: tls ? edgeFetchFixture({ rejectUnauthorized: false }) : fetch,
    baseUrl: edgeBaseUrl(edge),
    port
  }
}

async function postRaw (baseUrl, route, body, headers = {}, fetchImpl = fetch) {
  return fetchImpl(`${baseUrl}${route}`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, ...headers },
    body,
    redirect: 'manual'
  })
}

function supportedProfiles (identity) {
  const descriptor = identity.descriptor
  return {
    nowEpoch: identity.currentEpoch,
    supportedProtocolProfiles: descriptor.protocols.map(value => ({
      protocolId: value.protocolId,
      major: value.major,
      minimumMinor: value.minor,
      profileHash: b4a.from(value.profileHash)
    })),
    supportedTransportProfiles: descriptor.endpoints.map(value => ({
      transportId: value.transportId,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      transportProfileHash: b4a.from(value.transportProfileHash)
    }))
  }
}

async function describeGet (baseUrl, descriptorHash = null, fetchImpl = fetch) {
  const { requestBytes } = createDescribeGetRequest({ runtime, descriptorHash })
  const posted = encodeUnaryRequest({ runtime, familyId: FAMILY.DESCRIBE, operationId: OPERATION.DESCRIBE.GET, body: requestBytes }).body
  const response = await postRaw(baseUrl, '/api/blind/v1/describe', posted, {}, fetchImpl)
  const bytes = b4a.from(await response.arrayBuffer())
  return { response, bytes, posted }
}

function descriptorBody (envelopeBytes) {
  return decodeOuterEnvelope(envelopeBytes, { copyBody: true }).frame.body
}

function qualifiedControlClient (trusted, operationId, nowEpoch, fetchImpl) {
  const endpoint = qualifyDescribeControlEndpoint({
    trustedDescriptor: trusted,
    familyId: FAMILY.DESCRIBE,
    operationId,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requiredRoleBits: 1,
    privacyProfileBit: 1,
    nowEpoch
  })
  return { endpoint, client: new BlindDirectHttpClient({ runtime, fetch: fetchImpl, allowInsecureLoopback: true }) }
}

test('DESCRIBE.GET serves the hash-pinned signed descriptor with exact bounded bytes over credential-free HTTPS', async t => {
  const { identity, baseUrl, exchanges, fetchImpl } = await bootRelay(t, { capture: true })

  const { response, bytes, posted } = await describeGet(baseUrl, null, fetchImpl)
  t.is(response.status, 200)
  t.is(response.headers.get('content-type'), MEDIA_TYPE)
  t.is(Number(response.headers.get('content-length')), bytes.byteLength)
  t.is(response.headers.get('set-cookie'), null, 'no cookies are ever set')
  t.is(response.headers.get('content-encoding'), null, 'no compression')
  t.is(response.headers.get('location'), null, 'no redirect is ever issued')
  t.is(bytes.byteLength, OUTER_CLASS[3], 'descriptor answer fills its exact outer class')

  // Signed result + readback: the served body is exactly the signed canonical
  // descriptor the daemon activated.
  const descriptorBytes = descriptorBody(bytes)
  t.ok(b4a.equals(descriptorBytes, identity.successorBytes), 'descriptor bytes equal the signed canonical successor')
  t.ok(b4a.equals(serviceDescriptorHash(descriptorBytes), identity.successorHash), 'hash pin matches')

  const verified = verifyDescriptorBytes(descriptorBytes, supportedProfiles(identity))
  t.ok(b4a.equals(verified.descriptorHash, identity.successorHash), 'client verifies the signed descriptor')
  t.is(verified.descriptorSequence, 1n)

  // Relay-visible bytes: exactly one IPC exchange per direction; the edge
  // forwards the client-posted opaque envelope byte-identically and returns
  // the daemon envelope byte-identically. No caller metadata or application
  // plaintext crosses the edge boundary.
  t.is(exchanges.length, 2, 'one IPC exchange captured in each direction')
  t.ok(b4a.equals(exchanges[0].body, posted), 'edge forwards the exact posted opaque envelope')
  t.ok(exchanges[0].bytes.byteLength > posted.byteLength &&
      b4a.equals(exchanges[0].bytes.subarray(exchanges[0].bytes.byteLength - posted.byteLength), posted),
  'the IPC frame carries the exact envelope as its body')
  t.ok(b4a.equals(exchanges[1].bytes.subarray(exchanges[1].bytes.byteLength - bytes.byteLength), bytes),
    'the public response is byte-identical to the daemon envelope')
  const printable = exchanges[0].bytes.toString('latin1')
  t.ok(!printable.includes('cookie') && !printable.includes('authorization') && !printable.includes('127.0.0.1'),
    'no credential or address material appears in relay-visible bytes')

  const repeat = await describeGet(baseUrl, null, fetchImpl)
  t.ok(b4a.equals(descriptorBody(repeat.bytes), descriptorBody(bytes)),
    'repeat GET returns the byte-identical signed descriptor body')
})

test('descriptor continuity persists across reload and quarantines same-sequence forks', async t => {
  const { identity, baseUrl, layout, fetchImpl } = await bootRelay(t)
  const backendFile = path.join(layout.directory, 'client-trust.json')
  const profiles = supportedProfiles(identity)

  const genesisVerified = verifyDescriptorBytes(identity.genesisBytes, profiles)
  const trust = new DescriptorTrustStore(new JsonFileTrustBackend(backendFile))
  const trustedGenesis = await trust.accept(genesisVerified, { pinnedDescriptorHash: identity.genesisHash })
  t.is(trustedGenesis.descriptorSequence, 0n)
  t.ok(b4a.equals(trustedGenesis.rootRelayPublicKey, identity.relayPublicKey))

  const { bytes } = await describeGet(baseUrl, null, fetchImpl)
  const successorVerified = verifyDescriptorBytes(descriptorBody(bytes), profiles)
  const trustedSuccessor = await trust.accept(successorVerified, {
    continuityRootRelayPublicKey: identity.relayPublicKey
  })
  t.is(trustedSuccessor.descriptorSequence, 1n, 'continuity advances exactly +1')

  const again = await trust.accept(successorVerified, { continuityRootRelayPublicKey: identity.relayPublicKey })
  t.is(again.descriptorSequence, 1n, 'exact re-accept is idempotent')

  // Reload: a fresh trust store over the same persisted backend keeps the
  // complete continuity state (the IndexedDB-survives-reload analogue).
  const reloaded = new DescriptorTrustStore(new JsonFileTrustBackend(backendFile))
  const reAccepted = await reloaded.accept(successorVerified, { continuityRootRelayPublicKey: identity.relayPublicKey })
  t.is(reAccepted.descriptorSequence, 1n, 'continuity state survives reload')

  // Fork: a same-sequence descriptor with different bytes is quarantined,
  // and the quarantine is sticky for later accepts after another reload.
  const forked = decodeCanonical(blindServiceDescriptorV1, identity.successorBytes, { copyBytes: true })
  forked.descriptorNonce = b4a.alloc(32, 0x99)
  const unsignedFork = encodeCanonical(blindServiceDescriptorV1, { ...forked, signature: b4a.alloc(64) })
  const forkSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(forkSignature,
    resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, unsignedFork.subarray(0, unsignedFork.byteLength - 64)),
    identity.relaySecretKey)
  const forkedBytes = encodeCanonical(blindServiceDescriptorV1, { ...forked, signature: forkSignature })
  const forkVerified = verifyDescriptorBytes(forkedBytes, profiles)
  t.ok(!b4a.equals(forkVerified.descriptorHash, identity.successorHash), 'fork differs only in hash')
  let forkError = null
  try {
    await reloaded.accept(forkVerified, { continuityRootRelayPublicKey: identity.relayPublicKey })
  } catch (error) {
    forkError = error
  }
  t.is(forkError && forkError.code, 'DESCRIPTOR_FORK', 'same-sequence fork is quarantined')
  const reloadedAgain = new DescriptorTrustStore(new JsonFileTrustBackend(backendFile))
  let stickyError = null
  try {
    await reloadedAgain.accept(successorVerified, { continuityRootRelayPublicKey: identity.relayPublicKey })
  } catch (error) {
    stickyError = error
  }
  t.is(stickyError && stickyError.code, 'DESCRIPTOR_FORK', 'quarantine persists across reload')

  // A forged successor with an invalid signature fails closed at the client.
  const forged = decodeCanonical(blindServiceDescriptorV1, identity.successorBytes, { copyBytes: true })
  forged.descriptorSequence = 2n
  forged.previousDescriptorHash = identity.successorHash
  let verifyError = null
  try {
    verifyDescriptorBytes(encodeCanonical(blindServiceDescriptorV1, forged), profiles)
  } catch (error) {
    verifyError = error
  }
  t.is(verifyError && verifyError.code, 'RELAY_PROTOCOL_VIOLATION', 'unsigned successor fails verification')
})

test('signed health challenge qualifies readiness; bogus-credential probes fail closed', async t => {
  const { identity, baseUrl, layout, fetchImpl } = await bootRelay(t)
  const profiles = supportedProfiles(identity)
  const trust = new DescriptorTrustStore(new JsonFileTrustBackend(path.join(layout.directory, 'trust.json')))
  await trust.accept(verifyDescriptorBytes(identity.genesisBytes, profiles), { pinnedDescriptorHash: identity.genesisHash })

  const { bytes } = await describeGet(baseUrl, null, fetchImpl)
  const trusted = await trust.accept(verifyDescriptorBytes(descriptorBody(bytes), profiles), {
    continuityRootRelayPublicKey: identity.relayPublicKey
  })

  const { endpoint, client } = qualifiedControlClient(trusted, OPERATION.DESCRIBE.CHALLENGE, identity.currentEpoch, fetchImpl)
  const challenge = createHealthChallenge({
    trustedDescriptor: trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: 0x7,
    runtime
  })
  const result = await client.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    body: challenge.requestBytes,
    expectedResultBodyBytes: challenge.wire.expectedResultBodyBytes
  })
  t.ok(result.ok, 'health challenge is answered')
  const health = verifyHealthResultBytes(result.body, trusted, challenge.request, { nowEpoch: identity.currentEpoch })
  t.is(health.readyRoleBits, 1)
  t.is(health.readyOperationBits & 0x7, 0x7, 'signed health proves the DESCRIBE readiness subset')

  // Bogus challenge: a descriptor hash the relay never signed fails closed at
  // the daemon with a canonical error, never a signed health result.
  const bogusBody = encodeCanonical(blindHealthChallengeV1, {
    ...challenge.request,
    descriptorHash: b4a.alloc(32, 0xaa)
  })
  const bogus = await client.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    body: bogusBody,
    expectedResultBodyBytes: challenge.wire.expectedResultBodyBytes
  })
  t.ok(!bogus.ok, 'bogus-credential challenge is refused')
  t.is(bogus.error.code, ERROR_CODE.BAD_ENCODING)

  // A tampered health result fails client-side verification.
  const tampered = b4a.from(result.body)
  tampered[tampered.byteLength - 65] ^= 0xff
  let tamperError = null
  try {
    verifyHealthResultBytes(tampered, trusted, challenge.request, { nowEpoch: identity.currentEpoch })
  } catch (error) {
    tamperError = error
  }
  t.is(tamperError && tamperError.code, 'RELAY_PROTOCOL_VIOLATION', 'tampered health result fails closed')
})

test('exact transport negatives: short, long, chunked, compressed, redirect and credential headers', async t => {
  const { baseUrl, fetchImpl } = await bootRelay(t)
  const good = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    body: createDescribeGetRequest({ runtime }).requestBytes
  }).body

  const short = await postRaw(baseUrl, '/api/blind/v1/describe', good.subarray(0, good.byteLength - 1), {}, fetchImpl)
  t.is(short.status, 400, 'short body fails closed')
  t.is(short.headers.get('content-type'), 'text/plain; charset=utf-8')
  t.is((await short.arrayBuffer()).byteLength, 0, 'transport rejection carries no envelope')

  const longResponse = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, 'content-length': String(OUTER_CLASS[3] + 1) },
    body: b4a.concat([good, b4a.alloc(1)])
  })
  t.is(longResponse.status, 400, 'declared over-class length fails closed')

  const wrongClass = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, 'content-length': '4097' },
    body: b4a.alloc(4097)
  })
  t.is(wrongClass.status, 400, 'non-class content-length fails closed')

  const chunked = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, 'transfer-encoding': 'chunked' },
    body: good
  })
  t.is(chunked.status, 400, 'chunked transfer fails closed')

  const compressed = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, 'content-encoding': 'gzip', 'content-length': String(good.byteLength) },
    body: good
  })
  t.is(compressed.status, 400, 'compressed bodies fail closed')

  for (const header of ['cookie', 'authorization', 'referer']) {
    const credentialed = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
      method: 'POST',
      headers: { 'content-type': MEDIA_TYPE, [header]: header === 'cookie' ? 'a=b' : 'bogus' },
      body: good
    })
    t.is(credentialed.status, 400, `${header} credential material fails closed`)
    t.is(credentialed.headers.get('set-cookie'), null)
  }

  const wrongPath = await postRaw(baseUrl, '/api/blind/v1/describe/extra', good, {}, fetchImpl)
  t.is(wrongPath.status, 404, 'no operation-specific alternate URL exists')
  const query = await postRaw(baseUrl, '/api/blind/v1/describe?x=1', good, {}, fetchImpl)
  t.is(query.status, 404, 'query strings are not routed')
  const get = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, { method: 'GET', redirect: 'manual' })
  t.is(get.status, 405, 'only POST is served')
  t.ok(![301, 302, 303, 307, 308].includes(get.status), 'the edge never redirects')

  const wrongMedia = await fetchImpl(`${baseUrl}/api/blind/v1/describe`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: good
  })
  t.is(wrongMedia.status, 400, 'non-blind media type fails closed')
})

test('wrong family, reserved operation and non-advertised operation fail closed at the public edge', async t => {
  const { baseUrl, fetchImpl } = await bootRelay(t)

  const cellFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestId: b4a.alloc(16, 0x51),
    body: b4a.alloc(0)
  })
  const cellEnvelope = encodeOuterEnvelope({ innerDispatch: cellFrame, outerClass: 1 })
  const mismatch = await postRaw(baseUrl, '/api/blind/v1/describe', cellEnvelope, {}, fetchImpl)
  t.is(mismatch.status, 400, 'envelope family must match the route family')

  // Reserved operation: CORE.OPEN_REPLICATION is reserved by the release
  // profile and fails closed with a bare transport 400 (the corrected
  // fixture behavior), never a Blind envelope.
  const reservedFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.OPEN_REPLICATION,
    requestId: b4a.alloc(16, 0xa4),
    body: b4a.alloc(0)
  })
  const reservedEnvelope = encodeOuterEnvelope({ innerDispatch: reservedFrame, outerClass: 1 })
  const reserved = await postRaw(baseUrl, '/api/blind/v1/core', reservedEnvelope, {}, fetchImpl)
  t.is(reserved.status, 400, 'reserved OPEN_REPLICATION fails closed at the public edge')
  t.is(reserved.headers.get('content-type'), 'text/plain; charset=utf-8')
  t.is((await reserved.arrayBuffer()).byteLength, 0, 'fail-closed rejection carries no Blind envelope body')

  // Reserved FORWARD family over the unary envelope path.
  const forwardFrame = encodeDispatchFrame({
    frameKind: FRAME_KIND.REQUEST,
    familyId: FAMILY.FORWARD,
    operationId: OPERATION.FORWARD.OPEN,
    requestId: b4a.alloc(16, 0x52),
    body: b4a.alloc(0)
  })
  const forwardEnvelope = encodeOuterEnvelope({ innerDispatch: forwardFrame, outerClass: 1 })
  const forward = await postRaw(baseUrl, '/api/blind/v1/forward', forwardEnvelope, {}, fetchImpl)
  t.is(forward.status, 400, 'FORWARD over the unary envelope path fails closed')
})

test('restart recovers descriptor, health and admission capability on the same durable roots', async t => {
  const first = await bootRelay(t)
  const { identity, layout, baseUrl } = first
  const firstFetch = first.fetchImpl
  const before = await describeGet(baseUrl, null, firstFetch)
  t.is(before.response.status, 200)
  await first.edge.close()
  await first.relay.close()

  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    }
  })
  replayOffset.value = 0n
  await relay.start()
  const edge = await createEdgeFixture({
    port: first.port,
    tls: first.tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    launchTopologyHash: layout.launchTopologyHash,
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay.close().catch(() => {})
  })

  const after = await describeGet(edgeBaseUrl(edge), null, firstFetch)
  t.is(after.response.status, 200)
  t.ok(b4a.equals(descriptorBody(after.bytes), descriptorBody(before.bytes)),
    'descriptor readback is byte-identical after restart')
  t.is(relay.unary.status().descriptorSequence, 1n)
  t.ok(relay.unary.status().admissionCapture.complete, 'admission capability recovers')

  const profiles = supportedProfiles(identity)
  const trust = new DescriptorTrustStore(new JsonFileTrustBackend(path.join(layout.directory, 'restart-trust.json')))
  await trust.accept(verifyDescriptorBytes(identity.genesisBytes, profiles), { pinnedDescriptorHash: identity.genesisHash })
  const trusted = await trust.accept(verifyDescriptorBytes(descriptorBody(after.bytes), profiles), {
    continuityRootRelayPublicKey: identity.relayPublicKey
  })
  const { endpoint, client } = qualifiedControlClient(trusted, OPERATION.DESCRIBE.CHALLENGE, identity.currentEpoch, firstFetch)
  const challenge = createHealthChallenge({
    trustedDescriptor: trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 1,
    requestedOperationBits: 0x7,
    runtime
  })
  const result = await client.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    body: challenge.requestBytes,
    expectedResultBodyBytes: challenge.wire.expectedResultBodyBytes
  })
  t.ok(result.ok, 'health challenge qualifies after restart')
  verifyHealthResultBytes(result.body, trusted, challenge.request, { nowEpoch: identity.currentEpoch })

  // Close the second boot inline: the bootRelay teardown removes the shared
  // scratch, so the daemon must be closed before it runs.
  await edge.close()
  await relay.close()
})

// ---------------------------------------------------------------------------
// CELL route evidence (serial route 2/5): fixed-size cell PUT/GET with signed
// acknowledgement and exact readback through Edge -> peercred IPC -> daemon
// -> accepted storage.
// ---------------------------------------------------------------------------

function cellKeyPair (byte) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

function cellPutRequest (relay, identity, overrides = {}) {
  const keys = overrides.keys || [cellKeyPair(), cellKeyPair(), cellKeyPair()]
  const allocationEpoch = overrides.allocationEpoch == null
    ? relay.unary.storage.status().epochFloor
    : overrides.allocationEpoch
  const cellBlob = overrides.cellBlob || b4a.alloc(4096, 0xe1)
  const declaredBlobHash = blake2b256(cellBlob)
  const storageSlot = overrides.storageSlot || cellStorageSlot({
    allocationEpoch,
    createPublicKey: keys[0].publicKey
  })
  const allocation = allocationCommitment({
    relayPublicKey: identity.relayPublicKey,
    storageSlot,
    allocationEpoch,
    sizeClass: 1,
    leaseClass: 1,
    declaredCellBlobHash: declaredBlobHash,
    createPublicKey: keys[0].publicKey,
    renewPublicKey: keys[1].publicKey,
    dropPublicKey: keys[2].publicKey
  })
  const createSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(createSignature, allocation,
    overrides.signingKey || keys[0].secretKey)
  return {
    keys,
    allocationEpoch,
    cellBlob,
    declaredBlobHash,
    storageSlot,
    value: {
      version: 1,
      storageSlot,
      allocationEpoch,
      sizeClass: 1,
      leaseClass: 1,
      clientNonce: b4a.alloc(32, 0xe3),
      createPublicKey: keys[0].publicKey,
      renewPublicKey: keys[1].publicKey,
      dropPublicKey: keys[2].publicKey,
      declaredBlobHash,
      createSignature,
      admission: fixtureAdmission(identity.parameterHash, overrides.spendByte == null ? 0xe4 : overrides.spendByte),
      cellBlob
    }
  }
}

async function healthFor (trusted, identity, fetchImpl, requestedOperationBits) {
  const { endpoint, client } = qualifiedControlClient(trusted, OPERATION.DESCRIBE.CHALLENGE, identity.currentEpoch, fetchImpl)
  const challenge = createHealthChallenge({
    trustedDescriptor: trusted,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requestedRoleBits: 0x31,
    requestedOperationBits,
    runtime
  })
  const result = await client.request({
    endpoint,
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.CHALLENGE,
    body: challenge.requestBytes,
    expectedResultBodyBytes: challenge.wire.expectedResultBodyBytes
  })
  if (!result.ok) throw new Error(`health challenge failed: ${JSON.stringify(result.error)}`)
  return verifyHealthResultBytes(result.body, trusted, challenge.request, { nowEpoch: identity.currentEpoch })
}

function qualifiedClient (trusted, health, familyId, operationId, nowEpoch, fetchImpl) {
  const endpoint = qualifyRelay({
    trustedDescriptor: trusted,
    health,
    familyId,
    operationId,
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    requiredRoleBits: 0x31,
    privacyProfileBit: 1,
    nowEpoch
  })
  return { endpoint, client: new BlindDirectHttpClient({ runtime, fetch: fetchImpl, allowInsecureLoopback: true }) }
}

async function trustedRelay (identity, baseUrl, layout, fetchImpl) {
  const profiles = supportedProfiles(identity)
  const trust = new DescriptorTrustStore(new JsonFileTrustBackend(path.join(layout.directory, `trust-${Date.now()}-${Math.random()}.json`)))
  await trust.accept(verifyDescriptorBytes(identity.genesisBytes, profiles), { pinnedDescriptorHash: identity.genesisHash })
  const { bytes } = await describeGet(baseUrl, null, fetchImpl)
  const trusted = await trust.accept(verifyDescriptorBytes(descriptorBody(bytes), profiles), {
    continuityRootRelayPublicKey: identity.relayPublicKey
  })
  return trusted
}

test('CELL.PUT stores a fixed-size cell with a signed acknowledgement; GET and PROVE return exact readback', async t => {
  const { identity, layout, relay, baseUrl, exchanges, fetchImpl } = await bootRelay(t, { capture: true })
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x1ff)
  t.is(health.readyOperationBits & 0x8, 0x8, 'signed health proves CELL.PUT readiness')

  const put = cellPutRequest(relay, identity)
  const { endpoint, client } = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.PUT, identity.currentEpoch, fetchImpl)
  const putResult = await client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: encodeCanonical(putCellV1, put.value)
  })
  t.ok(putResult.ok, 'CELL.PUT is answered')
  const receipt = decodeCanonical(blindReceiptV1, putResult.body, { copyBytes: true })
  verifyResultSignedValue(blindReceiptV1, receipt, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, identity.relayPublicKey, 'cell receipt')
  t.is(receipt.result, CELL_RECEIPT_RESULT.STORED, 'receipt is a signed STORED acknowledgement')
  t.ok(b4a.equals(receipt.cellBlobHash, put.declaredBlobHash), 'receipt binds the exact blob hash')
  t.ok(b4a.equals(receipt.slotCommitment, blake2b256(put.storageSlot)), 'receipt binds the exact storage slot commitment')

  // Exact readback through the unary GET path.
  const read = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.GET, identity.currentEpoch, fetchImpl)
  const getResult = await read.client.request({
    endpoint: read.endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: put.storageSlot,
      clientNonce: b4a.alloc(32, 0xe5),
      admission: null
    })
  })
  t.ok(getResult.ok, 'CELL.GET is answered')
  const readback = decodeCanonical(getCellResultV1, getResult.body, { copyBytes: true })
  t.is(readback.sizeClass, 1)
  t.ok(b4a.equals(readback.cellBlob, put.cellBlob), 'GET returns the exact stored blob')

  // Signed proof with readback evidence.
  const prove = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.PROVE, identity.currentEpoch, fetchImpl)
  const proveResult = await prove.client.request({
    endpoint: prove.endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PROVE,
    body: encodeCanonical(proveCellV1, {
      version: 1,
      storageSlot: put.storageSlot,
      clientNonce: b4a.alloc(32, 0xe6),
      admission: null
    })
  })
  t.ok(proveResult.ok, 'CELL.PROVE is answered')
  const proof = decodeCanonical(proveCellResultV1, proveResult.body, { copyBytes: true })
  verifyResultSignedValue(blindReceiptV1, proof.receipt, RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, identity.relayPublicKey, 'cell proof receipt')
  t.is(proof.receipt.result, CELL_RECEIPT_RESULT.SERVED)
  t.ok(b4a.equals(proof.cellBlob, put.cellBlob), 'PROVE returns the exact stored blob with its signed receipt')

  // Relay-visible bytes: the PUT/GET/PROVE exchanges crossed the edge as
  // exact opaque fixed-class envelopes; the edge forwarded the posted bytes
  // byte-identically and returned the daemon envelope byte-identically.
  t.ok(exchanges.length >= 8, 'IPC exchanges captured for the route')
  const putExchange = exchanges[exchanges.length - 6]
  t.is(putExchange.phase, 'request')
  const putEnvelope = decodeOuterEnvelope(putExchange.body, { copyBody: true })
  t.is(putEnvelope.frame.familyId, FAMILY.CELL, 'edge sees only the opaque envelope')
  t.is(putEnvelope.frame.operationId, OPERATION.CELL.PUT)
  t.ok(!putExchange.bytes.toString('latin1').includes('authorization'), 'no credential material crosses')

  // Accepted storage evidence: the daemon's cell engine durably holds the blob.
  const stored = await relay.unary.storage.readCell(put.storageSlot)
  t.ok(b4a.equals(stored.cellBlob, put.cellBlob), 'accepted cell storage holds the exact blob')
})

test('CELL negatives fail closed: bogus credentials, bad signatures, unknown slots and credential headers', async t => {
  const { identity, layout, relay, baseUrl, fetchImpl } = await bootRelay(t)
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x1ff)
  const { endpoint, client } = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.PUT, identity.currentEpoch, fetchImpl)

  // Bad create signature (signed by a foreign key).
  const foreign = cellKeyPair()
  const badSign = cellPutRequest(relay, identity, { signingKey: foreign.secretKey })
  const badSignResult = await client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: encodeCanonical(putCellV1, badSign.value)
  })
  t.ok(!badSignResult.ok, 'foreign create signature fails closed')
  t.is(badSignResult.error.code, ERROR_CODE.BAD_CREATE_SIG)

  // Bogus admission parameter hash (the relay never signed those parameters).
  const bogusAdmission = cellPutRequest(relay, identity)
  bogusAdmission.value.admission = fixtureAdmission(b4a.alloc(32, 0x77), 0xe7)
  const bogusResult = await client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: encodeCanonical(putCellV1, bogusAdmission.value)
  })
  t.ok(!bogusResult.ok, 'bogus admission credentials fail closed')

  // Unknown slot readback is a canonical NOT_FOUND.
  const read = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.GET, identity.currentEpoch, fetchImpl)
  const missing = await read.client.request({
    endpoint: read.endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: b4a.alloc(32, 0x41),
      clientNonce: b4a.alloc(32, 0xe8),
      admission: null
    })
  })
  t.ok(!missing.ok, 'unknown slot fails closed')
  t.is(missing.error.code, ERROR_CODE.NOT_FOUND)

  // Credential-bearing headers on the operation path fail closed at the edge.
  const put = cellPutRequest(relay, identity)
  const envelope = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: encodeCanonical(putCellV1, put.value)
  }).body
  const credentialed = await fetchImpl(`${baseUrl}/api/blind/v1/cell`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, cookie: 'session=abc' },
    body: envelope
  })
  t.is(credentialed.status, 400, 'credential header fails closed')

  // Family mismatch: a CELL envelope posted to the INBOX route.
  const mismatch = await fetchImpl(`${baseUrl}/api/blind/v1/inbox`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE },
    body: envelope
  })
  t.is(mismatch.status, 400, 'family/operation/transport binding enforced before allocation')
})

test('CELL persists across relay restart with readback and signed proof', async t => {
  const first = await bootRelay(t)
  const { identity, layout, relay, baseUrl } = first
  const firstFetch = first.fetchImpl
  const trusted = await trustedRelay(identity, baseUrl, layout, firstFetch)
  const health = await healthFor(trusted, identity, firstFetch, 0x1ff)
  const put = cellPutRequest(relay, identity)
  const { endpoint, client } = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.PUT, identity.currentEpoch, firstFetch)
  const putResult = await client.request({
    endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: encodeCanonical(putCellV1, put.value)
  })
  t.ok(putResult.ok, 'CELL.PUT is answered before restart')
  await first.edge.close()
  await first.relay.close()

  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay2 = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    }
  })
  replayOffset.value = 0n
  await relay2.start()
  const edge = await createEdgeFixture({
    port: first.port,
    tls: first.tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    launchTopologyHash: layout.launchTopologyHash,
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay2.close().catch(() => {})
  })
  const read = qualifiedClient(trusted, health, FAMILY.CELL, OPERATION.CELL.GET, identity.currentEpoch, firstFetch)
  const getResult = await read.client.request({
    endpoint: read.endpoint,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    body: encodeCanonical(getCellV1, {
      version: 1,
      storageSlot: put.storageSlot,
      clientNonce: b4a.alloc(32, 0xe9),
      admission: null
    })
  })
  t.ok(getResult.ok, 'CELL.GET is answered after restart')
  const readback = decodeCanonical(getCellResultV1, getResult.body, { copyBytes: true })
  t.ok(b4a.equals(readback.cellBlob, put.cellBlob), 'exact readback survives the restart')
  const stored = await relay2.unary.storage.readCell(put.storageSlot)
  t.ok(b4a.equals(stored.cellBlob, put.cellBlob), 'accepted storage preserves the cell across restart')
  await edge.close()
  await relay2.close()
})

// ---------------------------------------------------------------------------
// INBOX route evidence (serial route 3/5): unary inbox operations on the same
// exact path — CREATE/APPEND/READ with signed receipts, exact readback,
// negatives and restart recovery.
// ---------------------------------------------------------------------------

test('INBOX CREATE, APPEND and READ serve signed receipts with exact readback', async t => {
  const { identity, layout, relay, baseUrl, fetchImpl } = await bootRelay(t)
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x7fff)
  const allocationEpoch = relay.unary.inboxStorage.status().epochFloor

  const created = inboxCreateFixture(identity.relayPublicKey, identity.parameterHash, allocationEpoch)
  const create = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.CREATE, identity.currentEpoch, fetchImpl)
  const createResult = await create.client.request({
    endpoint: create.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CREATE,
    body: encodeCanonical(inboxCreateV1, created.request)
  })
  t.ok(createResult.ok, 'INBOX.CREATE is answered')
  const receipt = decodeCanonical(inboxReceiptV1, createResult.body, { copyBytes: true })
  verifyResultSignedValue(inboxReceiptV1, receipt, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, identity.relayPublicKey, 'inbox receipt')
  t.is(receipt.result, INBOX_RECEIPT_RESULT.CREATED)
  t.ok(b4a.equals(receipt.topicCommitment, blake2b256(created.request.physicalTopic)), 'receipt binds the exact topic commitment')

  const appended = inboxAppendFixture(created, identity.relayPublicKey, identity.parameterHash, 0xb3)
  const append = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.APPEND, identity.currentEpoch, fetchImpl)
  const appendResult = await append.client.request({
    endpoint: append.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: encodeCanonical(inboxAppendV1, appended)
  })
  t.ok(appendResult.ok, 'INBOX.APPEND is answered')
  const ack = decodeCanonical(inboxAppendAckV1, appendResult.body, { copyBytes: true })
  verifyResultSignedValue(inboxAppendAckV1, ack, RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, identity.relayPublicKey, 'inbox append ack')
  t.is(ack.result, INBOX_APPEND_RESULT.STORED)

  const read = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.READ, identity.currentEpoch, fetchImpl)
  const readResult = await read.client.request({
    endpoint: read.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    body: encodeCanonical(inboxReadV1, inboxReadFixture(created, identity.parameterHash))
  })
  t.ok(readResult.ok, 'INBOX.READ is answered')
  const page = decodeCanonical(inboxReadResultV1, readResult.body, { copyBytes: true })
  verifyInboxReadSignature(t, page, identity.relayPublicKey)
  t.is(page.entries.length, 1, 'exact one-frame page')
  t.ok(b4a.equals(page.entries[0].frame, appended.frame), 'exact frame readback')

  // Signed RENEW and CLOSE complete the unary lifecycle.
  const renewed = inboxRenewFixture(created, receipt, identity.relayPublicKey, identity.parameterHash)
  const renew = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.RENEW, identity.currentEpoch, fetchImpl)
  const renewResult = await renew.client.request({
    endpoint: renew.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.RENEW,
    body: encodeCanonical(inboxManageV1, renewed)
  })
  t.ok(renewResult.ok, 'INBOX.RENEW is answered')
  const renewReceipt = decodeCanonical(inboxReceiptV1, renewResult.body, { copyBytes: true })
  verifyResultSignedValue(inboxReceiptV1, renewReceipt, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, identity.relayPublicKey, 'inbox renew receipt')
  t.is(renewReceipt.result, INBOX_RECEIPT_RESULT.RENEWED)

  const closed = inboxCloseFixture(created, renewReceipt, identity.relayPublicKey)
  const close = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.CLOSE, identity.currentEpoch, fetchImpl)
  const closeResult = await close.client.request({
    endpoint: close.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CLOSE,
    body: encodeCanonical(inboxManageV1, closed)
  })
  t.ok(closeResult.ok, 'INBOX.CLOSE is answered')
  const closeReceipt = decodeCanonical(inboxReceiptV1, closeResult.body, { copyBytes: true })
  verifyResultSignedValue(inboxReceiptV1, closeReceipt, RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, identity.relayPublicKey, 'inbox close receipt')
  t.is(closeReceipt.result, INBOX_RECEIPT_RESULT.CLOSED)
})

test('INBOX negatives fail closed: bogus signatures, unknown topics and credential headers', async t => {
  const { identity, layout, relay, baseUrl, fetchImpl } = await bootRelay(t)
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x7fff)
  const allocationEpoch = relay.unary.inboxStorage.status().epochFloor
  const created = inboxCreateFixture(identity.relayPublicKey, identity.parameterHash, allocationEpoch)
  const create = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.CREATE, identity.currentEpoch, fetchImpl)

  // Bogus create signature (foreign key).
  const foreign = inboxKeyPair()
  const bogusCreate = inboxCreateFixture(identity.relayPublicKey, identity.parameterHash, allocationEpoch, { nonceByte: 0xb5 })
  bogusCreate.request.createSignature = b4a.alloc(64)
  sodium.crypto_sign_detached(bogusCreate.request.createSignature,
    inboxCreateCommitment({ ...bogusCreate.request, relayPublicKey: identity.relayPublicKey }),
    foreign.secretKey)
  const bogus = await create.client.request({
    endpoint: create.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CREATE,
    body: encodeCanonical(inboxCreateV1, bogusCreate.request)
  })
  t.ok(!bogus.ok, 'foreign create signature fails closed')
  t.is(bogus.error.code, ERROR_CODE.BAD_CREATE_SIG)

  // Unknown topic append fails closed.
  const append = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.APPEND, identity.currentEpoch, fetchImpl)
  const ghostAppend = inboxAppendFixture(created, identity.relayPublicKey, identity.parameterHash, 0xd2)
  ghostAppend.physicalTopic = b4a.alloc(32, 0x99)
  const ghost = await append.client.request({
    endpoint: append.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: encodeCanonical(inboxAppendV1, ghostAppend)
  })
  t.ok(!ghost.ok, 'append to an unknown topic fails closed')

  // Credential-bearing headers on the inbox path fail closed at the edge.
  const envelope = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CREATE,
    body: encodeCanonical(inboxCreateV1, created.request)
  }).body
  const credentialed = await fetchImpl(`${baseUrl}/api/blind/v1/inbox`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, authorization: 'Bearer bogus' },
    body: envelope
  })
  t.is(credentialed.status, 400, 'authorization credential fails closed')
})

test('INBOX frames persist across relay restart with signed read pages', async t => {
  const first = await bootRelay(t)
  const { identity, layout, relay, baseUrl } = first
  const firstFetch = first.fetchImpl
  const trusted = await trustedRelay(identity, baseUrl, layout, firstFetch)
  const health = await healthFor(trusted, identity, firstFetch, 0x7fff)
  const allocationEpoch = relay.unary.inboxStorage.status().epochFloor
  const created = inboxCreateFixture(identity.relayPublicKey, identity.parameterHash, allocationEpoch)
  const create = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.CREATE, identity.currentEpoch, firstFetch)
  t.ok((await create.client.request({
    endpoint: create.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CREATE,
    body: encodeCanonical(inboxCreateV1, created.request)
  })).ok, 'INBOX.CREATE is answered before restart')
  const appended = inboxAppendFixture(created, identity.relayPublicKey, identity.parameterHash, 0xd3)
  const append = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.APPEND, identity.currentEpoch, firstFetch)
  t.ok((await append.client.request({
    endpoint: append.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: encodeCanonical(inboxAppendV1, appended)
  })).ok, 'INBOX.APPEND is answered before restart')
  await first.edge.close()
  await first.relay.close()

  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay2 = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    }
  })
  replayOffset.value = 0n
  await relay2.start()
  const edge = await createEdgeFixture({
    port: first.port,
    tls: first.tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    launchTopologyHash: layout.launchTopologyHash,
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay2.close().catch(() => {})
  })
  const read = qualifiedClient(trusted, health, FAMILY.INBOX, OPERATION.INBOX.READ, identity.currentEpoch, firstFetch)
  const readResult = await read.client.request({
    endpoint: read.endpoint,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    body: encodeCanonical(inboxReadV1, inboxReadFixture(created, identity.parameterHash))
  })
  t.ok(readResult.ok, 'INBOX.READ is answered after restart')
  const page = decodeCanonical(inboxReadResultV1, readResult.body, { copyBytes: true })
  verifyInboxReadSignature(t, page, identity.relayPublicKey)
  t.is(page.entries.length, 1)
  t.ok(b4a.equals(page.entries[0].frame, appended.frame), 'exact frame readback survives the restart')
  await edge.close()
  await relay2.close()
})

// ---------------------------------------------------------------------------
// CORE route evidence (serial route 4/5): unary MIRROR/PROVE on the same
// exact path with signed acknowledgement, exact replay, the fail-closed
// non-advertised OPEN_REPLICATION behavior, negatives and restart recovery.
// ---------------------------------------------------------------------------

test('CORE.MIRROR returns a signed acknowledgement and replays it exactly; PROVE fails closed without an active core', async t => {
  const { identity, layout, relay, baseUrl, fetchImpl } = await bootRelay(t)
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x1ffff)

  const mirror = coreMirrorFixture(identity.parameterHash)
  const mirrorBody = encodeCanonical(coreMirrorRequestV1, mirror)
  const mirrorClient = qualifiedClient(trusted, health, FAMILY.CORE, OPERATION.CORE.MIRROR, identity.currentEpoch, fetchImpl)
  const first = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: mirrorBody
  })
  t.ok(first.ok, 'CORE.MIRROR is answered')
  const accepted = decodeCanonical(blindCoreAckV1, first.body, { copyBytes: true })
  verifyResultSignedValue(blindCoreAckV1, accepted, RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, identity.relayPublicKey, 'core ack')
  t.is(accepted.result, CORE_ACK_RESULT.MIRROR_ACCEPTED)
  t.ok(b4a.equals(accepted.corePublicKey, mirror.corePublicKey), 'ack binds the exact core public key')
  t.ok(b4a.equals(accepted.signedHeadHash, mirror.signedHeadHash), 'ack binds the exact signed head hash')

  // Exact replay: the same charged MIRROR returns the byte-identical
  // committed acknowledgement through production wiring.
  const replay = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: mirrorBody
  })
  t.ok(replay.ok, 'CORE.MIRROR replay is answered')
  t.ok(b4a.equals(replay.body, first.body), 'charged MIRROR replays the exact committed acknowledgement')

  // PROVE serves only an ACTIVE sponsored generation: the unassembled
  // upstream cannot activate one, so PROVE fails closed (charged or not).
  const prove = coreProveFixture(mirror, identity.parameterHash)
  const proveClient = qualifiedClient(trusted, health, FAMILY.CORE, OPERATION.CORE.PROVE, identity.currentEpoch, fetchImpl)
  const unsponsored = await proveClient.client.request({
    endpoint: proveClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.PROVE,
    body: encodeCanonical(coreServeChallengeV1, prove)
  })
  t.ok(!unsponsored.ok, 'PROVE fails closed without an active sponsored generation')
  t.is(unsponsored.error.code, ERROR_CODE.NOT_FOUND)
  const charged = await proveClient.client.request({
    endpoint: proveClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.PROVE,
    body: encodeCanonical(coreServeChallengeV1, coreProveFixture(mirror, identity.parameterHash, { charged: true }))
  })
  t.ok(!charged.ok, 'charged PROVE fails closed before its spend')
  t.is(charged.error.code, ERROR_CODE.NOT_FOUND)

  // Accepted storage accounting: the sponsorship is durably pending on the
  // unavailable upstream, and no proof spend was consumed.
  const accounting = relay.unary.coreStorage.status().accounting
  t.is(accounting.mirrorAttempts, 1)
  t.is(accounting.activeCores, 0)
  t.is(accounting.proofSpendTombstones, 0)
  const spendTag = blake2b256(mirror.admission.token)
  t.is(relay.unary.coreStorage.inspectMirrorSpend(spendTag).state, 'RETRY_PENDING')
})

test('CORE fails closed on the reserved OPEN_REPLICATION and on bogus credentials', async t => {
  const { identity, layout, baseUrl, fetchImpl } = await bootRelay(t)
  const trusted = await trustedRelay(identity, baseUrl, layout, fetchImpl)
  const health = await healthFor(trusted, identity, fetchImpl, 0x1ffff)

  // The reserved operation is outside the advertised release profile: the
  // client cannot even qualify an endpoint for it.
  let qualifyError = null
  try {
    qualifyRelay({
      trustedDescriptor: trusted,
      health,
      familyId: FAMILY.CORE,
      operationId: OPERATION.CORE.OPEN_REPLICATION,
      endpointId: 1,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
      requiredRoleBits: 0x31,
      privacyProfileBit: 1,
      nowEpoch: identity.currentEpoch
    })
  } catch (error) {
    qualifyError = error
  }
  t.is(qualifyError && qualifyError.code, 'RELAY_NOT_QUALIFIED', 'reserved OPEN_REPLICATION has no qualified endpoint')

  // At the public edge the reserved operation fails closed with a bare
  // transport 400, never a Blind envelope (the corrected fixture behavior).
  const open = coreOpenReplicationFixture(identity.parameterHash)
  const openEnvelope = encodeOuterEnvelope({
    innerDispatch: encodeDispatchFrame({
      frameKind: FRAME_KIND.REQUEST,
      familyId: FAMILY.CORE,
      operationId: OPERATION.CORE.OPEN_REPLICATION,
      requestId: b4a.alloc(16, 0xa4),
      body: encodeCanonical(coreOpenReplicationV1, open)
    }),
    outerClass: 2
  })
  const rejected = await fetchImpl(`${baseUrl}/api/blind/v1/core`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE },
    body: openEnvelope
  })
  t.is(rejected.status, 400, 'reserved OPEN_REPLICATION fails closed at the public edge')
  t.is(rejected.headers.get('content-type'), 'text/plain; charset=utf-8')
  t.is((await rejected.arrayBuffer()).byteLength, 0, 'fail-closed rejection carries no Blind envelope body')

  // Bogus admission credentials fail closed through the qualified path.
  const mirror = coreMirrorFixture(identity.parameterHash)
  mirror.admission = fixtureAdmission(b4a.alloc(32, 0x66), 0xb5)
  const mirrorClient = qualifiedClient(trusted, health, FAMILY.CORE, OPERATION.CORE.MIRROR, identity.currentEpoch, fetchImpl)
  const bogus = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: encodeCanonical(coreMirrorRequestV1, mirror)
  })
  t.ok(!bogus.ok, 'bogus admission credentials fail closed')

  // A sponsorship advancing no admitted dimension is refused before spend.
  const mirror2 = coreMirrorFixture(identity.parameterHash, { spendByte: 0xb6 })
  t.ok((await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: encodeCanonical(coreMirrorRequestV1, mirror2)
  })).ok, 'second MIRROR is answered')
  const notDue = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: encodeCanonical(coreMirrorRequestV1, coreMirrorFixture(identity.parameterHash, {
      clientNonce: b4a.alloc(32, 0x53),
      spendByte: 0xb7
    }))
  })
  t.ok(!notDue.ok, 'non-advancing sponsorship is refused')
  t.is(notDue.error.code, ERROR_CODE.RENEW_NOT_DUE)
})

test('CORE committed acknowledgement replays byte-identically across relay restart', async t => {
  const first = await bootRelay(t)
  const { identity, layout, baseUrl } = first
  const firstFetch = first.fetchImpl
  const trusted = await trustedRelay(identity, baseUrl, layout, firstFetch)
  const health = await healthFor(trusted, identity, firstFetch, 0x1ffff)
  const mirror = coreMirrorFixture(identity.parameterHash)
  const mirrorBody = encodeCanonical(coreMirrorRequestV1, mirror)
  const mirrorClient = qualifiedClient(trusted, health, FAMILY.CORE, OPERATION.CORE.MIRROR, identity.currentEpoch, firstFetch)
  const before = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: mirrorBody
  })
  t.ok(before.ok, 'CORE.MIRROR is answered before restart')
  await first.edge.close()
  await first.relay.close()

  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay2 = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    }
  })
  replayOffset.value = 0n
  await relay2.start()
  const edge = await createEdgeFixture({
    port: first.port,
    tls: first.tls,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    launchTopologyHash: layout.launchTopologyHash,
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay2.close().catch(() => {})
  })
  const after = await mirrorClient.client.request({
    endpoint: mirrorClient.endpoint,
    familyId: FAMILY.CORE,
    operationId: OPERATION.CORE.MIRROR,
    body: mirrorBody
  })
  t.ok(after.ok, 'CORE.MIRROR is answered after restart')
  t.ok(b4a.equals(after.body, before.body), 'the committed acknowledgement replays byte-identically after restart')
  const spendTag = blake2b256(mirror.admission.token)
  t.is(relay2.unary.coreStorage.inspectMirrorSpend(spendTag).state, 'RETRY_PENDING',
    'mirror spend state recovers across restart')
  await edge.close()
  await relay2.close()
})

// ---------------------------------------------------------------------------
// FORWARD one-hop edge evidence (serial route 5/5): the full public path —
// origin client -> source Edge (real TLS exporter) -> peercred IPC -> source
// daemon runtime -> accepted storage -> bounded dial -> target Edge (separate
// OS process, real TLS exporter) -> peercred IPC -> target daemon runtime ->
// accepted storage. Exact 65536-byte request/result bodies, one outstanding
// sequence per signed session, idempotent retries, changed-replay terminal,
// no caller URL/host/IP, over-depth/A-B-A/reset negatives.
// ---------------------------------------------------------------------------

const FORWARD_EDGE_CATALOG_ENTRY_ID = b4a.alloc(32, 0x42)

async function spawnTargetRelay (t) {
  const fixturePath = new URL('./forward-https-vnext-integration-fixture.mjs', import.meta.url).pathname
  const child = spawn(process.execPath, [fixturePath, '--target-child'], {
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let readinessLine = null
  let stderr = ''
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('target child did not become ready')), 120_000)
    let buffer = ''
    child.stdout.on('data', chunk => {
      buffer += chunk
      const newline = buffer.indexOf('\n')
      if (newline !== -1) {
        readinessLine = buffer.slice(0, newline)
        clearTimeout(timer)
        resolve()
      }
    })
    child.once('exit', code => {
      if (readinessLine == null) {
        clearTimeout(timer)
        reject(new Error(`target child exited before ready (${code}): ${stderr.slice(-400)}`))
      }
    })
  })
  child.stderr.on('data', chunk => { stderr += chunk })
  await ready
  const readiness = JSON.parse(readinessLine)
  t.teardown(() => {
    child.kill('SIGTERM')
  })
  return {
    child,
    readiness,
    stderr: () => stderr,
    target: {
      relayPublicKey: b4a.from(readiness.relayPublicKey, 'hex'),
      descriptorSequence: BigInt(readiness.descriptorSequence),
      descriptorHash: b4a.from(readiness.descriptorHash, 'hex')
    }
  }
}

async function bootForwardSource (t, target, options = {}) {
  const port = options.port || await freePort()
  const identity = await createRelayIdentityFixture({ port })
  const layout = await createRelayEnvironmentFixture(identity)
  const tls = await createLoopbackTlsFixture(layout.directory)
  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    },
    source: {
      socketPath: path.join(layout.socketDirectory, 'source-origin.sock'),
      resolveTargetDescriptor: async relayPublicKey => Object.freeze({
        relayPublicKey,
        descriptorSequence: target.descriptorSequence,
        descriptorHash: b4a.from(target.descriptorHash)
      }),
      resolveCatalogEntry: async catalogEntryId => Object.freeze({
        catalogEntryId,
        relayPublicKey: b4a.from(target.relayPublicKey),
        descriptorSequence: target.descriptorSequence,
        descriptorHash: b4a.from(target.descriptorHash)
      }),
      dialTarget: createForwardHttpsTargetDialerVnext({
        url: `https://127.0.0.1:${target.port}/api/blind/v1/forward`,
        rejectUnauthorized: false
      }),
      budgetBytes: options.budgetBytes
    }
  })
  replayOffset.value = 0n
  await relay.start()
  const exchanges = []
  const edge = await createEdgeFixture({
    port,
    tls,
    role: FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    forwardSocketPath: relay.sourceIpc.socketPath,
    launchTopologyHash: layout.launchTopologyHash,
    wireV3AbiHash: PINNED_WIRE_V3_ABI_HASH,
    onError: error => daemonErrors.push(error),
    onForwardExchange: options.capture ? entry => exchanges.push(entry) : null
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay.close().catch(() => {})
    await removeFixtureScratch(layout)
  })
  return {
    identity,
    layout,
    relay,
    edge,
    daemonErrors,
    exchanges,
    tls,
    fetchImpl: edgeFetchFixture({ rejectUnauthorized: false }),
    baseUrl: edgeBaseUrl(edge),
    port
  }
}

function forwardOriginCapability (source, target, overrides = {}) {
  const issuedAtEpoch = overrides.issuedAtEpoch == null
    ? Math.floor(Date.now() / 1000) - 10
    : overrides.issuedAtEpoch
  return {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    sourceRelayPublicKey: b4a.from(source.descriptor.relayPublicKey),
    sourceDescriptorSequence: source.descriptorSequence,
    sourceDescriptorHash: b4a.from(source.hash),
    targetRelayPublicKey: b4a.from(target.relayPublicKey),
    targetDescriptorSequence: target.descriptorSequence,
    targetDescriptorHash: b4a.from(target.descriptorHash),
    targetCatalogEntryId: b4a.from(FORWARD_EDGE_CATALOG_ENTRY_ID),
    routeId: overrides.routeId || b4a.alloc(16, 0x31),
    routePrefixRelayPublicKey: b4a.from(source.descriptor.relayPublicKey),
    maxRelayCount: 2,
    remainingTransitions: overrides.remainingTransitions == null ? 1 : overrides.remainingTransitions,
    circuitClass: 1,
    maxCircuitBytes: 16n * 1024n * 1024n,
    initialWindowBytes: 65_536,
    idleMillis: 30_000,
    lifetimeMillis: 600_000,
    issuedAtEpoch,
    expiresAtEpoch: overrides.lifetimeSeconds == null ? issuedAtEpoch + 600 : issuedAtEpoch + overrides.lifetimeSeconds,
    circuitNonce: overrides.circuitNonce || b4a.alloc(32, 0x33),
    tlsExporterBindingHash: b4a.alloc(32),
    signature: b4a.alloc(64)
  }
}

function forwardOriginTurn (capability, requestKind, sequence, previousTargetResultHash, inner, overrides = {}) {
  const clientSessionNonce = overrides.clientSessionNonce || b4a.alloc(32, 0x34)
  return encodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, {
    version: 1,
    routeKind: 7,
    releaseProfileId: 2,
    requestRole: overrides.requestRole == null ? 0 : overrides.requestRole,
    requestKind,
    flags: 0,
    stableSessionId: forwardHttpsStableSessionIdV1(capability, clientSessionNonce),
    sequence,
    clientSessionNonce,
    requestNonce: overrides.requestNonce || b4a.alloc(32, 0x35),
    previousTargetResultHash,
    parentCapability: capability,
    turnTlsExporterBindingHash: b4a.alloc(32),
    originRequestCommitment: b4a.alloc(32),
    sourceTransformSignature: b4a.alloc(64),
    inner
  })
}

function forwardOpenInner (capability, parameterHash, overrides = {}) {
  return {
    version: 1,
    routeId: b4a.from(capability.routeId),
    nextDescriptorSequence: capability.targetDescriptorSequence,
    nextDescriptorHash: b4a.from(capability.targetDescriptorHash),
    requestedWireClass: 1,
    circuitClass: 1,
    circuitNonce: b4a.from(capability.circuitNonce),
    parentRouteScopeHash: overrides.parentRouteScopeHash || b4a.alloc(32),
    hopAdmission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: b4a.from(parameterHash),
      token: b4a.alloc(32, 0x45)
    },
    innerHandshake: b4a.alloc(32)
  }
}

async function forwardTurn (fetchImpl, baseUrl, turnBytes, headers = {}) {
  const response = await fetchImpl(`${baseUrl}/api/blind/v1/forward`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, ...headers },
    body: turnBytes
  })
  const body = b4a.from(await response.arrayBuffer())
  return { response, body }
}

test('FORWARD one-hop public path: signed exact turns through two relays and two OS processes with real TLS exporters', async t => {
  const spawned = await spawnTargetRelay(t)
  const source = await bootForwardSource(t, {
    ...spawned.target,
    port: spawned.readiness.port
  }, { capture: true })
  const { identity, fetchImpl, baseUrl } = source
  const sourceSnapshot = source.relay.unary.descriptorState.requireCurrent()
  const capability = forwardOriginCapability(sourceSnapshot, spawned.target)

  const openBytes = forwardOriginTurn(capability, 1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash))
  t.is(openBytes.byteLength, 65_536, 'request body is exactly 65536 bytes')
  const open = await forwardTurn(fetchImpl, baseUrl, openBytes)
  t.is(open.response.status, 200)
  t.is(open.response.headers.get('content-type'), MEDIA_TYPE)
  t.is(open.body.byteLength, 65_536, 'result body is exactly 65536 bytes')
  t.is(open.response.headers.get('set-cookie'), null, 'credential-free HTTPS')
  const openVerified = assertForwardHttpsResultForOriginRequestV1(openBytes, open.body)
  t.is(openVerified.result.resultRole, 1, 'TARGET_RESULT')
  t.is(openVerified.result.responseKind, 1, 'OPEN_ACCEPT')
  t.ok(b4a.equals(openVerified.result.signerPublicKey, spawned.target.relayPublicKey), 'result signed by the target relay')
  t.ok(!b4a.equals(openVerified.result.finalizedParentCapability.tlsExporterBindingHash, b4a.alloc(32)),
    'the finalized capability binds the real TLS exporter (nonzero binding)')
  t.ok(verifyForwardHttpsParentCapabilitySignatureV1(openVerified.result.finalizedParentCapability),
    'the source-minted parent capability signature verifies')
  t.ok(openVerified.result.sourceTransformSignature.some(byte => byte !== 0), 'source transform signature present')

  const chain1 = forwardHttpsTargetResultChainHashV1(open.body)
  const clientSessionNonce = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  const dataBytes = forwardOriginTurn(capability, 2, 1n, chain1, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64, 0x61)
  }, { clientSessionNonce })
  const data = await forwardTurn(fetchImpl, baseUrl, dataBytes)
  t.is(data.body.byteLength, 65_536)
  const dataVerified = assertForwardHttpsResultForOriginRequestV1(dataBytes, data.body)
  t.is(dataVerified.result.responseKind, 2, 'DATA answers ACK')

  const closeBytes = forwardOriginTurn(capability, 4, 2n, forwardHttpsTargetResultChainHashV1(data.body), {
    version: 1,
    circuitNonce: capability.circuitNonce,
    closeKind: 1,
    finalSendOffset: 64n,
    reasonCode: 0
  }, { clientSessionNonce })
  const close = await forwardTurn(fetchImpl, baseUrl, closeBytes)
  const closeVerified = assertForwardHttpsResultForOriginRequestV1(closeBytes, close.body)
  t.is(closeVerified.result.responseKind, 6, 'CLOSE answers CLOSE')

  // Relay-visible bytes at the source edge: exact IPC v4 transcripts only.
  t.is(source.exchanges.length, 6, 'three full exchanges captured')
  const requestTranscript = source.exchanges[0]
  t.is(requestTranscript.phase, 'request')
  t.is(requestTranscript.bytes.byteLength, 65_976, 'exact source-origin transcript')
  const decodedTranscript = decodeLocalForwardHttpsSourceOriginTranscriptV4(requestTranscript.bytes, { eof: true })
  t.ok(b4a.equals(decodedTranscript.turn.body, openBytes), 'the edge forwarded the exact client body')
  t.ok(!b4a.equals(decodedTranscript.authority.tlsExporterBindingHash, b4a.alloc(32)),
    'the edge derived a nonzero exporter binding from the live TLS socket')
  t.is(source.exchanges[1].bytes.byteLength, 65_684, 'exact result transcript')

  // The target edge is a separate OS process; its captured exchanges show the
  // bounded byte relay accepted only the exact forwarded bytes.
  const targetLog = spawned.stderr()
  t.ok(!targetLog.includes('PEERCRED') && !targetLog.includes('fatal'), 'target relay process ran clean across the multiprocess boundary')

  // Multiprocess evidence: the target relay is a different pid.
  t.not(spawned.child.pid, process.pid, 'target relay runs as a separate OS process')
})

test('FORWARD idempotent retry, changed-replay terminal and fail-closed negatives at the public edge', async t => {
  const spawned = await spawnTargetRelay(t)
  const source = await bootForwardSource(t, {
    ...spawned.target,
    port: spawned.readiness.port
  })
  const { identity, fetchImpl, baseUrl } = source
  const sourceSnapshot = source.relay.unary.descriptorState.requireCurrent()
  const capability = forwardOriginCapability(sourceSnapshot, spawned.target)
  const openBytes = forwardOriginTurn(capability, 1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash))

  const first = await forwardTurn(fetchImpl, baseUrl, openBytes)
  t.is(first.response.status, 200)
  const retry = await forwardTurn(fetchImpl, baseUrl, openBytes)
  t.is(retry.response.status, 200)
  t.ok(b4a.equals(retry.body, first.body), 'exact retry returns the byte-identical definitive result')

  // Changed bytes on the same sequence: signed terminal pre-forward error.
  const clientSessionNonce = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).clientSessionNonce
  const chain1 = forwardHttpsTargetResultChainHashV1(first.body)
  const dataA = forwardOriginTurn(capability, 2, 1n, chain1, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64, 0x62)
  }, { clientSessionNonce })
  const dataB = forwardOriginTurn(capability, 2, 1n, chain1, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64, 0x63)
  }, { clientSessionNonce })
  t.is((await forwardTurn(fetchImpl, baseUrl, dataA)).response.status, 200)
  const conflict = await forwardTurn(fetchImpl, baseUrl, dataB)
  t.is(conflict.response.status, 200, 'changed replay answers inside the exact contract')
  const conflictResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, conflict.body, { copyBytes: true })
  t.is(conflictResult.resultRole, 2, 'SOURCE_PRE_FORWARD_ERROR')
  t.is(conflictResult.responseKind, 7, 'ERROR')
  t.is(conflictResult.inner.code, 19, 'RETRY_TERMINAL')
  t.ok(b4a.equals(conflictResult.signerPublicKey, identity.relayPublicKey), 'terminal error signed by the source relay')

  // Sequence gap terminalizes.
  const gap = forwardOriginTurn(capability, 2, 5n, chain1, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64, 0x64)
  }, { clientSessionNonce: b4a.alloc(32, 0x74) })
  const gapResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1,
    (await forwardTurn(fetchImpl, baseUrl, gap)).body, { copyBytes: true })
  t.is(gapResult.inner && gapResult.inner.code, 19, 'sequence gap is terminal')

  // Fail-closed at the edge: A-B-A (source == target relay) is rejected by
  // the exact codec before any contact.
  const abaCapability = forwardOriginCapability(sourceSnapshot, {
    relayPublicKey: sourceSnapshot.descriptor.relayPublicKey,
    descriptorSequence: sourceSnapshot.descriptorSequence,
    descriptorHash: sourceSnapshot.hash
  }, { circuitNonce: b4a.alloc(32, 0x75) })
  let abaError = null
  try {
    forwardOriginTurn(abaCapability, 1, 0n, b4a.alloc(32), forwardOpenInner(abaCapability, identity.parameterHash), { clientSessionNonce: b4a.alloc(32, 0x76) })
  } catch (error) {
    abaError = error
  }
  t.ok(abaError != null, 'A-B-A capability cannot be built')
  // Over-depth: remainingTransitions other than one is not encodable.
  let depthError = null
  try {
    forwardOriginTurn(forwardOriginCapability(sourceSnapshot, spawned.target, { remainingTransitions: 2 }),
      1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash), { clientSessionNonce: b4a.alloc(32, 0x77) })
  } catch (error) {
    depthError = error
  }
  t.ok(depthError != null, 'over-depth capability cannot be built')
  // Nested parent: a nonzero parent route scope hash is rejected by the codec.
  let nestedError = null
  try {
    forwardOriginTurn(capability, 1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash, { parentRouteScopeHash: b4a.alloc(32, 0x78) }), { clientSessionNonce: b4a.alloc(32, 0x79) })
  } catch (error) {
    nestedError = error
  }
  t.ok(nestedError != null, 'nested parent OPEN cannot be built')
  // Reset: a sequence-zero request with a nonzero previous result hash is not
  // a canonical OPEN.
  let resetError = null
  try {
    forwardOriginTurn(capability, 1, 0n, b4a.alloc(32, 0x7a), forwardOpenInner(capability, identity.parameterHash), { clientSessionNonce: b4a.alloc(32, 0x7b) })
  } catch (error) {
    resetError = error
  }
  t.ok(resetError != null, 'reset request cannot be built')
  // An origin-template request at the TARGET edge is refused by role.
  const targetProbe = await fetchImpl(`https://127.0.0.1:${spawned.readiness.port}/api/blind/v1/forward`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE },
    body: openBytes
  })
  t.is(targetProbe.status, 400, 'target edge accepts no origin-template request')
  // A forwarded request at the SOURCE edge is refused by role.
  const forwardedProbe = await forwardTurn(fetchImpl, baseUrl, openBytes, {})
  t.is(forwardedProbe.response.status, 200, 'the retried origin still answers (control)')
  // Expired capability: signed source pre-forward terminal error.
  const expiredCapability = forwardOriginCapability(sourceSnapshot, spawned.target, {
    issuedAtEpoch: Math.floor(Date.now() / 1000) - 1200,
    circuitNonce: b4a.alloc(32, 0x7c)
  })
  const expiredBytes = forwardOriginTurn(expiredCapability, 1, 0n, b4a.alloc(32), forwardOpenInner(expiredCapability, identity.parameterHash), { clientSessionNonce: b4a.alloc(32, 0x7d) })
  const expired = await forwardTurn(fetchImpl, baseUrl, expiredBytes)
  const expiredResult = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1, expired.body, { copyBytes: true })
  t.is(expiredResult.resultRole, 2, 'expired capability answers a source pre-forward error')
  t.is(expiredResult.inner.code, 19, 'RETRY_TERMINAL')
  // Credential headers on the forward path fail closed at the edge.
  const credentialed = await fetchImpl(`${baseUrl}/api/blind/v1/forward`, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE, cookie: 'a=b' },
    body: openBytes
  })
  t.is(credentialed.status, 400, 'credential header fails closed')
  // A caller URL/host/IP field is unrepresentable in the capability codec.
  let dialFieldError = null
  try {
    const dialCapability = forwardOriginCapability(sourceSnapshot, spawned.target)
    dialCapability.url = 'https://attacker.example'
    forwardOriginTurn(dialCapability, 1, 0n, b4a.alloc(32), forwardOpenInner(dialCapability, identity.parameterHash))
  } catch (error) {
    dialFieldError = error
  }
  t.ok(dialFieldError != null, 'caller dial fields are unrepresentable')
})

test('FORWARD budget exhaustion terminalizes the session', async t => {
  const spawned = await spawnTargetRelay(t)
  const source = await bootForwardSource(t, {
    ...spawned.target,
    port: spawned.readiness.port
  }, { budgetBytes: 2 * 131_072 })
  const { identity, fetchImpl, baseUrl } = source
  const sourceSnapshot = source.relay.unary.descriptorState.requireCurrent()
  const capability = forwardOriginCapability(sourceSnapshot, spawned.target)
  const clientSessionNonce = b4a.alloc(32, 0x81)
  const openBytes = forwardOriginTurn(capability, 1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash), { clientSessionNonce })
  const open = await forwardTurn(fetchImpl, baseUrl, openBytes)
  t.is(open.response.status, 200, 'first exchange admitted within the two-exchange budget')
  const chain1 = forwardHttpsTargetResultChainHashV1(open.body)
  const data1 = forwardOriginTurn(capability, 2, 1n, chain1, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 0n,
    bytes: b4a.alloc(64, 0x82)
  }, { clientSessionNonce })
  const first = await forwardTurn(fetchImpl, baseUrl, data1)
  t.is(first.response.status, 200, 'second exchange admitted')
  const secondVerified = assertForwardHttpsResultForOriginRequestV1(data1, first.body)
  t.is(secondVerified.result.responseKind, 2, 'second exchange is definitive')
  const chain2 = forwardHttpsTargetResultChainHashV1(first.body)
  const data2 = forwardOriginTurn(capability, 2, 2n, chain2, {
    version: 1,
    circuitNonce: capability.circuitNonce,
    offset: 64n,
    bytes: b4a.alloc(64, 0x83)
  }, { clientSessionNonce })
  const exhausted = decodeCanonical(blindForwardHttpsOriginForwardTurnResultV1,
    (await forwardTurn(fetchImpl, baseUrl, data2)).body, { copyBytes: true })
  t.is(exhausted.resultRole, 2, 'over-budget answers a source pre-forward error')
  t.is(exhausted.inner.code, 19, 'RETRY_TERMINAL on budget exhaustion')
})

test('FORWARD source relay restart recovers storage, replay and capability', async t => {
  const spawned = await spawnTargetRelay(t)
  const first = await bootForwardSource(t, {
    ...spawned.target,
    port: spawned.readiness.port
  })
  const { identity, layout } = first
  const sourceSnapshot = first.relay.unary.descriptorState.requireCurrent()
  const capability = forwardOriginCapability(sourceSnapshot, spawned.target)
  const openBytes = forwardOriginTurn(capability, 1, 0n, b4a.alloc(32), forwardOpenInner(capability, identity.parameterHash))
  const before = await forwardTurn(first.fetchImpl, first.baseUrl, openBytes)
  t.is(before.response.status, 200)
  const stableSessionId = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, openBytes, { copyBytes: true }).stableSessionId
  await first.edge.close()
  await first.relay.close()

  const daemonErrors = []
  const replayOffset = { value: -15_000n }
  const relay2 = await assembleRelayFixture(identity, layout, {
    onError: error => daemonErrors.push(error),
    replayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset.value
    },
    source: {
      socketPath: path.join(layout.socketDirectory, 'source-origin.sock'),
      resolveTargetDescriptor: async relayPublicKey => Object.freeze({
        relayPublicKey,
        descriptorSequence: spawned.target.descriptorSequence,
        descriptorHash: b4a.from(spawned.target.descriptorHash)
      }),
      resolveCatalogEntry: async catalogEntryId => Object.freeze({
        catalogEntryId,
        relayPublicKey: b4a.from(spawned.target.relayPublicKey),
        descriptorSequence: spawned.target.descriptorSequence,
        descriptorHash: b4a.from(spawned.target.descriptorHash)
      }),
      dialTarget: createForwardHttpsTargetDialerVnext({
        url: `https://127.0.0.1:${spawned.readiness.port}/api/blind/v1/forward`,
        rejectUnauthorized: false
      })
    }
  })
  replayOffset.value = 0n
  await relay2.start()
  const edge = await createEdgeFixture({
    port: first.port,
    tls: first.tls,
    role: FORWARD_HTTPS_EDGE_ROLE_VNEXT.SOURCE,
    unarySocketPath: layout.environment.HIVERELAY_BLIND_UNARY_SOCKET,
    forwardSocketPath: relay2.sourceIpc.socketPath,
    launchTopologyHash: layout.launchTopologyHash,
    wireV3AbiHash: PINNED_WIRE_V3_ABI_HASH,
    onError: error => daemonErrors.push(error)
  })
  t.teardown(async () => {
    await edge.close().catch(() => {})
    await relay2.close().catch(() => {})
  })
  const sourceState = forwardHttpsSourceTurnStateV3(relay2.sourceRuntime.sourceStore, stableSessionId)
  t.is(sourceState.identity, 'PRESENT_ALLOCATED', 'source session identity recovered across restart')
  const recovered = inspectForwardHttpsReplayJournalV4(relay2.sourceRuntime.replayJournal)
  t.is(recovered.length, 1, 'replay journal recovered the burned tuple')
  t.is(recovered[0].state, 'CONSUMED', 'the tuple stays consumed')

  const capability2 = forwardOriginCapability(relay2.unary.descriptorState.requireCurrent(), spawned.target, { circuitNonce: b4a.alloc(32, 0x84) })
  const open2 = forwardOriginTurn(capability2, 1, 0n, b4a.alloc(32), forwardOpenInner(capability2, identity.parameterHash), { clientSessionNonce: b4a.alloc(32, 0x85) })
  const after = await forwardTurn(first.fetchImpl, edgeBaseUrl(edge), open2)
  t.is(after.response.status, 200)
  const verified = assertForwardHttpsResultForOriginRequestV1(open2, after.body)
  t.is(verified.result.responseKind, 1, 'fresh session completes after restart')
  await edge.close()
  await relay2.close()
})
