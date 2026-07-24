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
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  CELL_RECEIPT_RESULT,
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_SUPPORT,
  RESULT_SIGNATURE_DOMAIN_ID,
  allocationCommitment,
  blake2b256,
  blindHealthChallengeV1,
  blindReceiptV1,
  blindServiceDescriptorV1,
  cellStorageSlot,
  decodeCanonical,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  getCellResultV1,
  getCellV1,
  proveCellResultV1,
  proveCellV1,
  putCellV1,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
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
