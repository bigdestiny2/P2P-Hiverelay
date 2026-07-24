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
  ERROR_CODE,
  FAMILY,
  FRAME_KIND,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_SUPPORT,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindHealthChallengeV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  encodeDispatchFrame,
  encodeOuterEnvelope,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import { decodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
import {
  DescriptorTrustStore,
  createDescribeGetRequest,
  createHealthChallenge,
  verifyDescriptorBytes,
  verifyHealthResultBytes,
  qualifyDescribeControlEndpoint
} from '../../blind-client/describe.js'
import { BlindDirectHttpClient } from '../../blind-client/direct-http.js'
import { encodeUnaryRequest } from '../../blind-client/wire.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'
import {
  createRelayIdentityFixture,
  createRelayEnvironmentFixture,
  assembleRelayFixture,
  createEdgeFixture,
  createLoopbackTlsFixture,
  edgeBaseUrl,
  edgeFetchFixture,
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
