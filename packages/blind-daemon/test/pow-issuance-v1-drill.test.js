// pow-issuance-v1 LOCAL drills — full in-process stack:
// issuer (HTTP) + production daemon runtime (CELL+INBOX) + real TLS edge + real client
// wire path. No fleet contact. Prints observed values as the drill transcript.
import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash, randomBytes } from 'node:crypto'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  ADMISSION_CONFORMANCE_CLASS,
  CELL_RECEIPT_RESULT,
  ERROR_CODE,
  FAMILY,
  INBOX_APPEND_RESULT,
  INBOX_FRAME_CLASS,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  blake2b256,
  blindReceiptV1,
  decodeCanonical,
  inboxAppendAckV1,
  inboxAppendRequestCommitment,
  inboxReadResultV1,
  inboxReceiptV1,
  resultSignaturePayload
} from '@hiverelay/blind-protocol'
import { loadDaemonBootstrapConfig } from '../bootstrap-config.js'
import {
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} from '../production-runtime.js'
import {
  PowIssuanceV1AdmissionAdapter,
  createPowIssuanceV1AdapterResolver
} from '../pow-issuance-v1/admission-adapter.js'
import {
  POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES,
  POW_ISSUANCE_V1_SCHEME_ID,
  buildPowIssuanceV1Presentation,
  countLeadingZeroBits,
  derivePowIssuanceV1Keys,
  mintPowIssuanceV1Token,
  powIssuanceV1Preimage,
  powIssuanceV1RecordBindingRoot,
  powIssuanceV1SpendTag
} from '../pow-issuance-v1/token-codec.js'
import { createPowIssuanceV1Issuer } from '../pow-issuance-v1/issuer-service.js'
import { powIssuanceV1DrillFixture } from './pow-issuance-v1-drill-fixture.js'
import { createBlindBoundaryScratch, removeBlindBoundaryScratch } from '../../../test/blind-boundary-scratch.js'
import { BlindEdge } from '../../blind-edge/server.js'
import { createNodeCryptoRuntime } from '../../blind-client/runtime/node.js'
import { encodeUnaryRequest, decodeUnaryResponse } from '../../blind-client/wire.js'
import { createCellReplica } from '../../blind-client/requests.js'
import {
  createAppendInboxRequest,
  createInboxReplica,
  createReadInboxRequest
} from '../../blind-client/inbox.js'

const execFileAsync = promisify(execFile)
const ERROR_NAMES = new Map(Object.entries(ERROR_CODE).map(([name, code]) => [code, name]))

function log (line) {
  console.log(`    [drill] ${line}`)
}

function errorName (code) {
  return ERROR_NAMES.get(code) || `UNKNOWN(${code})`
}

function verifySignedBody (codec, body, domainId, publicKey) {
  const value = decodeCanonical(codec, body, { copyBytes: true })
  const unsigned = body.subarray(0, body.byteLength - sodium.crypto_sign_BYTES)
  const valid = sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), publicKey)
  return { value, valid }
}

const drillFixture = powIssuanceV1DrillFixture

async function ephemeralLoopbackTls (root) {
  const keyFile = path.join(root, 'edge-tls-key.pem')
  const certFile = path.join(root, 'edge-tls-cert.pem')
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=127.0.0.1', '-days', '1',
    '-keyout', keyFile, '-out', certFile
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 })
  await fs.chmod(keyFile, 0o600)
  return Object.freeze({ key: await fs.readFile(keyFile), cert: await fs.readFile(certFile) })
}

function httpsPost (port, route, body) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: '127.0.0.1',
      port,
      path: route,
      method: 'POST',
      rejectUnauthorized: false,
      headers: { 'content-type': PROTOCOL.mediaType, 'content-length': String(body.byteLength) }
    }, response => {
      const chunks = []
      let total = 0
      response.on('data', chunk => {
        chunks.push(b4a.from(chunk))
        total += chunk.byteLength
      })
      response.once('error', reject)
      response.once('end', () => resolve({
        statusCode: response.statusCode,
        body: b4a.concat(chunks, total)
      }))
    })
    request.once('error', reject)
    request.end(body)
  })
}

// Mining yields to the event loop in batches so the in-process edge/daemon timers
// stay live — the same shape as the browser minter's promise-round batches.
async function mineNonce (challengePayload, recordCommitment, difficultyBits) {
  let nonce = 0n
  while (nonce < (1n << 30n)) {
    for (let batch = 0; batch < 4096 && nonce < (1n << 30n); batch++, nonce++) {
      const digest = createHash('sha256')
        .update(powIssuanceV1Preimage(challengePayload, recordCommitment, nonce))
        .digest()
      if (countLeadingZeroBits(digest) >= difficultyBits) return nonce
    }
    await new Promise(resolve => setImmediate(resolve))
  }
  throw new Error('mining space exhausted')
}

// The client side of the D2 flow: fetch a challenge, mint the PoW over
// challenge‖recordCommitment, redeem for a token. The issuer key never appears here.
async function redeemToken (issuerBase, recordCommitment, allowance) {
  const challengeJson = await (await fetch(`${issuerBase}/challenge`)).json()
  const challenge = b4a.from(challengeJson.challenge.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  const challengePayload = challenge.subarray(0, POW_ISSUANCE_V1_CHALLENGE_PAYLOAD_BYTES)
  const started = Date.now()
  const nonce = await mineNonce(challengePayload, recordCommitment, challengeJson.difficultyBits)
  const mintMillis = Date.now() - started
  const nonceBytes = b4a.alloc(8)
  nonceBytes.writeBigUInt64BE(nonce, 0)
  const response = await fetch(`${issuerBase}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: challengeJson.challenge,
      nonce: b4a.toString(nonceBytes, 'hex'),
      recordCommitment: b4a.toString(recordCommitment, 'hex'),
      allowance
    })
  })
  const body = await response.json()
  if (response.status !== 200) {
    const error = new Error(`redeem failed: ${body.error}`)
    error.code = body.error
    throw error
  }
  return { token: b4a.from(body.token, 'hex'), allowance: body.allowance, expiryEpoch: body.expiryEpoch, mintMillis, difficultyBits: challengeJson.difficultyBits }
}

test('pow-issuance-v1 local drills (a)-(e): public PoW-admitted CELL.PUT + INBOX through the real edge', async t => {
  const runtime = createNodeCryptoRuntime()
  const issuerKey = b4a.from(randomBytes(32))
  const issuerKeys = derivePowIssuanceV1Keys(issuerKey)

  // --- stack standup: issuer → descriptor/parameters → daemon runtime → TLS edge
  const issuer = createPowIssuanceV1Issuer({ issuerKey }) // default difficulty 20 bits
  await issuer.start()
  const issuerBase = `http://127.0.0.1:${issuer.address().port}`
  log(`issuer up at ${issuerBase} (difficulty=${issuer.difficultyBits} bits, default)`)

  const directory = await createBlindBoundaryScratch('powdrill-')
  const fixture = await drillFixture({ issuerPort: issuer.address().port, issuerKey, directory })
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey })
  const tracedAdapter = Object.freeze({
    prepare: async input => {
      try {
        return await adapter.prepare(input)
      } catch (error) {
        log(`adapter.prepare rejected: ${error.code}: ${error.message}`)
        throw error
      }
    },
    preparePreflight: async input => {
      try {
        return await adapter.preparePreflight(input)
      } catch (error) {
        log(`adapter.preparePreflight rejected: ${error.code}: ${error.message}`)
        throw error
      }
    },
    confirmAfterEof: input => adapter.confirmAfterEof(input)
  })
  let replayOffset = -15_000n
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const daemonRuntime = await assembleProductionBlindDaemon({
    bootstrap: Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() }),
    runtimeConfig: loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    resolveAdmissionAdapter: createPowIssuanceV1AdapterResolver(tracedAdapter),
    testOnlyPrivateIpcReplayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
    },
    onError: error => log(`daemon onError: ${error.code || ''} ${error.message}`),
    releaseGate: async () => {}
  })
  await daemonRuntime.start()
  replayOffset = 0n // pass the mandatory 15s replay-journal startup quarantine

  t.teardown(async () => {
    await daemonRuntime.close()
    adapter.close()
    await issuer.close()
    await removeBlindBoundaryScratch(directory)
  })

  const status = daemonRuntime.status()
  log(`runtime: v2WritePathReady=${status.v2WritePathReady} cell.productionReady=${status.cell.productionReady} cell.blockers=[${status.cell.blockers}]`)
  log(`runtime: inbox.productionReady=${status.inbox.productionReady} inbox.blockers=[${status.inbox.blockers}]`)
  log(`runtime: exclusions=[${status.exclusions.join(', ')}]`)
  log(`runtime: admissionCapture=${JSON.stringify(status.admissionCapture)}`)
  t.is(status.v2WritePathReady, true, 'write path ready with the pow adapter captured')
  t.alike(status.admissionCapture, { complete: true, required: 1, captured: 1 })
  t.absent(status.exclusions.includes('CELL_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.absent(status.exclusions.includes('INBOX_PUBLIC_EXECUTION_UNASSEMBLED'))
  t.absent(status.exclusions.includes('ADMISSION_REDEMPTION_ADAPTER_UNASSEMBLED'))
  // This tree reports the two CELL assembly-requirement blockers statically even
  // when wired (same stale-flag note as the v1-integration line; the functional
  // readiness above is the honest signal). INBOX hardening blockers stay disclosed.
  t.is(status.inbox.productionReady, false, 'INBOX hardening blockers stay disclosed')
  t.is(status.inbox.blockers.length, 5)

  const profile = fixture.descriptor.admissionProfiles[0]
  log(`descriptor profile: {profileId=${profile.profileId}, schemeId=${profile.schemeId}, conformanceClass=${profile.conformanceClass} (OPEN), roleBits=${profile.roleBits}, parameterHash=${b4a.toString(profile.parameterHash, 'hex').slice(0, 16)}…}`)
  t.is(profile.schemeId, POW_ISSUANCE_V1_SCHEME_ID)
  t.is(profile.conformanceClass, ADMISSION_CONFORMANCE_CLASS.OPEN)
  t.alike(profile.parameterHash, fixture.parameterHash)

  const tls = await ephemeralLoopbackTls(directory)
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    releaseGate: () => {},
    tls,
    onError: error => log(`edge onError: ${error.code || ''} ${error.message}`),
    readinessTopology: {
      unarySocketPath: fixture.unarySocketPath,
      streamSocketPath: fixture.streamSocketPath,
      launchTopologyHash: fixture.launchTopologyHash,
      streamTransportProfileHash: fixture.transportProfileHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    }
  })
  await edge.start()
  t.teardown(() => edge.close())
  const edgePort = edge.address().port
  log(`edge up at https://127.0.0.1:${edgePort} (self-signed local TLS)`)

  const admission = token => ({
    profileId: 8,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    parameterHash: b4a.from(fixture.parameterHash),
    token
  })
  const probe = await daemonRuntime.readiness.evaluate({
    endpointId: 1,
    transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
    signal: null
  })
  log(`readiness.evaluate probe: kind=${probe.kind} readyRoleBits=${probe.readyRoleBits} readyOperationBits=0x${(probe.readyOperationBits || 0).toString(16)}`)
  const send = async (route, encoded) => {
    const response = await httpsPost(edgePort, route, encoded.body)
    if (response.statusCode !== 200) {
      log(`edge HTTP ${response.statusCode}: ${b4a.toString(response.body.subarray(0, 200), 'utf8')}`)
      return { httpStatus: response.statusCode, ok: false }
    }
    return { httpStatus: 200, ...decodeUnaryResponse(response.body, encoded) }
  }

  // --- (e-part 1) INBOX.CREATE with a single-slot PoW token (board standup)
  const created = await createInboxReplica({
    runtime,
    relayPublicKey: fixture.relayPublicKey,
    allocationEpoch: fixture.currentEpoch,
    frameClassBits: 1,
    retentionClass: 2,
    leaseClass: 2,
    admissionProvider: async context => {
      const minted = await redeemToken(issuerBase, powIssuanceV1RecordBindingRoot([context.requestCommitment]), 1)
      log(`INBOX.CREATE token: PoW ${minted.difficultyBits} bits minted in ${minted.mintMillis}ms, allowance=${minted.allowance}, expiryEpoch=${minted.expiryEpoch}`)
      return admission(buildPowIssuanceV1Presentation(minted.token, 0, [context.requestCommitment]))
    }
  })
  const createEncoded = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.CREATE,
    body: created.requestBytes,
    expectedResultBodyBytes: created.wire.expectedResultBodyBytes
  })
  const createResponse = await send('/api/blind/v1/inbox', createEncoded)
  if (!createResponse.ok) {
    log(`INBOX.CREATE failed: ${createResponse.error ? errorName(createResponse.error.code) : `HTTP ${createResponse.httpStatus}`}`)
  }
  t.is(createResponse.httpStatus, 200)
  t.is(createResponse.ok, true)
  const createReceipt = verifySignedBody(inboxReceiptV1, createResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_RECEIPT, fixture.relayPublicKey)
  t.is(createReceipt.valid, true)
  t.is(createReceipt.value.result, INBOX_RECEIPT_RESULT.CREATED)
  log(`INBOX.CREATE receipt: result=CREATED stateRevision=${createReceipt.value.stateRevision} leaseEpoch=${createReceipt.value.leaseEpoch} signature-valid=${createReceipt.valid}`)

  // --- (a) CELL.PUT with slot 0 of a two-slot token; slot 1 pre-committed to the
  // INBOX.APPEND pointer commitment (one PoW covers PUT + APPEND, decision D2)
  const pointerFrame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x2a)
  const pointerNonce = b4a.from(randomBytes(32))
  const pointerCommitment = inboxAppendRequestCommitment({
    relayPublicKey: fixture.relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(pointerFrame),
    clientNonce: pointerNonce
  })
  let twoSlotToken = null
  let twoSlotCommitments = null
  const replica = await createCellReplica({
    runtime,
    relayPublicKey: fixture.relayPublicKey,
    allocationEpoch: fixture.currentEpoch,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('pow-issuance-v1 drill record', 'utf8'),
    admissionProvider: async context => {
      twoSlotCommitments = [b4a.from(context.requestCommitment), b4a.from(pointerCommitment)]
      const root = powIssuanceV1RecordBindingRoot(twoSlotCommitments)
      const minted = await redeemToken(issuerBase, root, 2)
      twoSlotToken = minted.token
      log(`(a) CELL.PUT token: PoW ${minted.difficultyBits} bits minted in ${minted.mintMillis}ms, allowance=${minted.allowance} (one PoW covers PUT+APPEND), expiryEpoch=${minted.expiryEpoch}`)
      return admission(buildPowIssuanceV1Presentation(minted.token, 0, twoSlotCommitments))
    }
  })
  const putEncoded = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: replica.requestBytes,
    expectedResultBodyBytes: replica.wire.expectedResultBodyBytes
  })
  const putResponse = await send('/api/blind/v1/cell', putEncoded)
  t.is(putResponse.httpStatus, 200)
  t.is(putResponse.ok, true)
  const putReceipt = verifySignedBody(blindReceiptV1, putResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.relayPublicKey)
  t.is(putReceipt.valid, true)
  t.is(putReceipt.value.result, CELL_RECEIPT_RESULT.STORED)
  t.alike(putReceipt.value.cellBlobHash, replica.request.declaredBlobHash)
  t.alike(putReceipt.value.requestCommitment, replica.requestCommitment)
  log(`(a) CELL.PUT receipt: result=STORED sizeClass=${putReceipt.value.sizeClass} leaseEpoch=${putReceipt.value.leaseEpoch} cellBlobHash=${b4a.toString(putReceipt.value.cellBlobHash, 'hex').slice(0, 16)}… signature-valid=${putReceipt.valid}`)
  log(`(a) spendTag(slot0)=${b4a.toString(powIssuanceV1SpendTag(twoSlotToken, 0), 'hex').slice(0, 16)}… spendTag(slot1)=${b4a.toString(powIssuanceV1SpendTag(twoSlotToken, 1), 'hex').slice(0, 16)}…`)

  // --- (b1) byte-identical replay of the same envelope → the spend marker makes
  // the retry idempotent: the daemon replays the stored result; no second store,
  // no second spend
  const replaySame = await httpsPost(edgePort, '/api/blind/v1/cell', putEncoded.body)
  t.is(replaySame.statusCode, 200)
  const replaySameOk = decodeUnaryResponse(replaySame.body, putEncoded)
  t.is(replaySameOk.ok, true)
  const replaySameReceipt = verifySignedBody(blindReceiptV1, replaySameOk.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.relayPublicKey)
  t.is(replaySameReceipt.valid, true)
  t.alike(replaySameReceipt.value.cellBlobHash, putReceipt.value.cellBlobHash)
  t.is(replaySameReceipt.value.leaseEpoch, putReceipt.value.leaseEpoch)
  t.is(replaySameReceipt.value.stateRevision, putReceipt.value.stateRevision)
  log(`(b1) byte-identical envelope replay: deterministic replay of the original STORED receipt (stateRevision=${replaySameReceipt.value.stateRevision}, idempotent — no second spend)`)

  // --- (b2) same body, fresh requestId → the spend tag is already marked; storage
  // answers with the deterministic replay of the original mutation (idempotent retry)
  const replayFresh = await send('/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: replica.requestBytes,
    expectedResultBodyBytes: replica.wire.expectedResultBodyBytes
  }))
  t.is(replayFresh.ok, true)
  const replayReceipt = verifySignedBody(blindReceiptV1, replayFresh.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, fixture.relayPublicKey)
  t.is(replayReceipt.valid, true)
  t.is(replayReceipt.value.result, CELL_RECEIPT_RESULT.STORED)
  t.alike(replayReceipt.value.cellBlobHash, putReceipt.value.cellBlobHash)
  t.is(replayReceipt.value.leaseEpoch, putReceipt.value.leaseEpoch)
  log(`(b2) fresh-requestId replay of the same request: deterministic replay, same STORED receipt (leaseEpoch=${replayReceipt.value.leaseEpoch})`)

  // --- (b3) re-slotting the same spend unit onto a different request → the binding
  // root check rejects it (a spend cannot authorize a different request)
  const misFrame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x33)
  const misNonce = b4a.from(randomBytes(32))
  const misCommitment = inboxAppendRequestCommitment({
    relayPublicKey: fixture.relayPublicKey,
    physicalTopic: created.readCap.physicalTopic,
    frameClass: 1,
    frameHash: blake2b256(misFrame),
    clientNonce: misNonce
  })
  const misSlotted = await createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frame: misFrame,
    frameClass: 1,
    clientNonce: misNonce,
    admission: admission(buildPowIssuanceV1Presentation(twoSlotToken, 0, [
      misCommitment,
      twoSlotCommitments[1]
    ]))
  })
  const misSlottedResponse = await send('/api/blind/v1/inbox', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: misSlotted.requestBytes,
    expectedResultBodyBytes: misSlotted.wire.expectedResultBodyBytes
  }))
  t.is(misSlottedResponse.ok, false)
  t.is(misSlottedResponse.error.code, ERROR_CODE.SPEND_INVALID)
  log(`(b3) re-slotted spend unit on a different request: rejected ${errorName(misSlottedResponse.error.code)}`)

  // --- (c) bad PoW → issuer refuses, no token exists
  const badChallenge = await (await fetch(`${issuerBase}/challenge`)).json()
  const badRedeem = await fetch(`${issuerBase}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: badChallenge.challenge,
      nonce: '00'.repeat(8),
      recordCommitment: b4a.toString(powIssuanceV1RecordBindingRoot([b4a.alloc(32, 0x99)]), 'hex')
    })
  })
  t.is(badRedeem.status, 400)
  t.is((await badRedeem.json()).error, 'POW_INSUFFICIENT_WORK')
  log('(c) bad PoW redeem: HTTP 400 POW_INSUFFICIENT_WORK, no token issued')

  // --- (d) expired token and foreign-key token → adapter rejects at preflight
  const expiredReplica = await createCellReplica({
    runtime,
    relayPublicKey: fixture.relayPublicKey,
    allocationEpoch: fixture.currentEpoch,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('expired token drill', 'utf8'),
    admissionProvider: async context => {
      const token = mintPowIssuanceV1Token(issuerKeys.tokenKey, {
        challengeId: b4a.from(randomBytes(32)),
        recordCommitment: powIssuanceV1RecordBindingRoot([context.requestCommitment]),
        allowance: 1,
        expiryEpoch: fixture.currentEpoch // already elapsed
      })
      return admission(buildPowIssuanceV1Presentation(token, 0, [context.requestCommitment]))
    }
  })
  const expiredResponse = await send('/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: expiredReplica.requestBytes,
    expectedResultBodyBytes: expiredReplica.wire.expectedResultBodyBytes
  }))
  t.is(expiredResponse.ok, false)
  t.is(expiredResponse.error.code, ERROR_CODE.SPEND_INVALID)
  log(`(d) expired token CELL.PUT: rejected ${errorName(expiredResponse.error.code)}`)

  const foreignReplica = await createCellReplica({
    runtime,
    relayPublicKey: fixture.relayPublicKey,
    allocationEpoch: fixture.currentEpoch,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: b4a.from('foreign key drill', 'utf8'),
    admissionProvider: async context => {
      const token = mintPowIssuanceV1Token(b4a.from(randomBytes(32)), {
        challengeId: b4a.from(randomBytes(32)),
        recordCommitment: powIssuanceV1RecordBindingRoot([context.requestCommitment]),
        allowance: 1,
        expiryEpoch: fixture.currentEpoch + 4
      })
      return admission(buildPowIssuanceV1Presentation(token, 0, [context.requestCommitment]))
    }
  })
  const foreignResponse = await send('/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: foreignReplica.requestBytes,
    expectedResultBodyBytes: foreignReplica.wire.expectedResultBodyBytes
  }))
  t.is(foreignResponse.ok, false)
  t.is(foreignResponse.error.code, ERROR_CODE.SPEND_INVALID)
  log(`(d) foreign-key token CELL.PUT: rejected ${errorName(foreignResponse.error.code)}`)

  // --- (e-part 2) INBOX.APPEND pointer frame with slot 1 of the drill-(a) token
  const appendOne = await createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frame: pointerFrame,
    frameClass: 1,
    clientNonce: pointerNonce,
    admission: admission(buildPowIssuanceV1Presentation(twoSlotToken, 1, twoSlotCommitments))
  })
  const appendOneResponse = await send('/api/blind/v1/inbox', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: appendOne.requestBytes,
    expectedResultBodyBytes: appendOne.wire.expectedResultBodyBytes
  }))
  t.is(appendOneResponse.ok, true)
  const appendOneAck = verifySignedBody(inboxAppendAckV1, appendOneResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, fixture.relayPublicKey)
  t.is(appendOneAck.valid, true)
  t.is(appendOneAck.value.result, INBOX_APPEND_RESULT.STORED)
  t.is(appendOneAck.value.appendRevision, 1n)
  log(`(e) INBOX.APPEND #1 (slot 1 of the drill-(a) token): STORED revision=${appendOneAck.value.appendRevision} — same PoW as the PUT`)

  const secondFrame = b4a.alloc(INBOX_FRAME_CLASS[1], 0x5c)
  const appendTwo = await createAppendInboxRequest({
    runtime,
    writeCap: created.writeCap,
    frame: secondFrame,
    frameClass: 1,
    admissionProvider: async context => {
      const minted = await redeemToken(issuerBase, powIssuanceV1RecordBindingRoot([context.requestCommitment]), 1)
      return admission(buildPowIssuanceV1Presentation(minted.token, 0, [context.requestCommitment]))
    }
  })
  const appendTwoEncoded = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: appendTwo.requestBytes,
    expectedResultBodyBytes: appendTwo.wire.expectedResultBodyBytes
  })
  const appendTwoResponse = await send('/api/blind/v1/inbox', appendTwoEncoded)
  t.is(appendTwoResponse.ok, true)
  const appendTwoAck = verifySignedBody(inboxAppendAckV1, appendTwoResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, fixture.relayPublicKey)
  t.is(appendTwoAck.valid, true)
  t.is(appendTwoAck.value.appendRevision, 2n)
  log(`(e) INBOX.APPEND #2 (fresh single-slot token): STORED revision=${appendTwoAck.value.appendRevision}`)

  const appendTwoReplay = await send('/api/blind/v1/inbox', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.APPEND,
    body: appendTwo.requestBytes,
    expectedResultBodyBytes: appendTwo.wire.expectedResultBodyBytes
  }))
  t.is(appendTwoReplay.ok, true)
  const appendTwoReplayAck = verifySignedBody(inboxAppendAckV1, appendTwoReplay.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_APPEND_ACK, fixture.relayPublicKey)
  t.is(appendTwoReplayAck.value.appendRevision, 2n, 'same-request append replay is the deterministic stored mutation')
  log('(e) same-request INBOX.APPEND replay: deterministic replay returns revision=2 (no new frame)')

  // --- (e-part 3) UNCHARGED READ cursor enumeration (admission OPTIONAL, none sent)
  const readPageOne = await createReadInboxRequest({
    runtime,
    readCap: created.readCap,
    limit: 1
  })
  const readOneResponse = await send('/api/blind/v1/inbox', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    body: readPageOne.requestBytes,
    expectedResultBodyBytes: readPageOne.wire.expectedResultBodyBytes
  }))
  t.is(readOneResponse.ok, true)
  const readOne = verifySignedBody(inboxReadResultV1, readOneResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, fixture.relayPublicKey)
  t.is(readOne.valid, true)
  t.is(readOne.value.entries.length, 1)
  t.alike(readOne.value.entries[0].frameHash, blake2b256(pointerFrame))
  t.ok(readOne.value.nextCursor != null)
  log(`(e) UNCHARGED INBOX.READ page 1 (limit 1): ${readOne.value.entries.length} frame, snapshotRevision=${readOne.value.snapshotRevision}, nextCursor present, signature-valid=${readOne.valid}`)

  const readPageTwo = await createReadInboxRequest({
    runtime,
    readCap: created.readCap,
    cursor: readOne.value.nextCursor,
    limit: 64
  })
  const readTwoResponse = await send('/api/blind/v1/inbox', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.INBOX,
    operationId: OPERATION.INBOX.READ,
    body: readPageTwo.requestBytes,
    expectedResultBodyBytes: readPageTwo.wire.expectedResultBodyBytes
  }))
  t.is(readTwoResponse.ok, true)
  const readTwo = verifySignedBody(inboxReadResultV1, readTwoResponse.body,
    RESULT_SIGNATURE_DOMAIN_ID.INBOX_READ_RESULT, fixture.relayPublicKey)
  t.is(readTwo.valid, true)
  t.is(readTwo.value.entries.length, 1)
  t.alike(readTwo.value.entries[0].frameHash, blake2b256(secondFrame))
  t.is(readTwo.value.nextCursor, null)
  log(`(e) UNCHARGED INBOX.READ page 2 from cursor: ${readTwo.value.entries.length} frame, nextCursor absent (enumeration complete)`)

  log('drills (a)-(e) complete')
})
