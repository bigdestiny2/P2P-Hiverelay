import b4a from 'b4a'
import test from 'brittle'
import {
  FAMILY,
  OPERATION,
  TRANSPORT_ID,
  encodeCanonical,
  getCellResultV1
} from '@hiverelay/blind-protocol'
import { createCellReplica } from '../requests.js'
import {
  VerifiedCellGetResult,
  openVerifiedCellGetResult,
  verifyCellGetResult
} from '../cell-get-results.js'
import { createGetCellRequest } from '../cell-get-requests.js'
import { createBlindCellGetControl } from '../cell-get-control.js'
import { createNodeCryptoRuntime } from '../runtime/node.js'
import { verifiedEndpointFixture } from './endpoint-fixture.js'

const runtime = createNodeCryptoRuntime()

async function fixture () {
  const relayPublicKey = b4a.alloc(32, 0x31)
  const structuredContent = b4a.from('bounded Peerit seed record')
  const replica = await createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 7,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x32),
      token: b4a.from([0x33])
    }
  })
  const get = await createGetCellRequest({ runtime, readCap: replica.readCap })
  const endpoint = verifiedEndpointFixture({
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
  }, FAMILY.CELL, OPERATION.CELL.GET, { relayPublicKey })
  const resultBytes = encodeCanonical(getCellResultV1, {
    version: 1,
    sizeClass: replica.readCap.sizeClass,
    cellBlob: replica.request.cellBlob
  })
  return { endpoint, get, replica, resultBytes, structuredContent }
}

test('GET-only control composes, verifies and opens the exact capability-selected Cell', async t => {
  const value = await fixture()
  const verified = verifyCellGetResult({
    endpoint: value.endpoint,
    request: value.get.request,
    requestCommitment: value.get.requestCommitment,
    resultBytes: value.resultBytes
  })
  t.ok(verified instanceof VerifiedCellGetResult)
  t.alike(await openVerifiedCellGetResult({
    verifiedResult: verified,
    runtime,
    readCap: value.replica.readCap
  }), value.structuredContent)
})

test('GET-only result brand and endpoint reject substitution', async t => {
  const value = await fixture()
  const putEndpoint = verifiedEndpointFixture({
    endpointId: 1,
    transportId: TRANSPORT_ID.HTTPS_DIRECT,
    envelopeClassBits: 0x007e,
    canonicalUrl: b4a.from('https://relay.example:443/api/blind/v1/describe')
  }, FAMILY.CELL, OPERATION.CELL.PUT, { relayPublicKey: value.replica.readCap.relayPublicKey })
  t.exception(() => verifyCellGetResult({
    endpoint: putEndpoint,
    request: value.get.request,
    requestCommitment: value.get.requestCommitment,
    resultBytes: value.resultBytes
  }), /not CELL.GET/)
  await t.exception(openVerifiedCellGetResult({
    verifiedResult: Object.create(VerifiedCellGetResult.prototype),
    runtime,
    readCap: value.replica.readCap
  }), /package-owned/)
})

test('public Cell-GET control exposes no generic transport or operation selector', async t => {
  let fetches = 0
  const control = createBlindCellGetControl({
    runtime,
    nowEpoch: () => 7,
    supportedProtocolProfiles: [{
      protocolId: 1,
      major: 1,
      minimumMinor: 0,
      profileHash: b4a.alloc(32, 0x0a)
    }],
    supportedTransportProfiles: [{
      transportId: TRANSPORT_ID.HTTPS_DIRECT,
      transportSupportBit: 1,
      transportProfileHash: b4a.alloc(32, 0x0b)
    }],
    fetch: async () => {
      fetches++
      throw new Error('must not dial')
    }
  })
  t.ok(Object.isFrozen(control))
  t.alike(Object.keys(control), [])
  for (const attempt of [
    control.fetchDescriptorHead({ canonicalUrl: b4a.from('https://relay.example'), familyId: FAMILY.CELL }),
    control.qualifyCellGetCandidate({}, { operationId: OPERATION.CELL.PUT }),
    control.readCell({ operationId: OPERATION.CELL.PUT })
  ]) {
    await t.exception(attempt, /cannot select a family, operation, body, or envelope class/)
  }
  t.is(fetches, 0, 'caller-selected operations are rejected before network I/O')
})
