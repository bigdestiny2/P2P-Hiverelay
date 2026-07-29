import { webcrypto } from 'node:crypto'
import b4a from 'b4a'
import test from 'brittle'
import {
  ENDPOINT_ROLE,
  FAMILY,
  OPERATION,
  PRIVACY_PROFILE,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol'
import { createRealBlindRelayTestFixture } from '../../scripts/run-real-blind-relay-lab.mjs'

const browserClientUrl = new URL(
  '../../packages/blind-client/browser-artifacts/blind-client-control-v1.mjs',
  import.meta.url
)

test('real relay fixture exports sufficient public metadata for the shipped browser client', { timeout: 45_000 }, async t => {
  const client = await import(browserClientUrl)
  const fixture = await createRealBlindRelayTestFixture()
  try {
    const config = fixture.browserQualificationConfig()
    t.is(config.schema, 'HiveRelayRealBlindBrowserQualificationConfigV1')
    t.is(config.localTestOnly, true)
    t.is(config.currentEpoch, fixture.currentEpoch)
    t.ok(Object.isFrozen(config))
    t.ok(Object.isFrozen(config.candidate))
    t.ok(Object.isFrozen(config.genesis))
    t.ok(Object.isFrozen(config.supportedProtocolProfiles))
    t.ok(Object.isFrozen(config.supportedTransportProfiles))
    t.ok(Object.isFrozen(config.advertisedAdmissionProfile))

    for (const value of [
      config.candidate.canonicalUrl,
      config.candidate.expectedDescriptorHash,
      config.candidate.continuityRootRelayPublicKey,
      config.candidate.storeId,
      config.genesis.descriptorBytes,
      config.genesis.descriptorHash,
      config.supportedProtocolProfiles[0].profileHash,
      config.supportedTransportProfiles[0].transportProfileHash,
      config.advertisedAdmissionProfile.parameterHash
    ]) t.ok(value instanceof Uint8Array)
    if (config.advertisedAdmissionProfile.parameterUrl != null) {
      t.ok(config.advertisedAdmissionProfile.parameterUrl instanceof Uint8Array)
    }

    const descriptorHash = config.candidate.expectedDescriptorHash
    const descriptorHashSnapshot = b4a.from(descriptorHash)
    descriptorHash[0] ^= 0xff
    t.alike(config.candidate.expectedDescriptorHash, descriptorHashSnapshot)
    const storeId = config.candidate.storeId
    const storeIdSnapshot = b4a.from(storeId)
    storeId.fill(0)
    t.alike(config.candidate.storeId, storeIdSnapshot)

    t.alike(config.cellPutRequirement, {
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.PUT,
      endpointId: 1,
      requiredRoleBits: ENDPOINT_ROLE.STORAGE,
      privacyProfileBit: PRIVACY_PROFILE.DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
    t.alike(config.cellGetRequirement, {
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      endpointId: 1,
      requiredRoleBits: ENDPOINT_ROLE.STORAGE,
      privacyProfileBit: PRIVACY_PROFILE.DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
    t.alike(config.admissionParametersRequirement, {
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.ADMISSION_PARAMETERS,
      endpointId: 1,
      requiredRoleBits: ENDPOINT_ROLE.QUOTA_REDEEMER,
      privacyProfileBit: PRIVACY_PROFILE.DIRECT,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })

    const runtime = client.createBrowserCryptoRuntime(webcrypto)
    const trustStore = new client.DescriptorTrustStore()
    const verifiedGenesis = client.verifyDescriptorBytes(config.genesis.descriptorBytes, {
      nowEpoch: config.currentEpoch,
      supportedProtocolProfiles: config.supportedProtocolProfiles,
      supportedTransportProfiles: config.supportedTransportProfiles
    })
    await trustStore.accept(verifiedGenesis, {
      pinnedDescriptorHash: config.genesis.descriptorHash,
      continuityRootRelayPublicKey: config.candidate.continuityRootRelayPublicKey
    })
    const qualifier = new client.BlindRelayQualifier({
      runtime,
      nowEpoch: () => config.currentEpoch,
      fetch: fixture.fetch,
      trustStore,
      supportedProtocolProfiles: config.supportedProtocolProfiles,
      supportedTransportProfiles: config.supportedTransportProfiles
    })

    const qualifiedPut = await qualifier.qualifyCandidate(
      config.candidate,
      config.cellPutRequirement
    )
    const qualifiedGet = await qualifier.qualifyCandidate(
      config.candidate,
      config.cellGetRequirement
    )
    const qualifiedAdmission = await qualifier.qualifyCandidate(
      config.candidate,
      config.admissionParametersRequirement
    )
    t.is(client.verifiedEndpointContext(qualifiedPut.endpoint).operationId, OPERATION.CELL.PUT)
    t.is(client.verifiedEndpointContext(qualifiedGet.endpoint).operationId, OPERATION.CELL.GET)
    t.is(client.verifiedEndpointContext(qualifiedAdmission.endpoint).operationId,
      OPERATION.DESCRIBE.ADMISSION_PARAMETERS)

    const admissionRequest = client.createAdmissionParametersRequest({
      runtime,
      profileId: config.advertisedAdmissionProfile.profileId,
      schemeId: config.advertisedAdmissionProfile.schemeId
    })
    const direct = new client.BlindDirectHttpClient({ runtime, fetch: fixture.fetch })
    const admissionResult = await direct.request({
      endpoint: qualifiedAdmission.endpoint,
      ...admissionRequest.wire,
      body: admissionRequest.requestBytes
    })
    t.is(admissionResult.ok, true)
    let verifiedAdmission
    try {
      verifiedAdmission = client.verifyAdmissionParametersBytes(
        admissionResult.body,
        qualifiedAdmission.trustedDescriptor,
        config.advertisedAdmissionProfile,
        { nowEpoch: config.currentEpoch }
      )
    } catch (error) {
      t.fail(`advertised admission profile did not verify: ${error.code || 'ERROR'} ${error.message}`)
      return
    }
    t.ok(b4a.equals(
      verifiedAdmission.parameterHash,
      config.advertisedAdmissionProfile.parameterHash
    ))
    t.is(fixture.errors().length, 0)
  } finally {
    await fixture.close()
  }
})
