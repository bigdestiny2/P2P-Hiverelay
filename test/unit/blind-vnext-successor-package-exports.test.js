import test from 'brittle'
import * as protocol from '@hiverelay/blind-protocol'
import * as ipc from '@hiverelay/blind-ipc'
import * as browserV3 from '../../packages/blind-client/browser-artifact-v3.js'

test('successor protocol and IPC contracts are reachable through owned additive package root exports', t => {
  for (const [module, names] of [
    [protocol, [
      'decodeWireAbiV3',
      'blindForwardHttpsOriginForwardTurnRequestV1',
      'blindForwardHttpsOriginForwardTurnResultV1',
      'forwardHttpsParentCapabilityPrefixHashV1',
      'forwardHttpsCapabilityPrefixHashV1',
      'assertForwardHttpsForwardedRequestAuthorityV1',
      'assertForwardHttpsResultForOriginRequestV1',
      'assertForwardHttpsTargetResultForForwardedRequestV1',
      'decodeClientCompositionV3',
      'CLIENT_COMPOSITION_AUTHORITY_V3'
    ]],
    [ipc, [
      'decodePrivateIpcV4Registry',
      'decodeLocalForwardHttpsOriginAuthorityV4',
      'decodeLocalForwardHttpsTurnV4',
      'decodeLocalForwardHttpsTargetIngressV4',
      'PRIVATE_IPC_V4_STATUS'
    ]]
  ]) {
    for (const name of names) t.ok(name in module, `${name} is exported`)
  }
})

test('successor browser contract is reachable through its additive v3 module', t => {
  for (const name of [
    'decodeBlindClientBrowserArtifactManifestV3',
    'verifyBlindClientBrowserArtifactV3',
    'BlindClientBrowserCrashModelV3'
  ]) t.ok(name in browserV3, `${name} is exported`)
})
