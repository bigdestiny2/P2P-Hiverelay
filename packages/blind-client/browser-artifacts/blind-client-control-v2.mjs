/* eslint-disable */
export * from './blind-client-control-v1.mjs'
export const BLIND_CLIENT_CONTROL_V2_AUTHORITY = Object.freeze({
  "profile": "blind-client-control-v2",
  "wireV2AbiHash": "cc1abb0e24bd4c75e0cb99b824e114cf50ad91270362f39d8594a826e29d5053",
  "clientCompositionV2FormatHash": "e289e6a1658db9f63c79ae13b50a055e16eccc997ef4c752bf1c94090b91dcc2",
  "releaseProfileId": 2,
  "routeKind": 7,
  "exactRequestBytes": 65536,
  "exactResultBytes": 65536,
  "forwardDescriptorOperationBits": 0,
  "forwardAdvertisedOperationBits": 0,
  "forwardReadinessOperationBits": 0,
  "runtimeReady": false
})
function bytes (value, length, field) {
  if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) throw new TypeError(field + ' must be ArrayBuffer-backed bytes')
  const output = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  if (output.byteLength !== length) throw new RangeError(field + ' must be exactly ' + length + ' bytes')
  return new Uint8Array(output)
}
export function assertForwardHttpsBrowserCellV2 (value) {
  if (!value || typeof value !== 'object') throw new TypeError('browser cell must be an object')
  for (const field of ['url', 'host', 'hostname', 'ip', 'ipAddress', 'dialAddress', 'credentials']) {
    if (field in value) throw new TypeError('browser cell ' + field + ' is forbidden')
  }
  if (value.releaseProfileId !== 2 || value.routeKind !== 7 || value.credentialsMode !== 'omit' ||
      value.cacheMode !== 'no-store' || value.redirectMode !== 'error' || value.referrerPolicy !== 'no-referrer') {
    throw new TypeError('browser cell privacy policy is invalid')
  }
  return Object.freeze({ body: bytes(value.body, 65536, 'body'), releaseProfileId: 2, routeKind: 7 })
}
