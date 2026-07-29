export const PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE = 'public-t1-gateway'

export const PUBLIC_HIVE_GATEWAY_FINITE_POLICY = Object.freeze({
  schema: 'hiverelay-public-gateway-finite-policy-v1',
  maxResponseBytes: 64 * 1024 * 1024,
  maxTransformBytes: 4 * 1024 * 1024,
  oversizedFullOrHeadStatus: 413,
  oversizedRangeStatus: 416,
  unsupportedRangeStatus: 416,
  multiRangeStatus: 416,
  unsupportedProofAcceptStatus: 406,
  egressBytesPerClientAppWindow: 256 * 1024 * 1024,
  egressWindowMs: 60 * 1000,
  maxResponseLifetimeMs: 15 * 60 * 1000
})

export const PUBLIC_HIVE_GATEWAY_FINITE_CONFIG_FIELDS = Object.freeze({
  gatewayMaxResponseBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseBytes,
  gatewayMaxTransformBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxTransformBytes,
  gatewayEgressBytesPerWindow: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressBytesPerClientAppWindow,
  gatewayEgressWindowMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressWindowMs,
  gatewayMaxResponseLifetimeMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseLifetimeMs
})
