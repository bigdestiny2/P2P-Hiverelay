import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  applyPublicHiveGatewayEnv,
  assertPublicHiveGatewayConcurrency,
  assertPublicHiveGatewayFiniteLimits,
  assertPublicHiveGatewayVersionPins
} from '../../packages/core/config/public-hive-gateway-env.js'

const KEY_A = 'A'.repeat(64)
const KEY_B = 'b'.repeat(64)

test('public Hive gateway env: parses every deployment field into runtime types', (t) => {
  const overrides = applyPublicHiveGatewayEnv({}, {}, {
    HIVERELAY_GATEWAY_HOST: '127.0.0.1',
    HIVERELAY_GATEWAY_PORT: '9200',
    HIVERELAY_GATEWAY_TRUST_PROXY: '1',
    HIVERELAY_GATEWAY_TRUSTED_PROXY_ADDRESSES: '127.0.0.1, ::1, ::ffff:127.0.0.1',
    HIVERELAY_GATEWAY_REQUIRE_FORWARDED_SNI: 'true',
    HIVERELAY_GATEWAY_COMPATIBILITY_HOSTS: 'localhost,127.0.0.1:9200,[::1]',
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT: '256',
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT_PER_APP: '32',
    HIVERELAY_GATEWAY_MAX_RESPONSE_BYTES: '67108864',
    HIVERELAY_GATEWAY_MAX_TRANSFORM_BYTES: '4194304',
    HIVERELAY_GATEWAY_EGRESS_BYTES_PER_WINDOW: '268435456',
    HIVERELAY_GATEWAY_EGRESS_WINDOW_MS: '60000',
    HIVERELAY_GATEWAY_MAX_RESPONSE_LIFETIME_MS: '900000',
    HIVERELAY_HIVE_APP_HOST_SUFFIX: 'Hive.Operator.Example.',
    HIVERELAY_HIVE_APP_PUBLIC_KEYS: `${KEY_A},${KEY_B},${KEY_A}`,
    HIVERELAY_HIVE_APP_PUBLIC_VERSIONS: JSON.stringify({ [KEY_A]: 7, [KEY_B]: 8 })
  })

  t.is(overrides.gatewayHost, '127.0.0.1')
  t.is(overrides.gatewayPort, 9200)
  t.is(overrides.gatewayTrustProxy, true)
  t.alike(overrides.gatewayTrustedProxyAddresses, ['127.0.0.1', '::1'])
  t.is(overrides.gatewayRequireForwardedSNI, true)
  t.alike(overrides.gatewayCompatibilityHosts, ['localhost', '127.0.0.1', '[::1]'])
  t.is(overrides.gatewayMaxInFlight, 256)
  t.is(overrides.gatewayMaxInFlightPerApp, 32)
  t.is(overrides.gatewayMaxResponseBytes, 67108864)
  t.is(overrides.gatewayMaxTransformBytes, 4194304)
  t.is(overrides.gatewayEgressBytesPerWindow, 268435456)
  t.is(overrides.gatewayEgressWindowMs, 60000)
  t.is(overrides.gatewayMaxResponseLifetimeMs, 900000)
  t.is(overrides.hiveAppHostSuffix, 'hive.operator.example')
  t.alike(overrides.hiveAppPublicKeys, [KEY_A.toLowerCase(), KEY_B])
  t.alike(overrides.hiveAppPublicVersions, { [KEY_A.toLowerCase()]: 7, [KEY_B]: 8 })
})

test('public Hive gateway env: flags beat env and existing CLI overrides beat env', (t) => {
  const overrides = {
    gatewayHost: '127.0.0.2',
    gatewayMaxInFlight: 128
  }

  applyPublicHiveGatewayEnv(overrides, {
    'gateway-port': '9400',
    'gateway-trust-proxy': false,
    'gateway-trusted-proxy-address': ['127.0.0.1', '::1'],
    'gateway-compatibility-host': ['localhost', '127.0.0.1'],
    'gateway-max-in-flight-per-app': '16',
    'hive-app-public-key': [KEY_A, KEY_B],
    'hive-app-public-version': [`${KEY_A}=11`, `${KEY_B}=12`]
  }, {
    HIVERELAY_GATEWAY_HOST: '127.0.0.3',
    HIVERELAY_GATEWAY_PORT: '9200',
    HIVERELAY_GATEWAY_TRUST_PROXY: 'true',
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT: '512',
    HIVERELAY_HIVE_APP_PUBLIC_KEYS: 'c'.repeat(64)
  })

  t.is(overrides.gatewayHost, '127.0.0.2', 'an earlier CLI override is not replaced by env')
  t.is(overrides.gatewayPort, 9400, 'gateway flag beats env')
  t.is(overrides.gatewayTrustProxy, false, 'explicit false flag beats true env')
  t.is(overrides.gatewayMaxInFlight, 128, 'existing concurrency override beats env')
  t.is(overrides.gatewayMaxInFlightPerApp, 16)
  t.alike(overrides.gatewayTrustedProxyAddresses, ['127.0.0.1', '::1'])
  t.alike(overrides.gatewayCompatibilityHosts, ['localhost', '127.0.0.1'])
  t.alike(overrides.hiveAppPublicKeys, [KEY_A.toLowerCase(), KEY_B])
  t.alike(overrides.hiveAppPublicVersions, { [KEY_A.toLowerCase()]: 11, [KEY_B]: 12 })

  const numericBooleanFlags = applyPublicHiveGatewayEnv({}, {
    'gateway-trust-proxy': 1,
    'gateway-require-forwarded-sni': 0
  }, {})
  t.is(numericBooleanFlags.gatewayTrustProxy, true)
  t.is(numericBooleanFlags.gatewayRequireForwardedSNI, false)
})

test('public Hive gateway env: rejects partial, unsafe, and cross-field values', (t) => {
  const invalid = [
    ['HIVERELAY_GATEWAY_HOST', '127.0.0.1:9200', /HIVERELAY_GATEWAY_HOST/],
    ['HIVERELAY_GATEWAY_PORT', '9200x', /HIVERELAY_GATEWAY_PORT/],
    ['HIVERELAY_GATEWAY_PORT', '09200', /HIVERELAY_GATEWAY_PORT/],
    ['HIVERELAY_GATEWAY_PORT', '1e3', /HIVERELAY_GATEWAY_PORT/],
    ['HIVERELAY_GATEWAY_PORT', '65536', /HIVERELAY_GATEWAY_PORT/],
    ['HIVERELAY_GATEWAY_TRUST_PROXY', 'yes', /HIVERELAY_GATEWAY_TRUST_PROXY/],
    ['HIVERELAY_GATEWAY_TRUSTED_PROXY_ADDRESSES', '127.0.0.1,not-an-ip', /HIVERELAY_GATEWAY_TRUSTED_PROXY_ADDRESSES/],
    ['HIVERELAY_GATEWAY_REQUIRE_FORWARDED_SNI', '', /HIVERELAY_GATEWAY_REQUIRE_FORWARDED_SNI/],
    ['HIVERELAY_GATEWAY_COMPATIBILITY_HOSTS', '*.operator.example', /HIVERELAY_GATEWAY_COMPATIBILITY_HOSTS/],
    ['HIVERELAY_GATEWAY_MAX_IN_FLIGHT', '4097', /HIVERELAY_GATEWAY_MAX_IN_FLIGHT/],
    ['HIVERELAY_GATEWAY_MAX_IN_FLIGHT_PER_APP', '32.5', /HIVERELAY_GATEWAY_MAX_IN_FLIGHT_PER_APP/],
    ['HIVERELAY_GATEWAY_MAX_RESPONSE_BYTES', '0', /HIVERELAY_GATEWAY_MAX_RESPONSE_BYTES/],
    ['HIVERELAY_GATEWAY_MAX_TRANSFORM_BYTES', '4MiB', /HIVERELAY_GATEWAY_MAX_TRANSFORM_BYTES/],
    ['HIVERELAY_GATEWAY_EGRESS_BYTES_PER_WINDOW', 'Infinity', /HIVERELAY_GATEWAY_EGRESS_BYTES_PER_WINDOW/],
    ['HIVERELAY_GATEWAY_EGRESS_WINDOW_MS', '999', /HIVERELAY_GATEWAY_EGRESS_WINDOW_MS/],
    ['HIVERELAY_GATEWAY_MAX_RESPONSE_LIFETIME_MS', '3600001', /HIVERELAY_GATEWAY_MAX_RESPONSE_LIFETIME_MS/],
    ['HIVERELAY_HIVE_APP_HOST_SUFFIX', 'localhost', /HIVERELAY_HIVE_APP_HOST_SUFFIX/],
    ['HIVERELAY_HIVE_APP_PUBLIC_KEYS', 'not-a-key', /HIVERELAY_HIVE_APP_PUBLIC_KEYS/],
    ['HIVERELAY_HIVE_APP_PUBLIC_KEYS', '', /HIVERELAY_HIVE_APP_PUBLIC_KEYS/],
    ['HIVERELAY_HIVE_APP_PUBLIC_VERSIONS', '{not-json', /HIVERELAY_HIVE_APP_PUBLIC_VERSIONS/],
    ['HIVERELAY_HIVE_APP_PUBLIC_VERSIONS', JSON.stringify({ [KEY_A]: '7' }), /HIVERELAY_HIVE_APP_PUBLIC_VERSIONS/]
  ]

  for (const [name, value, pattern] of invalid) {
    t.exception(() => applyPublicHiveGatewayEnv({}, {}, { [name]: value }), pattern, `${name} rejects ${JSON.stringify(value)}`)
  }

  t.exception(() => applyPublicHiveGatewayEnv({}, {}, {
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT: '16',
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT_PER_APP: '17'
  }), /must not exceed/, 'per-app concurrency cannot exceed the global limit')

  t.execution(() => assertPublicHiveGatewayConcurrency({
    gatewayMaxInFlight: 256,
    gatewayMaxInFlightPerApp: 32
  }), 'merged runtime defaults are valid')
  t.exception(() => assertPublicHiveGatewayConcurrency({
    gatewayMaxInFlight: 16,
    gatewayMaxInFlightPerApp: 32
  }), /must not exceed/, 'merged config catches a one-sided override conflict')
  t.exception(() => assertPublicHiveGatewayConcurrency({
    gatewayMaxInFlight: '256',
    gatewayMaxInFlightPerApp: 32
  }), /gatewayMaxInFlight/, 'merged config never accepts numeric strings')
  t.execution(() => assertPublicHiveGatewayFiniteLimits({
    productProfile: 'public-t1-gateway',
    gatewayMaxResponseBytes: 67108864,
    gatewayMaxTransformBytes: 4194304,
    gatewayEgressBytesPerWindow: 268435456,
    gatewayEgressWindowMs: 60000,
    gatewayMaxResponseLifetimeMs: 900000
  }), 'merged finite production values are valid')
  t.exception(() => assertPublicHiveGatewayFiniteLimits({
    productProfile: 'public-t1-gateway',
    gatewayMaxResponseBytes: 67108863,
    gatewayMaxTransformBytes: 4194304,
    gatewayEgressBytesPerWindow: 268435456,
    gatewayEgressWindowMs: 60000,
    gatewayMaxResponseLifetimeMs: 900000
  }), /gatewayMaxResponseBytes must equal 67108864/,
  'public-t1-gateway cannot weaken or strengthen an exact signed finite value')
  t.exception(() => assertPublicHiveGatewayFiniteLimits({
    gatewayMaxResponseBytes: 1024,
    gatewayMaxTransformBytes: 2048,
    gatewayEgressBytesPerWindow: 268435456,
    gatewayEgressWindowMs: 60000,
    gatewayMaxResponseLifetimeMs: 900000
  }), /must not exceed/, 'transform budget cannot exceed the response budget')
  t.execution(() => assertPublicHiveGatewayVersionPins({
    hiveAppPublicKeys: [KEY_A],
    hiveAppPublicVersions: { [KEY_A]: 7 }
  }))
  t.exception(() => assertPublicHiveGatewayVersionPins({
    hiveAppPublicKeys: [KEY_A],
    hiveAppPublicVersions: { [KEY_B]: 7 }
  }), /outside hiveAppPublicKeys/)
  t.exception(() => applyPublicHiveGatewayEnv({}, {
    'gateway-prt': '9200'
  }, {}), /Unknown public Hive gateway option: --gateway-prt/, 'gateway option typos cannot be silently ignored')
})

test('public Hive gateway CLI: invalid env and flags fail before node boot', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-public-gateway-env-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const baseEnv = {
    HOME: home,
    NO_COLOR: '1',
    PATH: process.env.PATH || ''
  }
  const badEnv = await execCli(['start'], {
    ...baseEnv,
    HIVERELAY_GATEWAY_PORT: '9200junk'
  })
  t.is(badEnv.code, 1)
  t.ok(badEnv.stderr.includes('Invalid HIVERELAY_GATEWAY_PORT'))

  const badFlag = await execCli(['start', '--gateway-port=9200junk'], {
    ...baseEnv,
    HIVERELAY_GATEWAY_PORT: '9200'
  })
  t.is(badFlag.code, 1)
  t.ok(badFlag.stderr.includes('Invalid --gateway-port'), 'invalid flag wins over valid env')

  const badMergedConcurrency = await execCli(['start'], {
    ...baseEnv,
    HIVERELAY_GATEWAY_MAX_IN_FLIGHT: '16'
  })
  t.is(badMergedConcurrency.code, 1)
  t.ok(badMergedConcurrency.stderr.includes('gatewayMaxInFlightPerApp must not exceed gatewayMaxInFlight'))

  const unknownFlag = await execCli(['start', '--hive-app-host-sufix=hive.operator.example'], baseEnv)
  t.is(unknownFlag.code, 1)
  t.ok(unknownFlag.stderr.includes('Unknown public Hive gateway option'))
})

function execCli (argv, env) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['packages/core/cli/index.js', ...argv], {
      cwd: process.cwd(),
      env,
      timeout: 10_000
    }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(err)
      resolve({
        code: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}
