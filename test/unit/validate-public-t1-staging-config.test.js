import test from 'brittle'
import { spawnSync } from 'child_process'
import { mkdtemp, writeFile, rm } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import { validateStagingConfigObject } from '../../scripts/validate-public-t1-staging-config.mjs'

const script = fileURLToPath(new URL('../../scripts/validate-public-t1-staging-config.mjs', import.meta.url))
const KEY = 'a'.repeat(64)

const GOOD = {
  mode: 'public-t1-gateway',
  productProfile: 'public-t1-gateway',
  requirePhysicalEnforcement: true,
  enableAPI: true,
  enableSeeding: true,
  enableRelay: false,
  enableServices: false,
  plugins: [],
  apiHost: '127.0.0.1',
  apiPort: 9100,
  gatewayHost: '127.0.0.1',
  gatewayPort: 9200,
  gatewayTrustProxy: true,
  gatewayTrustedProxyAddresses: ['127.0.0.1', '::1', '::ffff:127.0.0.1'],
  gatewayRequireForwardedSNI: true,
  gatewayCompatibilityHosts: ['127.0.0.1', 'localhost', '[::1]'],
  gatewayMaxInFlight: 256,
  gatewayMaxInFlightPerApp: 32,
  gatewayMaxResponseBytes: 67108864,
  gatewayMaxTransformBytes: 4194304,
  gatewayEgressBytesPerWindow: 268435456,
  gatewayEgressWindowMs: 60000,
  gatewayMaxResponseLifetimeMs: 900000,
  custody: { enabled: false },
  hiveAppHostSuffix: 'hive-canary.staging.example',
  hiveAppPublicKeys: [KEY],
  hiveAppPublicVersions: { [KEY]: 1 }
}

test('staging validator - good single-app public-t1 config passes', (t) => {
  const result = validateStagingConfigObject(GOOD, { apiKeyPresent: true })
  t.ok(result.ok)
  t.alike(result.errors, [])
  t.ok(result.footgunsChecked.includes('exactly-one-public-app-key'))
  t.ok(result.footgunsChecked.includes('custody-disabled'))
  t.ok(result.footgunsChecked.includes('finite-max-response-bytes'))
})

test('staging validator - multi-app canary is refused', (t) => {
  const key2 = 'b'.repeat(64)
  const result = validateStagingConfigObject({
    ...GOOD,
    hiveAppPublicKeys: [KEY, key2],
    hiveAppPublicVersions: { [KEY]: 1, [key2]: 1 }
  }, { apiKeyPresent: true })
  t.absent(result.ok)
  t.ok(result.errors.some(e => /exactly one|Phase 1 must expose exactly one/i.test(e)))
})

test('staging validator - custody enabled is refused', (t) => {
  const result = validateStagingConfigObject({
    ...GOOD,
    custody: { enabled: true }
  }, { apiKeyPresent: true })
  t.absent(result.ok)
  t.ok(result.errors.some(e => /custody\.enabled must be false/i.test(e)))
})

test('staging validator - null maxResponseBytes / missing finite pin is refused', (t) => {
  const broken = { ...GOOD }
  delete broken.gatewayMaxResponseBytes
  const result = validateStagingConfigObject(broken, { apiKeyPresent: true })
  t.absent(result.ok)
  t.ok(result.errors.some(e => /gatewayMaxResponseBytes/i.test(e)))
})

test('staging validator - wrong productProfile is refused', (t) => {
  const result = validateStagingConfigObject({
    ...GOOD,
    productProfile: 'relay-core'
  }, { apiKeyPresent: true })
  t.absent(result.ok)
  t.ok(result.errors.some(e => /public-t1-gateway/i.test(e)))
})

test('staging validator CLI - example config passes with --json', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 't1-validate-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const cfgPath = path.join(dir, 'cfg.json')
  await writeFile(cfgPath, JSON.stringify(GOOD))

  const proc = spawnSync(process.execPath, [script, '--config', cfgPath, '--json'], {
    env: { ...process.env, HIVERELAY_API_KEY: 'staging-test-key' },
    encoding: 'utf8'
  })
  t.is(proc.status, 0, proc.stderr || proc.stdout)
  const body = JSON.parse(proc.stdout)
  t.ok(body.ok)
  t.is(body.mode, 'canary')
})

test('staging validator CLI - multi-app exits 1', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 't1-validate-bad-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const key2 = 'c'.repeat(64)
  const cfgPath = path.join(dir, 'cfg.json')
  await writeFile(cfgPath, JSON.stringify({
    ...GOOD,
    hiveAppPublicKeys: [KEY, key2],
    hiveAppPublicVersions: { [KEY]: 1, [key2]: 1 }
  }))

  const proc = spawnSync(process.execPath, [script, '--config', cfgPath], {
    env: { ...process.env, HIVERELAY_API_KEY: 'staging-test-key' },
    encoding: 'utf8'
  })
  t.is(proc.status, 1)
  t.ok(/FAIL|exactly one|Phase 1/i.test(proc.stdout + proc.stderr))
})
