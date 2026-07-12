import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  mkdtemp,
  link,
  readFile,
  rm,
  symlink,
  writeFile
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import {
  PUBLIC_HIVE_GATEWAY_PROBE_CHECKS,
  readAndVerifyPublicHiveGatewayEvidence,
  verifyPublicHiveGatewayEvidence
} from '../../scripts/lib/public-hive-gateway-evidence.mjs'
import {
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from '../../scripts/lib/public-hive-gateway-policy.mjs'

const RELEASE_TARGET = 'v1.2.3'
const RELEASE_SHA = 'a'.repeat(40)
const APP_KEY = 'a'.repeat(64)
const APP_LABEL = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
const APP_ORIGIN = `https://${APP_LABEL}.hive-canary.example`
const FINGERPRINT = Array(32).fill('AA').join(':')
const NOW = Date.now()

test('public gateway evidence verifier binds a live proof to the exact release', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-evidence-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'live.json')
  const contents = Buffer.from(JSON.stringify(validEvidence(), null, 2) + '\n')
  await writeFile(file, contents, { mode: 0o600 })

  const result = await readAndVerifyPublicHiveGatewayEvidence({
    file,
    releaseTarget: RELEASE_TARGET,
    releaseSha: RELEASE_SHA
  })

  t.is(result.status, 'verified')
  t.is(result.releaseTarget, RELEASE_TARGET)
  t.is(result.releaseSha, RELEASE_SHA)
  t.is(result.contentSha256, 'b'.repeat(64))
  t.is(result.tlsProtocol, 'TLSv1.3')
  t.is(result.mode, 'fleet')
  t.is(result.admissionProfile, 'frozen-public-admission-v1')
  t.is(result.connectAddress, '127.0.0.1')
  t.is(result.nginxSha256, 'c'.repeat(64))
  t.is(result.evidenceSha256, createHash('sha256').update(contents).digest('hex'))
  t.alike(Object.keys(result.checks), PUBLIC_HIVE_GATEWAY_PROBE_CHECKS)
})

test('public gateway evidence verifier rejects release drift and incomplete live checks', (t) => {
  const wrongRelease = validEvidence()
  wrongRelease.release.sha = 'c'.repeat(40)
  t.exception(() => verifyPublicHiveGatewayEvidence(wrongRelease, expected()), /release SHA/)

  for (const check of PUBLIC_HIVE_GATEWAY_PROBE_CHECKS) {
    const evidence = validEvidence()
    evidence.probe.checks[check] = false
    t.exception(() => verifyPublicHiveGatewayEvidence(evidence, expected()), new RegExp(`check ${check}`))
  }

  const noProbe = validEvidence()
  noProbe.probe = null
  t.exception(() => verifyPublicHiveGatewayEvidence(noProbe, expected()), /gateway live probe must be an object/)

  const oldTls = validEvidence()
  oldTls.probe.tlsProtocol = 'TLSv1.1'
  t.exception(() => verifyPublicHiveGatewayEvidence(oldTls, expected()), /TLS 1\.2 or TLS 1\.3/)

  const noFingerprint = validEvidence()
  noFingerprint.probe.peerFingerprint256 = null
  t.exception(() => verifyPublicHiveGatewayEvidence(noFingerprint, expected()), /certificate fingerprint/)

  const expiringCertificate = validEvidence()
  expiringCertificate.probe.peerValidTo = new Date(NOW + 6 * 24 * 60 * 60 * 1000).toUTCString()
  t.exception(() => verifyPublicHiveGatewayEvidence(expiringCertificate, expected()), /remain valid for at least 7 days/)

  const noHash = validEvidence()
  noHash.probe.sha256 = ''
  t.exception(() => verifyPublicHiveGatewayEvidence(noHash, expected()), /content SHA-256/)

  const unsafeDriveVersion = validEvidence()
  unsafeDriveVersion.probe.driveVersion = String(Number.MAX_SAFE_INTEGER + 1)
  t.exception(() => verifyPublicHiveGatewayEvidence(unsafeDriveVersion, expected()), /safe integer string/)

  const secret = validEvidence()
  secret.static.warnings = ['HIVERELAY_API_KEY=should-never-enter-public-evidence']
  t.exception(() => verifyPublicHiveGatewayEvidence(secret, expected()), /must not contain API key/)

  const unknownCheck = validEvidence()
  unknownCheck.probe.checks.futureUnreviewedCheck = true
  t.exception(() => verifyPublicHiveGatewayEvidence(unknownCheck, expected()), /checks has unsupported fields/)

  const canaryPosture = validEvidence()
  canaryPosture.mode = 'canary'
  t.exception(() => verifyPublicHiveGatewayEvidence(canaryPosture, expected()), /explicit fleet production posture/)

  const transitionalAdmission = validEvidence()
  transitionalAdmission.admissionProfile = 'transitional-operator-allowlist-v1'
  t.exception(() => verifyPublicHiveGatewayEvidence(transitionalAdmission, expected()), /must not use transitional/)

  const wrongAppOrigin = validEvidence()
  wrongAppOrigin.probe.origin = `https://${'y'.repeat(52)}.hive-canary.example`
  t.exception(() => verifyPublicHiveGatewayEvidence(wrongAppOrigin, expected()), /origin hostname must exactly encode appKey/)

  const wrongSuffixBinding = validEvidence()
  wrongSuffixBinding.config.suffix = 'other-canary.example'
  t.exception(() => verifyPublicHiveGatewayEvidence(wrongSuffixBinding, expected()), /origin hostname must exactly encode appKey/)

  const missingConnectAddress = validEvidence()
  missingConnectAddress.probe.connectAddress = null
  t.exception(() => verifyPublicHiveGatewayEvidence(missingConnectAddress, expected()), /connectAddress must be an explicit IP address/)

  const wrongNodeBinding = validEvidence()
  wrongNodeBinding.probe.connectAddress = '127.0.0.2'
  t.exception(() => verifyPublicHiveGatewayEvidence(wrongNodeBinding, expected()), /connectAddress binding/)

  const noActiveNginx = validEvidence()
  noActiveNginx.nginx = null
  t.exception(() => verifyPublicHiveGatewayEvidence(noActiveNginx, expected()), /active nginx result must be an object/)

  const renderedNginx = validEvidence()
  renderedNginx.nginx.source = 'rendered'
  t.exception(() => verifyPublicHiveGatewayEvidence(renderedNginx, expected()), /nginx evidence source/)

  const unhashedNginx = validEvidence()
  unhashedNginx.nginx.sha256 = ''
  t.exception(() => verifyPublicHiveGatewayEvidence(unhashedNginx, expected()), /active nginx SHA-256/)

  const unsafeMultiAppSuffix = validEvidence()
  unsafeMultiAppSuffix.config.appKeyCount = 2
  t.exception(() => verifyPublicHiveGatewayEvidence(unsafeMultiAppSuffix, expected()), /multi-app fleet evidence requires Public Suffix/)

  const unboundedPolicy = validEvidence()
  unboundedPolicy.config.finiteProductionPolicy.maxResponseBytes = null
  t.exception(() => verifyPublicHiveGatewayEvidence(unboundedPolicy, expected()), /finite production policy maxResponseBytes/)

  const expandedEgress = validEvidence()
  expandedEgress.config.finiteProductionPolicy.egressBytesPerClientAppWindow++
  t.exception(() => verifyPublicHiveGatewayEvidence(expandedEgress, expected()), /finite production policy egressBytesPerClientAppWindow/)

  const stale = validEvidence()
  stale.checkedAt = new Date(NOW - 24 * 60 * 60 * 1000 - 1).toISOString()
  stale.probe.observedAt = new Date(NOW - 24 * 60 * 60 * 1000 - 2).toISOString()
  t.exception(() => verifyPublicHiveGatewayEvidence(stale, expected()), /older than the allowed evidence age/)
  t.is(verifyPublicHiveGatewayEvidence(stale, {
    ...expected(),
    maxAgeMs: 25 * 60 * 60 * 1000
  }).status, 'verified', 'tests and offline audits can inject an explicit evidence window')

  const future = validEvidence()
  future.checkedAt = new Date(NOW + 5 * 60 * 1000 + 1).toISOString()
  future.probe.observedAt = new Date(NOW + 5 * 60 * 1000).toISOString()
  t.exception(() => verifyPublicHiveGatewayEvidence(future, expected()), /more than 5 minutes in the future/)
})

test('public gateway evidence verifier refuses symlinks, hard links, and oversized files', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-evidence-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const real = path.join(dir, 'real.json')
  const symlinkPath = path.join(dir, 'link.json')
  const hardLink = path.join(dir, 'hard-link.json')
  const large = path.join(dir, 'large.json')
  await writeFile(real, JSON.stringify(validEvidence()))
  await symlink(real, symlinkPath)
  await link(real, hardLink)
  await writeFile(large, Buffer.alloc(2 * 1024 * 1024 + 1, 0x20))

  await t.exception(readAndVerifyPublicHiveGatewayEvidence({ file: symlinkPath, ...expected() }), /non-symlink regular file/)
  await t.exception(readAndVerifyPublicHiveGatewayEvidence({ file: hardLink, ...expected() }), /one link/)
  await t.exception(readAndVerifyPublicHiveGatewayEvidence({ file: large, ...expected() }), /no larger than/)
})

test('public gateway evidence CLI emits only a public verification summary or digest', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-evidence-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'live.json')
  await writeFile(file, JSON.stringify(validEvidence()))
  const base = [
    'scripts/verify-public-hive-gateway-evidence.mjs',
    '--evidence', file,
    '--release-target', RELEASE_TARGET,
    '--release-sha', RELEASE_SHA,
    '--require-mode', 'fleet',
    '--require-admission-profile', 'frozen-public-admission-v1',
    '--expected-origin', APP_ORIGIN,
    '--expected-connect-address', '127.0.0.1',
    '--expected-app-key', APP_KEY,
    '--expected-path', '/index.html',
    '--expected-sha256', 'b'.repeat(64),
    '--expected-drive-version', '1',
    '--expected-peer-fingerprint256', FINGERPRINT,
    '--expected-nginx-sha256', 'c'.repeat(64)
  ]

  const summary = spawnSync(process.execPath, base, { encoding: 'utf8' })
  t.is(summary.status, 0, summary.stderr)
  const report = JSON.parse(summary.stdout)
  t.is(report.status, 'verified')
  t.is(report.origin, APP_ORIGIN)
  t.is(report.connectAddress, '127.0.0.1')
  t.is(report.nginxSha256, 'c'.repeat(64))
  t.is(report.path, '/index.html', 'public summary retains the bound content path')
  t.absent(summary.stdout.includes(file), 'private node-local evidence path is not printed')
  t.absent(summary.stdout.includes('apiKey'))

  const digest = spawnSync(process.execPath, [...base, '--digest-only'], { encoding: 'utf8' })
  t.is(digest.status, 0, digest.stderr)
  t.ok(/^[a-f0-9]{64}\n$/.test(digest.stdout))

  const token = spawnSync(process.execPath, [...base, '--rollout-token'], { encoding: 'utf8' })
  t.is(token.status, 0, token.stderr)
  t.ok(/^[A-Za-z0-9_-]+\n$/.test(token.stdout))
  const tokenBody = JSON.parse(Buffer.from(token.stdout.trim(), 'base64url').toString('utf8'))
  t.is(tokenBody.schema, 'hiverelay-public-gateway-evidence-verification-v1')
  t.is(tokenBody.evidenceSha256, digest.stdout.trim())
  t.is(tokenBody.origin, APP_ORIGIN)
  t.is(tokenBody.peerFingerprint256, FINGERPRINT)
  t.absent(JSON.stringify(tokenBody).includes(file), 'rollout token excludes the private evidence file path')

  const conflictingOutput = spawnSync(process.execPath, [...base, '--digest-only', '--rollout-token'], { encoding: 'utf8' })
  t.not(conflictingOutput.status, 0)
  t.ok(conflictingOutput.stderr.includes('mutually exclusive'))
})

test('public gateway preflight release binding flags are paired and public-safe', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-evidence-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const output = path.join(dir, 'preflight.json')
  const script = 'scripts/preflight-public-hive-gateway.mjs'
  const config = 'deploy/public-hive-gateway/hiverelay-config.example.json'
  const env = { ...process.env, HIVERELAY_API_KEY: 'present-but-never-persisted' }

  const missingSha = spawnSync(process.execPath, [script, '--config', config, '--release-target', RELEASE_TARGET], {
    encoding: 'utf8',
    env
  })
  t.not(missingSha.status, 0)
  t.ok(missingSha.stderr.includes('must be provided together'))

  const bound = spawnSync(process.execPath, [
    script,
    '--config', config,
    '--release-target', RELEASE_TARGET,
    '--release-sha', RELEASE_SHA.toUpperCase(),
    '--evidence', output
  ], { encoding: 'utf8', env })
  t.is(bound.status, 0, bound.stderr)
  const evidence = JSON.parse(await readFile(output, 'utf8'))
  t.alike(evidence.release, { target: RELEASE_TARGET, sha: RELEASE_SHA })
  t.absent(JSON.stringify(evidence).includes(env.HIVERELAY_API_KEY))
})

function expected () {
  return { releaseTarget: RELEASE_TARGET, releaseSha: RELEASE_SHA, now: NOW }
}

function validEvidence (now = NOW) {
  return {
    schema: 'hiverelay-public-gateway-preflight-v1',
    status: 'pass',
    checkedAt: new Date(now - 1000).toISOString(),
    mode: 'fleet',
    admissionProfile: 'frozen-public-admission-v1',
    release: {
      target: RELEASE_TARGET,
      sha: RELEASE_SHA
    },
    config: {
      suffix: 'hive-canary.example',
      appKeyCount: 1,
      apiHost: '127.0.0.1',
      apiPort: 9100,
      gatewayHost: '127.0.0.1',
      gatewayPort: 9200,
      connectAddress: '127.0.0.1',
      publicSuffixReady: false,
      custodyEnabled: false,
      finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY }
    },
    static: {
      ok: true,
      errors: [],
      warnings: ['public-safe warning']
    },
    nginx: {
      ok: true,
      errors: [],
      source: 'active',
      sha256: 'c'.repeat(64)
    },
    probe: {
      schema: 'hiverelay-public-gateway-probe-v1',
      observedAt: new Date(now - 2000).toISOString(),
      origin: APP_ORIGIN,
      connectAddress: '127.0.0.1',
      appKey: APP_KEY,
      path: '/index.html',
      sha256: 'b'.repeat(64),
      bytes: 42,
      driveVersion: '1',
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: FINGERPRINT,
      peerValidTo: new Date(now + 365 * 24 * 60 * 60 * 1000).toUTCString(),
      metadataSigned: false,
      checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
    },
    probeError: null
  }
}
