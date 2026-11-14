import test from 'brittle'
import { generateKeyPairSync, sign } from 'node:crypto'
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import {
  HEALTH_BODY_MAX,
  SOURCE_MAX,
  WATCHDOG_UNIT,
  authorizeRestart,
  canonicalJson,
  captureDiagnostic,
  cgroupHasUnit,
  classifyHealth,
  parseCanonicalJson,
  parseProcStarttime,
  policySigningBytes,
  recordFailureOutcome
} from '../../fleet/health-watchdog-policy.mjs'

const shell = readFileSync('fleet/health-watchdog.sh', 'utf8')
const installer = readFileSync('fleet/install-health-watchdog.sh', 'utf8')
const service = readFileSync('fleet/hiverelay-health-watchdog.service', 'utf8')
const timer = readFileSync('fleet/hiverelay-health-watchdog.timer', 'utf8')
const pidfd = readFileSync('fleet/health-watchdog-helper.c', 'utf8')
const policySource = readFileSync('fleet/health-watchdog-policy.mjs', 'utf8')
const execFileAsync = promisify(execFile)

test('watchdog CLI accepts curl timeout status 000 without relaxing other arguments', async (t) => {
  const { root } = await fixture(t)
  const body = join(root, 'health-body')
  await writeFile(body, '')
  const classify = (status, exit) => execFileAsync(process.execPath, [
    '--jitless', 'fleet/health-watchdog-policy.mjs', 'classify', body, status, exit
  ], { timeout: 5000 })
  t.is((await classify('000', '28')).stdout, 'eligible-timeout\n')
  t.is((await classify('000', '7')).stdout, 'eligible-timeout\n')
  t.is((await classify('204', '0')).stdout, 'eligible-empty\n')
  for (const status of ['0', '00', '0000', '-00', '+00', ' 000', '0e0', 'NaN']) {
    await t.exception(classify(status, '28'), { code: 1 }, `rejects noncanonical status ${status}`)
  }
  await t.exception(classify('000', '028'), { code: 1 }, 'curl exit retains strict decimal syntax')
  await writeFile(body, 'partial')
  t.is((await classify('000', '28')).stdout, 'responsive-not-restartable\n')
  await writeFile(body, '{"ok":false,"reason":"storage-fail-closed"}')
  t.is((await classify('503', '0')).stdout, 'responsive-not-restartable\n')
})

async function fixture (t) {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-watchdog-contract-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const paths = {
    policy: join(root, 'config', 'restart-policy-v1.json'),
    signer: join(root, 'config', 'signer-snapshot-v1.json'),
    sequence: join(root, 'state', 'highest-restart-policy-sequence-v1.json'),
    failure: join(root, 'runtime', 'failure-state-v1.json'),
    diagnostics: join(root, 'logs', 'diagnostics')
  }
  for (const directory of [
    join(root, 'config'),
    join(root, 'state'),
    join(root, 'runtime'),
    join(root, 'logs'),
    paths.diagnostics
  ]) {
    await mkdir(directory, { recursive: true, mode: 0o700 })
    await chmod(directory, 0o700)
  }
  const authority = {
    uid: typeof process.getuid === 'function' ? process.getuid() : 0,
    gid: typeof process.getgid === 'function' ? process.getgid() : 0,
    directoryMode: 0o700
  }
  return { root, paths, authority }
}

async function writeAuthorityJson (path, value, mode) {
  await chmod(path, 0o600).catch(err => {
    if (err.code !== 'ENOENT') throw err
  })
  await writeFile(path, canonicalJson(value), { mode })
  await chmod(path, mode)
}

function target (overrides = {}) {
  return {
    unit: WATCHDOG_UNIT,
    executableSha256: 'ab'.repeat(32),
    cgroupSha256: 'cd'.repeat(32),
    mainPid: 4321,
    procStarttime: 987654,
    ...overrides
  }
}

function signedAuthority (now, currentTarget, sequence = 1) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  const unsigned = {
    kind: 'HiveRelayWatchdogRestartPolicyV1',
    version: 1,
    sequence,
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    unit: WATCHDOG_UNIT,
    executableSha256: currentTarget.executableSha256,
    termGraceMs: 30_000,
    killAllowed: false,
    signerPrincipal: 'fleet-release-controller',
    signature: '00'.repeat(64)
  }
  const signature = sign(null, policySigningBytes(unsigned), privateKey).toString('hex')
  return {
    policy: { ...unsigned, signature },
    signer: {
      kind: 'HiveRelayWatchdogSignerSnapshotV1',
      version: 1,
      signerPrincipal: unsigned.signerPrincipal,
      publicKey: rawPublicKey
    }
  }
}

test('watchdog health classification restarts only on an empty transport outcome', (t) => {
  t.is(classifyHealth({ body: Buffer.alloc(0), status: 0, curlExit: 28 }), 'eligible-timeout')
  t.is(classifyHealth({ body: Buffer.alloc(0), status: 0, curlExit: 7 }), 'eligible-timeout')
  t.is(classifyHealth({ body: Buffer.alloc(0), status: 204, curlExit: 0 }), 'eligible-empty')
  t.is(classifyHealth({ body: Buffer.alloc(0), status: 0, curlExit: 23 }),
    'responsive-not-restartable', 'local write errors cannot authorize a relay restart')
  t.is(classifyHealth({ body: Buffer.alloc(0), status: 0, curlExit: 63 }),
    'responsive-not-restartable', 'the response-size fence cannot authorize a relay restart')
  t.is(classifyHealth({ body: Buffer.from('{"ok":true}'), status: 200, curlExit: 0 }), 'healthy')
  t.is(classifyHealth({ body: Buffer.from('{"ok":false}'), status: 503, curlExit: 0 }),
    'responsive-not-restartable', 'reason is not required to suppress restart')
  t.is(classifyHealth({ body: Buffer.from('malformed'), status: 500, curlExit: 0 }),
    'responsive-not-restartable')
  t.is(classifyHealth({ body: Buffer.from('partial'), status: 0, curlExit: 28 }),
    'responsive-not-restartable', 'transport errors with response bytes are not restartable')
})

test('failure state requires two distinct in-window observations and resets on every fence', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const firstAt = 2_000_000
  let result = await recordFailureOutcome({
    outcome: 'eligible-timeout',
    target: current,
    now: firstAt,
    paths,
    authority
  })
  t.is(result.state.consecutiveEligibleFailures, 1)
  t.absent(result.restartEligible)

  result = await recordFailureOutcome({
    outcome: 'eligible-empty',
    target: current,
    now: firstAt + 59_999,
    paths,
    authority
  })
  t.is(result.state.consecutiveEligibleFailures, 1, 'too-soon observation starts a new streak')
  t.is(result.state.firstFailureAt, firstAt + 59_999)

  result = await recordFailureOutcome({
    outcome: 'eligible-timeout',
    target: current,
    now: firstAt + 119_999,
    paths,
    authority
  })
  t.is(result.state.consecutiveEligibleFailures, 2)
  t.ok(result.restartEligible)

  result = await recordFailureOutcome({
    outcome: 'responsive-not-restartable',
    target: current,
    now: firstAt + 120_000,
    paths,
    authority
  })
  t.is(result.state.consecutiveEligibleFailures, 0)
  t.is(result.state.firstFailureAt, 0)

  result = await recordFailureOutcome({
    outcome: 'eligible-empty',
    target: current,
    now: firstAt + 180_000,
    paths,
    authority
  })
  result = await recordFailureOutcome({
    outcome: 'eligible-empty',
    target: target({ mainPid: 4322 }),
    now: firstAt + 240_000,
    paths,
    authority
  })
  t.is(result.state.consecutiveEligibleFailures, 1, 'target tuple change resets the streak')
})

test('restart authorization rejects a completed failure streak after its observation window expires', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const lastFailureAt = 3_000_000
  const now = lastFailureAt + 600_001
  await recordFailureOutcome({
    outcome: 'eligible-empty',
    target: current,
    now: lastFailureAt - 60_000,
    paths,
    authority
  })
  await recordFailureOutcome({
    outcome: 'eligible-timeout',
    target: current,
    now: lastFailureAt,
    paths,
    authority
  })

  const signed = signedAuthority(now, current)
  await writeAuthorityJson(paths.policy, signed.policy, 0o400)
  await writeAuthorityJson(paths.signer, signed.signer, 0o400)
  await writeAuthorityJson(paths.sequence, {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: 0,
    policySha256: '00'.repeat(32),
    consumedAt: 0
  }, 0o600)

  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_FAILURE_PREDICATE_INVALID' })
})

test('canonical policy JSON rejects trailing bytes, key-order drift, and unknown data', (t) => {
  const value = { a: 1, b: false }
  t.alike(parseCanonicalJson(Buffer.from('{"a":1,"b":false}'), 128), value)
  t.exception(() => parseCanonicalJson(Buffer.from('{"b":false,"a":1}'), 128),
    { code: 'WATCHDOG_JSON_NONCANONICAL' })
  t.exception(() => parseCanonicalJson(Buffer.from('{"a":1,"b":false}\n'), 128),
    { code: 'WATCHDOG_JSON_NONCANONICAL' })
})

test('signed authorization consumes sequence before bounded redacted diagnostics and rejects replay', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const now = 4_000_000
  await recordFailureOutcome({ outcome: 'eligible-empty', target: current, now: now - 120_000, paths, authority })
  await recordFailureOutcome({ outcome: 'eligible-timeout', target: current, now: now - 60_000, paths, authority })
  const signed = signedAuthority(now, current)
  await writeAuthorityJson(paths.policy, signed.policy, 0o400)
  await writeAuthorityJson(paths.signer, signed.signer, 0o400)
  await writeAuthorityJson(paths.sequence, {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: 0,
    policySha256: '00'.repeat(32),
    consumedAt: 0
  }, 0o600)

  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.from('partial'),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_RESTART_HEALTH_BODY_NONEMPTY' })

  const result = await authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: [
      ['bounded-secret-source', async () => Buffer.from(`password=hunter2\n${'x'.repeat(SOURCE_MAX + 1)}`)],
      ['invalid-utf8-source', async () => Buffer.alloc(SOURCE_MAX, 0xff)],
      ['ordinary-source', async () => Buffer.from('rss=100\n')]
    ]
  })
  t.ok(result.sequenceConsumed)
  t.is(result.policy.killAllowed, false, 'mandatory explicit false survives authorization')
  t.ok(result.diagnostic.bytes < 524_288)
  const bundleText = await readFile(result.diagnostic.path, 'utf8')
  const bundle = JSON.parse(bundleText)
  t.absent(bundleText.includes('hunter2'))
  t.ok(bundle.counters.redacted >= 1)
  t.is(bundle.counters.truncated, 2)
  t.is(bundle.sources.length, 3)
  for (const source of bundle.sources) {
    t.ok(source.storedBytes <= SOURCE_MAX)
    t.is(Buffer.byteLength(source.data), source.storedBytes)
  }
  t.is(bundle.target.cgroupSha256, current.cgroupSha256)

  const responsive = await captureDiagnostic({
    target: current,
    policySha256: '00'.repeat(32),
    healthBody: Buffer.from('{"ok":false,"authorization":"Bearer should-not-persist"}'),
    healthStatus: 503,
    now: now + 1,
    paths,
    authority,
    loaders: []
  })
  const responsiveText = await readFile(responsive.path, 'utf8')
  t.absent(responsiveText.includes('should-not-persist'))
  t.ok(JSON.parse(responsiveText).counters.redacted >= 1)

  const invalidHealth = await captureDiagnostic({
    target: current,
    policySha256: '00'.repeat(32),
    healthBody: Buffer.alloc(HEALTH_BODY_MAX, 0xff),
    healthStatus: 503,
    now: now + 2,
    paths,
    authority,
    loaders: []
  })
  const invalidHealthBundle = JSON.parse(await readFile(invalidHealth.path, 'utf8'))
  t.ok(invalidHealthBundle.health.truncated)
  t.ok(invalidHealthBundle.health.storedBytes <= HEALTH_BODY_MAX)
  t.is(Buffer.byteLength(invalidHealthBundle.health.data), invalidHealthBundle.health.storedBytes)

  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now: now + 3,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_POLICY_REPLAY' })
})

test('unknown or incomplete signed policy fields fail before signal authority', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const now = 8_000_000
  await recordFailureOutcome({ outcome: 'eligible-empty', target: current, now: now - 120_000, paths, authority })
  await recordFailureOutcome({ outcome: 'eligible-empty', target: current, now: now - 60_000, paths, authority })
  const signed = signedAuthority(now, current)
  const { killAllowed, ...missingKill } = signed.policy
  t.is(killAllowed, false)
  await writeAuthorityJson(paths.policy, missingKill, 0o400)
  await writeAuthorityJson(paths.signer, signed.signer, 0o400)
  await writeAuthorityJson(paths.sequence, {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: 0,
    policySha256: '00'.repeat(32),
    consumedAt: 0
  }, 0o600)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_SCHEMA_INVALID' })

  await writeAuthorityJson(paths.policy, { ...signed.policy, healthReason: 'memory' }, 0o400)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_SCHEMA_INVALID' })
})

test('policy, signer, sequence, and state authority reject mode, hard-link, and symlink drift', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const now = 9_000_000
  await recordFailureOutcome({ outcome: 'eligible-empty', target: current, now: now - 120_000, paths, authority })
  await recordFailureOutcome({ outcome: 'eligible-timeout', target: current, now: now - 60_000, paths, authority })
  const signed = signedAuthority(now, current)
  await writeAuthorityJson(paths.policy, signed.policy, 0o400)
  await writeAuthorityJson(paths.signer, signed.signer, 0o400)
  await writeAuthorityJson(paths.sequence, {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: 0,
    policySha256: '00'.repeat(32),
    consumedAt: 0
  }, 0o600)

  await chmod(paths.policy, 0o600)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_FILE_AUTHORITY_INVALID' })
  await chmod(paths.policy, 0o400)

  const signerAlias = `${paths.signer}.hardlink`
  await link(paths.signer, signerAlias)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_FILE_AUTHORITY_INVALID' })
  await unlink(signerAlias)

  const realPolicy = `${paths.policy}.real`
  await rename(paths.policy, realPolicy)
  await symlink(realPolicy, paths.policy)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'ELOOP' })
})

test('signature, timestamp, TTL, and integer policy drift all fail closed', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  const now = 200_000_000
  await recordFailureOutcome({ outcome: 'eligible-empty', target: current, now: now - 120_000, paths, authority })
  await recordFailureOutcome({ outcome: 'eligible-timeout', target: current, now: now - 60_000, paths, authority })
  const signed = signedAuthority(now, current)
  await writeAuthorityJson(paths.signer, signed.signer, 0o400)
  await writeAuthorityJson(paths.sequence, {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: 0,
    policySha256: '00'.repeat(32),
    consumedAt: 0
  }, 0o600)

  await writeAuthorityJson(paths.policy, { ...signed.policy, signature: '11'.repeat(64) }, 0o400)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_POLICY_SIGNATURE_INVALID' })

  await writeAuthorityJson(paths.policy, { ...signed.policy, expiresAt: now - 1 }, 0o400)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_POLICY_TIME_INVALID' })

  await writeAuthorityJson(paths.policy, {
    ...signed.policy,
    issuedAt: now - 86_400_001,
    expiresAt: now + 1
  }, 0o400)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_POLICY_TIME_INVALID' })

  await writeAuthorityJson(paths.policy, { ...signed.policy, sequence: 1.5 }, 0o400)
  await t.exception(authorizeRestart({
    target: current,
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  }), { code: 'WATCHDOG_SCHEMA_INVALID' })
})

test('diagnostic capture fails closed above its source allowlist', async (t) => {
  const { paths, authority } = await fixture(t)
  const loaders = Array.from({ length: 17 }, (_, index) => [`source-${index}`, async () => Buffer.alloc(0)])
  await t.exception(captureDiagnostic({
    target: target(),
    policySha256: 'ef'.repeat(32),
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now: 10_000_000,
    paths,
    authority,
    loaders
  }), { code: 'WATCHDOG_SOURCE_ALLOWLIST_INVALID' })
})

test('required capture failure and final encoded bundle overflow publish nothing', async (t) => {
  const { paths, authority } = await fixture(t)
  const current = target()
  await t.exception(captureDiagnostic({
    target: current,
    policySha256: 'ef'.repeat(32),
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now: 12_000_000,
    paths,
    authority,
    loaders: [['required-source', async () => { throw new Error('missing') }, true]]
  }), { code: 'WATCHDOG_REQUIRED_SOURCE_CAPTURE_FAILED' })

  const quoteSources = Array.from({ length: 16 }, (_, index) => [
    `quote-source-${index}`,
    async () => Buffer.from('"'.repeat(SOURCE_MAX))
  ])
  await t.exception(captureDiagnostic({
    target: current,
    policySha256: 'ef'.repeat(32),
    healthBody: Buffer.from('"'.repeat(65_536)),
    healthStatus: 503,
    now: 12_000_001,
    paths,
    authority,
    loaders: quoteSources
  }), { code: 'WATCHDOG_DIAGNOSTIC_BUNDLE_OVERSIZED' })
  t.alike(await readdir(paths.diagnostics), [])
})

test('diagnostic retention converges to sixteen canonical artifacts', async (t) => {
  const { paths, authority } = await fixture(t)
  const now = 20_000_000_000
  for (let index = 0; index < 16; index++) {
    const timestamp = String(now - index - 1).padStart(13, '0')
    const digest = index.toString(16).padStart(64, '0')
    const path = join(paths.diagnostics, `watchdog-${timestamp}-${digest}.json`)
    await writeFile(path, canonicalJson({ index }), { mode: 0o600 })
    await chmod(path, 0o600)
  }
  await captureDiagnostic({
    target: target(),
    policySha256: 'ef'.repeat(32),
    healthBody: Buffer.alloc(0),
    healthStatus: 0,
    now,
    paths,
    authority,
    loaders: []
  })
  const artifacts = (await readdir(paths.diagnostics)).filter(name => name.startsWith('watchdog-'))
  t.is(artifacts.length, 16)
})

test('process tuple parsers bind robust stat and exact systemd cgroup membership', (t) => {
  const fields = Array.from({ length: 52 }, (_, index) => String(index + 1))
  fields[19] = '987654'
  t.is(parseProcStarttime(`42 (relay worker) ${fields.join(' ')}`), 987654)
  t.ok(cgroupHasUnit(Buffer.from('0::/system.slice/hiverelay.service\n')))
  t.absent(cgroupHasUnit(Buffer.from('0::/system.slice/not-hiverelay.service\n')))
  t.absent(cgroupHasUnit(Buffer.from('0::/system.slice/hiverelay.service.attacker\n')))
})

test('fleet watchdog has no broad or numeric-PID signal fallback', (t) => {
  t.ok(shell.includes('active=$("$SYSTEMCTL" is-active "$UNIT"'))
  t.ok(shell.includes('--connect-timeout 5 --max-time 5 --max-filesize 65536'))
  t.ok(shell.includes('responsive-not-restartable'))
  t.ok(shell.indexOf(' authorize ') < shell.indexOf('"$SIGNAL_HELPER"'))
  t.absent(shell.includes('systemctl kill'))
  t.absent(shell.includes('systemctl restart'))
  t.absent(shell.includes('systemctl start'))
  t.absent(shell.includes('fuser'))
  t.absent(shell.includes('kill -'))
  t.absent(shell.includes('HIVERELAY_HEALTH_'))

  t.ok(pidfd.includes('SYS_pidfd_open'))
  t.ok(pidfd.includes('SYS_pidfd_send_signal'))
  t.ok(pidfd.includes('verify_target(pidfd, &target)'))
  t.ok(pidfd.match(/verify_target\(pidfd, &target\)/g).length >= 2)
  t.ok(pidfd.includes('cgroup_has_expected_unit'))
  t.ok(pidfd.includes('SIGTERM'))
  t.ok(pidfd.includes('SIGKILL'))
  t.absent(/(^|[^a-z_])kill\s*\(/m.test(pidfd), 'numeric kill syscall is absent')

  t.ok(policySource.includes("'HiveRelayWatchdogRestartPolicyV1'"))
  t.ok(policySource.includes("'HiveRelayWatchdogFailureStateV1'"))
  t.ok(policySource.includes("'HiveRelayWatchdogDiagnosticBundleV1'"))
  t.ok(policySource.includes("'HiveRelayWatchdogConsumedSequenceV1'"))
  t.ok(policySource.includes("'hiverelay.watchdog.restart-policy.v1'"))
})

test('watchdog installation and unit bind one tracked hardened set and prove no restart', (t) => {
  t.ok(installer.includes('health-watchdog-policy.mjs health-watchdog-helper.c'))
  t.ok(installer.includes('green watchdog proof detected a relay PID change'))
  t.ok(installer.includes('green watchdog proof detected a hidden restart'))
  t.ok(installer.includes('cmp -s -- "$script_dir/health-watchdog.sh"'))
  t.absent(installer.includes("<<'WATCH'"), 'installer has no duplicate embedded watchdog')

  t.ok(service.includes('/usr/bin/env -i PATH='))
  t.ok(service.includes('RuntimeDirectoryMode=0700'))
  t.ok(service.includes('StateDirectoryMode=0700'))
  t.ok(service.includes('LogsDirectoryMode=0700'))
  t.ok(service.includes('ProtectSystem=strict'))
  t.ok(service.includes('CapabilityBoundingSet=CAP_KILL'))
  t.ok(timer.includes('OnUnitActiveSec=2min'))
  t.ok(timer.includes('AccuracySec=1s'))
  t.ok(timer.includes('RandomizedDelaySec=0'))
})
