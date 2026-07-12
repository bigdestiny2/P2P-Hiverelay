import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { runPublicHiveGatewayDeploy } from '../../scripts/public-hive-gateway-deploy.mjs'
import { createPublicT1OpsFixture } from '../fixtures/public-hive-gateway-ops.js'

const TARGET = 'v1.2.3'
const PREVIOUS = 'v1.2.2'
const WINDOW_MS = 24 * 60 * 60 * 1000
const MAX_GAP_MS = 20 * 60 * 1000
const canRehearse = have('/usr/bin/git') && have('/usr/bin/ssh-keygen')

test('public gateway deploy rehearsal - signed canary CAS, updater recovery, observation, explicit stable CAS', {
  skip: !canRehearse,
  timeout: 120_000
}, async (t) => {
  const f = createReleaseFixture(t)
  const canaryReceipt = path.join(f.root, 'canary-receipt.json')
  const common = {
    target: TARGET,
    targetSha: f.targetSha,
    repo: f.repo,
    remote: 'origin',
    branch: 'main',
    allowedSigners: f.allowedSigners,
    relays: f.relaysPath
  }

  const canaryValidation = await runPublicHiveGatewayDeploy({
    action: 'canary',
    ...common,
    gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir
  })
  t.is(canaryValidation.status, 'validated')
  t.is(readJson(f.channelsPath).canary, PREVIOUS, 'validation-only does not move canary')
  const canary = await runPublicHiveGatewayDeploy({
    action: 'canary',
    ...common,
    gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir,
    publish: true,
    authorize: canaryValidation.authorizationRequired,
    receipt: canaryReceipt
  })
  t.is(canary.status, 'published')
  t.is(readJson(f.channelsPath).canary, TARGET)
  t.is(readJson(f.channelsPath).stable, PREVIOUS)
  assertSingleChannelsCommit(t, f.repo, canary.publication.publishedHead)
  assertRemoteHead(t, f)

  rehearseUpdaterFailurePaths(t, f)

  const session = path.join(f.root, 'observation-session.json')
  const windowState = path.join(f.root, 'window-state.json')
  const rolloutEvidence = path.join(f.root, 'canary-rollout-evidence.json')
  const knownHosts = path.join(f.root, 'known-hosts')
  writeFileSync(knownHosts, 'fixture host key authority\n')
  const nowMs = Date.now()
  const clock = [nowMs - WINDOW_MS, nowMs]
  // This disposable fixture deliberately time-compresses controller time so
  // the real stable promoter can be exercised in CI. It is never exported as
  // rollout evidence and does not claim that CI observed a live 24-hour day.
  const observation = await runPublicHiveGatewayDeploy({
    action: 'observe',
    ...common,
    canaryReceipt,
    session,
    knownHosts,
    gatewayEvidence: '/root/.hiverelay/gateway-evidence/preflight-live.json',
    gatewayWindowState: windowState,
    evidence: rolloutEvidence
  }, {
    now: () => clock.shift(),
    runObserver: async () => {
      writeCompletedObservation(f, windowState, rolloutEvidence, nowMs)
      return { code: 0 }
    }
  })
  t.is(observation.status, 'complete')
  t.is(observation.stableRemainsExplicit, true)
  t.is(readJson(f.channelsPath).stable, PREVIOUS, 'completed observation cannot move stable')

  const stableValidation = await runPublicHiveGatewayDeploy({
    action: 'stable',
    ...common,
    gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir,
    canaryReceipt,
    session
  })
  t.is(stableValidation.status, 'validated')
  t.is(readJson(f.channelsPath).stable, PREVIOUS, 'stable validation remains nonmutating')

  const stableReceipt = path.join(f.root, 'stable-receipt.json')
  const stable = await runPublicHiveGatewayDeploy({
    action: 'stable',
    ...common,
    gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir,
    canaryReceipt,
    session,
    publish: true,
    authorize: stableValidation.authorizationRequired,
    receipt: stableReceipt
  })
  t.is(stable.status, 'published')
  t.is(readJson(f.channelsPath).stable, TARGET)
  t.is(readJson(f.channelsPath).canary, TARGET)
  assertSingleChannelsCommit(t, f.repo, stable.publication.publishedHead)
  assertRemoteHead(t, f)
  verifySignedCommit(f.repo, stable.publication.publishedHead, f.allowedSigners)
})

function createReleaseFixture (t) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'hiverelay-deploy-rehearsal-')))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))
  const repo = path.join(root, 'control')
  const remote = path.join(root, 'remote.git')
  const fleet = path.join(repo, 'fleet')
  const scripts = path.join(repo, 'scripts')
  const scriptsLib = path.join(scripts, 'lib')
  const key = path.join(root, 'release-key')
  const allowedSigners = path.join(fleet, 'allowed-signers')
  const channelsPath = path.join(fleet, 'channels.json')
  const relaysPath = path.join(fleet, 'relays.json')
  const manifestPath = path.join(fleet, 'public-hive-gateway-release.json')
  const gatewayOpsEvidenceDir = path.join(root, 'gateway-ops-evidence')
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive-canary.operator.example'
  const publicT1 = createPublicT1OpsFixture({
    relay: 'canary-1',
    channel: 'canary',
    appKey,
    suffix,
    contentSha256: 'b'.repeat(64),
    nginxSha256: 'c'.repeat(64),
    fingerprint256: Array(32).fill('AA').join(':'),
    releaseTarget: TARGET
  })
  const gatewayEntry = publicT1.manifest.cohort[0]
  const disabledManifest = {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: false
  }
  const enabledManifest = publicT1.manifest

  mkdirSync(scriptsLib, { recursive: true })
  mkdirSync(fleet, { recursive: true })
  mkdirSync(gatewayOpsEvidenceDir, { recursive: true })
  command('/usr/bin/git', ['init', '--bare', remote])
  command('/usr/bin/git', ['init', '-b', 'main', repo])
  git(repo, ['config', 'user.name', 'Gateway Rehearsal'])
  git(repo, ['config', 'user.email', 'release@hiverelay'])
  git(repo, ['config', 'gpg.format', 'ssh'])
  command('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'release@hiverelay', '-f', key])
  git(repo, ['config', 'user.signingkey', key])
  const publicKey = readFileSync(`${key}.pub`, 'utf8').trim().split(/\s+/).slice(0, 2).join(' ')
  writeFileSync(allowedSigners, `release@hiverelay ${publicKey}\n`)
  writeFileSync(channelsPath, JSON.stringify({ canary: PREVIOUS, stable: PREVIOUS }, null, 2) + '\n')
  writeFileSync(relaysPath, JSON.stringify({
    relays: [{ name: 'canary-1', channel: 'canary', publicIp: '127.0.0.1' }]
  }, null, 2) + '\n')
  copyFixtureSource('scripts/promote-fleet-channel.mjs', path.join(scripts, 'promote-fleet-channel.mjs'))
  copyFixtureSource('scripts/lib/public-hive-gateway-release-manifest.mjs',
    path.join(scriptsLib, 'public-hive-gateway-release-manifest.mjs'))
  copyFixtureSource('scripts/lib/public-hive-gateway-policy.mjs',
    path.join(scriptsLib, 'public-hive-gateway-policy.mjs'))
  copyFixtureSource('scripts/lib/public-hive-gateway-quarantine-authority.mjs',
    path.join(scriptsLib, 'public-hive-gateway-quarantine-authority.mjs'))
  copyFixtureSource('scripts/verify-public-hive-gateway-quarantine.mjs',
    path.join(scripts, 'verify-public-hive-gateway-quarantine.mjs'))
  copyFixtureSource('fleet/updater.sh', path.join(fleet, 'updater.sh'))
  copyFixtureSource('fleet/quarantine-public-gateway.sh', path.join(fleet, 'quarantine-public-gateway.sh'))
  copyFixtureSource('scripts/resolve-public-hive-gateway-node.mjs',
    path.join(scripts, 'resolve-public-hive-gateway-node.mjs'))
  copyFixtureSource('scripts/preflight-public-hive-gateway.mjs',
    path.join(scripts, 'preflight-public-hive-gateway.mjs'))
  copyFixtureSource('scripts/verify-public-hive-gateway-evidence.mjs',
    path.join(scripts, 'verify-public-hive-gateway-evidence.mjs'))
  copyFixtureSource('scripts/preflight-public-hive-gateway-ops.mjs',
    path.join(scripts, 'preflight-public-hive-gateway-ops.mjs'))
  copyFixtureSource('scripts/verify-public-hive-gateway-ops-evidence.mjs',
    path.join(scripts, 'verify-public-hive-gateway-ops-evidence.mjs'))
  copyFixtureSource('scripts/resolve-signed-fleet-channel.mjs',
    path.join(scripts, 'resolve-signed-fleet-channel.mjs'))

  writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ name: 'fixture', version: PREVIOUS.slice(1) }, null, 2) + '\n')
  writeFileSync(manifestPath, JSON.stringify(disabledManifest, null, 2) + '\n')
  git(repo, ['add', '.'])
  git(repo, ['commit', '-m', 'bootstrap updater identity release'])
  git(repo, ['tag', '-s', '-m', `${PREVIOUS} bootstrap`, PREVIOUS])
  const previousSha = git(repo, ['rev-parse', `${PREVIOUS}^{commit}`]).stdout.trim()

  const manifestBytes = publicT1.manifestBytes
  writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ name: 'fixture', version: TARGET.slice(1) }, null, 2) + '\n')
  writeFileSync(manifestPath, manifestBytes)
  const operatorContractPath = path.join(repo, publicT1.contractPath)
  mkdirSync(path.dirname(operatorContractPath), { recursive: true })
  writeFileSync(operatorContractPath, publicT1.contractBytes)
  git(repo, ['add', 'package.json', 'fleet/public-hive-gateway-release.json', publicT1.contractPath])
  git(repo, ['commit', '-m', 'enabled gateway release'])
  git(repo, ['tag', '-s', '-m', `${TARGET} gateway`, TARGET])
  const targetSha = git(repo, ['rev-parse', `${TARGET}^{commit}`]).stdout.trim()
  const readiness = createPublicT1OpsFixture({
    relay: 'canary-1',
    channel: 'canary',
    appKey,
    suffix,
    contentSha256: gatewayEntry.contentSha256,
    nginxSha256: gatewayEntry.nginxConfigSha256,
    fingerprint256: gatewayEntry.peerFingerprint256,
    releaseTarget: TARGET,
    releaseSha: targetSha
  })
  if (!readiness.manifestBytes.equals(manifestBytes) || !readiness.contractBytes.equals(publicT1.contractBytes)) {
    throw new Error('public-t1 rehearsal authority changed while binding target SHA')
  }
  writeFileSync(path.join(gatewayOpsEvidenceDir, 'canary-1.json'), readiness.evidenceBytes)
  git(repo, ['remote', 'add', 'origin', remote])
  git(repo, ['push', '-u', 'origin', 'main'])
  git(repo, ['push', 'origin', `refs/tags/${PREVIOUS}`, `refs/tags/${TARGET}`])

  return {
    root,
    repo,
    remote,
    key,
    allowedSigners,
    channelsPath,
    relaysPath,
    gatewayOpsEvidenceDir,
    manifestPath,
    manifestBytes,
    previousSha,
    targetSha,
    gatewayEntry,
    enabledManifest
  }
}

function rehearseUpdaterFailurePaths (t, f) {
  const nodeRepo = path.join(f.root, 'canary-node')
  const bin = path.join(f.root, 'node-bin')
  const runtime = path.join(f.root, 'node-runtime')
  const updaterConf = path.join(runtime, 'hiverelay-updater.conf')
  const envFile = path.join(runtime, 'hiverelay.env')
  const gatewayConfig = path.join(runtime, 'gateway.json')
  const nginxConfig = path.join(runtime, 'gateway-nginx.conf')
  const nginxBinary = path.join(runtime, 'nginx')
  const gatewayEvidence = path.join(runtime, 'gateway-evidence.json')
  const gatewayOpsEvidence = path.join(runtime, 'gateway-ops-evidence.json')
  const certificateRoot = path.join(runtime, 'certificates')
  const certificate = path.join(certificateRoot, 'fullchain.pem')
  const certificateKey = path.join(certificateRoot, 'privkey.pem')
  const ssBinary = path.join(runtime, 'ss')
  const controlState = path.join(runtime, 'control-state', 'channel.json')
  const quarantine = path.join(runtime, 'quarantine')
  const nginxLog = path.join(runtime, 'nginx.log')
  const restartLog = path.join(runtime, 'restart.log')
  const preflightFailure = path.join(runtime, 'preflight-failure')
  const channelSnapshot = path.join(runtime, 'channels.json')
  mkdirSync(bin)
  mkdirSync(runtime)
  mkdirSync(certificateRoot)
  command('/usr/bin/git', ['clone', f.remote, nodeRepo])
  git(nodeRepo, ['checkout', '--detach', PREVIOUS])
  writeFileSync(channelSnapshot, readFileSync(f.channelsPath))
  writeFileSync(updaterConf, `CHANNEL=canary\nRELAY_NAME=canary-1\nREPO_DIR=${nodeRepo}\n`)
  writeFileSync(envFile, 'HIVERELAY_API_KEY=rehearsal-secret\n')
  writeFileSync(gatewayConfig, '{}\n')
  writeFileSync(gatewayOpsEvidence, '{"schema":"stale-ops-evidence"}\n')
  writeFileSync(certificate, 'fixture certificate\n')
  writeFileSync(certificateKey, 'fixture key\n')
  writeFileSync(nginxConfig, `server {
  listen 443 ssl;
  ssl_certificate ${certificate};
  ssl_certificate_key ${certificateKey};
  proxy_pass http://127.0.0.1:9200;
}\n`)
  executable(nginxBinary, '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$FIXTURE_NGINX_LOG"\nexit 0\n')
  executable(ssBinary, '#!/bin/sh\nexit 0\n')
  executable(path.join(bin, 'flock'), '#!/bin/sh\nexit 0\n')
  executable(path.join(bin, 'timeout'), '#!/bin/sh\nshift\nexec "$@"\n')
  executable(path.join(bin, 'systemctl'), `#!/bin/sh
if [ "\${1:-}" = show ]; then exit 0; fi
if [ "\${1:-}" = restart ]; then printf '%s\\n' "\${2:-}" >> "$FIXTURE_RESTART_LOG"; fi
exit 0
`)
  executable(path.join(bin, 'curl'), `#!/bin/sh
case " $* " in
  *" /health "*|*"/health"*)
    version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' "$FIXTURE_NODE_REPO/package.json" | head -n 1)"
    printf '{"running":true,"version":"%s"}\\n' "$version"
    ;;
  *) /bin/cat "$FIXTURE_CHANNELS" ;;
esac
`)
  executable(path.join(bin, 'node'), `#!/bin/sh
script="\${1:-}"
shift || true
case "$script" in
  */resolve-signed-fleet-channel.mjs)
    printf 'resolved\t%s\t%s\t%s\t%s\n' "$FIXTURE_TARGET" "$FIXTURE_TARGET_SHA" "$FIXTURE_CONTROL_COMMIT" "$FIXTURE_CONTROL_COMMIT"
    ;;
  */resolve-public-hive-gateway-node.mjs)
    printf '%s\\n' "$FIXTURE_GATEWAY_CONTRACT"
    ;;
  */preflight-public-hive-gateway.mjs)
    [ ! -e "$FIXTURE_PREFLIGHT_FAILURE" ] || exit 23
    evidence=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --evidence ]; then evidence="$2"; shift 2; else shift; fi
    done
    printf '{"schema":"fixture-gateway-evidence"}\\n' > "$evidence"
    ;;
  */verify-public-hive-gateway-evidence.mjs) exit 0 ;;
  */preflight-public-hive-gateway-ops.mjs)
    evidence=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --evidence ]; then evidence="$2"; shift 2; else shift; fi
    done
    printf '{"schema":"fixture-gateway-ops-evidence"}\n' > "$evidence"
    ;;
  */verify-public-hive-gateway-ops-evidence.mjs) exit 0 ;;
  */verify-public-hive-gateway-quarantine.mjs) exit 0 ;;
  *) exit 97 ;;
esac
`)
  copyFileSync(path.join(nodeRepo, 'fleet', 'quarantine-public-gateway.sh'), quarantine)
  chmodSync(quarantine, 0o755)
  const contract = [
    'cohort',
    f.enabledManifest.admissionProfile,
    f.gatewayEntry.origin,
    f.gatewayEntry.connectAddress,
    f.gatewayEntry.appKey,
    f.gatewayEntry.path,
    f.gatewayEntry.contentSha256,
    f.gatewayEntry.driveVersion,
    f.gatewayEntry.peerFingerprint256,
    f.gatewayEntry.nginxConfigSha256,
    'public-t1-gateway',
    f.gatewayEntry.operatorContractSha256
  ].join('\t')
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH || ''}`,
    TMPDIR: runtime,
    HOME: runtime,
    HIVERELAY_REPO_DIR: nodeRepo,
    HIVERELAY_UPDATER_CONF: updaterConf,
    HIVERELAY_CONTROL_STATE: controlState,
    HIVERELAY_ENV_FILE: envFile,
    HIVERELAY_ALLOWED_SIGNERS: f.allowedSigners,
    HIVERELAY_HEALTH_TIMEOUT: '1',
    HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG: gatewayConfig,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG: nginxConfig,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY: nginxBinary,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE: gatewayEvidence,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE: certificate,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY: certificateKey,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT: certificateRoot,
    HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY: ssBinary,
    HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE: gatewayOpsEvidence,
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_COMMAND: quarantine,
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP: `${nginxConfig}.pre-quarantine`,
    FIXTURE_CHANNELS: channelSnapshot,
    FIXTURE_TARGET: TARGET,
    FIXTURE_TARGET_SHA: f.targetSha,
    FIXTURE_CONTROL_COMMIT: git(f.repo, ['rev-parse', 'HEAD']).stdout.trim(),
    FIXTURE_NODE_REPO: nodeRepo,
    FIXTURE_GATEWAY_CONTRACT: contract,
    FIXTURE_PREFLIGHT_FAILURE: preflightFailure,
    FIXTURE_NGINX_LOG: nginxLog,
    FIXTURE_RESTART_LOG: restartLog
  }
  const updater = path.join(nodeRepo, 'fleet', 'updater.sh')

  writeFileSync(preflightFailure, 'red\n')
  const rolledBack = commandResult('/bin/bash', [updater], { env })
  t.not(rolledBack.status, 0, rolledBack.stderr || rolledBack.stdout)
  t.ok(rolledBack.stdout.includes('froze current-release public gateway quarantine verifier/helper authority'),
    rolledBack.stderr || rolledBack.stdout)
  t.ok(rolledBack.stdout.includes('management rollback OK'), rolledBack.stderr || rolledBack.stdout)
  t.is(git(nodeRepo, ['rev-parse', 'HEAD']).stdout.trim(), f.previousSha)
  t.is(lines(restartLog).length, 2, 'failed target restart is followed by prior-release restart')
  t.ok(readFileSync(nginxConfig, 'utf8').startsWith('# hiverelay-public-gateway-quarantine-v1\n'),
    'failed public-t1 target installs the signed quarantine helper result before management rollback')
  t.ok(existsSync(`${nginxConfig}.pre-quarantine`), 'signed helper retains exact recovery bytes')
  t.is(readJson(gatewayEvidence).schema, 'hiverelay-public-gateway-evidence-invalid-v1')
  t.is(readJson(gatewayOpsEvidence).schema, 'hiverelay-public-gateway-operator-readiness-invalid-v1')

  unlinkSync(preflightFailure)
  const updated = commandResult('/bin/bash', [updater], { env })
  t.is(updated.status, 0, updated.stderr || updated.stdout)
  t.is(git(nodeRepo, ['rev-parse', 'HEAD']).stdout.trim(), f.targetSha)
  t.is(lines(restartLog).length, 3)

  writeFileSync(preflightFailure, 'red\n')
  const contained = commandResult('/bin/bash', [updater], { env })
  t.not(contained.status, 0)
  t.ok(contained.stdout.includes('public edge quarantined; management API left running'))
  t.is(git(nodeRepo, ['rev-parse', 'HEAD']).stdout.trim(), f.targetSha)
  t.is(lines(restartLog).length, 3, 'up-to-date gateway failure does not restart management')
  t.ok(lines(nginxLog).some(line => line === '-s reload'))
  t.is(readJson(gatewayEvidence).schema, 'hiverelay-public-gateway-evidence-invalid-v1')

  unlinkSync(preflightFailure)
  const recovered = commandResult('/bin/bash', [updater], { env })
  t.is(recovered.status, 0, recovered.stderr || recovered.stdout)
  t.is(readJson(gatewayEvidence).schema, 'fixture-gateway-evidence')
  t.is(readJson(gatewayOpsEvidence).schema, 'fixture-gateway-ops-evidence')
}

function writeCompletedObservation (f, statePath, evidencePath, endMs) {
  const samples = []
  for (let offset = WINDOW_MS; offset >= 0; offset -= MAX_GAP_MS) {
    const timestamp = new Date(endMs - offset).toISOString()
    samples.push({
      observedAt: timestamp,
      collectedAt: timestamp,
      evidenceSha256: offset === 0
        ? 'd'.repeat(64)
        : sha256(Buffer.from(`rehearsal-window-${offset}`))
    })
  }
  const state = {
    schema: 'hiverelay-public-gateway-window-state-v1',
    releaseTarget: TARGET,
    releaseSha: f.targetSha,
    channel: 'canary',
    manifestSha256: sha256(f.manifestBytes),
    observationWindowMs: WINDOW_MS,
    maxProbeGapMs: MAX_GAP_MS,
    cohortNames: ['canary-1'],
    relays: [{ name: 'canary-1', samples }]
  }
  const stateBytes = Buffer.from(JSON.stringify(state, null, 2) + '\n')
  writeFileSync(statePath, stateBytes)
  const now = new Date(endMs).toISOString()
  const evidence = {
    schemaVersion: 2,
    generatedAt: now,
    status: 'verified',
    target: { tag: TARGET, version: TARGET.slice(1), sha: f.targetSha, channel: 'canary' },
    inventory: {
      sha256: sha256(readFileSync(f.relaysPath)),
      relayNames: ['canary-1']
    },
    channelConfig: {
      sha256: sha256(readFileSync(f.channelsPath)),
      targets: { canary: TARGET }
    },
    probes: { publicGatewayEvidence: true },
    summary: {
      total: 1,
      updated: 1,
      packageVersionMatches: 1,
      healthy: 1,
      runtimeVersionMatches: 1,
      gatewayHealthy: 1
    },
    publicGateway: {
      manifest: {
        path: 'fleet/public-hive-gateway-release.json',
        sha256: sha256(f.manifestBytes),
        releaseTarget: TARGET,
        admissionProfile: f.enabledManifest.admissionProfile,
        observationWindowMs: WINDOW_MS,
        maxProbeGapMs: MAX_GAP_MS,
        cohortNames: ['canary-1']
      },
      windowStateSha256: sha256(stateBytes),
      window: {
        windowStartedAt: samples[0].observedAt,
        windowEndedAt: samples.at(-1).observedAt,
        durationMs: WINDOW_MS,
        sampleCount: samples.length,
        maxGapMs: MAX_GAP_MS,
        relayCount: 1,
        complete: true
      }
    },
    relays: [{
      name: 'canary-1',
      channel: 'canary',
      packageVersion: TARGET,
      healthVersion: TARGET.slice(1),
      observedAt: now,
      headSha: f.targetSha,
      updated: true,
      packageVersionMatches: true,
      healthy: true,
      runtimeVersionMatches: true,
      gatewayHealthy: true,
      gateway: {
        schema: 'hiverelay-public-gateway-evidence-verification-v1',
        status: 'verified',
        mode: 'fleet',
        admissionProfile: f.enabledManifest.admissionProfile,
        publicSuffixReady: false,
        releaseTarget: TARGET,
        releaseSha: f.targetSha,
        checkedAt: now,
        probeObservedAt: samples.at(-1).observedAt,
        origin: f.gatewayEntry.origin,
        connectAddress: f.gatewayEntry.connectAddress,
        appKey: f.gatewayEntry.appKey,
        path: f.gatewayEntry.path,
        contentSha256: f.gatewayEntry.contentSha256,
        driveVersion: f.gatewayEntry.driveVersion,
        tlsProtocol: 'TLSv1.3',
        peerFingerprint256: f.gatewayEntry.peerFingerprint256,
        nginxSha256: f.gatewayEntry.nginxConfigSha256,
        checks: {
          metadata: true,
          exactBytes: true,
          range: true,
          head: true,
          canonicalIdentity: true,
          managementIsolation: true,
          forwardedHostIsolation: true,
          unavailableAppIsolation: true,
          defaultSniRejection: true,
          sniHostBinding: true
        },
        evidenceSha256: samples.at(-1).evidenceSha256
      }
    }]
  }
  writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n')
}

function assertSingleChannelsCommit (t, repo, commit) {
  const names = git(repo, ['diff-tree', '--no-commit-id', '--name-only', '-r', commit]).stdout.trim()
  t.is(names, 'fleet/channels.json')
}

function assertRemoteHead (t, f) {
  const local = git(f.repo, ['rev-parse', 'HEAD']).stdout.trim()
  const remote = command('/usr/bin/git', ['--git-dir', f.remote, 'rev-parse', 'refs/heads/main']).stdout.trim()
  t.is(remote, local)
}

function verifySignedCommit (repo, commit, allowedSigners) {
  git(repo, [
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSigners}`,
    '-c', 'gpg.ssh.program=/usr/bin/ssh-keygen',
    'verify-commit', commit
  ])
}

function copyFixtureSource (source, destination) {
  copyFileSync(path.resolve(source), destination)
}

function executable (file, source) {
  writeFileSync(file, source)
  chmodSync(file, 0o755)
}

function readJson (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

function lines (file) {
  if (!existsSync(file)) return []
  return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean)
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function git (repo, args) {
  return command('/usr/bin/git', ['-C', repo, ...args])
}

function command (program, args, options = {}) {
  const result = commandResult(program, args, options)
  if (result.status !== 0) {
    throw new Error(`${program} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  }
  return result
}

function commandResult (program, args, options = {}) {
  return spawnSync(program, args, {
    encoding: 'utf8',
    timeout: 30_000,
    ...options,
    env: options.env || process.env
  })
}

function have (program) {
  return !spawnSync(program, ['--version'], { stdio: 'ignore' }).error
}
