import test from 'brittle'
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'

const updaterPath = path.resolve('fleet/updater.sh')
const targetSha = 'c'.repeat(40)
const priorSha = 'd'.repeat(40)
const appKey = 'a'.repeat(64)
const contentSha256 = 'b'.repeat(64)
const nginxSha256 = 'e'.repeat(64)
const operatorContractSha256 = 'f'.repeat(64)
const fingerprint256 = Array(32).fill('AA').join(':')
const origin = 'https://manifest-app.hive.test'

function executable (filename, source) {
  writeFileSync(filename, source)
  chmodSync(filename, 0o755)
}

function fixture (t) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'hr-updater-gateway-')))
  const bin = path.join(root, 'bin')
  const repo = path.join(root, 'repo')
  const scripts = path.join(repo, 'scripts')
  const scriptLibrary = path.join(scripts, 'lib')
  const gitLog = path.join(root, 'git.log')
  const systemctlLog = path.join(root, 'systemctl.log')
  const restartCount = path.join(root, 'restart-count')
  const resolverArgs = path.join(root, 'resolver-args.log')
  const controlResolverArgs = path.join(root, 'control-resolver-args.log')
  const preflightArgs = path.join(root, 'preflight-args.log')
  const preflightEnv = path.join(root, 'preflight-env.log')
  const verifierArgs = path.join(root, 'verifier-args.log')
  const opsPreflightArgs = path.join(root, 'ops-preflight-args.log')
  const opsVerifierArgs = path.join(root, 'ops-verifier-args.log')
  const quarantineArgs = path.join(root, 'quarantine-args.log')
  const quarantineVerifierArgs = path.join(root, 'quarantine-verifier-args.log')
  const disabledConfigVerifierArgs = path.join(root, 'disabled-config-verifier-args.log')
  const syncLog = path.join(root, 'sync.log')
  const syncCount = path.join(root, 'sync-count')
  const envFile = path.join(root, 'hiverelay.env')
  const updaterConf = path.join(root, 'hiverelay-updater.conf')
  const allowedSigners = path.join(root, 'allowed-signers')
  const evidence = path.join(root, 'gateway-evidence.json')
  const gatewayConfig = path.join(root, 'gateway.json')
  const opsEvidence = path.join(root, 'gateway-ops-evidence.json')
  const certificate = path.join(root, 'fullchain.pem')
  const certificateKey = path.join(root, 'privkey.pem')
  const certificateRoot = path.join(root, 'letsencrypt')
  const ssBinary = path.join(root, 'ss')
  const nginxConfig = path.join(root, 'hiverelay-public-apps.conf')
  const nginxBinary = path.join(root, 'nginx')
  const nginxBinaryLog = path.join(root, 'nginx-binary.log')
  const ssBinaryLog = path.join(root, 'ss-binary.log')
  const hostileExecutionLog = path.join(root, 'hostile-execution.log')
  const quarantine = path.join(root, 'quarantine-public-gateway')
  const quarantineBackup = path.join(root, 'hiverelay-public-apps.conf.pre-quarantine')
  const operatorContract = path.join(repo, 'fleet', 'public-hive-gateway-operators', 'stable-1.json')
  const releaseManifest = path.join(repo, 'fleet', 'public-hive-gateway-release.json')
  const quarantineSource = `#!/bin/sh
for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_QUARANTINE_ARGS"
exit "$FAKE_QUARANTINE_STATUS"
`

  mkdirSync(bin)
  mkdirSync(scripts, { recursive: true })
  mkdirSync(scriptLibrary, { recursive: true })
  mkdirSync(path.join(repo, 'fleet', 'public-hive-gateway-operators'), { recursive: true })
  mkdirSync(certificateRoot)
  writeFileSync(path.join(repo, 'package.json'), '{"version":"1.2.2"}\n')
  writeFileSync(path.join(scripts, 'resolve-signed-fleet-channel.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'resolve-public-hive-gateway-node.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'preflight-public-hive-gateway.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'verify-public-hive-gateway-evidence.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'preflight-public-hive-gateway-ops.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'verify-public-hive-gateway-ops-evidence.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'verify-public-hive-gateway-quarantine.mjs'), '// fixture\n')
  writeFileSync(path.join(scripts, 'verify-public-hive-gateway-disabled-config.mjs'), '// fixture\n')
  writeFileSync(path.join(scriptLibrary, 'public-hive-gateway-quarantine-authority.mjs'), '// fixture\n')
  writeFileSync(path.join(scriptLibrary, 'public-hive-gateway-release-manifest.mjs'), '// fixture\n')
  writeFileSync(path.join(scriptLibrary, 'public-hive-gateway-policy.mjs'), '// fixture\n')
  writeFileSync(path.join(repo, 'fleet', 'quarantine-public-gateway.sh'), quarantineSource)
  writeFileSync(releaseManifest, '{"schema":"fixture"}\n')
  writeFileSync(operatorContract, '{"schema":"fixture"}\n')
  writeFileSync(envFile, 'HIVERELAY_API_KEY=fixture-secret\n')
  writeFileSync(updaterConf, `CHANNEL=stable\nRELAY_NAME=stable-1\nREPO_DIR=${repo}\n`)
  writeFileSync(allowedSigners, 'release@example.invalid ssh-ed25519 fixture\n')
  writeFileSync(evidence, '{"schema":"stale-valid-evidence"}\n')
  writeFileSync(gatewayConfig, '{}\n')
  writeFileSync(opsEvidence, '{"schema":"stale-valid-ops-evidence"}\n')
  writeFileSync(certificate, 'fixture certificate\n')
  writeFileSync(certificateKey, 'fixture key\n')
  writeFileSync(nginxConfig, '# installed edge fixture\n')
  executable(nginxBinary, '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$FAKE_NGINX_BINARY_LOG"\nexit 0\n')
  executable(ssBinary, '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$FAKE_SS_BINARY_LOG"\nexit 0\n')

  executable(path.join(bin, 'curl'), `#!/bin/sh
case "$*" in
  */health*)
    count=0
    [ ! -f "$FAKE_RESTART_COUNT" ] || count="$(cat "$FAKE_RESTART_COUNT")"
    if [ "$count" -ge 2 ]; then version="$FAKE_CURRENT_VERSION"; else version="$FAKE_TARGET_VERSION"; fi
    printf '{"running":true,"version":"%s"}\\n' "$version"
    ;;
  *) printf '{"stable":"v1.2.3"}\\n' ;;
esac
`)
  executable(path.join(bin, 'flock'), `#!/bin/sh
exit "${'$'}{FAKE_FLOCK_STATUS:-0}"
`)
  executable(path.join(bin, 'sync'), `#!/bin/sh
count=0
[ ! -f "$FAKE_SYNC_COUNT" ] || count="$(cat "$FAKE_SYNC_COUNT")"
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_SYNC_COUNT"
printf '%s\n' "$*" >> "$FAKE_SYNC_LOG"
[ "$count" != "${'$'}{FAKE_SYNC_FAIL_AT:-0}" ]
`)
  executable(path.join(bin, 'git'), `#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_GIT_LOG"
case "$1" in
  diff|fetch) exit 0 ;;
  checkout)
    case "$*" in
      *" $FAKE_TARGET_TAG") exit "$FAKE_TARGET_CHECKOUT_STATUS" ;;
    esac
    exit "$FAKE_PRIOR_CHECKOUT_STATUS"
    ;;
  status) exit 0 ;;
  ls-files)
    [ "$2" != "-v" ] || printf 'H package.json\nH scripts/resolve-public-hive-gateway-node.mjs\n'
    exit 0
    ;;
  cat-file)
    if [ "$2" = "-t" ]; then printf 'tag\\n'; exit 0; fi
    if [ "$2" = "-e" ]; then [ "$FAKE_MANIFEST_PRESENT" = "1" ]; exit $?; fi
    ;;
  rev-parse)
    case "$*" in
      *refs/tags*) printf '%s\\n' "$FAKE_TARGET_SHA" ;;
      *) printf '%s\\n' "$FAKE_CURRENT_SHA" ;;
    esac
    exit 0
    ;;
  ls-tree)
    case "$*" in
      *fleet/quarantine-public-gateway.sh*)
        printf 'fleet/quarantine-public-gateway.sh\n'
        exit 0
        ;;
      *scripts/verify-public-hive-gateway-quarantine.mjs*)
        printf 'scripts/verify-public-hive-gateway-quarantine.mjs\n'
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-quarantine-authority.mjs*)
        printf 'scripts/lib/public-hive-gateway-quarantine-authority.mjs\n'
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-release-manifest.mjs*)
        printf 'scripts/lib/public-hive-gateway-release-manifest.mjs\n'
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-policy.mjs*)
        printf 'scripts/lib/public-hive-gateway-policy.mjs\n'
        exit 0
        ;;
      *fleet/public-hive-gateway-operators/stable-1.json*)
        printf 'fleet/public-hive-gateway-operators/stable-1.json\n'
        exit 0
        ;;
    esac
    [ "$FAKE_MANIFEST_TREE_STATUS" = "0" ] || exit "$FAKE_MANIFEST_TREE_STATUS"
    present="$FAKE_MANIFEST_PRESENT"
    if [ "$3" = "$FAKE_CURRENT_SHA" ] && [ -n "$FAKE_SOURCE_MANIFEST_PRESENT" ]; then
      present="$FAKE_SOURCE_MANIFEST_PRESENT"
    elif [ "$3" = "$FAKE_TARGET_SHA" ] && [ -n "$FAKE_TARGET_MANIFEST_PRESENT" ]; then
      present="$FAKE_TARGET_MANIFEST_PRESENT"
    fi
    [ "$present" != "1" ] || printf 'fleet/public-hive-gateway-release.json\\n'
    exit 0
    ;;
  show)
    case "$*" in
      *fleet/quarantine-public-gateway.sh*)
        cat "$FAKE_REPO/fleet/quarantine-public-gateway.sh"
        exit 0
        ;;
      *scripts/verify-public-hive-gateway-quarantine.mjs*)
        cat "$FAKE_REPO/scripts/verify-public-hive-gateway-quarantine.mjs"
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-quarantine-authority.mjs*)
        cat "$FAKE_REPO/scripts/lib/public-hive-gateway-quarantine-authority.mjs"
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-release-manifest.mjs*)
        cat "$FAKE_REPO/scripts/lib/public-hive-gateway-release-manifest.mjs"
        exit 0
        ;;
      *scripts/lib/public-hive-gateway-policy.mjs*)
        cat "$FAKE_REPO/scripts/lib/public-hive-gateway-policy.mjs"
        exit 0
        ;;
      *fleet/public-hive-gateway-operators/stable-1.json*)
        printf '%s\n' "$FAKE_OPERATOR_CONTRACT"
        exit 0
        ;;
    esac
    [ "$FAKE_MANIFEST_SHOW_STATUS" = "0" ] || exit "$FAKE_MANIFEST_SHOW_STATUS"
    printf '%s\\n' "$FAKE_GATEWAY_MANIFEST"
    exit 0
    ;;
esac
case "$*" in
  *verify-tag*) printf 'Good "git" signature\\n'; exit "$FAKE_VERIFY_TAG_STATUS" ;;
esac
exit 0
`)
  executable(path.join(bin, 'systemctl'), `#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_SYSTEMCTL_LOG"
if [ "$1" = "restart" ]; then
  count=0
  [ ! -f "$FAKE_RESTART_COUNT" ] || count="$(cat "$FAKE_RESTART_COUNT")"
  count=$((count + 1))
  printf '%s\\n' "$count" > "$FAKE_RESTART_COUNT"
  if [ "$count" = "${'$'}{FAKE_SYSTEMCTL_FAIL_RESTART_AT:-0}" ]; then
    exit "${'$'}{FAKE_SYSTEMCTL_RESTART_STATUS:-1}"
  fi
fi
exit 0
`)
  executable(path.join(bin, 'timeout'), `#!/bin/sh
shift
exec "$@"
`)
  executable(path.join(bin, 'node'), `#!/bin/sh
if [ "$1" = "--version" ]; then printf '%s\n' 'v22.0.0'; exit 0; fi
script="$1"
shift
case "$script" in
  */resolve-signed-fleet-channel.mjs)
    for arg in "$@"; do printf '%s\n' "$arg"; done > "$FAKE_CONTROL_RESOLVER_ARGS"
    printf 'resolved\tv1.2.3\t%s\t%s\t%s\n' "$FAKE_TARGET_SHA" "$FAKE_CONTROL_COMMIT" "$FAKE_CONTROL_TIP"
    exit "$FAKE_CONTROL_RESOLVER_STATUS"
    ;;
  */resolve-public-hive-gateway-node.mjs)
    for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_RESOLVER_ARGS"
    selected="$FAKE_GATEWAY_CONTRACT"
    previous=""
    for arg in "$@"; do
      if [ "$previous" = "--release-target" ] && [ "$arg" = "$FAKE_CURRENT_VERSION_TAG" ] &&
        [ -n "$FAKE_SOURCE_GATEWAY_CONTRACT" ]; then
        selected="$FAKE_SOURCE_GATEWAY_CONTRACT"
      fi
      previous="$arg"
    done
    printf '%s\\n' "$selected"
    exit "$FAKE_RESOLVER_STATUS"
    ;;
  */preflight-public-hive-gateway.mjs)
    for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_PREFLIGHT_ARGS"
    printf '%s\\n' "$HIVERELAY_API_KEY" > "$FAKE_PREFLIGHT_ENV"
    if [ "$FAKE_PREFLIGHT_RUN_NGINX" = 1 ]; then "$FAKE_NGINX_BINARY" -T; fi
    if [ "$FAKE_PREFLIGHT_REPLACE_NGINX" = 1 ]; then
      replacement="$FAKE_NGINX_BINARY.replacement"
      printf '%s\\n' '#!/bin/sh' 'printf nginx-hostile >> "$FAKE_HOSTILE_EXECUTION_LOG"' > "$replacement"
      chmod 0755 "$replacement"
      mv -f "$replacement" "$FAKE_NGINX_BINARY"
    fi
    exit "$FAKE_PREFLIGHT_STATUS"
    ;;
  */verify-public-hive-gateway-evidence.mjs)
    for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_VERIFIER_ARGS"
    exit "$FAKE_VERIFIER_STATUS"
    ;;
  */preflight-public-hive-gateway-ops.mjs)
    for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_OPS_PREFLIGHT_ARGS"
    if [ "$FAKE_OPS_RUN_SS" = 1 ]; then "$FAKE_SS_BINARY" -H -lntup; fi
    if [ "$FAKE_OPS_REPLACE_SS" = 1 ]; then
      replacement="$FAKE_SS_BINARY.replacement"
      printf '%s\\n' '#!/bin/sh' 'printf ss-hostile >> "$FAKE_HOSTILE_EXECUTION_LOG"' > "$replacement"
      chmod 0755 "$replacement"
      mv -f "$replacement" "$FAKE_SS_BINARY"
    fi
    exit "$FAKE_OPS_PREFLIGHT_STATUS"
    ;;
  */verify-public-hive-gateway-ops-evidence.mjs)
    for arg in "$@"; do printf '%s\\n' "$arg"; done > "$FAKE_OPS_VERIFIER_ARGS"
    exit "$FAKE_OPS_VERIFIER_STATUS"
    ;;
  */verify-public-hive-gateway-quarantine.mjs)
    for arg in "$@"; do printf '%s\n' "$arg"; done > "$FAKE_QUARANTINE_VERIFIER_ARGS"
    exit "$FAKE_QUARANTINE_VERIFIER_STATUS"
    ;;
  */verify-public-hive-gateway-disabled-config.mjs)
    for arg in "$@"; do printf '%s\n' "$arg"; done > "$FAKE_DISABLED_CONFIG_VERIFIER_ARGS"
    exit "$FAKE_DISABLED_CONFIG_VERIFIER_STATUS"
    ;;
esac
exit 97
`)
  executable(quarantine, quarantineSource)

  t.teardown(() => rmSync(root, { recursive: true, force: true }))

  const contract = [
    'cohort',
    'blind-substrate-public-v1',
    origin,
    '127.0.0.1',
    appKey,
    '/index.html',
    contentSha256,
    '7',
    fingerprint256,
    nginxSha256,
    'public-t1-gateway',
    operatorContractSha256
  ].join('\t')
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH || ''}`,
    TMPDIR: root,
    HOME: root,
    HIVERELAY_REPO_DIR: repo,
    HIVERELAY_GIT_BIN: path.join(bin, 'git'),
    HIVERELAY_UPDATER_CONF: updaterConf,
    HIVERELAY_CONTROL_STATE: path.join(root, 'control-state', 'channel.json'),
    HIVERELAY_ENV_FILE: envFile,
    HIVERELAY_ALLOWED_SIGNERS: allowedSigners,
    HIVERELAY_HEALTH_TIMEOUT: '1',
    HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG: gatewayConfig,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG: nginxConfig,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY: nginxBinary,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE: evidence,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE: certificate,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY: certificateKey,
    HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT: certificateRoot,
    HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY: ssBinary,
    HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE: opsEvidence,
    HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY: '0',
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_COMMAND: quarantine,
    HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP: quarantineBackup,
    // These retired, mutable selectors must never override the signed manifest.
    HIVERELAY_PUBLIC_GATEWAY_PROBE_ORIGIN: 'https://attacker.invalid/',
    HIVERELAY_PUBLIC_GATEWAY_PROBE_CONNECT_ADDRESS: '192.0.2.99',
    HIVERELAY_PUBLIC_GATEWAY_PROBE_APP_KEY: 'f'.repeat(64),
    HIVERELAY_PUBLIC_GATEWAY_PROBE_PATH: '/attacker',
    HIVERELAY_PUBLIC_GATEWAY_PROBE_SHA256: '0'.repeat(64),
    HIVERELAY_PUBLIC_GATEWAY_PROBE_MODE: 'canary',
    FAKE_CURRENT_SHA: targetSha,
    FAKE_NGINX_BINARY: nginxBinary,
    FAKE_SS_BINARY: ssBinary,
    FAKE_NGINX_BINARY_LOG: nginxBinaryLog,
    FAKE_SS_BINARY_LOG: ssBinaryLog,
    FAKE_HOSTILE_EXECUTION_LOG: hostileExecutionLog,
    FAKE_PREFLIGHT_RUN_NGINX: '0',
    FAKE_PREFLIGHT_REPLACE_NGINX: '0',
    FAKE_OPS_RUN_SS: '0',
    FAKE_OPS_REPLACE_SS: '0',
    FAKE_REPO: repo,
    FAKE_TARGET_SHA: targetSha,
    FAKE_CONTROL_COMMIT: '1'.repeat(40),
    FAKE_CONTROL_TIP: '2'.repeat(40),
    FAKE_CONTROL_RESOLVER_STATUS: '0',
    FAKE_CURRENT_VERSION: '1.2.2',
    FAKE_CURRENT_VERSION_TAG: 'v1.2.2',
    FAKE_TARGET_VERSION: '1.2.3',
    FAKE_TARGET_TAG: 'v1.2.3',
    FAKE_GATEWAY_MANIFEST: '{"schema":"fixture"}',
    FAKE_OPERATOR_CONTRACT: '{"schema":"fixture-operator"}',
    FAKE_GATEWAY_CONTRACT: contract,
    FAKE_MANIFEST_PRESENT: '1',
    FAKE_SOURCE_MANIFEST_PRESENT: '',
    FAKE_TARGET_MANIFEST_PRESENT: '',
    FAKE_SOURCE_GATEWAY_CONTRACT: '',
    FAKE_MANIFEST_TREE_STATUS: '0',
    FAKE_MANIFEST_SHOW_STATUS: '0',
    FAKE_VERIFY_TAG_STATUS: '0',
    FAKE_RESOLVER_STATUS: '0',
    FAKE_PREFLIGHT_STATUS: '0',
    FAKE_VERIFIER_STATUS: '0',
    FAKE_OPS_PREFLIGHT_STATUS: '0',
    FAKE_OPS_VERIFIER_STATUS: '0',
    FAKE_QUARANTINE_STATUS: '0',
    FAKE_QUARANTINE_VERIFIER_STATUS: '0',
    FAKE_DISABLED_CONFIG_VERIFIER_STATUS: '0',
    FAKE_TARGET_CHECKOUT_STATUS: '0',
    FAKE_PRIOR_CHECKOUT_STATUS: '0',
    FAKE_SYSTEMCTL_FAIL_RESTART_AT: '0',
    FAKE_SYSTEMCTL_RESTART_STATUS: '1',
    FAKE_FLOCK_STATUS: '0',
    FAKE_SYNC_FAIL_AT: '0',
    FAKE_SYNC_LOG: syncLog,
    FAKE_SYNC_COUNT: syncCount,
    FAKE_GIT_LOG: gitLog,
    FAKE_SYSTEMCTL_LOG: systemctlLog,
    FAKE_RESTART_COUNT: restartCount,
    FAKE_RESOLVER_ARGS: resolverArgs,
    FAKE_CONTROL_RESOLVER_ARGS: controlResolverArgs,
    FAKE_PREFLIGHT_ARGS: preflightArgs,
    FAKE_PREFLIGHT_ENV: preflightEnv,
    FAKE_VERIFIER_ARGS: verifierArgs,
    FAKE_OPS_PREFLIGHT_ARGS: opsPreflightArgs,
    FAKE_OPS_VERIFIER_ARGS: opsVerifierArgs,
    FAKE_QUARANTINE_ARGS: quarantineArgs,
    FAKE_QUARANTINE_VERIFIER_ARGS: quarantineVerifierArgs,
    FAKE_DISABLED_CONFIG_VERIFIER_ARGS: disabledConfigVerifierArgs
  }

  return {
    root,
    bin,
    env,
    evidence,
    gitLog,
    nginxBinary,
    nginxBinaryLog,
    ssBinaryLog,
    hostileExecutionLog,
    nginxConfig,
    certificate,
    certificateKey,
    certificateRoot,
    contract,
    controlResolverArgs,
    gatewayConfig,
    operatorContract,
    opsEvidence,
    opsPreflightArgs,
    opsVerifierArgs,
    preflightArgs,
    preflightEnv,
    quarantineArgs,
    quarantine,
    quarantineVerifierArgs,
    disabledConfigVerifierArgs,
    quarantineBackup,
    releaseManifest,
    repo,
    resolverArgs,
    systemctlLog,
    ssBinary,
    syncLog,
    updaterConf,
    verifierArgs,
    run: (overrides = {}) => spawnSync('bash', [updaterPath], {
      encoding: 'utf8',
      env: { ...env, ...overrides }
    })
  }
}

function argsFrom (filename) {
  return readFileSync(filename, 'utf8').trim().split('\n')
}

function valueAfter (args, flag) {
  const index = args.indexOf(flag)
  return index === -1 ? undefined : args[index + 1]
}

function assertContained (t, f) {
  const invalid = JSON.parse(readFileSync(f.evidence, 'utf8'))
  t.is(invalid.schema, 'hiverelay-public-gateway-evidence-invalid-v1')
  t.is(invalid.releaseTarget, 'v1.2.3')
  t.is(invalid.releaseSha, targetSha)
  t.is(invalid.relay, 'stable-1')
  t.is(statSync(f.evidence).mode & 0o777, 0o600)
  const invalidOps = JSON.parse(readFileSync(f.opsEvidence, 'utf8'))
  t.is(invalidOps.schema, 'hiverelay-public-gateway-operator-readiness-invalid-v1')
  t.is(invalidOps.releaseTarget, 'v1.2.3')
  t.is(invalidOps.releaseSha, targetSha)
  t.is(invalidOps.relay, 'stable-1')
  t.is(invalidOps.operatorContractSha256, operatorContractSha256)
  t.is(statSync(f.opsEvidence).mode & 0o777, 0o600)
  t.alike(argsFrom(f.quarantineArgs), [f.nginxConfig, f.quarantineBackup, f.nginxBinary])
  const verifier = argsFrom(f.quarantineVerifierArgs)
  t.is(valueAfter(verifier, '--expected-digest'), operatorContractSha256)
  t.is(valueAfter(verifier, '--nginx-binary'), f.nginxBinary)
}

test('signed cohort forces preflight and standalone verification from exact manifest bindings', (t) => {
  const f = fixture(t)
  const result = f.run()

  t.is(result.status, 0, result.stderr || result.stdout)
  const preflight = argsFrom(f.preflightArgs)
  t.is(valueAfter(preflight, '--mode'), 'fleet')
  t.is(valueAfter(preflight, '--probe-origin'), origin)
  t.is(valueAfter(preflight, '--connect-address'), '127.0.0.1')
  t.is(valueAfter(preflight, '--app-key'), appKey)
  t.is(valueAfter(preflight, '--path'), '/index.html')
  t.is(valueAfter(preflight, '--expected-sha256'), contentSha256)
  t.is(valueAfter(preflight, '--evidence'), f.evidence)
  t.is(valueAfter(preflight, '--release-target'), 'v1.2.3')
  t.is(valueAfter(preflight, '--release-sha'), targetSha)
  t.absent(preflight.includes('--public-suffix-ready'))
  t.is(readFileSync(f.preflightEnv, 'utf8').trim(), 'fixture-secret')
  t.absent(preflight.includes('fixture-secret'), 'relay API key stays out of child argv')

  const verifier = argsFrom(f.verifierArgs)
  t.is(valueAfter(verifier, '--require-mode'), 'fleet')
  t.is(valueAfter(verifier, '--require-admission-profile'), 'blind-substrate-public-v1')
  t.is(valueAfter(verifier, '--expected-origin'), origin)
  t.is(valueAfter(verifier, '--expected-connect-address'), '127.0.0.1')
  t.is(valueAfter(verifier, '--expected-app-key'), appKey)
  t.is(valueAfter(verifier, '--expected-path'), '/index.html')
  t.is(valueAfter(verifier, '--expected-sha256'), contentSha256)
  t.is(valueAfter(verifier, '--expected-drive-version'), '7')
  t.is(valueAfter(verifier, '--expected-peer-fingerprint256'), fingerprint256)
  t.is(valueAfter(verifier, '--expected-nginx-sha256'), nginxSha256)

  const opsPreflight = argsFrom(f.opsPreflightArgs)
  t.is(valueAfter(opsPreflight, '--mode'), 'fleet')
  t.is(valueAfter(opsPreflight, '--contract'), f.operatorContract)
  t.is(valueAfter(opsPreflight, '--config'), f.gatewayConfig)
  t.is(valueAfter(opsPreflight, '--gateway-evidence'), f.evidence)
  t.is(valueAfter(opsPreflight, '--release-sha'), targetSha)
  t.is(valueAfter(opsPreflight, '--release-manifest'), f.releaseManifest)
  t.is(valueAfter(opsPreflight, '--certificate'), f.certificate)
  t.is(valueAfter(opsPreflight, '--certificate-key'), f.certificateKey)
  t.is(valueAfter(opsPreflight, '--certificate-root'), f.certificateRoot)
  t.is(valueAfter(opsPreflight, '--ss-binary'), f.ssBinary)
  t.ok(opsPreflight.includes('--dns-live'))
  t.is(valueAfter(opsPreflight, '--evidence'), f.opsEvidence)

  const opsVerifier = argsFrom(f.opsVerifierArgs)
  t.is(valueAfter(opsVerifier, '--evidence'), f.opsEvidence)
  t.is(valueAfter(opsVerifier, '--contract'), f.operatorContract)
  t.is(valueAfter(opsVerifier, '--release-manifest'), f.releaseManifest)
  t.is(valueAfter(opsVerifier, '--release-sha'), targetSha)
  t.is(valueAfter(opsVerifier, '--relay'), 'stable-1')
  t.is(valueAfter(opsVerifier, '--expected-contract-sha256'), operatorContractSha256)

  t.alike(argsFrom(f.resolverArgs), [
    '--release-target', 'v1.2.3',
    '--relay', 'stable-1',
    '--channel', 'stable',
    '--require-public-t1'
  ])
  const control = argsFrom(f.controlResolverArgs)
  t.is(valueAfter(control, '--repo'), f.repo)
  t.is(valueAfter(control, '--remote'), 'origin')
  t.is(valueAfter(control, '--branch'), 'main')
  t.is(valueAfter(control, '--channel'), 'stable')
  t.is(valueAfter(control, '--installed-head'), targetSha)
  t.absent(readFileSync(f.gitLog, 'utf8').includes('checkout'))
  t.absent(readFileSync(f.systemctlLog, 'utf8').includes('restart'))
  t.absent(existsSync(f.quarantineArgs))
  t.ok(result.stdout.includes('up-to-date at v1.2.3'))
})

test('signed control resolver failure stops before tag policy or gateway execution', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_CONTROL_RESOLVER_STATUS: '31' })
  t.not(result.status, 0)
  t.ok(result.stdout.includes('signed fleet channel control resolution failed'))
  t.ok(existsSync(f.controlResolverArgs))
  t.absent(existsSync(f.resolverArgs))
  t.absent(existsSync(f.preflightArgs))
  t.absent(readFileSync(f.gitLog, 'utf8').includes('verify-tag'))
})

test('up-to-date preflight failure invalidates evidence and quarantines only public edge', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_PREFLIGHT_STATUS: '23' })

  t.not(result.status, 0)
  t.ok(result.stdout.includes('public edge quarantined; management API left running'))
  assertContained(t, f)
  t.absent(existsSync(f.verifierArgs), 'failed preflight never reaches evidence acceptance')
  t.absent(readFileSync(f.gitLog, 'utf8').includes('checkout'))
  t.absent(readFileSync(f.systemctlLog, 'utf8').includes('restart'))
  t.absent(readFileSync(f.systemctlLog, 'utf8').includes('stop'))
})

test('up-to-date evidence binding failure also triggers containment', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_VERIFIER_STATUS: '24' })

  t.not(result.status, 0)
  t.ok(result.stdout.includes('public edge quarantined'))
  assertContained(t, f)
  t.ok(existsSync(f.preflightArgs))
  t.ok(existsSync(f.verifierArgs))
})

test('public-t1 ops preflight and verifier failures both invalidate evidence and contain the edge', (t) => {
  const preflightFailure = fixture(t)
  const failedPreflight = preflightFailure.run({ FAKE_OPS_PREFLIGHT_STATUS: '25' })
  t.not(failedPreflight.status, 0)
  t.ok(failedPreflight.stdout.includes('operator preflight failed'))
  t.ok(existsSync(preflightFailure.opsPreflightArgs))
  t.absent(existsSync(preflightFailure.opsVerifierArgs))
  assertContained(t, preflightFailure)

  const verifierFailure = fixture(t)
  const failedVerifier = verifierFailure.run({ FAKE_OPS_VERIFIER_STATUS: '26' })
  t.not(failedVerifier.status, 0)
  t.ok(failedVerifier.stdout.includes('ops evidence does not match'))
  t.ok(existsSync(verifierFailure.opsPreflightArgs))
  t.ok(existsSync(verifierFailure.opsVerifierArgs))
  assertContained(t, verifierFailure)
})

test('public-t1 profile, digest, contract, and ss posture fail closed before ops execution', (t) => {
  const malformedDigest = fixture(t)
  const malformedFields = malformedDigest.contract.split('\t')
  malformedFields[11] = '-'
  const malformedResult = malformedDigest.run({ FAKE_GATEWAY_CONTRACT: malformedFields.join('\t') })
  t.not(malformedResult.status, 0)
  t.ok(malformedResult.stdout.includes('requires a canonical operator contract digest'))
  t.absent(existsSync(malformedDigest.preflightArgs))
  t.absent(existsSync(malformedDigest.opsPreflightArgs))

  const unknownProfile = fixture(t)
  const unknownFields = unknownProfile.contract.split('\t')
  unknownFields[10] = 'public-t2-gateway'
  const unknownResult = unknownProfile.run({ FAKE_GATEWAY_CONTRACT: unknownFields.join('\t') })
  t.not(unknownResult.status, 0)
  t.ok(unknownResult.stdout.includes('deployment profile is unsupported'))
  t.absent(existsSync(unknownProfile.preflightArgs))

  const missingContract = fixture(t)
  rmSync(missingContract.operatorContract)
  const missingResult = missingContract.run()
  t.not(missingResult.status, 0)
  t.ok(missingResult.stdout.includes('operator contract is missing or unsafe'))
  t.ok(existsSync(missingContract.verifierArgs), 'base gateway evidence is verified before ops posture')
  t.absent(existsSync(missingContract.opsPreflightArgs))
  assertContained(t, missingContract)

  const linkedContract = fixture(t)
  rmSync(linkedContract.operatorContract)
  symlinkSync(linkedContract.releaseManifest, linkedContract.operatorContract)
  const linkedResult = linkedContract.run()
  t.not(linkedResult.status, 0)
  t.ok(linkedResult.stdout.includes('operator contract is missing or unsafe'))
  t.absent(existsSync(linkedContract.opsPreflightArgs))
  assertContained(t, linkedContract)

  const unsafeSs = fixture(t)
  rmSync(unsafeSs.ssBinary)
  symlinkSync('/bin/true', unsafeSs.ssBinary)
  const unsafeSsResult = unsafeSs.run()
  t.not(unsafeSsResult.status, 0)
  t.ok(unsafeSsResult.stdout.includes('ss binary is missing or unsafe') ||
    unsafeSsResult.stdout.includes('gateway ss binary path must be canonical') ||
    unsafeSsResult.stdout.includes('gateway ss binary is not a regular executable'))
  t.absent(existsSync(unsafeSs.opsPreflightArgs))
  assertContained(t, unsafeSs)
})

test('enabled legacy cohort is rejected by the updater activation path', (t) => {
  const f = fixture(t)
  const fields = f.contract.split('\t')
  fields[10] = 'legacy'
  fields[11] = '-'
  const result = f.run({ FAKE_GATEWAY_CONTRACT: fields.join('\t') })
  t.not(result.status, 0)
  t.ok(result.stdout.includes('must use public-t1-gateway'))
  t.absent(existsSync(f.preflightArgs))
  t.absent(existsSync(f.verifierArgs))
  t.absent(existsSync(f.opsPreflightArgs))
  t.absent(existsSync(f.opsVerifierArgs))
  t.is(JSON.parse(readFileSync(f.opsEvidence, 'utf8')).schema, 'stale-valid-ops-evidence')
})

test('cohort missing local config fails closed and still attempts edge containment', (t) => {
  const f = fixture(t)
  const result = f.run({ HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG: '' })

  t.not(result.status, 0)
  t.ok(result.stdout.includes('requires explicit config, nginx config, and nginx binary paths'))
  t.absent(existsSync(f.preflightArgs))
  assertContained(t, f)
})

test('containment reports partial failure but never preserves stale evidence', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_PREFLIGHT_STATUS: '23', FAKE_QUARANTINE_STATUS: '9' })

  t.not(result.status, 0)
  t.ok(result.stdout.includes('containment incomplete'))
  t.ok(result.stdout.includes('management service was not stopped'))
  const invalid = JSON.parse(readFileSync(f.evidence, 'utf8'))
  t.is(invalid.schema, 'hiverelay-public-gateway-evidence-invalid-v1')
  t.ok(existsSync(f.quarantineArgs), 'quarantine is attempted independently of evidence invalidation')
  t.absent(readFileSync(f.systemctlLog, 'utf8').includes('restart'))
})

test('new public-t1 release failure quarantines the edge before management rollback', (t) => {
  const f = fixture(t)
  const result = f.run({
    FAKE_CURRENT_SHA: priorSha,
    FAKE_PREFLIGHT_STATUS: '23'
  })

  t.not(result.status, 0)
  const git = readFileSync(f.gitLog, 'utf8')
  const systemctl = readFileSync(f.systemctlLog, 'utf8')
  t.ok(git.includes('checkout --quiet v1.2.3'))
  t.ok(git.includes(`checkout --quiet ${priorSha}`))
  t.ok(argsFrom(f.resolverArgs).includes('--require-public-t1'),
    'the updater never activates a historical legacy cohort')
  t.is(systemctl.split('\n').filter(line => line === 'restart hiverelay').length, 2)
  assertContained(t, f)
  t.ok(result.stdout.includes('management rollback OK'))
  t.ok(result.stdout.includes('public edge remains quarantined pending refreshed previous-release'))
})

test('gateway posture is never evaluated before target tag trust', (t) => {
  const f = fixture(t)
  const result = f.run({ HIVERELAY_ALLOWED_SIGNERS: path.join(path.dirname(f.evidence), 'missing-signers') })

  t.not(result.status, 0)
  t.ok(result.stdout.includes('refusing target release'))
  t.absent(existsSync(f.resolverArgs))
  t.absent(existsSync(f.preflightArgs))
  t.absent(existsSync(f.verifierArgs))
  t.absent(existsSync(f.quarantineArgs))
  t.is(JSON.parse(readFileSync(f.evidence, 'utf8')).schema, 'stale-valid-evidence')
})

test('target-tree or manifest-object failure cannot degrade a cohort into legacy mode', (t) => {
  const treeFailure = fixture(t)
  const treeResult = treeFailure.run({ FAKE_MANIFEST_TREE_STATUS: '2' })
  t.not(treeResult.status, 0)
  t.ok(treeResult.stdout.includes('could not inspect exact target tree'))
  t.absent(existsSync(treeFailure.resolverArgs))
  t.absent(existsSync(treeFailure.preflightArgs))

  const objectFailure = fixture(t)
  const objectResult = objectFailure.run({ FAKE_MANIFEST_SHOW_STATUS: '3' })
  t.not(objectResult.status, 0)
  t.ok(objectResult.stdout.includes('could not read public gateway manifest from exact target'))
  t.absent(existsSync(objectFailure.resolverArgs))
  t.absent(existsSync(objectFailure.preflightArgs))
})

test('signed noncohort and legacy targets remain ordinary health-only no-ops', (t) => {
  const f = fixture(t)

  const noncohort = f.run({ FAKE_GATEWAY_CONTRACT: 'ordinary\tnoncohort' })
  t.is(noncohort.status, 0, noncohort.stderr || noncohort.stdout)
  t.ok(noncohort.stdout.includes('posture=noncohort'))
  t.absent(existsSync(f.preflightArgs))
  t.absent(existsSync(f.verifierArgs))
  t.absent(existsSync(f.quarantineArgs))
  t.absent(existsSync(f.systemctlLog), 'ordinary no-op does not read the API key or restart service')

  rmSync(f.resolverArgs, { force: true })
  const legacy = f.run({ FAKE_MANIFEST_PRESENT: '0' })
  t.is(legacy.status, 0, legacy.stderr || legacy.stdout)
  t.ok(legacy.stdout.includes('uses legacy health only'))
  t.absent(existsSync(f.resolverArgs), 'missing manifest does not execute manifest parser')
})

test('active public-t1 source retires only after quarantine, durable tombstones, and explicit disabled config', (t) => {
  const f = fixture(t)
  const result = f.run({
    FAKE_CURRENT_SHA: priorSha,
    FAKE_GATEWAY_CONTRACT: 'ordinary\tnoncohort',
    FAKE_SOURCE_GATEWAY_CONTRACT: f.contract,
    FAKE_SOURCE_MANIFEST_PRESENT: '1',
    FAKE_TARGET_MANIFEST_PRESENT: '1'
  })
  t.is(result.status, 0, result.stderr || result.stdout)
  t.ok(result.stdout.includes('source public-t1 gateway is leaving its signed cohort'))
  t.ok(result.stdout.includes('public gateway retired green'))
  const git = readFileSync(f.gitLog, 'utf8')
  t.ok(git.indexOf('show ' + priorSha + ':scripts/verify-public-hive-gateway-quarantine.mjs') <
    git.indexOf('checkout --quiet v1.2.3'), 'current-release verifier closure is frozen before target checkout')
  t.ok(existsSync(f.quarantineArgs))
  t.alike(argsFrom(f.disabledConfigVerifierArgs), [f.gatewayConfig])
  const synced = readFileSync(f.syncLog, 'utf8')
  t.ok(synced.includes(`-f ${f.evidence}`))
  t.ok(synced.includes(`-f ${f.opsEvidence}`))
  t.is(readFileSync(f.systemctlLog, 'utf8').trim().split('\n').filter(line => line === 'restart hiverelay').length, 1)
})

test('retirement blocks checkout on missing disabled proof and succeeds on retry, including legacy target', (t) => {
  const f = fixture(t)
  const base = {
    FAKE_CURRENT_SHA: priorSha,
    FAKE_GATEWAY_CONTRACT: 'ordinary\tnoncohort',
    FAKE_SOURCE_GATEWAY_CONTRACT: f.contract,
    FAKE_SOURCE_MANIFEST_PRESENT: '1',
    FAKE_TARGET_MANIFEST_PRESENT: '0'
  }
  const blocked = f.run({ ...base, FAKE_DISABLED_CONFIG_VERIFIER_STATUS: '41' })
  t.not(blocked.status, 0)
  t.ok(blocked.stdout.includes('operator config remains active'))
  t.absent(readFileSync(f.gitLog, 'utf8').includes('checkout --quiet'), 'no target bytes execute before disabled proof')
  t.ok(existsSync(f.quarantineArgs), 'failed retirement remains edge-contained')

  const retried = f.run(base)
  t.is(retried.status, 0, retried.stderr || retried.stdout)
  t.ok(readFileSync(f.gitLog, 'utf8').includes('checkout --quiet v1.2.3'))
  t.ok(retried.stdout.includes('public gateway retired green'))
})

test('retirement checkout/restart failures restore the exact prior SHA while leaving containment in place', (t) => {
  const checkout = fixture(t)
  const base = {
    FAKE_CURRENT_SHA: priorSha,
    FAKE_GATEWAY_CONTRACT: 'ordinary\tnoncohort',
    FAKE_SOURCE_GATEWAY_CONTRACT: checkout.contract,
    FAKE_SOURCE_MANIFEST_PRESENT: '1',
    FAKE_TARGET_MANIFEST_PRESENT: '1'
  }
  const checkoutFailure = checkout.run({ ...base, FAKE_TARGET_CHECKOUT_STATUS: '9' })
  t.not(checkoutFailure.status, 0)
  const checkoutGit = readFileSync(checkout.gitLog, 'utf8')
  t.ok(checkoutGit.includes('checkout --quiet v1.2.3'))
  t.ok(checkoutGit.includes(`checkout --quiet ${priorSha}`))
  t.ok(existsSync(checkout.quarantineArgs))

  const restart = fixture(t)
  const restartFailure = restart.run({
    ...base,
    FAKE_SOURCE_GATEWAY_CONTRACT: restart.contract,
    FAKE_SYSTEMCTL_FAIL_RESTART_AT: '1'
  })
  t.not(restartFailure.status, 0)
  t.ok(restartFailure.stdout.includes('management service restart failed'))
  t.ok(readFileSync(restart.gitLog, 'utf8').includes(`checkout --quiet ${priorSha}`))
  t.is(readFileSync(restart.systemctlLog, 'utf8').trim().split('\n').filter(line => line.startsWith('restart ')).length, 2,
    'failed activation and rollback each attempt one management restart')
  t.ok(existsSync(restart.quarantineArgs))
})

test('rollback restart failure is critical and never reported healthy', (t) => {
  const f = fixture(t)
  const result = f.run({
    FAKE_CURRENT_SHA: priorSha,
    FAKE_PREFLIGHT_STATUS: '23',
    FAKE_SYSTEMCTL_FAIL_RESTART_AT: '2'
  })
  t.not(result.status, 0)
  t.ok(result.stdout.includes('rollback checkout was restored but management service restart failed'))
  t.absent(result.stdout.includes('management rollback OK'))
})

test('evidence invalidation sync failures are explicit and still force edge containment', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_PREFLIGHT_STATUS: '23', FAKE_SYNC_FAIL_AT: '2' })
  t.not(result.status, 0)
  t.ok(result.stdout.includes('could not invalidate stale public gateway evidence'))
  t.ok(existsSync(f.quarantineArgs), 'durability failure cannot leave the public edge open')
  t.ok(existsSync(f.quarantineVerifierArgs), 'live quarantine proof still runs after tombstone sync failure')
})

test('updater rejects unsafe executable boundaries and asks trusted nginx to close when possible', (t) => {
  const writable = fixture(t)
  chmodSync(writable.quarantine, 0o777)
  const writableResult = writable.run({ FAKE_PREFLIGHT_STATUS: '23' })
  t.not(writableResult.status, 0)
  t.ok(writableResult.stdout.includes('gateway quarantine command must be executable and not group/world writable'),
    writableResult.stdout)
  t.ok(readFileSync(writable.nginxBinaryLog, 'utf8').includes('-s stop'))
  t.absent(existsSync(writable.quarantineArgs), 'untrusted helper bytes never execute')

  const linked = fixture(t)
  linkSync(linked.quarantine, path.join(linked.root, 'quarantine-hardlink'))
  const linkedResult = linked.run({ FAKE_PREFLIGHT_STATUS: '23' })
  t.not(linkedResult.status, 0)
  t.ok(linkedResult.stdout.includes('gateway quarantine command must have exactly one link'))
  t.ok(readFileSync(linked.nginxBinaryLog, 'utf8').includes('-s stop'))

  const unsafeNginx = fixture(t)
  writeFileSync(unsafeNginx.nginxBinary, '#!/bin/sh\nprintf nginx-hostile >> "$FAKE_HOSTILE_EXECUTION_LOG"\n')
  chmodSync(unsafeNginx.nginxBinary, 0o777)
  const nginxResult = unsafeNginx.run({ FAKE_PREFLIGHT_STATUS: '23' })
  t.not(nginxResult.status, 0)
  t.ok(nginxResult.stdout.includes('gateway nginx binary must be executable and not group/world writable'))
  t.absent(existsSync(unsafeNginx.quarantineArgs))
  t.absent(existsSync(unsafeNginx.preflightArgs), 'unsafe nginx bytes fail before the preflight child')
  t.absent(existsSync(unsafeNginx.hostileExecutionLog), 'unsafe nginx bytes never execute')

  const staleHelper = fixture(t)
  writeFileSync(staleHelper.quarantine, '#!/bin/sh\nexit 0\n')
  chmodSync(staleHelper.quarantine, 0o755)
  const staleResult = staleHelper.run({ FAKE_PREFLIGHT_STATUS: '23' })
  t.not(staleResult.status, 0)
  t.ok(staleResult.stdout.includes('differs from the signed current-release helper bytes'))
  t.absent(existsSync(staleHelper.quarantineArgs), 'old root-owned helper bytes never execute')
  t.ok(readFileSync(staleHelper.nginxBinaryLog, 'utf8').includes('-s stop'))
})

test('updater trusts nginx and ss before first execution and rejects unsafe parents and links', (t) => {
  const writableSs = fixture(t)
  writeFileSync(writableSs.ssBinary, '#!/bin/sh\nprintf ss-hostile >> "$FAKE_HOSTILE_EXECUTION_LOG"\n')
  chmodSync(writableSs.ssBinary, 0o777)
  const writableSsResult = writableSs.run()
  t.not(writableSsResult.status, 0)
  t.ok(writableSsResult.stdout.includes('gateway ss binary must be executable and not group/world writable'))
  t.absent(existsSync(writableSs.preflightArgs))
  t.absent(existsSync(writableSs.hostileExecutionLog), 'unsafe ss bytes never execute')

  for (const [property, label] of [['nginxBinary', 'nginx'], ['ssBinary', 'ss']]) {
    const linked = fixture(t)
    linkSync(linked[property], path.join(linked.root, `${label}-hardlink`))
    const linkedResult = linked.run()
    t.not(linkedResult.status, 0)
    t.ok(linkedResult.stdout.includes(`gateway ${label} binary must have exactly one link`))
    t.absent(existsSync(linked.preflightArgs), `${label} hardlink fails before preflight`)

    const symlinked = fixture(t)
    const hostile = path.join(symlinked.root, `${label}-hostile`)
    executable(hostile, '#!/bin/sh\nprintf hostile >> "$FAKE_HOSTILE_EXECUTION_LOG"\n')
    rmSync(symlinked[property])
    symlinkSync(hostile, symlinked[property])
    const symlinkResult = symlinked.run()
    t.not(symlinkResult.status, 0)
    t.ok(symlinkResult.stdout.includes(`gateway ${label} binary is not a regular executable`))
    t.absent(existsSync(symlinked.preflightArgs), `${label} symlink fails before preflight`)
    t.absent(existsSync(symlinked.hostileExecutionLog), `${label} symlink target never executes`)
  }

  const writableParent = fixture(t)
  const writableRuntime = path.join(writableParent.root, 'writable-runtime')
  const writableNginx = path.join(writableRuntime, 'nginx')
  mkdirSync(writableRuntime)
  executable(writableNginx, '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$FAKE_NGINX_BINARY_LOG"\nexit 0\n')
  chmodSync(writableRuntime, 0o777)
  const writableParentResult = writableParent.run({
    HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY: writableNginx,
    FAKE_NGINX_BINARY: writableNginx
  })
  t.not(writableParentResult.status, 0)
  t.ok(writableParentResult.stdout.includes('gateway nginx binary parent is group/world writable'))
  t.absent(existsSync(writableParent.preflightArgs), 'writable parent fails before either binary can execute')
  t.absent(existsSync(writableParent.nginxBinaryLog))
  t.absent(existsSync(writableParent.ssBinaryLog))

  for (const [property, envName, fakeName, label] of [
    ['nginxBinary', 'HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY', 'FAKE_NGINX_BINARY', 'nginx'],
    ['ssBinary', 'HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY', 'FAKE_SS_BINARY', 'ss']
  ]) {
    const linkedAncestor = fixture(t)
    const ancestor = path.join(linkedAncestor.root, `${label}-ancestor-link`)
    symlinkSync(linkedAncestor.root, ancestor)
    const lexicalPath = path.join(ancestor, path.basename(linkedAncestor[property]))
    const result = linkedAncestor.run({
      [envName]: lexicalPath,
      [fakeName]: lexicalPath
    })
    t.not(result.status, 0)
    t.ok(result.stdout.includes(`gateway ${label} binary path must be canonical and contain no symlink ancestors`))
    t.absent(existsSync(linkedAncestor.preflightArgs), `${label} ancestor link fails before preflight`)
    t.absent(existsSync(linkedAncestor.hostileExecutionLog), `${label} ancestor swap cannot execute hostile bytes`)
  }
})

test('updater detects nginx and ss replacement races before later use', (t) => {
  const nginx = fixture(t)
  const nginxResult = nginx.run({
    FAKE_PREFLIGHT_RUN_NGINX: '1',
    FAKE_PREFLIGHT_REPLACE_NGINX: '1'
  })
  t.not(nginxResult.status, 0)
  t.ok(nginxResult.stdout.includes('gateway nginx binary identity changed after its trusted snapshot'))
  t.ok(readFileSync(nginx.nginxBinaryLog, 'utf8').includes('-T'), 'only the snapshotted nginx executes')
  t.absent(existsSync(nginx.hostileExecutionLog), 'replacement nginx is never used for containment')
  t.absent(existsSync(nginx.quarantineArgs))

  const ss = fixture(t)
  const ssResult = ss.run({
    FAKE_OPS_RUN_SS: '1',
    FAKE_OPS_REPLACE_SS: '1'
  })
  t.not(ssResult.status, 0)
  t.ok(ssResult.stdout.includes('gateway ss binary identity changed after its trusted snapshot'))
  t.ok(readFileSync(ss.ssBinaryLog, 'utf8').includes('-H -lntup'), 'only the snapshotted ss executes')
  t.absent(existsSync(ss.hostileExecutionLog), 'replacement ss never executes')
  t.absent(existsSync(ss.opsVerifierArgs), 'ops evidence cannot be accepted after ss replacement')
})

test('updater lock fails closed for held, missing, unsafe, or symlinked lock authority', (t) => {
  const held = fixture(t)
  const heldResult = held.run({ FAKE_FLOCK_STATUS: '1' })
  t.is(heldResult.status, 0)
  t.ok(heldResult.stdout.includes('another run in progress'))
  t.absent(existsSync(held.controlResolverArgs))

  const missing = fixture(t)
  rmSync(path.join(missing.bin, 'flock'))
  const missingResult = missing.run({ PATH: missing.bin })
  t.not(missingResult.status, 0)
  t.absent(existsSync(missing.controlResolverArgs))

  for (const kind of ['symlink', 'writable']) {
    const f = fixture(t)
    const lockRoot = path.join(f.root, `locks-${kind}`)
    mkdirSync(lockRoot)
    const lock = path.join(lockRoot, `hiverelay-updater-${process.geteuid?.() ?? process.getuid()}`)
    if (kind === 'symlink') symlinkSync(f.repo, lock)
    else { mkdirSync(lock); chmodSync(lock, 0o777) }
    const result = f.run({ TMPDIR: lockRoot })
    t.not(result.status, 0)
    t.ok(result.stdout.includes('lock directory'))
    t.absent(existsSync(f.controlResolverArgs))
  }
})

test('missing or malformed relay identity stops before target resolution', (t) => {
  const f = fixture(t)
  writeFileSync(f.updaterConf, 'CHANNEL=stable\n')
  const missing = f.run()
  t.not(missing.status, 0)
  t.ok(missing.stdout.includes('RELAY_NAME is required'))
  t.absent(existsSync(f.gitLog))

  writeFileSync(f.updaterConf, 'CHANNEL=stable\nRELAY_NAME=bad relay\n')
  const malformed = f.run()
  t.not(malformed.status, 0)
  t.ok(malformed.stdout.includes('invalid RELAY_NAME'))
  t.absent(existsSync(f.gitLog))

  writeFileSync(f.updaterConf, 'RELAY_NAME=stable-1\n')
  const missingChannel = f.run()
  t.not(missingChannel.status, 0)
  t.ok(missingChannel.stdout.includes('CHANNEL is required'))
  t.absent(existsSync(f.gitLog))
})
