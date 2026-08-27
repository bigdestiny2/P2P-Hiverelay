import test from 'brittle'
import { readFileSync } from 'node:fs'

const updater = readFileSync('fleet/updater.sh', 'utf8')
const updaterLauncher = readFileSync('fleet/updater-launcher.sh', 'utf8')
const updaterInstaller = readFileSync('fleet/install-updater.sh', 'utf8')
const updaterService = readFileSync('fleet/hiverelay-updater.service', 'utf8')
const gatewayQuarantine = readFileSync('fleet/quarantine-public-gateway.sh', 'utf8')
const fleetStatus = readFileSync('fleet/fleet-status.sh', 'utf8')
const deployVps = readFileSync('scripts/deploy-vps.sh', 'utf8')
const rolloutCheck = readFileSync('scripts/check-fleet-rollout.mjs', 'utf8')
const relayJanitor = readFileSync('scripts/relay-janitor.js', 'utf8')
const cli = readFileSync('packages/core/cli/index.js', 'utf8')

test('fleet updater installation executes only an exact signed-checkout updater', (t) => {
  const blobGate = 'fleet/updater.sh differs from the signed checkout'
  const tagGate = 'is not an allowed-signer-verified release tag'
  const execUpdater = 'exec /bin/bash --noprofile --norc "$UPDATER" "$@"'

  t.ok(updaterInstaller.includes('install -m 0755 "$SRC/updater-launcher.sh" "$BIN_DIR/hiverelay-updater"'))
  t.absent(updaterInstaller.includes('install -m 0755 "$SRC/updater.sh"'),
    'the mutable installed copy is gone')
  t.ok(updaterLauncher.includes("rev-parse --verify 'HEAD:fleet/updater.sh'"))
  t.ok(updaterLauncher.includes('hash-object --no-filters "$UPDATER"'))
  t.ok(updaterLauncher.includes('verify-tag --raw "$tag"'))
  t.ok(updaterLauncher.includes('gpg.ssh.program=/usr/bin/ssh-keygen'))
  t.ok(updaterLauncher.includes(blobGate))
  t.ok(updaterLauncher.includes(tagGate))
  t.ok(updaterLauncher.indexOf(blobGate) < updaterLauncher.indexOf(execUpdater))
  t.ok(updaterLauncher.indexOf(tagGate) < updaterLauncher.indexOf(execUpdater))
  t.absent(updaterLauncher.includes('source "$CONF"'))
  t.absent(updaterLauncher.includes('. "$CONF"'))
})

test('fleet updater service requires the preserved root-only runtime environment', (t) => {
  t.ok(updaterService.includes('ExecStart=/usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --noprofile --norc /usr/local/bin/hiverelay-updater'))
  t.absent(updaterService.includes('EnvironmentFile='),
    'systemd never imports unchecked updater data into the root process environment')
  t.ok(updaterInstaller.includes('ENV_FILE="$ENV_DIR/hiverelay-updater.env"'))
  t.ok(updaterInstaller.includes('chmod 0600 "$ENV_TMP"'))
  t.ok(updaterService.includes('StateDirectory=hiverelay-updater'))
  t.ok(updaterService.includes('StateDirectoryMode=0700'))
  t.ok(updaterInstaller.includes('quarantined unsafe updater environment path'))
  t.ok(updaterInstaller.includes("printf 'CHANNEL=%s\\nRELAY_NAME=%s\\nREPO_DIR=%s\\n'"))
  t.ok(updaterInstaller.includes('install -m 0755 "$SRC/quarantine-public-gateway.sh"'))
  t.absent(updaterInstaller.includes('printf \'HIVERELAY_PUBLIC_GATEWAY_'),
    'installer never regenerates operator gateway settings')
})

test('fleet updater accepts channel authority only from signed monotonic Git control', (t) => {
  t.ok(updater.includes('scripts/resolve-signed-fleet-channel.mjs'))
  t.ok(updater.includes('--channel "$CHANNEL"'))
  t.ok(updater.includes('--state "$CONTROL_STATE"'))
  t.ok(updater.includes('--installed-head "$CUR_SHA"'))
  t.absent(updater.includes('HIVERELAY_CHANNELS_URL'))
  t.absent(updater.includes('raw.githubusercontent.com'))
  t.absent(updater.includes('cannot fetch channels.json'))
  t.ok(fleetStatus.includes('CHANNEL="$channel" python3 -c'))
  t.ok(fleetStatus.includes('os.environ["CHANNEL"]'))
  t.absent(fleetStatus.includes(".get('$channel'"))
  t.absent(fleetStatus.includes('python3 -c "import sys,json;print(json.load(sys.stdin).get('))
})

test('fleet updater routes dependency-install failures through rollback', (t) => {
  const scopedInstall = [
    'npm ci --omit=dev --no-audit --no-fund',
    '--include-workspace-root',
    '--workspace packages/core',
    '--workspace packages/services',
    '--workspace packages/client',
    '--workspace packages/verifier'
  ]

  t.ok(updater.includes('rollback_to_previous'))
  t.ok(updater.includes('deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous'))
  t.ok(updater.includes('if ! git checkout --quiet --force "$CUR_SHA"; then'))
  t.ok(updater.includes('CRITICAL could not checkout previous SHA'))
  t.ok(updater.includes('if ! deps_if_changed "$TARGET_SHA" "$CUR_SHA"; then'))
  for (const argument of scopedInstall) t.ok(updater.includes(argument))
  t.absent(updater.includes('--workspace packages/blind-'))
  t.absent(updater.includes('npm install --omit=dev'), 'npm ci failure cannot fall back to a non-lockfile install')
  t.ok(updater.includes('verify_raw_tracked_tree || rollback_to_previous "dependency install changed tracked release bytes on $TARGET"'))
  t.ok(updater.includes('if ! verify_raw_tracked_tree; then'))
  t.ok(updater.includes('git checkout --quiet --force "$CUR_SHA" || die "target checkout failed and prior SHA restoration also failed"'))
  t.absent(updater.includes('git checkout --quiet "$CUR_SHA" || log "CRITICAL could not checkout previous SHA"'))
})

test('fleet updater and direct deploy fail closed below Node.js 20', (t) => {
  const updaterGate = updater.indexOf('require_supported_node')
  const controlResolution = updater.indexOf('CONTROL_RESOLUTION=')
  const deployGate = deployVps.indexOf('Node.js >=20 is required before deployment')
  const deployFetch = deployVps.indexOf('git fetch --force origin')

  t.ok(updater.includes('Node.js >=20 is required; found $version'))
  t.ok(updaterGate !== -1 && updaterGate < controlResolution)
  t.ok(deployVps.includes('NODE_VERSION="\\$(/usr/bin/node --version 2>/dev/null)"'))
  t.ok(deployGate !== -1 && deployGate < deployFetch)
})

test('direct deploy accepts only an explicit active relay and exact signed release', (t) => {
  for (const argument of [
    'npm ci --omit=dev --no-audit --no-fund',
    '--include-workspace-root',
    '--workspace packages/core',
    '--workspace packages/services',
    '--workspace packages/client',
    '--workspace packages/verifier'
  ]) t.ok(deployVps.includes(argument))

  t.ok(deployVps.includes('HIVERELAY_RELEASE_TARGET:?Set HIVERELAY_RELEASE_TARGET to an exact signed release tag'))
  t.ok(deployVps.includes('gpg.ssh.allowedSignersFile=/etc/hiverelay/allowed-signers'))
  t.ok(deployVps.includes('gpg.ssh.program=/usr/bin/ssh-keygen'))
  t.ok(deployVps.includes('core.hooksPath=/dev/null'))
  t.ok(deployVps.includes('verify-tag --raw "' + '$' + '{RELEASE_TARGET}"'))
  t.ok(deployVps.includes('checkout --detach --force "' + '$' + '{RELEASE_TARGET}^{commit}"'))
  t.ok(deployVps.includes('git status --porcelain=v1 --untracked-files=all'))
  t.ok(deployVps.includes('exit 1\n        fi\n\n        echo "Deployment complete'))
  t.absent(deployVps.includes('git fetch origin main'))
  t.absent(deployVps.includes('git reset --hard origin/main'))
  t.absent(deployVps.includes('npm install --production'))
  t.absent(deployVps.includes('git push origin main'))
  t.absent(deployVps.includes('TARGET=' + '$' + '{1:-all}'))
  t.absent(deployVps.includes('    all)'))
  t.absent(deployVps.includes('144.172.101.215'), 'retired relay is not a deploy target')
  t.absent(deployVps.includes('45.59.123.112'), 'held relay is not a deploy target')
})

test('fleet updater health-gates target and rollback runtime versions', (t) => {
  const expectedVersionArg = 'expected_version="' + '$' + '{1:-}"'
  const targetHealthGate = 'if healthy "' + '$' + '{TARGET#v}"; then'
  const rollbackHealthGate = 'if healthy "' + '$' + '{CUR_VER#v}"; then'

  t.ok(updater.includes(expectedVersionArg))
  t.ok(updater.includes('"version"[[:space:]]*:[[:space:]]*"'))
  t.ok(updater.includes('[ "$version" = "$expected_version" ]'))
  t.ok(updater.includes(targetHealthGate))
  t.ok(updater.includes(rollbackHealthGate))
  t.absent(updater.includes('if healthy; then'))
})

test('signed manifest cohort forces exact preflight and evidence bindings', (t) => {
  const dollar = '$'
  const probeInvocation = 'HIVERELAY_API_KEY="$key" timeout "$PUBLIC_GATEWAY_PROBE_TIMEOUT" "' + dollar + '{probe_args[@]}"'
  const verifyIndex = updater.indexOf('verify_tag "$TARGET"')
  const manifestIndex = updater.indexOf('resolve_public_gateway_contract', verifyIndex)

  t.ok(updater.includes('RELAY_NAME is required in $CONF'))
  t.ok(updater.includes('PUBLIC_GATEWAY_REQUIRED=0'))
  t.ok(updater.includes('git ls-tree --name-only "$TARGET_SHA" -- "$PUBLIC_GATEWAY_MANIFEST_PATH"'))
  t.ok(updater.includes('git show "$TARGET_SHA:$PUBLIC_GATEWAY_MANIFEST_PATH"'))
  t.ok(updater.includes('scripts/resolve-public-hive-gateway-node.mjs'))
  t.ok(verifyIndex !== -1 && manifestIndex > verifyIndex,
    'target trust is established before signed policy is interpreted')
  t.ok(updater.includes('[ "$PUBLIC_GATEWAY_REQUIRED" = 1 ] || return 0'))
  t.ok(updater.includes('scripts/preflight-public-hive-gateway.mjs'))
  t.ok(updater.includes('scripts/verify-public-hive-gateway-evidence.mjs'))
  t.ok(updater.includes('PUBLIC_GATEWAY_DEPLOYMENT_PROFILE="legacy"'))
  t.ok(updater.includes('PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256="-"'))
  t.ok(updater.includes('public-t1-gateway)'))
  t.ok(updater.includes('PUBLIC_GATEWAY_OPS_REQUIRED=1'))
  t.ok(updater.includes('--require-public-t1'))
  t.ok(updater.includes('enabled public gateway updater cohort must use public-t1-gateway'))
  t.ok(updater.includes('scripts/preflight-public-hive-gateway-ops.mjs'))
  t.ok(updater.includes('scripts/verify-public-hive-gateway-ops-evidence.mjs'))
  t.ok(updater.includes('[[ "$PUBLIC_GATEWAY_PROBE_EVIDENCE" != /* ]]'))
  t.ok(updater.includes('[ "$PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY" != "0" ]'))
  t.ok(updater.includes('--mode fleet'))
  t.ok(updater.includes('--probe-origin "$PUBLIC_GATEWAY_EXPECTED_ORIGIN"'))
  t.ok(updater.includes('--connect-address "$PUBLIC_GATEWAY_EXPECTED_CONNECT_ADDRESS"'))
  t.ok(updater.includes('--app-key "$PUBLIC_GATEWAY_EXPECTED_APP_KEY"'))
  t.ok(updater.includes('--path "$PUBLIC_GATEWAY_EXPECTED_PATH"'))
  t.ok(updater.includes('--nginx-config "$PUBLIC_GATEWAY_PROBE_NGINX_CONFIG"'))
  t.ok(updater.includes('--nginx-binary "$PUBLIC_GATEWAY_PROBE_NGINX_BINARY"'))
  t.ok(updater.includes('--expected-sha256 "$PUBLIC_GATEWAY_EXPECTED_SHA256"'))
  t.ok(updater.includes('--evidence "$PUBLIC_GATEWAY_PROBE_EVIDENCE"'))
  t.ok(updater.includes('[ "$PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY" != "1" ] || probe_args+=(--public-suffix-ready)'))
  t.ok(updater.includes('--release-target "$TARGET"'))
  t.ok(updater.includes('--release-sha "$TARGET_SHA"'))
  t.ok(updater.includes('--require-admission-profile "$PUBLIC_GATEWAY_ADMISSION_PROFILE"'))
  t.ok(updater.includes('--expected-drive-version "$PUBLIC_GATEWAY_EXPECTED_DRIVE_VERSION"'))
  t.ok(updater.includes('--expected-peer-fingerprint256 "$PUBLIC_GATEWAY_EXPECTED_PEER_FINGERPRINT256"'))
  t.ok(updater.includes('--expected-nginx-sha256 "$PUBLIC_GATEWAY_EXPECTED_NGINX_SHA256"'))
  t.ok(updater.includes('--release-manifest "$release_manifest"'))
  t.ok(updater.includes('--expected-contract-sha256 "$PUBLIC_GATEWAY_OPERATOR_CONTRACT_SHA256"'))
  t.ok(updater.includes('--dns-live'))
  t.ok(updater.includes('--ss-binary "$PUBLIC_GATEWAY_OPS_SS_BINARY"'))
  t.ok(updater.includes(probeInvocation))
  t.absent(updater.includes('env HIVERELAY_API_KEY='), 'API key is not exposed in child argv')
  for (const retired of [
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_ORIGIN',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_CONNECT_ADDRESS',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_APP_KEY',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_PATH',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_SHA256',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_MODE'
  ]) t.absent(updater.includes(retired), `${retired} cannot weaken or redirect signed policy`)
})

test('fleet updater contains both same-release and failed public-t1 transition edges', (t) => {
  const targetHealthGate = 'if healthy "' + '$' + '{TARGET#v}"; then'
  const gatewayGate = 'public_gateway_healthy || rollback_to_previous "public HTTPS gateway probe failed on ' + '$' + 'TARGET"'
  const successLog = 'log "OK updated ' + '$' + 'CUR_VER -> ' + '$' + 'TARGET — health green"'
  const rollbackHealthGate = 'if healthy "' + '$' + '{CUR_VER#v}"; then'
  const noOpBranch = 'if [ "$UP_TO_DATE" = 1 ]; then'
  const containCall = 'if contain_up_to_date_gateway_failure; then'

  const noOpIndex = updater.lastIndexOf(noOpBranch)
  const noOpProbeIndex = updater.indexOf('if ! public_gateway_healthy; then', noOpIndex)
  const containmentIndex = updater.indexOf(containCall, noOpIndex)
  const targetHealthIndex = updater.indexOf(targetHealthGate)
  const gatewayGateIndex = updater.indexOf(gatewayGate)
  const successIndex = updater.indexOf(successLog)
  const rollbackFunctionIndex = updater.indexOf('rollback_to_previous()')
  const rollbackHealthIndex = updater.indexOf(rollbackHealthGate, rollbackFunctionIndex)
  const updateSectionIndex = updater.indexOf('# ── update')

  t.ok(noOpIndex > rollbackFunctionIndex, 'same-release decision runs after the probe helper exists')
  t.ok(noOpProbeIndex > noOpIndex && noOpProbeIndex < updateSectionIndex,
    'same-release tick refreshes gateway evidence before exiting')
  t.ok(containmentIndex > noOpProbeIndex && containmentIndex < updateSectionIndex,
    'same-release probe failure enters narrow containment')
  t.absent(updater.slice(noOpIndex, updateSectionIndex).includes('rollback_to_previous'),
    'same-release probe failure cannot enter rollback')
  t.absent(updater.slice(noOpIndex, updateSectionIndex).includes('systemctl'),
    'same-release containment does not stop or restart management service')
  t.ok(updater.includes('hiverelay-public-gateway-evidence-invalid-v1'))
  t.ok(updater.includes('hiverelay-public-gateway-operator-readiness-invalid-v1'))
  t.ok(updater.indexOf('invalidate_public_gateway_evidence ||') < updater.indexOf('quarantine_public_gateway_edge ||'))
  t.ok(updater.indexOf('invalidate_public_gateway_evidence ||') <
    updater.indexOf('invalidate_public_gateway_ops_evidence ||'))
  t.ok(updater.indexOf('invalidate_public_gateway_ops_evidence ||') <
    updater.indexOf('quarantine_public_gateway_edge ||'))
  t.ok(updater.includes('management API left running'))
  t.absent(gatewayQuarantine.includes('systemctl'))
  t.absent(gatewayQuarantine.includes('sudo'))
  t.ok(gatewayQuarantine.includes('return 421;'))
  t.ok(gatewayQuarantine.includes('"$NGINX_BINARY" "$@"'))
  t.ok(gatewayQuarantine.includes('run_trusted_nginx -t'))
  t.ok(gatewayQuarantine.includes('run_trusted_nginx -s reload'))
  t.ok(targetHealthIndex > updateSectionIndex, 'target health gate is in the update path')
  t.ok(gatewayGateIndex > targetHealthIndex, 'gateway probe follows target API health')
  t.ok(successIndex > gatewayGateIndex, 'success is declared only after the gateway probe')
  t.ok(rollbackHealthIndex > rollbackFunctionIndex && rollbackHealthIndex < updateSectionIndex,
    'rollback retains its independent API-only health gate')
  t.absent(updater.slice(rollbackFunctionIndex, noOpIndex).includes('public_gateway_healthy'),
    'rollback function never invokes the public gateway probe')
  t.ok(updater.slice(rollbackFunctionIndex, noOpIndex).includes('contain_up_to_date_gateway_failure'),
    'failed public-t1 transitions contain the public edge before code rollback')
  t.ok(updater.includes('public edge remains quarantined pending refreshed previous-release manifest/config/nginx/DNS/TLS/SPKI/socket/content evidence'))
})

test('deploy script keeps API keys out of world-readable systemd units', (t) => {
  t.ok(deployVps.includes('validate_api_key "$EFFECTIVE_KEY"'))
  t.ok(deployVps.includes("API_KEY_B64='" + '$' + "{API_KEY_B64}'"))
  t.ok(deployVps.includes('base64 -d'))
  t.ok(deployVps.includes('EnvironmentFile=/etc/hiverelay/hiverelay.env'))
  t.ok(deployVps.includes('chmod 0600 /etc/hiverelay/hiverelay.env'))
  t.absent(deployVps.includes('Environment=HIVERELAY_API_KEY=API_KEY_PLACEHOLDER'))
  t.absent(deployVps.includes('sed -i "s/API_KEY_PLACEHOLDER'))
  t.ok(deployVps.includes('HIVERELAY_FLEET_KNOWN_HOSTS'))
  t.ok(deployVps.includes('StrictHostKeyChecking=yes'))
  t.ok(deployVps.includes('UpdateHostKeys=no'))
  t.ok(deployVps.includes('UserKnownHostsFile="$KNOWN_HOSTS"'))
  t.ok(deployVps.includes('GlobalKnownHostsFile=/dev/null'))
  t.absent(deployVps.includes('accept-new'))
})

test('deploy script computes MemoryHigh correctly for gigabyte relay limits', (t) => {
  t.ok(deployVps.includes('MEMORY_HIGH="$(memory_high_limit "$MAX_MEM")"'))
  t.ok(deployVps.includes('memory_high_limit()'))
  t.ok(deployVps.includes('NUM * 1024 * 80 / 100'))
  t.ok(deployVps.includes('sed -i "s/MEMHIGH_PLACEHOLDER/' + '$' + '{MEMORY_HIGH}/"'))
  t.absent(deployVps.includes('MEM_HIGH=$(( MEM_NUM * 80 / 100 ))'))
})

test('fleet health tooling discovers API keys from root-only env files', (t) => {
  for (const source of [updater, fleetStatus, rolloutCheck, relayJanitor]) {
    t.ok(source.includes('/etc/hiverelay/hiverelay.env'))
    t.ok(source.includes('awk -F='))
    t.absent(source.includes("grep -o 'HIVERELAY_API_KEY=[^ ]*'"))
    t.absent(source.includes("grep -oE 'HIVERELAY_API_KEY=[A-Za-z0-9._-]+'"))
  }
  t.ok(updater.includes('ENV_FILE='))
  t.ok(fleetStatus.includes('read_api_key()'))
  t.ok(rolloutCheck.includes('env_file='))
  t.ok(relayJanitor.includes('root-only env file first'))
})

test('relay janitor keeps remote API keys out of local ssh argv', (t) => {
  t.ok(relayJanitor.includes('remoteHasApiKey'))
  t.ok(relayJanitor.includes('remoteUnseed'))
  t.ok(relayJanitor.includes("spawn('ssh', [...sshBase, 'bash', '-s', '--', ...args]"))
  t.ok(relayJanitor.includes('Never print or return it'))
  t.ok(relayJanitor.includes('-H "@$header_file"'))
  t.absent(relayJanitor.includes('const key = await readApiKey'))
  t.absent(relayJanitor.includes('authorization: Bearer ' + '$' + '{key}'))
  t.absent(relayJanitor.includes("printf '%s\\n' \"$key\""))
})

test('fleet health probes keep relay API keys out of curl argv', (t) => {
  for (const source of [updater, fleetStatus, rolloutCheck]) {
    t.ok(source.includes('curl_with_optional_key()'))
    t.ok(source.includes('header_file="$(mktemp)"'))
    t.ok(source.includes('chmod 600 "$header_file"'))
    t.ok(source.includes('curl -H "@$header_file" "$@"'))
    t.absent(source.includes('-H "Authorization: Bearer $key"'))
    t.absent(source.includes('-H "Authorization: Bearer $K"'))
  }
  t.ok(relayJanitor.includes('header_file="$(mktemp)"'))
  t.ok(relayJanitor.includes('chmod 600 "$header_file"'))
  t.ok(relayJanitor.includes("printf 'authorization: Bearer %s\\n' \"$key\""))
  t.ok(relayJanitor.includes('-H "@$header_file"'))
  t.absent(relayJanitor.includes('-H "authorization: Bearer $key"'))
})

test('fleet status sanitizes terminal output and validates inventory before ssh', (t) => {
  t.ok(fleetStatus.includes('clean_field()'))
  t.ok(fleetStatus.includes("tr -c '[:print:]' '?'"))
  t.ok(fleetStatus.includes("tr '|' '?'"))
  t.ok(fleetStatus.includes('valid_host()'))
  t.ok(fleetStatus.includes('valid_channel()'))
  t.ok(fleetStatus.includes('valid_key_path()'))
  t.ok(fleetStatus.includes('BADHOST'))
  t.ok(fleetStatus.includes('BADCHAN'))
  t.ok(fleetStatus.includes('BADKEY'))
  t.ok(fleetStatus.includes('safe_name="$(clean_field "$name")"'))
  t.ok(fleetStatus.includes('safe_target="$(clean_field "$target")"'))
  t.ok(fleetStatus.includes('out="$(printf \'%s\\n\' "$out" | tail -n 1)"'))
  t.absent(fleetStatus.includes('"$name" UNREACH'))
  t.absent(fleetStatus.includes(
    '"$' + '{ver:-?}" "$' + '{run:-?}" "$' + '{apps:-?}" "$' + '{conns:-?}" "$' + '{disk:-?}" "$target"'
  ))
})

test('relay CLI keeps high-frequency status output off service logs', (t) => {
  t.ok(cli.includes('const interactiveStatus = process.stdout.isTTY === true'))
  t.ok(cli.includes('const statusIntervalMs = interactiveStatus ? 5000 : 60000'))
  t.ok(cli.includes('if (interactiveStatus)'))
  t.ok(cli.includes("log.info(status, 'relay status')"))
  t.ok(cli.includes('function statusSnapshot (node)'))
  t.ok(cli.includes('stats.served ? stats.served.totalBytesServed'))
  t.absent(cli.includes('if (!args.quiet) {\n    statusInterval = setInterval(() =>'))
})
