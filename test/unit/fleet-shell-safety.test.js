import test from 'brittle'
import { readFileSync } from 'node:fs'

const updater = readFileSync('fleet/updater.sh', 'utf8')
const fleetStatus = readFileSync('fleet/fleet-status.sh', 'utf8')
const deployVps = readFileSync('scripts/deploy-vps.sh', 'utf8')
const rolloutCheck = readFileSync('scripts/check-fleet-rollout.mjs', 'utf8')
const relayJanitor = readFileSync('scripts/relay-janitor.js', 'utf8')
const cli = readFileSync('packages/core/cli/index.js', 'utf8')

test('fleet scripts pass channel names into JSON parsing as data', (t) => {
  t.ok(updater.includes('CHANNEL="$CHANNEL" python3 -c'))
  t.ok(updater.includes('os.environ["CHANNEL"]'))
  t.ok(fleetStatus.includes('CHANNEL="$channel" python3 -c'))
  t.ok(fleetStatus.includes('os.environ["CHANNEL"]'))
  t.absent(fleetStatus.includes(".get('$channel'"))
  t.absent(fleetStatus.includes('python3 -c "import sys,json;print(json.load(sys.stdin).get('))
})

test('fleet updater routes dependency-install failures through rollback', (t) => {
  t.ok(updater.includes('rollback_to_previous'))
  t.ok(updater.includes('deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous'))
  t.ok(updater.includes('if ! git checkout --quiet "$CUR_SHA"; then'))
  t.ok(updater.includes('CRITICAL could not checkout previous SHA'))
  t.ok(updater.includes('if ! deps_if_changed "$TARGET_SHA" "$CUR_SHA"; then'))
  t.absent(updater.includes('git checkout --quiet "$CUR_SHA" || log "CRITICAL could not checkout previous SHA"'))
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

test('deploy script keeps API keys out of world-readable systemd units', (t) => {
  t.ok(deployVps.includes('validate_api_key "$EFFECTIVE_KEY"'))
  t.ok(deployVps.includes("API_KEY_B64='" + '$' + "{API_KEY_B64}'"))
  t.ok(deployVps.includes('base64 -d'))
  t.ok(deployVps.includes('EnvironmentFile=/etc/hiverelay/hiverelay.env'))
  t.ok(deployVps.includes('chmod 0600 /etc/hiverelay/hiverelay.env'))
  t.absent(deployVps.includes('Environment=HIVERELAY_API_KEY=API_KEY_PLACEHOLDER'))
  t.absent(deployVps.includes('sed -i "s/API_KEY_PLACEHOLDER'))
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
