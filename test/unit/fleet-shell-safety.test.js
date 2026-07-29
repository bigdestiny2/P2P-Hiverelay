import test from 'brittle'
import { readFileSync } from 'node:fs'

const updater = readFileSync('fleet/updater.sh', 'utf8')
const watchdog = readFileSync('fleet/health-watchdog.sh', 'utf8')
const fleetStatus = readFileSync('fleet/fleet-status.sh', 'utf8')
const deployVps = readFileSync('scripts/deploy-vps.sh', 'utf8')
const rolloutCheck = readFileSync('scripts/check-fleet-rollout.mjs', 'utf8')
const fleetServiceProbe = readFileSync('scripts/probe-fleet-services.mjs', 'utf8')
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

test('fleet updater supports an exact signed-tag pin without changing shared channels', (t) => {
  t.ok(updater.includes('PINNED_TAG=""'))
  t.ok(updater.includes('PINNED_TAG[[:space:]]*=[[:space:]]*'))
  t.ok(updater.includes("invalid pinned tag '$PINNED_TAG' in $CONF"))
  t.ok(updater.includes('TARGET="$PINNED_TAG"'))
  t.ok(updater.includes('pinned=$PINNED_TAG'))
  t.ok(updater.indexOf('verify_tag "$TARGET"') > updater.indexOf('TARGET="$PINNED_TAG"'),
    'a pinned tag still crosses the signed-tag gate')
  t.absent(updater.includes('source "$CONF"'))
  t.ok(fleetStatus.includes('PINNED_TAG[[:space:]]*='))
  t.ok(fleetStatus.includes('C="$C@$P"'))
})

test('fleet updater routes dependency-install failures through rollback', (t) => {
  t.ok(updater.includes('rollback_to_previous'))
  t.ok(updater.includes('deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous'))
  // --force is required, and this assertion previously locked in its absence.
  // npm ci rewrites package-lock.json, so by the time a dependency install has
  // failed the tree is dirty and a plain checkout refuses — stranding the box on
  // the NEW tree with a half-built node_modules, which is the opposite of a
  // rollback. Observed on utah 2026-07-28: "CRITICAL could not checkout previous
  // SHA". Safe because the pre-update dirty-tree guard already refused to start
  // on a dirty tree, so anything dirty at rollback time was created by that run.
  t.ok(updater.includes('if ! git checkout --quiet --force "$CUR_SHA"; then'))
  t.absent(updater.includes('if ! git checkout --quiet "$CUR_SHA"; then'),
    'a rollback checkout without --force cannot survive npm ci dirtying the lockfile')
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

test('fleet status preserves prerelease versions and reads counters from status', (t) => {
  t.ok(fleetStatus.includes('require(process.env.HOME + "/hiverelay/package.json").version'))
  t.absent(fleetStatus.includes('tr -dc \'0-9.\''))
  t.ok(fleetStatus.includes('http://127.0.0.1:9100/status'))
  t.ok(fleetStatus.includes('HEALTH="$H" STATUS="$S" python3 -c'))
  t.ok(fleetStatus.includes('s.get("seededApps","?")'))
  t.ok(fleetStatus.includes('s.get("connections","?")'))
  t.ok(fleetStatus.includes('systemctl is-enabled hiverelay-updater.timer'))
  t.ok(fleetStatus.includes('systemctl is-active hiverelay-updater.timer'))
  t.ok(fleetStatus.includes('/etc/hiverelay-updater.conf'))
  t.ok(fleetStatus.includes('UPDATER CONFIGURED ASSIGNED'))
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
  t.ok(fleetStatus.includes('valid_name_list()'))
  t.ok(fleetStatus.includes('HIVERELAY_FLEET_INCLUDE'))
  t.ok(fleetStatus.includes('HIVERELAY_FLEET_EXCLUDE'))
  t.ok(fleetStatus.includes('INCLUDE="$INCLUDE" EXCLUDE="$EXCLUDE" python3 -c'))
  t.ok(fleetStatus.includes('if include and r["name"] not in include:'))
  t.ok(fleetStatus.includes('if r["name"] in exclude:'))
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

test('fleet service probe scopes relay ownership before opening connections', (t) => {
  t.ok(fleetServiceProbe.includes("optionValue('--include')"))
  t.ok(fleetServiceProbe.includes("optionValue('--exclude')"))
  t.ok(fleetServiceProbe.includes('HIVERELAY_FLEET_INCLUDE'))
  t.ok(fleetServiceProbe.includes('HIVERELAY_FLEET_EXCLUDE'))
  t.ok(fleetServiceProbe.indexOf('const relays = inventoryRelays.filter') < fleetServiceProbe.indexOf('Promise.all(relays.map(probe))'))
  t.ok(fleetServiceProbe.includes('if (!knownNames.has(name)) throw new Error'))
  t.ok(fleetServiceProbe.includes("throw new Error('relay scope selected no inventory entries')"))
  t.ok(fleetServiceProbe.includes('base.error = safeProbeError(err)'))
  t.ok(fleetServiceProbe.includes("return 'probe failed'"))
  t.absent(fleetServiceProbe.includes('err?.message?.slice'))
  t.ok(fleetServiceProbe.includes("inventoryLabel = inv === join(REPO, 'fleet', 'relays.json') ? 'fleet/relays.json' : 'operator inventory'"))
  t.ok(fleetServiceProbe.includes('/.well-known/hiverelay.json'))
  t.ok(fleetServiceProbe.includes("notifyWatchSources.includes('notify-outbox-lane')"))
  t.ok(fleetServiceProbe.includes('notifyProfile?.egress?.live === true'))
  t.ok(fleetServiceProbe.includes("features.includes('notify-v1')"))
  t.ok(fleetServiceProbe.includes('unsafe legacy wake advertisements:'))
  t.ok(fleetServiceProbe.includes('signed exact-lane wake:'))
  t.ok(fleetServiceProbe.includes('advertised outbox mailbox:'))
  t.ok(fleetServiceProbe.includes("privacyTransports.find(entry => entry?.network === 'tor')"))
  t.ok(fleetServiceProbe.includes('restricted Tor endpoints with negative proof:'))
  t.ok(fleetServiceProbe.includes('advertised one-hop forward relays:'))
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

test('fleet updater proves the runtime boots before restarting the live service', (t) => {
  // npm ci succeeding does not mean the relay can start. utah-0.5gb installed
  // cleanly on 2026-07-28 and then crash-looped: require-addon resolved the
  // package root to "/" and looked for /prebuilds/linux-x64/sodium-native.node
  // while the binary sat correct inside node_modules. The cause was a
  // memory-starved install on a 458MB box leaving node_modules partial — not a
  // Node incompatibility: three other relays run the identical v22.22.2 and
  // pass. A version pin would have caught nothing; only executing the runtime
  // does, which is why the gate is a require rather than a version comparison.
  t.ok(updater.includes('preflight_runtime'), 'preflight helper exists')
  t.ok(updater.includes('require("hyperswarm")'),
    'loads the chain that actually broke: hyperswarm -> hyperdht -> dht-rpc -> udx-native -> require-addon -> sodium-native')

  // Ordering is the whole point: prove the runtime AFTER deps are installed and
  // BEFORE the service is restarted, so a bad install rolls back instead of
  // leaving a crash-looping relay.
  const preflightAt = updater.indexOf('preflight_runtime || rollback_to_previous')
  const depsAt = updater.indexOf('deps_if_changed "$CUR_SHA" "$TARGET_SHA"')
  // `systemctl restart` appears twice — the first is inside
  // rollback_to_previous(), which is defined above the update path. Search from
  // the preflight so this compares against the UPDATE path's restart.
  const restartAt = updater.indexOf('systemctl restart "$SERVICE"', preflightAt)
  t.ok(preflightAt > depsAt, 'preflight runs after the dependency install')
  t.ok(restartAt > preflightAt, 'preflight runs before the service restart')
})

test('fleet updater refreshes its own agent so update-path fixes can reach a box', (t) => {
  // The agent runs from /usr/local/bin and nothing reinstalled it, so a bug in
  // the update path could only ever be fixed by hand-visiting every relay. That
  // is why rc.6's --force rollback fix reached no box at all.
  t.ok(updater.includes('SELF_PATH'), 'knows where it is installed')
  t.ok(updater.includes('agent self-updated'), 'reports the refresh')

  // Atomic install: write beside the target, syntax-check, then rename. A crash
  // mid-copy must not leave a partial interpreter script at a path systemd runs.
  t.ok(updater.includes('bash -n "$SELF_PATH.next"'), 'syntax-checks before adopting')
  t.ok(updater.includes('mv -f "$SELF_PATH.next" "$SELF_PATH"'), 'adopts by rename, not in-place write')

  // Must come after the signature gate — never install an agent from an
  // unverified tree — and after a deps install that has proven itself.
  t.ok(updater.indexOf('verify_tag "$TARGET"') < updater.indexOf('SELF_PATH.next'),
    'self-update happens only after the supply-chain gate has passed')
})

test('health watchdog does not kill a relay that is answering honestly', (t) => {
  // This watchdog exists for event-loop hangs that systemd cannot see. A
  // structured reply proves the loop is turning. `curl -f` discarded the body on
  // non-2xx, so a deliberate 503 drain was indistinguishable from a hang — and
  // since a restart frees no disk, the box looped SIGKILL every ~4 minutes.
  t.absent(watchdog.includes('curl -fsS --max-time "$TIMEOUT" "$URL"'),
    '-f discards the body that distinguishes a drain from a hang')
  t.ok(watchdog.includes('curl -sS --max-time "$TIMEOUT" "$URL"'))
  t.ok(watchdog.includes('"reason"[[:space:]]*:'), 'stands down on any reasoned reply')
  t.ok(watchdog.includes('not a hang; not restarting'))
})
