import fs from 'node:fs'
import path from 'node:path'
import test from 'brittle'

const root = path.resolve(import.meta.dirname, '../..')

function read (file) {
  return fs.readFileSync(path.join(root, file), 'utf8')
}

function json (file) {
  return JSON.parse(read(file))
}

function exactKeys (object) {
  return Object.keys(object).sort()
}

function occurrences (value, fragment) {
  return value.split(fragment).length - 1
}

test('replacement root has no direct legacy runtime escape hatch', t => {
  const rootPackage = json('package.json')
  t.is(rootPackage.scripts.start, 'node scripts/start-blind-local.mjs')
  t.absent(Object.prototype.hasOwnProperty.call(rootPackage.scripts, 'start:legacy'))
  t.absent(Object.values(rootPackage.scripts).some(command =>
    command.includes('packages/core/cli/index.js start')))
})

test('blind production images have independent current install-links closures', t => {
  const daemonPackage = json('packages/blind-daemon/package.json')
  const edgeManifest = json('deploy/blind/edge/package.json')
  const daemonManifest = json('deploy/blind/daemon/package.json')
  const edge = json('deploy/blind/edge/package-lock.json')
  const daemon = json('deploy/blind/daemon/package-lock.json')
  const edgePackages = Object.keys(edge.packages)
  const daemonPackages = Object.keys(daemon.packages)

  t.alike(daemonPackage.files, ['*.js'])
  t.is(daemonPackage.dependencies['sodium-universal'], '^4.0.0')

  t.alike(exactKeys(edgeManifest.dependencies), [
    '@hiverelay/blind-edge',
    '@hiverelay/blind-ipc',
    '@hiverelay/blind-peercred',
    '@hiverelay/blind-protocol'
  ])
  t.alike(exactKeys(daemonManifest.dependencies), [
    '@hiverelay/blind-daemon',
    '@hiverelay/blind-ipc',
    '@hiverelay/blind-peercred',
    '@hiverelay/blind-protocol'
  ])
  t.absent(edgePackages.some(name => name.includes('blind-daemon')))
  t.absent(daemonPackages.some(name => name.includes('blind-edge')))
  t.ok(edgePackages.some(name => name.includes('blind-edge')))
  t.ok(daemonPackages.some(name => name.includes('blind-daemon')))
  t.ok(edgePackages.some(name => name.includes('blind-peercred')))
  t.ok(daemonPackages.some(name => name.includes('blind-peercred')))
  t.is(edge.packages['node_modules/@hiverelay/blind-edge'].dependencies['@hiverelay/blind-peercred'], '0.0.0-draft.1')
  t.is(edge.packages['node_modules/@hiverelay/blind-ipc'].dependencies['compact-encoding'], '^2.15.0')
  t.is(daemon.packages['node_modules/@hiverelay/blind-ipc'].dependencies['compact-encoding'], '^2.15.0')
  t.is(daemon.packages['node_modules/@hiverelay/blind-daemon'].dependencies['sodium-universal'], '^4.0.0')
  for (const packages of [edgePackages, daemonPackages]) {
    t.absent(packages.some(name => /(?:legacy-compat|packages\/(?:core|services|client|verifier)|node_modules\/p2p-hiverelay)/.test(name)))
  }
})

test('blind Dockerfile builds native peer credentials independently and ships compiler-free final images', t => {
  const dockerfile = read('Dockerfile.blind')
  const edgeToolchain = dockerfile.match(/FROM blind-native-toolchain AS blind-edge-toolchain[\s\S]+?FROM blind-native-toolchain AS blind-daemon-toolchain/)?.[0] || ''
  const daemonToolchain = dockerfile.match(/FROM blind-native-toolchain AS blind-daemon-toolchain[\s\S]+?FROM --platform=\$TARGETPLATFORM \$\{NODE_IMAGE\} AS blind-edge/)?.[0] || ''
  const edgeFinal = dockerfile.match(/FROM --platform=\$TARGETPLATFORM \$\{NODE_IMAGE\} AS blind-edge[\s\S]+?FROM --platform=\$TARGETPLATFORM \$\{NODE_IMAGE\} AS blind-daemon/)?.[0] || ''
  const daemonFinal = dockerfile.match(/FROM --platform=\$TARGETPLATFORM \$\{NODE_IMAGE\} AS blind-daemon[\s\S]+$/)?.[0] || ''

  t.ok(dockerfile.includes('AS blind-native-toolchain'))
  t.ok(dockerfile.includes('AS blind-edge-toolchain'))
  t.ok(dockerfile.includes('AS blind-daemon-toolchain'))
  t.is(occurrences(dockerfile, 'npm_config_build_from_source=true npm ci'), 2)
  t.is(occurrences(dockerfile, 'blind_peercred.node'), 2)
  t.ok(edgeToolchain.includes('COPY packages/blind-peercred'))
  t.absent(edgeToolchain.includes('COPY packages/blind-daemon'))
  t.ok(daemonToolchain.includes('COPY packages/blind-peercred'))
  t.absent(daemonToolchain.includes('COPY packages/blind-edge'))
  t.absent(edgeFinal.includes('apt-get'))
  t.absent(daemonFinal.includes('apt-get'))
  t.ok(edgeFinal.includes('COPY --from=blind-edge-toolchain'))
  t.ok(daemonFinal.includes('COPY --from=blind-daemon-toolchain'))
  t.ok(edgeFinal.includes('USER 998:997'))
  t.ok(daemonFinal.includes('USER 999:997'))
  t.is(occurrences(dockerfile, 'HIVERELAY_BLIND_UNARY_SOCKET=/run/hiverelay-blind/unary.sock'), 2)
  t.is(occurrences(dockerfile, 'HIVERELAY_BLIND_STREAM_SOCKET=/run/hiverelay-blind/stream.sock'), 2)
  t.absent(dockerfile.includes('HIVERELAY_BLIND_SOCKET='))
  t.ok(edgeFinal.includes('HIVERELAY_BLIND_DAEMON_UID=999'))
  t.ok(edgeFinal.includes('HIVERELAY_BLIND_DAEMON_GID=997'))
  t.ok(edgeFinal.includes('HIVERELAY_BLIND_SHARED_GID=997'))
})

test('blind compose freezes two sockets, isolation, identities and a bounded initializer', t => {
  const compose = read('docker-compose.blind.yml')
  const initializer = compose.match(/ {2}blind-volume-init:[\s\S]+?\n {2}blind-daemon:/)?.[0] || ''
  const daemon = compose.match(/ {2}blind-daemon:[\s\S]+?\n {2}blind-edge:/)?.[0] || ''
  const edge = compose.match(/ {2}blind-edge:[\s\S]+?\nvolumes:/)?.[0] || ''

  t.ok(compose.includes('condition: service_healthy'))
  t.ok(compose.includes('condition: service_completed_successfully'))
  t.absent(compose.includes('condition: service_started'))
  t.ok(initializer.includes('entrypoint: ["/usr/bin/timeout", "--signal=KILL", "59s", "/bin/sh", "-ec"]'))
  t.ok(initializer.includes('pids_limit: 32'))
  t.ok(initializer.includes('network_mode: none'))
  t.ok(initializer.includes('read_only: true'))
  t.ok(initializer.includes('no-new-privileges:true'))
  t.ok(initializer.includes('cap_add:\n      - CHOWN\n      - DAC_OVERRIDE\n      - FOWNER'))
  t.ok(initializer.includes('test ! -L /run/hiverelay-blind'))
  t.ok(initializer.includes('test ! -L /data/blind'))
  t.absent(initializer.includes(' -R'))
  t.ok(initializer.includes('blind-runtime:/run/hiverelay-blind'))
  t.ok(initializer.includes('blind-data:/data/blind'))

  for (const service of [daemon, edge]) {
    t.ok(service.includes('HIVERELAY_BLIND_UNARY_SOCKET: /run/hiverelay-blind/unary.sock'))
    t.ok(service.includes('HIVERELAY_BLIND_STREAM_SOCKET: /run/hiverelay-blind/stream.sock'))
    t.ok(service.includes('HIVERELAY_BLIND_DAEMON_UID: "999"'))
    t.ok(service.includes('HIVERELAY_BLIND_DAEMON_GID: "997"'))
    t.ok(service.includes('HIVERELAY_BLIND_SHARED_GID: "997"'))
    t.absent(service.includes('HIVERELAY_BLIND_SOCKET:'))
    t.absent(service.includes('cap_add:'))
  }
  t.ok(daemon.includes('network_mode: none'))
  t.absent(daemon.includes('ports:'))
  t.absent(daemon.includes('blind-public'))
  for (const name of [
    'HIVERELAY_BLIND_RUNTIME_PROFILE',
    'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE',
    'HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256',
    'HIVERELAY_BLIND_DESCRIPTOR_FILES',
    'HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES',
    'HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE',
    'HIVERELAY_BLIND_STORE_ROOT',
    'HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT',
    'HIVERELAY_BLIND_INBOX_STORE_ROOT',
    'HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE',
    'HIVERELAY_BLIND_CORE_STORE_ROOT',
    'HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE',
    'HIVERELAY_BLIND_STORE_READER_MODE',
    'HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE',
    'HIVERELAY_BLIND_MAP_GENERATION',
    'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE',
    'HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH',
    'HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS'
  ]) {
    t.ok(daemon.includes(name + ': "' + '$' + '{' + name + ':-}"'))
  }
  t.absent(daemon.includes('HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE'))
  t.absent(daemon.includes('HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256'))
  t.ok(daemon.includes('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: "' + '$' + '{HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH:-}' + '"'))
  t.ok(daemon.includes('HIVERELAY_BLIND_ENDPOINT_IDS: "' + '$' + '{HIVERELAY_BLIND_ENDPOINT_IDS:-}' + '"'))
  t.ok(edge.includes('networks:\n      - blind-public'))
  t.ok(edge.includes('ports:'))
  t.ok(edge.includes('blind-runtime:/run/hiverelay-blind:ro'))
  t.ok(edge.includes('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: "' + '$' + '{HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH:-}' + '"'))
  t.ok(edge.includes('HIVERELAY_BLIND_STREAM_TRANSPORT_PROFILE_HASH: "' + '$' + '{HIVERELAY_BLIND_STREAM_TRANSPORT_PROFILE_HASH:-}' + '"'))
  t.ok(edge.includes('HIVERELAY_BLIND_ENDPOINT_ID: "' + '$' + '{HIVERELAY_BLIND_ENDPOINT_ID:-}' + '"'))
  t.absent(edge.includes('HIVERELAY_BLIND_ENDPOINT_ID: "1"'))
})

test('blind healthchecks inspect both exact listeners without minting stream-readiness tickets', t => {
  const edge = read('deploy/blind/edge/healthcheck.mjs')
  const daemon = read('deploy/blind/daemon/healthcheck.mjs')

  for (const healthcheck of [edge, daemon]) {
    t.ok(healthcheck.includes('HIVERELAY_BLIND_UNARY_SOCKET'))
    t.ok(healthcheck.includes('HIVERELAY_BLIND_STREAM_SOCKET'))
    t.ok(healthcheck.includes('HIVERELAY_BLIND_DAEMON_UID'))
    t.ok(healthcheck.includes('HIVERELAY_BLIND_DAEMON_GID'))
    t.ok(healthcheck.includes('HIVERELAY_BLIND_SHARED_GID'))
    t.ok(healthcheck.includes('fs.realpathSync(socketPath)'))
    t.ok(healthcheck.includes('fs.lstatSync(socketPath)'))
    t.ok(healthcheck.includes('(socket.mode & 0o777) !== 0o660'))
    t.ok(healthcheck.includes('unarySocket.dev === streamSocket.dev && unarySocket.ino === streamSocket.ino'))
  }
  t.absent(edge.includes("fs.readFileSync('/proc/net/unix'"))
  t.ok(daemon.includes("fs.readFileSync('/proc/net/unix'"))
  t.absent(daemon.includes('createConnection'))
  t.absent(daemon.includes("from 'node:net'"))
  t.ok(edge.includes('tls.connect'))
})

test('local launcher passes the exact dual-socket and signed-topology environment', t => {
  const launcher = read('scripts/start-blind-local.mjs')
  t.ok(launcher.includes('HIVERELAY_BLIND_UNARY_SOCKET'))
  t.ok(launcher.includes('HIVERELAY_BLIND_STREAM_SOCKET'))
  t.ok(launcher.includes('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH'))
  t.ok(launcher.includes("requiredUnsignedEnvironment('HIVERELAY_BLIND_ENDPOINT_ID', 0xff, 1)"))
  t.ok(launcher.includes('HIVERELAY_BLIND_ENDPOINT_IDS: String(endpointId)'))
  t.ok(launcher.includes('HIVERELAY_BLIND_EDGE_UID'))
  t.ok(launcher.includes('HIVERELAY_BLIND_DAEMON_UID'))
  t.ok(launcher.includes('HIVERELAY_BLIND_DAEMON_GID'))
  t.ok(launcher.includes('HIVERELAY_BLIND_SHARED_GID'))
  t.ok(launcher.includes('await waitForSockets(daemon, unarySocketPath, streamSocketPath)'))
  t.absent(launcher.includes('HIVERELAY_BLIND_SOCKET:'))
})

test('image inventory names only replacement packages and edge carries peercred', t => {
  const policy = json('deploy/blind/image-inventory-policy.json')
  t.alike(policy.components.edge.hiverelayPackages, ['blind-edge', 'blind-ipc', 'blind-peercred', 'blind-protocol'])
  t.alike(policy.components.daemon.hiverelayPackages, ['blind-daemon', 'blind-ipc', 'blind-peercred', 'blind-protocol'])
  t.ok(policy.forbiddenHiverelayPackages.includes('core'))
  t.ok(policy.forbiddenHiverelayPackages.includes('services'))
  t.ok(policy.forbiddenRoots.includes('/opt/hiverelay/legacy-compat'))
  t.ok(policy.forbiddenCompilerCommands.includes('g++'))
  t.ok(policy.forbiddenCompilerCommands.includes('make'))
})
