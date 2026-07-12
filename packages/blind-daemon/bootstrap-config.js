import path from 'node:path'

const U32_MAX = 0xffffffff

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_BOOTSTRAP_CONFIG_INVALID'
  throw error
}

export function requiredUnsignedEnvironment (environment, name, maximum = U32_MAX, minimum = 0) {
  const raw = environment[name]
  if (typeof raw !== 'string' || raw.length > 10 || !/^(0|[1-9][0-9]*)$/.test(raw)) {
    fail(`${name} is required from the signed launch topology as a canonical unsigned integer`)
  }
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${name} is outside its signed launch-topology range`)
  }
  return value
}

export function requiredTopologyHash (environment) {
  const raw = environment.HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH
  if (typeof raw !== 'string' || !/^[0-9a-fA-F]{64}$/.test(raw)) {
    fail('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH must be the exact 32-byte signed topology hash in hex')
  }
  return Buffer.from(raw, 'hex')
}

export function requiredEndpointIds (environment) {
  const raw = environment.HIVERELAY_BLIND_ENDPOINT_IDS
  if (typeof raw !== 'string' || raw.length > 1019 || !/^[1-9][0-9]*(?:,[1-9][0-9]*)*$/.test(raw)) {
    fail('HIVERELAY_BLIND_ENDPOINT_IDS must be a canonical comma-separated endpoint set')
  }
  const values = raw.split(',').map(value => Number(value))
  if (values.length < 1 || values.length > 255) fail('HIVERELAY_BLIND_ENDPOINT_IDS has an invalid set size')
  let previous = 0
  for (const value of values) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 0xff) {
      fail('HIVERELAY_BLIND_ENDPOINT_IDS contains an ID outside 1..255')
    }
    if (value <= previous) {
      fail('HIVERELAY_BLIND_ENDPOINT_IDS must be strictly increasing and duplicate-free')
    }
    previous = value
  }
  return values
}

function requiredSocketPath (environment, name) {
  const value = environment[name]
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0') || path.normalize(value) !== value) {
    fail(`${name} must be a canonical absolute Unix socket path from the signed launch topology`)
  }
  if (Buffer.byteLength(value) > 100) fail(`${name} exceeds the portable Unix socket path bound`)
  return value
}

function currentIdentity (identity, name) {
  if (!identity || typeof identity[name] !== 'function') fail('blind daemon bootstrap requires POSIX process credentials')
  const value = identity[name]()
  if (!Number.isSafeInteger(value) || value < 0 || value > U32_MAX) fail(`process ${name} returned an invalid identity`)
  return value
}

export function loadDaemonBootstrapConfig (environment = process.env, identity = process) {
  const unarySocketPath = requiredSocketPath(environment, 'HIVERELAY_BLIND_UNARY_SOCKET')
  const streamSocketPath = requiredSocketPath(environment, 'HIVERELAY_BLIND_STREAM_SOCKET')
  if (unarySocketPath === streamSocketPath) fail('signed unary and stream socket paths must be unequal')

  const expectedPeerUid = requiredUnsignedEnvironment(environment, 'HIVERELAY_BLIND_EDGE_UID')
  const daemonUid = requiredUnsignedEnvironment(environment, 'HIVERELAY_BLIND_DAEMON_UID')
  const daemonGid = requiredUnsignedEnvironment(environment, 'HIVERELAY_BLIND_DAEMON_GID')
  const sharedGid = requiredUnsignedEnvironment(environment, 'HIVERELAY_BLIND_SHARED_GID')
  if (daemonUid === expectedPeerUid) fail('signed edge and daemon UIDs must be unequal')
  if (daemonGid !== sharedGid) fail('signed daemon GID must equal the shared socket GID in topology v1')
  if (currentIdentity(identity, 'getuid') !== daemonUid || currentIdentity(identity, 'getgid') !== daemonGid) {
    fail('effective daemon UID/GID does not match the signed launch topology')
  }

  return Object.freeze({
    unarySocketPath,
    streamSocketPath,
    expectedPeerUid,
    expectedPeerGid: sharedGid,
    socketGroupGid: sharedGid,
    launchTopologyHash: requiredTopologyHash(environment),
    endpointIds: Object.freeze(requiredEndpointIds(environment))
  })
}
