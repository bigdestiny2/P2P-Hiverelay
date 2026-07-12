import test from 'brittle'
import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import {
  LOCAL_BROKER_ERROR,
  LOCAL_RESPONSE_KIND,
  decodeLocalResponse,
  encodeLocalReadyProbe
} from '@hiverelay/blind-ipc'
import { BlindDaemon } from '../index.js'

const TOPOLOGY_HASH = b4a.alloc(32, 0x31)
const DESCRIPTOR_HASH = b4a.alloc(32, 0x42)
const OTHER_DESCRIPTOR_HASH = b4a.alloc(32, 0x43)
const EDGE_NONCE = b4a.alloc(32, 0x51)

const peer = () => ({
  expectedPeerUid: process.getuid(),
  expectedPeerGid: process.getgid(),
  socketGroupGid: process.getgid()
})

function socketPaths (directory) {
  return {
    unarySocketPath: path.join(directory, 'unary.sock'),
    streamSocketPath: path.join(directory, 'stream.sock')
  }
}

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

function validOptions (paths, overrides = {}) {
  return {
    ...paths,
    ...peer(),
    launchTopologyHash: TOPOLOGY_HASH,
    endpointIds: [1],
    releaseGate: () => {},
    dispatch: async () => {
      throw new Error('readiness must not enter external dispatch')
    },
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence: 1n,
      descriptorHash: DESCRIPTOR_HASH,
      readyRoleBits: 1,
      readyOperationBits: 0x7
    }),
    ...overrides
  }
}

async function pathExists (file) {
  try {
    await fs.lstat(file)
    return true
  } catch (error) {
    if (error && error.code === 'ENOENT') return false
    throw error
  }
}

function connectNoFrame (socketPath, tolerateReset = false) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath })
    let settled = false
    const finish = error => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error && !tolerateReset) reject(error)
      else resolve()
    }
    const timer = setTimeout(() => finish(new Error('stream readiness check timed out')), 3000)
    socket.once('connect', () => socket.end())
    socket.once('close', () => finish())
    socket.once('error', finish)
  })
}

function connectWithData (socketPath) {
  return new Promise(resolve => {
    const socket = net.createConnection({ path: socketPath })
    const timer = setTimeout(() => {
      socket.destroy()
      resolve()
    }, 3000)
    socket.once('connect', () => socket.end(b4a.from([1])))
    socket.once('error', () => {})
    socket.once('close', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

function exchange (socketPath, frame) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath })
    const chunks = []
    let total = 0
    let settled = false
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => finish(new Error('unary exchange timed out')), 3000)
    socket.once('connect', () => socket.write(frame))
    socket.on('data', chunk => {
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
    })
    socket.once('end', () => finish(null, b4a.concat(chunks, total)))
    socket.once('error', error => finish(error))
  })
}

async function probe (paths, acceptedMonotonicMillis, overrides = {}) {
  const frame = encodeLocalReadyProbe({
    endpointId: overrides.endpointId == null ? 1 : overrides.endpointId,
    acceptedMonotonicMillis,
    edgeInstanceNonce: overrides.edgeInstanceNonce || EDGE_NONCE,
    launchTopologyHash: overrides.launchTopologyHash || TOPOLOGY_HASH
  })
  return decodeLocalResponse(await exchange(paths.unarySocketPath, frame), { copyBody: true })
}

function isBrokerError (t, response, code) {
  t.is(response.responseKind, LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR)
  t.is(response.localBrokerError, code)
  t.is(response.externalCanonicalBytes.byteLength, 0)
}

test('blind daemon requires two absolute canonical unequal socket paths', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-paths-')
  t.teardown(async () => fs.rm(directory, { recursive: true, force: true }))
  const paths = socketPaths(directory)

  t.exception.all(() => new BlindDaemon(validOptions({
    unarySocketPath: undefined,
    streamSocketPath: paths.streamSocketPath
  })), /unarySocketPath must be an absolute/)
  t.exception.all(() => new BlindDaemon(validOptions({
    unarySocketPath: 'relative.sock',
    streamSocketPath: paths.streamSocketPath
  })), /unarySocketPath must be an absolute/)
  t.exception.all(() => new BlindDaemon(validOptions({
    unarySocketPath: `${directory}/a/../unary.sock`,
    streamSocketPath: paths.streamSocketPath
  })), /canonical normalized/)
  t.exception.all(() => new BlindDaemon(validOptions({
    unarySocketPath: paths.unarySocketPath,
    streamSocketPath: paths.unarySocketPath
  })), /must be unequal/)
  t.is(await pathExists(paths.unarySocketPath), false)
  t.is(await pathExists(paths.streamSocketPath), false)
})

test('blind daemon refuses non-sockets and symlinked socket parents before binding either path', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-refusal-')
  t.teardown(async () => fs.rm(directory, { recursive: true, force: true }))

  const unaryBlocked = socketPaths(path.join(directory, 'unary-blocked'))
  await fs.mkdir(path.dirname(unaryBlocked.unarySocketPath), { recursive: true })
  await fs.writeFile(unaryBlocked.unarySocketPath, 'do not replace')
  const first = new BlindDaemon(validOptions(unaryBlocked))
  await t.exception(first.start(), /refusing to replace a non-socket/)
  t.is(await fs.readFile(unaryBlocked.unarySocketPath, 'utf8'), 'do not replace')
  t.is(await pathExists(unaryBlocked.streamSocketPath), false)

  const streamBlocked = socketPaths(path.join(directory, 'stream-blocked'))
  await fs.mkdir(path.dirname(streamBlocked.streamSocketPath), { recursive: true })
  await fs.writeFile(streamBlocked.streamSocketPath, 'also do not replace')
  const second = new BlindDaemon(validOptions(streamBlocked))
  await t.exception(second.start(), /refusing to replace a non-socket/)
  t.is(await pathExists(streamBlocked.unarySocketPath), false)
  t.is(await fs.readFile(streamBlocked.streamSocketPath, 'utf8'), 'also do not replace')

  const realParent = path.join(directory, 'real-parent')
  const linkedParent = path.join(directory, 'linked-parent')
  await fs.mkdir(realParent)
  await fs.symlink(realParent, linkedParent)
  const symlinked = socketPaths(linkedParent)
  const third = new BlindDaemon(validOptions(symlinked))
  await t.exception(third.start(), /symlink socket parent/)
  t.is(await pathExists(path.join(realParent, 'unary.sock')), false)
  t.is(await pathExists(path.join(realParent, 'stream.sock')), false)
})

test('release, dispatcher, readiness and topology gates fail before creating either socket', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-gate-')
  const paths = socketPaths(directory)
  t.teardown(async () => fs.rm(directory, { recursive: true, force: true }))

  const incomplete = new BlindDaemon(validOptions(paths, {
    releaseGate: () => {
      const error = new Error('injected release authority is incomplete')
      error.code = 'BLIND_TEST_RELEASE_INCOMPLETE'
      throw error
    }
  }))
  await t.exception(incomplete.start(), /injected release authority is incomplete/)

  const missingDispatcher = new BlindDaemon(validOptions(paths, { dispatch: null }))
  await t.exception(missingDispatcher.start(), /no complete dispatcher/)

  const missingReadiness = new BlindDaemon(validOptions(paths, { readinessSnapshot: null }))
  await t.exception(missingReadiness.start(), /no self-verified readiness snapshot/)

  const missingTopology = new BlindDaemon(validOptions(paths, { launchTopologyHash: null }))
  await t.exception(missingTopology.start(), /no signed topology hash or endpoint set/)

  t.is(await pathExists(paths.unarySocketPath), false)
  t.is(await pathExists(paths.streamSocketPath), false)
})

test('both sockets bind atomically with distinct inodes and an active daemon cannot be taken over', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-takeover-')
  const paths = socketPaths(directory)
  const options = validOptions(paths)
  const first = new BlindDaemon(options)
  const second = new BlindDaemon(options)
  t.teardown(async () => {
    await first.close()
    await second.close()
    await fs.rm(directory, { recursive: true, force: true })
  })

  await first.start()
  const unaryBefore = await fs.lstat(paths.unarySocketPath)
  const streamBefore = await fs.lstat(paths.streamSocketPath)
  t.ok(unaryBefore.isSocket())
  t.ok(streamBefore.isSocket())
  t.is(unaryBefore.mode & 0o777, 0o660)
  t.is(streamBefore.mode & 0o777, 0o660)
  t.is(unaryBefore.gid, process.getgid())
  t.is(streamBefore.gid, process.getgid())
  t.not(unaryBefore.ino, streamBefore.ino)

  await t.exception(second.start(), /active blind daemon socket/)
  const unaryAfter = await fs.lstat(paths.unarySocketPath)
  const streamAfter = await fs.lstat(paths.streamSocketPath)
  t.is(unaryAfter.ino, unaryBefore.ino)
  t.is(unaryAfter.dev, unaryBefore.dev)
  t.is(streamAfter.ino, streamBefore.ino)
  t.is(streamAfter.dev, streamBefore.dev)
})

test('one clean authenticated stream EOF authorizes exactly one ready ACK', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-ready-')
  const paths = socketPaths(directory)
  const now = 10000n
  let dispatchCalls = 0
  let snapshotCalls = 0
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    dispatch: async () => { dispatchCalls++; throw new Error('must not dispatch') },
    readinessSnapshot: async context => {
      snapshotCalls++
      t.is(context.endpointId, 1)
      t.ok(b4a.equals(context.edgeInstanceNonce, EDGE_NONCE))
      t.ok(b4a.equals(context.launchTopologyHash, TOPOLOGY_HASH))
      t.is(context.acceptedMonotonicMillis, now)
      t.is(context.absoluteDeadlineMonotonicMillis, now + 2000n)
      t.ok(context.signal instanceof AbortSignal)
      context.edgeInstanceNonce.fill(0)
      context.launchTopologyHash.fill(0)
      return {
        selfVerified: true,
        descriptorSequence: 1n,
        descriptorHash: DESCRIPTOR_HASH,
        readyRoleBits: 1,
        readyOperationBits: 0x7
      }
    }
  }))
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()

  await connectNoFrame(paths.streamSocketPath)
  const response = await probe(paths, now)
  t.is(response.responseKind, LOCAL_RESPONSE_KIND.LOCAL_READY_ACK)
  t.is(response.localBrokerError, 0)
  t.ok(b4a.equals(response.readyAck.edgeInstanceNonce, EDGE_NONCE))
  t.ok(b4a.equals(response.readyAck.launchTopologyHash, TOPOLOGY_HASH))
  t.is(response.readyAck.endpointId, 1)
  t.is(response.readyAck.descriptorSequence, 1n)
  t.ok(b4a.equals(response.readyAck.descriptorHash, DESCRIPTOR_HASH))
  t.is(response.readyAck.readyOperationBits, 0x7)
  t.is(response.readyAck.expiresMonotonicMillis, now + 5000n)
  t.is(snapshotCalls, 1)
  t.is(dispatchCalls, 0)

  const replay = await probe(paths, now)
  isBrokerError(t, replay, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
  t.is(snapshotCalls, 1)

  await daemon.close()
  t.is(await pathExists(paths.unarySocketPath), false)
  t.is(await pathExists(paths.streamSocketPath), false)
})

test('readiness tickets are one-use under concurrency and stream data creates no ticket', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-ready-race-')
  const paths = socketPaths(directory)
  const now = 15000n
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    maxPendingReadinessChecks: 1
  }))
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()

  await connectWithData(paths.streamSocketPath)
  isBrokerError(t, await probe(paths, now), LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  await connectNoFrame(paths.streamSocketPath)
  await connectNoFrame(paths.streamSocketPath)
  await connectNoFrame(paths.streamSocketPath)
  t.is(daemon.pendingReadinessChecks.length, 1)
  const [left, right] = await Promise.all([probe(paths, now), probe(paths, now)])
  const responses = [left, right]
  t.is(responses.filter(response => response.responseKind === LOCAL_RESPONSE_KIND.LOCAL_READY_ACK).length, 1)
  t.is(responses.filter(response => response.responseKind === LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR &&
    response.localBrokerError === LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH).length, 1)
})

test('wrong peer, stale stream check and expired probe never produce an ACK', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-negative-ready-')
  const paths = socketPaths(directory)
  let now = 20000n
  const wrongPeer = new BlindDaemon(validOptions(paths, {
    expectedPeerUid: process.getuid() + 1,
    monotonicMillis: () => now
  }))
  await wrongPeer.start()
  await connectNoFrame(paths.streamSocketPath, true)
  const unauthorized = await probe(paths, now)
  isBrokerError(t, unauthorized, LOCAL_BROKER_ERROR.UNAUTHORIZED_EDGE_PEER)
  await wrongPeer.close()

  const daemon = new BlindDaemon(validOptions(paths, { monotonicMillis: () => now }))
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()
  await connectNoFrame(paths.streamSocketPath)
  now += 2001n
  const stale = await probe(paths, now)
  isBrokerError(t, stale, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  now = 30000n
  await connectNoFrame(paths.streamSocketPath)
  now = 32001n
  const expired = await probe(paths, 30001n)
  isBrokerError(t, expired, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
})

test('topology, endpoint, readiness bits, snapshot and completion substitutions fail closed', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-substitution-')
  const paths = socketPaths(directory)
  let now = 40000n
  let snapshot = {
    selfVerified: true,
    descriptorSequence: 1n,
    descriptorHash: DESCRIPTOR_HASH,
    readyRoleBits: 1,
    readyOperationBits: 0x7
  }
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    readinessSnapshot: async () => snapshot
  }))
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()

  await connectNoFrame(paths.streamSocketPath)
  const badTopology = await probe(paths, now, { launchTopologyHash: b4a.alloc(32, 0x99) })
  isBrokerError(t, badTopology, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  const badEndpoint = await probe(paths, now, { endpointId: 2 })
  isBrokerError(t, badEndpoint, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  snapshot = { ...snapshot, readyOperationBits: 0x3 }
  const missingDescribe = await probe(paths, now)
  isBrokerError(t, missingDescribe, LOCAL_BROKER_ERROR.DAEMON_DRAINING)

  await connectNoFrame(paths.streamSocketPath)
  snapshot = { ...snapshot, readyOperationBits: 0x7, readyRoleBits: 0x80 }
  const reservedRole = await probe(paths, now)
  isBrokerError(t, reservedRole, LOCAL_BROKER_ERROR.INTERNAL_IPC_FAILURE)

  await connectNoFrame(paths.streamSocketPath)
  snapshot = { ...snapshot, selfVerified: false, readyRoleBits: 1 }
  const unverified = await probe(paths, now)
  isBrokerError(t, unverified, LOCAL_BROKER_ERROR.INTERNAL_IPC_FAILURE)
  const consumedAfterFailure = await probe(paths, now)
  isBrokerError(t, consumedAfterFailure, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  await connectNoFrame(paths.streamSocketPath)
  snapshot = { ...snapshot, selfVerified: true }
  const priorProvider = daemon.readinessSnapshot
  daemon.readinessSnapshot = async context => {
    now = context.absoluteDeadlineMonotonicMillis
    return snapshot
  }
  const late = await probe(paths, 40000n)
  isBrokerError(t, late, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
  daemon.readinessSnapshot = priorProvider
})

test('readiness descriptor sequence is monotonic and equal sequence cannot fork', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-descriptor-floor-')
  const paths = socketPaths(directory)
  const now = 50000n
  let descriptorSequence = 2n
  let descriptorHash = DESCRIPTOR_HASH
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    readinessSnapshot: async () => ({
      selfVerified: true,
      descriptorSequence,
      descriptorHash,
      readyRoleBits: 1,
      readyOperationBits: 0x7
    })
  }))
  t.teardown(async () => {
    await daemon.close()
    await fs.rm(directory, { recursive: true, force: true })
  })
  await daemon.start()

  await connectNoFrame(paths.streamSocketPath)
  t.is((await probe(paths, now)).responseKind, LOCAL_RESPONSE_KIND.LOCAL_READY_ACK)

  await connectNoFrame(paths.streamSocketPath)
  descriptorSequence = 1n
  isBrokerError(t, await probe(paths, now), LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  await connectNoFrame(paths.streamSocketPath)
  descriptorSequence = 2n
  descriptorHash = OTHER_DESCRIPTOR_HASH
  isBrokerError(t, await probe(paths, now), LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)

  await connectNoFrame(paths.streamSocketPath)
  descriptorSequence = 3n
  t.is((await probe(paths, now)).responseKind, LOCAL_RESPONSE_KIND.LOCAL_READY_ACK)
})

test('socket identity substitution blocks ACK and cleanup never unlinks the replacement', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-inode-fence-')
  const paths = socketPaths(directory)
  const now = 60000n
  const replacementTarget = path.join(directory, 'replacement-target')
  await fs.writeFile(replacementTarget, 'operator file')
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    readinessSnapshot: async () => {
      await fs.unlink(paths.streamSocketPath)
      await fs.symlink(replacementTarget, paths.streamSocketPath)
      return {
        selfVerified: true,
        descriptorSequence: 1n,
        descriptorHash: DESCRIPTOR_HASH,
        readyRoleBits: 1,
        readyOperationBits: 0x7
      }
    }
  }))
  t.teardown(async () => fs.rm(directory, { recursive: true, force: true }))
  await daemon.start()
  await connectNoFrame(paths.streamSocketPath)
  const response = await probe(paths, now)
  isBrokerError(t, response, LOCAL_BROKER_ERROR.TOPOLOGY_PROFILE_ENDPOINT_MISMATCH)
  await daemon.close()
  t.ok((await fs.lstat(paths.streamSocketPath)).isSymbolicLink())
  t.is(await fs.readFile(replacementTarget, 'utf8'), 'operator file')
  t.is(await pathExists(paths.unarySocketPath), false)
})

test('close aborts pending readiness work, clears both sockets and releases lifecycle state', async t => {
  const directory = await fs.mkdtemp('/private/tmp/blind-daemon-close-ready-')
  const paths = socketPaths(directory)
  const now = monotonicMillis()
  let providerStarted
  const started = new Promise(resolve => { providerStarted = resolve })
  let providerAborted = false
  const daemon = new BlindDaemon(validOptions(paths, {
    monotonicMillis: () => now,
    readinessSnapshot: async ({ signal }) => new Promise((resolve, reject) => {
      providerStarted()
      signal.addEventListener('abort', () => {
        providerAborted = true
        reject(new Error('snapshot aborted'))
      }, { once: true })
    })
  }))
  t.teardown(async () => fs.rm(directory, { recursive: true, force: true }))
  await daemon.start()
  await connectNoFrame(paths.streamSocketPath)
  const pending = probe(paths, now).catch(() => null)
  await started
  await daemon.close()
  await pending
  t.is(providerAborted, true)
  t.is(daemon.pendingReadinessChecks.length, 0)
  t.is(await pathExists(paths.unarySocketPath), false)
  t.is(await pathExists(paths.streamSocketPath), false)
})

test('blind executable source graph has no legacy or application-semantic imports', async t => {
  const root = path.resolve(new URL('..', import.meta.url).pathname, '..')
  for (const packageName of ['blind-edge', 'blind-daemon', 'blind-ipc', 'blind-peercred']) {
    const packageRoot = path.join(root, packageName)
    const entries = await fs.readdir(packageRoot, { withFileTypes: true })
    const files = entries.filter(entry => entry.isFile() && entry.name.endsWith('.js'))
    for (const entry of files) {
      const source = await fs.readFile(path.join(packageRoot, entry.name), 'utf8')
      for (const forbidden of [
        'packages/core',
        'packages/services',
        '@hiverelay/core',
        'p2p-hiverelay',
        'plugin-loader',
        'ServiceProvider',
        'OutboxLog',
        'BlindShard',
        'peerit',
        'appId',
        'applicationId',
        'namespace',
        '/api/sync',
        '/api/directory',
        '/api/notify',
        'authorKey',
        'communityId',
        'moderationAction',
        'searchTerm'
      ]) t.is(source.includes(forbidden), false, `${packageName}/${entry.name} excludes ${forbidden}`)
    }
    const manifest = JSON.parse(await fs.readFile(path.join(packageRoot, 'package.json'), 'utf8'))
    const dependencies = Object.keys(manifest.dependencies || {})
    t.alike(dependencies.filter(name => ![
      '@hiverelay/blind-protocol',
      '@hiverelay/blind-ipc',
      '@hiverelay/blind-peercred',
      'b4a',
      'compact-encoding',
      'sodium-universal'
    ].includes(name)), [])
  }
})
