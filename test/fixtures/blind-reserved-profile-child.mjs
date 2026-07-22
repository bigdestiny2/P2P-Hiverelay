import fs from 'node:fs/promises'
import net from 'node:net'
import path from 'node:path'
import b4a from 'b4a'
import {
  FAMILY,
  FRAME_KIND,
  OPERATION,
  PROTOCOL,
  RESERVED_OPERATION_PAIRS
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { encodeDispatchFrame } from '@hiverelay/blind-protocol/dispatch'
import { encodeOuterEnvelope } from '@hiverelay/blind-protocol/outer-envelope'
import { encodeUnaryRequest } from '@hiverelay/blind-client/wire'
import { BlindEdge } from '@hiverelay/blind-edge'
import { daemonOperationProfile } from '../../packages/blind-daemon/operation-catalog.js'
import { ResourceBudget } from '../../packages/blind-daemon/resource-budget.js'

function listen (server, socketPath) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, resolve)
  })
}

function close (server) {
  return new Promise(resolve => server.close(resolve))
}

function reservedEnvelope (pair) {
  const activeStream = pair.familyId === FAMILY.FORWARD && pair.operationId !== OPERATION.FORWARD.OPEN
  return encodeOuterEnvelope({
    outerClass: 1,
    innerDispatch: encodeDispatchFrame({
      frameKind: activeStream ? FRAME_KIND.STREAM : FRAME_KIND.REQUEST,
      familyId: pair.familyId,
      operationId: pair.operationId,
      requestId: b4a.alloc(16, activeStream ? 0 : pair.operationId),
      ...(activeStream ? { streamId: 1n, sequence: 0n } : {}),
      body: b4a.from([1])
    })
  }, { randomFill: padding => padding.fill(0x5a) })
}

const root = await fs.mkdtemp(path.join('/private/tmp', 'blind-reserved-edge-'))
const socketPath = path.join(root, 'daemon.sock')
let daemonConnections = 0
const daemonTrap = net.createServer(socket => {
  daemonConnections++
  socket.destroy()
})
await listen(daemonTrap, socketPath)
const edge = new BlindEdge({
  socketPath,
  host: '127.0.0.1',
  port: 0,
  maxBufferedBytes: 5000,
  allowInsecureLoopback: true,
  allowUnsafeReadinessProbe: true,
  unsafeReadinessProbe: async () => true,
  releaseGate: () => {}
})
await edge.start()
const base = `http://127.0.0.1:${edge.address().port}`

const results = []
try {
  for (const pair of RESERVED_OPERATION_PAIRS) {
    let clientRejected = false
    try {
      encodeUnaryRequest({ familyId: pair.familyId, operationId: pair.operationId })
    } catch (error) {
      clientRejected = error?.code === 'BAD_CLIENT_INPUT'
    }
    let budgetRejected = false
    try {
      new ResourceBudget().acquire({ familyId: pair.familyId, operationId: pair.operationId, bytes: 1 })
    } catch (error) {
      budgetRejected = /reserved operation/.test(error.message)
    }
    const route = pair.familyId === FAMILY.CORE ? 'core' : 'forward'
    const response = await fetch(`${base}/api/blind/v1/${route}`, {
      method: 'POST',
      headers: { 'content-type': PROTOCOL.mediaType },
      body: reservedEnvelope(pair)
    })
    await response.arrayBuffer()
    results.push({
      pair,
      clientRejected,
      daemonRejected: daemonOperationProfile(pair.familyId, pair.operationId) === null,
      budgetRejected,
      edgeStatus: response.status,
      edgeReleasedMemory: edge.bufferedBytes === 0 && edge.inFlight === 0
    })
  }
} finally {
  await edge.close()
  await close(daemonTrap)
  await fs.rm(root, { recursive: true, force: true })
}

if (results.length !== 5 || results.some(result =>
  !result.clientRejected || !result.daemonRejected || !result.budgetRejected ||
  result.edgeStatus !== 400 || !result.edgeReleasedMemory) || daemonConnections !== 0 ||
  results[0].pair.familyId !== FAMILY.CORE ||
  results[0].pair.operationId !== OPERATION.CORE.OPEN_REPLICATION) process.exitCode = 1
else {
  process.stdout.write(JSON.stringify({
    pid: process.pid,
    realEdgeProcess: true,
    daemonConnections,
    results
  }))
}
