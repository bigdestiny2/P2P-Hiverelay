#!/usr/bin/env node
import fs from 'node:fs/promises'
import { BlindEdge } from './server.js'

function requiredUnsignedEnvironment (name, maximum = 0xffffffff, minimum = 0) {
  const value = process.env[name]
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} is required from the signed launch topology as an unsigned integer`)
  }
  const decoded = Number(value)
  if (!Number.isSafeInteger(decoded) || decoded < minimum || decoded > maximum) {
    throw new Error(`${name} is outside its signed launch-topology range`)
  }
  return decoded
}

function requiredTopologyHash () {
  const value = process.env.HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH must be the exact 32-byte signed topology hash in hex')
  }
  return Buffer.from(value, 'hex')
}

function optionalStreamTransportProfileHash () {
  const value = process.env.HIVERELAY_BLIND_STREAM_TRANSPORT_PROFILE_HASH
  if (value == null) return null
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value) || /^0{64}$/i.test(value)) {
    throw new Error('HIVERELAY_BLIND_STREAM_TRANSPORT_PROFILE_HASH must be one nonzero 32-byte descriptor transport-profile hash in hex')
  }
  return Buffer.from(value, 'hex')
}

const tlsKeyPath = process.env.HIVERELAY_BLIND_TLS_KEY || '/run/secrets/hiverelay-blind-tls.key'
const tlsCertPath = process.env.HIVERELAY_BLIND_TLS_CERT || '/run/secrets/hiverelay-blind-tls.crt'
const endpointId = requiredUnsignedEnvironment('HIVERELAY_BLIND_ENDPOINT_ID', 0xff, 1)
const readinessTopology = {
  unarySocketPath: process.env.HIVERELAY_BLIND_UNARY_SOCKET || '/run/hiverelay-blind/unary.sock',
  streamSocketPath: process.env.HIVERELAY_BLIND_STREAM_SOCKET || '/run/hiverelay-blind/stream.sock',
  launchTopologyHash: requiredTopologyHash(),
  streamTransportProfileHash: optionalStreamTransportProfileHash(),
  daemonUid: requiredUnsignedEnvironment('HIVERELAY_BLIND_DAEMON_UID'),
  daemonGid: requiredUnsignedEnvironment('HIVERELAY_BLIND_DAEMON_GID'),
  socketGroupGid: requiredUnsignedEnvironment('HIVERELAY_BLIND_SHARED_GID'),
  socketMode: 0o660
}
const [key, cert] = await Promise.all([fs.readFile(tlsKeyPath), fs.readFile(tlsCertPath)])

const edge = new BlindEdge({
  host: process.env.HIVERELAY_BLIND_HOST || '0.0.0.0',
  port: Number(process.env.HIVERELAY_BLIND_PORT || 9100),
  endpointId,
  readinessTopology,
  tls: { key, cert },
  onError: error => process.stderr.write(`[blind-edge] ${error.message}\n`)
})

await edge.start()
const address = edge.address()
process.stdout.write(`[blind-edge] public blind transport ready at ${address.address}:${address.port}\n`)

let closing = false
async function close () {
  if (closing) return
  closing = true
  await edge.close()
}

process.once('SIGINT', () => close().finally(() => process.exit(0)))
process.once('SIGTERM', () => close().finally(() => process.exit(0)))
