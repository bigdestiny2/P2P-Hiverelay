/**
 * Classify the externally visible onion-service vports without relying on
 * array position. A role is advertised only when the mapping resolves to a
 * known local protocol endpoint. Arbitrary explicit TCP mappings remain
 * unclassified instead of being signed as HTTP or Noise by guesswork.
 */
export function classifyOnionVports (vports, {
  peerVport = null,
  peerTargetPort = null,
  readVport = null,
  readTargetPort = null
} = {}) {
  const entries = (Array.isArray(vports) ? vports : [])
    .filter((entry) => entry && Number.isSafeInteger(entry.vport))
  const peerEntry = Number.isSafeInteger(peerTargetPort)
    ? entries.find((entry) => Number(entry.targetPort) === peerTargetPort)
    : Number.isSafeInteger(peerVport)
      ? entries.find((entry) => entry.vport === peerVport)
      : null
  const peer = peerEntry ? peerEntry.vport : null
  const targetReadEntry = Number.isSafeInteger(readTargetPort)
    ? entries.find((entry) => entry !== peerEntry && Number(entry.targetPort) === readTargetPort)
    : null
  const explicitRead = !Number.isSafeInteger(readTargetPort) &&
    Number.isSafeInteger(readVport) &&
    readVport !== peer &&
    entries.some((entry) => entry.vport === readVport)
    ? readVport
    : null
  const readPlane = targetReadEntry?.vport ?? explicitRead ?? null
  return { readPlane, peer }
}

/**
 * Tor daemon forwarding makes every target connection appear loopback-local.
 * RelayAPI can expose local-only routes or embed its bearer token, and a
 * trustProxy gateway accepts forwarded metadata from loopback. Neither
 * listener is a safe onion target.
 */
export function assertSafeOnionVports (vports, {
  apiPort = null,
  trustedProxyGatewayPort = null
} = {}) {
  if (!Array.isArray(vports) || vports.length === 0) return
  const forbidden = [
    { value: apiPort, name: 'RelayAPI' },
    { value: trustedProxyGatewayPort, name: 'a trustProxy gateway' }
  ]
  for (const target of forbidden) {
    if (target.value == null) continue
    const port = Number(target.value)
    if (!Number.isSafeInteger(port)) continue
    if (vports.some((entry) => entry && Number(entry.targetPort) === port)) {
      throw new Error(`tor.vports cannot expose ${target.name}; route onion HTTP to a dedicated read-only listener with trustProxy disabled`)
    }
  }
}

export function selectOnionReadPort (gatewayServer) {
  if (!gatewayServer || gatewayServer.trustProxy === true) return null
  return Number.isSafeInteger(gatewayServer.port) ? gatewayServer.port : null
}
