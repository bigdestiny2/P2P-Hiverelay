// Internal capability boundary for exact app-origin serving. This module is
// deliberately absent from package exports: only the isolation-validated
// GatewayServer may mint contexts accepted by HyperGateway.
const exactContexts = new WeakSet()
const activeExactGateways = new WeakMap()

export function issueExactAppContext (fields) {
  const context = Object.freeze({ ...fields, byteMode: 'exact' })
  exactContexts.add(context)
  return context
}

export function isIssuedExactAppContext (value) {
  return !!value && typeof value === 'object' && exactContexts.has(value) &&
    Object.isFrozen(value) && value.byteMode === 'exact'
}

export function registerActiveExactGateway (node, gateway) {
  let gateways = activeExactGateways.get(node)
  if (!gateways) activeExactGateways.set(node, (gateways = new Set()))
  gateways.add(gateway)
}

export function unregisterActiveExactGateway (node, gateway) {
  const gateways = activeExactGateways.get(node)
  if (!gateways) return
  gateways.delete(gateway)
  if (gateways.size === 0) activeExactGateways.delete(node)
}

export function hasActiveExactGateway (node) {
  return (activeExactGateways.get(node)?.size || 0) > 0
}
