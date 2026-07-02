function serviceEntry (node, name) {
  const registry = node && node.serviceRegistry
  const services = registry && registry.services
  return services && typeof services.get === 'function' ? services.get(name) : null
}

export function resolveAIServiceProvider (node) {
  const entry = serviceEntry(node, 'ai')
  if (!entry) {
    return { ok: false, status: 503, error: 'AI service is not registered on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'AI service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || typeof provider['list-models'] !== 'function' ||
      typeof provider['register-model'] !== 'function' ||
      typeof provider['remove-model'] !== 'function') {
    return { ok: false, status: 503, error: 'AI service does not expose model management methods' }
  }

  return { ok: true, provider, entry }
}

export function resolvePokerServiceProvider (node) {
  const entry = serviceEntry(node, 'poker')
  if (!entry) {
    return { ok: false, status: 503, error: 'Poker service is not enabled on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'Poker service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || typeof provider.listTables !== 'function') {
    return { ok: false, status: 503, error: 'Poker service does not expose the substrate methods' }
  }

  return { ok: true, provider, entry }
}

export function resolveOutboxLogServiceProvider (node) {
  const entry = serviceEntry(node, 'outboxlog')
  if (!entry) {
    return { ok: false, status: 503, error: 'OutboxLog service is not enabled on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'OutboxLog service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || !provider.sync || typeof provider.sync.create !== 'function' || typeof provider.sync.append !== 'function') {
    return { ok: false, status: 503, error: 'OutboxLog service does not expose sync methods' }
  }
  if (!provider.swarm || typeof provider.swarm.join !== 'function' || typeof provider.swarm.subscribe !== 'function') {
    return { ok: false, status: 503, error: 'OutboxLog service does not expose swarm methods' }
  }

  return { ok: true, provider, entry }
}

export function resolveWitnessLogServiceProvider (node) {
  const entry = serviceEntry(node, 'witnesslog')
  if (!entry) {
    return { ok: false, status: 503, error: 'WitnessLog service is not enabled on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'WitnessLog service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || typeof provider.append !== 'function' || typeof provider.list !== 'function') {
    return { ok: false, status: 503, error: 'WitnessLog service does not expose append/range methods' }
  }
  if (typeof provider.markers !== 'function' || typeof provider.subscribe !== 'function') {
    return { ok: false, status: 503, error: 'WitnessLog service does not expose event methods' }
  }

  return { ok: true, provider, entry }
}

export function resolveRepairTicketServiceProvider (node) {
  const entry = serviceEntry(node, 'repairticket')
  if (!entry) {
    return { ok: false, status: 503, error: 'RepairTicket service is not enabled on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'RepairTicket service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || typeof provider.append !== 'function' || typeof provider.list !== 'function' || typeof provider.tickets !== 'function') {
    return { ok: false, status: 503, error: 'RepairTicket service does not expose append/range/ticket methods' }
  }
  if (typeof provider.markers !== 'function' || typeof provider.subscribe !== 'function') {
    return { ok: false, status: 503, error: 'RepairTicket service does not expose event methods' }
  }

  return { ok: true, provider, entry }
}

export function resolveNotifyServiceProvider (node) {
  const entry = serviceEntry(node, 'notify')
  if (!entry) {
    return { ok: false, status: 503, error: 'Notify service is not enabled on this relay' }
  }

  if (entry.status && entry.status !== 'running') {
    return { ok: false, status: 503, error: 'Notify service is not running (status=' + entry.status + ')' }
  }

  const provider = entry.provider || entry
  if (!provider || typeof provider.manifest !== 'function' || typeof provider.status !== 'function') {
    return { ok: false, status: 503, error: 'Notify service does not expose service methods' }
  }

  return { ok: true, provider, entry }
}
