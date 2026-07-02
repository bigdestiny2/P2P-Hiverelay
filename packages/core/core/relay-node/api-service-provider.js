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
