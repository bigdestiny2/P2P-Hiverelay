import test from 'brittle'
import {
  resolveAIServiceProvider,
  resolveNotifyServiceProvider,
  resolveOutboxLogServiceProvider,
  resolvePokerServiceProvider
} from 'p2p-hiverelay/core/relay-node/api-service-provider.js'

function nodeWithServices (entries) {
  return {
    serviceRegistry: {
      services: new Map(entries)
    }
  }
}

function aiProvider () {
  return {
    async 'list-models' () {},
    async 'register-model' () {},
    async 'remove-model' () {}
  }
}

function pokerProvider () {
  return {
    listTables () {
      return []
    }
  }
}

function outboxLogProvider () {
  return {
    sync: {
      create () {},
      append () {}
    },
    swarm: {
      join () {},
      subscribe () {}
    }
  }
}

function notifyProvider () {
  return {
    manifest () {
      return { name: 'notify', version: '0.1.0', capabilities: ['send'] }
    },
    async status () {
      return { ok: true }
    }
  }
}

test('api service provider: AI lookup preserves readiness and method-shape contract', (t) => {
  t.alike(resolveAIServiceProvider({ serviceRegistry: null }), {
    ok: false,
    status: 503,
    error: 'AI service is not registered on this relay'
  })

  t.alike(resolveAIServiceProvider(nodeWithServices([['ai', { status: 'starting', provider: aiProvider() }]])), {
    ok: false,
    status: 503,
    error: 'AI service is not running (status=starting)'
  })

  t.alike(resolveAIServiceProvider(nodeWithServices([['ai', { status: 'running', provider: { async 'list-models' () {} } }]])), {
    ok: false,
    status: 503,
    error: 'AI service does not expose model management methods'
  })

  const provider = aiProvider()
  const entry = { status: 'running', provider }
  const resolved = resolveAIServiceProvider(nodeWithServices([['ai', entry]]))
  t.is(resolved.ok, true)
  t.is(resolved.provider, provider)
  t.is(resolved.entry, entry)

  const direct = aiProvider()
  const directResolved = resolveAIServiceProvider(nodeWithServices([['ai', direct]]))
  t.is(directResolved.ok, true)
  t.is(directResolved.provider, direct)
  t.is(directResolved.entry, direct)
})

test('api service provider: poker lookup preserves runtime and substrate contract', (t) => {
  t.alike(resolvePokerServiceProvider({ serviceRegistry: null }), {
    ok: false,
    status: 503,
    error: 'Poker service is not enabled on this relay'
  })

  t.alike(resolvePokerServiceProvider(nodeWithServices([['poker', { status: 'stopped', provider: pokerProvider() }]])), {
    ok: false,
    status: 503,
    error: 'Poker service is not running (status=stopped)'
  })

  t.alike(resolvePokerServiceProvider(nodeWithServices([['poker', { status: 'running', provider: {} }]])), {
    ok: false,
    status: 503,
    error: 'Poker service does not expose the substrate methods'
  })

  const provider = pokerProvider()
  const entry = { status: 'running', provider }
  const resolved = resolvePokerServiceProvider(nodeWithServices([['poker', entry]]))
  t.is(resolved.ok, true)
  t.is(resolved.provider, provider)
  t.is(resolved.entry, entry)

  const direct = pokerProvider()
  const directResolved = resolvePokerServiceProvider(nodeWithServices([['poker', direct]]))
  t.is(directResolved.ok, true)
  t.is(directResolved.provider, direct)
  t.is(directResolved.entry, direct)
})

test('api service provider: outboxlog lookup preserves sync and swarm contract', (t) => {
  t.alike(resolveOutboxLogServiceProvider({ serviceRegistry: null }), {
    ok: false,
    status: 503,
    error: 'OutboxLog service is not enabled on this relay'
  })

  t.alike(resolveOutboxLogServiceProvider(nodeWithServices([['outboxlog', { status: 'stopped', provider: outboxLogProvider() }]])), {
    ok: false,
    status: 503,
    error: 'OutboxLog service is not running (status=stopped)'
  })

  t.alike(resolveOutboxLogServiceProvider(nodeWithServices([['outboxlog', { status: 'running', provider: { sync: { create () {} }, swarm: outboxLogProvider().swarm } }]])), {
    ok: false,
    status: 503,
    error: 'OutboxLog service does not expose sync methods'
  })

  t.alike(resolveOutboxLogServiceProvider(nodeWithServices([['outboxlog', { status: 'running', provider: { sync: outboxLogProvider().sync, swarm: { join () {} } } }]])), {
    ok: false,
    status: 503,
    error: 'OutboxLog service does not expose swarm methods'
  })

  const provider = outboxLogProvider()
  const entry = { status: 'running', provider }
  const resolved = resolveOutboxLogServiceProvider(nodeWithServices([['outboxlog', entry]]))
  t.is(resolved.ok, true)
  t.is(resolved.provider, provider)
  t.is(resolved.entry, entry)
})

test('api service provider: notify lookup preserves readiness and method-shape contract', (t) => {
  t.alike(resolveNotifyServiceProvider({ serviceRegistry: null }), {
    ok: false,
    status: 503,
    error: 'Notify service is not enabled on this relay'
  })

  t.alike(resolveNotifyServiceProvider(nodeWithServices([['notify', { status: 'stopped', provider: notifyProvider() }]])), {
    ok: false,
    status: 503,
    error: 'Notify service is not running (status=stopped)'
  })

  t.alike(resolveNotifyServiceProvider(nodeWithServices([['notify', { status: 'running', provider: { manifest () {} } }]])), {
    ok: false,
    status: 503,
    error: 'Notify service does not expose service methods'
  })

  const provider = notifyProvider()
  const entry = { status: 'running', provider }
  const resolved = resolveNotifyServiceProvider(nodeWithServices([['notify', entry]]))
  t.is(resolved.ok, true)
  t.is(resolved.provider, provider)
  t.is(resolved.entry, entry)
})
