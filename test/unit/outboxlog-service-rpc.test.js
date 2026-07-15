import test from 'brittle'
import { ServiceRegistry } from '../../packages/core/core/services/registry.js'
import { OutboxLogApp } from '../../packages/services/builtin/outboxlog/index.js'

const APP = 'a'.repeat(64)

test('outboxlog service: existing sync surface is callable over service RPC', async t => {
  const app = new OutboxLogApp({ verifyAppend: () => true, persistence: false, namespaces: { p2poker: { blind: false } } })
  const registry = new ServiceRegistry()
  registry.register(app)
  await registry.startAll({})
  t.teardown(() => registry.stopAll())

  const manifest = app.manifest()
  for (const method of ['create', 'append', 'get', 'range', 'directory']) {
    t.ok(manifest.capabilities.includes(method), `${method} is feature-discoverable`)
  }

  const created = await registry.handleRequest('outboxlog', 'create', { appId: APP, namespace: 'p2poker' }, {})
  t.is(created.appId, APP, 'create accepts the object-shaped RPC convention')

  const record = { id: APP, kind: 'table-ad', _ns: 'p2poker' }
  t.alike(
    await registry.handleRequest('outboxlog', 'append', { appId: APP, op: { type: 'head', data: record } }, {}),
    { ok: true, key: 'head!' + APP },
    'append reaches the existing verified sync engine'
  )
  t.alike(await registry.handleRequest('outboxlog', 'get', { appId: APP, key: 'head!' + APP }, {}), record)
  t.is((await registry.handleRequest('outboxlog', 'range', { appId: APP, opts: { prefix: 'head!' } }, {})).length, 1)
  t.is((await registry.handleRequest('outboxlog', 'directory', { limit: 10 }, {})).count, 1)
})

test('outboxlog service: operator-only methods remain unavailable over service RPC', async t => {
  const app = new OutboxLogApp({ verifyAppend: () => true, persistence: false, namespaces: { p2poker: { blind: false } } })
  const registry = new ServiceRegistry()
  registry.register(app)
  await registry.startAll({})
  t.teardown(() => registry.stopAll())

  await t.exception(
    () => registry.handleRequest('outboxlog', 'takedown', { appId: APP, key: 'x' }, {}),
    /METHOD_NOT_ALLOWED/,
    'content-blind operator controls are not exposed to anonymous peers'
  )
})
