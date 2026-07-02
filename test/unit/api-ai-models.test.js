import test from 'brittle'
import {
  buildManageAIModelRegistration,
  buildManageAIModelsPayload,
  runAIModelManagementRouteAction,
  runManageAIModelRegisterAction,
  runManageAIModelRemoveAction,
  runManageAIModelsListAction,
  manageAIModelStatus,
  publicManageAIModelError,
  resolveAIModelManagementRoute
} from 'p2p-hiverelay/core/relay-node/api-ai-models.js'

test('api ai models: route helper maps exact POST model mutation routes', (t) => {
  t.alike(resolveAIModelManagementRoute('POST', '/api/manage/ai/models'), { kind: 'register' })
  t.alike(resolveAIModelManagementRoute('POST', '/api/manage/ai/models/remove'), { kind: 'remove' })

  t.is(resolveAIModelManagementRoute('GET', '/api/manage/ai/models'), null)
  t.is(resolveAIModelManagementRoute('POST', '/api/manage/ai/models/remove/extra'), null)
  t.is(resolveAIModelManagementRoute('POST', '/api/manage/ai/model'), null)
})

test('api ai models: route action helper dispatches register and remove primitives', async (t) => {
  const calls = []
  const provider = {
    async 'register-model' (params, ctx) {
      calls.push({ action: 'register', params, ctx })
      return { registered: true }
    },
    async 'remove-model' (params, ctx) {
      calls.push({ action: 'remove', params, ctx })
      return { removed: true }
    },
    async 'list-models' () {
      return [{ modelId: 'local-qvac', backend: 'qvac', qvac: { loaded: true } }]
    },
    async status () {
      return { qvac: { enabled: true, checked: true, available: true } }
    }
  }
  const node = { id: 'relay-node' }

  const registered = await runAIModelManagementRouteAction({
    route: { kind: 'register' },
    provider,
    body: { modelId: ' local-qvac ', qvac: { qvacModelId: 'loaded' } },
    node
  })
  const removed = await runAIModelManagementRouteAction({
    route: { kind: 'remove' },
    provider,
    body: { modelId: ' local-qvac ' },
    node
  })
  const unknown = await runAIModelManagementRouteAction({
    route: { kind: 'unknown' },
    provider,
    body: {}
  })

  t.is(registered.ok, true)
  t.is(registered.payload.action, 'registered')
  t.is(removed.ok, true)
  t.is(removed.payload.action, 'removed')
  t.alike(calls.map(call => call.action), ['register', 'remove'])
  t.is(calls[0].params.modelId, 'local-qvac')
  t.alike(calls[0].ctx, {
    role: 'relay-admin',
    caller: 'manage-api',
    authenticated: true,
    node
  })
  t.is(calls[1].params.modelId, 'local-qvac')
  t.is(unknown.status, 404)
  t.is(unknown.payload.error, 'unknown AI model management route')
})

test('api ai models: registration requires a model id and qvac source or loaded id', (t) => {
  t.alike(buildManageAIModelRegistration(null), { ok: false, error: 'request body required' })
  t.alike(buildManageAIModelRegistration([]), { ok: false, error: 'request body required' })
  t.alike(buildManageAIModelRegistration({}), { ok: false, error: 'modelId required' })
  t.alike(buildManageAIModelRegistration({ modelId: 'x', backend: 'http', endpoint: 'http://127.0.0.1' }), {
    ok: false,
    error: 'this endpoint only registers qvac-backed models'
  })
  t.alike(buildManageAIModelRegistration({ modelId: 'x' }), {
    ok: false,
    error: 'modelSrc or loadedModelId required for qvac model registration'
  })
})

test('api ai models: registration rejects malformed qvac option shapes', (t) => {
  const cases = [
    [{ modelId: 'x', qvac: [] }, 'qvac must be an object'],
    [{ modelId: 'x', modelSrc: '/models/a.gguf', modelConfig: [] }, 'modelConfig must be an object'],
    [{ modelId: 'x', qvac: { qvacModelId: 'loaded', loadOptions: [] } }, 'loadOptions must be an object'],
    [{ modelId: 'x', qvac: { qvacModelId: 'loaded', completionOptions: 'fast' } }, 'completionOptions must be an object'],
    [{ modelId: 'x', qvac: { qvacModelId: 'loaded', embedOptions: 3 } }, 'embedOptions must be an object'],
    [{ modelId: 'x', modelSrc: { path: '/models/a.gguf' } }, 'modelSrc must be a string'],
    [{ modelId: 'x', loadedModelId: 42 }, 'loadedModelId must be a string']
  ]

  for (const [body, error] of cases) {
    t.alike(buildManageAIModelRegistration(body), { ok: false, error })
  }
})

test('api ai models: registration normalizes top-level qvac model sources', (t) => {
  const out = buildManageAIModelRegistration({
    modelId: ' operator-qvac ',
    type: ' embeddings ',
    modelSrc: '/models/operator.gguf',
    modelType: 'llm',
    modelConfig: { ctx_size: 512 },
    delegate: 'worker-1',
    handler: () => {}
  })

  t.is(out.ok, true)
  t.absent(out.params.handler)
  t.is(out.params.modelId, 'operator-qvac')
  t.is(out.params.type, 'embeddings')
  t.is(out.params.backend, 'qvac')
  t.alike(out.params.qvac, {
    modelSrc: '/models/operator.gguf',
    loadedModelId: undefined,
    modelType: 'llm',
    modelConfig: { ctx_size: 512 },
    delegate: 'worker-1'
  })
})

test('api ai models: registration accepts nested loaded model aliases', (t) => {
  const out = buildManageAIModelRegistration({
    modelId: 'loaded',
    qvac: {
      qvacModelId: 'already-loaded',
      modelType: 'embed',
      modelConfig: { dimensions: 384 }
    }
  })

  t.is(out.ok, true)
  t.is(out.params.qvac.loadedModelId, 'already-loaded')
  t.is(out.params.qvac.modelType, 'embed')
  t.alike(out.params.qvac.modelConfig, { dimensions: 384 })
})

test('api ai models: status decoration distinguishes qvac and handler backends', (t) => {
  t.is(manageAIModelStatus({ backend: 'qvac', qvac: { loaded: true } }, { enabled: true, checked: true, available: true }), 'loaded')
  t.is(manageAIModelStatus({ backend: 'qvac', qvac: { loaded: false } }, { enabled: false }), 'disabled')
  t.is(manageAIModelStatus({ backend: 'qvac' }, { checked: true, available: false }), 'sdk-unavailable')
  t.is(manageAIModelStatus({ backend: 'qvac' }, { enabled: true, checked: true, available: true }), 'registered')
  t.is(manageAIModelStatus({ hasHandler: true }, null), 'handler-ready')
  t.is(manageAIModelStatus({ hasEndpoint: true }, null), 'http-ready')
  t.is(manageAIModelStatus({}, null), 'no-backend')
})

test('api ai models: payload decorates model list and counts qvac models', (t) => {
  const payload = buildManageAIModelsPayload([
    { modelId: 'a', backend: 'qvac', qvac: { loaded: true } },
    { modelId: 'b', hasEndpoint: true },
    { modelId: 'c', qvac: { loaded: false } }
  ], { qvac: { enabled: true, checked: true, available: true } })

  t.is(payload.ok, true)
  t.alike(payload.qvac, { enabled: true, checked: true, available: true })
  t.is(payload.count, 3)
  t.is(payload.qvacCount, 2)
  t.alike(payload.models.map(model => model.status), ['loaded', 'http-ready', 'registered'])
  t.alike(buildManageAIModelsPayload(null, null), {
    ok: true,
    qvac: null,
    count: 0,
    qvacCount: 0,
    models: []
  })
})

test('api ai models: public errors preserve stable AI codes and redact internals', (t) => {
  t.is(
    publicManageAIModelError(new Error('AI_MODEL_NOT_FOUND: local-qvac')),
    'AI_MODEL_NOT_FOUND: local-qvac'
  )
  t.is(
    publicManageAIModelError(new Error('ACCESS_DENIED: model removal requires relay-admin/local context')),
    'ACCESS_DENIED: model removal requires relay-admin/local context'
  )
  t.is(
    publicManageAIModelError(new Error('failed to read /data/models/private/key-material'), 'AI model registration failed'),
    'AI model registration failed'
  )
})

test('api ai models: list action decorates provider models and emits redacted failures', async (t) => {
  const contexts = []
  const provider = {
    async 'list-models' (params, ctx) {
      contexts.push(ctx)
      return [{ modelId: 'local-qvac', backend: 'qvac' }]
    },
    async status (params, ctx) {
      contexts.push(ctx)
      return { qvac: { enabled: true, checked: true, available: true } }
    }
  }

  const out = await runManageAIModelsListAction({ provider })
  t.is(out.ok, true)
  t.is(out.payload.count, 1)
  t.alike(contexts, [
    { role: 'relay-admin', caller: 'manage-api', authenticated: true },
    { role: 'relay-admin', caller: 'manage-api', authenticated: true }
  ])

  const events = []
  const failed = await runManageAIModelsListAction({
    provider: {
      async 'list-models' () { throw new Error('/private/models/key') }
    },
    emit: (name, event) => events.push({ name, event })
  })

  t.is(failed.ok, false)
  t.is(failed.status, 500)
  t.alike(failed.payload, { error: 'AI model list failed' })
  t.is(events[0].name, 'ai-model-error')
  t.is(events[0].event.action, 'list')
})

test('api ai models: register action validates, calls provider with node context, and returns decorated model', async (t) => {
  const node = { id: 'relay-node' }
  const calls = []
  const provider = {
    async 'register-model' (params, ctx) {
      calls.push({ params, ctx })
      return { registered: true }
    },
    async 'list-models' () {
      return [{ modelId: 'local-qvac', backend: 'qvac', qvac: { loaded: true } }]
    },
    async status () {
      return { qvac: { enabled: true, checked: true, available: true } }
    }
  }

  const invalid = await runManageAIModelRegisterAction({ provider, body: {} })
  t.alike(invalid, {
    ok: false,
    status: 400,
    payload: { error: 'modelId required' }
  })

  const out = await runManageAIModelRegisterAction({
    provider,
    body: { modelId: ' local-qvac ', qvac: { qvacModelId: 'loaded' } },
    node
  })

  t.is(out.ok, true)
  t.is(out.payload.action, 'registered')
  t.is(out.payload.model.modelId, 'local-qvac')
  t.is(out.payload.model.status, 'loaded')
  t.is(calls[0].params.modelId, 'local-qvac')
  t.alike(calls[0].ctx, {
    role: 'relay-admin',
    caller: 'manage-api',
    authenticated: true,
    node
  })
})

test('api ai models: register and remove actions preserve known errors and redact unexpected errors', async (t) => {
  const events = []
  const denied = await runManageAIModelRegisterAction({
    provider: {
      async 'register-model' () { throw new Error('ACCESS_DENIED: no') }
    },
    body: { modelId: 'local-qvac', qvac: { qvacModelId: 'loaded' } },
    emit: (name, event) => events.push({ name, event })
  })
  t.is(denied.status, 403)
  t.alike(denied.payload, { error: 'ACCESS_DENIED: no' })
  t.is(events[0].event.publicError, 'ACCESS_DENIED: no')

  const removed = await runManageAIModelRemoveAction({
    provider: {
      async 'remove-model' (params, ctx) {
        t.alike(params, { modelId: 'local-qvac' })
        t.is(ctx.node.id, 'relay-node')
        return { removed: true }
      },
      async 'list-models' () { return [] },
      async status () { return { qvac: { enabled: true } } }
    },
    body: { modelId: ' local-qvac ' },
    node: { id: 'relay-node' }
  })
  t.is(removed.ok, true)
  t.is(removed.payload.action, 'removed')
  t.is(removed.payload.removed, true)

  const failed = await runManageAIModelRemoveAction({
    provider: {
      async 'remove-model' () { throw new Error('/private/model/path') }
    },
    body: { modelId: 'local-qvac' }
  })
  t.is(failed.status, 500)
  t.alike(failed.payload, { error: 'AI model removal failed' })
})
