import test from 'brittle'
import {
  buildManageAIModelRegistration,
  buildManageAIModelsPayload,
  manageAIModelStatus,
  publicManageAIModelError
} from 'p2p-hiverelay/core/relay-node/api-ai-models.js'

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
