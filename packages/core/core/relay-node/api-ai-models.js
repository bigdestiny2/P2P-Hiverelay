function objectRecord (value) {
  return value && typeof value === 'object' && !Array.isArray(value)
}

function optionalObjectField (value, name) {
  if (value === undefined || value === null) return { ok: true, value: {} }
  if (!objectRecord(value)) return { ok: false, error: `${name} must be an object` }
  return { ok: true, value }
}

const PUBLIC_AI_MODEL_ERROR_CODES = new Set([
  'ACCESS_DENIED',
  'AI_CALLER_QUEUE_FULL',
  'AI_INVALID_ENDPOINT',
  'AI_MISSING_PARAMS',
  'AI_MODEL_EXISTS',
  'AI_MODEL_NOT_FOUND',
  'AI_NO_BACKEND',
  'AI_QVAC_MODEL_NOT_CONFIGURED',
  'AI_QVAC_UNAVAILABLE',
  'AI_QVAC_UNSUPPORTED',
  'AI_QUEUE_FULL',
  'AI_WRONG_TYPE'
])
const AI_MODEL_MANAGEMENT_ROUTES = Object.freeze({
  'POST /api/manage/ai/models': Object.freeze({ kind: 'register' }),
  'POST /api/manage/ai/models/remove': Object.freeze({ kind: 'remove' })
})

export function resolveAIModelManagementRoute (method, path) {
  const route = AI_MODEL_MANAGEMENT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function publicManageAIModelError (err, fallback = 'AI model operation failed') {
  const message = err && err.message ? err.message : String(err || '')
  const code = message.split(':', 1)[0]
  if (PUBLIC_AI_MODEL_ERROR_CODES.has(code)) return message
  return fallback
}

export async function runManageAIModelsListAction ({
  provider,
  emit = null
} = {}) {
  try {
    return {
      ok: true,
      payload: await buildManageAIModelsProviderPayload(provider)
    }
  } catch (err) {
    const error = publicManageAIModelError(err, 'AI model list failed')
    emitManageAIModelError(emit, { action: 'list', err })
    return {
      ok: false,
      status: 500,
      payload: { error }
    }
  }
}

export async function runManageAIModelRegisterAction ({
  provider,
  body,
  node = null,
  emit = null
} = {}) {
  const request = buildManageAIModelRegistration(body)
  if (!request.ok) {
    return {
      ok: false,
      status: 400,
      payload: { error: request.error }
    }
  }

  try {
    const result = await provider['register-model'](request.params, manageAIModelProviderContext({ node }))
    const payload = await buildManageAIModelsProviderPayload(provider)
    const model = payload.models.find(m => m.modelId === request.params.modelId) || null
    return {
      ok: true,
      payload: {
        ok: true,
        action: 'registered',
        ...result,
        model,
        qvac: payload.qvac
      }
    }
  } catch (err) {
    const message = publicManageAIModelError(err, 'AI model registration failed')
    const status = manageAIModelErrorStatus(message, 'AI model registration failed')
    emitManageAIModelError(emit, { action: 'register', err, publicError: message })
    return {
      ok: false,
      status,
      payload: { error: message }
    }
  }
}

export async function runManageAIModelRemoveAction ({
  provider,
  body,
  node = null,
  emit = null
} = {}) {
  const modelId = body && typeof body.modelId === 'string' ? body.modelId.trim() : ''
  if (!modelId) {
    return {
      ok: false,
      status: 400,
      payload: { error: 'modelId required' }
    }
  }

  try {
    const result = await provider['remove-model']({ modelId }, manageAIModelProviderContext({ node }))
    const payload = await buildManageAIModelsProviderPayload(provider)
    return {
      ok: true,
      payload: {
        ok: true,
        action: 'removed',
        modelId,
        removed: !!result.removed,
        qvac: payload.qvac,
        count: payload.count,
        qvacCount: payload.qvacCount
      }
    }
  } catch (err) {
    const message = publicManageAIModelError(err, 'AI model removal failed')
    const status = manageAIModelErrorStatus(message, 'AI model removal failed')
    emitManageAIModelError(emit, { action: 'remove', err, publicError: message })
    return {
      ok: false,
      status,
      payload: { error: message }
    }
  }
}

export async function runAIModelManagementRouteAction ({
  route,
  provider,
  body,
  node = null,
  emit = null
} = {}) {
  const kind = route && route.kind
  if (kind === 'register') {
    return runManageAIModelRegisterAction({ provider, body, node, emit })
  }
  if (kind === 'remove') {
    return runManageAIModelRemoveAction({ provider, body, node, emit })
  }
  return {
    ok: false,
    status: 404,
    payload: { error: 'unknown AI model management route' }
  }
}

export async function buildManageAIModelsProviderPayload (provider) {
  const models = await provider['list-models']({}, manageAIModelProviderContext())
  const status = typeof provider.status === 'function'
    ? await provider.status({}, manageAIModelProviderContext())
    : null
  return buildManageAIModelsPayload(models, status)
}

export function buildManageAIModelRegistration (body) {
  if (!objectRecord(body)) {
    return { ok: false, error: 'request body required' }
  }
  const modelId = typeof body.modelId === 'string' ? body.modelId.trim() : ''
  if (!modelId) return { ok: false, error: 'modelId required' }

  const type = typeof body.type === 'string' && body.type.trim() ? body.type.trim() : 'llm'
  const qvacField = optionalObjectField(body.qvac, 'qvac')
  if (!qvacField.ok) return qvacField
  const qvacBody = qvacField.value

  const modelConfigField = optionalObjectField(
    body.modelConfig !== undefined ? body.modelConfig : qvacBody.modelConfig,
    'modelConfig'
  )
  if (!modelConfigField.ok) return modelConfigField

  for (const field of ['loadOptions', 'completionOptions', 'embedOptions']) {
    const optionField = optionalObjectField(qvacBody[field], field)
    if (!optionField.ok) return optionField
  }

  if (body.backend && body.backend !== 'qvac') {
    return { ok: false, error: 'this endpoint only registers qvac-backed models' }
  }

  const modelSrc = body.modelSrc !== undefined ? body.modelSrc : qvacBody.modelSrc
  const loadedModelId = body.loadedModelId !== undefined
    ? body.loadedModelId
    : (body.qvacModelId !== undefined ? body.qvacModelId : (qvacBody.loadedModelId ?? qvacBody.qvacModelId))
  if (modelSrc !== undefined && modelSrc !== null && modelSrc !== '' && typeof modelSrc !== 'string') {
    return { ok: false, error: 'modelSrc must be a string' }
  }
  if (loadedModelId !== undefined && loadedModelId !== null && loadedModelId !== '' && typeof loadedModelId !== 'string') {
    return { ok: false, error: 'loadedModelId must be a string' }
  }
  if ((modelSrc === undefined || modelSrc === null || modelSrc === '') &&
      (loadedModelId === undefined || loadedModelId === null || loadedModelId === '')) {
    return { ok: false, error: 'modelSrc or loadedModelId required for qvac model registration' }
  }

  const qvac = {
    ...qvacBody,
    modelSrc,
    loadedModelId,
    modelType: body.modelType ?? qvacBody.modelType ?? type,
    modelConfig: modelConfigField.value,
    delegate: body.delegate ?? qvacBody.delegate ?? null
  }

  const params = {
    ...body,
    modelId,
    type,
    backend: 'qvac',
    qvac
  }
  delete params.handler

  return { ok: true, params }
}

export function manageAIModelStatus (model, qvacStatus) {
  if (model.backend === 'qvac' || model.qvac) {
    if (model.qvac && model.qvac.loaded) return 'loaded'
    if (qvacStatus && qvacStatus.enabled === false) return 'disabled'
    if (qvacStatus && qvacStatus.checked && qvacStatus.available === false) return 'sdk-unavailable'
    return 'registered'
  }
  if (model.hasHandler) return 'handler-ready'
  if (model.hasEndpoint) return 'http-ready'
  return 'no-backend'
}

export function buildManageAIModelsPayload (models, providerStatus) {
  const qvac = providerStatus && providerStatus.qvac ? providerStatus.qvac : null
  const decorated = (Array.isArray(models) ? models : []).map(model => ({
    ...model,
    status: manageAIModelStatus(model, qvac)
  }))
  return {
    ok: true,
    qvac,
    count: decorated.length,
    qvacCount: decorated.filter(model => model.backend === 'qvac' || model.qvac).length,
    models: decorated
  }
}

function manageAIModelProviderContext ({ node = null } = {}) {
  const context = {
    role: 'relay-admin',
    caller: 'manage-api',
    authenticated: true
  }
  if (node) context.node = node
  return context
}

function manageAIModelErrorStatus (message, fallback) {
  if (message === fallback) return 500
  return message.startsWith('ACCESS_DENIED') ? 403 : 400
}

function emitManageAIModelError (emit, { action, err, publicError = null }) {
  if (typeof emit !== 'function') return
  const event = {
    action,
    error: err && err.message ? err.message : String(err || 'unknown error')
  }
  if (publicError) event.publicError = publicError
  emit('ai-model-error', event)
}
