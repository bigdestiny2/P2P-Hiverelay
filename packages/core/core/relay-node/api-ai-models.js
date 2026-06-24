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

export function publicManageAIModelError (err, fallback = 'AI model operation failed') {
  const message = err && err.message ? err.message : String(err || '')
  const code = message.split(':', 1)[0]
  if (PUBLIC_AI_MODEL_ERROR_CODES.has(code)) return message
  return fallback
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
