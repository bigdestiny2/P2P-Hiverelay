/**
 * HiveRelay CLI - `qvac` model management.
 *
 * Operator-facing wrappers around /api/manage/ai/models. This avoids
 * hand-written ai.register-model / ai.remove-model dispatch calls while
 * keeping the relay's management API auth boundary in place.
 */

import {
  resolveApiUrl, resolveApiKey, performRequest
} from './catalog.js'

const VALID_MODEL_TYPES = ['llm', 'embedding', 'classification', 'image', 'custom']

export const QVAC_HELP = `Usage:
  hiverelay qvac list
  hiverelay qvac register <modelId> --model-src <path-or-id> [--type <kind>]
  hiverelay qvac register <modelId> --loaded-model-id <id> [--type <kind>]
  hiverelay qvac remove <modelId>

Options:
  --api-url <url>              Relay API base URL (default: http://127.0.0.1:9100)
  --api-key <key>              API key (or use HIVERELAY_API_KEY env)
  --type <kind>                llm | embedding | classification | image | custom (default: llm)
  --model-src <path-or-id>     qvac model source passed to @qvac/sdk loadModel
  --loaded-model-id <id>       Existing qvac-loaded model id
  --model-type <kind>          qvac model type override
  --model-config <json>        JSON object passed as qvac modelConfig
  --load-options <json>        JSON object merged into qvac load options
  --completion-options <json>  JSON object merged into qvac completion options
  --embed-options <json>       JSON object merged into qvac embed options
  --delegate <id>              qvac delegate id
  --endpoint <url>             Optional HTTP fallback endpoint
  --no-fallback-http           Disable HTTP fallback when qvac is unavailable
`

function normalizeSubcommand (subcommand) {
  if (subcommand === 'ls') return 'list'
  if (subcommand === 'add') return 'register'
  if (subcommand === 'rm') return 'remove'
  return subcommand
}

function option (argv, kebab, camel) {
  if (argv[kebab] !== undefined) return argv[kebab]
  if (camel && argv[camel] !== undefined) return argv[camel]
  return undefined
}

function parseJsonObjectOption (argv, key, label) {
  const value = option(argv, key)
  if (value === undefined) return undefined
  let parsed
  try {
    parsed = typeof value === 'string' ? JSON.parse(value) : value
  } catch (err) {
    throw new Error(label + ' must be valid JSON: ' + err.message)
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(label + ' must be a JSON object')
  }
  return parsed
}

export function buildQvacRequest (subcommandRaw, positional, argv = {}) {
  const subcommand = normalizeSubcommand(subcommandRaw)

  switch (subcommand) {
    case 'list':
      return { method: 'GET', path: '/api/manage/ai/models', body: null }

    case 'register': {
      const modelId = positional[0]
      if (!modelId || typeof modelId !== 'string') {
        throw new Error('modelId required')
      }

      const type = String(option(argv, 'type') || positional[1] || 'llm')
      if (!VALID_MODEL_TYPES.includes(type)) {
        throw new Error('--type must be one of: ' + VALID_MODEL_TYPES.join(', '))
      }

      const modelSrc = option(argv, 'model-src', 'modelSrc')
      const loadedModelId = option(argv, 'loaded-model-id', 'loadedModelId') ||
        option(argv, 'qvac-model-id', 'qvacModelId')
      if (!modelSrc && !loadedModelId) {
        throw new Error('register requires --model-src or --loaded-model-id')
      }

      const body = {
        modelId,
        type,
        backend: 'qvac'
      }
      if (modelSrc !== undefined) body.modelSrc = String(modelSrc)
      if (loadedModelId !== undefined) body.loadedModelId = String(loadedModelId)

      const modelType = option(argv, 'model-type', 'modelType')
      if (modelType !== undefined) body.modelType = String(modelType)

      const delegate = option(argv, 'delegate')
      if (delegate !== undefined) body.delegate = String(delegate)

      const endpoint = option(argv, 'endpoint')
      if (endpoint !== undefined) body.endpoint = String(endpoint)

      const modelConfig = parseJsonObjectOption(argv, 'model-config', '--model-config')
      if (modelConfig !== undefined) body.modelConfig = modelConfig

      const qvac = {}
      const loadOptions = parseJsonObjectOption(argv, 'load-options', '--load-options')
      if (loadOptions !== undefined) qvac.loadOptions = loadOptions
      const completionOptions = parseJsonObjectOption(argv, 'completion-options', '--completion-options')
      if (completionOptions !== undefined) qvac.completionOptions = completionOptions
      const embedOptions = parseJsonObjectOption(argv, 'embed-options', '--embed-options')
      if (embedOptions !== undefined) qvac.embedOptions = embedOptions
      if (argv['fallback-http'] === false) qvac.fallbackToHttp = false
      if (Object.keys(qvac).length > 0) body.qvac = qvac

      return { method: 'POST', path: '/api/manage/ai/models', body }
    }

    case 'remove': {
      const modelId = positional[0]
      if (!modelId || typeof modelId !== 'string') {
        throw new Error('modelId required')
      }
      return {
        method: 'POST',
        path: '/api/manage/ai/models/remove',
        body: { modelId }
      }
    }

    default:
      throw new Error('Unknown qvac subcommand: ' + subcommandRaw)
  }
}

function sdkStatusLabel (qvac) {
  if (!qvac) return 'unknown'
  if (qvac.enabled === false) return 'disabled'
  if (qvac.checked && qvac.available === false) return 'unavailable'
  if (qvac.available === true) return 'available'
  return 'not checked'
}

function modelStatusLabel (model) {
  if (model.status) return model.status
  if (model.qvac?.loaded) return 'loaded'
  if (model.backend === 'qvac' || model.qvac) return 'registered'
  if (model.hasHandler) return 'handler-ready'
  if (model.hasEndpoint) return 'http-ready'
  return 'unknown'
}

export function formatQvacModelList (payload) {
  const qvac = payload?.qvac || null
  const models = Array.isArray(payload?.models)
    ? payload.models.filter(model => model.backend === 'qvac' || model.qvac)
    : []
  const lines = []
  const moduleName = qvac?.module ? ' module:' + qvac.module : ''
  const error = qvac?.error ? ' error:' + qvac.error : ''
  lines.push('QVAC SDK: ' + sdkStatusLabel(qvac) + moduleName + error)

  if (models.length === 0) {
    lines.push('No qvac models registered.')
    return lines.join('\n')
  }

  lines.push('QVAC models: ' + models.length)
  for (const model of models) {
    const stats = model.stats || {}
    const q = model.qvac || {}
    const loaded = q.loaded ? 'yes' : 'no'
    const delegated = q.delegated ? 'yes' : 'no'
    const src = q.hasModelSrc ? 'yes' : 'no'
    lines.push(
      '  ' + model.modelId +
      '  type:' + (model.type || 'unknown') +
      '  status:' + modelStatusLabel(model) +
      '  loaded:' + loaded +
      '  modelSrc:' + src +
      '  delegated:' + delegated +
      '  requests:' + (stats.requests || 0) +
      '  errors:' + (stats.errors || 0)
    )
  }
  return lines.join('\n')
}

export async function runQvacCommand ({
  argv,
  positional,
  env = process.env,
  fetchImpl,
  out = (msg) => console.log(msg),
  err = (msg) => console.error(msg)
}) {
  const subcommandRaw = positional[0]
  if (!subcommandRaw || subcommandRaw === 'help' || argv.help) {
    out(QVAC_HELP)
    return 0
  }
  const subcommand = normalizeSubcommand(subcommandRaw)

  let apiUrl
  try {
    apiUrl = resolveApiUrl(argv)
  } catch (e) {
    err(e.message)
    return 1
  }
  const apiKey = resolveApiKey(argv, env)

  let request
  try {
    request = buildQvacRequest(subcommand, positional.slice(1), argv)
  } catch (e) {
    err(e.message)
    return 1
  }

  let payload
  try {
    payload = await performRequest({
      apiUrl, apiKey, method: request.method, path: request.path, body: request.body, fetchImpl
    })
  } catch (e) {
    err('qvac ' + subcommand + ' failed: ' + e.message)
    return 1
  }

  if (subcommand === 'list') {
    out(formatQvacModelList(payload))
    return 0
  }

  if (subcommand === 'register') {
    const status = payload?.model ? modelStatusLabel(payload.model) : 'registered'
    out('OK - qvac model registered: ' + request.body.modelId + ' status:' + status)
  } else if (subcommand === 'remove') {
    out('OK - qvac model removed: ' + request.body.modelId + (payload?.removed ? '' : ' (no-op)'))
  }
  return 0
}
