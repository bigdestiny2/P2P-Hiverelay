import test from 'brittle'
import { AIService } from 'p2p-hiveservices/builtin/ai-service.js'
import { ServiceRegistry } from 'p2p-hiverelay/core/services/registry.js'

const smoke = process.env.HIVERELAY_QVAC_SMOKE === '1' ? test : test.skip

smoke('QVAC smoke - local qvac model is reachable through HiveRelay AIService', async (t) => {
  let sdk
  try {
    sdk = await import('@qvac/sdk')
  } catch (err) {
    t.fail(`@qvac/sdk is required for smoke test: ${err.message}`)
    return
  }

  const modelSrc = resolveModelSrc(sdk)
  if (!modelSrc) {
    t.fail('Set HIVERELAY_QVAC_MODEL_SRC or HIVERELAY_QVAC_MODEL_CONSTANT for the qvac smoke test')
    return
  }

  const registry = new ServiceRegistry({ metering: false })
  const ai = new AIService({ qvac: { sdk } })
  registry.register(ai)
  await registry.startAll({})
  t.teardown(() => registry.stopAll())

  const modelId = process.env.HIVERELAY_QVAC_MODEL_ID || 'qvac-smoke'
  const modelType = process.env.HIVERELAY_QVAC_MODEL_TYPE || 'llm'
  const modelConfig = parseJsonEnv('HIVERELAY_QVAC_MODEL_CONFIG') || {}
  const prompt = process.env.HIVERELAY_QVAC_PROMPT || 'Reply with the word HiveRelay.'

  await registry.handleRequest('ai', 'register-model', {
    modelId,
    type: 'llm',
    backend: 'qvac',
    modelSrc,
    modelType,
    modelConfig
  }, { role: 'local' })

  const list = await registry.handleRequest('ai', 'list-models', {}, { role: 'anonymous' })
  t.ok(list.find(m => m.modelId === modelId && m.backend === 'qvac'), 'qvac model is listed through ai.list-models')

  const result = await registry.handleRequest('ai', 'infer', {
    modelId,
    input: prompt,
    options: {
      qvac: parseJsonEnv('HIVERELAY_QVAC_COMPLETION_OPTIONS') || {}
    }
  }, { role: 'authenticated-user', remotePubkey: 'qvac-smoke' })

  t.is(result.state, 'complete', result.error || 'qvac inference completed')
  t.ok(result.result?.text && result.result.text.length > 0, 'qvac returned completion text through ai.infer')
  t.is(result.result.backend, 'qvac')
})

function resolveModelSrc (sdk) {
  if (process.env.HIVERELAY_QVAC_MODEL_SRC) return process.env.HIVERELAY_QVAC_MODEL_SRC
  const constant = process.env.HIVERELAY_QVAC_MODEL_CONSTANT
  if (!constant) return null
  return sdk[constant] || null
}

function parseJsonEnv (name) {
  const value = process.env[name]
  if (!value) return null
  try {
    return JSON.parse(value)
  } catch (err) {
    throw new Error(`${name} must be valid JSON: ${err.message}`)
  }
}
