const WIZARD_ACTION_PREFIX = '/api/wizard/'
const WIZARD_SNAPSHOT_ROUTE = '/api/wizard'
const WIZARD_AUTH_MESSAGE = 'Unauthorized — wizard requires API key or localhost'

function snapshotWizardState (wizard) {
  if (!wizard || !wizard.state) return null
  return { ...wizard.state }
}

function restoreWizardState (wizard, snapshot) {
  if (wizard && snapshot) wizard.state = { ...snapshot }
}

function emitRollbackError (emit, event, error) {
  if (typeof emit !== 'function') return
  emit(event, {
    message: error && error.message ? error.message : String(error || 'unknown error'),
    error
  })
}

async function persistConfigRollback ({ persistConfig, emit }) {
  try {
    await persistConfig()
  } catch (err) {
    emitRollbackError(emit, 'config-rollback-error', err)
  }
}

export function wizardActionFromPath (path) {
  return typeof path === 'string' && path.startsWith(WIZARD_ACTION_PREFIX)
    ? path.slice(WIZARD_ACTION_PREFIX.length)
    : null
}

export function resolveWizardSnapshotRoute (method, path) {
  if (method !== 'GET') return null
  if (path === WIZARD_SNAPSHOT_ROUTE) {
    return { kind: 'wizard-snapshot', authMessage: WIZARD_AUTH_MESSAGE }
  }
  return null
}

export async function buildWizardSnapshotRoutePayload ({ route, getWizard }) {
  if (!route || route.kind !== 'wizard-snapshot') {
    return {
      ok: false,
      status: 404,
      payload: { error: 'unknown wizard snapshot route' }
    }
  }

  const wizard = typeof getWizard === 'function' ? await getWizard() : null
  if (!wizard || typeof wizard.snapshot !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'wizard unavailable' }
    }
  }

  return {
    ok: true,
    payload: wizard.snapshot()
  }
}

export async function runWizardAction ({
  wizard,
  action,
  body,
  applyConfig = null,
  persistConfig = async () => {},
  snapshotConfig = null,
  restoreConfig = null,
  emit = null
}) {
  const wizardSnapshot = snapshotWizardState(wizard)
  const configSnapshot = action === 'complete' && typeof snapshotConfig === 'function'
    ? snapshotConfig()
    : null
  const restoreRuntime = () => {
    restoreWizardState(wizard, wizardSnapshot)
    if (configSnapshot && typeof restoreConfig === 'function') restoreConfig(configSnapshot)
  }

  let result
  let configPersisted = false

  switch (action) {
    case 'goto':
      result = wizard.goToStep({ step: body && body.step })
      break
    case 'relay-name':
      result = wizard.setRelayName({ relayName: body && body.relayName })
      break
    case 'payout':
      result = wizard.setPayoutDestination({ address: body && body.address })
      break
    case 'accept-mode':
      result = wizard.setAcceptMode({ acceptMode: body && body.acceptMode })
      break
    case 'complete':
      result = wizard.complete()
      if (result.ok && typeof applyConfig === 'function') {
        try {
          applyConfig(wizard.toConfig())
        } catch (err) {
          restoreRuntime()
          return { ok: false, kind: 'apply-config', error: err }
        }
        try {
          await persistConfig()
          configPersisted = true
        } catch (err) {
          restoreRuntime()
          return { ok: false, kind: 'config-persist', error: err }
        }
      }
      break
    case 'reset':
      wizard.reset()
      result = { ok: true, state: wizard.snapshot() }
      break
    default:
      return { ok: false, kind: 'not-found', message: 'unknown wizard action: ' + action }
  }

  if (!result.ok) {
    restoreWizardState(wizard, wizardSnapshot)
    return { ok: false, kind: 'bad-request', message: result.reason }
  }

  try {
    await wizard.save()
  } catch (err) {
    restoreRuntime()
    if (configPersisted) {
      await persistConfigRollback({ persistConfig, emit })
    }
    return { ok: false, kind: 'wizard-persist', error: err }
  }

  return { ok: true, payload: { ok: true, state: result.state } }
}
