import { formatErr } from '../error-prefixes.js'

const CONFIG_PERSIST_FAILED_MESSAGE = 'failed to persist config; check storage permissions and disk space'
const WIZARD_PERSIST_FAILED_MESSAGE = 'failed to persist wizard state; check storage permissions and disk space'

export function persistErrorMessage (err) {
  return err && err.message ? err.message : String(err || 'unknown error')
}

export function configPersistFailureResult () {
  return {
    ok: false,
    kind: 'config-persist',
    status: 500,
    payload: {
      error: formatErr('PERSIST_FAILED', CONFIG_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }
  }
}

export function wizardPersistFailureResult ({
  error,
  emit = null
} = {}) {
  if (typeof emit === 'function') {
    emit('wizard-persist-error', {
      message: persistErrorMessage(error),
      error
    })
  }

  return {
    ok: false,
    kind: 'wizard-persist',
    status: 500,
    payload: {
      error: formatErr('PERSIST_FAILED', WIZARD_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }
  }
}
