import { validatePayoutDestination } from '../../incentive/subsidy/index.js'
import { formatErr } from '../error-prefixes.js'

const DESTINATION_REQUIRED = 'destination (string or null) required'
const DESTINATION_UNRECOGNIZED = 'Unrecognized payout destination (expected lightning address, BOLT12 offer, or bitcoin address)'

export function subsidyDestinationFromConfig (config) {
  return validatePayoutDestination(config?.subsidy?.payoutDestination || '')
}

export function buildSubsidyStatusPayload ({ config, subsidyAccrual } = {}) {
  if (!subsidyAccrual) {
    return {
      payload: {
        enabled: false,
        payoutDestination: subsidyDestinationFromConfig(config)
      },
      status: 200
    }
  }

  const summary = typeof subsidyAccrual.getSummary === 'function'
    ? subsidyAccrual.getSummary()
    : {}

  return {
    payload: { enabled: true, ...summary },
    status: 200
  }
}

export function buildSubsidyClaimPayload ({ subsidyAccrual } = {}) {
  if (!subsidyAccrual) {
    return {
      payload: { error: formatErr('NOT_ENABLED', 'subsidy is not enabled on this relay') },
      status: 409
    }
  }

  if (typeof subsidyAccrual.buildClaim !== 'function') {
    return {
      payload: { error: formatErr('UNSUPPORTED', 'subsidy claim export unavailable') },
      status: 503
    }
  }

  return {
    payload: subsidyAccrual.buildClaim(),
    status: 200
  }
}

export function parseSubsidyDestinationUpdate (body) {
  const raw = body && Object.prototype.hasOwnProperty.call(body, 'destination')
    ? body.destination
    : undefined
  if (raw !== null && typeof raw !== 'string') {
    return { ok: false, kind: 'bad-request', message: DESTINATION_REQUIRED }
  }

  const trimmed = raw === null ? '' : raw.trim()
  const destination = raw === null || trimmed === ''
    ? null
    : validatePayoutDestination(raw)
  if (raw !== null && trimmed !== '' && !destination) {
    return { ok: false, kind: 'bad-request', message: DESTINATION_UNRECOGNIZED }
  }

  return {
    ok: true,
    destination,
    value: destination ? destination.value : null,
    wizardAddress: destination ? destination.value : ''
  }
}

export function snapshotSubsidyConfig (config) {
  const hadSubsidyConfig = !!(config && config.subsidy && typeof config.subsidy === 'object')
  return {
    hadSubsidyConfig,
    subsidyConfig: hadSubsidyConfig ? { ...config.subsidy } : undefined
  }
}

export function restoreSubsidyConfig (config, snapshot) {
  if (!config || !snapshot) return
  if (snapshot.hadSubsidyConfig) config.subsidy = snapshot.subsidyConfig
  else delete config.subsidy
}

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

async function saveWizardRollback (wizard, wizardSaved, emit) {
  if (!wizardSaved || !wizard) return
  try {
    await wizard.save()
  } catch (err) {
    emitRollbackError(emit, 'wizard-rollback-error', err)
  }
}

export async function updateSubsidyDestination ({
  body,
  config,
  wizard = null,
  subsidyAccrual = null,
  persistConfig = async () => {},
  emit = null
}) {
  const parsed = parseSubsidyDestinationUpdate(body)
  if (!parsed.ok) return parsed

  const subsidySnapshot = snapshotSubsidyConfig(config)
  const wizardSnapshot = snapshotWizardState(wizard)
  let wizardSaved = false

  const restoreRuntime = () => {
    restoreSubsidyConfig(config, subsidySnapshot)
    restoreWizardState(wizard, wizardSnapshot)
  }

  if (!config.subsidy || typeof config.subsidy !== 'object') {
    config.subsidy = {}
  }
  config.subsidy.payoutDestination = parsed.value

  if (wizard) {
    const result = wizard.setPayoutDestination({ address: parsed.wizardAddress })
    if (!result.ok) {
      restoreRuntime()
      return { ok: false, kind: 'bad-request', message: result.reason }
    }
    try {
      await wizard.save()
      wizardSaved = true
    } catch (err) {
      restoreRuntime()
      return { ok: false, kind: 'wizard-persist', error: err }
    }
  }

  try {
    await persistConfig()
  } catch (err) {
    restoreRuntime()
    await saveWizardRollback(wizard, wizardSaved, emit)
    return { ok: false, kind: 'config-persist', error: err }
  }

  let liveDestination = parsed.destination
  if (subsidyAccrual) {
    try {
      liveDestination = await subsidyAccrual.setPayoutDestination(parsed.value)
    } catch (err) {
      restoreRuntime()
      await saveWizardRollback(wizard, wizardSaved, emit)
      try {
        await persistConfig()
      } catch (rollbackErr) {
        emitRollbackError(emit, 'config-rollback-error', rollbackErr)
      }
      return { ok: false, kind: 'subsidy-persist', error: err }
    }
  }

  return {
    ok: true,
    payload: {
      ok: true,
      enabled: !!subsidyAccrual,
      payoutDestination: liveDestination
    }
  }
}
