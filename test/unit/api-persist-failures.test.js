import test from 'brittle'
import {
  configPersistFailureResult,
  persistErrorMessage,
  wizardPersistFailureResult
} from '../../packages/core/core/relay-node/api-persist-failures.js'

test('api persist failures: config mapper returns stable public payload', (t) => {
  const result = configPersistFailureResult()

  t.is(result.ok, false)
  t.is(result.kind, 'config-persist')
  t.is(result.status, 500)
  t.is(result.payload.errorCode, 'persist-failed')
  t.is(result.payload.error, 'persist-failed: failed to persist config; check storage permissions and disk space')
})

test('api persist failures: wizard mapper emits internal diagnostics', (t) => {
  const err = new Error('wizard disk full')
  const events = []
  const result = wizardPersistFailureResult({
    error: err,
    emit: (event, payload) => events.push({ event, payload })
  })

  t.is(result.ok, false)
  t.is(result.kind, 'wizard-persist')
  t.is(result.status, 500)
  t.is(result.payload.errorCode, 'persist-failed')
  t.ok(result.payload.error.startsWith('persist-failed: '))
  t.absent(result.payload.error.includes('wizard disk full'), 'public payload does not leak local storage error')
  t.alike(events, [{
    event: 'wizard-persist-error',
    payload: {
      message: 'wizard disk full',
      error: err
    }
  }])
})

test('api persist failures: diagnostic message helper is stable for unusual throws', (t) => {
  t.is(persistErrorMessage(new Error('boom')), 'boom')
  t.is(persistErrorMessage('plain failure'), 'plain failure')
  t.is(persistErrorMessage(null), 'unknown error')
})
