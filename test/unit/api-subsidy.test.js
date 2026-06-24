import test from 'brittle'
import {
  buildSubsidyClaimPayload,
  buildSubsidyStatusPayload,
  parseSubsidyDestinationUpdate,
  subsidyDestinationFromConfig,
  updateSubsidyDestination
} from 'p2p-hiverelay/core/relay-node/api-subsidy.js'

function makeWizard (opts = {}) {
  return {
    state: { step: 'payout', payoutDestination: opts.payoutDestination || 'old@example.com' },
    saves: 0,
    setPayoutDestination ({ address }) {
      if (opts.reject) return { ok: false, reason: opts.reject }
      this.state = { ...this.state, payoutDestination: address || null }
      return { ok: true, state: { ...this.state } }
    },
    async save () {
      this.saves++
      if (opts.saveError) throw opts.saveError
    }
  }
}

test('api subsidy: destination parser requires string or null and normalizes rails', (t) => {
  t.alike(parseSubsidyDestinationUpdate({}), {
    ok: false,
    kind: 'bad-request',
    message: 'destination (string or null) required'
  })
  t.alike(parseSubsidyDestinationUpdate({ destination: 123 }), {
    ok: false,
    kind: 'bad-request',
    message: 'destination (string or null) required'
  })
  t.alike(parseSubsidyDestinationUpdate({ destination: 'not a destination' }), {
    ok: false,
    kind: 'bad-request',
    message: 'Unrecognized payout destination (expected lightning address, BOLT12 offer, or bitcoin address)'
  })
  t.alike(parseSubsidyDestinationUpdate({ destination: null }), {
    ok: true,
    destination: null,
    value: null,
    wizardAddress: ''
  })
  t.alike(parseSubsidyDestinationUpdate({ destination: ' Operator@Example.com ' }), {
    ok: true,
    destination: { type: 'lightning-address', value: 'operator@example.com' },
    value: 'operator@example.com',
    wizardAddress: 'operator@example.com'
  })
  t.alike(subsidyDestinationFromConfig({
    subsidy: { payoutDestination: 'Operator@Example.com' }
  }), { type: 'lightning-address', value: 'operator@example.com' })
})

test('api subsidy: status payload is shaped for disabled and enabled accrual', (t) => {
  const disabled = buildSubsidyStatusPayload({
    config: { subsidy: { payoutDestination: 'Operator@Example.com' } }
  })
  t.is(disabled.status, 200)
  t.alike(disabled.payload, {
    enabled: false,
    payoutDestination: { type: 'lightning-address', value: 'operator@example.com' }
  })

  const enabled = buildSubsidyStatusPayload({
    subsidyAccrual: {
      getSummary () {
        return {
          payoutDestination: { type: 'bolt12-offer', value: 'lno1example' },
          accruedSats: 42
        }
      }
    }
  })
  t.is(enabled.status, 200)
  t.alike(enabled.payload, {
    enabled: true,
    payoutDestination: { type: 'bolt12-offer', value: 'lno1example' },
    accruedSats: 42
  })

  t.alike(buildSubsidyStatusPayload({ subsidyAccrual: {} }).payload, { enabled: true })
})

test('api subsidy: claim payload reports disabled and unavailable exporters without throwing', (t) => {
  const disabled = buildSubsidyClaimPayload()
  t.is(disabled.status, 409)
  t.ok(disabled.payload.error.startsWith('not-enabled: '))

  const unavailable = buildSubsidyClaimPayload({ subsidyAccrual: {} })
  t.is(unavailable.status, 503)
  t.ok(unavailable.payload.error.startsWith('unsupported: '))

  const claim = buildSubsidyClaimPayload({
    subsidyAccrual: {
      buildClaim () {
        return { relay: 'a'.repeat(64), amountSats: 42 }
      }
    }
  })
  t.is(claim.status, 200)
  t.alike(claim.payload, { relay: 'a'.repeat(64), amountSats: 42 })
})

test('api subsidy: update persists config and optional wizard state', async (t) => {
  const config = { subsidy: { enabled: true, payoutDestination: 'old@example.com' } }
  const wizard = makeWizard()
  let persists = 0

  const result = await updateSubsidyDestination({
    body: { destination: ' Operator@Example.com ' },
    config,
    wizard,
    persistConfig: async () => { persists++ }
  })

  t.is(result.ok, true)
  t.alike(result.payload, {
    ok: true,
    enabled: false,
    payoutDestination: { type: 'lightning-address', value: 'operator@example.com' }
  })
  t.is(config.subsidy.payoutDestination, 'operator@example.com')
  t.is(wizard.state.payoutDestination, 'operator@example.com')
  t.is(wizard.saves, 1)
  t.is(persists, 1)
})

test('api subsidy: update can clear live accrual destination', async (t) => {
  const config = { subsidy: { payoutDestination: 'old@example.com' } }
  const calls = []
  const subsidyAccrual = {
    async setPayoutDestination (value) {
      calls.push(value)
      return null
    }
  }

  const result = await updateSubsidyDestination({
    body: { destination: null },
    config,
    subsidyAccrual,
    persistConfig: async () => {}
  })

  t.is(result.ok, true)
  t.alike(calls, [null])
  t.is(config.subsidy.payoutDestination, null)
  t.alike(result.payload, { ok: true, enabled: true, payoutDestination: null })
})

test('api subsidy: wizard save failures restore config and wizard state', async (t) => {
  const config = { subsidy: { payoutDestination: 'old@example.com' } }
  const wizard = makeWizard({ saveError: new Error('wizard disk full') })

  const result = await updateSubsidyDestination({
    body: { destination: 'operator@example.com' },
    config,
    wizard,
    persistConfig: async () => {
      throw new Error('should not persist config after wizard failure')
    }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'wizard-persist')
  t.is(config.subsidy.payoutDestination, 'old@example.com')
  t.is(wizard.state.payoutDestination, 'old@example.com')
  t.is(wizard.saves, 1)
})

test('api subsidy: config persist failures restore runtime state and wizard file', async (t) => {
  const config = { subsidy: { payoutDestination: 'old@example.com' } }
  const wizard = makeWizard()

  const result = await updateSubsidyDestination({
    body: { destination: 'operator@example.com' },
    config,
    wizard,
    persistConfig: async () => {
      throw new Error('config disk full')
    }
  })

  t.is(result.ok, false)
  t.is(result.kind, 'config-persist')
  t.is(config.subsidy.payoutDestination, 'old@example.com')
  t.is(wizard.state.payoutDestination, 'old@example.com')
  t.is(wizard.saves, 2)
})

test('api subsidy: live accrual failures restore persisted config and emit rollback drift', async (t) => {
  const config = { subsidy: { payoutDestination: 'old@example.com' } }
  const wizard = makeWizard()
  const events = []
  let persists = 0

  const result = await updateSubsidyDestination({
    body: { destination: 'operator@example.com' },
    config,
    wizard,
    subsidyAccrual: {
      async setPayoutDestination () {
        throw new Error('subsidy disk full')
      }
    },
    persistConfig: async () => {
      persists++
      if (persists === 2) throw new Error('rollback disk full')
    },
    emit: (event, payload) => events.push({ event, message: payload.message })
  })

  t.is(result.ok, false)
  t.is(result.kind, 'subsidy-persist')
  t.is(config.subsidy.payoutDestination, 'old@example.com')
  t.is(wizard.state.payoutDestination, 'old@example.com')
  t.is(wizard.saves, 2)
  t.is(persists, 2)
  t.alike(events, [{ event: 'config-rollback-error', message: 'rollback disk full' }])
})
