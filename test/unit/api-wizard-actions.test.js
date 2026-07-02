import test from 'brittle'
import {
  buildWizardSnapshotRoutePayload,
  resolveWizardSnapshotRoute,
  runWizardAction,
  wizardActionFromPath
} from 'p2p-hiverelay/core/relay-node/api-wizard-actions.js'

function makeWizard (opts = {}) {
  const wizard = {
    state: {
      step: 'welcome',
      relayName: 'old-relay',
      payoutDestination: null,
      acceptMode: 'review',
      completedAt: null
    },
    saves: 0,
    goToStep ({ step }) {
      if (!['welcome', 'relay_name', 'payout', 'accept_mode', 'complete'].includes(step)) {
        return { ok: false, reason: 'unknown step: ' + step }
      }
      this.state = { ...this.state, step }
      return { ok: true, state: this.snapshot() }
    },
    setRelayName ({ relayName }) {
      if (typeof relayName !== 'string' || relayName.trim() === '') {
        return { ok: false, reason: 'relayName cannot be empty' }
      }
      this.state = { ...this.state, relayName: relayName.trim() }
      return { ok: true, state: this.snapshot() }
    },
    setPayoutDestination ({ address }) {
      this.state = { ...this.state, payoutDestination: address || null }
      return { ok: true, state: this.snapshot() }
    },
    setAcceptMode ({ acceptMode }) {
      if (!['open', 'review', 'allowlist', 'closed'].includes(acceptMode)) {
        return { ok: false, reason: 'bad accept mode' }
      }
      this.state = { ...this.state, acceptMode }
      return { ok: true, state: this.snapshot() }
    },
    complete () {
      this.state = { ...this.state, step: 'complete', completedAt: 1234 }
      return { ok: true, state: this.snapshot() }
    },
    reset () {
      this.state = {
        step: 'welcome',
        relayName: 'reset-relay',
        payoutDestination: null,
        acceptMode: 'review',
        completedAt: null
      }
    },
    snapshot () {
      return { ...this.state, isComplete: this.state.step === 'complete' }
    },
    toConfig () {
      return {
        name: this.state.relayName,
        acceptMode: this.state.acceptMode,
        subsidy: { payoutDestination: this.state.payoutDestination }
      }
    },
    async save () {
      this.saves++
      if (opts.saveError) throw opts.saveError
    }
  }
  return wizard
}

function snapshotConfig (config) {
  return {
    name: config.name,
    acceptMode: config.acceptMode,
    subsidy: config.subsidy ? { ...config.subsidy } : undefined,
    hasSubsidy: Object.prototype.hasOwnProperty.call(config, 'subsidy')
  }
}

function restoreConfig (config, snapshot) {
  config.name = snapshot.name
  config.acceptMode = snapshot.acceptMode
  if (snapshot.hasSubsidy) config.subsidy = snapshot.subsidy
  else delete config.subsidy
}

test('api wizard actions: route helper extracts action names without validation', (t) => {
  t.is(wizardActionFromPath('/api/wizard/goto'), 'goto')
  t.is(wizardActionFromPath('/api/wizard/relay-name'), 'relay-name')
  t.is(wizardActionFromPath('/api/wizard/made-up'), 'made-up')
  t.is(wizardActionFromPath('/api/wizard/'), '')
  t.is(wizardActionFromPath('/api/wizard'), null)
  t.is(wizardActionFromPath('/api/manage/wizard/goto'), null)
})

test('api wizard actions: snapshot route helper matches exact GET route', (t) => {
  t.alike(resolveWizardSnapshotRoute('GET', '/api/wizard'), {
    kind: 'wizard-snapshot',
    authMessage: 'Unauthorized — wizard requires API key or localhost'
  })
  t.is(resolveWizardSnapshotRoute('POST', '/api/wizard'), null)
  t.is(resolveWizardSnapshotRoute('GET', '/api/wizard/'), null)
  t.is(resolveWizardSnapshotRoute('GET', '/api/wizard/goto'), null)
  t.is(resolveWizardSnapshotRoute('GET', '/api/manage/wizard'), null)
})

test('api wizard actions: snapshot route payload helper dispatches wizard reads', async (t) => {
  const wizard = makeWizard()
  wizard.state = {
    ...wizard.state,
    step: 'complete',
    relayName: 'operator relay',
    completedAt: 1234
  }
  let calls = 0

  const result = await buildWizardSnapshotRoutePayload({
    route: resolveWizardSnapshotRoute('GET', '/api/wizard'),
    getWizard: async () => {
      calls++
      return wizard
    }
  })

  t.is(calls, 1)
  t.is(result.ok, true)
  t.is(result.status, undefined)
  t.alike(result.payload, {
    step: 'complete',
    relayName: 'operator relay',
    payoutDestination: null,
    acceptMode: 'review',
    completedAt: 1234,
    isComplete: true
  })

  const unavailable = await buildWizardSnapshotRoutePayload({
    route: resolveWizardSnapshotRoute('GET', '/api/wizard'),
    getWizard: async () => null
  })
  t.alike(unavailable, {
    ok: false,
    status: 503,
    payload: { error: 'wizard unavailable' }
  })

  const unknown = await buildWizardSnapshotRoutePayload({
    route: null,
    getWizard: async () => {
      throw new Error('should not call getWizard')
    }
  })
  t.alike(unknown, {
    ok: false,
    status: 404,
    payload: { error: 'unknown wizard snapshot route' }
  })
})

test('api wizard actions: step actions mutate and save wizard state', async (t) => {
  const wizard = makeWizard()

  let out = await runWizardAction({ wizard, action: 'goto', body: { step: 'relay_name' } })
  t.is(out.ok, true)
  t.is(out.payload.state.step, 'relay_name')

  out = await runWizardAction({ wizard, action: 'relay-name', body: { relayName: '  Umbrel Relay  ' } })
  t.is(out.ok, true)
  t.is(out.payload.state.relayName, 'Umbrel Relay')

  out = await runWizardAction({ wizard, action: 'payout', body: { address: 'operator@example.com' } })
  t.is(out.ok, true)
  t.is(out.payload.state.payoutDestination, 'operator@example.com')

  out = await runWizardAction({ wizard, action: 'accept-mode', body: { acceptMode: 'allowlist' } })
  t.is(out.ok, true)
  t.is(out.payload.state.acceptMode, 'allowlist')

  out = await runWizardAction({ wizard, action: 'reset', body: {} })
  t.is(out.ok, true)
  t.is(out.payload.state.relayName, 'reset-relay')
  t.is(wizard.saves, 5)
})

test('api wizard actions: unknown and invalid actions return typed failures without saving', async (t) => {
  const wizard = makeWizard()
  const old = { ...wizard.state }

  let out = await runWizardAction({ wizard, action: 'made-up', body: {} })
  t.is(out.ok, false)
  t.is(out.kind, 'not-found')
  t.alike(wizard.state, old)
  t.is(wizard.saves, 0)

  out = await runWizardAction({ wizard, action: 'relay-name', body: { relayName: '' } })
  t.is(out.ok, false)
  t.is(out.kind, 'bad-request')
  t.alike(wizard.state, old)
  t.is(wizard.saves, 0)
})

test('api wizard actions: complete applies and persists config before saving wizard', async (t) => {
  const wizard = makeWizard()
  wizard.state = {
    ...wizard.state,
    relayName: 'New Relay',
    acceptMode: 'open',
    payoutDestination: 'operator@example.com'
  }
  const config = { name: 'Old Relay', acceptMode: 'review', subsidy: { payoutDestination: null } }
  const calls = []

  const out = await runWizardAction({
    wizard,
    action: 'complete',
    body: {},
    applyConfig: cfg => {
      calls.push('apply')
      config.name = cfg.name
      config.acceptMode = cfg.acceptMode
      config.subsidy = { ...cfg.subsidy }
    },
    persistConfig: async () => { calls.push('persist') },
    snapshotConfig: () => snapshotConfig(config),
    restoreConfig: snapshot => restoreConfig(config, snapshot)
  })

  t.is(out.ok, true)
  t.alike(calls, ['apply', 'persist'])
  t.is(wizard.saves, 1)
  t.is(wizard.state.step, 'complete')
  t.alike(config, {
    name: 'New Relay',
    acceptMode: 'open',
    subsidy: { payoutDestination: 'operator@example.com' }
  })
})

test('api wizard actions: apply-config failure restores wizard and config', async (t) => {
  const wizard = makeWizard()
  const oldWizard = { ...wizard.state }
  const config = { name: 'Old Relay', acceptMode: 'review' }

  const out = await runWizardAction({
    wizard,
    action: 'complete',
    body: {},
    applyConfig: () => {
      config.name = 'partial'
      throw new Error('bad config')
    },
    persistConfig: async () => { throw new Error('should not persist') },
    snapshotConfig: () => snapshotConfig(config),
    restoreConfig: snapshot => restoreConfig(config, snapshot)
  })

  t.is(out.ok, false)
  t.is(out.kind, 'apply-config')
  t.alike(wizard.state, oldWizard)
  t.alike(config, { name: 'Old Relay', acceptMode: 'review' })
  t.is(wizard.saves, 0)
})

test('api wizard actions: config persistence failure restores wizard and config', async (t) => {
  const wizard = makeWizard()
  const oldWizard = { ...wizard.state }
  const config = { name: 'Old Relay', acceptMode: 'review' }

  const out = await runWizardAction({
    wizard,
    action: 'complete',
    body: {},
    applyConfig: cfg => {
      config.name = cfg.name
      config.acceptMode = cfg.acceptMode
    },
    persistConfig: async () => { throw new Error('readonly config') },
    snapshotConfig: () => snapshotConfig(config),
    restoreConfig: snapshot => restoreConfig(config, snapshot)
  })

  t.is(out.ok, false)
  t.is(out.kind, 'config-persist')
  t.alike(wizard.state, oldWizard)
  t.alike(config, { name: 'Old Relay', acceptMode: 'review' })
  t.is(wizard.saves, 0)
})

test('api wizard actions: wizard save failure after config persist rolls back config', async (t) => {
  const wizard = makeWizard({ saveError: new Error('wizard readonly') })
  const oldWizard = { ...wizard.state }
  const config = { name: 'Old Relay', acceptMode: 'review' }
  const events = []
  let persists = 0

  const out = await runWizardAction({
    wizard,
    action: 'complete',
    body: {},
    applyConfig: cfg => {
      config.name = cfg.name
      config.acceptMode = cfg.acceptMode
    },
    persistConfig: async () => { persists++ },
    snapshotConfig: () => snapshotConfig(config),
    restoreConfig: snapshot => restoreConfig(config, snapshot),
    emit: (event, payload) => events.push({ event, message: payload.message })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'wizard-persist')
  t.alike(wizard.state, oldWizard)
  t.alike(config, { name: 'Old Relay', acceptMode: 'review' })
  t.is(persists, 2, 'initial config persist plus rollback persist')
  t.alike(events, [])
})

test('api wizard actions: rollback persistence failure emits drift event', async (t) => {
  const wizard = makeWizard({ saveError: new Error('wizard readonly') })
  const config = { name: 'Old Relay', acceptMode: 'review' }
  const events = []
  let persists = 0

  const out = await runWizardAction({
    wizard,
    action: 'complete',
    body: {},
    applyConfig: cfg => {
      config.name = cfg.name
      config.acceptMode = cfg.acceptMode
    },
    persistConfig: async () => {
      persists++
      if (persists === 2) throw new Error('rollback readonly')
    },
    snapshotConfig: () => snapshotConfig(config),
    restoreConfig: snapshot => restoreConfig(config, snapshot),
    emit: (event, payload) => events.push({ event, message: payload.message })
  })

  t.is(out.ok, false)
  t.is(out.kind, 'wizard-persist')
  t.is(persists, 2)
  t.alike(events, [{ event: 'config-rollback-error', message: 'rollback readonly' }])
})
