import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const dashboard = readFileSync('dashboard/blindspark.html', 'utf8')
const fullDashboard = readFileSync('dashboard/index.html', 'utf8')
const wizard = readFileSync('dashboard/wizard.html', 'utf8')

test('umbrel ui controls do not rely on submit-default buttons', (t) => {
  t.alike(buttonsMissingType(dashboard), [])
  t.alike(buttonsMissingType(wizard), [])
})

test('umbrel dashboard has unique element ids for interactive controls', (t) => {
  const ids = htmlIds(dashboard)
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index)

  t.alike(duplicates, [])
  t.is(countId(dashboard, 'servicesCard'), 1)
  t.is(countId(dashboard, 'svcStatus'), 1)
  t.is(countId(dashboard, 'svcBody'), 1)
  t.is(countId(dashboard, 'walletDialog'), 1)
})

test('umbrel dashboard critical click handlers stay wired', (t) => {
  t.ok(dashboard.includes("$('setupLink').setAttribute('href', appPath('/wizard?edit=1'));"))
  t.ok(dashboard.includes("edit.addEventListener('click', openWalletDialog);"))
  t.ok(dashboard.includes("writeClipboard(pubKey, 'Public key copied');"))
  t.ok(dashboard.includes("writeClipboard(addr, 'Payout destination copied');"))
  t.ok(dashboard.includes("$('walletSave').addEventListener('click', function(){ saveWallet(false); });"))
  t.ok(dashboard.includes("save.addEventListener('click', function(){"))
  t.ok(dashboard.includes('svcSetConfig(selected.length > 0, selected);'))
  t.ok(dashboard.includes('refreshServices(true);'))
  t.absent(dashboard.includes('fetchServices();'))
})

test('umbrel dashboard mobile controls avoid cramped appliance layout', (t) => {
  t.ok(dashboard.includes('@media(max-width:440px)'))
  t.ok(dashboard.includes('.hdr{align-items:flex-start;flex-wrap:wrap}'))
  t.ok(dashboard.includes('.hdr-right{width:100%;margin-left:0;justify-content:space-between}'))
  t.ok(dashboard.includes('.svc-btn,.row-btn,.setup-link,.status,.pk,.addr{min-height:34px}'))
  t.ok(dashboard.includes('.svc-model-field input,.dlg-field input{min-height:38px}'))
  t.ok(dashboard.includes('dialog{width:calc(100vw - 2rem);max-width:calc(100vw - 2rem)}'))
})

test('umbrel service manager keeps the section unframed around service cards', (t) => {
  t.ok(dashboard.includes('.services-card{'))
  t.ok(dashboard.includes('background:transparent;border:0;border-radius:0;padding:0'))
  t.ok(dashboard.includes('.services-card .apps-head{padding:0 .15rem;margin-bottom:.65rem}'))
  t.ok(dashboard.includes('.svc-card:focus-within{outline:2px solid var(--cyan);outline-offset:2px}'))
  t.ok(dashboard.includes("toast('Poker preset selected; save to apply');"))
})

test('umbrel wallet and service controls expose accessible busy/error state', (t) => {
  t.ok(dashboard.includes('id="svcStatus" role="status" aria-live="polite" aria-atomic="true"'))
  t.ok(dashboard.includes('id="walletHelp"'))
  t.ok(dashboard.includes('aria-describedby="walletHelp walletError"'))
  t.ok(dashboard.includes('id="walletError" role="status" aria-live="polite" aria-atomic="true"'))
  t.ok(dashboard.includes("$('walletSave').textContent = busy ? 'Saving...' : 'Save';"))
  t.ok(dashboard.includes("$('walletDialog').setAttribute('aria-busy', busy ? 'true' : 'false');"))
  t.ok(dashboard.includes("$('servicesCard').setAttribute('aria-busy', controlsDisabled ? 'true' : 'false');"))
  t.ok(dashboard.includes("progress.setAttribute('role', 'status');"))
  t.ok(dashboard.includes("hint.setAttribute('role', 'status');"))
})

test('umbrel service auto refresh preserves unsaved selection drafts', (t) => {
  t.ok(dashboard.includes('var svcDraftDirty = false;'))
  t.ok(dashboard.includes('svcDraftDirty = true;'))
  t.ok(dashboard.includes('svcDraftDirty = false;'))
  t.ok(dashboard.includes('refreshServices(true);'))
  t.ok(dashboard.includes('function refreshServices(force)'))
  t.ok(dashboard.includes('if (svcDraftDirty && force !== true) return;'))
})

test('umbrel dashboard polling avoids hidden-tab and overlapping refresh churn', (t) => {
  t.ok(dashboard.includes('var REQUEST_TIMEOUT_MS = 10000;'))
  t.ok(dashboard.includes('function fetchWithTimeout(path, opts)'))
  t.ok(dashboard.includes('typeof AbortController === \'function\''))
  t.ok(dashboard.includes('controller.abort();'))
  t.ok(dashboard.includes('if (timeout) clearTimeout(timeout);'))
  t.ok(dashboard.includes('fetchWithTimeout(path, { headers: { \'Accept\': \'application/json\' } })'))
  t.ok(dashboard.includes('fetchWithTimeout(\'/api/subsidy/destination\''))
  t.ok(dashboard.includes('return fetchWithTimeout(path, {'))
  t.ok(dashboard.includes('var overviewRefreshBusy = false;'))
  t.ok(dashboard.includes('var wizardRefreshBusy = false;'))
  t.ok(dashboard.includes('var servicesRefreshBusy = false;'))
  t.ok(dashboard.includes('var servicesRefreshPendingForce = false;'))
  t.ok(dashboard.includes('function canPoll(force, busy)'))
  t.ok(dashboard.includes('document.hidden === true'))
  t.ok(dashboard.includes('if (force === true) servicesRefreshPendingForce = true;'))
  t.ok(dashboard.includes('refreshServices(true);'))
  t.ok(dashboard.includes('refreshVisible(true);'))
  t.ok(dashboard.includes('setInterval(function(){ refresh(false); }, 5000);'))
  t.ok(dashboard.includes('setInterval(function(){ refreshWizard(false); }, 30000);'))
  t.ok(dashboard.includes('setInterval(function(){ refreshServices(false); }, 15000);'))
  t.ok(dashboard.includes('document.addEventListener(\'visibilitychange\''))
  t.ok(dashboard.includes('if (document.hidden !== true) refreshVisible(true);'))
  t.absent(dashboard.includes('setInterval(refresh, 5000);'))
  t.absent(dashboard.includes('setInterval(refreshWizard, 30000);'))
  t.absent(dashboard.includes('setInterval(refreshServices, 15000);'))
})

test('umbrel service restart shows pending state until selected providers run', (t) => {
  t.ok(dashboard.includes('var svcRestartPending = false;'))
  t.ok(dashboard.includes('var svcConfigBusy = false;'))
  t.ok(dashboard.includes('var svcRestartStartedAt = 0;'))
  t.ok(dashboard.includes('function setSvcConfigBusy(busy)'))
  t.ok(dashboard.includes('function beginSvcRestartWatch(expected)'))
  t.ok(dashboard.includes('function checkSvcRestart()'))
  t.ok(dashboard.includes('function svcRestartReady(avail)'))
  t.ok(dashboard.includes('var controlsDisabled = svcRestartPending || svcConfigBusy;'))
  t.ok(dashboard.includes('if (svcRestartPending || svcConfigBusy) return;'))
  t.ok(dashboard.includes('Saving service selection...'))
  t.ok(dashboard.includes('if (svcDraftDirty){'))
  t.ok(dashboard.includes('toast(\'Save selection before restart\');'))
  t.ok(dashboard.includes('? \'Saving service selection...\''))
  t.ok(dashboard.includes(': (svcDraftDirty ? \'Unsaved changes - save selection before restarting.\''))
  t.ok(dashboard.includes('Date.now() - svcRestartStartedAt < 2500'))
  t.ok(dashboard.includes('var managedActive = active.filter'))
  t.ok(dashboard.includes('if (!expected.length) return managedActive.length === 0;'))
  t.ok(dashboard.includes('if (expected.indexOf(managedActive[j]) === -1) return false;'))
  t.ok(dashboard.includes("$('svcStatus').textContent = svcConfigBusy ? 'Saving'"))
  t.ok(dashboard.includes('restart.disabled = controlsDisabled;'))
  t.ok(dashboard.includes('save.disabled = controlsDisabled;'))
  t.ok(dashboard.includes('cb.disabled = controlsDisabled;'))
  t.ok(dashboard.includes('Services are running'))
  t.ok(dashboard.includes('Restart still pending'))
})

test('umbrel service save disables duplicate in-flight config writes', async (t) => {
  const script = [
    'var svcConfigBusy = false',
    'var svcDraftDirty = true',
    'var svcLastConfiguredPlugins = []',
    'var posts = []',
    'var busy = []',
    'var toasts = []',
    'var refreshes = []',
    'var updates = 0',
    'var resolver = null',
    'function setSvcConfigBusy (value) { svcConfigBusy = !!value; busy.push(!!value) }',
    'function svcPost (path, body) { posts.push({ path: path, body: body }); return new Promise(function(resolve){ resolver = resolve }) }',
    'function apiError () { return "Update failed" }',
    'function toast (msg) { toasts.push(msg) }',
    'function refreshServices (force) { refreshes.push(force) }',
    'function updateSvcCards () { updates++ }',
    extractFunction('svcSetConfig'),
    'svcSetConfig(true, ["ai"])',
    'svcSetConfig(true, ["vrf"])',
    'var before = { posts: posts.slice(), busy: busy.slice(), toasts: toasts.slice(), refreshes: refreshes.slice(), updates: updates }',
    'resolver({ ok: true, out: { config: { plugins: ["ai"] } } })',
    'Promise.resolve().then(function(){ return Promise.resolve() }).then(function(){ return JSON.stringify({ before: before, after: { posts: posts, busy: busy, toasts: toasts, refreshes: refreshes, updates: updates, plugins: svcLastConfiguredPlugins } }) })'
  ].join('\n')

  const out = JSON.parse(await vm.runInNewContext(script, { Promise, JSON }))
  t.is(out.before.posts.length, 1)
  t.alike(out.before.posts[0], {
    path: '/api/manage/services/config',
    body: { enabled: true, plugins: ['ai'] }
  })
  t.alike(out.before.busy, [true])
  t.alike(out.after.busy, [true, false])
  t.alike(out.after.toasts, ['Saved; restart to apply'])
  t.alike(out.after.refreshes, [true])
  t.is(out.after.updates, 1)
  t.alike(out.after.plugins, ['ai'])
})

test('umbrel service restart refuses unsaved service drafts', async (t) => {
  const script = [
    'var svcRestartPending = false',
    'var svcConfigBusy = false',
    'var svcDraftDirty = true',
    'var posts = []',
    'var toasts = []',
    'var watches = []',
    'function toast (msg) { toasts.push(msg) }',
    'function svcSelectedOrConfigured () { return ["ai"] }',
    'function svcPost (path, body) { posts.push({ path: path, body: body }); return Promise.resolve({ ok: true, out: {} }) }',
    'function apiError () { return "Restart failed" }',
    'function beginSvcRestartWatch (expected) { watches.push(expected.slice()) }',
    extractFunction('svcRestartNode'),
    'svcRestartNode()',
    'var dirty = { posts: posts.length, toasts: toasts.slice(), watches: watches.slice() }',
    'svcDraftDirty = false',
    'svcRestartNode()',
    'Promise.resolve().then(function(){ return JSON.stringify({ dirty: dirty, clean: { posts: posts, toasts: toasts, watches: watches } }) })'
  ].join('\n')

  const out = JSON.parse(await vm.runInNewContext(script, { Promise, JSON }))
  t.alike(out.dirty, {
    posts: 0,
    toasts: ['Save selection before restart'],
    watches: []
  })
  t.is(out.clean.posts.length, 1)
  t.alike(out.clean.posts[0], { path: '/api/manage/restart', body: {} })
  t.alike(out.clean.watches, [['ai']])
  t.alike(out.clean.toasts, ['Save selection before restart', 'Restarting Blindspark'])
})

test('umbrel service restart readiness requires exact managed service convergence', (t) => {
  t.is(runSvcRestartReady({
    now: 1000,
    expected: ['vrf'],
    avail: { available: ['vrf'], active: ['vrf'], plugins: ['vrf'] }
  }), false, 'does not clear immediately before restart can cycle')

  t.is(runSvcRestartReady({
    expected: ['vrf', 'ai'],
    avail: { available: ['vrf', 'ai', 'zk'], active: ['vrf', 'ai'], plugins: ['vrf', 'ai'] }
  }), true, 'clears once every selected managed service is active')

  t.is(runSvcRestartReady({
    expected: ['vrf', 'ai'],
    avail: { available: ['vrf', 'ai', 'zk'], active: ['vrf'], plugins: ['vrf', 'ai'] }
  }), false, 'keeps waiting while a selected service is missing')

  t.is(runSvcRestartReady({
    expected: ['vrf'],
    avail: { available: ['vrf', 'ai', 'zk'], active: ['vrf', 'ai'], plugins: ['vrf'] }
  }), false, 'keeps waiting while a removed managed service is still active')

  t.is(runSvcRestartReady({
    expected: ['vrf'],
    avail: { available: ['vrf', 'ai'], active: ['vrf', 'external'], plugins: ['vrf'] }
  }), true, 'ignores active providers outside the managed built-in catalog')

  t.is(runSvcRestartReady({
    expected: [],
    avail: { available: ['vrf', 'ai'], active: ['vrf'], plugins: [] }
  }), false, 'disabled services wait until managed providers stop')

  t.is(runSvcRestartReady({
    expected: [],
    avail: { available: ['vrf', 'ai'], active: [], plugins: [] }
  }), true, 'disabled services clear once managed providers are stopped')
})

test('umbrel service manager builds service UI without HTML-string metadata injection', (t) => {
  const renderServices = extractFunction('renderServices')
  const renderMetering = extractFunction('renderMetering')
  const renderApps = extractFunction('renderApps')

  t.absent(renderServices.includes('hero.innerHTML'))
  t.absent(renderServices.includes('catalog.innerHTML'))
  t.absent(renderServices.includes('content.innerHTML'))
  t.absent(renderServices.includes('actions.innerHTML'))
  t.absent(renderServices.includes('live.innerHTML'))
  t.absent(renderServices.includes('row.innerHTML'))
  t.absent(renderServices.includes('form.innerHTML'))
  t.ok(renderServices.includes("appendEl(content, 'span', 'svc-name', meta.label)"))
  t.ok(renderServices.includes("appendEl(row, 'span', 'svc-live-status', status)"))
  t.ok(renderServices.includes("appendModelField(form, 'svcModelId', 'Model ID', 'qvac-small')"))
  t.absent(renderMetering.includes('box.innerHTML'))
  t.ok(renderMetering.includes("appendMeterRow(meter, 'Signed receipts', metricCount(verified.count))"))
  t.absent(renderApps.includes('box.innerHTML'))
  t.ok(renderApps.includes("var row = appendEl(box, 'div', 'app')"))
})

test('umbrel service manager renders untrusted service metadata as text', (t) => {
  const svcBody = new FakeElement('div')
  const svcStatus = new FakeElement('span')
  const servicesCard = new FakeElement('section')
  const serviceName = '<img src=x onerror=alert(1)>'
  const serviceStatus = '<svg onload=alert(2)>'
  const script = [
    'var svcLastConfiguredPlugins = []',
    'var svcRestartPending = false',
    'var svcRestartExpected = []',
    'var svcDraftDirty = false',
    'var svcConfigBusy = false',
    'var svcModelBusy = false',
    "var svcModelMessageText = 'Persisted model error'",
    "var svcModelMessageKind = 'error'",
    'function svcSetConfig () {}',
    'function svcRestartNode () {}',
    'function svcAddModel () {}',
    'function handleSvcModelInputKey () {}',
    'function renderMetering () {}',
    'var SERVICE_META = {}',
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('appendSectionTitle'),
    extractFunction('appendModelField'),
    extractFunction('svcMeta'),
    extractFunction('renderServices'),
    'renderServices(' + JSON.stringify({
      enabled: false,
      available: [serviceName, 'ai'],
      plugins: [serviceName],
      active: [serviceName, 'ai'],
      bundles: { poker: ['vrf', serviceName] }
    }) + ', ' + JSON.stringify({
      services: [
        { name: serviceName, running: true, status: serviceStatus }
      ]
    }) + ')',
    "$('svcBody').innerHTML"
  ].join('\n')

  const html = vm.runInNewContext(script, {
    document: {
      createElement: (tag) => new FakeElement(tag),
      querySelectorAll: () => []
    },
    $: (id) => {
      if (id === 'svcBody') return svcBody
      if (id === 'svcStatus') return svcStatus
      if (id === 'servicesCard') return servicesCard
      throw new Error('unexpected id ' + id)
    }
  })

  t.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(html.includes('&lt;svg onload=alert(2)&gt;'))
  t.ok(html.includes('Persisted model error'))
  t.absent(html.includes('<img'))
  t.absent(html.includes('<svg'))
  t.absent(html.includes('onerror=alert(1)><'))
  t.alike(svcBody.innerHTMLAssignments, [])
})

test('umbrel appliance copy controls report missing or rejected clipboard writes', async (t) => {
  const script = [
    extractFunction('toast'),
    extractFunction('writeClipboard'),
    `
    (async function () {
      var toastEl = {
        textContent: '',
        classList: {
          added: [],
          removed: [],
          add: function (name) { this.added.push(name) },
          remove: function (name) { this.removed.push(name) }
        }
      }
      var timers = []
      globalThis.$ = function (id) {
        if (id === 'toast') return toastEl
        throw new Error('unexpected id ' + id)
      }
      globalThis.setTimeout = function (fn) { timers.push(fn); return timers.length }
      globalThis.clearTimeout = function () {}
      var results = {}

      delete globalThis.navigator
      writeClipboard('public-key', 'Public key copied')
      results.noClipboard = toastEl.textContent

      var writes = []
      globalThis.navigator = {
        clipboard: {
          writeText: function (text) {
            writes.push(text)
            return Promise.reject(new Error('denied'))
          }
        }
      }
      writeClipboard('payout', 'Payout destination copied')
      await Promise.resolve()
      await Promise.resolve()
      results.rejected = toastEl.textContent

      globalThis.navigator.clipboard.writeText = function (text) {
        writes.push(text)
        return Promise.resolve()
      }
      writeClipboard('payout-ok', 'Payout destination copied')
      await Promise.resolve()
      await Promise.resolve()
      results.success = {
        toast: toastEl.textContent,
        writes: writes,
        timers: timers.length
      }
      return results
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(script, { Promise, Error })

  t.is(out.noClipboard, 'Clipboard unavailable')
  t.is(out.rejected, 'Copy failed')
  t.is(out.success.toast, 'Payout destination copied')
  t.is(out.success.writes.join(','), 'payout,payout-ok')
  t.is(out.success.timers, 3)
})

test('ui auth shim only attaches bearer tokens to same-origin fetches', (t) => {
  for (const html of [dashboard, fullDashboard, wizard]) {
    t.ok(html.includes('new URL(raw, window.location.href)'))
    t.ok(html.includes('u.origin === window.location.origin'))
    t.ok(html.includes("h.set('Authorization', 'Bearer ' + t)"))
  }
})

test('umbrel wizard setup actions post to the server instead of refreshing', (t) => {
  t.ok(wizard.includes('data-wizard-action="goto" data-step-target="relay_name"'))
  t.ok(wizard.includes('data-wizard-action="payout"'))
  t.ok(wizard.includes('data-wizard-action="accept-mode"'))
  t.ok(wizard.includes("const el = event.target.closest('[data-wizard-action]')"))
  t.ok(wizard.includes("if (action === 'goto') result = goNext(el.dataset.stepTarget || 'welcome')"))
  t.ok(wizard.includes("await api('/api/wizard/relay-name', { method: 'POST', body: { relayName: name } })"))
  t.ok(wizard.includes("await api('/api/wizard/payout', { method: 'POST', body: { address } })"))
  t.ok(wizard.includes("await api('/api/wizard/accept-mode', { method: 'POST', body: { acceptMode: selectedMode } })"))
  t.ok(wizard.includes("await api('/api/wizard/complete', { method: 'POST', body: {} })"))
  t.ok(wizard.includes('const REQUEST_TIMEOUT_MS = 10000'))
  t.ok(wizard.includes('async function fetchWithTimeout (path, opts = {})'))
  t.ok(wizard.includes("typeof AbortController === 'function'"))
  t.ok(wizard.includes('timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)'))
  t.ok(wizard.includes('const res = await fetchWithTimeout(path, {'))
  t.absent(wizard.includes('onclick='))
})

test('umbrel wallet save posts through app proxy without navigation', async (t) => {
  const walletInput = new FakeElement('input')
  const walletError = new FakeElement('div')
  const walletSave = new FakeElement('button')
  const walletClear = new FakeElement('button')
  const walletCancel = new FakeElement('button')
  const walletDialog = new FakeElement('dialog')
  const payout = new FakeElement('div')
  const fetchCalls = []
  const toasts = []
  let closed = false
  walletInput.value = 'operator@example.com'
  walletDialog.close = () => { closed = true }

  const script = [
    'var payoutDestination = ""',
    'function openWalletDialog () {}',
    extractFunction('appBasePath'),
    'var APP_BASE = appBasePath()',
    extractFunction('appPath'),
    extractFunction('apiError'),
    'var REQUEST_TIMEOUT_MS = 10000',
    extractFunction('fetchWithTimeout'),
    extractFunction('payoutValue'),
    extractFunction('clearNode'),
    extractFunction('renderPayout'),
    extractFunction('closeWalletDialog'),
    extractFunction('setWalletBusy'),
    extractFunction('saveWallet'),
    'saveWallet(false)',
    'new Promise(function(resolve){ setTimeout(resolve, 0) })'
  ].join('\n')

  await vm.runInNewContext(script, {
    Promise,
    JSON,
    setTimeout,
    window: {
      location: {
        pathname: '/apps/blindspark/dashboard'
      }
    },
    document: {
      createElement: (tag) => new FakeElement(tag)
    },
    navigator: {},
    fetch: (url, init) => {
      fetchCalls.push({ url, init })
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ payoutDestination: 'operator@example.com' })
      })
    },
    toast: (msg) => { toasts.push(msg) },
    refreshWizard: () => {},
    $: (id) => {
      if (id === 'walletInput') return walletInput
      if (id === 'walletError') return walletError
      if (id === 'walletSave') return walletSave
      if (id === 'walletClear') return walletClear
      if (id === 'walletCancel') return walletCancel
      if (id === 'walletDialog') return walletDialog
      if (id === 'payout') return payout
      throw new Error('unexpected id ' + id)
    }
  })

  t.is(fetchCalls.length, 1)
  t.is(fetchCalls[0].url, '/apps/blindspark/api/subsidy/destination')
  t.is(fetchCalls[0].init.method, 'POST')
  t.is(fetchCalls[0].init.headers['Content-Type'], 'application/json')
  t.alike(JSON.parse(fetchCalls[0].init.body), { destination: 'operator@example.com' })
  t.is(walletError.textContent, '')
  t.is(walletSave.disabled, false)
  t.is(walletClear.disabled, false)
  t.is(walletCancel.disabled, false)
  t.is(walletSave.textContent, 'Save')
  t.is(walletDialog.attributes['aria-busy'], 'false')
  t.is(closed, true)
  t.alike(toasts, ['Payout wallet saved'])
  t.ok(payout.innerHTML.includes('operator@example.com'))
})

test('umbrel wallet destination saves on Enter without form navigation', (t) => {
  t.ok(dashboard.includes("$('walletInput').addEventListener('keydown', handleWalletInputKey);"))

  const result = vm.runInNewContext([
    'var calls = []',
    'var prevented = 0',
    'var walletSave = { disabled: false }',
    "function $ (id) { if (id === 'walletSave') return walletSave; throw new Error('unexpected id ' + id) }",
    'function saveWallet (clear) { calls.push(clear) }',
    extractFunction('handleWalletInputKey'),
    "handleWalletInputKey({ key: 'Escape', isComposing: false, preventDefault: function () { prevented++ } })",
    "handleWalletInputKey({ key: 'Enter', isComposing: true, preventDefault: function () { prevented++ } })",
    "handleWalletInputKey({ key: 'Enter', isComposing: false, preventDefault: function () { prevented++ } })",
    'walletSave.disabled = true',
    "handleWalletInputKey({ key: 'Enter', isComposing: false, preventDefault: function () { prevented++ } })",
    'JSON.stringify({ calls: calls, prevented: prevented })'
  ].join('\n'), {
    JSON,
    Error
  })

  t.alike(JSON.parse(result), { calls: [false], prevented: 2 })
})

test('umbrel AI model fields add on Enter without form navigation', (t) => {
  t.ok(dashboard.includes('modelId.addEventListener(\'keydown\', handleSvcModelInputKey);'))
  t.ok(dashboard.includes('modelSrc.addEventListener(\'keydown\', handleSvcModelInputKey);'))

  const result = vm.runInNewContext([
    'var calls = 0',
    'var prevented = 0',
    'var svcModelBusy = false',
    'function svcAddModel () { calls++ }',
    extractFunction('handleSvcModelInputKey'),
    "handleSvcModelInputKey({ key: 'Tab', isComposing: false, preventDefault: function () { prevented++ } })",
    "handleSvcModelInputKey({ key: 'Enter', isComposing: true, preventDefault: function () { prevented++ } })",
    "handleSvcModelInputKey({ key: 'Enter', isComposing: false, preventDefault: function () { prevented++ } })",
    'svcModelBusy = true',
    "handleSvcModelInputKey({ key: 'Enter', isComposing: false, preventDefault: function () { prevented++ } })",
    'JSON.stringify({ calls: calls, prevented: prevented })'
  ].join('\n'), {
    JSON
  })

  t.alike(JSON.parse(result), { calls: 1, prevented: 2 })
})

test('umbrel AI model add blocks duplicate writes and reports inline status', async (t) => {
  const modelId = new FakeElement('input')
  const modelSrc = new FakeElement('input')
  const modelAdd = new FakeElement('button')
  const modelMessage = new FakeElement('div')
  const posts = []
  const toasts = []
  const refreshes = []
  const focusLog = []
  let resolver = null
  modelAdd.id = 'svcModelAdd'
  modelId.focus = () => { focusLog.push('id') }
  modelSrc.focus = () => { focusLog.push('src') }
  modelId.value = ''
  modelSrc.value = '/models/qvac-a'

  const script = [
    'var svcModelBusy = false',
    'var svcConfigBusy = false',
    'var svcRestartPending = false',
    "var svcModelMessageText = ''",
    "var svcModelMessageKind = ''",
    extractFunction('apiError'),
    extractFunction('setSvcModelMessage'),
    extractFunction('setSvcModelBusy'),
    extractFunction('svcAddModel'),
    `
    (async function () {
      svcAddModel()
      var missing = {
        message: $('svcModelMessage').textContent,
        className: $('svcModelMessage').className,
        focused: focusLog[0] || ''
      }

      $('svcModelId').value = 'qvac-a'
      $('svcModelSrc').value = '/models/qvac-a'
      svcAddModel()
      svcAddModel()
      var busy = {
        posts: posts.slice(),
        disabled: [$('svcModelId').disabled, $('svcModelSrc').disabled, $('svcModelAdd').disabled],
        button: $('svcModelAdd').textContent,
        message: $('svcModelMessage').textContent
      }
      resolvePost({ ok: false, out: { error: 'AI_MODEL_EXISTS: qvac-a' } })
      await Promise.resolve()
      await Promise.resolve()
      var failed = {
        disabled: [$('svcModelId').disabled, $('svcModelSrc').disabled, $('svcModelAdd').disabled],
        button: $('svcModelAdd').textContent,
        message: $('svcModelMessage').textContent,
        className: $('svcModelMessage').className
      }

      $('svcModelId').value = 'qvac-b'
      $('svcModelSrc').value = '/models/qvac-b'
      svcAddModel()
      resolvePost({ ok: true, out: {} })
      await Promise.resolve()
      await Promise.resolve()
      var success = {
        disabled: [$('svcModelId').disabled, $('svcModelSrc').disabled, $('svcModelAdd').disabled],
        button: $('svcModelAdd').textContent,
        message: $('svcModelMessage').textContent,
        className: $('svcModelMessage').className,
        values: [$('svcModelId').value, $('svcModelSrc').value],
        posts: posts.slice(),
        toasts: toasts.slice(),
        refreshes: refreshes.slice()
      }
      return { missing: missing, busy: busy, failed: failed, success: success }
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(script, {
    Promise,
    JSON,
    focusLog,
    posts,
    toasts,
    refreshes,
    document: {
      querySelectorAll: () => [modelId, modelSrc, modelAdd]
    },
    $: (id) => {
      if (id === 'svcModelId') return modelId
      if (id === 'svcModelSrc') return modelSrc
      if (id === 'svcModelAdd') return modelAdd
      if (id === 'svcModelMessage') return modelMessage
      throw new Error('unexpected id ' + id)
    },
    svcPost: (path, body) => {
      posts.push({ path, body })
      return new Promise((resolve) => { resolver = resolve })
    },
    resolvePost: (value) => {
      if (!resolver) throw new Error('missing resolver')
      resolver(value)
      resolver = null
    },
    toast: (msg) => { toasts.push(msg) },
    refreshServices: (force) => { refreshes.push(force) }
  })

  const clean = JSON.parse(JSON.stringify(out))

  t.alike(clean.missing, {
    message: 'Model ID and source required.',
    className: 'svc-model-message error',
    focused: 'id'
  })
  t.is(clean.busy.posts.length, 1)
  t.alike(clean.busy.posts[0], {
    path: '/api/manage/ai/models',
    body: { modelId: 'qvac-a', qvac: { modelSrc: '/models/qvac-a' } }
  })
  t.alike(clean.busy.disabled, [true, true, true])
  t.is(clean.busy.button, 'Adding...')
  t.is(clean.busy.message, 'Adding model...')
  t.alike(clean.failed.disabled, [false, false, false])
  t.is(clean.failed.button, 'Add model')
  t.is(clean.failed.message, 'qvac-a')
  t.is(clean.failed.className, 'svc-model-message error')
  t.alike(clean.success.disabled, [false, false, false])
  t.is(clean.success.button, 'Add model')
  t.is(clean.success.message, 'Model added. Refreshing service state...')
  t.is(clean.success.className, 'svc-model-message ok')
  t.alike(clean.success.values, ['', ''])
  t.is(clean.success.posts.length, 2)
  t.alike(clean.success.toasts, ['Model added: qvac-b'])
  t.alike(clean.success.refreshes, [true])
})

test('umbrel apps list escapes app names and app-key attributes', (t) => {
  const appsList = new FakeElement('div')
  const appsCount = { textContent: '' }
  const script = [
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('shortKey'),
    extractFunction('escapeHtml'),
    extractFunction('renderApps'),
    'renderApps([{ name: "<img src=x onerror=alert(1)>", appKey: "abc\\" onmouseover=\\"alert(1)<script>" }])',
    'JSON.stringify({ html: appsList.innerHTML, assignments: appsList.innerHTMLAssignments })'
  ].join('\n')
  const rendered = JSON.parse(vm.runInNewContext(script, {
    JSON,
    document: {
      createElement: (tag) => new FakeElement(tag)
    },
    appsList,
    $: (id) => {
      if (id === 'appsList') return appsList
      if (id === 'appsCount') return appsCount
      throw new Error('unexpected id ' + id)
    }
  }))

  const html = rendered.html
  t.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(html.includes('title="abc&quot; onmouseover=&quot;alert(1)&lt;script&gt;"'))
  t.absent(html.includes('title="abc" onmouseover='))
  t.absent(html.includes('<script>'))
  t.alike(rendered.assignments, [])
})

test('umbrel service usage meter normalizes untrusted metric values', async (t) => {
  const svcMeterBox = new FakeElement('div')
  const script = [
    extractFunction('escapeHtml'),
    extractFunction('metricCount'),
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('appendSectionTitle'),
    extractFunction('appendMeterRow'),
    extractFunction('renderMetering'),
    'new Promise(function(resolve){',
    '  renderMetering(["vrf", "arbitration"])',
    '  setTimeout(function(){ resolve(JSON.stringify({ html: svcMeterBox.innerHTML, assignments: svcMeterBox.innerHTMLAssignments })) }, 0)',
    '})'
  ].join('\n')
  const rendered = JSON.parse(await vm.runInNewContext(script, {
    JSON,
    svcMeterBox,
    Promise,
    setTimeout,
    document: {
      createElement: (tag) => new FakeElement(tag)
    },
    $: (id) => {
      if (id === 'svcMeterBox') return svcMeterBox
      throw new Error('unexpected id ' + id)
    },
    jget: (path) => {
      if (path === '/api/usage') {
        return Promise.resolve({
          verified: {
            count: '<img src=x onerror=alert(1)>',
            totals: {
              '<script>alert(1)</script>': '<img src=x onerror=alert(2)>'
            }
          }
        })
      }
      if (path === '/api/poker/usage') {
        return Promise.resolve({
          appends: 3,
          seats: '<svg onload=alert(3)>'
        })
      }
      return Promise.resolve(null)
    }
  }))

  const html = rendered.html
  t.ok(html.includes('<span>Signed receipts</span><span>0</span>'))
  t.ok(html.includes('<span>Poker appends</span><span>3</span>'))
  t.ok(html.includes('<span>Poker seats</span><span>0</span>'))
  t.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
  t.absent(html.includes('<img'))
  t.absent(html.includes('<svg'))
  t.absent(html.includes('<script>'))
  t.alike(rendered.assignments, [])
})

function buttonsMissingType (html) {
  const missing = []
  const re = /<button\b([^>]*)>/gi
  let match
  while ((match = re.exec(html)) !== null) {
    const attrs = match[1]
    if (/\btype\s*=\s*["']button["']/i.test(attrs)) continue
    missing.push(match[0])
  }
  return missing
}

function htmlIds (html) {
  return Array.from(html.matchAll(/\bid\s*=\s*["']([^"']+)["']/gi), match => match[1])
}

function countId (html, id) {
  return htmlIds(html).filter(value => value === id).length
}

function runSvcRestartReady ({ now = 3000, startedAt = 0, expected = [], avail }) {
  const script = [
    'var svcRestartExpected = ' + JSON.stringify(expected),
    'var svcRestartStartedAt = ' + JSON.stringify(startedAt),
    extractFunction('svcRestartReady'),
    'svcRestartReady(' + JSON.stringify(avail) + ')'
  ].join('\n')
  return vm.runInNewContext(script, {
    Date: { now: () => now }
  })
}

function extractFunction (name) {
  let start = dashboard.indexOf('function ' + name + '(')
  if (start === -1) throw new Error('missing function ' + name)
  if (dashboard.slice(Math.max(0, start - 6), start) === 'async ') start -= 6
  const firstBrace = dashboard.indexOf('{', dashboard.indexOf(')', start))
  let depth = 0
  for (let i = firstBrace; i < dashboard.length; i++) {
    const char = dashboard[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return dashboard.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tag) {
    this.tag = tag
    this.children = []
    this.parentNode = null
    this.className = ''
    this.id = ''
    this.title = ''
    this.type = ''
    this.value = ''
    this.placeholder = ''
    this.checked = false
    this.disabled = false
    this.attributes = {}
    this.innerHTMLAssignments = []
    this._text = ''
  }

  appendChild (child) {
    child.parentNode = this
    this.children.push(child)
    return child
  }

  removeChild (child) {
    const index = this.children.indexOf(child)
    if (index !== -1) this.children.splice(index, 1)
    child.parentNode = null
    return child
  }

  addEventListener () {}

  setAttribute (name, value) {
    this.attributes[name] = String(value)
  }

  get firstChild () {
    return this.children[0] || null
  }

  set textContent (value) {
    this._text = String(value)
    this.children = []
  }

  get textContent () {
    return this._text + this.children.map((child) => child.textContent).join('')
  }

  set innerHTML (value) {
    this.innerHTMLAssignments.push(String(value))
    this._text = ''
    this.children = []
  }

  get innerHTML () {
    return this.children.map((child) => child.outerHTML).join('')
  }

  get outerHTML () {
    const attrs = []
    if (this.className) attrs.push(['class', this.className])
    if (this.id) attrs.push(['id', this.id])
    if (this.title) attrs.push(['title', this.title])
    if (this.type) attrs.push(['type', this.type])
    if (this.value) attrs.push(['value', this.value])
    if (this.placeholder) attrs.push(['placeholder', this.placeholder])
    if (this.checked) attrs.push(['checked', ''])
    if (this.disabled) attrs.push(['disabled', ''])
    for (const [name, value] of Object.entries(this.attributes)) attrs.push([name, value])
    const attrText = attrs.map(([name, value]) => value === ''
      ? ' ' + name
      : ' ' + name + '="' + escapeFixtureHtml(value) + '"'
    ).join('')
    return '<' + this.tag + attrText + '>' + escapeFixtureHtml(this._text) + this.innerHTML + '</' + this.tag + '>'
  }
}

function escapeFixtureHtml (value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char])
}
