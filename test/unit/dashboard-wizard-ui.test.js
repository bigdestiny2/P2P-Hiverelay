import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const wizard = readFileSync('dashboard/wizard.html', 'utf8')

test('wizard controls use delegated actions instead of inline handlers', (t) => {
  const actionControls = wizard.match(/\bdata-wizard-action="[^"]+"/g) || []

  t.ok(actionControls.length >= 10, 'wizard exposes setup actions through data attributes')
  t.ok(wizard.includes('data-step-target="relay_name"'))
  t.ok(wizard.includes('data-wizard-action="select-mode" data-mode="review"'))
  t.ok(wizard.includes('data-wizard-action="dashboard"'))
  t.ok(wizard.includes('id="wizard-status" role="status" aria-live="polite"'))
  t.ok(wizard.includes("const el = event.target.closest('[data-wizard-action]')"))
  t.ok(wizard.includes("if (wizardActionBusy && action !== 'select-mode') return"))
  t.ok(wizard.includes("if (action === 'goto') result = goNext(el.dataset.stepTarget || 'welcome')"))
  t.absent(wizard.includes('onclick='))
  t.absent(wizard.includes('href="#"'))
})

test('wizard delegated action router preserves setup behavior', (t) => {
  const calls = []
  let listener = null
  const source = [
    extractFunction('bindWizardActions'),
    'bindWizardActions()'
  ].join('\n')

  vm.runInNewContext(source, {
    document: {
      addEventListener (type, fn) {
        t.is(type, 'click')
        listener = fn
      }
    },
    console,
    goNext (step) {
      calls.push('goto:' + step)
      return Promise.resolve()
    },
    submitRelayName () {
      calls.push('relay-name')
      return Promise.resolve()
    },
    submitPayout () {
      calls.push('payout')
      return Promise.resolve()
    },
    skipPayout () {
      calls.push('skip-payout')
      return Promise.resolve()
    },
    selectMode (mode) {
      calls.push('select-mode:' + mode)
    },
    submitAcceptMode () {
      calls.push('accept-mode')
      return Promise.resolve()
    },
    goToDashboard () {
      calls.push('dashboard')
    },
    wizardActionBusy: false,
    setWizardActionBusy () {}
  })

  for (const dataset of [
    { wizardAction: 'goto', stepTarget: 'relay_name' },
    { wizardAction: 'relay-name' },
    { wizardAction: 'payout' },
    { wizardAction: 'skip-payout' },
    { wizardAction: 'select-mode', mode: 'review' },
    { wizardAction: 'accept-mode' },
    { wizardAction: 'dashboard' }
  ]) {
    let prevented = false
    listener({
      preventDefault () { prevented = true },
      target: {
        closest (selector) {
          t.is(selector, '[data-wizard-action]')
          return { dataset }
        }
      }
    })
    t.ok(prevented, 'delegated action prevents default navigation/submission')
  }

  t.alike(calls, [
    'goto:relay_name',
    'relay-name',
    'payout',
    'skip-payout',
    'select-mode:review',
    'accept-mode',
    'dashboard'
  ])
})

test('wizard delegated action router blocks duplicate pending setup writes', async (t) => {
  const controls = [
    { id: 'btn-relay-name', disabled: false, attributes: {}, setAttribute (key, value) { this.attributes[key] = value }, removeAttribute (key) { delete this.attributes[key] } },
    { id: 'btn-payout', disabled: false, attributes: {}, setAttribute (key, value) { this.attributes[key] = value }, removeAttribute (key) { delete this.attributes[key] } },
    { id: 'setup-logo', attributes: {}, setAttribute (key, value) { this.attributes[key] = value }, removeAttribute (key) { delete this.attributes[key] } }
  ]
  const status = { textContent: '', className: '' }
  const accept = { disabled: false }
  const calls = []
  let listener = null
  let resolvePending = null
  const pending = new Promise(resolve => { resolvePending = resolve })
  const source = [
    'var wizardActionBusy = false',
    'var selectedMode = null',
    extractFunction('wizardActionLabel'),
    extractFunction('setWizardStatus'),
    extractFunction('setWizardActionBusy'),
    extractFunction('bindWizardActions'),
    'bindWizardActions()'
  ].join('\n')

  vm.runInNewContext(source, {
    document: {
      addEventListener (type, fn) {
        t.is(type, 'click')
        listener = fn
      },
      querySelectorAll (selector) {
        t.is(selector, '[data-wizard-action]')
        return controls
      },
      getElementById (id) {
        if (id === 'wizard-status') return status
        if (id === 'btn-accept-mode') return accept
        throw new Error('unexpected id ' + id)
      }
    },
    console,
    goNext () { throw new Error('unexpected goto') },
    submitRelayName () {
      calls.push('relay-name')
      return pending
    },
    submitPayout () { throw new Error('unexpected payout') },
    skipPayout () { throw new Error('unexpected skip') },
    selectMode () { calls.push('select-mode') },
    submitAcceptMode () { throw new Error('unexpected accept mode') },
    goToDashboard () { throw new Error('unexpected dashboard') }
  })

  const event = {
    preventDefault () {},
    target: {
      closest () {
        return { dataset: { wizardAction: 'relay-name' } }
      }
    }
  }

  listener(event)
  listener(event)

  t.alike(calls, ['relay-name'])
  t.is(status.textContent, 'Saving relay name...')
  t.is(status.className, 'wizard-status busy')
  t.ok(controls.every(control => control.disabled === true || control.attributes['aria-disabled'] === 'true'))

  resolvePending()
  await Promise.resolve()
  await Promise.resolve()

  t.is(status.textContent, '')
  t.is(status.className, 'wizard-status')
  t.ok(controls.every(control => control.disabled === false || control.attributes['aria-disabled'] === undefined))
  t.is(accept.disabled, true)
})

test('wizard busy state renders spinner without assigning HTML', (t) => {
  const button = {
    dataset: {},
    disabled: false,
    textContent: 'Continue',
    children: [],
    innerHTMLAssignments: [],
    replaceChildren (...children) {
      this.children = children
      this.textContent = children.map(child => child.textContent || '').join('')
    },
    set innerHTML (value) {
      this.innerHTMLAssignments.push(String(value))
    },
    get innerHTML () {
      return ''
    }
  }
  const source = [
    extractFunction('setBusy'),
    'setBusy("next", true)',
    'setBusy("next", false)'
  ].join('\n')

  vm.runInNewContext(source, {
    document: {
      getElementById (id) {
        t.is(id, 'next')
        return button
      },
      createElement (tag) {
        return { tag, className: '', textContent: '' }
      },
      createTextNode (text) {
        return { isTextNode: true, textContent: text }
      }
    }
  })

  t.alike(button.innerHTMLAssignments, [])
  t.is(button.dataset.label, 'Continue')
  t.is(button.disabled, false)
  t.is(button.textContent, 'Continue')
  t.is(button.children[0].tag, 'span')
  t.is(button.children[0].className, 'loading')
})

test('wizard API helper bounds setup requests and clears timeout handles', async (t) => {
  const calls = []
  let timeoutFn = null
  let cleared = 0
  let aborted = 0
  const source = [
    'const APP_BASE = "/apps/blindspark"',
    'const REQUEST_TIMEOUT_MS = 10000',
    extractFunction('appPath'),
    extractFunction('fetchWithTimeout'),
    'fetchWithTimeout("/api/wizard", { headers: { Accept: "application/json" } })'
  ].join('\n')

  await vm.runInNewContext(source, {
    fetch (url, opts) {
      calls.push({ url, opts })
      return Promise.resolve({ ok: true })
    },
    AbortController: class AbortController {
      constructor () {
        this.signal = { id: 'signal' }
      }

      abort () {
        aborted++
      }
    },
    setTimeout (fn, ms) {
      t.is(ms, 10000)
      timeoutFn = fn
      return 123
    },
    clearTimeout (id) {
      t.is(id, 123)
      cleared++
    }
  })

  t.is(calls.length, 1)
  t.is(calls[0].url, '/apps/blindspark/api/wizard')
  t.is(calls[0].opts.signal.id, 'signal')
  t.is(cleared, 1)
  timeoutFn()
  t.is(aborted, 1)
})

test('wizard load errors render untrusted messages as text', (t) => {
  const card = {
    children: [],
    replaceChildren (...children) {
      this.children = children
    }
  }
  const created = []
  const source = [
    extractFunction('renderLoadError'),
    'renderLoadError({ message: "<img src=x onerror=alert(1)>" })'
  ].join('\n')

  vm.runInNewContext(source, {
    document: {
      querySelector (selector) {
        t.is(selector, '.card')
        return card
      },
      createElement (tag) {
        const element = {
          tag,
          children: [],
          className: '',
          textContent: '',
          append (...items) {
            this.children.push(...items)
          }
        }
        created.push(element)
        return element
      }
    }
  })

  t.is(card.children.length, 3)
  t.is(card.children[0].tag, 'h2')
  t.is(card.children[0].textContent, "Couldn't load setup")
  t.is(card.children[1].children[1].tag, 'code')
  t.is(card.children[1].children[1].textContent, '<img src=x onerror=alert(1)>')
  t.is(card.children[2].className, 'small')
  t.ok(created.every(element => element.innerHTML === undefined), 'renderer did not assign HTML')
})

function extractFunction (name) {
  let start = wizard.indexOf('function ' + name)
  if (start === -1) throw new Error('missing function ' + name)
  if (wizard.slice(Math.max(0, start - 6), start) === 'async ') start -= 6
  const firstBrace = wizard.indexOf('{', wizard.indexOf(')', start))
  let depth = 0
  for (let i = firstBrace; i < wizard.length; i++) {
    const char = wizard[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return wizard.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}
