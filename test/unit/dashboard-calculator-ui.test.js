import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const calculator = readFileSync('dashboard/calculator.html', 'utf8')

test('calculator controls avoid inline handlers and use delegated data hooks', (t) => {
  const presetButtons = calculator.match(/<button\b[^>]*class="preset-btn"[^>]*>/g) || []
  const rangeInputs = calculator.match(/<input\b[^>]*type="range"[^>]*>/g) || []
  const numberInputs = calculator.match(/<input\b[^>]*type="number"[^>]*>/g) || []

  t.is(presetButtons.length, 5)
  t.ok(presetButtons.every(tag => /\btype="button"/.test(tag)))
  t.ok(presetButtons.every(tag => /\bdata-calculator-preset="/.test(tag)))
  t.is(rangeInputs.length, 7)
  t.ok(rangeInputs.every(tag => /\bdata-slider-display="/.test(tag)))
  t.ok(numberInputs.length >= 5)
  t.ok(numberInputs.every(tag => /\bdata-calculator-recalculate\b/.test(tag)))
  t.ok(calculator.includes('function bindCalculatorControls()'))
  t.ok(calculator.includes("document.querySelectorAll('[data-calculator-preset]')"))
  t.ok(calculator.includes("document.querySelectorAll('[data-slider-display]')"))
  t.ok(calculator.includes("document.querySelectorAll('[data-calculator-recalculate]')"))
  t.ok(calculator.includes('function renderBreakdown(breakdown, dailySats, btcPrice)'))
  t.absent(calculator.includes('onclick='))
  t.absent(calculator.includes('oninput='))
  t.absent(calculator.includes('innerHTML'))
})

test('calculator delegated control binding preserves preset, slider, and recalculate behavior', (t) => {
  const calls = []
  const preset = fakeControl({ calculatorPreset: 'small' })
  const slider = fakeControl({ sliderDisplay: 'appsVal', sliderSuffix: '' })
  const number = fakeControl({})

  const source = [
    extractFunction('bindCalculatorControls'),
    'bindCalculatorControls()'
  ].join('\n')

  vm.runInNewContext(source, {
    document: {
      querySelectorAll (selector) {
        if (selector === '[data-calculator-preset]') return [preset]
        if (selector === '[data-slider-display]') return [slider]
        if (selector === '[data-calculator-recalculate]') return [number]
        throw new Error('unexpected selector ' + selector)
      }
    },
    applyPreset (name, button) {
      calls.push(['preset', name, button === preset])
    },
    onSlider (input, display, suffix) {
      calls.push(['slider', input === slider, display, suffix])
    },
    recalculate () {
      calls.push(['recalculate'])
    }
  })

  preset.listeners.click()
  slider.listeners.input()
  number.listeners.input()

  t.alike(calls, [
    ['preset', 'small', true],
    ['slider', true, 'appsVal', ''],
    ['recalculate']
  ])
})

test('calculator breakdown renders untrusted labels as text and clamps widths', (t) => {
  const breakdownList = new FakeElement('div')
  const breakdownTotal = new FakeElement('span')
  const source = [
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('numberOrZero'),
    extractFunction('pctWidth'),
    extractFunction('fmt'),
    extractFunction('formatSats'),
    extractFunction('formatUsd'),
    extractFunction('renderBreakdown'),
    'renderBreakdown([{ name: "<img src=x onerror=alert(1)>", detail: "<script>alert(2)</script>", sats: "bad", pct: 2 }], 100, 100000)',
    'document.getElementById("breakdownList").innerHTML'
  ].join('\n')

  const html = vm.runInNewContext(source, {
    Math,
    Number,
    document: {
      createElement: (tag) => new FakeElement(tag),
      getElementById (id) {
        if (id === 'breakdownList') return breakdownList
        if (id === 'breakdownTotal') return breakdownTotal
        throw new Error('unexpected id ' + id)
      }
    }
  })

  t.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(html.includes('&lt;script&gt;alert(2)&lt;/script&gt;'))
  t.ok(html.includes('style="width:100%"'))
  t.ok(breakdownTotal.textContent.includes('100 sats'))
  t.absent(html.includes('<img'))
  t.absent(html.includes('<script>'))
  t.alike(breakdownList.innerHTMLAssignments, [])
})

function fakeControl (dataset) {
  return {
    dataset,
    listeners: {},
    addEventListener (event, fn) {
      this.listeners[event] = fn
    }
  }
}

function extractFunction (name) {
  const start = calculator.indexOf('function ' + name + '(')
  if (start === -1) throw new Error('missing function ' + name)
  const firstBrace = calculator.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < calculator.length; i++) {
    const char = calculator[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return calculator.slice(start, i + 1)
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
    this.style = {}
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
    const style = Object.entries(this.style)
      .map(([name, value]) => name.replace(/[A-Z]/g, c => '-' + c.toLowerCase()) + ':' + value)
      .join(';')
    if (style) attrs.push(['style', style])
    const attrText = attrs.map(([name, value]) => ' ' + name + '="' + escapeFixtureHtml(value) + '"').join('')
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
