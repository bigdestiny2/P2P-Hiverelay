import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const payments = readFileSync('dashboard/payments.html', 'utf8')

test('payments finance reads use the embedded management bearer token', (t) => {
  const source = [
    extractFunction('getUiToken'),
    extractFunction('getUiAuthHeaders'),
    'getUiAuthHeaders()'
  ].join('\n')
  const withToken = vm.runInNewContext(source, {
    document: {
      querySelector () {
        return { getAttribute () { return 'operator-secret' } }
      }
    }
  })
  const withoutToken = vm.runInNewContext(source, {
    document: { querySelector () { return null } }
  })

  t.is(withToken.Authorization, 'Bearer operator-secret')
  t.is(Object.keys(withoutToken).length, 0)
  t.absent(payments.includes('x-api-key'), 'dashboard does not send unsupported empty x-api-key headers')
  t.ok(payments.includes("fetchWithTimeout('/api/v1/credits/stats', { headers: getUiAuthHeaders() })"))
  t.ok(payments.includes("fetchWithTimeout('/api/v1/credits/wallets', { headers: getUiAuthHeaders() })"))
})

test('payments pricing tables render untrusted API strings as DOM text and normalize malformed prices', async (t) => {
  const out = await renderPricing({
    '/api/v1/credits/pricing': {
      'ai.infer"><img src=x onerror=alert(1)>': {
        description: 'local <script>alert(2)</script> route',
        perCall: '<svg onload=alert(3)>',
        perInputToken: '0.002',
        perOutputToken: 'bad',
        perKB: '1"><img src=x>',
        perMs: '0.001'
      }
    },
    '/api/v1/credits/pricing/compare': {
      services: {
        'ai.infer': {
          hiverelay: {
            per1kInput: '<img src=x onerror=alert(4)>',
            per1kInputUsd: '<script>alert(5)</script>',
            per1kOutput: '7',
            per1kOutputUsd: '0.003'
          },
          claude: { per1kInputUsd: '3.5', per1kOutputUsd: '<svg onload=alert(6)>' },
          openai: { per1kInputUsd: '2.25', per1kOutputUsd: '4.5' },
          savingsVsClaude: 'cheaper <img src=x onerror=alert(7)>'
        }
      }
    }
  })

  t.ok(out.rateCard.includes('ai.infer&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(out.rateCard.includes('local &lt;script&gt;alert(2)&lt;/script&gt; route'))
  t.ok(out.rateCard.includes('2.0 sat/1K input'))
  t.ok(out.rateCard.includes('1.0 sat/sec'))
  t.ok(out.compareBody.includes('1 sats ($0.0000)'))
  t.ok(out.compareBody.includes('7 sats ($0.0030)'))
  t.ok(out.compareBody.includes('cheaper &lt;img src=x onerror=alert(7)&gt;'))
  t.absent(out.rateCard.includes('<img'))
  t.absent(out.rateCard.includes('<script>'))
  t.absent(out.rateCard.includes('<svg'))
  t.absent(out.compareBody.includes('<img'))
  t.absent(out.compareBody.includes('<script>'))
  t.absent(out.compareBody.includes('<svg'))
  t.alike(out.innerHTMLAssignments, [])
})

test('payments pricing renderer avoids rate card and comparison innerHTML', async (t) => {
  const out = await renderPricing({
    '/api/v1/credits/pricing': {},
    '/api/v1/credits/pricing/compare': {
      services: {
        'ai.infer': {
          savingsVsClaude: 'no model routes yet'
        }
      }
    }
  })

  t.ok(out.rateCard.includes('No pricing routes advertised yet.'))
  t.ok(out.compareBody.includes('AI Input (1K tokens)'))
  t.ok(out.compareBody.includes('no model routes yet'))
  t.alike(out.innerHTMLAssignments, [])
})

test('payments overview clamps percentages and normalizes counts', (t) => {
  const out = renderOverview({
    overview: {
      metering: {
        totalRevenue: '1200',
        totalCalls: '2500',
        totalApps: '<img src=x onerror=alert(1)>'
      },
      credits: {
        totalWallets: '3.9',
        totalBalance: '-20'
      },
      invoices: {
        settled: '4',
        pending: 'bad',
        expired: '2.7',
        cancelled: '<script>alert(2)</script>',
        totalSettledSats: '9000'
      },
      payment: {
        provider: '<img src=x onerror=alert(3)>',
        accounts: [{
          totalEarned: '100',
          totalPaid: '20',
          currentlyHeld: '80',
          pendingPayout: '10',
          heldPercentage: '350',
          monthsActive: '<svg onload=alert(4)>'
        }]
      }
    }
  })

  t.is(out.totalRevenue.textContent, '1.2k sats')
  t.is(out.totalCalls.textContent, '2.5k')
  t.is(out.totalApps.textContent, '0 apps')
  t.is(out.totalWallets.textContent, '3')
  t.is(out.walletBalance.textContent, '-- total balance')
  t.is(out.invoicePending.textContent, '0 pending')
  t.is(out.invExpired.textContent, '2')
  t.is(out.invCancelled.textContent, '0')
  t.is(out.accHeldPct.textContent, '100%')
  t.is(out.heldBar.style.width, '100%')
  t.is(out.accTenure.textContent, 'Active 0 months (held % decreases over time)')
})

async function renderPricing (responses) {
  const elements = {}
  const source = [
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('appendCell'),
    extractFunction('metricNumber'),
    extractFunction('formatUsd'),
    extractFunction('pricingParts'),
    extractFunction('hasPositivePricePart'),
    extractFunction('isFreeRate'),
    extractFunction('renderRateCard'),
    extractFunction('appendCompareRow'),
    extractFunction('renderPricingComparison'),
    'var REQUEST_TIMEOUT_MS = 10000',
    extractFunction('fetchWithTimeout'),
    extractFunction('fetchPricing'),
    'fetchPricing().then(function(){ return { rateCard: document.getElementById("rateCard").outerHTML, compareBody: document.getElementById("compareBody").outerHTML, innerHTMLAssignments: document._innerHTMLAssignments() } })'
  ].join('\n')
  return vm.runInNewContext(source, context(elements, responses))
}

function renderOverview (data) {
  const elements = {}
  const source = [
    extractFunction('escapeHtml'),
    extractFunction('metricNumber'),
    extractFunction('metricCount'),
    extractFunction('clampPercent'),
    extractFunction('formatUsd'),
    extractFunction('formatSats'),
    extractFunction('formatCount'),
    extractFunction('truncateKey'),
    extractFunction('timeAgo'),
    extractFunction('tierBadge'),
    extractFunction('updatePayments'),
    'updatePayments(' + JSON.stringify(data) + ')',
    'document._elements'
  ].join('\n')
  return vm.runInNewContext(source, context(elements, {}))
}

function context (elements, responses) {
  return {
    Math,
    Number,
    String,
    Object,
    Date,
    Promise,
    console: { warn () {} },
    fetch (url) {
      return Promise.resolve({
        json () {
          return Promise.resolve(responses[url] || {})
        }
      })
    },
    document: {
      _elements: elements,
      _innerHTMLAssignments () {
        return Object.values(elements).flatMap(function (el) {
          return el.innerHTMLAssignments()
        })
      },
      createElement (tag) {
        return new FakeElement(tag)
      },
      getElementById (id) {
        if (!elements[id]) {
          elements[id] = new FakeElement(id === 'compareBody' ? 'tbody' : 'div')
        }
        return elements[id]
      }
    }
  }
}

function extractFunction (name) {
  let start = payments.indexOf('function ' + name)
  if (start === -1) throw new Error('missing function ' + name)
  if (payments.slice(Math.max(0, start - 6), start) === 'async ') start -= 6
  const firstBrace = payments.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < payments.length; i++) {
    const char = payments[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return payments.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tag) {
    this.tag = String(tag || 'div').toLowerCase()
    this.children = []
    this.parentNode = null
    this.style = {}
    this._text = ''
    this._className = ''
    this._colSpan = 0
    this._innerHTMLAssignments = []
  }

  set className (value) {
    this._className = value ? String(value) : ''
  }

  get className () {
    return this._className
  }

  set colSpan (value) {
    this._colSpan = Number(value) || 0
  }

  get colSpan () {
    return this._colSpan
  }

  set textContent (value) {
    this.children = []
    this._text = value === null || value === undefined ? '' : String(value)
  }

  get textContent () {
    return this._text + this.children.map(function (child) {
      return child.textContent
    }).join('')
  }

  set innerHTML (value) {
    this._innerHTMLAssignments.push(String(value))
    this.children = []
    this._text = ''
  }

  get innerHTML () {
    return escapeHtml(this._text) + this.children.map(function (child) {
      return child.outerHTML
    }).join('')
  }

  get outerHTML () {
    const attrs = []
    if (this._className) attrs.push('class="' + escapeHtml(this._className) + '"')
    if (this._colSpan) attrs.push('colspan="' + this._colSpan + '"')
    return '<' + this.tag + (attrs.length ? ' ' + attrs.join(' ') : '') + '>' + this.innerHTML + '</' + this.tag + '>'
  }

  get firstChild () {
    return this.children[0] || null
  }

  appendChild (child) {
    this.children.push(child)
    child.parentNode = this
    return child
  }

  removeChild (child) {
    const index = this.children.indexOf(child)
    if (index !== -1) this.children.splice(index, 1)
    child.parentNode = null
    return child
  }

  innerHTMLAssignments () {
    return this._innerHTMLAssignments.concat(this.children.flatMap(function (child) {
      return child.innerHTMLAssignments()
    }))
  }
}

function escapeHtml (value) {
  return String(value).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  })
}
