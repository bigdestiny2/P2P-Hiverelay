import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const docs = readFileSync('dashboard/docs.html', 'utf8')

test('docs copy buttons avoid inline handlers and protect external tabs', (t) => {
  const copyButtons = docs.match(/<button\b[^>]*class="copy-btn"[^>]*>/g) || []
  const blankLinks = docs.match(/<a\b[^>]*target="_blank"[^>]*>/g) || []

  t.ok(copyButtons.length > 20, 'docs page has many copyable code blocks')
  t.ok(copyButtons.every(tag => /\btype="button"/.test(tag)), 'copy controls are explicit buttons')
  t.ok(copyButtons.every(tag => /\bdata-docs-action="copy-code"/.test(tag)), 'copy controls use delegated action hooks')
  t.ok(blankLinks.length >= 2, 'external docs links still open in new tabs')
  t.ok(blankLinks.every(tag => /\brel="noopener noreferrer"/.test(tag)), 'new-tab links prevent opener access')
  t.absent(docs.includes('onclick="copyCode'))
  t.absent(docs.includes('onclick='))
})

test('docs copy handler writes the adjacent code block', async (t) => {
  const state = { written: null, timeoutMs: null }
  const btn = {
    textContent: 'Copy',
    classList: {
      added: [],
      removed: [],
      add (name) { this.added.push(name) },
      remove (name) { this.removed.push(name) }
    },
    closest (selector) {
      t.is(selector, '.code-wrap')
      return {
        querySelector (innerSelector) {
          t.is(innerSelector, 'pre')
          return { textContent: 'p2p-hiverelay start --region NA --port 9100' }
        }
      }
    }
  }

  const source = [
    extractFunction('getCodeText'),
    extractFunction('writeClipboard'),
    extractFunction('markCopied'),
    extractFunction('copyCode'),
    'copyCode(btn)'
  ].join('\n')

  await vm.runInNewContext(source, {
    btn,
    navigator: {
      clipboard: {
        async writeText (text) {
          state.written = text
        }
      }
    },
    setTimeout (_fn, delay) {
      state.timeoutMs = delay
    }
  })

  t.is(state.written, 'p2p-hiverelay start --region NA --port 9100')
  t.is(btn.textContent, 'Copied!')
  t.alike(btn.classList.added, ['copied'])
  t.is(state.timeoutMs, 2000)
})

test('docs copy handler uses legacy fallback and reports fallback failures', async (t) => {
  const source = [
    extractFunction('getCodeText'),
    extractFunction('writeClipboard'),
    extractFunction('markCopied'),
    extractFunction('markCopyFailed'),
    extractFunction('copyCode'),
    `
    (async function () {
      function makeBtn () {
        return {
          textContent: 'Copy',
          classList: {
            added: [],
            removed: [],
            add: function (name) { this.added.push(name) },
            remove: function (name) { this.removed.push(name) }
          },
          closest: function () {
            return { querySelector: function () { return { textContent: 'hiverelay docs copy' } } }
          }
        }
      }
      function makeTextarea () {
        return {
          value: '',
          style: {},
          selected: false,
          removed: false,
          setAttribute: function (name, value) { this[name] = value },
          select: function () { this.selected = true },
          remove: function () { this.removed = true }
        }
      }

      var timers = []
      globalThis.setTimeout = function (fn, delay) { timers.push(delay); return timers.length }
      delete globalThis.navigator
      var textareas = []
      globalThis.document = {
        body: {
          appended: [],
          appendChild: function (el) { this.appended.push(el); return el }
        },
        createElement: function () {
          var textarea = makeTextarea()
          textareas.push(textarea)
          return textarea
        },
        execCommand: function (cmd) {
          this.command = cmd
          return true
        }
      }

      var okBtn = makeBtn()
      await copyCode(okBtn)

      var failBtn = makeBtn()
      globalThis.document.execCommand = function () { return false }
      var failCode = null
      try {
        await copyCode(failBtn)
      } catch (err) {
        failCode = err.code
        markCopyFailed(failBtn, err.code === 'clipboard-unavailable' ? 'Clipboard unavailable' : 'Copy failed')
      }

      var unavailableBtn = makeBtn()
      delete globalThis.document.execCommand
      var unavailableCode = null
      try {
        await copyCode(unavailableBtn)
      } catch (err) {
        unavailableCode = err.code
        markCopyFailed(unavailableBtn, err.code === 'clipboard-unavailable' ? 'Clipboard unavailable' : 'Copy failed')
      }

      return {
        okText: okBtn.textContent,
        okClass: okBtn.classList.added.join(','),
        textareaValue: textareas[0].value,
        selected: textareas[0].selected,
        removed: textareas[0].removed,
        command: globalThis.document.command,
        failCode: failCode,
        failText: failBtn.textContent,
        unavailableCode: unavailableCode,
        unavailableText: unavailableBtn.textContent,
        timers: timers.join(',')
      }
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(source, { Promise, Error })

  t.is(out.okText, 'Copied!')
  t.is(out.okClass, 'copied')
  t.is(out.textareaValue, 'hiverelay docs copy')
  t.is(out.selected, true)
  t.is(out.removed, true)
  t.is(out.command, 'copy')
  t.is(out.failCode, 'copy-failed')
  t.is(out.failText, 'Copy failed')
  t.is(out.unavailableCode, 'clipboard-unavailable')
  t.is(out.unavailableText, 'Clipboard unavailable')
  t.is(out.timers, '2000,2000,2000')
})

function extractFunction (name) {
  let start = docs.indexOf('function ' + name)
  if (start === -1) throw new Error('missing function ' + name)
  if (docs.slice(start - 6, start) === 'async ') start -= 6
  const firstBrace = docs.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < docs.length; i++) {
    const char = docs[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return docs.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}
