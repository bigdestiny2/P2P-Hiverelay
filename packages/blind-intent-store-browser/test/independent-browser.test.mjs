import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { chromium, firefox, webkit } from 'playwright'
import { build } from '../../../node_modules/esbuild/lib/main.js'
import { createHash } from 'node:crypto'

const code = await readFile(new URL('../index.js', import.meta.url))
const bundle = await build({ stdin: { contents: "export * from './packages/blind-client/intent.js'; export * from './packages/blind-client/runtime/browser.js'", resolveDir: fileURLToPath(new URL('../../../', import.meta.url)) }, bundle: true, write: false, platform: 'browser', format: 'iife', globalName: 'Intent', target: 'es2020', metafile: true })
const intentBundle = bundle.outputFiles[0].contents
console.log(JSON.stringify({ privateIntentBundleSha256: createHash('sha256').update(intentBundle).digest('hex'), inputs: Object.keys(bundle.metafile.inputs) }))
const server = createServer((req, res) => {
  if (req.url === '/index.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(code) } else {
    if (req.url === '/intent.js') { res.setHeader('Content-Type', 'text/javascript'); res.end(intentBundle); return }
    res.setHeader('Content-Type', 'text/html')
    res.end('<!doctype html><script src="/intent.js"></script><script type="module">import {BrowserIntentBackend} from "/index.js";window.Backend=BrowserIntentBackend</script>')
  }
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const origin = `http://127.0.0.1:${server.address().port}`
test.after(() => new Promise(resolve => server.close(resolve)))


// Derived from the independent review's F2 reproduction; broadened to every
// locally qualified browser and coercible/non-string names before storage access.
for (const [name, engine, options] of [
  ['chromium', chromium, {}],
  ['brave', chromium, { executablePath: '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' }],
  ['firefox', firefox, { executablePath: fileURLToPath(new URL('../.browser-cache/firefox-1538/firefox/Nightly.app/Contents/MacOS/firefox', import.meta.url)) }],
  ['webkit', webkit, {}]
]) {
  test(name + ' exact database identity refuses omitted, null and coercible non-string names before open', async t => {
    const browser = await engine.launch({ headless: true, ...options }); t.after(() => browser.close())
    const page = await browser.newPage(); await page.goto(origin); await page.waitForFunction(() => window.Backend)
    const observed = await page.evaluate(async () => {
      const options = { origin: location.origin, mode: 'create', maxRecords: 2, maxTotalBytes: 1024 }
      let storageCalls = 0; let coercions = 0
      const originalOpen = indexedDB.open.bind(indexedDB)
      indexedDB.open = (...args) => { storageCalls++; return originalOpen(...args) }
      const results = []
      const invalid = [{}, { name: undefined }, { name: null }, { name: false }, { name: 0 }, { name: 123 }, { name: [] }, { name: ['valid'] }, { name: new String('valid') }, { name: { toString () { coercions++; return 'valid' } } }, { name: Symbol('valid') }, { name: '' }]
      for (const input of invalid) {
        let backend; let error
        try { backend = new Backend({ ...options, ...input }); await backend.ready() } catch (e) { error = e.code }
        results.push(error || null)
        if (backend) await backend.close()
      }
      const invalidStorageCalls = storageCalls
      const created = new Backend({ ...options, name: 'valid.explicit' }); await created.ready(); await created.close()
      const reopened = new Backend({ ...options, name: 'valid.explicit', mode: 'reopen' }); await reopened.ready(); await reopened.close()
      indexedDB.open = originalOpen
      return { errors: results, invalidStorageCalls, coercions, validStorageCalls: storageCalls - invalidStorageCalls }
    })
    console.log(JSON.stringify({ independentMissingIdentity: observed, engine: name, browser: browser.version() }))
    assert.deepEqual(observed.errors, Array(12).fill('INTENT_STORE_INPUT'))
    assert.equal(observed.invalidStorageCalls, 0)
    assert.equal(observed.coercions, 0)
    assert.equal(observed.validStorageCalls, 2)
  })
}
