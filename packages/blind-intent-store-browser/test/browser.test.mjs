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

for (const [name, engine, options] of [
  ['chromium', chromium, {}],
  ['brave', chromium, { executablePath: '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' }],
  ['firefox', firefox, { executablePath: fileURLToPath(new URL('../.browser-cache/firefox-1538/firefox/Nightly.app/Contents/MacOS/firefox', import.meta.url)) }],
  ['webkit', webkit, {}]
]) {
  test(name + ' real-origin durable CAS, bounds, conflicts, encrypted recovery and lost acknowledgment', { timeout: 90000 }, async t => {
    const browser = await engine.launch({ headless: true, ...options })
    t.after(() => browser.close())
    console.log(JSON.stringify({ engine: name, version: browser.version(), platform: process.platform, arch: process.arch, playwright: '1.62.1' }))
    const context = await browser.newContext()
    const page = await context.newPage()
    const other = await context.newPage()
    for (const p of [page, other]) { await p.goto(origin); await p.waitForFunction(() => window.Backend) }
    const policy = { name: 'test.' + name, origin, mode: 'create', maxRecords: 3, maxTotalBytes: 1024, maxCiphertextBytes: 512 }
    await page.evaluate(async policy => { window.backend = new Backend(policy); await backend.ready() }, policy)
    await other.evaluate(async policy => { window.backend = new Backend({ ...policy, mode: 'reopen' }); await backend.ready() }, policy)
    const subclassCopy = await page.evaluate(async policy => {
      class AliasedBytes extends Uint8Array { slice () { return this.subarray() } }
      const backend = new Backend({ ...policy, name: 'subclass.' + policy.name })
      await backend.ready()
      const key = 'intent:' + '09'.repeat(32)
      const first = new AliasedBytes([7]); const second = new AliasedBytes([11])
      const a = backend.compareAndSwap(key, 0n, first)
      const b = backend.compareAndSwap(key, 1n, second)
      first[0] = 99; second[0] = 99
      const changed = await Promise.all([a, b])
      const stored = [...(await backend.read(key)).ciphertext]
      await backend.close()
      return { changed, stored }
    }, policy)
    assert.deepEqual(subclassCopy, { changed: [true, true], stored: [11] }, 'queued typed-array subclass inputs must be copied without invoking slice')
    const key = 'intent:' + '01'.repeat(32)
    const sameRevision = await Promise.all([page, other].map(p => p.evaluate(async key => backend.compareAndSwap(key, 0n, new Uint8Array([1, 2, 3])), key)))
    assert.deepEqual(sameRevision.sort(), [false, true], 'two real pages serialize exact CAS')
    assert.equal(await page.evaluate(async key => (await backend.read(key)).revision === 1n, key), true)
    assert.equal(await page.evaluate(async policy => {
      try { await new Backend(policy).ready(); return 'unexpected' } catch (error) { return error.code }
    }, policy), 'INTENT_STORE_EXISTS')
    assert.equal(await page.evaluate(async policy => {
      try { await new Backend({ ...policy, name: 'missing', mode: 'reopen' }).ready(); return 'unexpected' } catch (error) { return error.code }
    }, policy), 'INTENT_STORE_MISSING')
    assert.equal(await page.evaluate(policy => {
      try { new Backend({ ...policy, origin: 'https://foreign.example' }); return 'unexpected' } catch (error) { return error.code }
    }, policy), 'INTENT_STORE_ORIGIN')
    await page.evaluate(async () => {
      for (const n of ['02', '03']) await backend.compareAndSwap('intent:' + n.repeat(32), 0n, new Uint8Array(400))
    })
    assert.equal(await page.evaluate(async () => {
      try { await backend.compareAndSwap('intent:' + '04'.repeat(32), 0n, new Uint8Array([9])); return 'unexpected' } catch (error) { return error.code }
    }), 'INTENT_STORE_CAPACITY')
    assert.equal(await page.evaluate(async () => {
      try { await backend.compareAndSwap('intent:' + '01'.repeat(32), 1n, new Uint8Array(400)); return 'unexpected' } catch (error) { return error.code }
    }), 'INTENT_STORE_CAPACITY')
    assert.equal(await page.evaluate(async () => backend.compareAndSwap('intent:' + '02'.repeat(32), 1n, new Uint8Array([8]))), true, 'shrinking update remains possible at record capacity')
    const cursor = await page.evaluate(async () => (await backend.keysPage({ limit: 1 })).cursor)
    await other.evaluate(async key => backend.compareAndSwap(key, 1n, new Uint8Array([4])), key)
    assert.equal(await page.evaluate(async cursor => {
      try { await backend.keysPage({ cursor, limit: 1 }); return 'unexpected' } catch (error) { return error.code }
    }, cursor), 'INTENT_SCAN_CHANGED')
    assert.deepEqual(await page.evaluate(async () => {
      const keys = []; let cursor = null
      do { const page = await backend.keysPage({ cursor, limit: 1 }); keys.push(...page.keys); cursor = page.cursor } while (cursor)
      return keys
    }), ['01', '02', '03'].map(n => 'intent:' + n.repeat(32)))
    const encrypted = await page.evaluate(async key => {
      const secret = new Uint8Array(32).fill(19)
      const cryptoKey = await crypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['encrypt', 'decrypt'])
      const nonce = crypto.getRandomValues(new Uint8Array(12))
      const aad = new TextEncoder().encode(key + ':3')
      const plaintext = new TextEncoder().encode('PRIVATE_CAPABILITY_SENTINEL_same_logical_intent')
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, cryptoKey, plaintext))
      const ciphertext = new Uint8Array(12 + sealed.length); ciphertext.set(nonce); ciphertext.set(sealed, 12)
      if (!await backend.compareAndSwap(key, 2n, ciphertext)) throw Error('encryption CAS conflict')
      const raw = await backend.read(key)
      if (new TextDecoder().decode(raw.ciphertext).includes('PRIVATE_CAPABILITY')) throw Error('plaintext leaked')
      return [...ciphertext]
    }, key)
    await page.reload(); await page.waitForFunction(() => window.Backend)
    await page.evaluate(async policy => { window.backend = new Backend({ ...policy, mode: 'reopen' }); await backend.ready() }, policy)
    assert.deepEqual(await page.evaluate(async key => [...(await backend.read(key)).ciphertext], key), encrypted)
    assert.equal(await page.evaluate(async key => {
      const record = await backend.read(key)
      const cryptoKey = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(19), 'AES-GCM', false, ['decrypt'])
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.ciphertext.slice(0, 12), additionalData: new TextEncoder().encode(key + ':' + record.revision) }, cryptoKey, record.ciphertext.slice(12))
      return new TextDecoder().decode(plaintext)
    }, key), 'PRIVATE_CAPABILITY_SENTINEL_same_logical_intent')
    assert.equal(await page.evaluate(async key => {
      const record = await backend.read(key)
      const wrong = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(20), 'AES-GCM', false, ['decrypt'])
      try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv: record.ciphertext.slice(0, 12), additionalData: new TextEncoder().encode(key + ':' + record.revision) }, wrong, record.ciphertext.slice(12)); return false } catch { return true }
    }, key), true, 'wrong recovered key fails authentication')
    const commonPolicy = { ...policy, name: 'common.' + name, maxTotalBytes: 8192, maxCiphertextBytes: 4096 }
    await page.evaluate(async policy => {
      window.commonBackend = new Backend(policy)
      window.commonStore = new Intent.EncryptedIntentStore({ backend: commonBackend, sealer: Intent.createAesGcmIntentSealer(Intent.createBrowserCryptoRuntime(), new Uint8Array(32).fill(9)) })
      const b = n => new Uint8Array(32).fill(n)
      await commonStore.create(Intent.createClientIntent({ runtime: Intent.createBrowserCryptoRuntime(), intentId: b(1), logicalId: b(2), continuityRoot: b(3), storeId: b(4), descriptorHash: b(5), descriptorSequence: 7n,
        endpointId: 1, transportId: 1, transportSupportBit: 1, privacyProfileBit: 1, familyId: 2, operationId: 1, requestCommitment: b(6), clientNonce: b(7), operationBytes: new TextEncoder().encode('PRIVATE_CAPABILITY_AND_SAME_OPERATION_JOURNAL_V1') }))
      await commonStore.update(b(1), value => ({ ...value, state: Intent.INTENT_STATE.TARGET_PREPARED }))
      await commonStore.update(b(1), value => ({ ...value, state: Intent.INTENT_STATE.SENT, mayHaveCommitted: true, attemptCount: 1 }))
    }, commonPolicy)
    await page.reload(); await page.waitForFunction(() => window.Backend)
    const commonRecovery = await page.evaluate(async policy => {
      const backend = new Backend({ ...policy, mode: 'reopen' })
      const store = new Intent.EncryptedIntentStore({ backend, sealer: Intent.createAesGcmIntentSealer(Intent.createBrowserCryptoRuntime(), new Uint8Array(32).fill(9)) })
      const id = new Uint8Array(32).fill(1)
      const before = await store.read(id)
      await store.update(id, value => ({ ...value, state: Intent.INTENT_STATE.PENDING_UNKNOWN }))
      const after = await store.read(id)
      await backend.close()
      return { beforeState: before.value.state, beforeRevision: String(before.revision), state: after.value.state, revision: String(after.revision), logicalId: [...after.value.logicalId], nonce: [...after.value.clientNonce], operation: new TextDecoder().decode(after.value.operationBytes), mayHaveCommitted: after.value.mayHaveCommitted }
    }, commonPolicy)
    assert.deepEqual(commonRecovery, { beforeState: 3, beforeRevision: '3', state: 5, revision: '4', logicalId: Array(32).fill(2), nonce: Array(32).fill(7), operation: 'PRIVATE_CAPABILITY_AND_SAME_OPERATION_JOURNAL_V1', mayHaveCommitted: true }, 'accepted intent codec/sealer preserves the native common vector across page loss')
    await page.evaluate(async policy => { window.backend = new Backend({ ...policy, mode: 'reopen' }); await backend.ready() }, policy)
    // Suppress the page-facing completion only after a real transaction commits.
    await page.evaluate(key => {
      const original = backend._transaction.bind(backend)
      backend._transaction = (...args) => original(...args).then(result => { window.committedWithoutAck = true; return new Promise(() => {}) })
      backend.compareAndSwap(key, 3n, new Uint8Array([99]))
    }, key)
    await page.waitForFunction(() => window.committedWithoutAck)
    await page.close()
    assert.deepEqual(await other.evaluate(async key => {
      const value = await backend.read(key); return { revision: String(value.revision), ciphertext: [...value.ciphertext] }
    }, key), { revision: '4', ciphertext: [99] }, 'page dies before caller ACK; exact revision remains recoverable')
    await other.evaluate(async () => backend.close())
    await other.evaluate(async name => new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase('hiverelay.private-intent.v1.' + name)
      request.onsuccess = resolve; request.onerror = () => reject(request.error)
    }), policy.name)
    assert.equal(await other.evaluate(async policy => {
      try { await new Backend({ ...policy, mode: 'reopen' }).ready(); return 'unexpected' } catch (error) { return error.code }
    }, policy), 'INTENT_STORE_MISSING', 'database eviction/missing boundary cannot synthesize empty intent state')
    const bounded = await other.evaluate(async policy => {
      const b = new Backend({ ...policy, name: 'admission.' + policy.name, maxRecords: 16, maxTotalBytes: 8192 })
      const input = new Uint8Array([7])
      const operations = Array.from({ length: 8 }, (_, n) => b.compareAndSwap('intent:' + (n + 1).toString(16).padStart(64, '0'), 0n, input))
      input[0] = 9
      let ninth
      try { await b.compareAndSwap('intent:' + '99'.repeat(32), 0n, input) } catch (error) { ninth = error.code }
      const completed = await Promise.all(operations)
      const first = await b.read('intent:' + '1'.padStart(64, '0'))
      await b.close()
      return { ninth, completed, first: [...first.ciphertext] }
    }, policy)
    assert.deepEqual(bounded, { ninth: 'INTENT_STORE_BUSY', completed: Array(8).fill(true), first: [7] })
    const fenced = await other.evaluate(async policy => {
      const b = new Backend({ ...policy, name: 'abort.' + policy.name })
      await b.ready()
      const original = b._db.transaction.bind(b._db)
      let first = true
      b._db.transaction = (...args) => { const tx = original(...args); if (first) { first = false; queueMicrotask(() => tx.abort()) }; return tx }
      const results = await Promise.allSettled([b.compareAndSwap('intent:' + 'aa'.repeat(32), 0n, new Uint8Array([1])), b.compareAndSwap('intent:' + 'bb'.repeat(32), 0n, new Uint8Array([2]))])
      await b.close()
      const reopened = new Backend({ ...policy, name: 'abort.' + policy.name, mode: 'reopen' })
      const records = await Promise.all(['aa', 'bb'].map(async n => String((await reopened.read('intent:' + n.repeat(32))).revision)))
      await reopened.close()
      return { outcomes: results.map(result => result.status), records }
    }, policy)
    assert.deepEqual(fenced, { outcomes: ['rejected', 'rejected'], records: ['0', '0'] }, 'uncertain aborted writer fences queued work in its session')
    await context.close()
  })
}
