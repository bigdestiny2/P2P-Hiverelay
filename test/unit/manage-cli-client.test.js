import test from 'brittle'
import http from 'node:http'
import { RelayClient } from '../../packages/core/cli/manage.js'

function listen (server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

function close (server) {
  return new Promise((resolve) => server.close(resolve))
}

test('manage CLI client attaches bearer auth to GET and POST requests', async (t) => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push({
      method: req.method,
      url: req.url,
      authorization: req.headers.authorization,
      contentType: req.headers['content-type']
    })
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: true }))
  })
  const port = await listen(server)
  t.teardown(() => close(server))

  const client = new RelayClient('127.0.0.1', port, { apiKey: '  secret-key  ' })
  t.alike(await client.get('/api/manage/config'), { ok: true })
  t.alike(await client.post('/api/manage/config', { regions: ['NA'] }), { ok: true })

  t.is(seen[0].authorization, 'Bearer secret-key')
  t.is(seen[0].contentType, undefined)
  t.is(seen[1].authorization, 'Bearer secret-key')
  t.ok(seen[1].contentType.startsWith('application/json'))
})

test('manage CLI client omits bearer auth when no key is configured', async (t) => {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push(req.headers.authorization || null)
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: true }))
  })
  const port = await listen(server)
  t.teardown(() => close(server))

  const client = new RelayClient('127.0.0.1', port)
  t.alike(await client.get('/health'), { ok: true })
  t.is(seen[0], null)
})
