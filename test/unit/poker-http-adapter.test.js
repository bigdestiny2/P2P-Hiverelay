import test from 'brittle'
import { Readable } from 'node:stream'
import { handlePokerRoute } from 'p2p-hiveservices/builtin/poker/http-adapter.js'

function fakeReq (method, url, body = null, headers = {}) {
  const chunks = body === null || body === undefined ? [] : [body]
  const req = Readable.from(chunks)
  req.method = method
  req.url = url
  req.headers = { ...headers }
  return req
}

function jsonReq (method, url, body) {
  const text = JSON.stringify(body)
  return fakeReq(method, url, text, {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(text))
  })
}

function fakeRes () {
  const headers = {}
  return {
    headers,
    statusCode: null,
    body: null,
    setHeader (name, value) {
      headers[name] = value
    },
    getHeader (name) {
      return this.header(name)
    },
    hasHeader (name) {
      return this.header(name) !== undefined
    },
    header (name) {
      const lower = name.toLowerCase()
      const key = Object.keys(headers).find(key => key.toLowerCase() === lower)
      return key ? headers[key] : undefined
    },
    writeHead (status) {
      this.statusCode = status
    },
    end (body = '') {
      this.body = String(body)
    }
  }
}

function parseBody (res) {
  return JSON.parse(res.body)
}

test('poker http adapter uses hardened JSON response headers', async (t) => {
  const res = fakeRes()
  const handled = await handlePokerRoute(
    fakeReq('GET', '/api/poker/tables'),
    res,
    {
      pokerApp: {
        listTables () {
          return [{ tableKey: 'table-1', length: 2 }]
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 200)
  t.is(res.header('Content-Type'), 'application/json; charset=utf-8')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.header('Cache-Control'), 'no-store, max-age=0')
  t.is(res.header('Access-Control-Allow-Origin'), '*')
  t.alike(parseBody(res), { tables: [{ tableKey: 'table-1', length: 2 }] })
})

test('poker http adapter rejects body-bearing non-json posts before parsing', async (t) => {
  const res = fakeRes()
  const body = '{"tableKey":'
  let created = false
  const handled = await handlePokerRoute(
    fakeReq('POST', '/api/poker/tables', body, {
      'content-type': 'text/plain',
      'content-length': String(Buffer.byteLength(body))
    }),
    res,
    {
      pokerApp: {
        createTable () {
          created = true
          return { tableKey: 'table-1' }
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 400)
  t.alike(parseBody(res), { error: 'Content-Type must be application/json' })
  t.is(res.header('Connection'), 'close')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.header('Cache-Control'), 'no-store, max-age=0')
  t.is(created, false)
})

test('poker http adapter rejects oversized JSON posts with close hint', async (t) => {
  const res = fakeRes()
  const body = JSON.stringify({ tableKey: 't', payload: 'x'.repeat(128 * 1024) })
  const handled = await handlePokerRoute(
    fakeReq('POST', '/api/poker/tables', body, {
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(body))
    }),
    res,
    {
      pokerApp: {
        createTable () {
          t.fail('createTable should not run for oversized bodies')
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 413)
  t.alike(parseBody(res), { error: 'Request body too large' })
  t.is(res.header('Connection'), 'close')
  t.is(res.header('Content-Type'), 'application/json; charset=utf-8')
})

test('poker http adapter still creates tables from valid JSON posts', async (t) => {
  const res = fakeRes()
  let received = null
  const handled = await handlePokerRoute(
    jsonReq('POST', '/api/poker/tables', {
      tableKey: 'table-1',
      writers: ['a'.repeat(64), 'b'.repeat(64)],
      options: { seats: 2 }
    }),
    res,
    {
      pokerApp: {
        createTable (body) {
          received = body
          return { tableKey: body.tableKey, writers: body.writers, seats: body.options.seats }
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 201)
  t.alike(received, {
    tableKey: 'table-1',
    writers: ['a'.repeat(64), 'b'.repeat(64)],
    options: { seats: 2 }
  })
  t.alike(parseBody(res), {
    tableKey: 'table-1',
    writers: ['a'.repeat(64), 'b'.repeat(64)],
    seats: 2
  })
})

test('poker http adapter redacts unexpected create table errors', async (t) => {
  const res = fakeRes()
  const secretPath = '/data/poker/private/corestore/key-material'
  const handled = await handlePokerRoute(
    jsonReq('POST', '/api/poker/tables', {
      tableKey: 'a'.repeat(64),
      writers: ['b'.repeat(64)]
    }),
    res,
    {
      pokerApp: {
        createTable () {
          throw new Error('corestore failed at ' + secretPath)
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 500)
  t.alike(parseBody(res), { error: 'Poker table create failed' })
  t.absent(res.body.includes(secretPath), 'internal path is not exposed')
  t.is(res.header('X-Content-Type-Options'), 'nosniff')
  t.is(res.header('Cache-Control'), 'no-store, max-age=0')
})

test('poker http adapter normalizes invalid writer errors without reflecting input', async (t) => {
  const res = fakeRes()
  const reflected = '../private/writer-secret'.repeat(20)
  const handled = await handlePokerRoute(
    jsonReq('POST', '/api/poker/tables', {
      tableKey: 'a'.repeat(64),
      writers: [reflected]
    }),
    res,
    {
      pokerApp: {
        createTable () {
          throw new Error('SignedLog: bad writer pubkey: ' + reflected)
        }
      }
    }
  )

  t.is(handled, true)
  t.is(res.statusCode, 400)
  t.alike(parseBody(res), { error: 'SignedLog: bad writer pubkey' })
  t.absent(res.body.includes(reflected), 'untrusted writer input is not reflected')
})

test('poker http adapter redacts unexpected read and move failures', async (t) => {
  const tables = fakeRes()
  const listHandled = await handlePokerRoute(
    fakeReq('GET', '/api/poker/tables'),
    tables,
    {
      pokerApp: {
        listTables () {
          throw new Error('list failed with /private/service-state')
        }
      }
    }
  )

  t.is(listHandled, true)
  t.is(tables.statusCode, 500)
  t.alike(parseBody(tables), { error: 'Poker table list failed' })
  t.absent(tables.body.includes('/private/service-state'))

  const move = fakeRes()
  const moveHandled = await handlePokerRoute(
    jsonReq('POST', '/api/poker/' + 'a'.repeat(64) + '/move', {
      tableKey: 'a'.repeat(64),
      writer: 'b'.repeat(64),
      seq: 0,
      ts: Date.now(),
      payload: {}
    }),
    move,
    {
      pokerApp: {
        submitEntry () {
          throw new Error('append failed with token=super-secret')
        }
      }
    }
  )

  t.is(moveHandled, true)
  t.is(move.statusCode, 500)
  t.alike(parseBody(move), { error: 'Poker move failed' })
  t.absent(move.body.includes('super-secret'))
})
