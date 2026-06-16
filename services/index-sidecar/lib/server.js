// Query server — the §2 read-only HTTP contract the desktop consumes (the
// relay reverse-proxies these so clients hit a single gatewayUrl).
//
// Query model: ?query= is a JMESPath FILTER applied per row against the row's
// json (a row is included iff the expression yields a non-empty match) — the
// row payload is returned INTACT, never replaced by a projection (passing the
// expression through to schema-sheets' list() would replace row.json and
// corrupt the response for non-filter queries). ?type= is a convenience filter.
// ?gte=/?lte= bound the projection WRITE-time (the value surfaced as
// _updatedAt), NOT a content field. Pagination uses /catalog.json's page/pageSize.
import http from 'http'
import { compile, TreeInterpreter } from '@jmespath-community/jmespath'
import { SCHEMA_NAMES } from './schemas.js'

const ROUTE_SCHEMA = {
  '/index/pins': 'pin-registry',
  '/index/relays': 'relay-directory',
  '/index/manifests': 'app-manifest',
  '/index/verifications': 'verification'
}

function sendJSON (res, status, data) {
  const body = JSON.stringify(data)
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
  res.end(body)
}

// True if the JMESPath expression matches the row (used as a predicate so the
// row's json is preserved). Mirrors schema-sheets' [row.json] wrapping so the
// documented [?field=='x'] filter style works.
function matchesQuery (expr, json) {
  try {
    const m = TreeInterpreter.search(expr, [json])
    return Array.isArray(m) ? m.length > 0 : (m != null && m !== false)
  } catch {
    return false
  }
}

export function createServer ({ room, config, log = () => {} }) {
  const defaultPageSize = (config && config.pageSize) || 100

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'GET') return sendJSON(res, 405, { error: 'method not allowed' })
    let url
    try { url = new URL(req.url, 'http://127.0.0.1') } catch { return sendJSON(res, 400, { error: 'bad url' }) }
    const path = url.pathname
    const q = url.searchParams

    try {
      if (path === '/health') {
        return sendJSON(res, 200, { ok: true, indexRoom: room.roomKeyZ32, schemas: SCHEMA_NAMES, log: room.localLength })
      }

      if (path === '/api/index/room') {
        return sendJSON(res, 200, {
          indexRoom: room.roomKeyZ32,
          discoveryKey: room.discoveryKey ? Buffer.from(room.discoveryKey).toString('hex') : null,
          schemas: SCHEMA_NAMES,
          queries: []
        })
      }

      const schema = ROUTE_SCHEMA[path]
      if (!schema) return sendJSON(res, 404, { error: 'not found' })

      // Bounds on write-time only (schema-sheets indexes rows by write time).
      const opts = {}
      const gte = parseInt(q.get('gte'), 10)
      const lte = parseInt(q.get('lte'), 10)
      if (Number.isFinite(gte)) opts.gte = gte
      if (Number.isFinite(lte)) opts.lte = lte

      // Fetch WITHOUT a query so schema-sheets never projects/replaces row.json.
      let rows = await room.list(schema, opts)

      const typeFilter = q.get('type')
      if (typeFilter) rows = rows.filter(r => r.json && r.json.type === typeFilter)

      const query = q.get('query')
      if (query) {
        let expr
        try { expr = compile(query) } catch { return sendJSON(res, 400, { error: 'invalid query expression' }) }
        rows = rows.filter(r => matchesQuery(expr, r.json))
      }

      const shaped = rows.map(r => ({ ...r.json, _uuid: r.uuid, _updatedAt: r.time }))
      const page = Math.max(parseInt(q.get('page'), 10) || 1, 1)
      const pageSize = Math.min(Math.max(parseInt(q.get('pageSize'), 10) || defaultPageSize, 1), 1000)
      const start = (page - 1) * pageSize
      const pageRows = shaped.slice(start, start + pageSize)

      return sendJSON(res, 200, {
        indexRoom: room.roomKeyZ32,
        schema,
        rows: pageRows,
        page,
        pageSize,
        total: shaped.length,
        totalPages: Math.ceil(shaped.length / pageSize) || 0,
        hasNext: start + pageSize < shaped.length,
        hasPrev: page > 1
      })
    } catch (err) {
      log('query error on ' + path + ': ' + err.message)
      return sendJSON(res, 500, { error: 'query failed', detail: err.message })
    }
  })

  return server
}
