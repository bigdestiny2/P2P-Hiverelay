/**
 * Reference HTTP adapter for PokerApp.
 *
 * Wires the poker substrate to a Node-style http(req, res) callback. The
 * relay's existing HTTP servers (bare-http-server, RelayAPI's gateway) can
 * delegate the `/api/poker/...` prefix to `handlePokerRoute` and get the
 * full route set without re-implementing it.
 *
 * ─── Routes ─────────────────────────────────────────────────────────────────
 *
 *   POST /api/poker/tables
 *     body: { tableKey, writers, options? }
 *     201 → table descriptor | 409 if exists | 400 on bad shape | 503 if full
 *
 *   GET  /api/poker/tables
 *     200 → { tables: [...] }
 *
 *   GET  /api/poker/:tableKey/state
 *     200 → state | 404
 *
 *   GET  /api/poker/:tableKey/log?from=N&limit=M
 *     200 → { from, to, entries } | 404
 *
 *   POST /api/poker/:tableKey/move
 *     body: <signed entry>
 *     200 → { ok: true, index, tick } on success
 *     422 → { ok: false, reason, detail, layer: 'signed-log' }
 *     404 → unknown table
 *
 * WebSocket fan-out (`/api/poker/:tableKey/events`) is deferred — the
 * subscriber API on PokerApp is the integration point. Operators wire it
 * to whatever WS server their relay uses (the hiveworm work-stream's WS
 * shape will fit cleanly here).
 *
 * ─── Why a standalone adapter? ──────────────────────────────────────────────
 *
 * Keeping route definitions in their own module means:
 *   - Both relay HTTP entrypoints (bare-http-server, gateway-server) can
 *     reuse the same handler without duplicating route logic.
 *   - Tests can exercise the routes against a stub `req`/`res` without
 *     spinning up a real server.
 *   - Future adapters (e.g. fastify, hyper-gateway-mounted) can swap in
 *     without touching PokerApp.
 *
 * The adapter does NOT enforce auth — the relay's outer middleware should.
 * Endpoints that mutate state (POST /tables, POST /move) carry signed
 * payloads, so the cryptographic check happens in SignedLog regardless.
 *
 * ─── Why no /dispute-types endpoint here ────────────────────────────────────
 *
 * Poker disputes go through the arbitration service (a separate package).
 * The substrate intentionally does NOT import arbitration — that would make
 * `packages/core` depend on `packages/services`, the wrong dependency
 * direction (services depends on core, never the reverse). Relays that load
 * PokerApp but not arbitration would otherwise fail at module-resolve time.
 *
 * Clients that want the canonical dispute-type list call the arbitration
 * service's own endpoint, or read POKER_DISPUTE_TYPES from
 * `arbitration-service.js` at build time.
 */

import { readJsonBody } from 'p2p-hiverelay/core/relay-node/api-body.js'
import { getPostJsonContentTypeProblem } from 'p2p-hiverelay/core/relay-node/api-request.js'
import { writeJson } from 'p2p-hiverelay/core/relay-node/api-response.js'

const PREFIX = '/api/poker'
const MAX_JSON_BODY_BYTES = 128 * 1024

/**
 * Top-level dispatcher. Returns:
 *   - `true` if it handled the request (sent a response).
 *   - `false` if the path doesn't match (caller should fall through to its
 *     own 404 or next handler).
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {object} ctx
 * @param {import('./index.js').PokerApp} ctx.pokerApp
 * @returns {Promise<boolean>}
 */
export async function handlePokerRoute (req, res, ctx) {
  if (!ctx || !ctx.pokerApp) return false

  let parsed
  try {
    parsed = new URL(req.url, 'http://localhost')
  } catch {
    return false
  }
  const path = parsed.pathname
  if (!path.startsWith(PREFIX)) return false

  // CORS: very permissive by default because the poker substrate is meant
  // to be hit from Pear apps embedded in arbitrary origins. Tighten via a
  // middleware in front if the operator needs to.
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    res.writeHead(204)
    res.end()
    return true
  }

  // /api/poker/tables — list / create
  if (path === PREFIX + '/tables') {
    if (req.method === 'GET') return _listTables(res, ctx)
    if (req.method === 'POST') return _createTable(req, res, ctx)
    return _respond(res, 405, { error: 'method not allowed' })
  }

  // /api/poker/<tableKey>/<verb>
  const rest = path.slice(PREFIX.length + 1) // strip "/api/poker/"
  const [tableKey, verb, ...tail] = rest.split('/')
  if (!tableKey || !verb || tail.length > 0) {
    return _respond(res, 404, { error: 'not found' })
  }

  if (verb === 'state' && req.method === 'GET') {
    return _getState(res, ctx, tableKey)
  }

  if (verb === 'log' && req.method === 'GET') {
    const from = clampInt(parsed.searchParams.get('from'), 0, 0)
    const limit = clampInt(parsed.searchParams.get('limit'), 1, Infinity)
    return _getLog(res, ctx, tableKey, from, limit)
  }

  if (verb === 'move' && req.method === 'POST') {
    return _submitMove(req, res, ctx, tableKey)
  }

  return _respond(res, 404, { error: 'not found' })
}

// ─── Per-route handlers ─────────────────────────────────────────────────────

function _listTables (res, ctx) {
  try {
    return _respond(res, 200, { tables: ctx.pokerApp.listTables() })
  } catch {
    return _respond(res, 500, { error: 'Poker table list failed' })
  }
}

async function _createTable (req, res, ctx) {
  const bodyResult = await _readJson(req)
  if (!bodyResult.ok) {
    return _respond(
      res,
      bodyResult.status,
      { error: bodyResult.error },
      bodyResult.close ? { Connection: 'close' } : null
    )
  }
  const body = bodyResult.body

  try {
    const desc = ctx.pokerApp.createTable({
      tableKey: body.tableKey,
      writers: body.writers,
      options: body.options
    })
    return _respond(res, 201, desc)
  } catch (err) {
    const failure = _createTableFailure(err)
    return _respond(res, failure.status, { error: failure.error })
  }
}

function _getState (res, ctx, tableKey) {
  try {
    const s = ctx.pokerApp.getState(tableKey)
    if (!s) return _respond(res, 404, { error: 'no such table' })
    return _respond(res, 200, s)
  } catch {
    return _respond(res, 500, { error: 'Poker table state failed' })
  }
}

function _getLog (res, ctx, tableKey, from, limit) {
  try {
    const slice = ctx.pokerApp.getLog(tableKey, from, limit)
    if (!slice) return _respond(res, 404, { error: 'no such table' })
    return _respond(res, 200, slice)
  } catch {
    return _respond(res, 500, { error: 'Poker table log failed' })
  }
}

async function _submitMove (req, res, ctx, tableKey) {
  const bodyResult = await _readJson(req)
  if (!bodyResult.ok) {
    return _respond(
      res,
      bodyResult.status,
      { error: bodyResult.error },
      bodyResult.close ? { Connection: 'close' } : null
    )
  }
  const body = bodyResult.body

  let result
  try {
    result = ctx.pokerApp.submitEntry(tableKey, body)
  } catch {
    return _respond(res, 500, { error: 'Poker move failed' })
  }
  if (result.ok) {
    // Mirror hiveworm-style success envelope so clients can be uniform.
    return _respond(res, 200, { ok: true, index: result.index, tick: result.ts })
  }
  if (result.reason === 'no-such-table') {
    return _respond(res, 404, { ok: false, reason: result.reason })
  }
  // Any other reason is a per-entry validation failure — 422.
  return _respond(res, 422, {
    ok: false,
    reason: result.reason,
    detail: result.detail,
    layer: 'signed-log'
  })
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function _respond (res, status, body, headers = null) {
  writeJson(res, body, status, headers)
  return true
}

function _createTableFailure (err) {
  const msg = err && err.message ? err.message : ''
  if (msg.includes('already exists')) {
    return { status: 409, error: 'createTable: table already exists' }
  }
  if (msg.includes('max tables')) {
    return { status: 503, error: 'createTable: max tables reached' }
  }
  if (msg === 'createTable: bad args') {
    return { status: 400, error: msg }
  }
  if (msg === 'SignedLog: bad tableKey') {
    return { status: 400, error: msg }
  }
  if (msg === 'SignedLog: writers must be a non-empty array') {
    return { status: 400, error: msg }
  }
  if (msg.startsWith('SignedLog: bad writer pubkey')) {
    return { status: 400, error: 'SignedLog: bad writer pubkey' }
  }
  return { status: 500, error: 'Poker table create failed' }
}

/**
 * Read a JSON request body with a hard byte cap so a malformed POST can't
 * exhaust memory.
 */
async function _readJson (req, maxBytes = MAX_JSON_BODY_BYTES) {
  const contentTypeProblem = getPostJsonContentTypeProblem(req)
  if (contentTypeProblem) {
    return {
      ok: false,
      status: 400,
      error: contentTypeProblem.error,
      close: contentTypeProblem.close
    }
  }

  try {
    return { ok: true, body: await readJsonBody(req, maxBytes) }
  } catch (err) {
    if (err && err.message === 'Request body too large') {
      return { ok: false, status: 413, error: 'Request body too large', close: true }
    }
    return { ok: false, status: 400, error: 'bad json body', close: false }
  }
}

function clampInt (raw, lo, hi) {
  const n = parseInt(raw, 10)
  if (!Number.isFinite(n) || Number.isNaN(n)) return lo
  if (n < lo) return lo
  if (Number.isFinite(hi) && n > hi) return hi
  return n
}

export { PREFIX as POKER_API_PREFIX }
