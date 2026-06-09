/**
 * WebSocket fan-out for PokerApp.
 *
 * Per-table subscription endpoint at `ws://<host>/api/poker/<tableKey>/events`.
 * New connections get an immediate state snapshot, then every successful
 * append on that table's SignedLog is pushed to all subscribers as a
 * `{ type: 'entry', entry }` frame.
 *
 * Follows the same shape as relay-node/ws-feed.js (DashboardFeed) so the
 * relay's existing HTTP upgrade flow stays uniform:
 *
 *   - `new WebSocketServer({ noServer: true })`
 *   - Hooked into the HTTP server's `upgrade` event
 *   - Path-filtered so other upgrade handlers can coexist
 *   - Per-connection cleanup via `ws.on('close', ...)`
 *
 * ─── Concurrency model ─────────────────────────────────────────────────────
 *
 * One WebSocketServer instance services all tables. We maintain a Map of
 * `tableKey → Set<ws>` so an append on table T fans out to only T's clients
 * (not every connected socket). Per-connection, we also hold the
 * PokerApp.subscribe unsubscribe so we can detach cleanly on close.
 *
 * ─── Frames ────────────────────────────────────────────────────────────────
 *
 *   Server → Client:
 *     { type: 'state', state }    on connect / on demand
 *     { type: 'entry', entry, index }    on each successful append
 *     { type: 'error', error }    on subscription failure (e.g. table closed)
 *
 *   Client → Server: ignored. This is a one-way feed. Clients post moves
 *   over HTTP — see http-adapter.js.
 *
 * ─── Auth ──────────────────────────────────────────────────────────────────
 *
 * Optional API-key query param (`?token=...`). Same shape as DashboardFeed
 * so operators can reuse their existing key plumbing. Absent → public read,
 * matching the public read of `/api/poker/<table>/log` over HTTP.
 */

import { WebSocketServer } from 'ws'

const POKER_EVENTS_PREFIX = '/api/poker/'
const POKER_EVENTS_SUFFIX = '/events'
// Outbound buffer cap per client — if a client falls behind by more than
// this many messages, we close the socket rather than letting memory grow
// unbounded. Real interactive poker traffic should stay well below this.
const MAX_BUFFERED_PER_CLIENT = 256 * 1024 // 256 KB

/**
 * Match `/api/poker/<tableKey>/events` and return the tableKey, or null.
 * Strict: rejects trailing junk so `/events/extra` doesn't match.
 */
function matchTableKey (pathname) {
  if (!pathname.startsWith(POKER_EVENTS_PREFIX)) return null
  if (!pathname.endsWith(POKER_EVENTS_SUFFIX)) return null
  const inner = pathname.slice(POKER_EVENTS_PREFIX.length, pathname.length - POKER_EVENTS_SUFFIX.length)
  if (!inner || inner.includes('/')) return null
  if (!/^[0-9a-f]{64}$/i.test(inner)) return null
  return inner.toLowerCase()
}

export class PokerWsAdapter {
  /**
   * @param {object} opts
   * @param {import('./index.js').PokerApp} opts.pokerApp
   * @param {import('http').Server} opts.server  HTTP server to hook upgrade on.
   * @param {string|string[]} [opts.corsOrigins]  '*' (default) or allowlist.
   * @param {string} [opts.apiKey]               Optional auth token.
   * @param {(label, info) => void} [opts.log]   Optional logger.
   */
  constructor (opts) {
    if (!opts || !opts.pokerApp) throw new Error('PokerWsAdapter: pokerApp required')
    if (!opts.server) throw new Error('PokerWsAdapter: server required')
    this.pokerApp = opts.pokerApp
    this.server = opts.server
    this.corsOrigins = opts.corsOrigins || '*'
    this._apiKey = opts.apiKey || null
    this._log = opts.log || (() => {})

    this.wss = null
    /** @type {Map<string, Set<WebSocket>>} */
    this._clientsByTable = new Map()
    /** @type {Map<WebSocket, { tableKey: string, unsub: () => void }>} */
    this._stateByClient = new Map()
    this._upgradeHandler = null
  }

  start () {
    this.wss = new WebSocketServer({ noServer: true })

    this._upgradeHandler = (req, socket, head) => {
      let url
      try { url = new URL(req.url, 'http://localhost') } catch { return /* not ours */ }
      const tableKey = matchTableKey(url.pathname)
      if (!tableKey) return // not our path — let other handlers route it

      // Origin check (matches DashboardFeed semantics).
      if (this.corsOrigins !== '*') {
        const origin = req.headers.origin
        const allowed = Array.isArray(this.corsOrigins) ? this.corsOrigins : [this.corsOrigins]
        if (!origin || !allowed.includes(origin)) {
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
          socket.destroy()
          return
        }
      }
      if (this._apiKey) {
        const token = url.searchParams.get('token')
        if (token !== this._apiKey) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
          socket.destroy()
          return
        }
      }

      // Refuse upgrade if the table doesn't exist — fail closed at handshake
      // time so the client gets an HTTP error rather than a silently-empty
      // socket. Race: the table could be closed between this check and the
      // subscribe() call below; we handle that case too by sending an error
      // frame + closing.
      if (!this.pokerApp.getState(tableKey)) {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n')
        socket.destroy()
        return
      }

      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this._attach(ws, tableKey)
      })
    }
    this.server.on('upgrade', this._upgradeHandler)
  }

  stop () {
    if (this._upgradeHandler && this.server) {
      this.server.removeListener('upgrade', this._upgradeHandler)
      this._upgradeHandler = null
    }
    // Detach every subscription and close every client.
    for (const [ws, st] of this._stateByClient) {
      try { st.unsub && st.unsub() } catch {}
      try { ws.close() } catch {}
    }
    this._stateByClient.clear()
    this._clientsByTable.clear()
    if (this.wss) {
      this.wss.close()
      this.wss = null
    }
  }

  /**
   * Number of currently-connected clients. Exposed for metrics + tests.
   */
  clientCount (tableKey) {
    if (tableKey) {
      const set = this._clientsByTable.get(tableKey.toLowerCase())
      return set ? set.size : 0
    }
    return this._stateByClient.size
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  _attach (ws, tableKey) {
    // Per-client state tracked here so close() can clean up cleanly.
    let unsub
    try {
      unsub = this.pokerApp.subscribe(tableKey, (entry, index) => {
        this._send(ws, { type: 'entry', entry, index })
      })
    } catch (err) {
      // The table was closed between handshake and subscribe — fail soft.
      this._send(ws, { type: 'error', error: 'subscribe-failed:' + (err && err.message) })
      try { ws.close() } catch {}
      return
    }

    let set = this._clientsByTable.get(tableKey)
    if (!set) { set = new Set(); this._clientsByTable.set(tableKey, set) }
    set.add(ws)
    this._stateByClient.set(ws, { tableKey, unsub })

    // Initial snapshot — saves the client a separate HTTP round-trip for
    // /state. If the table goes away before this completes the send fails
    // silently; the close handler still cleans up.
    const snapshot = this.pokerApp.getState(tableKey)
    if (snapshot) this._send(ws, { type: 'state', state: snapshot })

    ws.on('close', () => this._detach(ws))
    ws.on('error', () => { /* close fires after; cleanup happens there */ })
    // We don't read client frames — but install a no-op handler so Node
    // doesn't accumulate unread bytes in the underlying socket buffer.
    ws.on('message', () => {})
  }

  _detach (ws) {
    const st = this._stateByClient.get(ws)
    if (!st) return
    try { st.unsub && st.unsub() } catch {}
    this._stateByClient.delete(ws)
    const set = this._clientsByTable.get(st.tableKey)
    if (set) {
      set.delete(ws)
      if (set.size === 0) this._clientsByTable.delete(st.tableKey)
    }
  }

  _send (ws, frame) {
    if (!ws || ws.readyState !== 1 /* OPEN */) return
    if (ws.bufferedAmount > MAX_BUFFERED_PER_CLIENT) {
      // Client is too far behind. Cut them off rather than letting the
      // outbound buffer eat all the memory.
      this._log('ws-backpressure-disconnect', { bufferedAmount: ws.bufferedAmount })
      try { ws.close() } catch {}
      return
    }
    try {
      ws.send(JSON.stringify(frame))
    } catch (err) {
      this._log('ws-send-error', { error: err && err.message })
    }
  }
}

export { POKER_EVENTS_PREFIX, POKER_EVENTS_SUFFIX, matchTableKey as _matchTableKeyForTest }
