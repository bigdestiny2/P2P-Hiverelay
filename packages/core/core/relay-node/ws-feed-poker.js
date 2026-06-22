/**
 * WebSocket live feed for poker tables.
 *
 * Mirrors DashboardFeed's `noServer` + shared-upgrade-listener pattern so it
 * coexists on the same HTTP server: the handler returns for any path that
 * isn't a poker events path, letting other upgrade listeners (e.g. /ws) route
 * their own. Each connection subscribes to ONE table's SignedLog and forwards
 * new entries as they're appended; an optional `?from=N` replays the log from
 * index N as the first frame.
 *
 * The streamed data is the same public, card-blind log that
 * `GET /api/poker/:table/log` already serves (the relay never sees payloads),
 * so the socket is unauthenticated by design — consistent with the open GET
 * reads. Table CREATE remains auth-gated at the HTTP layer.
 */
import { WebSocketServer } from 'ws'

const EVENTS_RE = /^\/api\/poker\/([^/]+)\/events$/

export class PokerFeed {
  constructor (opts = {}) {
    this.server = opts.server || null
    // () => running PokerApp | null. Resolved per-connection so the feed works
    // whether poker was enabled at boot or toggled on later.
    this.getPokerApp = typeof opts.getPokerApp === 'function' ? opts.getPokerApp : () => null
    this.wss = null
    this._upgradeHandler = null
  }

  start () {
    if (!this.server) return
    this.wss = new WebSocketServer({ noServer: true })

    this._upgradeHandler = (req, socket, head) => {
      let url
      try { url = new URL(req.url, 'http://localhost') } catch { return }
      const m = EVENTS_RE.exec(url.pathname)
      if (!m) return // not a poker events path — leave it for other upgrade listeners

      const app = this.getPokerApp()
      if (!app) { socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n'); socket.destroy(); return }

      const tableKey = m[1]
      if (!app.getState(tableKey)) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return }

      const fromRaw = parseInt(url.searchParams.get('from'), 10)
      const from = Number.isFinite(fromRaw) && fromRaw >= 0 ? fromRaw : null

      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this._onConnection(ws, app, tableKey, from)
      })
    }
    this.server.on('upgrade', this._upgradeHandler)
  }

  _onConnection (ws, app, tableKey, from) {
    const sendJson = (obj) => {
      if (ws.readyState === 1) { try { ws.send(JSON.stringify(obj)) } catch {} }
    }

    // First frame: replay from `from`, else the current state snapshot.
    if (from != null) {
      const slice = app.getLog(tableKey, from, Infinity)
      if (slice) sendJson({ type: 'replay', ...slice })
    } else {
      const st = app.getState(tableKey)
      if (st) sendJson({ type: 'state', state: st })
    }

    // Live: forward each newly appended entry for this table.
    let unsub = null
    try {
      unsub = app.subscribe(tableKey, (entry, index) => sendJson({ type: 'entry', index, entry }))
    } catch {
      // Table was reaped between the checks above and here — the socket will
      // just idle until the client closes it.
    }

    const cleanup = () => { if (unsub) { try { unsub() } catch {} unsub = null } }
    ws.on('close', cleanup)
    ws.on('error', cleanup)
  }

  stop () {
    if (this._upgradeHandler && this.server) {
      this.server.removeListener('upgrade', this._upgradeHandler)
      this._upgradeHandler = null
    }
    if (this.wss) {
      for (const ws of this.wss.clients) { try { ws.close() } catch {} }
      this.wss.close()
      this.wss = null
    }
  }
}
