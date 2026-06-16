// Thin client for the relay's loopback HTTP surface. The sidecar READS the
// relay's already-public, already-redacted data (the catalogue + the signed
// capability doc) and PUBLISHES its room key back. This keeps the projection
// decoupled: identical whether the relay is local or remote, and the relay
// needs no knowledge of schema-sheets.

// Per-request timeout, optionally combined with an overall-sync deadline signal
// so one slow relay cannot wedge a whole projection pass.
async function getJSON (url, { timeoutMs = 8000, headers = {}, signal = null } = {}) {
  const signals = [AbortSignal.timeout(timeoutMs)]
  if (signal) signals.push(signal)
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.any(signals) })
    const text = await res.text()
    let body
    try { body = JSON.parse(text) } catch { body = null }
    return { ok: res.ok, status: res.status, body }
  } catch (err) {
    return { ok: false, status: 0, body: null, error: err }
  }
}

export class RelayClient {
  constructor ({ baseUrl, apiKey } = {}) {
    this.baseUrl = (baseUrl || '').replace(/\/+$/, '')
    this.apiKey = apiKey || null
  }

  _auth () {
    return this.apiKey ? { Authorization: 'Bearer ' + this.apiKey } : {}
  }

  /**
   * Fetch the full catalogue, following the /catalog.json page/pageSize
   * envelope. Aborts on the shared `signal` (overall sync deadline). Returns
   * { entries, envelope, ok } — ok:false signals an incomplete read so the
   * caller must NOT treat absent entries as deletions.
   */
  async getCatalog ({ maxPages = 25, pageSize = 200, signal = null } = {}) {
    const entries = []
    let envelope = null
    let ok = true
    for (let page = 1; page <= maxPages; page++) {
      const res = await getJSON(`${this.baseUrl}/catalog.json?page=${page}&pageSize=${pageSize}`, { signal })
      if (!res.ok || !res.body) { ok = false; break }
      const body = res.body
      if (page === 1) envelope = body
      const items = Array.isArray(body.items) ? body.items : (Array.isArray(body.entries) ? body.entries : (Array.isArray(body.catalog) ? body.catalog : []))
      entries.push(...items)
      // /catalog.json nests pagination: { page, pageSize, total }
      const pag = body.pagination || {}
      const effPageSize = typeof pag.pageSize === 'number' ? pag.pageSize : pageSize
      const total = typeof pag.total === 'number' ? pag.total : (typeof body.total === 'number' ? body.total : null)
      if (items.length < effPageSize) break
      if (total !== null && entries.length >= total) break
    }
    return { entries, envelope, ok }
  }

  /** Fetch the signed capability doc (relay self-description). */
  async getCapability ({ signal = null } = {}) {
    const res = await getJSON(`${this.baseUrl}/.well-known/hiverelay.json`, { signal })
    if (res.ok && res.body) return res.body
    const alt = await getJSON(`${this.baseUrl}/api/capabilities`, { signal })
    return alt.ok ? alt.body : null
  }

  /** Publish this relay's index-room pointer (operator-authed loopback). */
  async publishRoom (z32) {
    try {
      const r = await fetch(`${this.baseUrl}/api/manage/index-room`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...this._auth() },
        body: JSON.stringify({ room: z32 }),
        signal: AbortSignal.timeout(8000)
      })
      let body = null
      try { body = await r.json() } catch { /* ignore */ }
      return { ok: r.ok, status: r.status, body }
    } catch (err) {
      return { ok: false, status: 0, body: null, error: err }
    }
  }
}
