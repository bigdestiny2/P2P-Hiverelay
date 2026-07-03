/**
 * HTTP shard transport (CLIENT-SIDE) — the over-the-wire realization of the
 * transport-agnostic put()/fetch() that disperseSecret()/recoverSecret()
 * (blind-shards.js) inject. It turns those into real POST/GET against a relay's
 * mounted `/api/v1/shard` surface (see packages/core … api-shard-http-adapter):
 *
 *   PUT  — sign a custody pin, POST the opaque shard bytes to the assigned relay
 *   GET  — fetch a shard by content address from whichever relay answers
 *
 * Pin signing is INJECTED (`signPin`), not imported: the custody-pin signature
 * must stay byte-identical to the relay's verifier, so the app supplies the
 * exact signer it already uses rather than this layer reimplementing it. This
 * module depends only on b4a + blind-shards, never on the relay/service code.
 *
 * Uses globalThis.fetch (Node 18+, browsers, Bare via a fetch polyfill) — the
 * same HTTP primitive the rest of the client uses.
 */
import b4a from 'b4a'
import { shardAddressOf } from './blind-shards.js'

const SHARD_PATH = '/api/v1/shard'

function joinUrl (base, path) {
  return String(base).replace(/\/+$/, '') + path
}

function hashOf (shardAddress) {
  const s = String(shardAddress)
  return (s.startsWith('shard:') ? s.slice('shard:'.length) : s).toLowerCase()
}

function toBytes (v) {
  return b4a.isBuffer(v) ? v : b4a.from(v)
}

/**
 * Build a `put(shardBytes, {shareIndex})` for disperseSecret that POSTs one
 * opaque shard to a single relay's `/api/v1/shard`, authorized by a custody pin.
 *
 * @param {object} o
 * @param {string} o.baseUrl   the relay origin, e.g. "https://relay.example:9100"
 * @param {(ctx:{hash:string, address:string, shareIndex:number}) => Promise<object>|object} o.signPin
 *        returns a signed shard pin for this (hash, shareIndex)
 * @param {typeof fetch} [o.fetch]  HTTP impl (defaults to globalThis.fetch)
 * @returns {(bytes:Uint8Array, meta:{shareIndex:number}) => Promise<string>} the shard address
 */
export function createHttpShardPut ({ baseUrl, signPin, fetch = globalThis.fetch } = {}) {
  if (!baseUrl) throw new Error('createHttpShardPut: baseUrl required')
  if (typeof signPin !== 'function') throw new Error('createHttpShardPut: signPin(ctx) required')
  if (typeof fetch !== 'function') throw new Error('createHttpShardPut: fetch unavailable (Node 18+, browser, or a polyfill)')

  return async (bytes, { shareIndex } = {}) => {
    const buf = toBytes(bytes)
    const address = shardAddressOf(buf) // 'shard:<hash>'
    const pin = await signPin({ hash: hashOf(address), address, shareIndex })
    const res = await fetch(joinUrl(baseUrl, SHARD_PATH), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Shard-Pin': JSON.stringify(pin)
      },
      body: buf // raw opaque bytes; the adapter reads them and stores by hash
    })
    if (!res || !res.ok) {
      let detail = ''
      try { detail = (await res.json()).error || '' } catch { /* non-JSON body */ }
      const status = res ? res.status : '?'
      throw new Error('shard PUT failed (' + status + (detail ? ' ' + detail : '') + ') for share ' + shareIndex)
    }
    const out = await res.json()
    return out.shard // 'shard:<hash>' — disperseSecret checks it equals the local address
  }
}

/**
 * Build a `fetch(shardAddress)` for recoverSecret that GETs a shard by content
 * address from the first relay that holds it. Byte integrity is re-checked by
 * recoverSecret (re-hash), so no relay is trusted for the bytes.
 *
 * @param {object} o
 * @param {string[]} o.baseUrls  relay origins to try in order
 * @param {typeof fetch} [o.fetch]
 * @returns {(shardAddress:string) => Promise<Uint8Array|null>}
 */
export function createHttpShardFetch ({ baseUrls, fetch = globalThis.fetch } = {}) {
  const bases = Array.isArray(baseUrls) ? baseUrls.filter(Boolean) : []
  if (!bases.length) throw new Error('createHttpShardFetch: baseUrls[] required')
  if (typeof fetch !== 'function') throw new Error('createHttpShardFetch: fetch unavailable (Node 18+, browser, or a polyfill)')

  return async (shardAddress) => {
    const hash = hashOf(shardAddress)
    for (const base of bases) {
      try {
        const res = await fetch(joinUrl(base, SHARD_PATH + '/' + hash), { method: 'GET' })
        if (res && res.ok) {
          const buf = new Uint8Array(await res.arrayBuffer())
          if (buf.length) return b4a.from(buf)
        }
      } catch {
        // this relay didn't answer / not held here — try the next
      }
    }
    return null
  }
}
