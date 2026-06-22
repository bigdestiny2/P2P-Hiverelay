/**
 * GatewayServer._serveCatalog advertises config.catalogBeeKey so clients that
 * can replicate + verify a signed P2P catalog prefer it over the HTTP firehose.
 * Only emitted for a valid bare 64-hex key; otherwise the response shape is
 * unchanged. Mirrors the field already surfaced by the relay's /catalog.json.
 */
import test from 'brittle'
import { GatewayServer } from 'p2p-hiverelay/core/relay-node/gateway-server.js'

const KEY = 'f5fb7500bccd60a976d2b1d24246108f4444a210b9ca591533114dffc089934d'

function fakeNode (catalogBeeKey) {
  return {
    store: {},
    config: catalogBeeKey === undefined ? {} : { catalogBeeKey },
    appRegistry: { catalog () { return [{ type: 'app', name: 'x' }] } }
  }
}
function serve (node) {
  // opts.gateway:{} avoids constructing a real HyperGateway.
  const gs = new GatewayServer(node, { gateway: {} })
  let body = ''
  const res = { setHeader () {}, writeHead () {}, end (s) { body += s } }
  gs._serveCatalog({ url: '/catalog.json' }, res)
  return JSON.parse(body)
}

test('advertises catalogBeeKey when a valid 64-hex key is configured', (t) => {
  const r = serve(fakeNode(KEY))
  t.is(r.catalogBeeKey, KEY)
  t.ok(Array.isArray(r.items) && r.items.length === 1, 'normal catalog still served')
})

test('omits the field entirely when unconfigured / empty / invalid', (t) => {
  t.absent('catalogBeeKey' in serve(fakeNode(undefined)), 'unconfigured: field absent')
  t.absent('catalogBeeKey' in serve(fakeNode('')), 'empty string: field absent')
  t.absent('catalogBeeKey' in serve(fakeNode('not-hex')), 'non-hex: field absent')
  t.absent('catalogBeeKey' in serve(fakeNode(KEY.slice(0, 63))), 'wrong length: field absent')
})
