import test from 'brittle'
import {
  buildCorsDecision,
  getAllowedOrigin,
  isPublicPokerCorsRoute
} from 'p2p-hiverelay/core/relay-node/api-cors.js'

test('api cors: origin allowlist supports deny-by-default, strings, arrays, and wildcard', (t) => {
  t.absent(getAllowedOrigin([], 'https://app.example'))
  t.is(getAllowedOrigin(['https://app.example'], 'https://app.example'), 'https://app.example')
  t.is(getAllowedOrigin('https://app.example', 'https://app.example'), 'https://app.example')
  t.is(getAllowedOrigin('*', undefined), '*')
  t.absent(getAllowedOrigin(['https://app.example'], ['https://app.example']))
})

test('api cors: dynamic allowlists vary by Origin while wildcard config does not', (t) => {
  const allowed = buildCorsDecision(['https://app.example'], 'https://app.example', '/health')
  t.is(allowed.allowedOrigin, 'https://app.example')
  t.ok(allowed.varyOrigin)
  t.absent(allowed.preflightDenied)

  const denied = buildCorsDecision(['https://app.example'], 'https://evil.example', '/api/v1/dispatch')
  t.absent(denied.allowedOrigin)
  t.ok(denied.varyOrigin)
  t.ok(denied.preflightDenied)

  const wildcard = buildCorsDecision('*', 'https://anything.example', '/health')
  t.is(wildcard.allowedOrigin, '*')
  t.absent(wildcard.varyOrigin)
  t.absent(wildcard.preflightDenied)
})

test('api cors: public poker routes stay wildcard but usage telemetry stays managed', (t) => {
  t.ok(isPublicPokerCorsRoute('/api/poker/tables'))
  t.ok(isPublicPokerCorsRoute('/api/poker/table-key/events'))
  t.absent(isPublicPokerCorsRoute('/api/poker/usage'))
  t.absent(isPublicPokerCorsRoute('/api/poker'))

  const tables = buildCorsDecision([], 'https://game.example', '/api/poker/tables')
  t.is(tables.allowedOrigin, '*')
  t.absent(tables.varyOrigin)
  t.absent(tables.preflightDenied)
  t.ok(tables.publicPokerRoute)

  const usage = buildCorsDecision([], 'https://game.example', '/api/poker/usage')
  t.absent(usage.allowedOrigin)
  t.ok(usage.varyOrigin)
  t.ok(usage.preflightDenied)
  t.absent(usage.publicPokerRoute)
})
