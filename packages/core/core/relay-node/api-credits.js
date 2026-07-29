import { PricingEngine } from '../../incentive/credits/pricing.js'

export const MAX_CREDITS_WALLETS = 100

const DEFAULT_PRICING_ENGINE = new PricingEngine()

const CREDITS_ROUTES = Object.freeze({
  'GET /api/v1/credits/pricing': Object.freeze({
    kind: 'credits-pricing',
    requiresAuth: false
  }),
  'GET /api/v1/credits/pricing/compare': Object.freeze({
    kind: 'credits-pricing-compare',
    requiresAuth: false
  }),
  'GET /api/v1/credits/stats': Object.freeze({
    kind: 'credits-stats',
    requiresAuth: true,
    authMessage: 'Unauthorized — credits stats require API key or localhost'
  }),
  'GET /api/v1/credits/wallets': Object.freeze({
    kind: 'credits-wallets',
    requiresAuth: true,
    authMessage: 'Unauthorized — credits wallets require API key or localhost'
  })
})

export function resolveCreditsRoute (method, path) {
  const route = CREDITS_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildCreditsPricingRoutePayload ({ route, node } = {}) {
  if (!route || route.kind !== 'credits-pricing') return notFound(route)
  const engine = pricingEngine(node)
  return {
    ok: true,
    status: 200,
    payload: engine.getRateCard()
  }
}

export function buildCreditsCompareRoutePayload ({ route, node } = {}) {
  if (!route || route.kind !== 'credits-pricing-compare') return notFound(route)
  const engine = pricingEngine(node)
  return {
    ok: true,
    status: 200,
    payload: engine.getComparison()
  }
}

export function buildCreditsStatsRoutePayload ({ route, node } = {}) {
  if (!route || route.kind !== 'credits-stats') return notFound(route)
  const manager = creditManager(node)
  if (!manager || typeof manager.stats !== 'function') return creditsUnavailable()

  let stats
  try {
    stats = manager.stats()
  } catch {
    return creditsUnavailable()
  }

  return {
    ok: true,
    status: 200,
    payload: {
      credits: {
        totalWallets: finiteCount(stats && stats.totalWallets),
        totalBalance: finiteAmount(stats && stats.totalBalance),
        totalDeposited: finiteAmount(stats && stats.totalDeposited),
        totalSpent: finiteAmount(stats && stats.totalSpent),
        totalWelcomeCredits: finiteAmount(stats && stats.totalWelcomeCredits),
        frozenWallets: finiteCount(stats && stats.frozenWallets),
        avgBalance: finiteAmount(stats && stats.avgBalance)
      }
    }
  }
}

export function buildCreditsWalletsRoutePayload ({ route, node } = {}) {
  if (!route || route.kind !== 'credits-wallets') return notFound(route)
  const manager = creditManager(node)
  if (!manager || !manager.wallets || typeof manager.wallets.values !== 'function') {
    return creditsUnavailable()
  }

  let wallets
  try {
    wallets = Array.from(manager.wallets.values(), sanitizeWallet)
  } catch {
    return creditsUnavailable()
  }

  wallets.sort(compareWallets)
  const total = wallets.length
  if (wallets.length > MAX_CREDITS_WALLETS) wallets.length = MAX_CREDITS_WALLETS

  return {
    ok: true,
    status: 200,
    payload: {
      wallets,
      total,
      truncated: total > wallets.length
    }
  }
}

function pricingEngine (node) {
  const engine = node && node.pricingEngine
  return engine && typeof engine.getRateCard === 'function' && typeof engine.getComparison === 'function'
    ? engine
    : DEFAULT_PRICING_ENGINE
}

function creditManager (node) {
  if (!node) return null
  const manager = node.creditManager
  return manager || null
}

function sanitizeWallet (wallet) {
  const value = wallet && typeof wallet === 'object' ? wallet : {}
  return {
    appPubkey: boundedString(value.appPubkey, 128),
    balance: finiteAmount(value.balance),
    totalDeposited: finiteAmount(value.totalDeposited),
    totalSpent: finiteAmount(value.totalSpent),
    totalBonusReceived: finiteAmount(value.totalBonusReceived),
    welcomeCreditsReceived: finiteAmount(value.welcomeCreditsReceived),
    tier: creditTier(value.tier),
    lastActivity: finiteTimestamp(value.lastActivity),
    createdAt: finiteTimestamp(value.createdAt)
  }
}

function compareWallets (left, right) {
  const activity = (right.lastActivity || 0) - (left.lastActivity || 0)
  if (activity !== 0) return activity
  return String(left.appPubkey || '').localeCompare(String(right.appPubkey || ''))
}

function creditTier (value) {
  if (value === 'standard' || value === 'unlimited') return value
  return 'free'
}

function boundedString (value, maxBytes) {
  if (typeof value !== 'string') return null
  return value.length <= maxBytes ? value : value.slice(0, maxBytes)
}

function finiteAmount (value) {
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : 0
}

function finiteCount (value) {
  return Math.floor(finiteAmount(value))
}

function finiteTimestamp (value) {
  const number = Number(value)
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : null
}

function creditsUnavailable () {
  return {
    ok: false,
    status: 503,
    payload: {
      error: 'credits runtime unavailable',
      errorCode: 'credits-unavailable'
    }
  }
}

function notFound (route) {
  return {
    ok: false,
    status: 404,
    payload: { error: 'unknown credits route', route: route && route.kind }
  }
}
