const FULL_DASHBOARD_ROUTES = new Map([
  ['/network', { cacheKey: '_networkHtml', filename: 'network.html' }],
  ['/docs', { cacheKey: '_docsHtml', filename: 'docs.html' }],
  ['/payments', { cacheKey: '_paymentsHtml', filename: 'payments.html' }],
  ['/calculator', { cacheKey: '_calculatorHtml', filename: 'calculator.html' }],
  ['/leaderboard', { cacheKey: '_leaderboardHtml', filename: 'leaderboard.html' }],
  ['/catalog', { cacheKey: '_catalogHtml', filename: 'catalog.html' }]
])

export function resolveDashboardGetRoute ({
  path,
  uiSimple = false,
  uiExposeToken = false,
  isLocalRequest = false,
  wizardComplete = null
} = {}) {
  if (path === '/dashboard') {
    return serve(uiSimple ? '_blindsparkHtml' : '_dashboardHtml', uiSimple ? 'blindspark.html' : 'index.html')
  }

  if (uiSimple && FULL_DASHBOARD_ROUTES.has(path)) {
    return redirect('/dashboard')
  }

  if (path === '/wizard') {
    if (!isLocalRequest && !uiExposeToken) {
      return {
        kind: 'forbidden',
        contentType: 'text/plain',
        message: 'Wizard is localhost-only.\n'
      }
    }
    return serve('_wizardHtml', 'wizard.html')
  }

  if (path === '/') {
    if (typeof wizardComplete !== 'boolean') return null
    return redirect(wizardComplete ? '/dashboard' : '/wizard')
  }

  const fullRoute = FULL_DASHBOARD_ROUTES.get(path)
  if (fullRoute) return serve(fullRoute.cacheKey, fullRoute.filename)

  return null
}

function serve (cacheKey, filename) {
  return { kind: 'serve', cacheKey, filename }
}

function redirect (location) {
  return { kind: 'redirect', location }
}
