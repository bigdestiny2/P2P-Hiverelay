import test from 'brittle'
import { resolveDashboardGetRoute } from 'p2p-hiverelay/core/relay-node/api-dashboard-routes.js'

test('api dashboard routes: dashboard picks full or Blindspark page', (t) => {
  t.alike(resolveDashboardGetRoute({
    path: '/dashboard',
    uiSimple: false,
    isLocalRequest: true
  }), {
    kind: 'serve',
    cacheKey: '_dashboardHtml',
    filename: 'index.html'
  })

  t.alike(resolveDashboardGetRoute({
    path: '/dashboard',
    uiSimple: true,
    isLocalRequest: true
  }), {
    kind: 'serve',
    cacheKey: '_blindsparkHtml',
    filename: 'blindspark.html'
  })
})

test('api dashboard routes: simple mode redirects full operator tabs', (t) => {
  for (const path of ['/network', '/fleet', '/docs', '/payments', '/calculator', '/leaderboard', '/catalog']) {
    t.alike(resolveDashboardGetRoute({
      path,
      uiSimple: true,
      isLocalRequest: true
    }), {
      kind: 'redirect',
      location: '/dashboard'
    }, `${path} redirects to appliance dashboard`)
  }

  t.alike(resolveDashboardGetRoute({
    path: '/network',
    uiSimple: false,
    isLocalRequest: true
  }), {
    kind: 'serve',
    cacheKey: '_networkHtml',
    filename: 'network.html'
  }, 'full dashboard still serves network page')

  t.alike(resolveDashboardGetRoute({
    path: '/fleet',
    uiSimple: false,
    isLocalRequest: true
  }), {
    kind: 'serve',
    cacheKey: '_fleetHtml',
    filename: 'fleet.html'
  }, 'full dashboard still serves fleet page')
})

test('api dashboard routes: wizard remains local unless token exposure is enabled', (t) => {
  t.alike(resolveDashboardGetRoute({
    path: '/wizard',
    isLocalRequest: false,
    uiExposeToken: false
  }), {
    kind: 'forbidden',
    contentType: 'text/plain',
    message: 'Wizard is localhost-only.\n'
  })

  t.alike(resolveDashboardGetRoute({
    path: '/wizard',
    isLocalRequest: false,
    uiExposeToken: true
  }), {
    kind: 'serve',
    cacheKey: '_wizardHtml',
    filename: 'wizard.html'
  })
})

test('api dashboard routes: root redirects by wizard completion state', (t) => {
  t.alike(resolveDashboardGetRoute({
    path: '/',
    wizardComplete: false
  }), {
    kind: 'redirect',
    location: '/wizard'
  })

  t.alike(resolveDashboardGetRoute({
    path: '/',
    wizardComplete: true
  }), {
    kind: 'redirect',
    location: '/dashboard'
  })

  t.is(resolveDashboardGetRoute({ path: '/' }), null, 'root waits for explicit wizard state')
})

test('api dashboard routes: unrelated API paths fall through', (t) => {
  t.is(resolveDashboardGetRoute({
    path: '/api/health-detail',
    isLocalRequest: true
  }), null)
})
