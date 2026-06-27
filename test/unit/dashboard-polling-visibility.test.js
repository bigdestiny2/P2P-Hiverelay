import test from 'brittle'
import { readFileSync } from 'node:fs'

const dashboards = new Map([
  ['index', readFileSync('dashboard/index.html', 'utf8')],
  ['network', readFileSync('dashboard/network.html', 'utf8')],
  ['payments', readFileSync('dashboard/payments.html', 'utf8')],
  ['leaderboard', readFileSync('dashboard/leaderboard.html', 'utf8')],
  ['catalog', readFileSync('dashboard/catalog.html', 'utf8')]
])

test('operator dashboards pause automatic polling while hidden', (t) => {
  for (const [name, html] of dashboards) {
    t.ok(html.includes('document.hidden === true'), `${name} checks hidden-tab state`)
    t.ok(html.includes("document.addEventListener('visibilitychange'"), `${name} refreshes when visible again`)
  }

  const index = dashboards.get('index')
  t.ok(index.includes('function refreshData(force)'), 'index wraps HTTP polling')
  t.ok(index.includes('function refreshPending(force)'), 'index wraps pending-request polling')
  t.ok(index.includes('setInterval(function() { refreshData(false); }, ms);'), 'index uses hidden-aware data interval')
  t.ok(index.includes('setInterval(function() { refreshPending(false); }, 10000);'), 'index uses hidden-aware registry interval')
  t.ok(index.includes('if (document.hidden !== true) setTimeout(connectWS, 3000);'), 'index defers reconnects while hidden')
  t.absent(index.includes('setInterval(fetchData, ms);'), 'index no longer schedules direct data fetches')
  t.absent(index.includes('setInterval(function() { if (!autoAcceptToggle.checked) fetchPending(); }, 10000);'), 'index no longer schedules direct pending fetches')

  const network = dashboards.get('network')
  t.ok(network.includes('function refreshNetwork(force)'), 'network wraps HTTP polling')
  t.ok(network.includes('setInterval(function() { refreshNetwork(false); }, ms);'), 'network uses hidden-aware interval')
  t.ok(network.includes('if (document.hidden !== true) setTimeout(connectWS, 3000);'), 'network defers reconnects while hidden')
  t.absent(network.includes('setInterval(refresh, ms);'), 'network no longer schedules direct refreshes')

  const payments = dashboards.get('payments')
  t.ok(payments.includes('function refreshOverview(force)'), 'payments wraps overview polling')
  t.ok(payments.includes('function refreshWallets(force)'), 'payments wraps wallet polling')
  t.ok(payments.includes('setInterval(function() { refreshOverview(false); }, 10000);'), 'payments uses hidden-aware overview interval')
  t.ok(payments.includes('setInterval(function() { refreshWallets(false); }, 30000);'), 'payments uses hidden-aware wallet interval')
  t.ok(payments.includes('if (document.hidden !== true) setTimeout(connectWS, 3000);'), 'payments defers reconnects while hidden')
  t.absent(payments.includes('setInterval(fetchOverview, 10000);'), 'payments no longer schedules direct overview fetches')
  t.absent(payments.includes('setInterval(fetchWallets, 30000);'), 'payments no longer schedules direct wallet fetches')

  const leaderboard = dashboards.get('leaderboard')
  t.ok(leaderboard.includes('function refreshLeaderboardState(force)'), 'leaderboard wraps reputation polling')
  t.ok(leaderboard.includes('refreshLeaderboardState(false);'), 'leaderboard uses hidden-aware interval')
  t.ok(leaderboard.includes('if (document.hidden !== true) setTimeout(connectWS, 5000);'), 'leaderboard defers reconnects while hidden')
  t.absent(leaderboard.includes('fetchLeaderboard();\n    fetchMyPubkey();\n  }, 10000);'), 'leaderboard no longer schedules direct reputation fetches')

  const catalog = dashboards.get('catalog')
  t.ok(catalog.includes('function refreshCatalog (force)'), 'catalog wraps catalog polling')
  t.ok(catalog.includes('setInterval(() => { refreshCatalog(false) }, 30_000)'), 'catalog uses hidden-aware interval')
  t.absent(catalog.includes('setInterval(loadCatalog, 30_000)'), 'catalog no longer schedules direct catalog loads')
})

test('operator dashboards avoid overlapping automatic refreshes', (t) => {
  const index = dashboards.get('index')
  t.ok(index.includes('var dataRefreshBusy = false;'), 'index tracks data refresh in flight')
  t.ok(index.includes('var pendingRefreshBusy = false;'), 'index tracks registry refresh in flight')
  t.ok(index.includes('if (dataRefreshBusy) return;'), 'index skips overlapping data refreshes')
  t.ok(index.includes('dataRefreshBusy = true;'), 'index marks data refresh busy')
  t.ok(index.includes('dataRefreshBusy = false;'), 'index clears data refresh busy state')
  t.ok(index.includes('if (pendingRefreshBusy) return;'), 'index skips overlapping registry refreshes')
  t.ok(index.includes('if (autoAcceptToggle.checked) return;'), 'index skips registry polling in auto-accept mode')
  t.ok(index.includes("return fetchWithTimeout('/api/registry/pending')"), 'index registry fetch returns a promise for cleanup')
  t.ok(index.includes('fetchPending().finally(function()'), 'index clears registry busy state after fetch')

  const network = dashboards.get('network')
  t.ok(network.includes('var networkRefreshBusy = false;'), 'network tracks refresh in flight')
  t.ok(network.includes('if (networkRefreshBusy) return;'), 'network skips overlapping refreshes')
  t.ok(network.includes('networkRefreshBusy = true;'), 'network marks refresh busy')
  t.ok(network.includes('networkRefreshBusy = false;'), 'network clears refresh busy state')
  t.ok(network.includes('refresh().finally(function()'), 'network waits for refresh settlement')

  const payments = dashboards.get('payments')
  t.ok(payments.includes('var overviewRefreshBusy = false;'), 'payments tracks overview refresh in flight')
  t.ok(payments.includes('var walletsRefreshBusy = false;'), 'payments tracks wallet refresh in flight')
  t.ok(payments.includes('if (overviewRefreshBusy) return;'), 'payments skips overlapping overview refreshes')
  t.ok(payments.includes('if (walletsRefreshBusy) return;'), 'payments skips overlapping wallet refreshes')
  t.ok(payments.includes('fetchOverview().finally(function()'), 'payments clears overview busy state after fetch')
  t.ok(payments.includes('fetchWallets().finally(function()'), 'payments clears wallet busy state after fetch')

  const leaderboard = dashboards.get('leaderboard')
  t.ok(leaderboard.includes('var leaderboardRefreshBusy = false;'), 'leaderboard tracks refresh in flight')
  t.ok(leaderboard.includes('if (leaderboardRefreshBusy) return;'), 'leaderboard skips overlapping refreshes')
  t.ok(leaderboard.includes("return fetchWithTimeout('/api/reputation')"), 'leaderboard reputation fetch returns a promise')
  t.ok(leaderboard.includes("return fetchWithTimeout('/api/overview')"), 'leaderboard pubkey fetch returns a promise')
  t.ok(leaderboard.includes('Promise.all([fetchLeaderboard(), fetchMyPubkey()]).finally(function()'), 'leaderboard clears busy state after both fetches settle')

  const catalog = dashboards.get('catalog')
  t.ok(catalog.includes('let catalogRefreshBusy = false'), 'catalog tracks refresh in flight')
  t.ok(catalog.includes('if (catalogRefreshBusy) return'), 'catalog skips overlapping refreshes')
  t.ok(catalog.includes('catalogRefreshBusy = true'), 'catalog marks refresh busy')
  t.ok(catalog.includes('catalogRefreshBusy = false'), 'catalog clears refresh busy state')
  t.ok(catalog.includes('loadCatalog().finally(() =>'), 'catalog waits for catalog load settlement')
})

test('operator dashboards bound automatic HTTP refresh latency', (t) => {
  for (const [name, html] of dashboards) {
    t.ok(html.includes('REQUEST_TIMEOUT_MS = 10000'), `${name} defines a bounded request timeout`)
    t.ok(html.includes('fetchWithTimeout'), `${name} routes polling fetches through timeout helper`)
    t.ok(html.includes('AbortController'), `${name} uses AbortController when available`)
    t.ok(html.includes('clearTimeout(timeout)'), `${name} clears request timeout handles`)
  }

  const index = dashboards.get('index')
  t.ok(index.includes("fetchWithTimeout('/api/overview')"), 'index overview refresh is timeout-bounded')
  t.ok(index.includes("fetchWithTimeout('/api/history?minutes=60')"), 'index history refresh is timeout-bounded')
  t.ok(index.includes("fetchWithTimeout('/api/apps')"), 'index apps refresh is timeout-bounded')
  t.ok(index.includes("fetchWithTimeout('/api/registry/pending')"), 'index registry refresh is timeout-bounded')
  t.ok(index.includes("fetchWithTimeout('/catalog.json')"), 'index catalog name lookup is timeout-bounded')

  const network = dashboards.get('network')
  t.ok(network.includes("fetchWithTimeout('/api/network?detailed=1'"), 'network detailed discovery is timeout-bounded')
  t.ok(network.includes("fetchWithTimeout('/api/network')"), 'network public fallback is timeout-bounded')
  t.absent(network.includes('AbortSignal.timeout'), 'network does not require AbortSignal.timeout support')

  const payments = dashboards.get('payments')
  t.ok(payments.includes("fetchWithTimeout('/api/v1/credits/pricing')"), 'payments pricing fetch is timeout-bounded')
  t.ok(payments.includes("fetchWithTimeout('/api/v1/credits/pricing/compare')"), 'payments pricing comparison fetch is timeout-bounded')
  t.ok(payments.includes("fetchWithTimeout('/api/v1/credits/stats'"), 'payments wallet stats fetch is timeout-bounded')
  t.ok(payments.includes("fetchWithTimeout('/api/overview')"), 'payments overview fetch is timeout-bounded')

  const leaderboard = dashboards.get('leaderboard')
  t.ok(leaderboard.includes("fetchWithTimeout('/api/reputation')"), 'leaderboard reputation fetch is timeout-bounded')
  t.ok(leaderboard.includes("fetchWithTimeout('/api/overview')"), 'leaderboard pubkey fetch is timeout-bounded')

  const catalog = dashboards.get('catalog')
  t.ok(catalog.includes("fetchWithTimeout('/catalog.json?pageSize=200'"), 'catalog refresh is timeout-bounded')
})
