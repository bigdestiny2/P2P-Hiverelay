const keyMatch = location.pathname.match(/\/v1\/hyper\/([0-9a-f]{64})(?:\/|$)/i)
const appKey = keyMatch ? keyMatch[1].toLowerCase() : null

const gatewayState = document.querySelector('#gateway-state')
const catalogState = document.querySelector('#catalog-state')
const keyNode = document.querySelector('#app-key')
const relaySource = document.querySelector('#relay-source')
const catalogRow = document.querySelector('#catalog-row')
const catalogCount = document.querySelector('#catalog-count')
const anchorState = document.querySelector('#anchor-state')

gatewayState.textContent = appKey ? 'served over HTTP gateway' : 'direct file view'
keyNode.textContent = appKey ? shortKey(appKey) : 'not in gateway path'

loadCatalog().catch((err) => {
  catalogState.textContent = 'unavailable'
  catalogRow.textContent = err.message || 'Catalog fetch failed.'
  anchorState.textContent = 'catalog unavailable'
})

async function loadCatalog () {
  const response = await fetch('/catalog.json', { cache: 'no-store' })
  if (!response.ok) throw new Error('Catalog returned HTTP ' + response.status)

  const catalog = await response.json()
  const apps = Array.isArray(catalog.apps) ? catalog.apps : []
  const entry = appKey
    ? apps.find(app => String(app.appKey || app.driveKey || '').toLowerCase() === appKey)
    : apps.find(app => app.id === 'pearbrowser-marketplace-demo')

  catalogState.textContent = entry ? 'listed in relay catalog' : 'catalog loaded'
  relaySource.textContent = catalog.relayKey ? 'Relay ' + shortKey(catalog.relayKey) : 'Local relay catalog'
  catalogCount.textContent = apps.length + (apps.length === 1 ? ' app' : ' apps')

  if (entry) {
    catalogRow.textContent = (entry.name || entry.id || 'Demo app') + ' is visible from this relay catalog.'
    anchorState.textContent = entry.anchored ? 'anchored' : 'accepted'
  } else {
    catalogRow.textContent = 'Catalog loaded, but this app row is not visible yet.'
    anchorState.textContent = 'row pending'
  }
}

function shortKey (key) {
  return key.slice(0, 10) + '...' + key.slice(-6)
}
