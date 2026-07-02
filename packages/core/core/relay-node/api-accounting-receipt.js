const ACCOUNTING_RECEIPT_ROUTES = Object.freeze({
  'GET /api/accounting/receipt': Object.freeze({
    kind: 'receipt',
    authMessage: 'Unauthorized — accounting receipt requires API key or localhost'
  })
})

export function resolveAccountingReceiptRoute (method, path) {
  const route = ACCOUNTING_RECEIPT_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function accountingReceiptRefreshFlag (value) {
  return value !== '0'
}

export async function buildAccountingReceiptRoutePayload ({ route, node, url = null } = {}) {
  if (!route || route.kind !== 'receipt') {
    return {
      status: 404,
      payload: { error: 'unknown accounting receipt route' }
    }
  }

  return buildAccountingReceiptPayload({
    node,
    refresh: accountingReceiptRefreshFlag(searchParamValue(url, 'refresh'))
  })
}

export async function buildAccountingReceiptPayload ({ node, refresh = true } = {}) {
  if (!node || typeof node.createAccountingReceipt !== 'function') {
    return {
      status: 503,
      payload: { error: 'accounting receipts unavailable' }
    }
  }

  try {
    const receipt = await node.createAccountingReceipt({ refresh })
    return {
      status: 200,
      payload: { receipt }
    }
  } catch (err) {
    return {
      status: 503,
      payload: { error: accountingReceiptErrorMessage(err) }
    }
  }
}

function accountingReceiptErrorMessage (err) {
  return err && err.message ? err.message : 'accounting receipt unavailable'
}

function searchParamValue (url, name) {
  if (!url || !url.searchParams || typeof url.searchParams.get !== 'function') return null
  return url.searchParams.get(name)
}
