export function hasResponseHeader (res, name) {
  if (typeof res.hasHeader === 'function') return res.hasHeader(name)
  if (typeof res.getHeader === 'function') return res.getHeader(name) != null
  const headers = res.headers || {}
  const lower = name.toLowerCase()
  return Object.keys(headers).some(key => key.toLowerCase() === lower)
}

export function getResponseHeader (res, name) {
  if (typeof res.getHeader === 'function') return res.getHeader(name)
  const headers = res.headers || {}
  const lower = name.toLowerCase()
  const key = Object.keys(headers).find(key => key.toLowerCase() === lower)
  return key ? headers[key] : undefined
}

export function appendVaryHeader (res, value) {
  const existing = getResponseHeader(res, 'Vary')
  if (!existing) {
    res.setHeader('Vary', value)
    return
  }
  const text = Array.isArray(existing) ? existing.join(', ') : String(existing)
  if (text.trim() === '*') return
  const names = text.split(',').map(part => part.trim().toLowerCase()).filter(Boolean)
  if (names.includes(value.toLowerCase())) return
  res.setHeader('Vary', text + ', ' + value)
}

export function writeJson (res, data, status = 200, headers = null) {
  let explicitCacheControl = false
  if (headers) {
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() === 'cache-control') explicitCacheControl = true
      res.setHeader(name, value)
    }
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  if (!explicitCacheControl && !hasResponseHeader(res, 'Cache-Control')) {
    res.setHeader('Cache-Control', 'no-store, max-age=0')
  }
  res.writeHead(status)
  res.end(JSON.stringify(data) + '\n')
}

export function writeText (res, text, status = 200, headers = null) {
  let explicitCacheControl = false
  if (headers) {
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() === 'cache-control') explicitCacheControl = true
      res.setHeader(name, value)
    }
  }
  res.setHeader('Content-Type', 'text/plain; charset=utf-8')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  if (!explicitCacheControl && !hasResponseHeader(res, 'Cache-Control')) {
    res.setHeader('Cache-Control', 'no-store, max-age=0')
  }
  res.writeHead(status)
  res.end(String(text))
}
