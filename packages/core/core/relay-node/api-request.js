export const JSON_CONTENT_TYPE_ERROR = 'Content-Type must be application/json'

export function getPostJsonContentTypeProblem (req) {
  if (!req || req.method !== 'POST') return null
  const headers = req.headers || {}
  const contentType = headers['content-type'] || ''
  const contentMediaType = contentType.split(';', 1)[0].trim().toLowerCase()
  const contentLength = headers['content-length']
  const transferEncoding = headers['transfer-encoding']
  const hasBody = (contentLength !== undefined && contentLength !== '0') || !!transferEncoding
  if (contentType && contentMediaType !== 'application/json') {
    return { error: JSON_CONTENT_TYPE_ERROR, close: hasBody }
  }
  if (!contentType && hasBody) {
    return { error: JSON_CONTENT_TYPE_ERROR, close: true }
  }
  return null
}
