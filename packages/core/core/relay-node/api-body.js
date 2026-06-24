export function readJsonBody (req, maxBytes = 65536) {
  return new Promise((resolve, reject) => {
    let settled = false
    const done = (fn, val) => { if (!settled) { settled = true; fn(val) } }
    let data = ''
    let size = 0
    let tooLarge = false

    req.on('data', (chunk) => {
      if (tooLarge) return
      size += chunk.length
      if (size > maxBytes) {
        tooLarge = true
        data = ''
        req.resume()
        done(reject, new Error('Request body too large'))
        return
      }
      data += chunk
    })
    req.on('end', () => {
      if (tooLarge) return
      let body
      try {
        body = data ? JSON.parse(data) : {}
      } catch {
        done(reject, new Error('Invalid JSON body'))
        return
      }
      if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        done(reject, new Error('JSON body must be an object'))
        return
      }
      done(resolve, body)
    })
    req.on('error', (err) => done(reject, err))
  })
}
