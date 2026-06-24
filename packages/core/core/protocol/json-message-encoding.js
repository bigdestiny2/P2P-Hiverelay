import b4a from 'b4a'

export function createLengthPrefixedJsonEncoding (opts = {}) {
  const maxBytes = opts.maxBytes
  const malformedError = opts.malformedError || 'bad json'
  const tooLargeError = opts.tooLargeError || 'message too large'
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('createLengthPrefixedJsonEncoding requires a positive safe integer maxBytes')
  }

  function encodeJson (msg) {
    const json = JSON.stringify(msg)
    const byteLength = b4a.byteLength(json)
    if (byteLength > maxBytes) throw new Error(tooLargeError)
    return { json, byteLength }
  }

  return {
    preencode (state, msg) {
      const { byteLength } = encodeJson(msg)
      state.end += 4 + byteLength
    },
    encode (state, msg) {
      const { json } = encodeJson(msg)
      const buf = b4a.from(json)
      state.buffer.writeUInt32BE(buf.length, state.start)
      buf.copy(state.buffer, state.start + 4)
      state.start += 4 + buf.length
    },
    decode (state) {
      const buffer = state && state.buffer
      if (!buffer || typeof buffer.readUInt32BE !== 'function' || typeof buffer.subarray !== 'function') {
        if (state) state.start = 0
        return { type: -1, error: malformedError }
      }

      const bufferLength = buffer.length
      const hasStart = Object.prototype.hasOwnProperty.call(state, 'start')
      const hasEnd = Object.prototype.hasOwnProperty.call(state, 'end')
      const start = hasStart ? state.start : 0
      if (!Number.isSafeInteger(start) || start < 0 || start > bufferLength) {
        state.start = bufferLength
        return { type: -1, error: malformedError }
      }
      const limit = hasEnd ? state.end : bufferLength
      if (!Number.isSafeInteger(limit) || limit < start || limit > bufferLength) {
        state.start = bufferLength
        return { type: -1, error: malformedError }
      }

      if (start + 4 > limit) {
        state.start = limit
        return { type: -1, error: malformedError }
      }

      const len = buffer.readUInt32BE(start)
      if (len > maxBytes) {
        state.start = start + 4 + len
        return { type: -1, error: tooLargeError }
      }
      const end = start + 4 + len
      if (end > limit) {
        state.start = limit
        return { type: -1, error: malformedError }
      }

      const json = buffer.subarray(start + 4, end).toString()
      state.start = end
      try {
        return JSON.parse(json)
      } catch (_) {
        return { type: -1, error: malformedError }
      }
    }
  }
}
