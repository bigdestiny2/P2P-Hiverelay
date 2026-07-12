import net from 'node:net'
import b4a from 'b4a'
import { FAMILY } from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  LOCAL_STREAM_DIRECTION,
  LOCAL_STREAM_FLAG,
  LOCAL_STREAM_FRAME_KIND,
  LocalLengthPrefixedReassembler,
  LocalStreamSequenceGuard,
  LOCAL_RESPONSE_KIND,
  MAX_LOCAL_BODY_BYTES,
  PRIVATE_IPC_LIMITS,
  createLocalAuthenticatedChannelContext,
  decodeLocalStreamFrame,
  decodeLocalStreamOpen,
  decodeLocalResponse,
  encodeLocalStreamOpen,
  encodeLocalRequest,
  fragmentLocalContent,
  localStreamFrameLength,
  localResponseFrameLength
} from '@hiverelay/blind-ipc'

const DEFAULT_TIMEOUT_MS = 15_000
const DEFAULT_WRITE_TIMEOUT_MS = 2_000

function monotonicMillis () {
  return process.hrtime.bigint() / 1_000_000n
}

function positiveInteger (value, fallback, field) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${field} must be a positive safe integer`)
  return value
}

export function exchangeLocal (socketPath, request, options = {}) {
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/') || socketPath.includes('\0')) {
    return Promise.reject(new TypeError('socketPath must be an absolute Unix socket path'))
  }
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 'timeoutMs')
  const familyTimeoutMs = request && request.family === FAMILY.INBOX ? 35_000 : 15_000
  if (timeoutMs > familyTimeoutMs) return Promise.reject(new TypeError(`timeoutMs may only tighten the ${familyTimeoutMs} ms family bound`))
  const writeTimeoutMs = positiveInteger(options.writeTimeoutMs, DEFAULT_WRITE_TIMEOUT_MS, 'writeTimeoutMs')
  if (writeTimeoutMs > DEFAULT_WRITE_TIMEOUT_MS) return Promise.reject(new TypeError('writeTimeoutMs may only tighten the 2000 ms protocol bound'))
  const socketFactory = options.socketFactory == null ? net.createConnection : options.socketFactory
  if (typeof socketFactory !== 'function') return Promise.reject(new TypeError('socketFactory must be a function'))
  const encodedRequest = encodeLocalRequest(request)

  return new Promise((resolve, reject) => {
    const startedMonotonicMillis = monotonicMillis()
    const exchangeDeadlineMonotonicMillis = startedMonotonicMillis + BigInt(timeoutMs)
    const writeDeadlineMonotonicMillis = startedMonotonicMillis + BigInt(Math.min(writeTimeoutMs, timeoutMs))
    let socket = null
    let settled = false
    const chunks = []
    let total = 0
    let expectedLength = null

    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      clearTimeout(writeTimer)
      if (options.signal) options.signal.removeEventListener('abort', onAbort)
      if (socket) socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const onAbort = () => {
      const error = new Error('private IPC exchange aborted')
      error.code = 'ABORT_ERR'
      finish(error)
    }
    const writeTimeoutError = () => {
      const error = new Error('private IPC connect/write timed out')
      error.code = 'IPC_WRITE_TIMEOUT'
      return error
    }
    const timer = setTimeout(() => {
      const error = new Error('private IPC exchange timed out')
      error.code = 'IPC_TIMEOUT'
      finish(error)
    }, timeoutMs)
    const writeTimer = setTimeout(() => {
      finish(writeTimeoutError())
    }, Math.min(writeTimeoutMs, timeoutMs))

    if (options.signal) {
      if (options.signal.aborted) return onAbort()
      options.signal.addEventListener('abort', onAbort, { once: true })
    }
    try {
      socket = socketFactory({ path: socketPath })
    } catch (error) {
      finish(error)
      return
    }
    if (!socket || typeof socket.once !== 'function' || typeof socket.on !== 'function' || typeof socket.write !== 'function' || typeof socket.destroy !== 'function') {
      finish(new TypeError('socketFactory must return a socket-like object'))
      return
    }
    // Keep the writable half open until the daemon returns its one response.
    // Ending here lets Node's default allowHalfOpen=false close the daemon's
    // response half while an asynchronous dispatch is still running.
    socket.once('connect', () => {
      if (monotonicMillis() > writeDeadlineMonotonicMillis) return finish(writeTimeoutError())
      try {
        socket.write(encodedRequest, error => {
          if (error) return finish(error)
          if (monotonicMillis() > writeDeadlineMonotonicMillis) return finish(writeTimeoutError())
          clearTimeout(writeTimer)
        })
      } catch (error) {
        finish(error)
      }
    })
    socket.once('error', finish)
    socket.on('data', chunk => {
      if (monotonicMillis() > exchangeDeadlineMonotonicMillis) {
        const error = new Error('private IPC exchange timed out')
        error.code = 'IPC_TIMEOUT'
        finish(error)
        return
      }
      if (total + chunk.byteLength > 11 + MAX_LOCAL_BODY_BYTES) {
        const error = new Error('private IPC response exceeds its bound')
        error.code = 'IPC_TOO_LARGE'
        finish(error)
        return
      }
      try {
        if (typeof options.reserveBytes === 'function') options.reserveBytes(chunk.byteLength)
      } catch (error) {
        finish(error)
        return
      }
      chunks.push(b4a.from(chunk))
      total += chunk.byteLength
      try {
        if (expectedLength == null && total >= 4) expectedLength = localResponseFrameLength(b4a.concat(chunks, total))
      } catch (error) {
        finish(error)
        return
      }
      if (expectedLength == null || total < expectedLength) return
      if (total !== expectedLength) {
        finish(new Error('private IPC response has trailing bytes'))
        return
      }
      try {
        const response = decodeLocalResponse(b4a.concat(chunks, total), { copyBody: true })
        if (response.responseKind === LOCAL_RESPONSE_KIND.LOCAL_BROKER_ERROR) {
          const error = new Error('private daemon rejected the broker exchange')
          error.code = 'LOCAL_BROKER_ERROR'
          error.localBrokerError = response.localBrokerError
          finish(error)
          return
        }
        if (request.outerClass != null && response.externalCanonicalBytes.byteLength !== request.body.byteLength) {
          finish(new Error('private IPC response changed the selected outer class'))
          return
        }
        finish(null, response.externalCanonicalBytes)
      } catch (error) {
        finish(error)
      }
    })
    socket.once('end', () => {
      if (!settled && (expectedLength == null || total !== expectedLength)) {
        finish(new Error('private IPC response ended before one complete frame'))
      }
    })
  })
}

function asBytes (value, field) {
  if (!value || typeof value.byteLength !== 'number') throw new TypeError(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

async function writeFrames (socket, frames, deadline, now) {
  for (const frame of frames) {
    if (now() > deadline) {
      const error = new Error('private IPC stream write timed out')
      error.code = 'IPC_WRITE_TIMEOUT'
      throw error
    }
    await new Promise((resolve, reject) => {
      let settled = false
      const finish = error => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (error) reject(error)
        else resolve()
      }
      const remaining = deadline - now()
      const timer = setTimeout(() => finish(Object.assign(new Error('private IPC stream write timed out'), {
        code: 'IPC_WRITE_TIMEOUT'
      })), Math.max(1, Number(remaining)))
      if (timer.unref) timer.unref()
      socket.write(frame, finish)
    })
  }
}

// Exchange exactly one canonical length-prefixed dispatch over the authenticated
// PRIVATE_IPC CONTENT path. The caller supplies only locally synthesized channel
// binding inputs; no public header, address, cookie, or application metadata is
// accepted by this API.
export function exchangeLocalContent (socketPath, dispatch, input, options = {}) {
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/') || socketPath.includes('\0')) {
    return Promise.reject(new TypeError('socketPath must be an absolute Unix socket path'))
  }
  try { dispatch = asBytes(dispatch, 'canonical dispatch') } catch (error) { return Promise.reject(error) }
  if (!input || typeof input !== 'object') return Promise.reject(new TypeError('stream binding input is required'))
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 'timeoutMs')
  if (timeoutMs > DEFAULT_TIMEOUT_MS) return Promise.reject(new TypeError('timeoutMs may only tighten 15000 ms'))
  const writeTimeoutMs = positiveInteger(options.writeTimeoutMs, DEFAULT_WRITE_TIMEOUT_MS, 'writeTimeoutMs')
  if (writeTimeoutMs > DEFAULT_WRITE_TIMEOUT_MS) return Promise.reject(new TypeError('writeTimeoutMs may only tighten 2000 ms'))
  const socketFactory = options.socketFactory == null ? net.createConnection : options.socketFactory
  if (typeof socketFactory !== 'function') return Promise.reject(new TypeError('socketFactory must be a function'))

  let openBytes
  let open
  let requestFrames
  try {
    const context = createLocalAuthenticatedChannelContext(input.channel, input.open)
    openBytes = encodeLocalStreamOpen({ ...input.open, context })
    open = decodeLocalStreamOpen(openBytes, { copyContext: true })
    requestFrames = fragmentLocalContent(dispatch, {
      direction: LOCAL_STREAM_DIRECTION.EDGE_TO_DAEMON,
      wireClass: open.channelClass,
      sequence: 0n,
      fin: true
    })
  } catch (error) {
    return Promise.reject(error)
  }

  return new Promise((resolve, reject) => {
    const now = typeof options.monotonicMillis === 'function' ? options.monotonicMillis : monotonicMillis
    const started = now()
    const writeDeadline = started + BigInt(Math.min(timeoutMs, writeTimeoutMs))
    let socket
    let settled = false
    let buffer = b4a.alloc(0)
    const guard = new LocalStreamSequenceGuard(open)
    const reassembler = new LocalLengthPrefixedReassembler()
    const complete = []

    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (options.signal) options.signal.removeEventListener('abort', onAbort)
      if (socket) socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const onAbort = () => finish(Object.assign(new Error('private IPC stream aborted'), { code: 'ABORT_ERR' }))
    const timer = setTimeout(() => finish(Object.assign(new Error('private IPC stream timed out'), {
      code: 'IPC_TIMEOUT'
    })), timeoutMs)
    if (timer.unref) timer.unref()
    if (options.signal) {
      if (options.signal.aborted) return onAbort()
      options.signal.addEventListener('abort', onAbort, { once: true })
    }
    try { socket = socketFactory({ path: socketPath, allowHalfOpen: true }) } catch (error) { return finish(error) }
    if (!socket || typeof socket.once !== 'function' || typeof socket.on !== 'function' ||
        typeof socket.write !== 'function' || typeof socket.end !== 'function' || typeof socket.destroy !== 'function') {
      return finish(new TypeError('socketFactory must return a duplex socket-like object'))
    }
    socket.once('connect', () => {
      writeFrames(socket, [openBytes, ...requestFrames], writeDeadline, now).then(() => {
        // The request direction is terminal after FIN. Half-close it so the
        // daemon can authenticate exact EOF before committing the staged PUT;
        // allowHalfOpen keeps this socket's response direction readable.
        socket.end()
      }).catch(finish)
    })
    socket.once('error', finish)
    socket.on('data', chunk => {
      if (buffer.byteLength + chunk.byteLength > 2 * (PRIVATE_IPC_LIMITS.STREAM_FRAME_HEADER_BYTES +
        PRIVATE_IPC_LIMITS.MAX_STREAM_FRAME_BODY_BYTES)) {
        return finish(Object.assign(new Error('private IPC stream response exceeds its record buffer'), {
          code: 'IPC_TOO_LARGE'
        }))
      }
      buffer = buffer.byteLength === 0 ? b4a.from(chunk) : b4a.concat([buffer, chunk])
      try {
        for (;;) {
          const expected = localStreamFrameLength(buffer)
          if (expected == null || buffer.byteLength < expected) break
          const frame = decodeLocalStreamFrame(buffer.subarray(0, expected), { copyBody: true })
          buffer = b4a.from(buffer.subarray(expected))
          guard.accept(frame)
          if (frame.direction !== LOCAL_STREAM_DIRECTION.DAEMON_TO_EDGE ||
              frame.frameKind !== LOCAL_STREAM_FRAME_KIND.CONTENT) {
            throw new Error('private IPC response contains a non-content frame')
          }
          complete.push(...reassembler.push(frame))
          if ((frame.flags & LOCAL_STREAM_FLAG.FIN) !== 0) {
            if (complete.length !== 1 || buffer.byteLength !== 0) {
              throw new Error('private IPC response did not contain exactly one canonical dispatch')
            }
            return finish(null, complete[0])
          }
        }
      } catch (error) {
        finish(error)
      }
    })
    socket.once('end', () => {
      if (!settled) finish(new Error('private IPC stream ended before one complete response'))
    })
  })
}
