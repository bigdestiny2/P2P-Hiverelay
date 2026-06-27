import { formatErr } from '../error-prefixes.js'

export const INDEX_ROOM_KEY_RE = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/

function badRequest (message) {
  return { error: formatErr('BAD_REQUEST', message) }
}

export function parseIndexRoomRequest (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, message: 'JSON body object required' }
  }

  const room = typeof body.room === 'string' ? body.room.trim() : null
  if (!room || !INDEX_ROOM_KEY_RE.test(room)) {
    return { ok: false, message: 'room must be a 52-char z32 key' }
  }

  return { ok: true, room }
}

export async function runIndexRoomAction ({ body, node, emit = () => {} } = {}) {
  const parsed = parseIndexRoomRequest(body)
  if (!parsed.ok) {
    return {
      ok: false,
      status: 400,
      payload: badRequest(parsed.message)
    }
  }

  if (typeof node?.setIndexRoom !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: formatErr('UNSUPPORTED', 'index room not supported') }
    }
  }

  try {
    await node.setIndexRoom(parsed.room)
    return {
      ok: true,
      status: 200,
      payload: { ok: true, indexRoom: parsed.room }
    }
  } catch (err) {
    emit('index-room-error', { error: err })
    return {
      ok: false,
      status: 503,
      payload: { error: formatErr('PERSIST_FAILED', 'failed to set index room') }
    }
  }
}
