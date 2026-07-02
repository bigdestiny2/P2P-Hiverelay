import test from 'brittle'
import {
  INDEX_ROOM_AUTH_MESSAGE,
  INDEX_ROOM_KEY_RE,
  parseIndexRoomRequest,
  resolveIndexRoomRoute,
  runIndexRoomAction
} from '../../packages/core/core/relay-node/api-index-room.js'

const ROOM = 'y'.repeat(52)

test('api index room: route resolver maps only the exact operator index-room route', (t) => {
  t.alike(resolveIndexRoomRoute('POST', '/api/manage/index-room'), {
    kind: 'index-room',
    authMessage: INDEX_ROOM_AUTH_MESSAGE
  })
  t.is(resolveIndexRoomRoute('GET', '/api/manage/index-room'), null, 'wrong method falls through')
  t.is(resolveIndexRoomRoute('POST', '/api/manage/index-room/extra'), null, 'subpath falls through')
  t.is(resolveIndexRoomRoute('POST', '/api/manage/index'), null, 'adjacent management route falls through')
})

test('api index room: validates and trims z32 room requests', async (t) => {
  const calls = []
  const node = {
    async setIndexRoom (room) {
      calls.push(room)
      return room
    }
  }

  t.ok(INDEX_ROOM_KEY_RE.test(ROOM))
  const parsed = parseIndexRoomRequest({ room: `  ${ROOM}  ` })
  t.ok(parsed.ok)
  t.is(parsed.room, ROOM)

  const out = await runIndexRoomAction({ body: { room: `\n${ROOM}\t` }, node })
  t.is(out.status, 200)
  t.alike(out.payload, { ok: true, indexRoom: ROOM })
  t.alike(calls, [ROOM])
})

test('api index room: rejects malformed body and room before mutation', async (t) => {
  const node = {
    async setIndexRoom () {
      t.fail('invalid requests must not call setIndexRoom')
    }
  }
  const cases = [
    [null, 'JSON body object required'],
    [[], 'JSON body object required'],
    [{}, 'room must be a 52-char z32 key'],
    [{ room: '' }, 'room must be a 52-char z32 key'],
    [{ room: '0'.repeat(52) }, 'room must be a 52-char z32 key'],
    [{ room: 'y'.repeat(51) }, 'room must be a 52-char z32 key'],
    [{ room: 'y'.repeat(53) }, 'room must be a 52-char z32 key']
  ]

  for (const [body, message] of cases) {
    const out = await runIndexRoomAction({ body, node })
    t.is(out.status, 400)
    t.ok(out.payload.error.startsWith('bad-request: '))
    t.ok(out.payload.error.includes(message), message)
  }
})

test('api index room: reports unsupported relay node without mutation', async (t) => {
  const out = await runIndexRoomAction({
    body: { room: ROOM },
    node: {}
  })

  t.is(out.status, 503)
  t.is(out.payload.error, 'unsupported: index room not supported')
})

test('api index room: redacts unexpected setter failures and emits raw error internally', async (t) => {
  const error = new Error('storage path /data/private/index-room.json leaked')
  const events = []
  const node = {
    async setIndexRoom () {
      throw error
    }
  }

  const out = await runIndexRoomAction({
    body: { room: ROOM },
    node,
    emit: (...args) => events.push(args)
  })

  t.is(out.status, 503)
  t.is(out.payload.error, 'persist-failed: failed to set index room')
  t.absent(out.payload.error.includes('/data/private'))
  t.is(events.length, 1)
  t.is(events[0][0], 'index-room-error')
  t.is(events[0][1].error, error)
})
