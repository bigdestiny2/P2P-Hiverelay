import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from '../lib/server.js'

// Fake room: exercises the server's routing/pagination/filter without a real
// schema-sheets room.
function fakeRoom (rowsBySchema = {}) {
  return {
    roomKeyZ32: 'y'.repeat(52),
    discoveryKey: Buffer.alloc(32, 1),
    localLength: 3,
    // server applies query/type filtering itself; list returns rows verbatim
    async list (schema, opts = {}) {
      return (rowsBySchema[schema] || []).map((json, i) => ({ uuid: 'u' + i, time: 1000 + i, json }))
    }
  }
}

async function serve (t, room) {
  const server = createServer({ room, config: { pageSize: 2 } })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise(resolve => server.close(resolve)))
  return server.address().port
}

const get = async (port, path) => {
  const res = await fetch(`http://127.0.0.1:${port}${path}`)
  return { status: res.status, body: await res.json() }
}

test('GET /api/index/room returns key + schemas', async (t) => {
  const port = await serve(t, fakeRoom())
  const { status, body } = await get(port, '/api/index/room')
  assert.equal(status, 200)
  assert.equal(body.indexRoom, 'y'.repeat(52))
  assert.deepEqual(body.schemas.sort(), ['app-manifest', 'pin-registry', 'relay-directory', 'verification'])
})

test('GET /index/manifests paginates + carries indexRoom', async (t) => {
  const room = fakeRoom({ 'app-manifest': [{ appId: '1', type: 'standalone' }, { appId: '2', type: 'hypersite' }, { appId: '3', type: 'standalone' }] })
  const port = await serve(t, room)
  const p1 = await get(port, '/index/manifests?page=1')
  assert.equal(p1.body.total, 3)
  assert.equal(p1.body.rows.length, 2, 'pageSize=2')
  assert.equal(p1.body.rows[0]._uuid, 'u0', 'row meta attached')
  const p2 = await get(port, '/index/manifests?page=2')
  assert.equal(p2.body.rows.length, 1)
})

test('GET /index/manifests?type= filters', async (t) => {
  const room = fakeRoom({ 'app-manifest': [{ appId: '1', type: 'standalone' }, { appId: '2', type: 'hypersite' }] })
  const port = await serve(t, room)
  const { body } = await get(port, '/index/manifests?type=hypersite')
  assert.equal(body.total, 1)
  assert.equal(body.rows[0].appId, '2')
})

test('GET /index/manifests?query= filters without corrupting row shape', async (t) => {
  const room = fakeRoom({ 'app-manifest': [{ appId: '1', type: 'standalone', name: 'A' }, { appId: '2', type: 'hypersite', name: 'B' }] })
  const port = await serve(t, room)
  // filter-style query → only standalone, rows intact (not projected to scalars)
  const f = await get(port, '/index/manifests?query=' + encodeURIComponent("[?type=='standalone']"))
  assert.equal(f.body.total, 1)
  assert.equal(f.body.rows[0].appId, '1')
  assert.equal(f.body.rows[0].name, 'A', 'row payload preserved, not replaced by projection')
  // an invalid expression is a clean 400, not a 500
  const bad = await get(port, '/index/manifests?query=' + encodeURIComponent('[?'))
  assert.equal(bad.status, 400)
})

test('GET unknown index path = 404; POST = 405', async (t) => {
  const port = await serve(t, fakeRoom())
  assert.equal((await get(port, '/index/nope')).status, 404)
  const res = await fetch(`http://127.0.0.1:${port}/index/pins`, { method: 'POST' })
  assert.equal(res.status, 405)
})
