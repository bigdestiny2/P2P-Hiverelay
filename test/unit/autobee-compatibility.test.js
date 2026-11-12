// Experimental consumer compatibility only. No HiveRelay store adopts Autobee.
// This same disposable storage/replication fixture runs in Node and real Bare.
import test from 'brittle'
import Autobee from 'autobee'
import Corestore from 'corestore'
import b4a from 'b4a'
import { isBare } from 'which-runtime'

const fs = await import(isBare ? 'bare-fs/promises' : 'fs/promises')
const os = await import(isBare ? 'bare-os' : 'os')
const path = await import(isBare ? 'bare-path' : 'path')

function encoded (value) { return b4a.from(JSON.stringify(value)) }

async function until (predicate, label) {
  const deadline = Date.now() + 15000
  while (Date.now() < deadline) {
    if (await bounded(predicate(), label, Math.max(1, deadline - Date.now()))) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  throw new Error(`Autobee compatibility deadline: ${label}`)
}

async function bounded (promise, label, milliseconds = 15000) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Autobee compatibility deadline: ${label}`)), milliseconds)
      })
    ])
  } finally {
    clearTimeout(timer)
  }
}

test('Autobee 2.13.4: multiwriter convergence, fresh reader and cold reopen', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-autobee-compat-'))
  const peers = new Set()
  const streams = new Set()
  let creator = null
  const errors = []
  let cleaning = null
  function cleanup () {
    cleaning ||= closeAll()
    return cleaning
  }
  async function closeAll () {
    for (const stream of streams) stream.destroy()
    for (const peer of peers) await peer.db.close()
    for (const peer of peers) await peer.store.close()
    await fs.rm(root, { recursive: true, force: true })
  }
  t.teardown(cleanup)

  async function apply (nodes, view, host) {
    for (const node of nodes) {
      const op = JSON.parse(b4a.toString(node.value))
      if (op.addWriter) {
        // Membership is controlled by the creating writer in this fixture.
        if (b4a.equals(node.key, creator)) await host.addWriter(op.addWriter)
        continue
      }
      const batch = view.write()
      batch.tryPut(b4a.from(op.key), encoded(op.value))
      await batch.flush()
    }
  }

  async function open (name, key = null) {
    const store = new Corestore(path.join(root, name))
    // Upstream's membership tests use a creator weight of 3 to grant writers.
    const db = new Autobee(store, key, { apply, bootstrapWeight: 3, optimistic: false })
    const peer = { store, db }
    peers.add(peer)
    db.on('error', err => errors.push(err))
    await db.ready()
    return peer
  }

  function connect (left, right) {
    const a = left.db.replicate(true)
    const b = right.db.replicate(false)
    for (const stream of [a, b]) {
      streams.add(stream)
      stream.on('error', err => errors.push(err))
    }
    a.pipe(b).pipe(a)
    return [a, b]
  }

  async function value (peer, key) {
    const row = await peer.db.view.get(b4a.from(key))
    return row ? JSON.parse(b4a.toString(row.value)) : null
  }

  try {
    const a = await open('writer-a')
    creator = b4a.from(a.db.local.key)
    const key = b4a.from(a.db.key)
    const b = await open('writer-b', key)
    const writerB = b4a.from(b.db.local.key)
    const firstLink = connect(a, b)
    await a.db.append(encoded({ addWriter: b4a.toString(writerB, 'hex') }))
    await until(async () => { await b.db.updated(); return b.db.writable }, 'second writer membership')
    t.ok(a.db.writable && b.db.writable, 'both peers are admitted writers')

    await Promise.all([
      a.db.append(encoded({ key: 'from-a', value: 'alpha' })),
      b.db.append(encoded({ key: 'from-b', value: 'beta' }))
    ])
    await until(async () => await value(a, 'from-b') === 'beta' && await value(b, 'from-a') === 'alpha', 'concurrent writer convergence')
    t.is(await value(a, 'from-b'), 'beta')
    t.is(await value(b, 'from-a'), 'alpha')

    const c = await open('fresh-reader', key)
    const readerLink = connect(b, c)
    await until(async () => await value(c, 'from-a') === 'alpha' && await value(c, 'from-b') === 'beta', 'fresh reader replication')
    t.is(c.db.writable, false, 'replication alone does not admit a reader as writer')
    t.is(await value(c, 'from-a'), 'alpha')
    t.is(await value(c, 'from-b'), 'beta')

    for (const stream of [...firstLink, ...readerLink]) stream.destroy()
    for (const peer of [a, b, c]) await peer.db.close()
    for (const peer of [a, b, c]) { await peer.store.close(); peers.delete(peer) }

    const reopened = await open('writer-b', key)
    t.alike(reopened.db.local.key, writerB, 'cold reopen preserves the writer identity')
    t.is(await value(reopened, 'from-a'), 'alpha', 'cold reopen retains first writer data')
    t.is(await value(reopened, 'from-b'), 'beta', 'cold reopen retains second writer data')
    t.ok(reopened.db.writable, 'admission survives cold reopen')
    await reopened.db.append(encoded({ key: 'after-restart', value: 'gamma' }))

    const reopenedReader = await open('fresh-reader', key)
    connect(reopened, reopenedReader)
    await until(async () => await value(reopenedReader, 'after-restart') === 'gamma', 'post-restart replication')
    t.is(await value(reopenedReader, 'after-restart'), 'gamma')
    t.alike(errors, [], 'no storage or replication errors were hidden')
  } finally {
    await bounded(cleanup(), 'owned cleanup', 5000)
  }
})
