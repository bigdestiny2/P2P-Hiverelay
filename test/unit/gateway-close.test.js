/**
 * HyperGateway.close() teardown unit test.
 *
 * Pins the bug where close() iterated the DriveCache directly
 * (`for (const [, drive] of this._drives)`). DriveCache exposes entries()
 * but no Symbol.iterator, so close() threw "this._drives is not iterable"
 * on every call — which aborted RelayAPI.stop() before server.close(),
 * leaking the HTTP listener and causing EADDRINUSE on self-heal restart.
 *
 * These tests need no P2P stack: they inject fake drives straight into the
 * cache and assert close() drains them without throwing.
 */

import test from 'brittle'
import { HyperGateway } from 'p2p-hiverelay/gateway'

function fakeDrive () {
  return {
    closed: false,
    closeCalls: 0,
    async close () { this.closeCalls++; this.closed = true }
  }
}

test('close() iterates the DriveCache and closes every cached drive', async (t) => {
  const gateway = new HyperGateway({}, {})
  const a = fakeDrive()
  const b = fakeDrive()
  gateway._drives.set('aa', a)
  gateway._drives.set('bb', b)

  await t.execution(gateway.close(), 'close() does not throw')

  t.is(a.closeCalls, 1, 'first cached drive closed')
  t.is(b.closeCalls, 1, 'second cached drive closed')
  t.is(gateway._drives.size, 0, 'cache cleared after close()')
})

test('close() is a no-op-safe call on an empty gateway', async (t) => {
  const gateway = new HyperGateway({}, {})
  await t.execution(gateway.close(), 'empty close() does not throw')
  t.is(gateway._drives.size, 0, 'still empty')
})

test('close() skips already-closed drives and survives a drive that throws', async (t) => {
  const gateway = new HyperGateway({}, {})
  const already = fakeDrive()
  already.closed = true
  const throws = { closed: false, async close () { throw new Error('boom') } }
  const ok = fakeDrive()
  gateway._drives.set('already', already)
  gateway._drives.set('throws', throws)
  gateway._drives.set('ok', ok)

  let errored = false
  gateway.on('drive-close-error', () => { errored = true })

  await t.execution(gateway.close(), 'close() swallows a drive-close error')

  t.is(already.closeCalls, 0, 'already-closed drive not re-closed')
  t.ok(errored, 'drive-close-error emitted for the throwing drive')
  t.is(ok.closeCalls, 1, 'a throwing drive does not stop the others closing')
  t.is(gateway._drives.size, 0, 'cache cleared')
})
