import test from 'brittle'
import b4a from 'b4a'
import { PubSub } from 'p2p-hiverelay/core/router/pubsub.js'
import { CircuitRelay } from 'p2p-hiverelay/core/protocol/relay-circuit.js'
import { TokenBucketRateLimiter } from 'p2p-hiverelay/core/protocol/rate-limiter.js'
import { SeedProtocol } from 'p2p-hiverelay/core/protocol/seed-request.js'
import { Seeder } from 'p2p-hiverelay/core/relay-node/seeder.js'

test('runtime cleanup timers do not keep short-lived processes alive', async (t) => {
  const pubsub = new PubSub()
  const circuit = new CircuitRelay(null, null)
  const limiter = new TokenBucketRateLimiter()
  const seed = new SeedProtocol(null)

  t.absent(pubsub._cleanupInterval.hasRef(), 'pubsub cleanup interval is unrefed')
  t.absent(circuit._cleanupInterval.hasRef(), 'circuit cleanup interval is unrefed')
  t.absent(limiter._cleanupInterval.hasRef(), 'rate limiter cleanup interval is unrefed')
  t.absent(seed._pendingCleanup.hasRef(), 'seed pending cleanup interval is unrefed')
  t.absent(seed._unseedNonceCleanup.hasRef(), 'seed nonce cleanup interval is unrefed')
  t.absent(seed.rateLimiter._cleanupInterval.hasRef(), 'seed rate limiter cleanup interval is unrefed')

  pubsub.destroy()
  circuit.destroy()
  limiter.destroy()
  seed.destroy()
})

test('seeder reannounce interval does not pin the process', async (t) => {
  const keyHex = 'a'.repeat(64)
  const store = {
    get () {
      return {
        discoveryKey: b4a.alloc(32, 0x11),
        length: 0,
        async ready () {},
        download () { return { done: async () => {}, destroy () {} } },
        on () {},
        async close () {}
      }
    }
  }
  const swarm = {
    join () {},
    async leave () {}
  }
  const seeder = new Seeder(store, swarm)
  await seeder.start()
  const entry = await seeder.seedCore(keyHex)

  t.absent(entry.interval.hasRef(), 'seeder reannounce interval is unrefed')

  await seeder.stop()
})
