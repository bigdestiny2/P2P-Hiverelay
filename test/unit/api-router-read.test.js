import test from 'brittle'
import {
  MAX_ROUTER_TOPICS,
  MAX_ROUTER_TOPIC_BYTES,
  buildRouterInfoPayload
} from 'p2p-hiverelay/core/relay-node/api-router-read.js'

test('api router read: missing router returns stable disabled payload', (t) => {
  t.alike(buildRouterInfoPayload(), {
    status: 503,
    payload: { error: 'Router not enabled' }
  })
})

test('api router read: uses router stats for route count without materializing routes', (t) => {
  let routesCalled = false
  const result = buildRouterInfoPayload({
    router: {
      getStats () {
        return { routes: 3 }
      },
      routes () {
        routesCalled = true
        return ['should.not.read']
      },
      pubsub: null
    }
  })

  t.is(result.status, 200)
  t.is(result.payload.routes, 3)
  t.is(result.payload.pubsub, null)
  t.alike(result.headers, { 'Cache-Control': 'public, max-age=10' })
  t.absent(routesCalled)
})

test('api router read: bounds and sanitizes public pubsub topics', (t) => {
  const validTopics = Array.from({ length: MAX_ROUTER_TOPICS + 12 }, (_, i) => 'topic/' + i)
  const result = buildRouterInfoPayload({
    router: {
      getStats () {
        return { routes: 9 }
      },
      pubsub: {
        topics () {
          return [
            ' services/ai ',
            'bad\nname',
            'x'.repeat(MAX_ROUTER_TOPIC_BYTES + 1),
            ...validTopics
          ]
        },
        topicCount () {
          return 999
        },
        subscriberCount () {
          return 7.9
        }
      }
    }
  })

  t.is(result.status, 200)
  t.is(result.payload.routes, 9)
  t.is(result.payload.pubsub.topics.length, MAX_ROUTER_TOPICS)
  t.is(result.payload.pubsub.topics[0], 'services/ai')
  t.absent(result.payload.pubsub.topics.includes('bad\nname'))
  t.absent(result.payload.pubsub.topics.includes('x'.repeat(MAX_ROUTER_TOPIC_BYTES + 1)))
  t.is(result.payload.pubsub.topicCount, 999)
  t.is(result.payload.pubsub.subscriberCount, 7)
  t.is(result.payload.pubsub.truncated, true)
})

test('api router read: tolerates throwing router and pubsub helpers', (t) => {
  const result = buildRouterInfoPayload({
    router: {
      getStats () { throw new Error('stats failed') },
      routes () { throw new Error('routes failed') },
      pubsub: {
        topics () { throw new Error('topics failed') },
        topicCount () { throw new Error('count failed') },
        subscriberCount () { throw new Error('subs failed') }
      }
    }
  })

  t.is(result.status, 200)
  t.alike(result.payload, {
    routes: 0,
    pubsub: {
      topics: [],
      topicCount: 0,
      subscriberCount: 0,
      truncated: false
    }
  })
})
