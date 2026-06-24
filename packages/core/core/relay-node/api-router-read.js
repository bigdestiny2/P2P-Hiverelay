import b4a from 'b4a'

export const MAX_ROUTER_TOPICS = 256
export const MAX_ROUTER_TOPIC_BYTES = 256

function safeCounter (value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.floor(n)
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function sanitizeTopic (value) {
  if (typeof value !== 'string') return null
  const topic = value.trim()
  if (!topic || hasControlChar(topic)) return null
  if (b4a.byteLength(topic) > MAX_ROUTER_TOPIC_BYTES) return null
  return topic
}

function safeRouteCount (router) {
  if (!router) return 0
  if (typeof router.getStats === 'function') {
    try {
      const stats = router.getStats()
      if (stats && stats.routes !== undefined) return safeCounter(stats.routes)
    } catch {}
  }
  if (typeof router.routes === 'function') {
    try {
      const routes = router.routes()
      return Array.isArray(routes) ? routes.length : safeCounter(routes && routes.length)
    } catch {}
  }
  return 0
}

function safeTopicCount (pubsub, rawTopics) {
  if (!pubsub) return 0
  if (typeof pubsub.topicCount === 'function') {
    try {
      return safeCounter(pubsub.topicCount())
    } catch {}
  }
  return Array.isArray(rawTopics) ? rawTopics.length : 0
}

function safeSubscriberCount (pubsub) {
  if (!pubsub || typeof pubsub.subscriberCount !== 'function') return 0
  try {
    return safeCounter(pubsub.subscriberCount())
  } catch {
    return 0
  }
}

export function buildRouterInfoPayload ({ router = null } = {}) {
  if (!router) {
    return {
      status: 503,
      payload: { error: 'Router not enabled' }
    }
  }

  const pubsub = router.pubsub || null
  let rawTopics = []
  if (pubsub && typeof pubsub.topics === 'function') {
    try {
      rawTopics = pubsub.topics()
    } catch {
      rawTopics = []
    }
  }
  rawTopics = Array.isArray(rawTopics) ? rawTopics : []

  const topics = []
  for (const raw of rawTopics) {
    if (topics.length >= MAX_ROUTER_TOPICS) break
    const topic = sanitizeTopic(raw)
    if (topic) topics.push(topic)
  }

  const topicCount = safeTopicCount(pubsub, rawTopics)

  return {
    status: 200,
    payload: {
      routes: safeRouteCount(router),
      pubsub: pubsub
        ? {
            topics,
            topicCount,
            subscriberCount: safeSubscriberCount(pubsub),
            truncated: topicCount > topics.length || rawTopics.length > topics.length
          }
        : null
    },
    headers: { 'Cache-Control': 'public, max-age=10' }
  }
}
