/**
 * In-process swarm.v1 compatibility hub for OutboxLog browser clients.
 *
 * This is the small Peerit relay swarm stand-in: channels on the same topic see
 * each other as peers, `send()` routes descriptor messages to a peer's live
 * event stream, and signed descriptors are remembered for later joiners.
 */

export function createOutboxSwarmHub ({ maxDescriptorsPerTopic = 20000, onChange = null } = {}) {
  const channels = new Map()
  const descriptors = new Map()
  let seq = 0
  let synth = 0

  return {
    join (topicHex, opts = {}) {
      const channelId = 'ch-' + (++seq)
      channels.set(channelId, {
        topic: topicHex || 'default',
        onEvent: null,
        linked: new Set()
      })
      return {
        channelId,
        topicHex: topicHex || 'default',
        protocol: opts.protocol || 'pear.swarm.v1',
        version: opts.version == null ? 1 : opts.version,
        tier: 'A'
      }
    },

    send (channelId, peerId, data) {
      const channel = channels.get(channelId)
      if (channel) remember(channel.topic, data)
      deliver(peerId, { type: 'message', peerId: channelId, data })
      return { ok: true }
    },

    leave,

    subscribe (channelId, onEvent) {
      const channel = channels.get(channelId)
      if (!channel) return () => {}
      channel.onEvent = onEvent
      setTimeout(() => {
        linkPeers(channelId)
        replay(channelId)
      }, 0)
      return () => leave(channelId)
    },

    _channelCount () {
      return channels.size
    },

    _snapshotDescriptors () {
      const out = {}
      for (const [topic, map] of descriptors) out[topic] = [...map.keys()]
      return out
    },

    _loadDescriptors (obj) {
      if (!obj || typeof obj !== 'object') return
      for (const topic of Object.keys(obj)) {
        const arr = obj[topic]
        if (!Array.isArray(arr)) continue
        const map = new Map()
        for (const descriptor of arr) {
          if (typeof descriptor === 'string' && descriptor.length <= 16384 && map.size < maxDescriptorsPerTopic) {
            map.set(descriptor, descriptor)
          }
        }
        descriptors.set(topic, map)
      }
    }
  }

  function deliver (channelId, event) {
    const channel = channels.get(channelId)
    if (!channel || !channel.onEvent) return
    try {
      channel.onEvent(event)
    } catch {}
  }

  function remember (topic, data) {
    if (typeof data !== 'string' || !data || data.length > 16384) return
    let map = descriptors.get(topic)
    if (!map) {
      map = new Map()
      descriptors.set(topic, map)
    }
    if (map.has(data) || map.size >= maxDescriptorsPerTopic) return
    map.set(data, data)
    if (onChange) {
      try {
        onChange()
      } catch {}
    }
  }

  function replay (channelId) {
    const channel = channels.get(channelId)
    if (!channel || !channel.onEvent) return
    const map = descriptors.get(channel.topic)
    if (!map) return
    for (const data of map.keys()) {
      const peerId = 'cache-' + (++synth)
      deliver(channelId, { type: 'peer', peerId, pubkey: null })
      deliver(channelId, { type: 'message', peerId, data })
    }
  }

  function linkPeers (channelId) {
    const channel = channels.get(channelId)
    if (!channel || !channel.onEvent) return
    for (const [otherId, other] of channels) {
      if (otherId === channelId || other.topic !== channel.topic || !other.onEvent) continue
      if (channel.linked.has(otherId)) continue
      channel.linked.add(otherId)
      other.linked.add(channelId)
      deliver(channelId, { type: 'peer', peerId: otherId, pubkey: null })
      deliver(otherId, { type: 'peer', peerId: channelId, pubkey: null })
    }
  }

  function leave (channelId) {
    const channel = channels.get(channelId)
    if (channel) {
      for (const otherId of channel.linked) {
        const other = channels.get(otherId)
        if (other) {
          other.linked.delete(channelId)
          deliver(otherId, { type: 'peer-leave', peerId: channelId })
        }
      }
    }
    channels.delete(channelId)
    return { ok: true }
  }
}
