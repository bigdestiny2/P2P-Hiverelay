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
  let destroyed = false

  return {
    join (topicHex, opts = {}) {
      if (destroyed) return null
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
      if (destroyed) return { ok: false }
      const channel = channels.get(channelId)
      if (channel) remember(channel.topic, data)
      deliver(peerId, { type: 'message', peerId: channelId, data })
      return { ok: true }
    },

    leave,

    // Explicit teardown: null every live event sink so no descriptor delivery
    // can fire after close, drop all channel + descriptor state, and make the
    // hub inert. Idempotent. (Mafintosh: a primitive that opens must close.)
    destroy,
    close: destroy,

    subscribe (channelId, onEvent) {
      if (destroyed) return () => {}
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

    // Drop remembered descriptors the keep(topic, data) predicate rejects.
    // Used by the outboxlog ghost sweep: descriptors for swept appIds would
    // otherwise be replayed to EVERY future subscriber forever (the per-boot
    // request amplifier the churn era left behind) and hold maxDescriptorsPerTopic
    // slots. A throwing predicate keeps the descriptor (conservative). Fires
    // onChange once when anything was pruned so persistence snapshots update.
    pruneDescriptors (keep) {
      if (destroyed || typeof keep !== 'function') return 0
      let pruned = 0
      for (const [topic, map] of descriptors) {
        for (const data of [...map.keys()]) {
          let keepIt = true
          try { keepIt = keep(topic, data) !== false } catch { keepIt = true }
          if (!keepIt) { map.delete(data); pruned++ }
        }
        if (map.size === 0) descriptors.delete(topic)
      }
      if (pruned > 0 && onChange) {
        try { onChange() } catch {}
      }
      return pruned
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

  function destroy () {
    if (destroyed) return
    destroyed = true
    for (const channel of channels.values()) channel.onEvent = null
    channels.clear()
    descriptors.clear()
  }

  function deliver (channelId, event) {
    if (destroyed) return
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
