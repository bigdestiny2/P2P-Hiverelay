// HiveWorm — client-side Worm representation.
//
// Holds rendering state separate from the authoritative game state. Each
// Worm tracks `targetSegments` (truth from the relay) and `renderSegments`
// (interpolated visuals). Calling tick(dt) eases renderSegments toward
// targetSegments — gives the smooth no-teleport feel even though the
// authoritative simulation is one cell per move.
//
// Visual identity is a saturated 90s-cartoon palette, with each worm getting
// a deterministic body color and a darker outline of the same hue. The
// renderer also reads the per-worm face state (blink phase, chomp timer,
// dying flag) from this class.
//
// Reference vibe: Worms 2 / Bubble Bobble / Pokémon overworld worms.

import { config } from './config.js'

// 6-color saturated cartoon palette. Each entry pairs a body fill with a
// matching darker outline (multiply-blend feel) and a lighter top-stripe
// highlight. Picked to feel like classic Saturday-morning animation, not
// pastel kids-book.
const WORM_PALETTE = [
  { body: '#ff5e9c', outline: '#7a1a44', hi: '#ffc6dd' }, // bubblegum pink
  { body: '#aedb45', outline: '#3a6d10', hi: '#e2f4a7' }, // lime
  { body: '#4fc3f7', outline: '#0d4e7a', hi: '#bde8ff' }, // electric blue
  { body: '#ffd54f', outline: '#7a5410', hi: '#fff0bd' }, // sunshine yellow
  { body: '#ff5e3a', outline: '#7a1810', hi: '#ffc7b8' }, // tomato
  { body: '#b266ff', outline: '#46197a', hi: '#dfc5ff' } // hot purple
]

export function paletteFromPubkey (hex) {
  if (!hex || hex.length < 4) return WORM_PALETTE[0]
  const a = parseInt(hex.slice(0, 2), 16)
  const b = parseInt(hex.slice(2, 4), 16)
  const idx = ((a ^ (b * 7)) >>> 0) % WORM_PALETTE.length
  return WORM_PALETTE[idx]
}

// Backwards-compat exports for callers that still want a single hex color.
export function colorFromPubkey (hex) { return paletteFromPubkey(hex).body }
export function glowFromPubkey (hex) { return paletteFromPubkey(hex).hi }

export function darken (hex, amt = 0.35) {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  const f = 1 - amt
  return '#' + [r, g, b].map(v => Math.max(0, Math.min(255, Math.round(v * f))).toString(16).padStart(2, '0')).join('')
}

function easeOutCubic (t) { return 1 - Math.pow(1 - t, 3) }
function easeOutBack (t, s = 1.7) {
  const x = t - 1
  return 1 + (s + 1) * x * x * x + s * x * x
}

export class Worm {
  constructor (pubkey) {
    this.pubkey = pubkey
    const pal = paletteFromPubkey(pubkey)
    this.color = pal.body
    this.outline = pal.outline
    this.highlight = pal.hi
    // Lighter version (for top-of-segment highlight stripe)
    this.glow = pal.hi

    // Authoritative truth from the relay:
    this.targetSegments = [] // [[x, y], ...]
    this.length = 3
    this.alive = true
    this.bornAt = 0

    // Visual state — pixels relative to the world grid. Eased toward
    // targetSegments * cellSize.
    this.renderSegments = []
    this._fromSegments = []
    this._easeStart = 0
    this._easeDuration = config.segmentInterpolationMs

    // ─── Face / animation state ─────────────────────────────
    // Blink: closes for ~120ms every 4-8s
    this.eyeBlinkOpen = true
    this._nextBlinkAt = 0
    this._blinkUntil = 0

    // Chomp: triggered on .chomp(), opens mouth wide for 100ms
    this.chompUntil = 0

    // Squash: head squash-stretch on eat, 100ms ease-out
    this.squashUntil = 0
    this.squashStrength = 0

    // Death: x_x eyes + slight rotation on the head
    this.dyingAt = 0 // performance.now() at the moment of death

    // Idle bob — tiny sinusoid, NOT bouncy
    this.bobOffset = Math.random() * Math.PI * 2

    // Movement direction — used for pupil shift and squash axis
    this.lastMoveDir = [1, 0]

    // Tail dust particles spawned when a segment leaves a cell
    this.dustParticles = []
  }

  /**
   * Update authoritative segments. Triggers a smooth ease from current
   * render position to the new target.
   */
  setSegments (segments, now) {
    if (!Array.isArray(segments) || segments.length === 0) return

    // Track movement direction (head delta)
    if (segments.length >= 2) {
      const dx = segments[0][0] - segments[1][0]
      const dy = segments[0][1] - segments[1][1]
      if (dx !== 0 || dy !== 0) this.lastMoveDir = [dx, dy]
    }

    // Snap on first call
    if (this.renderSegments.length === 0) {
      this.renderSegments = segments.map(([x, y]) => [x * config.cellSize, y * config.cellSize])
      this._fromSegments = this.renderSegments.map(p => [p[0], p[1]])
      this.targetSegments = segments.map(s => [s[0], s[1]])
      this._easeStart = now - this._easeDuration
      return
    }

    // Pad / trim render segments to match new target length
    while (this.renderSegments.length < segments.length) {
      const tail = this.renderSegments[this.renderSegments.length - 1] ||
                   [segments[0][0] * config.cellSize, segments[0][1] * config.cellSize]
      this.renderSegments.push([tail[0], tail[1]])
    }
    if (this.renderSegments.length > segments.length) {
      const dropped = this.renderSegments[this.renderSegments.length - 1]
      this._spawnDust(dropped[0], dropped[1], now)
      this.renderSegments.length = segments.length
    }
    this._fromSegments = this.renderSegments.map(p => [p[0], p[1]])
    this.targetSegments = segments.map(s => [s[0], s[1]])
    this._easeStart = now
  }

  setAlive (alive) {
    if (this.alive && !alive) this.dyingAt = performance.now()
    if (!this.alive && alive) this.dyingAt = 0
    this.alive = !!alive
  }

  /**
   * Trigger the eat-chomp animation. Renderer reads `chompUntil` to draw
   * an open mouth + scrunched eyes for 100ms, and the head squashes.
   */
  chomp (now = performance.now()) {
    this.chompUntil = now + 100
    this.squashUntil = now + 140
    this.squashStrength = 1
  }

  /**
   * Advance interpolation. dt is the time since the last tick.
   */
  tick (now, dt) {
    // Ease render segments toward target
    const t = Math.min(1, (now - this._easeStart) / this._easeDuration)
    const k = easeOutCubic(t)
    for (let i = 0; i < this.targetSegments.length; i++) {
      const target = this.targetSegments[i]
      const tx = target[0] * config.cellSize
      const ty = target[1] * config.cellSize
      const from = this._fromSegments[i] || [tx, ty]
      const px = from[0] + (tx - from[0]) * k
      const py = from[1] + (ty - from[1]) * k
      this.renderSegments[i] = [px, py]
    }

    // Blink
    if (now >= this._nextBlinkAt && this._nextBlinkAt > 0) {
      if (this.eyeBlinkOpen) {
        this.eyeBlinkOpen = false
        this._blinkUntil = now + 110
        this._nextBlinkAt = 0
      }
    } else if (this._nextBlinkAt === 0) {
      this._nextBlinkAt = now + 4000 + Math.random() * 4000
    }
    if (!this.eyeBlinkOpen && now >= this._blinkUntil) {
      this.eyeBlinkOpen = true
    }

    // Squash decay
    if (now < this.squashUntil) {
      const tt = 1 - (this.squashUntil - now) / 140
      this.squashStrength = 1 - easeOutBack(tt) * 0.7
      if (this.squashStrength < 0) this.squashStrength = 0
    } else {
      this.squashStrength = 0
    }

    // Trail particle decay
    for (let i = this.dustParticles.length - 1; i >= 0; i--) {
      const p = this.dustParticles[i]
      p.life -= dt
      p.x += p.vx * (dt / 16)
      p.y += p.vy * (dt / 16)
      p.vy += 0.01 * (dt / 16) // tiny gravity to fall
      p.vx *= 0.94
      if (p.life <= 0) this.dustParticles.splice(i, 1)
    }
  }

  _spawnDust (px, py, now) {
    if (!this.alive) return
    for (let i = 0; i < 3; i++) {
      this.dustParticles.push({
        x: px + (Math.random() - 0.5) * 6,
        y: py + (Math.random() - 0.5) * 4 + 4,
        vx: (Math.random() - 0.5) * 0.5,
        vy: -Math.random() * 0.4,
        life: 200 + Math.random() * 80,
        maxLife: 280
      })
    }
  }

  /**
   * Tiny per-segment idle bob — just enough to feel alive, not bouncy.
   * Returns [dx, dy] in pixels.
   */
  bob (i, now) {
    if (!this.alive) return [0, 0]
    const phase = (now / 1000) * Math.PI * 2 * 0.55 + this.bobOffset - i * 0.45
    return [Math.sin(phase) * 0.8, Math.cos(phase * 1.1) * 0.5]
  }

  /**
   * Returns true if the head should be drawn with chomp face right now.
   */
  isChomping (now = performance.now()) { return now < this.chompUntil }
}
