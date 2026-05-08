// HiveWorm — Canvas2D renderer.
//
// Stylistically: Worms 2 / Pokémon overworld / Saturday morning cartoon.
// Saturated greens, chunky outlines, worms with faces, food with smiles,
// clouds drifting overhead, distant hills. Goofy is the personality, slick
// is the quality — every animation has a real easing curve.
//
// Coordinate spaces:
//   Grid    — integer cell coords from the relay (0..config.width)
//   Pixel   — cellSize * grid (what worm.renderSegments stores)
//   Screen  — pixel - camera offset, scaled to canvas
//
// The camera lazily chases my worm with cameraInertiaMs of inertia.

import { config } from './config.js'

const COL = {
  // sky / scenery
  skyTop: '#7ec8e3',
  skyMid: '#a8e6cf',
  grass: '#7cba5f',
  grassDeep: '#4a8a3c',
  grassLine: '#6aa64f',
  hillFar: '#5fa64e',
  hillNear: '#6fb358',
  dirt: '#8b5a2b',
  flowerR: '#e74c3c',
  flowerY: '#f1c40f',
  cloud: '#ffffff',
  ink: '#1f1d2b',
  bone: '#fff8e7',
  shadow: 'rgba(31, 29, 43, 0.25)'
}

// Food sprite types — drawn procedurally on each frame so we keep zero
// asset payload but still get the pixel-art feel. Each draws into a square
// of size 2*r centered at (cx,cy). Each function also paints a tiny smile.
const FOOD_TYPES = [
  drawApple,
  drawDonut,
  drawIceCream,
  drawPizza,
  drawGummy,
  drawCherry
]

export class Renderer {
  constructor (canvas, world) {
    this.canvas = canvas
    this.ctx = canvas.getContext('2d')
    this.world = world
    this.dpr = window.devicePixelRatio || 1
    this.width = 0
    this.height = 0

    this.camera = { x: 0, y: 0 }
    this.cameraTarget = { x: 0, y: 0 }

    this.shake = { until: 0, magnitude: 0 }
    this.slowMo = { until: 0, factor: 1 }
    this.particles = []
    this.popups = [] // floating "+1" texts
    this.confetti = [] // rare-eat confetti bits
    this.cloudPhase = 0

    // Pre-baked decoration for the world: stable per-cell decisions for
    // tufts, flowers, pebbles. Generated lazily once we know world size.
    this._decor = null

    this.myPubkey = null
    this.lastFrameTime = performance.now()
  }

  resize () {
    const rect = this.canvas.getBoundingClientRect()
    this.width = rect.width
    this.height = rect.height
    this.canvas.width = Math.floor(rect.width * this.dpr)
    this.canvas.height = Math.floor(rect.height * this.dpr)
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0)
  }

  setMyPubkey (pubkey) { this.myPubkey = pubkey }

  // ─── Scenery decoration generation ──────────────────────

  _ensureDecor () {
    if (this._decor && this._decor.w === this.world.config.width) return
    const w = this.world.config.width
    const h = this.world.config.height
    const flowers = []
    const tufts = []
    const pebbles = []
    // Deterministic-ish mulberry32 PRNG so the meadow looks the same on each load
    let seed = 0xc0ffee
    const rnd = () => {
      seed |= 0; seed = (seed + 0x6d2b79f5) | 0
      let t = Math.imul(seed ^ seed >>> 15, 1 | seed)
      t = (t + Math.imul(t ^ t >>> 7, 61 | t)) ^ t
      return ((t ^ t >>> 14) >>> 0) / 4294967296
    }
    const cs = config.cellSize
    // Tufts — darker grass clumps, fairly dense
    for (let i = 0; i < w * h * 0.05; i++) {
      tufts.push({
        x: rnd() * w * cs,
        y: rnd() * h * cs,
        r: 4 + rnd() * 5,
        sway: rnd() * Math.PI * 2
      })
    }
    // Flowers — spaced out
    for (let i = 0; i < w * h * 0.005; i++) {
      flowers.push({
        x: rnd() * w * cs,
        y: rnd() * h * cs,
        red: rnd() < 0.5
      })
    }
    // Pebbles
    for (let i = 0; i < w * h * 0.003; i++) {
      pebbles.push({ x: rnd() * w * cs, y: rnd() * h * cs })
    }
    this._decor = { w, h, flowers, tufts, pebbles }
  }

  // ─── Effects ────────────────────────────────────────────

  triggerDeath ({ atPos, worm }) {
    this.shake = { until: performance.now() + 320, magnitude: 9 }
    this.slowMo = { until: performance.now() + 350, factor: 0.4 }
    if (atPos && worm) {
      const px = atPos[0] * config.cellSize + config.cellSize / 2
      const py = atPos[1] * config.cellSize + config.cellSize / 2
      const segCount = worm.length || 8
      // Body explodes into food-shaped scatter
      for (let i = 0; i < Math.max(8, segCount * 2); i++) {
        const ang = (i / Math.max(8, segCount * 2)) * Math.PI * 2 + Math.random() * 0.4
        const speed = 2.0 + Math.random() * 2.6
        this.particles.push({
          kind: 'food-bit',
          foodType: Math.floor(Math.random() * FOOD_TYPES.length),
          x: px,
          y: py,
          vx: Math.cos(ang) * speed,
          vy: Math.sin(ang) * speed - 1.5,
          life: 900 + Math.random() * 500,
          maxLife: 1400,
          size: 5 + Math.random() * 3,
          spin: (Math.random() - 0.5) * 0.4,
          rot: Math.random() * Math.PI * 2
        })
      }
    }
  }

  triggerEat (atPos, opts = {}) {
    if (!atPos) return
    const px = atPos[0] * config.cellSize + config.cellSize / 2
    const py = atPos[1] * config.cellSize + config.cellSize / 2
    // Trigger chomp on the worm whose head just landed there (caller sets
    // worm directly via game.js; here we just paint particles + popup)
    for (let i = 0; i < 7; i++) {
      const ang = (i / 7) * Math.PI * 2
      this.particles.push({
        kind: 'spark',
        x: px,
        y: py,
        vx: Math.cos(ang) * 1.2,
        vy: Math.sin(ang) * 1.2 - 0.6,
        life: 280,
        maxLife: 280,
        color: COL.bone,
        size: 2.2
      })
    }
    // Floating "+1" popup
    this.popups.push({
      text: opts.rare ? '+5!' : '+1',
      x: px,
      y: py - 8,
      life: 600,
      maxLife: 600,
      rare: !!opts.rare
    })
    if (opts.rare) {
      this.slowMo = { until: performance.now() + 200, factor: 0.6 }
      // confetti
      for (let i = 0; i < 22; i++) {
        const ang = -Math.PI / 2 + (Math.random() - 0.5) * Math.PI
        const speed = 2 + Math.random() * 3
        this.confetti.push({
          x: px,
          y: py,
          vx: Math.cos(ang) * speed,
          vy: Math.sin(ang) * speed,
          life: 1200,
          maxLife: 1200,
          color: [COL.flowerR, COL.flowerY, '#4fc3f7', '#ff5e9c', '#aedb45', '#b266ff'][i % 6],
          rot: Math.random() * Math.PI * 2,
          spin: (Math.random() - 0.5) * 0.3,
          size: 4 + Math.random() * 3
        })
      }
    }
  }

  triggerSpawn (atPos) {
    if (!atPos) return
    const px = atPos[0] * config.cellSize + config.cellSize / 2
    const py = atPos[1] * config.cellSize + config.cellSize / 2
    for (let i = 0; i < 14; i++) {
      const ang = (i / 14) * Math.PI * 2
      this.particles.push({
        kind: 'spark',
        x: px,
        y: py,
        vx: Math.cos(ang) * 1.5,
        vy: Math.sin(ang) * 1.5 - 0.8,
        life: 500,
        maxLife: 500,
        color: COL.bone,
        size: 3
      })
    }
  }

  // ─── Frame ────────────────────────────────────────────────

  draw (now) {
    const dt = Math.max(1, now - this.lastFrameTime)
    this.lastFrameTime = now

    const slow = now < this.slowMo.until ? this.slowMo.factor : 1
    this.world.tickAnim(now, dt * slow)
    this.updateCamera(now, dt)
    this._ensureDecor()

    // Tick popups + particles + confetti
    for (let i = this.popups.length - 1; i >= 0; i--) {
      this.popups[i].life -= dt * slow
      if (this.popups[i].life <= 0) this.popups.splice(i, 1)
    }
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i]
      p.life -= dt * slow
      p.x += p.vx * (dt * slow / 16)
      p.y += p.vy * (dt * slow / 16)
      if (p.kind === 'food-bit') {
        p.vy += 0.18 * (dt * slow / 16)
        p.rot += p.spin * (dt * slow / 16)
      } else {
        p.vy += 0.05 * (dt * slow / 16)
      }
      p.vx *= 0.97
      if (p.life <= 0) this.particles.splice(i, 1)
    }
    for (let i = this.confetti.length - 1; i >= 0; i--) {
      const c = this.confetti[i]
      c.life -= dt * slow
      c.x += c.vx * (dt * slow / 16)
      c.y += c.vy * (dt * slow / 16)
      c.vy += 0.15 * (dt * slow / 16)
      c.rot += c.spin * (dt * slow / 16)
      if (c.life <= 0) this.confetti.splice(i, 1)
    }

    this.cloudPhase += dt * 0.005

    const ctx = this.ctx
    ctx.save()

    // Sky gradient — drawn in screen space, behind world
    this._drawSky()

    // Camera shake
    let shx = 0; let shy = 0
    if (now < this.shake.until) {
      const k = (this.shake.until - now) / 320
      shx = (Math.random() - 0.5) * this.shake.magnitude * k
      shy = (Math.random() - 0.5) * this.shake.magnitude * k
    }
    ctx.translate(-this.camera.x + shx, -this.camera.y + shy)

    this._drawHills()
    this._drawClouds()
    this._drawMeadow()
    this._drawDecor()
    this._drawFood(now)
    this._drawWorms(now)
    this._drawParticles()
    this._drawConfetti()
    this._drawPopups()

    ctx.restore()
  }

  updateCamera (now, dt) {
    let cx = this.cameraTarget.x
    let cy = this.cameraTarget.y
    if (this.myPubkey) {
      const w = this.world.worms.get(this.myPubkey)
      if (w && w.renderSegments.length > 0) {
        const head = w.renderSegments[0]
        cx = head[0] - this.width / 2
        cy = head[1] - this.height / 2
      }
    }
    const wmax = this.world.config.width * config.cellSize
    const hmax = this.world.config.height * config.cellSize
    cx = Math.max(-config.viewportPadding, Math.min(wmax - this.width + config.viewportPadding, cx))
    cy = Math.max(-config.viewportPadding, Math.min(hmax - this.height + config.viewportPadding, cy))
    this.cameraTarget.x = cx
    this.cameraTarget.y = cy
    const k = Math.min(1, dt / config.cameraInertiaMs)
    this.camera.x += (this.cameraTarget.x - this.camera.x) * k
    this.camera.y += (this.cameraTarget.y - this.camera.y) * k
  }

  // ─── Sky / clouds / hills / meadow / decor ──────────────

  _drawSky () {
    const ctx = this.ctx
    // Gradient from sky-top through mint to grass at the bottom
    const grad = ctx.createLinearGradient(0, 0, 0, this.height)
    grad.addColorStop(0, COL.skyTop)
    grad.addColorStop(0.55, COL.skyMid)
    grad.addColorStop(1, COL.grass)
    ctx.fillStyle = grad
    ctx.fillRect(0, 0, this.width, this.height)
  }

  _drawClouds () {
    const ctx = this.ctx
    // Clouds live in *screen* space (parallaxed): we draw them in world coords
    // by undoing camera, but it's cleaner to just lock them to camera with
    // a subtle parallax. We're already in world-translate; offset by camera*0.6
    // to fake parallax against the meadow.
    const px = this.camera.x * 0.6
    const py = this.camera.y * 0.4
    const wmax = this.world.config.width * config.cellSize
    // Three cloud layers, scrolled by cloudPhase
    const clouds = [
      { x: 80, y: 60, s: 1.0, drift: 18 },
      { x: 380, y: 130, s: 0.8, drift: 12 },
      { x: 720, y: 50, s: 1.2, drift: 22 }
    ]
    ctx.save()
    for (const c of clouds) {
      const tx = px + ((c.x + this.cloudPhase * c.drift) % (wmax + 600)) - 200
      const ty = py + c.y
      this._drawCloud(tx, ty, c.s)
    }
    ctx.restore()
  }

  _drawCloud (x, y, s) {
    const ctx = this.ctx
    ctx.fillStyle = COL.cloud
    ctx.strokeStyle = COL.ink
    ctx.lineWidth = 3
    ctx.beginPath()
    ctx.ellipse(x, y, 42 * s, 22 * s, 0, 0, Math.PI * 2)
    ctx.ellipse(x + 36 * s, y - 8 * s, 30 * s, 20 * s, 0, 0, Math.PI * 2)
    ctx.ellipse(x + 70 * s, y + 4 * s, 26 * s, 18 * s, 0, 0, Math.PI * 2)
    ctx.ellipse(x - 28 * s, y + 6 * s, 24 * s, 16 * s, 0, 0, Math.PI * 2)
    ctx.fill()
    ctx.stroke()
  }

  _drawHills () {
    const ctx = this.ctx
    const wmax = this.world.config.width * config.cellSize
    const hmax = this.world.config.height * config.cellSize
    // Distant rolling hills painted across the top of the world
    // (only visible when the player is high in the world)
    ctx.save()
    ctx.fillStyle = COL.hillFar
    ctx.strokeStyle = COL.ink
    ctx.lineWidth = 2.5
    ctx.beginPath()
    const baseY = -10
    ctx.moveTo(-200, baseY + 80)
    const phase = 0
    for (let x = -200; x <= wmax + 200; x += 60) {
      const yy = baseY + 60 + Math.sin((x / 200) + phase) * 28
      ctx.lineTo(x, yy)
    }
    ctx.lineTo(wmax + 200, baseY - 200)
    ctx.lineTo(-200, baseY - 200)
    ctx.closePath()
    ctx.fill()
    ctx.stroke()
    ctx.restore()
    void hmax
  }

  _drawMeadow () {
    const ctx = this.ctx
    const wmax = this.world.config.width * config.cellSize
    const hmax = this.world.config.height * config.cellSize

    const vx0 = this.camera.x - 100
    const vy0 = this.camera.y - 100
    const vx1 = this.camera.x + this.width + 100
    const vy1 = this.camera.y + this.height + 100

    // Off-world (outside grid) — slightly darker grass with a softer fade
    ctx.fillStyle = COL.grassDeep
    ctx.fillRect(vx0, vy0, vx1 - vx0, vy1 - vy0)

    // World grass
    ctx.fillStyle = COL.grass
    const x0 = Math.max(0, vx0)
    const y0 = Math.max(0, vy0)
    const x1 = Math.min(wmax, vx1)
    const y1 = Math.min(hmax, vy1)
    if (x1 > x0 && y1 > y0) ctx.fillRect(x0, y0, x1 - x0, y1 - y0)

    // World border — a chunky black-outlined frame, cartoon-style
    ctx.strokeStyle = COL.ink
    ctx.lineWidth = 4
    ctx.strokeRect(0, 0, wmax, hmax)
  }

  _drawDecor () {
    const ctx = this.ctx
    if (!this._decor) return
    const vx0 = this.camera.x - 60
    const vy0 = this.camera.y - 60
    const vx1 = this.camera.x + this.width + 60
    const vy1 = this.camera.y + this.height + 60

    // Tufts
    ctx.fillStyle = COL.grassDeep
    for (const t of this._decor.tufts) {
      if (t.x < vx0 || t.x > vx1 || t.y < vy0 || t.y > vy1) continue
      // Tufts are small triangle clumps — three little blade lines
      const x = t.x; const y = t.y
      ctx.beginPath()
      ctx.moveTo(x - 4, y + 4)
      ctx.lineTo(x - 2, y - 5)
      ctx.lineTo(x, y + 4)
      ctx.lineTo(x + 2, y - 6)
      ctx.lineTo(x + 4, y + 4)
      ctx.closePath()
      ctx.fill()
    }
    // Pebbles
    for (const p of this._decor.pebbles) {
      if (p.x < vx0 || p.x > vx1 || p.y < vy0 || p.y > vy1) continue
      ctx.fillStyle = '#a89886'
      ctx.strokeStyle = COL.ink
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.ellipse(p.x, p.y, 4, 3, 0, 0, Math.PI * 2)
      ctx.fill()
      ctx.stroke()
    }
    // Flowers — tiny stem + 4-petal bloom
    for (const f of this._decor.flowers) {
      if (f.x < vx0 || f.x > vx1 || f.y < vy0 || f.y > vy1) continue
      ctx.strokeStyle = COL.grassDeep
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.moveTo(f.x, f.y + 6)
      ctx.lineTo(f.x, f.y - 2)
      ctx.stroke()
      const c = f.red ? COL.flowerR : COL.flowerY
      ctx.fillStyle = c
      ctx.strokeStyle = COL.ink
      ctx.lineWidth = 1.2
      // 4 petals
      for (let k = 0; k < 4; k++) {
        const a = (k / 4) * Math.PI * 2
        ctx.beginPath()
        ctx.ellipse(f.x + Math.cos(a) * 3, f.y - 4 + Math.sin(a) * 3, 2.6, 2.6, 0, 0, Math.PI * 2)
        ctx.fill()
        ctx.stroke()
      }
      // center
      ctx.fillStyle = '#fff8e7'
      ctx.beginPath()
      ctx.arc(f.x, f.y - 4, 1.6, 0, Math.PI * 2)
      ctx.fill()
    }
  }

  // ─── Food ───────────────────────────────────────────────

  _drawFood (now) {
    const ctx = this.ctx
    for (const f of this.world.food.values()) {
      const cx = f.x * config.cellSize + config.cellSize / 2
      const cy = f.y * config.cellSize + config.cellSize / 2
      // Pulse: 0.95 → 1.05
      const pulse = 1 + Math.sin(f.pulse) * 0.05
      // Spawn-pop: in the first 280ms, pop in with overshoot
      const ageMs = now - f.born
      let popK = 1
      if (ageMs < 320) {
        const t = Math.min(1, ageMs / 320)
        popK = Math.max(0, easeOutBack(t, 2.0))
      }
      const r = Math.max(0.1, 7 * pulse * popK)
      // shadow
      ctx.fillStyle = COL.shadow
      ctx.beginPath()
      ctx.ellipse(cx + 1, cy + 6, r * 0.9, r * 0.4, 0, 0, Math.PI * 2)
      ctx.fill()
      // pick a deterministic food type from cell coords
      const typeIdx = ((f.x * 7 + f.y * 11) >>> 0) % FOOD_TYPES.length
      const drawer = f.rare ? drawGoldenApple : FOOD_TYPES[typeIdx]
      drawer(ctx, cx, cy, r, now, f.pulse)
    }
  }

  // ─── Worms ──────────────────────────────────────────────

  _drawWorms (now) {
    // Sort: dead worms first (drawn under living), then alphabetical
    const list = [...this.world.worms.values()]
    list.sort((a, b) => (a.alive ? 1 : 0) - (b.alive ? 1 : 0))
    for (const worm of list) this._drawWorm(worm, now)
  }

  _drawWorm (worm, now) {
    const ctx = this.ctx
    if (!worm.renderSegments.length) return

    const baseColor = worm.alive ? worm.color : '#9e9989'
    const outline = worm.alive ? worm.outline : '#3a3530'
    const highlight = worm.alive ? worm.highlight : '#cccabb'

    // Drop shadow under each segment
    ctx.fillStyle = COL.shadow
    for (let i = 0; i < worm.renderSegments.length; i++) {
      const [px, py] = worm.renderSegments[i]
      const [bx, by] = worm.bob(i, now)
      const cx = px + config.cellSize / 2 + bx
      const cy = py + config.cellSize / 2 + by + 5
      const sz = this._segmentSize(i, worm.renderSegments.length)
      ctx.beginPath()
      ctx.ellipse(cx, cy, sz * 0.85, sz * 0.4, 0, 0, Math.PI * 2)
      ctx.fill()
    }

    // Tail dust
    for (const p of worm.dustParticles) {
      const a = Math.max(0, p.life / p.maxLife)
      ctx.fillStyle = `rgba(140, 96, 46, ${a * 0.55})`
      ctx.beginPath()
      ctx.arc(p.x + config.cellSize / 2, p.y + config.cellSize / 2, 2.2 * a + 1, 0, Math.PI * 2)
      ctx.fill()
    }

    // Body — back-to-front so head sits on top.
    // Each segment is a chunky rounded square with a darker outline + lighter
    // highlight stripe on top.
    for (let i = worm.renderSegments.length - 1; i >= 0; i--) {
      const [px, py] = worm.renderSegments[i]
      const [bx, by] = worm.bob(i, now)
      const cx = px + config.cellSize / 2 + bx
      const cy = py + config.cellSize / 2 + by
      const sz = this._segmentSize(i, worm.renderSegments.length)

      // Squash on the head: stretch along movement direction
      let sx = 1; let sy = 1
      if (i === 0 && worm.alive && worm.squashStrength > 0) {
        const k = worm.squashStrength
        // Squash y, stretch x... on the worm's facing axis
        const horiz = Math.abs(worm.lastMoveDir[0]) > Math.abs(worm.lastMoveDir[1])
        if (horiz) { sx = 1 + 0.18 * k; sy = 1 - 0.22 * k } else { sx = 1 - 0.22 * k; sy = 1 + 0.18 * k }
      }

      // Death wobble on the head: rotate slightly + flip
      let rot = 0
      if (!worm.alive && i === 0) {
        const since = now - (worm.dyingAt || now)
        rot = Math.min(Math.PI, since / 600 * Math.PI)
      }

      ctx.save()
      ctx.translate(cx, cy)
      ctx.rotate(rot)
      ctx.scale(sx, sy)

      // Rounded-square body
      const half = sz * 0.5
      this._roundRect(ctx, -half, -half, sz, sz, half * 0.45)
      ctx.fillStyle = baseColor
      ctx.fill()
      ctx.strokeStyle = outline
      ctx.lineWidth = 2.6
      ctx.stroke()

      // Top highlight stripe (lighter shade of body)
      ctx.fillStyle = highlight
      this._roundRect(ctx, -half * 0.7, -half * 0.78, sz * 0.7, sz * 0.18, sz * 0.08)
      ctx.fill()

      ctx.restore()
    }

    // Face on the head (always on segment 0).
    if (worm.renderSegments.length > 0) {
      const [px, py] = worm.renderSegments[0]
      const [bx, by] = worm.bob(0, now)
      const cx = px + config.cellSize / 2 + bx
      const cy = py + config.cellSize / 2 + by
      const sz = this._segmentSize(0, worm.renderSegments.length)
      this._drawFace(worm, cx, cy, sz, now)
    }

    // Pubkey hint label for non-self worms (first 4 hex chars)
    if (worm.pubkey && worm.alive && worm.pubkey !== this.myPubkey && worm.renderSegments[0]) {
      const [px, py] = worm.renderSegments[0]
      const cx = px + config.cellSize / 2
      const cy = py + config.cellSize / 2
      const labelOffset = this._segmentSize(0, worm.renderSegments.length)
      ctx.font = '700 11px "Press Start 2P", monospace'
      ctx.textAlign = 'center'
      ctx.lineWidth = 3
      ctx.strokeStyle = COL.ink
      ctx.fillStyle = COL.bone
      const label = worm.pubkey.slice(0, 4).toUpperCase()
      ctx.strokeText(label, cx, cy - labelOffset - 8)
      ctx.fillText(label, cx, cy - labelOffset - 8)
    }
  }

  /**
   * Draw the face — eyes + mouth — on the head segment.
   * Reads worm.eyeBlinkOpen, worm.isChomping(), worm.alive (dead = x_x),
   * and uses worm.lastMoveDir to shift pupils in facing direction.
   */
  _drawFace (worm, cx, cy, sz, now) {
    const ctx = this.ctx
    const dx = worm.lastMoveDir[0] || 1
    const dy = worm.lastMoveDir[1] || 0
    // Place eyes facing the movement direction. The face sits on the leading
    // edge of the head along (dx,dy). For diagonal-ish (we only have ortho
    // dirs), this gives the worm a clean "looking forward" feel.
    const facex = dx / Math.max(1e-3, Math.hypot(dx, dy))
    const facey = dy / Math.max(1e-3, Math.hypot(dx, dy))
    const px1 = cx + facex * sz * 0.18 + (-facey) * sz * 0.22
    const py1 = cy + facey * sz * 0.18 + (facex) * sz * 0.22
    const px2 = cx + facex * sz * 0.18 + (-facey) * -sz * 0.22
    const py2 = cy + facey * sz * 0.18 + (facex) * -sz * 0.22
    const eyeR = sz * 0.18

    const dead = !worm.alive
    const blinking = !worm.eyeBlinkOpen
    const chomping = worm.isChomping(now)

    if (dead) {
      // x_x eyes
      ctx.strokeStyle = COL.ink
      ctx.lineWidth = 2.6
      ctx.lineCap = 'round'
      const r = eyeR * 0.9
      ctx.beginPath()
      ctx.moveTo(px1 - r, py1 - r); ctx.lineTo(px1 + r, py1 + r)
      ctx.moveTo(px1 + r, py1 - r); ctx.lineTo(px1 - r, py1 + r)
      ctx.moveTo(px2 - r, py2 - r); ctx.lineTo(px2 + r, py2 + r)
      ctx.moveTo(px2 + r, py2 - r); ctx.lineTo(px2 - r, py2 + r)
      ctx.stroke()
      ctx.lineCap = 'butt'
      // Open-mouth surprise
      const mx = cx + facex * sz * 0.34
      const my = cy + facey * sz * 0.34
      ctx.fillStyle = COL.ink
      ctx.beginPath()
      ctx.ellipse(mx, my, sz * 0.16, sz * 0.18, 0, 0, Math.PI * 2)
      ctx.fill()
      return
    }

    // White-of-eye shape — chomp scrunches them, blink closes them
    ctx.fillStyle = COL.bone
    ctx.strokeStyle = COL.ink
    ctx.lineWidth = 1.8
    if (blinking || chomping) {
      // Closed/scrunched: a thick black arc
      ctx.strokeStyle = COL.ink
      ctx.lineWidth = 2.4
      ctx.lineCap = 'round'
      ctx.beginPath()
      ctx.moveTo(px1 - eyeR * 0.9, py1)
      if (chomping) ctx.quadraticCurveTo(px1, py1 - eyeR * 0.9, px1 + eyeR * 0.9, py1)
      else ctx.lineTo(px1 + eyeR * 0.9, py1)
      ctx.stroke()
      ctx.beginPath()
      ctx.moveTo(px2 - eyeR * 0.9, py2)
      if (chomping) ctx.quadraticCurveTo(px2, py2 - eyeR * 0.9, px2 + eyeR * 0.9, py2)
      else ctx.lineTo(px2 + eyeR * 0.9, py2)
      ctx.stroke()
      ctx.lineCap = 'butt'
    } else {
      ctx.beginPath(); ctx.arc(px1, py1, eyeR, 0, Math.PI * 2); ctx.fill(); ctx.stroke()
      ctx.beginPath(); ctx.arc(px2, py2, eyeR, 0, Math.PI * 2); ctx.fill(); ctx.stroke()
      // Pupils — shifted toward facing direction
      ctx.fillStyle = COL.ink
      const pupilR = eyeR * 0.5
      const shx = facex * eyeR * 0.4
      const shy = facey * eyeR * 0.4
      ctx.beginPath(); ctx.arc(px1 + shx, py1 + shy, pupilR, 0, Math.PI * 2); ctx.fill()
      ctx.beginPath(); ctx.arc(px2 + shx, py2 + shy, pupilR, 0, Math.PI * 2); ctx.fill()
      // Tiny shine
      ctx.fillStyle = COL.bone
      const shineR = pupilR * 0.4
      ctx.beginPath(); ctx.arc(px1 + shx - pupilR * 0.3, py1 + shy - pupilR * 0.4, shineR, 0, Math.PI * 2); ctx.fill()
      ctx.beginPath(); ctx.arc(px2 + shx - pupilR * 0.3, py2 + shy - pupilR * 0.4, shineR, 0, Math.PI * 2); ctx.fill()
    }

    // Mouth
    const mx = cx + facex * sz * 0.32
    const my = cy + facey * sz * 0.32
    ctx.strokeStyle = COL.ink
    ctx.lineCap = 'round'
    if (chomping) {
      // Open chomping mouth — filled black oval
      ctx.fillStyle = COL.ink
      ctx.beginPath()
      ctx.ellipse(mx, my, sz * 0.16, sz * 0.13, Math.atan2(facey, facex), 0, Math.PI * 2)
      ctx.fill()
    } else {
      // Tiny smile (closed mouth) — a small arc perpendicular to facing
      const ang = Math.atan2(facey, facex)
      const smileR = sz * 0.13
      ctx.lineWidth = 2.2
      ctx.beginPath()
      ctx.arc(mx, my, smileR, ang - 0.5, ang + 0.5)
      ctx.stroke()
    }
    ctx.lineCap = 'butt'
  }

  _segmentSize (i, total) {
    // Head largest, tail smallest
    const headSz = config.cellSize * 0.92
    const tailSz = config.cellSize * 0.55
    const t = total <= 1 ? 0 : i / (total - 1)
    return headSz + (tailSz - headSz) * Math.pow(t, 0.85)
  }

  _roundRect (ctx, x, y, w, h, r) {
    ctx.beginPath()
    ctx.moveTo(x + r, y)
    ctx.lineTo(x + w - r, y)
    ctx.quadraticCurveTo(x + w, y, x + w, y + r)
    ctx.lineTo(x + w, y + h - r)
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h)
    ctx.lineTo(x + r, y + h)
    ctx.quadraticCurveTo(x, y + h, x, y + h - r)
    ctx.lineTo(x, y + r)
    ctx.quadraticCurveTo(x, y, x + r, y)
    ctx.closePath()
  }

  // ─── Particles / popups ─────────────────────────────────

  _drawParticles () {
    const ctx = this.ctx
    for (const p of this.particles) {
      const a = Math.max(0, p.life / p.maxLife)
      if (p.kind === 'food-bit') {
        ctx.save()
        ctx.translate(p.x, p.y)
        ctx.rotate(p.rot || 0)
        ctx.globalAlpha = a
        const drawer = FOOD_TYPES[p.foodType] || drawApple
        drawer(ctx, 0, 0, p.size, performance.now(), 0)
        ctx.restore()
      } else {
        ctx.fillStyle = p.color
        ctx.globalAlpha = a
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.size * a, 0, Math.PI * 2)
        ctx.fill()
      }
    }
    ctx.globalAlpha = 1
  }

  _drawConfetti () {
    const ctx = this.ctx
    for (const c of this.confetti) {
      const a = Math.max(0, c.life / c.maxLife)
      ctx.save()
      ctx.translate(c.x, c.y)
      ctx.rotate(c.rot)
      ctx.globalAlpha = a
      ctx.fillStyle = c.color
      ctx.strokeStyle = COL.ink
      ctx.lineWidth = 1.5
      ctx.fillRect(-c.size / 2, -c.size / 4, c.size, c.size / 2)
      ctx.strokeRect(-c.size / 2, -c.size / 4, c.size, c.size / 2)
      ctx.restore()
    }
    ctx.globalAlpha = 1
  }

  _drawPopups () {
    const ctx = this.ctx
    for (const p of this.popups) {
      const t = 1 - (p.life / p.maxLife)
      const a = Math.min(1, (1 - t) * 1.4)
      const yOff = -28 * t // arc upward
      const scale = p.rare ? 1.2 + Math.sin(t * 6) * 0.1 : 1
      ctx.save()
      ctx.translate(p.x, p.y + yOff)
      ctx.scale(scale, scale)
      ctx.globalAlpha = a
      ctx.font = `700 ${p.rare ? 22 : 16}px "Press Start 2P", monospace`
      ctx.textAlign = 'center'
      ctx.lineWidth = 4
      ctx.strokeStyle = COL.ink
      ctx.fillStyle = p.rare ? '#ffd54f' : COL.bone
      ctx.strokeText(p.text, 0, 0)
      ctx.fillText(p.text, 0, 0)
      ctx.restore()
    }
    ctx.globalAlpha = 1
  }

  // ─── Mini-map ─────────────────────────────────────────────

  drawMiniMap (canvas) {
    if (!canvas) return
    const c = canvas.getContext('2d')
    const w = canvas.width
    const h = canvas.height
    c.clearRect(0, 0, w, h)
    // grass background
    c.fillStyle = COL.grass
    c.fillRect(0, 0, w, h)
    // dotted darker tufts for texture
    c.fillStyle = COL.grassDeep
    for (let i = 0; i < 18; i++) {
      const x = (i * 17 + 5) % w
      const y = (i * 23 + 9) % h
      c.fillRect(x, y, 2, 2)
    }
    c.strokeStyle = COL.ink
    c.lineWidth = 2
    c.strokeRect(1, 1, w - 2, h - 2)
    const sx = (w - 4) / this.world.config.width
    const sy = (h - 4) / this.world.config.height
    // food
    c.fillStyle = COL.bone
    for (const f of this.world.food.values()) {
      c.fillRect(2 + f.x * sx, 2 + f.y * sy, 1.6, 1.6)
    }
    // worms
    for (const worm of this.world.worms.values()) {
      if (!worm.alive) continue
      c.fillStyle = worm.color
      const head = worm.targetSegments[0]
      if (!head) continue
      const r = worm.pubkey === this.myPubkey ? 3 : 2
      c.beginPath()
      c.arc(2 + head[0] * sx, 2 + head[1] * sy, r, 0, Math.PI * 2)
      c.fill()
      if (worm.pubkey === this.myPubkey) {
        // outline my own dot for legibility
        c.strokeStyle = COL.ink
        c.lineWidth = 1.5
        c.stroke()
      }
    }
    // Camera viewport rectangle
    c.strokeStyle = COL.ink
    c.globalAlpha = 0.6
    c.lineWidth = 1
    const vx = 2 + (this.camera.x / config.cellSize) * sx
    const vy = 2 + (this.camera.y / config.cellSize) * sy
    const vw = (this.width / config.cellSize) * sx
    const vh = (this.height / config.cellSize) * sy
    c.strokeRect(vx, vy, vw, vh)
    c.globalAlpha = 1
  }
}

// ─── Food sprite drawers ───────────────────────────────────
//
// Each takes (ctx, cx, cy, r, now, pulse). All food draws a tiny smile,
// because that's THE goofy touch — food that's happy to be eaten.

function smile (ctx, cx, cy, r) {
  // Two dot eyes + a tiny curved smile
  ctx.fillStyle = '#1f1d2b'
  ctx.beginPath(); ctx.arc(cx - r * 0.28, cy - r * 0.05, r * 0.10, 0, Math.PI * 2); ctx.fill()
  ctx.beginPath(); ctx.arc(cx + r * 0.28, cy - r * 0.05, r * 0.10, 0, Math.PI * 2); ctx.fill()
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1, r * 0.10)
  ctx.lineCap = 'round'
  ctx.beginPath()
  ctx.arc(cx, cy + r * 0.18, r * 0.30, 0.2 * Math.PI, 0.8 * Math.PI)
  ctx.stroke()
  ctx.lineCap = 'butt'
}

function drawApple (ctx, cx, cy, r) {
  // Stem + leaf
  ctx.strokeStyle = '#5a3920'
  ctx.lineWidth = Math.max(1.2, r * 0.18)
  ctx.lineCap = 'round'
  ctx.beginPath(); ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy - r * 1.3); ctx.stroke()
  ctx.fillStyle = '#7cba5f'
  ctx.beginPath()
  ctx.ellipse(cx + r * 0.45, cy - r * 1.05, r * 0.4, r * 0.22, -0.4, 0, Math.PI * 2)
  ctx.fill()
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = 1.5; ctx.stroke()
  // body
  ctx.fillStyle = '#e74c3c'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.22)
  ctx.beginPath()
  ctx.arc(cx, cy, r, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // highlight
  ctx.fillStyle = 'rgba(255,255,255,0.55)'
  ctx.beginPath()
  ctx.ellipse(cx - r * 0.35, cy - r * 0.35, r * 0.22, r * 0.14, -0.6, 0, Math.PI * 2)
  ctx.fill()
  smile(ctx, cx, cy + r * 0.05, r)
}

function drawDonut (ctx, cx, cy, r) {
  // ring body
  ctx.fillStyle = '#f4a07a'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.22)
  ctx.beginPath()
  ctx.arc(cx, cy, r, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // pink frosting (dripping shape on top)
  ctx.fillStyle = '#ff5e9c'
  ctx.beginPath()
  ctx.arc(cx, cy, r * 0.95, Math.PI * 1.05, Math.PI * 1.95)
  ctx.lineTo(cx + r * 0.7, cy + r * 0.1)
  ctx.bezierCurveTo(cx + r * 0.4, cy + r * 0.5, cx - r * 0.4, cy + r * 0.3, cx - r * 0.7, cy + r * 0.05)
  ctx.closePath()
  ctx.fill()
  ctx.lineWidth = Math.max(1.2, r * 0.16); ctx.stroke()
  // sprinkles
  const cols = ['#4fc3f7', '#ffd54f', '#aedb45', '#fff8e7']
  for (let i = 0; i < 5; i++) {
    const a = i / 5 * Math.PI * 2
    ctx.fillStyle = cols[i % cols.length]
    ctx.save()
    ctx.translate(cx + Math.cos(a) * r * 0.55, cy - r * 0.2 + Math.sin(a) * r * 0.25)
    ctx.rotate(a)
    ctx.fillRect(-r * 0.18, -r * 0.05, r * 0.36, r * 0.10)
    ctx.restore()
  }
  // hole
  ctx.fillStyle = '#7cba5f'
  ctx.beginPath()
  ctx.arc(cx, cy, r * 0.30, 0, Math.PI * 2)
  ctx.fill()
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = 1.5; ctx.stroke()
  smile(ctx, cx, cy + r * 0.55, r * 0.7)
}

function drawIceCream (ctx, cx, cy, r) {
  // Cone (triangle)
  ctx.fillStyle = '#d49a4f'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.18)
  ctx.lineJoin = 'round'
  ctx.beginPath()
  ctx.moveTo(cx - r * 0.6, cy)
  ctx.lineTo(cx + r * 0.6, cy)
  ctx.lineTo(cx, cy + r * 1.0)
  ctx.closePath()
  ctx.fill(); ctx.stroke()
  // waffle lines
  ctx.beginPath()
  ctx.moveTo(cx - r * 0.5, cy + r * 0.1); ctx.lineTo(cx + r * 0.5, cy + r * 0.1)
  ctx.moveTo(cx - r * 0.4, cy + r * 0.4); ctx.lineTo(cx + r * 0.4, cy + r * 0.4)
  ctx.moveTo(cx - r * 0.25, cy + r * 0.7); ctx.lineTo(cx + r * 0.25, cy + r * 0.7)
  ctx.lineWidth = 1.2; ctx.stroke()
  // scoop
  ctx.fillStyle = '#ff5e9c'
  ctx.lineWidth = Math.max(1.5, r * 0.22)
  ctx.beginPath()
  ctx.arc(cx, cy - r * 0.15, r * 0.7, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // cherry
  ctx.fillStyle = '#e74c3c'
  ctx.beginPath()
  ctx.arc(cx, cy - r * 0.85, r * 0.15, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  smile(ctx, cx, cy - r * 0.10, r * 0.55)
}

function drawPizza (ctx, cx, cy, r) {
  // triangle slice
  ctx.fillStyle = '#ffd54f'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.20)
  ctx.lineJoin = 'round'
  ctx.beginPath()
  ctx.moveTo(cx, cy - r * 0.8)
  ctx.lineTo(cx + r * 0.85, cy + r * 0.5)
  ctx.lineTo(cx - r * 0.85, cy + r * 0.5)
  ctx.closePath()
  ctx.fill(); ctx.stroke()
  // crust strip at the bottom
  ctx.fillStyle = '#e09c4d'
  ctx.beginPath()
  ctx.moveTo(cx + r * 0.85, cy + r * 0.5)
  ctx.lineTo(cx - r * 0.85, cy + r * 0.5)
  ctx.lineTo(cx - r * 0.7, cy + r * 0.32)
  ctx.lineTo(cx + r * 0.7, cy + r * 0.32)
  ctx.closePath()
  ctx.fill(); ctx.stroke()
  // pepperoni
  ctx.fillStyle = '#e74c3c'
  for (const [dx, dy] of [[-0.25, -0.15], [0.30, 0.05], [0.0, 0.30]]) {
    ctx.beginPath()
    ctx.arc(cx + dx * r, cy + dy * r, r * 0.16, 0, Math.PI * 2)
    ctx.fill(); ctx.stroke()
  }
  smile(ctx, cx, cy - r * 0.05, r * 0.55)
}

function drawGummy (ctx, cx, cy, r) {
  // bear shape — stylized: rounded body + 2 little ears
  ctx.fillStyle = '#aedb45'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.20)
  // body
  ctx.beginPath()
  ctx.ellipse(cx, cy + r * 0.05, r * 0.85, r * 0.95, 0, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // ears
  ctx.beginPath()
  ctx.arc(cx - r * 0.55, cy - r * 0.55, r * 0.25, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  ctx.beginPath()
  ctx.arc(cx + r * 0.55, cy - r * 0.55, r * 0.25, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // belly highlight
  ctx.fillStyle = 'rgba(255,255,255,0.4)'
  ctx.beginPath()
  ctx.ellipse(cx, cy + r * 0.25, r * 0.4, r * 0.5, 0, 0, Math.PI * 2)
  ctx.fill()
  smile(ctx, cx, cy - r * 0.10, r * 0.7)
}

function drawCherry (ctx, cx, cy, r) {
  // two stems meeting + two cherries
  ctx.strokeStyle = '#5a3920'
  ctx.lineWidth = Math.max(1.5, r * 0.16)
  ctx.lineCap = 'round'
  ctx.beginPath()
  ctx.moveTo(cx - r * 0.3, cy + r * 0.3)
  ctx.bezierCurveTo(cx - r * 0.4, cy - r * 0.6, cx + r * 0.0, cy - r * 0.7, cx + r * 0.2, cy - r * 0.95)
  ctx.moveTo(cx + r * 0.3, cy + r * 0.3)
  ctx.bezierCurveTo(cx + r * 0.4, cy - r * 0.6, cx + r * 0.1, cy - r * 0.6, cx + r * 0.2, cy - r * 0.95)
  ctx.stroke()
  ctx.lineCap = 'butt'
  // leaf at top
  ctx.fillStyle = '#7cba5f'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = 1.4
  ctx.beginPath()
  ctx.ellipse(cx + r * 0.42, cy - r * 0.95, r * 0.22, r * 0.10, -0.6, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // cherries
  ctx.fillStyle = '#e74c3c'
  ctx.lineWidth = Math.max(1.5, r * 0.20)
  ctx.beginPath()
  ctx.arc(cx - r * 0.3, cy + r * 0.45, r * 0.45, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  ctx.beginPath()
  ctx.arc(cx + r * 0.3, cy + r * 0.45, r * 0.45, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  // shines
  ctx.fillStyle = 'rgba(255,255,255,0.6)'
  ctx.beginPath()
  ctx.ellipse(cx - r * 0.40, cy + r * 0.30, r * 0.10, r * 0.06, -0.5, 0, Math.PI * 2)
  ctx.fill()
  ctx.beginPath()
  ctx.ellipse(cx + r * 0.20, cy + r * 0.30, r * 0.10, r * 0.06, -0.5, 0, Math.PI * 2)
  ctx.fill()
  // smile across both cherries (one of them, who cares which)
  ctx.fillStyle = '#1f1d2b'
  ctx.beginPath()
  ctx.arc(cx - r * 0.36, cy + r * 0.42, r * 0.06, 0, Math.PI * 2); ctx.fill()
  ctx.beginPath()
  ctx.arc(cx - r * 0.20, cy + r * 0.42, r * 0.06, 0, Math.PI * 2); ctx.fill()
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1, r * 0.10)
  ctx.lineCap = 'round'
  ctx.beginPath()
  ctx.arc(cx - r * 0.28, cy + r * 0.55, r * 0.14, 0.2 * Math.PI, 0.8 * Math.PI)
  ctx.stroke()
  ctx.lineCap = 'butt'
}

function drawGoldenApple (ctx, cx, cy, r, now) {
  // Sparkle ring around a yellow apple
  const t = now / 1000
  const ringR = r * 1.7 + Math.sin(t * 4) * r * 0.15
  // ring sparkles
  ctx.save()
  ctx.translate(cx, cy)
  ctx.rotate(t * 1.5)
  for (let i = 0; i < 8; i++) {
    const a = (i / 8) * Math.PI * 2
    ctx.fillStyle = '#fff8e7'
    ctx.strokeStyle = '#1f1d2b'
    ctx.lineWidth = 1.2
    const sx = Math.cos(a) * ringR
    const sy = Math.sin(a) * ringR
    ctx.save()
    ctx.translate(sx, sy)
    ctx.rotate(a)
    ctx.beginPath()
    ctx.moveTo(0, -r * 0.18)
    ctx.lineTo(r * 0.06, 0)
    ctx.lineTo(0, r * 0.18)
    ctx.lineTo(-r * 0.06, 0)
    ctx.closePath()
    ctx.fill(); ctx.stroke()
    ctx.restore()
  }
  ctx.restore()
  // golden apple
  ctx.strokeStyle = '#5a3920'
  ctx.lineWidth = Math.max(1.2, r * 0.16)
  ctx.beginPath(); ctx.moveTo(cx, cy - r); ctx.lineTo(cx, cy - r * 1.2); ctx.stroke()
  ctx.fillStyle = '#ffd54f'
  ctx.strokeStyle = '#1f1d2b'
  ctx.lineWidth = Math.max(1.5, r * 0.22)
  ctx.beginPath()
  ctx.arc(cx, cy, r, 0, Math.PI * 2)
  ctx.fill(); ctx.stroke()
  ctx.fillStyle = 'rgba(255,255,255,0.7)'
  ctx.beginPath()
  ctx.ellipse(cx - r * 0.35, cy - r * 0.35, r * 0.22, r * 0.14, -0.6, 0, Math.PI * 2)
  ctx.fill()
  smile(ctx, cx, cy + r * 0.05, r)
}

function easeOutBack (t, s = 1.7) {
  const x = t - 1
  return 1 + (s + 1) * x * x * x + s * x * x
}
