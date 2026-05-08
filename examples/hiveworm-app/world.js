// HiveWorm — client-side world model
//
// Holds Worms (visuals + authoritative segments), food dots, and a few
// derived stats. Receives entries from the network module and applies
// them. We do NOT re-derive the full world state in the browser — the
// relay's /state endpoint is the source of truth and we keep ourselves
// close to it.
//
// We *do* apply MOVE/SPAWN/MEMORIAL entries optimistically when we see
// them streamed (so animation is responsive), but a periodic state pull
// will overwrite anything that drifted.

import { Worm } from './worm.js'
import { SCHEMAS, DIR_VEC } from './schema.js'
import { config } from './config.js'

export class World {
  constructor () {
    this.worms = new Map() // pubkey -> Worm
    this.food = new Map() // "x,y" -> { x, y, value, born, pulse }
    this.deaths = [] // recent deaths { pubkey, atPos, byPubkey, ts }
    this.memorials = []
    this.config = {
      width: config.worldWidth,
      height: config.worldHeight,
      moveCooldownMs: config.moveCooldownMs,
      spawnLength: 3,
      targetFoodCount: 50
    }
    this.tick = 0

    // Fired so the renderer / audio can react
    this._listeners = {
      moved: [],
      ate: [],
      spawned: [],
      died: []
    }
  }

  on (event, fn) {
    (this._listeners[event] = this._listeners[event] || []).push(fn)
  }

  emit (event, payload) {
    const ls = this._listeners[event] || []
    for (const fn of ls) {
      try { fn(payload) } catch (_) {}
    }
  }

  cellKey (x, y) { return x + ',' + y }

  /**
   * Replace world from the relay's /state JSON. Snaps any newly seen
   * worms; leaves existing render state in place where possible.
   */
  loadState (stateJson, now) {
    if (!stateJson) return
    if (stateJson.config) Object.assign(this.config, stateJson.config)
    if (typeof stateJson.tick === 'number') this.tick = stateJson.tick

    // Worms
    const seen = new Set()
    for (const w of (stateJson.worms || [])) {
      seen.add(w.pubkey)
      let worm = this.worms.get(w.pubkey)
      if (!worm) {
        worm = new Worm(w.pubkey)
        this.worms.set(w.pubkey, worm)
      }
      worm.length = w.length
      worm.bornAt = w.bornAt
      worm.lastMoveTs = w.lastMoveTs
      worm.setAlive(w.alive)
      worm.setSegments(w.segments, now)
    }
    // Don't delete missing worms — relay could have just trimmed state;
    // we keep ghosts in place for ~30 seconds (death animations)

    // Food
    this.food.clear()
    for (const f of (stateJson.food || [])) {
      this.food.set(this.cellKey(f.x, f.y), {
        x: f.x,
        y: f.y,
        value: f.value || 1,
        born: now,
        pulse: Math.random() * Math.PI * 2,
        rare: ((f.x * 31 + f.y * 17) % 23) === 0
      })
    }

    if (Array.isArray(stateJson.deaths)) {
      this.deaths = stateJson.deaths.slice(-20)
    }
    if (Array.isArray(stateJson.memorials)) {
      this.memorials = stateJson.memorials.slice(-20)
    }
  }

  /**
   * Apply a single signed entry from the log/WS. Returns a hint about
   * what changed so the audio + renderer can react.
   */
  applyEntry (entry, now) {
    if (!entry || typeof entry.schema !== 'string') return null
    switch (entry.schema) {
      case SCHEMAS.SPAWN:
        return this._applySpawn(entry, now)
      case SCHEMAS.MOVE:
        return this._applyMove(entry, now)
      case SCHEMAS.MEMORIAL:
        this.memorials.push({
          pubkey: entry.worm,
          epitaph: entry.epitaph,
          atTick: this.tick
        })
        return { kind: 'memorial', worm: entry.worm }
      default:
        return null
    }
  }

  _applySpawn (entry, now) {
    const [x, y] = entry.atPos
    const segs = []
    for (let i = 0; i < this.config.spawnLength; i++) segs.push([x, y])
    let worm = this.worms.get(entry.worm)
    if (!worm) {
      worm = new Worm(entry.worm)
      this.worms.set(entry.worm, worm)
    }
    worm.length = this.config.spawnLength
    worm.alive = true
    worm.bornAt = entry.ts
    worm.setSegments(segs, now)
    this.emit('spawned', { pubkey: entry.worm, atPos: [x, y] })
    return { kind: 'spawn', worm: entry.worm }
  }

  _applyMove (entry, now) {
    const worm = this.worms.get(entry.worm)
    if (!worm || !worm.alive) return null
    const head = worm.targetSegments[0]
    if (!head) return null
    const dv = DIR_VEC[entry.direction]
    if (!dv) return null
    const nx = head[0] + dv[0]
    const ny = head[1] + dv[1]

    // Check food
    const foodKey = this.cellKey(nx, ny)
    const eatenFood = this.food.get(foodKey) || null
    const ate = !!eatenFood
    const ateRare = !!(eatenFood && eatenFood.rare)

    // Check collision
    let collidedWith = null
    for (const other of this.worms.values()) {
      if (other === worm) continue
      if (!other.alive) continue
      for (const [sx, sy] of other.targetSegments) {
        if (sx === nx && sy === ny) { collidedWith = other.pubkey; break }
      }
      if (collidedWith) break
    }

    const newSegs = [[nx, ny], ...worm.targetSegments]
    if (!ate) newSegs.pop()
    else {
      worm.length += 1
      this.food.delete(foodKey)
    }
    worm.setSegments(newSegs, now)
    worm.lastMoveTs = entry.ts

    if (collidedWith) {
      worm.alive = false
      // Drop dead worm's segments as food (matches deriver behavior)
      for (const [sx, sy] of worm.targetSegments) {
        if (sx >= 0 && sy >= 0 && sx < this.config.width && sy < this.config.height) {
          this.food.set(this.cellKey(sx, sy), {
            x: sx,
            y: sy,
            value: 1,
            born: now,
            pulse: Math.random() * Math.PI * 2,
            rare: false
          })
        }
      }
      this.deaths.push({
        pubkey: entry.worm,
        atPos: [nx, ny],
        byPubkey: collidedWith,
        ts: entry.ts
      })
      this.emit('died', {
        pubkey: entry.worm,
        atPos: [nx, ny],
        byPubkey: collidedWith,
        worm
      })
      return { kind: 'death', worm: entry.worm, atPos: [nx, ny] }
    }

    this.emit('moved', { pubkey: entry.worm, direction: entry.direction, ate })
    if (ate) this.emit('ate', { pubkey: entry.worm, atPos: [nx, ny], rare: ateRare })
    return { kind: ate ? 'ate' : 'move', worm: entry.worm }
  }

  /**
   * Per-frame update — eases worm visuals, ages food pulses.
   */
  tickAnim (now, dt) {
    for (const w of this.worms.values()) w.tick(now, dt)
    for (const f of this.food.values()) f.pulse += dt * 0.003
  }

  myWorm (pubkey) { return this.worms.get(pubkey) || null }
}
