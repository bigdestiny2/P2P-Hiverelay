// HiveWorm — chiptune-pop SFX via Web Audio API.
//
// Vibe: Sega Genesis FM synth meets Pokémon item-pickup. Square waves with
// short envelopes, simple FM, minimal reverb. Aiming for "characterful 8-bit
// arcade with warm chord progressions" — NOT modern EDM, NOT cypherpunk, NOT
// generic notification UI sounds.
//
// Each sound is timed precisely against the on-screen animation that fires
// it (e.g. `eat` is exactly 100ms, matching the chomp animation).
//
// Public API:
//   audio.unlock()           call inside a user gesture (browser policy)
//   audio.play(name, opts)   names: blip, splat, swoosh, chime, spawn,
//                            click, rare, ko
//   audio.toggleMute()
//   audio.startAmbient()     bossa-chiptune ambient pad (off by default)

import { config } from './config.js'

export class AudioEngine {
  constructor () {
    this.muted = !!config.defaultMuted
    this.ctx = null
    this.master = null
    this._unlocked = false
    this._ambient = null
  }

  unlock () {
    if (this._unlocked) return
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext
      if (!Ctx) return
      this.ctx = new Ctx()
      this.master = this.ctx.createGain()
      this.master.gain.value = this.muted ? 0 : 0.4
      // Subtle highshelf boost so square waves don't sound dull
      const hs = this.ctx.createBiquadFilter()
      hs.type = 'highshelf'
      hs.frequency.value = 3500
      hs.gain.value = 2
      this.master.connect(hs)
      hs.connect(this.ctx.destination)
      this._unlocked = true
    } catch (_) { /* ignore */ }
  }

  toggleMute () {
    this.muted = !this.muted
    if (this.master) {
      this.master.gain.cancelScheduledValues(this.ctx.currentTime)
      this.master.gain.setTargetAtTime(this.muted ? 0 : 0.4, this.ctx.currentTime, 0.05)
    }
  }

  // ─── Effect playback ────────────────────────────────────────

  play (name, opts = {}) {
    if (!this._unlocked || !this.ctx) return
    switch (name) {
      case 'blip': return this._eat(opts)
      case 'rare': return this._rareEat()
      case 'splat': return this._death()
      case 'ko': return this._ko()
      case 'swoosh': return this._swoosh()
      case 'chime': return this._chime()
      case 'spawn': return this._spawn()
      case 'click': return this._click()
    }
  }

  // ─── Internals ──────────────────────────────────────────────

  _tone (type, freq, t0, dur, peak = 0.3, opts = {}) {
    const osc = this.ctx.createOscillator()
    const g = this.ctx.createGain()
    osc.type = type
    osc.frequency.setValueAtTime(freq, t0)
    if (opts.sweepTo != null) {
      osc.frequency.exponentialRampToValueAtTime(Math.max(20, opts.sweepTo), t0 + dur)
    }
    // Punchy envelope: short attack, exp decay
    g.gain.setValueAtTime(0, t0)
    g.gain.linearRampToValueAtTime(peak, t0 + 0.005)
    g.gain.exponentialRampToValueAtTime(0.001, t0 + dur)
    osc.connect(g)
    if (opts.filter) {
      const f = this.ctx.createBiquadFilter()
      f.type = opts.filter.type || 'lowpass'
      f.frequency.value = opts.filter.freq || 2400
      f.Q.value = opts.filter.q || 0.5
      g.disconnect()
      g.connect(f)
      f.connect(this.master)
    } else {
      g.connect(this.master)
    }
    osc.start(t0)
    osc.stop(t0 + dur + 0.05)
    return { osc, g }
  }

  /**
   * Eat blip — short pop with slight pitch variance per call.
   * Matches the 100ms chomp animation. Two-step climb: low → high.
   */
  _eat (opts = {}) {
    const t = this.ctx.currentTime
    // pitch variance: ±2 semitones from the base
    const variance = (opts.variance != null) ? opts.variance : (Math.random() - 0.5) * 0.18
    const base = 880 * Math.pow(2, variance)
    this._tone('square', base * 0.7, t, 0.06, 0.22, { sweepTo: base * 1.25 })
    this._tone('square', base * 1.4, t + 0.04, 0.05, 0.16, { sweepTo: base * 1.7 })
  }

  /**
   * Rare-food ascending arpeggio — Mario-star vibe, 4 quick notes up.
   */
  _rareEat () {
    const t = this.ctx.currentTime
    const root = 523.25 // C5
    // C E G C — major arpeggio
    const ratios = [1, 5 / 4, 3 / 2, 2]
    ratios.forEach((r, i) => {
      this._tone('square', root * r, t + i * 0.06, 0.12, 0.24)
      // Octave-up FM tinge for sparkle
      this._tone('triangle', root * r * 2, t + i * 0.06, 0.10, 0.10)
    })
  }

  /**
   * Death — cartoon slide-whistle descending.
   */
  _death () {
    const t = this.ctx.currentTime
    const osc = this.ctx.createOscillator()
    const g = this.ctx.createGain()
    osc.type = 'triangle'
    osc.frequency.setValueAtTime(880, t)
    osc.frequency.exponentialRampToValueAtTime(80, t + 0.55)
    g.gain.setValueAtTime(0, t)
    g.gain.linearRampToValueAtTime(0.32, t + 0.02)
    g.gain.exponentialRampToValueAtTime(0.001, t + 0.55)
    osc.connect(g)
    g.connect(this.master)
    osc.start(t)
    osc.stop(t + 0.6)
    // Add a brief noise tail for the "splat" body
    const buf = this.ctx.createBuffer(1, this.ctx.sampleRate * 0.18, this.ctx.sampleRate)
    const d = buf.getChannelData(0)
    for (let i = 0; i < d.length; i++) {
      d[i] = (Math.random() * 2 - 1) * (1 - i / d.length) * 0.4
    }
    const noise = this.ctx.createBufferSource()
    noise.buffer = buf
    const nf = this.ctx.createBiquadFilter()
    nf.type = 'lowpass'; nf.frequency.value = 1200
    const ng = this.ctx.createGain()
    ng.gain.setValueAtTime(0.2, t + 0.45); ng.gain.exponentialRampToValueAtTime(0.001, t + 0.7)
    noise.connect(nf); nf.connect(ng); ng.connect(this.master)
    noise.start(t + 0.45); noise.stop(t + 0.7)
  }

  /**
   * Big "K.O." stinger — heavier than normal death blip.
   */
  _ko () {
    const t = this.ctx.currentTime
    // dramatic descending power-chord
    const base = 220
    this._tone('square', base, t, 0.32, 0.30, { sweepTo: base * 0.5 })
    this._tone('square', base * 1.5, t, 0.28, 0.22, { sweepTo: base * 0.75 })
    this._tone('triangle', base * 2, t + 0.05, 0.20, 0.16, { sweepTo: base })
  }

  /**
   * Swoosh — short cartoon-trail whoosh, rising triangle.
   */
  _swoosh () {
    const t = this.ctx.currentTime
    this._tone('triangle', 380, t, 0.13, 0.16, { sweepTo: 720 })
    // Hint of noise for air
    const buf = this.ctx.createBuffer(1, this.ctx.sampleRate * 0.12, this.ctx.sampleRate)
    const d = buf.getChannelData(0)
    for (let i = 0; i < d.length; i++) {
      d[i] = (Math.random() * 2 - 1) * (1 - i / d.length) * 0.3
    }
    const noise = this.ctx.createBufferSource()
    noise.buffer = buf
    const f = this.ctx.createBiquadFilter()
    f.type = 'bandpass'; f.frequency.value = 1800; f.Q.value = 1.2
    const g = this.ctx.createGain()
    g.gain.setValueAtTime(0.06, t); g.gain.exponentialRampToValueAtTime(0.001, t + 0.13)
    noise.connect(f); f.connect(g); g.connect(this.master)
    noise.start(t); noise.stop(t + 0.14)
  }

  /**
   * Friendly milestone bell — like a 90s game menu confirm.
   * Pentatonic stack with a tiny FM sparkle.
   */
  _chime () {
    const t = this.ctx.currentTime
    // C major pentatonic up: C E G C
    const freqs = [523.25, 659.25, 783.99, 1046.5]
    freqs.forEach((f, i) => {
      this._tone('square', f, t + i * 0.07, 0.32, 0.20 - i * 0.03)
      // Soft triangle harmonic
      this._tone('triangle', f * 0.5, t + i * 0.07, 0.25, 0.10)
    })
  }

  /**
   * Spawn — cheerful boing + ascending arpeggio.
   */
  _spawn () {
    const t = this.ctx.currentTime
    // Boing: low square that quick-sweeps up
    this._tone('square', 200, t, 0.15, 0.30, { sweepTo: 440 })
    // Then a 3-note arpeggio up the major triad
    const ratios = [1, 1.25, 1.5]
    ratios.forEach((r, i) => {
      this._tone('square', 440 * r, t + 0.10 + i * 0.07, 0.16, 0.20)
    })
  }

  _click () {
    const t = this.ctx.currentTime
    this._tone('square', 880, t, 0.05, 0.15)
  }

  /**
   * Optional bossa-meets-chiptune ambient bed. Off by default; call
   * startAmbient() to begin. A slow looping bassline + held chord pad
   * on square waves through a lowpass, ~110 BPM. Animal Crossing morning
   * energy, not city pop.
   */
  startAmbient () {
    if (!this._unlocked || this._ambient) return
    const ctx = this.ctx
    const out = ctx.createGain()
    out.gain.value = 0.10
    out.connect(this.master)

    // Pad — held square chord through a slow filter sweep
    const padFilter = ctx.createBiquadFilter()
    padFilter.type = 'lowpass'
    padFilter.frequency.value = 600
    padFilter.Q.value = 0.6
    padFilter.connect(out)
    const padOscs = []
    // C major 7 voicing: C E G B (one octave down each)
    for (const f of [130.81, 164.81, 196.00, 246.94]) {
      const osc = ctx.createOscillator()
      osc.type = 'square'
      osc.frequency.value = f
      const g = ctx.createGain()
      g.gain.value = 0.05
      osc.connect(g)
      g.connect(padFilter)
      osc.start()
      padOscs.push(osc)
    }
    // Slow filter LFO so the pad breathes
    const padLfo = ctx.createOscillator()
    padLfo.frequency.value = 0.07
    const padLfoGain = ctx.createGain()
    padLfoGain.gain.value = 350
    padLfo.connect(padLfoGain)
    padLfoGain.connect(padFilter.frequency)
    padLfo.start()

    // Bassline — looping 4-note pattern at ~110 BPM (8 eighth-notes per bar,
    // 4-bar phrase)
    const bpm = 110
    const eighth = 60 / bpm / 2 // seconds per 8th
    const bass = [65.41, 65.41, 82.41, 65.41, 49.00, 49.00, 65.41, 73.42]
    let i = 0
    const tickBass = () => {
      if (!this._ambient) return
      const t = ctx.currentTime
      const f = bass[i % bass.length]
      const osc = ctx.createOscillator()
      osc.type = 'triangle'
      osc.frequency.value = f
      const g = ctx.createGain()
      g.gain.setValueAtTime(0, t)
      g.gain.linearRampToValueAtTime(0.18, t + 0.01)
      g.gain.exponentialRampToValueAtTime(0.001, t + eighth * 0.9)
      osc.connect(g)
      g.connect(out)
      osc.start(t)
      osc.stop(t + eighth)
      i++
    }
    const bassInt = setInterval(tickBass, eighth * 1000)

    // Twinkle melody — pentatonic notes triggered with a 1-in-4 chance per beat
    const melodyNotes = [523.25, 587.33, 659.25, 783.99, 880.00, 1046.5]
    let mi = 0
    const tickMelody = () => {
      if (!this._ambient) return
      mi++
      if (Math.random() < 0.35) {
        const t = ctx.currentTime
        const f = melodyNotes[Math.floor(Math.random() * melodyNotes.length)]
        const osc = ctx.createOscillator()
        osc.type = 'square'
        osc.frequency.value = f
        const g = ctx.createGain()
        g.gain.setValueAtTime(0, t)
        g.gain.linearRampToValueAtTime(0.05, t + 0.01)
        g.gain.exponentialRampToValueAtTime(0.001, t + 0.6)
        osc.connect(g)
        g.connect(out)
        osc.start(t)
        osc.stop(t + 0.7)
      }
    }
    const melInt = setInterval(tickMelody, eighth * 2000)

    this._ambient = { padOscs, padLfo, padFilter, out, bassInt, melInt }
  }

  stopAmbient () {
    if (!this._ambient) return
    try {
      for (const o of this._ambient.padOscs) o.stop()
      this._ambient.padLfo.stop()
      clearInterval(this._ambient.bassInt)
      clearInterval(this._ambient.melInt)
    } catch (_) {}
    this._ambient = null
  }
}
