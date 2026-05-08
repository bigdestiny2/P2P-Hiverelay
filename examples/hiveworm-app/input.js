// HiveWorm — keyboard + touch input with a cooldown gate
//
// Players move by pressing arrow keys or WASD, or by tapping a directional
// pad on touch devices. The cooldown gate prevents the UI from queuing
// requests faster than the relay will accept them.

import { config } from './config.js'

const KEY_TO_DIR = {
  ArrowUp: 'N',
  ArrowDown: 'S',
  ArrowLeft: 'W',
  ArrowRight: 'E',
  w: 'N',
  s: 'S',
  a: 'W',
  d: 'E',
  W: 'N',
  S: 'S',
  A: 'W',
  D: 'E',
  k: 'N',
  j: 'S',
  h: 'W',
  l: 'E'
}

export class Input {
  constructor ({ onMove, onMute, onRespawn, onSpawn } = {}) {
    this.onMove = onMove || (() => {})
    this.onMute = onMute || (() => {})
    this.onRespawn = onRespawn || (() => {})
    this.onSpawn = onSpawn || (() => {})

    this.lastSubmittedTs = 0
    this._pad = null
    this._padButtons = []
  }

  start () {
    window.addEventListener('keydown', this._onKey)
  }

  stop () {
    window.removeEventListener('keydown', this._onKey)
  }

  _onKey = (e) => {
    if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return
    if (e.key === 'm' || e.key === 'M') {
      this.onMute()
      return
    }
    if (e.key === 'Enter' || e.key === ' ') {
      // Used for SPAWN / RESPAWN buttons when they're focused; let the
      // browser handle Enter/Space natively for buttons. No-op here.
      return
    }
    const dir = KEY_TO_DIR[e.key]
    if (!dir) return
    e.preventDefault()
    this.tryMove(dir)
  }

  /**
   * Attempt a move. Returns:
   *   { ok: true, direction }
   *   { ok: false, reason: 'cooldown', remainingMs }
   */
  tryMove (direction) {
    const now = Date.now()
    const since = now - this.lastSubmittedTs
    if (this.lastSubmittedTs && since < config.moveCooldownMs) {
      const remainingMs = config.moveCooldownMs - since
      return { ok: false, reason: 'cooldown', remainingMs }
    }
    // We only optimistically advance lastSubmittedTs when the caller
    // confirms; otherwise a rejected move would lock us out.
    this.onMove(direction, () => { this.lastSubmittedTs = Date.now() })
    return { ok: true, direction }
  }

  cooldownRemaining () {
    if (!this.lastSubmittedTs) return 0
    return Math.max(0, config.moveCooldownMs - (Date.now() - this.lastSubmittedTs))
  }

  /**
   * Mount a touch directional-pad. `host` is a DOM element to render into.
   */
  mountTouchPad (host) {
    if (!host) return
    host.innerHTML = ''
    const pad = document.createElement('div')
    pad.className = 'touch-pad'
    const dirs = [
      { d: 'N', label: 'up', cls: 'up' },
      { d: 'W', label: 'left', cls: 'left' },
      { d: 'E', label: 'right', cls: 'right' },
      { d: 'S', label: 'down', cls: 'down' }
    ]
    for (const item of dirs) {
      const btn = document.createElement('button')
      btn.className = 'touch-btn touch-' + item.cls
      btn.setAttribute('aria-label', 'Move ' + item.label)
      btn.textContent = '▲' // arrow placeholder, CSS rotates per cls
      btn.addEventListener('touchstart', (e) => {
        e.preventDefault()
        this.tryMove(item.d)
      }, { passive: false })
      btn.addEventListener('click', (e) => {
        e.preventDefault()
        this.tryMove(item.d)
      })
      pad.appendChild(btn)
      this._padButtons.push(btn)
    }
    host.appendChild(pad)
    this._pad = pad
  }
}
