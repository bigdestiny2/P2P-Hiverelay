/**
 * First-run setup wizard — state machine + persistence.
 *
 * Guides a fresh operator from "I just installed this" to "my relay is
 * online" in 5 steps:
 *
 *   1. welcome      — user clicks "Let's go"
 *   2. relay_name   — operator picks a name (or accepts the default)
 *   3. payout       — OPTIONAL on-chain BTC payout address (skippable)
 *   4. accept_mode  — choose review/open/allowlist/closed (default: review)
 *   5. complete     — wizard done; main dashboard takes over
 *
 * The payout address feeds `subsidy.payoutDestination`. The relay NEVER
 * holds funds — it accrues a capped sats estimate for blind-peer work and
 * signs claims that a subsidy coordinator independently verifies and pays
 * out to the operator's own address. Because the address is public, it is
 * stored in plaintext (no encryption needed) — unlike the old
 * `lnbits_connect` step, which stored a secret admin key and is now gone.
 *
 * State persists to a small JSON file in the storage dir so container
 * restarts and reinstalls don't reset wizard progress.
 *
 * The wizard is OPTIONAL — relays started via CLI or env-only configs skip
 * it entirely. The HTTP layer checks `wizard.isComplete()` and redirects to
 * /wizard only when the answer is false.
 */

import { EventEmitter } from 'events'
import { readFile, writeFile, rename, mkdir, chmod } from 'fs/promises'
import { dirname, basename, join } from 'path'
import { validatePayoutDestination } from '../incentive/subsidy/index.js'

const VALID_STEPS = ['welcome', 'relay_name', 'payout', 'accept_mode', 'complete']
const VALID_ACCEPT_MODES = ['open', 'review', 'allowlist', 'closed']
// v3: replaced the encrypted-lnbits-adminKey model (v2) with a plaintext
// on-chain BTC payout address. Older files are loaded forward-compatibly —
// the legacy `lnbits` block is discarded on load.
const SCHEMA_VERSION = 3

export class SetupWizard extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.storagePath - JSON file path; usually `<storage>/wizard.json`
   * @param {object} [opts.defaults] - default values pre-filled in each step
   */
  constructor (opts = {}) {
    super()
    if (!opts.storagePath) throw new Error('SetupWizard requires storagePath')
    this.storagePath = opts.storagePath
    this.defaults = opts.defaults || {}
    this.state = {
      schemaVersion: SCHEMA_VERSION,
      step: 'welcome',
      relayName: this.defaults.relayName || generateDefaultName(),
      // Public on-chain BTC address (e.g. bc1…), or null if skipped.
      payoutDestination: this.defaults.payoutDestination || null,
      acceptMode: 'review',
      startedAt: null,
      completedAt: null
    }
  }

  /**
   * Load existing wizard state from disk. Silently no-ops if the file
   * doesn't exist (first run). Bad files are reset to defaults rather than
   * crashing relay startup. Loads forward-compatibly: only known fields are
   * adopted, and the legacy v2 `lnbits` block is intentionally dropped.
   */
  async load () {
    let raw
    try {
      raw = await readFile(this.storagePath, 'utf8')
    } catch (err) {
      if (err.code === 'ENOENT') return
      throw err
    }
    try {
      const parsed = JSON.parse(raw)
      if (!parsed || typeof parsed !== 'object') return
      // A file saved mid-wizard on the removed 'lnbits_connect' step maps
      // forward to the new 'payout' step.
      const step = parsed.step === 'lnbits_connect' ? 'payout' : parsed.step
      this.state = {
        ...this.state,
        schemaVersion: SCHEMA_VERSION,
        step: VALID_STEPS.includes(step) ? step : this.state.step,
        relayName: typeof parsed.relayName === 'string' ? parsed.relayName : this.state.relayName,
        payoutDestination: typeof parsed.payoutDestination === 'string' ? parsed.payoutDestination : null,
        acceptMode: VALID_ACCEPT_MODES.includes(parsed.acceptMode) ? parsed.acceptMode : this.state.acceptMode,
        startedAt: parsed.startedAt ?? this.state.startedAt,
        completedAt: parsed.completedAt ?? this.state.completedAt
      }
    } catch (err) {
      this.emit('load-error', { message: 'bad wizard.json, resetting', error: err })
    }
  }

  /**
   * Persist current state. Atomic — write to .tmp then rename — so a power
   * cut never leaves a half-written wizard file.
   */
  async save () {
    const dir = dirname(this.storagePath)
    try { await mkdir(dir, { recursive: true }) } catch (_) {}
    const tmp = join(dir, basename(this.storagePath) + '.tmp')
    await writeFile(tmp, JSON.stringify(this.state, null, 2), 'utf8')
    try { await chmod(tmp, 0o600) } catch (_) {}
    await rename(tmp, this.storagePath)
  }

  /**
   * Whether the wizard has been completed. The HTTP layer uses this to
   * decide whether to render the wizard or the main dashboard.
   */
  isComplete () {
    return this.state.step === 'complete'
  }

  /**
   * Snapshot of current state for the UI. The payout address is public, so
   * it's returned as-is (no redaction needed).
   */
  snapshot () {
    return {
      step: this.state.step,
      relayName: this.state.relayName,
      payoutDestination: this.state.payoutDestination,
      hasPayout: !!this.state.payoutDestination,
      acceptMode: this.state.acceptMode,
      startedAt: this.state.startedAt,
      completedAt: this.state.completedAt,
      isComplete: this.isComplete()
    }
  }

  /**
   * Advance to (or jump to) a step. Jumping back is allowed so operators
   * can revisit prior steps without losing state.
   */
  goToStep ({ step }) {
    if (!VALID_STEPS.includes(step)) {
      return { ok: false, reason: 'unknown step: ' + step }
    }
    if (this.state.startedAt === null) this.state.startedAt = Date.now()
    this.state.step = step
    this.emit('step-changed', { step })
    return { ok: true, state: this.snapshot() }
  }

  /**
   * Set the relay's display name (used in the dashboard, /api/info, and as
   * a hint to federation peers). Length-bounded to avoid UI-layout issues.
   */
  setRelayName ({ relayName }) {
    if (typeof relayName !== 'string') return { ok: false, reason: 'relayName must be a string' }
    const trimmed = relayName.trim()
    if (trimmed.length === 0) return { ok: false, reason: 'relayName cannot be empty' }
    if (trimmed.length > 60) return { ok: false, reason: 'relayName max 60 chars' }
    this.state.relayName = trimmed
    return { ok: true, state: this.snapshot() }
  }

  /**
   * Set the operator's on-chain BTC payout address. OPTIONAL — pass null or
   * an empty string to clear/skip. The relay never holds funds; this feeds
   * `subsidy.payoutDestination`, which a coordinator pays out signed work
   * claims to. Validates as an on-chain BTC address (bc1…, 1…, or 3…).
   */
  setPayoutDestination ({ address } = {}) {
    if (address === null || address === undefined || (typeof address === 'string' && address.trim() === '')) {
      this.state.payoutDestination = null
      return { ok: true, state: this.snapshot() }
    }
    if (typeof address !== 'string') {
      return { ok: false, reason: 'address must be a string' }
    }
    const parsed = validatePayoutDestination(address)
    if (!parsed || parsed.type !== 'onchain') {
      return { ok: false, reason: 'enter a valid on-chain BTC address (bc1…, 1…, or 3…)' }
    }
    this.state.payoutDestination = parsed.value
    return { ok: true, state: this.snapshot() }
  }

  /**
   * Set the accept-mode policy.
   */
  setAcceptMode ({ acceptMode }) {
    if (!VALID_ACCEPT_MODES.includes(acceptMode)) {
      return { ok: false, reason: 'acceptMode must be one of: ' + VALID_ACCEPT_MODES.join(', ') }
    }
    this.state.acceptMode = acceptMode
    return { ok: true, state: this.snapshot() }
  }

  /**
   * Mark the wizard complete. Caller should also call save() to persist.
   */
  complete () {
    this.state.step = 'complete'
    this.state.completedAt = Date.now()
    this.emit('completed', this.snapshot())
    return { ok: true, state: this.snapshot() }
  }

  /**
   * Returns the wizard's settings as a config object the relay node merges
   * into its live config (see RelayNode._applyWizardConfig). The payout
   * address is public, so no decryption is involved — this is synchronous.
   */
  toConfig () {
    return {
      name: this.state.relayName,
      acceptMode: this.state.acceptMode,
      subsidy: { payoutDestination: this.state.payoutDestination }
    }
  }

  /**
   * Reset the wizard. Mostly for debugging / reinstall scenarios.
   */
  reset () {
    this.state = {
      schemaVersion: SCHEMA_VERSION,
      step: 'welcome',
      relayName: generateDefaultName(),
      payoutDestination: null,
      acceptMode: 'review',
      startedAt: null,
      completedAt: null
    }
  }
}

/**
 * Picks a friendly default name, e.g. `silent-ember-4291`, that operators
 * can keep or change.
 */
function generateDefaultName () {
  const adjectives = ['silent', 'sturdy', 'glowing', 'patient', 'humble', 'eager', 'crisp', 'steady']
  const nouns = ['ember', 'beacon', 'anchor', 'lantern', 'spark', 'pillar', 'compass', 'haven']
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)]
  const noun = nouns[Math.floor(Math.random() * nouns.length)]
  const suffix = String(Math.floor(Math.random() * 9000) + 1000)
  return `${adj}-${noun}-${suffix}`
}

export { VALID_STEPS, VALID_ACCEPT_MODES, SCHEMA_VERSION as WIZARD_SCHEMA_VERSION }
