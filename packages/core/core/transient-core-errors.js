/**
 * Detect transient Hypercore / Corestore errors that warrant a retryable
 * 503 response instead of an opaque 400.
 *
 * Background: when a relay's corestore is closed or one of its cores is
 * mid-close (e.g. self-heal cycle, store recreation after error, session
 * leak), HTTP routes that call into seedApp / publishCustodyIntent surface
 * the underlying error verbatim. Consumers can't distinguish "your request
 * was malformed" from "the relay's storage subsystem is in a closing
 * transition state" — both bubble up as opaque 400s.
 *
 * Detection here is by message-string match because corestore + hypercore
 * don't throw typed errors. The strings cover:
 *
 *   - "The corestore is closed" — corestore.close() has been called;
 *     all subsequent .get() / .append() throw this.
 *   - "SESSION_CLOSED: Cannot make sessions on a closing core" — a
 *     specific core is mid-close; session-creation attempts are rejected
 *     while it transitions.
 *   - "Cannot make sessions on a closing core" — same condition,
 *     without the SESSION_CLOSED prefix (older hypercore versions).
 *   - "CORE_CLOSED" / "SESSION_CLOSED" prefixes — typed-ish error codes
 *     from newer hypercore releases.
 *
 * If you add new detection patterns, please also add a unit case in
 * test/unit/transient-core-errors.test.js.
 */

const TRANSIENT_MARKERS = [
  'The corestore is closed',
  'Cannot make sessions on a closing core',
  'SESSION_CLOSED',
  'CORE_CLOSED'
]

/**
 * Returns true if the error appears to be a transient corestore/hypercore
 * lifecycle issue that the client should retry against the same relay.
 *
 * @param {Error|string|null|undefined} err
 * @returns {boolean}
 */
export function isTransientCoreError (err) {
  if (!err) return false
  const msg = typeof err === 'string'
    ? err
    : (err && typeof err.message === 'string' ? err.message : '')
  if (!msg) return false
  for (const marker of TRANSIENT_MARKERS) {
    if (msg.includes(marker)) return true
  }
  // Some hypercore error-code constants come through as err.code instead
  // of err.message — accept both surfaces.
  if (err && typeof err.code === 'string') {
    for (const marker of TRANSIENT_MARKERS) {
      if (err.code === marker || err.code.startsWith(marker)) return true
    }
  }
  return false
}

/**
 * Suggested Retry-After header value (seconds) for a transient core
 * error. 5 seconds gives self-heal restarts (or in-flight session close
 * transitions) time to complete before the client tries again.
 */
export const TRANSIENT_RETRY_AFTER_SECONDS = 5
