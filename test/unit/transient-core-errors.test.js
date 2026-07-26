// Unit tests for the transient-core-error classifier.
//
// The classifier decides which thrown errors warrant a retryable HTTP 503
// response (vs the existing opaque 400) on store-touching endpoints. The
// markers it detects are message-string fragments + error.code values
// emitted by corestore / hypercore when the underlying store or core is
// in a closing/closed lifecycle state — situations the client should
// retry against the same relay, not give up on.

import test from 'brittle'
import { isTransientCoreError, TRANSIENT_RETRY_AFTER_SECONDS } from 'p2p-hiverelay/core/transient-core-errors.js'

test('isTransientCoreError: detects "The corestore is closed"', (t) => {
  t.ok(isTransientCoreError(new Error('The corestore is closed')))
  t.ok(isTransientCoreError(new Error('uncaught: The corestore is closed (at append)')))
  t.ok(isTransientCoreError('The corestore is closed')) // string-shaped also works
})

test('isTransientCoreError: detects "Cannot make sessions on a closing core"', (t) => {
  t.ok(isTransientCoreError(new Error('Cannot make sessions on a closing core')))
  t.ok(isTransientCoreError(new Error('SESSION_CLOSED: Cannot make sessions on a closing core')))
})

test('isTransientCoreError: detects SESSION_CLOSED prefix without trailing text', (t) => {
  t.ok(isTransientCoreError(new Error('SESSION_CLOSED')))
  t.ok(isTransientCoreError(new Error('SESSION_CLOSED — at storage layer')))
})

test('isTransientCoreError: detects CORE_CLOSED prefix', (t) => {
  t.ok(isTransientCoreError(new Error('CORE_CLOSED: core 1 was closed during append')))
  t.ok(isTransientCoreError(new Error('CORE_CLOSED')))
})

test('isTransientCoreError: matches on err.code as well as err.message', (t) => {
  // Some hypercore versions surface a code string instead of (or in
  // addition to) the message. Accept either.
  const errWithCode = Object.assign(new Error('something else'), { code: 'SESSION_CLOSED' })
  t.ok(isTransientCoreError(errWithCode))

  const errWithCodePrefix = Object.assign(new Error('whatever'), { code: 'CORE_CLOSED_OPERATION_ABORTED' })
  t.ok(isTransientCoreError(errWithCodePrefix))
})

test('isTransientCoreError: returns false for malformed-request errors', (t) => {
  t.absent(isTransientCoreError(new Error('appKey must be 64 hex characters')))
  t.absent(isTransientCoreError(new Error('INVALID_SIGNATURE: publisher signature does not match')))
  t.absent(isTransientCoreError(new Error('Storage capacity exceeded')))
  t.absent(isTransientCoreError(new Error('POLICY_VIOLATION: replicate-encrypted-data blocked')))
})

test('isTransientCoreError: returns false for null/undefined/empty', (t) => {
  t.absent(isTransientCoreError(null))
  t.absent(isTransientCoreError(undefined))
  t.absent(isTransientCoreError(''))
  t.absent(isTransientCoreError(new Error('')))
  t.absent(isTransientCoreError({}))
})

test('isTransientCoreError: returns false for arbitrary objects without message or code', (t) => {
  t.absent(isTransientCoreError({ foo: 'bar' }))
  t.absent(isTransientCoreError({ message: 42 })) // non-string message
})

test('TRANSIENT_RETRY_AFTER_SECONDS is a positive integer', (t) => {
  t.ok(Number.isInteger(TRANSIENT_RETRY_AFTER_SECONDS))
  t.ok(TRANSIENT_RETRY_AFTER_SECONDS > 0)
})
