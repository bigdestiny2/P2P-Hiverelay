import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SCHEMA_NAMES, SCHEMAS, validateRow } from '../lib/schemas.js'

test('SCHEMA_NAMES matches SCHEMAS keys', () => {
  assert.deepEqual([...SCHEMA_NAMES].sort(), Object.keys(SCHEMAS).sort())
})

test('pin-registry requires a 64-hex appKey', () => {
  assert.equal(validateRow('pin-registry', { appKey: 'a'.repeat(64) }).valid, true)
  assert.equal(validateRow('pin-registry', { appKey: 'nope' }).valid, false)
  assert.equal(validateRow('pin-registry', {}).valid, false)
})

test('pin-registry rejects an unknown seedState', () => {
  assert.equal(validateRow('pin-registry', { appKey: 'a'.repeat(64), seedState: 'frozen' }).valid, false)
  assert.equal(validateRow('pin-registry', { appKey: 'a'.repeat(64), seedState: 'anchored' }).valid, true)
})

test('relay-directory is closed (additionalProperties:false) + needs pubkey+gateway', () => {
  const ok = { pubkey: 'b'.repeat(64), gatewayUrl: 'https://x' }
  assert.equal(validateRow('relay-directory', ok).valid, true)
  assert.equal(validateRow('relay-directory', { ...ok, surprise: 1 }).valid, false, 'closed schema rejects extras')
  assert.equal(validateRow('relay-directory', { pubkey: 'b'.repeat(64) }).valid, false)
})

test('app-manifest needs appId+name and at least one of driveKey|link', () => {
  assert.equal(validateRow('app-manifest', { appId: 'x', name: 'X', driveKey: 'a'.repeat(64) }).valid, true)
  assert.equal(validateRow('app-manifest', { appId: 'x', name: 'X', link: 'hyper://y' }).valid, true)
  assert.equal(validateRow('app-manifest', { appId: 'x', name: 'X' }).valid, false, 'needs driveKey or link')
  assert.equal(validateRow('app-manifest', { appId: 'x', name: 'X', type: 'weird', link: 'z' }).valid, false)
})

test('verification is closed + enum-checked', () => {
  const ok = { subjectAppKey: 'a'.repeat(64), verifierPubkey: 'b'.repeat(64), verdict: 'agree' }
  assert.equal(validateRow('verification', ok).valid, true)
  assert.equal(validateRow('verification', { ...ok, verdict: 'maybe' }).valid, false)
  assert.equal(validateRow('verification', { ...ok, method: 'guessing' }).valid, false)
})

test('unknown schema name yields a clear error', () => {
  const r = validateRow('nope', {})
  assert.equal(r.valid, false)
  assert.match(r.errors[0], /unknown schema/)
})
