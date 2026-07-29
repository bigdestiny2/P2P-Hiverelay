import test from 'brittle'
import { redactTorInfo, auditPayload, FORBIDDEN_PATTERNS } from 'p2p-hiverelay/transports/tor/redaction.js'
import { sanitizeTransportSummary } from 'p2p-hiverelay/core/relay-node/api-status-read.js'
import { buildCapabilityDoc } from 'p2p-hiverelay/core/capability-doc.js'
import { generateClientAuthKeypair, OnionRosterStore } from 'p2p-hiverelay/transports/tor/auth-keys.js'
import fs from 'fs'
import os from 'os'
import path from 'path'

const ONION = 'b'.repeat(56) + '.onion'

function fullTorInfo () {
  return {
    running: true,
    health: 'ready',
    daemonVersion: '0.4.9.6',
    socksProxy: '127.0.0.1:9050',
    onionAddress: ONION,
    vports: [80, 19737],
    authClients: 3,
    pow: true,
    persistent: true,
    descriptorUploads: 7,
    activeConnections: 2
  }
}

test('redactTorInfo — operator gets full payload', async (t) => {
  const out = redactTorInfo(fullTorInfo(), { operator: true })
  t.is(out.onionAddress, ONION)
  t.is(out.authClients, 3)
  t.is(out.descriptorUploads, 7)
})

test('redactTorInfo — public gets coarse health only', async (t) => {
  const out = redactTorInfo(fullTorInfo())
  t.alike(Object.keys(out).sort(), ['activeConnections', 'health', 'running'])
  t.is(out.health, 'ready')
  // and the public shape passes the forbidden-field audit
  const audit = auditPayload(out)
  t.ok(audit.ok, JSON.stringify(audit.violations))
})

test('redactTorInfo — null-safe', async (t) => {
  t.is(redactTorInfo(null), null)
  t.is(redactTorInfo(undefined), null)
})

test('auditPayload detects every forbidden class', async (t) => {
  const kp = generateClientAuthKeypair()
  const payload = {
    note: `peer ${ONION} connected`,
    rosterEntry: { pub: kp.publicKeyB32, name: 'alice' },
    key: 'ED25519-V3:' + Buffer.alloc(64, 7).toString('base64'),
    line: `alice:descriptor:x25519:${kp.publicKeyB32.toUpperCase()}`
  }
  const audit = auditPayload(payload)
  t.absent(audit.ok)
  const names = audit.violations.map((v) => v.name)
  t.ok(names.includes('onion-address'))
  t.ok(names.includes('client-auth-pubkey'))
  t.ok(names.includes('hs-key-blob'))
  t.ok(names.includes('auth-private-line'))
})

test('auditPayload whitelists only explicitly advertised onion addresses', async (t) => {
  const payload = { advertised: ONION, other: 'c'.repeat(56) + '.onion' }
  const audit = auditPayload(payload, { allowOnionAddresses: [ONION] })
  t.absent(audit.ok)
  t.is(audit.violations.length, 1)
  t.is(audit.violations[0].name, 'onion-address')
})

test('roster file contents always fail the audit (operator-private)', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tor-redaction-test-'))
  t.teardown(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch {} })
  const store = new OnionRosterStore(path.join(dir, 'roster.json'))
  store.add(generateClientAuthKeypair().publicKeyB32, { name: 'a' })
  await store.save()
  const audit = auditPayload(fs.readFileSync(store.file, 'utf8'))
  t.absent(audit.ok)
})

test('public status sanitizer stays inside the bounded legacy contract', async (t) => {
  const out = sanitizeTransportSummary({ tor: fullTorInfo() })
  // the public status contract is deliberately minimal: running + connections
  t.alike(out.tor, { running: true, activeConnections: 2 })
  const audit = auditPayload(out)
  t.ok(audit.ok, JSON.stringify(audit.violations))
})

test('capability doc with advertised onion passes audit when whitelisted', async (t) => {
  const relay = {
    config: { custody: { enabled: true }, tor: {} },
    serviceRegistry: { services: new Map() },
    torTransport: {
      running: true,
      health: 'ready',
      onionAddress: ONION,
      startedAtMs: 1784323200000,
      clientAuthKeys: [],
      rosterFile: null,
      pow: null
    }
  }
  const doc = buildCapabilityDoc({ relay })
  // without whitelisting, the advertised address is (correctly) flagged
  t.absent(auditPayload(doc).ok)
  // with the relay's own advertised endpoint whitelisted, the doc is clean
  const audit = auditPayload(doc, { allowOnionAddresses: [ONION] })
  t.ok(audit.ok, JSON.stringify(audit.violations))
})

test('pattern sanity: no false positives on hex pubkeys and ordinary text', async (t) => {
  const payload = {
    pubkey: 'ab'.repeat(32), // 64-char hex relay identity — must NOT match
    note: 'relay restarted after 3 attempts',
    version: '0.4.9.6'
  }
  const audit = auditPayload(payload)
  t.ok(audit.ok, JSON.stringify(audit.violations))
  t.ok(FORBIDDEN_PATTERNS.length >= 5)
})
