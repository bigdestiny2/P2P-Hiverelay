import test from 'brittle'
import {
  validateIntent,
  resolvePath,
  candidatesFromCapabilityDoc,
  DEFAULT_INTENT,
  PATH_DIRECT,
  PATH_FORWARD_RELAY,
  PATH_TOR_ONION,
  PATH_NYM_MIXNET
} from 'p2p-hiverelay-client/privacy-policy.js'

const directPath = { id: PATH_DIRECT, available: true, transportPrivacy: 'direct', relayLocation: 'exposed', coverTraffic: false, coverage: 'full' }
const forwardPath = { id: PATH_FORWARD_RELAY, available: true, transportPrivacy: 'source-ip-hidden', relayLocation: 'hidden-1hop', coverTraffic: false, coverage: 'full' }
const onionPath = { id: PATH_TOR_ONION, available: true, transportPrivacy: 'source-ip-hidden', relayLocation: 'hidden-onion', coverTraffic: false, coverage: 'full' }
const nymPath = { id: PATH_NYM_MIXNET, available: true, transportPrivacy: 'traffic-analysis-resistant', relayLocation: 'hidden-mixnet', coverTraffic: true, coverage: 'control-only' }
const ALL = [directPath, forwardPath, onionPath, nymPath]

test('validateIntent rejects unknown axis values', async (t) => {
  t.exception(() => validateIntent({ transportPrivacy: 'invisible' }), /invalid transportPrivacy/)
  t.exception(() => validateIntent({ relayLocation: 'hidden-2hop' }), /invalid relayLocation/)
  t.exception(() => validateIntent({ downgradePolicy: 'sure' }), /invalid downgradePolicy/)
  t.is(validateIntent({}), true)
})

test('default intent resolves to direct path', async (t) => {
  const r = resolvePath({}, ALL)
  t.is(r.selectedTransport, PATH_DIRECT)
  t.is(r.downgraded, false)
  t.ok(r.satisfied.length > 0)
  t.alike(r.unsatisfied, [])
})

test('stronger path satisfies weaker requirement (hidden-onion covers source-ip-hidden)', async (t) => {
  const r = resolvePath({ transportPrivacy: 'source-ip-hidden', relayLocation: 'hidden-onion', downgradePolicy: 'deny' }, ALL)
  t.is(r.selectedTransport, PATH_TOR_ONION)
  t.is(r.downgraded, false)
})

test('traffic-analysis-resistant requires cover traffic and mixnet location', async (t) => {
  const r = resolvePath({ transportPrivacy: 'traffic-analysis-resistant', relayLocation: 'hidden-mixnet', metadataShaping: 'cover-and-mix', pathCoverage: 'control-only' }, ALL)
  t.is(r.selectedTransport, PATH_NYM_MIXNET)
  t.is(r.coverage, 'control-only') // nym lane never claims full bulk coverage
})

test('fail-closed: required mixnet with no nym candidate and deny', async (t) => {
  const r = resolvePath({ transportPrivacy: 'traffic-analysis-resistant', downgradePolicy: 'deny' }, [directPath, onionPath])
  t.is(r.selectedTransport, null)
  t.is(r.downgraded, false)
  t.ok(r.unsatisfied.includes('no-satisfying-path'))
})

test('fail-closed: unavailable candidate is not selected silently', async (t) => {
  const r = resolvePath({ relayLocation: 'hidden-onion', downgradePolicy: 'deny' }, [directPath, { ...onionPath, available: false }])
  t.is(r.selectedTransport, null)
  t.ok(r.unsatisfied.includes('no-satisfying-path'))
})

test('explicit ordered fallback: used in order, recorded as downgrade', async (t) => {
  const r = resolvePath(
    { relayLocation: 'hidden-onion', downgradePolicy: [PATH_FORWARD_RELAY, PATH_DIRECT] },
    [directPath, forwardPath] // no onion available
  )
  t.is(r.selectedTransport, PATH_FORWARD_RELAY)
  t.is(r.downgraded, true)
  t.ok(r.unsatisfied.includes('relayLocation:hidden-onion'))
})

test('fallback never silently picks an undeclared path', async (t) => {
  const r = resolvePath(
    { relayLocation: 'hidden-onion', downgradePolicy: [PATH_DIRECT] },
    [directPath, forwardPath]
  )
  t.is(r.selectedTransport, PATH_DIRECT)
  t.is(r.downgraded, true)
})

test('declared-but-unavailable fallback fails closed with reason', async (t) => {
  const r = resolvePath(
    { relayLocation: 'hidden-mixnet', downgradePolicy: [PATH_NYM_MIXNET] },
    [directPath]
  )
  t.is(r.selectedTransport, null)
  t.ok(r.unsatisfied.includes('no-available-fallback'))
})

test('candidatesFromCapabilityDoc maps relay advertisement to candidates', async (t) => {
  const doc = {
    supported_transports: ['hyperswarm', 'tor'],
    gatewayUrl: 'https://relay.example',
    privacyTransports: [
      { id: PATH_TOR_ONION, auth: { mode: 'client-auth-v3' }, vports: [80, 19737] },
      { id: PATH_NYM_MIXNET, replyModes: ['surb'] }
    ]
  }
  const c = candidatesFromCapabilityDoc(doc, { direct: true, tor: true, nym: false })
  const ids = c.map((x) => x.id)
  t.ok(ids.includes(PATH_DIRECT))
  t.ok(ids.includes(PATH_TOR_ONION))
  t.ok(ids.includes(PATH_NYM_MIXNET))
  const nym = c.find((x) => x.id === PATH_NYM_MIXNET)
  t.is(nym.available, false) // local nym not running → not selectable
  const onion = c.find((x) => x.id === PATH_TOR_ONION)
  t.is(onion.relayLocation, 'hidden-onion')
  t.alike(onion.vports, [80, 19737])
})

test('candidatesFromCapabilityDoc tolerates junk input', async (t) => {
  t.alike(candidatesFromCapabilityDoc(null), [])
  t.alike(candidatesFromCapabilityDoc({}), [])
})

test('full-journey composition: nym control + onion bulk evaluate independently', async (t) => {
  // control op: nym lane satisfies
  const control = resolvePath({ transportPrivacy: 'traffic-analysis-resistant', pathCoverage: 'control-only', downgradePolicy: 'deny' }, ALL)
  t.is(control.selectedTransport, PATH_NYM_MIXNET)
  // bulk op: same intent with full coverage required — nym lane cannot claim it
  const bulk = resolvePath({ transportPrivacy: 'traffic-analysis-resistant', pathCoverage: 'full', downgradePolicy: 'deny' }, ALL)
  t.is(bulk.selectedTransport, null) // fails closed rather than mislabeling
})

test('DEFAULT_INTENT is a valid, resolvable intent', async (t) => {
  t.is(validateIntent(DEFAULT_INTENT), true)
  const r = resolvePath(DEFAULT_INTENT, ALL)
  t.ok(r.selectedTransport)
})
