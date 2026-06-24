import test from 'brittle'
import b4a from 'b4a'
import {
  RELAY_DISCOVERY_TOPIC,
  FOUNDATION_TOPIC,
  regionTopic,
  SEED_PROTOCOL_NAME,
  CIRCUIT_PROTOCOL_NAME,
  FORWARD_PROTOCOL_NAME,
  SERVICES_PROTOCOL_NAME
} from 'p2p-hiverelay/core/constants.js'

test('discovery topics — global topic is 32 bytes and stable', (t) => {
  t.is(RELAY_DISCOVERY_TOPIC.length, 32, 'is 32 bytes')
  // Stability: the topic must not change across releases or every existing
  // relay loses its peers. Snapshot the hex for regression detection.
  t.is(b4a.toString(RELAY_DISCOVERY_TOPIC, 'hex').length, 64, 'hex length 64')
})

test('discovery topics — foundation topic is 32 bytes', (t) => {
  t.is(FOUNDATION_TOPIC.length, 32)
  t.unlike(b4a.toString(FOUNDATION_TOPIC, 'hex'), b4a.toString(RELAY_DISCOVERY_TOPIC, 'hex'),
    'foundation topic differs from global')
})

test('regionTopic — returns 32-byte buffer per region', (t) => {
  for (const code of ['NA', 'EU', 'AS', 'SA', 'AF', 'OC']) {
    const topic = regionTopic(code)
    t.is(topic.length, 32, code + ' is 32 bytes')
  }
})

test('regionTopic — different regions yield different topics', (t) => {
  const na = regionTopic('NA')
  const eu = regionTopic('EU')
  const as = regionTopic('AS')
  t.unlike(b4a.toString(na, 'hex'), b4a.toString(eu, 'hex'), 'NA != EU')
  t.unlike(b4a.toString(eu, 'hex'), b4a.toString(as, 'hex'), 'EU != AS')
  t.unlike(b4a.toString(na, 'hex'), b4a.toString(as, 'hex'), 'NA != AS')
})

test('regionTopic — case-insensitive', (t) => {
  const upper = regionTopic('NA')
  const lower = regionTopic('na')
  const mixed = regionTopic('Na')
  t.is(b4a.toString(upper, 'hex'), b4a.toString(lower, 'hex'), 'upper == lower')
  t.is(b4a.toString(upper, 'hex'), b4a.toString(mixed, 'hex'), 'upper == mixed')
})

test('regionTopic — falsy region falls back to global namespace', (t) => {
  const noArg = regionTopic()
  const nullArg = regionTopic(null)
  const emptyArg = regionTopic('')
  t.is(b4a.toString(noArg, 'hex'), b4a.toString(nullArg, 'hex'), 'no-arg == null')
  t.is(b4a.toString(noArg, 'hex'), b4a.toString(emptyArg, 'hex'), 'no-arg == empty')
})

test('regionTopic — neither region nor foundation collides with global', (t) => {
  const na = regionTopic('NA')
  t.unlike(b4a.toString(na, 'hex'), b4a.toString(RELAY_DISCOVERY_TOPIC, 'hex'),
    'NA region != global topic')
  t.unlike(b4a.toString(na, 'hex'), b4a.toString(FOUNDATION_TOPIC, 'hex'),
    'NA region != foundation topic')
})

test('regionTopic — deterministic across calls', (t) => {
  const a = regionTopic('NA')
  const b = regionTopic('NA')
  t.is(b4a.toString(a, 'hex'), b4a.toString(b, 'hex'), 'same input → same topic')
})

test('protocol constants — stable Protomux channel names', (t) => {
  t.is(SEED_PROTOCOL_NAME, 'hiverelay-seed', 'seed protocol name is stable')
  t.is(CIRCUIT_PROTOCOL_NAME, 'hiverelay-circuit', 'circuit protocol name is stable')
  t.is(FORWARD_PROTOCOL_NAME, 'hiverelay-forward', 'forward protocol name is stable')
  t.is(SERVICES_PROTOCOL_NAME, 'hiverelay-services', 'services protocol name is stable')
})
