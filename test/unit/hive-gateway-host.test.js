import test from 'brittle'
import b4a from 'b4a'
import {
  decodeHiveAppKey,
  encodeHiveAppKey,
  normalizeHiveAppHostSuffix,
  resolveHiveAppHost
} from 'p2p-hiverelay/gateway/hive-host.js'

const KEY = b4a.alloc(32, 0xaa)
const KEY_HEX = b4a.toString(KEY, 'hex')
const KEY_LABEL = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
const SUFFIX = 'hive.relay.example'

test('Hive gateway host - z-base-32 key encoding is canonical', (t) => {
  t.is(encodeHiveAppKey(KEY), KEY_LABEL, 'known 32-byte vector encodes correctly')
  t.alike(decodeHiveAppKey(KEY_LABEL), KEY, 'known vector decodes correctly')
  t.is(encodeHiveAppKey(decodeHiveAppKey(KEY_LABEL)), KEY_LABEL, 'round trip stays canonical')

  t.is(decodeHiveAppKey(KEY_LABEL.slice(0, -1) + 'a'), null, 'non-zero trailing padding is rejected')
  t.is(decodeHiveAppKey('y'.repeat(51) + 'b'), null, 'same-key non-canonical padding alias is rejected')
  t.is(decodeHiveAppKey(KEY_LABEL.toUpperCase()), null, 'codec accepts canonical lowercase only')
  t.is(decodeHiveAppKey('y'.repeat(51)), null, 'wrong label length is rejected')
  t.exception(() => encodeHiveAppKey(b4a.alloc(31)), /must be 32 bytes/)
})

test('Hive gateway host - suffix validation is strict and normalized', (t) => {
  t.is(normalizeHiveAppHostSuffix(' HIVE.Relay.Example. '), SUFFIX)
  t.is(normalizeHiveAppHostSuffix('localhost'), null, 'single-label suffix rejected')
  t.is(normalizeHiveAppHostSuffix('-hive.relay.example'), null, 'leading hyphen rejected')
  t.is(normalizeHiveAppHostSuffix('hive..relay.example'), null, 'empty DNS label rejected')
  t.is(normalizeHiveAppHostSuffix('hivé.relay.example'), null, 'Unicode hostname rejected')
  t.is(normalizeHiveAppHostSuffix(`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(9)}`), null, 'suffix leaves room for app label')
})

test('Hive gateway host - canonical app origins resolve to one exact key', (t) => {
  const plain = resolveHiveAppHost(`${KEY_LABEL}.${SUFFIX}`, SUFFIX)
  t.alike(plain, {
    kind: 'app',
    appKey: KEY_HEX,
    label: KEY_LABEL,
    host: `${KEY_LABEL}.${SUFFIX}`
  })

  const withPort = resolveHiveAppHost(`${KEY_LABEL.toUpperCase()}.${SUFFIX.toUpperCase()}.:443`, SUFFIX)
  t.is(withPort.kind, 'app', 'DNS case and trailing dot normalize')
  t.is(withPort.appKey, KEY_HEX)

  t.is(resolveHiveAppHost('127.0.0.1:9200', SUFFIX).kind, 'none', 'IP compatibility host is not an app')
  t.is(resolveHiveAppHost('relay.example:9200', SUFFIX).kind, 'none', 'unrelated DNS host is not an app')
  t.is(resolveHiveAppHost('[::1]:9200', SUFFIX).kind, 'none', 'IPv6 compatibility host is not an app')
  t.is(resolveHiveAppHost('[::1]:99999', SUFFIX).kind, 'invalid', 'invalid IPv6 port rejected')
  t.is(resolveHiveAppHost('[::1]:0', SUFFIX).kind, 'invalid', 'zero IPv6 port rejected')
})

test('Hive gateway host - intended malformed app origins fail closed', (t) => {
  t.is(resolveHiveAppHost(SUFFIX, SUFFIX).kind, 'invalid', 'missing key label rejected')
  t.is(resolveHiveAppHost(`extra.${KEY_LABEL}.${SUFFIX}`, SUFFIX).kind, 'invalid', 'multiple prefix labels rejected')
  t.is(resolveHiveAppHost(`not-a-key.${SUFFIX}`, SUFFIX).kind, 'invalid', 'invalid key label rejected')
  t.is(resolveHiveAppHost(`${KEY_LABEL}.${SUFFIX}:99999`, SUFFIX).kind, 'invalid', 'invalid port rejected')
  t.is(resolveHiveAppHost(`${KEY_LABEL}.${SUFFIX}:0`, SUFFIX).kind, 'invalid', 'zero port rejected')
  t.is(resolveHiveAppHost(`${KEY_LABEL}.${SUFFIX},evil.example`, SUFFIX).kind, 'invalid', 'ambiguous Host rejected')
  t.is(resolveHiveAppHost(null, SUFFIX).kind, 'invalid', 'missing Host rejected when feature enabled')
  t.is(resolveHiveAppHost(`${KEY_LABEL}.${SUFFIX}`, null).kind, 'none', 'feature is inert without a suffix')
})
