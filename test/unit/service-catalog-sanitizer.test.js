import test from 'brittle'
import {
  MAX_SERVICE_CAPABILITIES,
  MAX_SERVICE_CATALOG_ENTRIES,
  MAX_SERVICE_DESCRIPTION_BYTES,
  sanitizeServiceCatalogEntries,
  sanitizeServiceCatalogEntry
} from 'p2p-hiverelay/core/services/service-catalog.js'
import { buildServiceCatalogPayload } from 'p2p-hiverelay/core/relay-node/api-service-read.js'

test('service catalog sanitizer shapes public entries', (t) => {
  const raw = {
    name: ' storage ',
    version: ' 1.0.0 ',
    description: 'Durable storage service',
    capabilities: ['get', 'put', 'get'],
    provider: { secret: true },
    stats: { requests: 10 },
    privateNote: 'do-not-leak'
  }

  const entry = sanitizeServiceCatalogEntry(raw)
  t.alike(entry, {
    name: 'storage',
    version: '1.0.0',
    capabilities: ['get', 'put'],
    description: 'Durable storage service'
  })
  t.absent(JSON.stringify(entry).includes('privateNote'))
  t.absent(JSON.stringify(entry).includes('do-not-leak'))
  t.absent(JSON.stringify(entry).includes('provider'))
  t.absent(JSON.stringify(entry).includes('stats'))
})

test('service catalog sanitizer rejects malformed identity fields', (t) => {
  t.is(sanitizeServiceCatalogEntry(null), null)
  t.is(sanitizeServiceCatalogEntry([]), null)
  t.is(sanitizeServiceCatalogEntry({ name: '', version: '1.0.0' }), null)
  t.is(sanitizeServiceCatalogEntry({ name: 'bad\nname', version: '1.0.0' }), null)
  t.is(sanitizeServiceCatalogEntry({ name: 'a'.repeat(65), version: '1.0.0' }), null)
  t.is(sanitizeServiceCatalogEntry({ name: 'ok', version: 'v'.repeat(65) }), null)
})

test('service catalog sanitizer caps description, capabilities, and entries', (t) => {
  const entry = sanitizeServiceCatalogEntry({
    name: 'ai',
    version: '2.0.0',
    description: 'x'.repeat(MAX_SERVICE_DESCRIPTION_BYTES + 32),
    capabilities: [
      ...Array.from({ length: MAX_SERVICE_CAPABILITIES + 10 }, (_, i) => 'cap-' + i),
      'bad\ncap',
      'y'.repeat(129)
    ]
  })

  t.is(Buffer.byteLength(entry.description, 'utf8'), MAX_SERVICE_DESCRIPTION_BYTES)
  t.is(entry.capabilities.length, MAX_SERVICE_CAPABILITIES)
  t.is(entry.capabilities[0], 'cap-0')
  t.is(entry.capabilities[MAX_SERVICE_CAPABILITIES - 1], 'cap-' + (MAX_SERVICE_CAPABILITIES - 1))

  const list = Array.from({ length: MAX_SERVICE_CATALOG_ENTRIES + 12 }, (_, i) => ({
    name: 'svc-' + i,
    version: '1.0.0'
  }))
  const sanitized = sanitizeServiceCatalogEntries(list)
  t.is(sanitized.length, MAX_SERVICE_CATALOG_ENTRIES)
  t.is(sanitized[0].name, 'svc-0')
  t.is(sanitized[MAX_SERVICE_CATALOG_ENTRIES - 1].name, 'svc-' + (MAX_SERVICE_CATALOG_ENTRIES - 1))
})

test('api service read helper returns bounded public payload', (t) => {
  const raw = [
    { name: 'identity', version: '1.0.0', capabilities: ['verify'], secretToken: 'nope' },
    { name: 'bad\nname', version: '1.0.0' }
  ]
  const result = buildServiceCatalogPayload({
    registry: {
      catalog: () => raw
    }
  })

  t.is(result.status, 200)
  t.is(result.payload.count, 1)
  t.is(result.payload.total, 2)
  t.is(result.payload.truncated, true)
  t.alike(result.payload.services, [{
    name: 'identity',
    version: '1.0.0',
    capabilities: ['verify'],
    description: ''
  }])
  t.alike(result.headers, { 'Cache-Control': 'public, max-age=10' })
  t.absent(JSON.stringify(result.payload).includes('secretToken'))
})

test('api service read helper handles disabled services', (t) => {
  t.alike(buildServiceCatalogPayload(), {
    status: 503,
    payload: { error: 'Services not enabled' }
  })
})
