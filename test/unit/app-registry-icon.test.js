/**
 * v0.17.0: optional display `icon` on catalog entries (for PearBrowser /
 * catalogue app tiles). Pins: icon surfaces in catalog() for non-blind
 * entries, normalizes correctly (string|null, length-capped), survives a
 * persistence round-trip, and is STRIPPED for blind/redacted drives — a
 * drive-relative icon path would leak the addressKey.
 */

import test from 'brittle'
import { mkdtemp, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { AppRegistry } from 'p2p-hiverelay/core/app-registry.js'

test('catalog() surfaces icon for a non-blind entry', (t) => {
  const registry = new AppRegistry(null)
  const appKey = 'a'.repeat(64)
  registry.set(appKey, { type: 'app', appId: 'icon-app', name: 'Icon App', icon: '/assets/icon.png' })
  const entry = registry.catalog()[0]
  t.is(entry.icon, '/assets/icon.png', 'icon surfaced in catalog')
})

test('icon defaults to null when unset, and normalizes junk to null', (t) => {
  const registry = new AppRegistry(null)
  registry.set('b'.repeat(64), { type: 'app', appId: 'no-icon', name: 'No Icon' })
  t.is(registry.catalog()[0].icon, null, 'absent icon is null')

  registry.set('c'.repeat(64), { type: 'app', appId: 'bad-icon', name: 'Bad', icon: 12345 })
  t.is(registry.catalog().find(e => e.id === 'bad-icon').icon, null, 'non-string icon normalized to null')

  registry.set('d'.repeat(64), { type: 'app', appId: 'blank-icon', name: 'Blank', icon: '   ' })
  t.is(registry.catalog().find(e => e.id === 'blank-icon').icon, null, 'whitespace-only icon normalized to null')
})

test('icon is length-capped (512 chars) and trimmed', (t) => {
  const registry = new AppRegistry(null)
  registry.set('e'.repeat(64), { type: 'app', appId: 'long-icon', name: 'Long', icon: '  ' + 'x'.repeat(900) + '  ' })
  const icon = registry.catalog()[0].icon
  t.is(icon.length, 512, 'capped to 512')
  t.absent(icon.startsWith(' '), 'leading whitespace trimmed')
})

test('icon is STRIPPED for blind/redacted entries (no addressKey leak)', (t) => {
  const registry = new AppRegistry(null)
  const appKey = 'f'.repeat(64)
  registry.set(appKey, {
    type: 'app',
    appId: 'blind-app',
    name: 'Secret',
    icon: '/icon.png', // a drive-relative path would expose the addressKey
    blind: true,
    blindContentId: '9'.repeat(64)
  })
  const entry = registry.catalog({ redactPrivate: true })[0]
  t.is(entry.redacted, true, 'blind entry is redacted')
  t.is(entry.icon, null, 'icon stripped for blind drive')
})

test('icon survives a persistence round-trip (reload from disk)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'icon-reg-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const appKey = '1'.repeat(64)

  const reg1 = new AppRegistry(dir)
  await reg1.load().catch(() => {})
  reg1.set(appKey, { type: 'app', appId: 'persist-icon', name: 'Persist', icon: 'https://example.com/i.png' })
  if (typeof reg1.flush === 'function') await reg1.flush()
  if (typeof reg1.close === 'function') await reg1.close()

  const reg2 = new AppRegistry(dir)
  await reg2.load().catch(() => {})
  const got = reg2.get(appKey)
  t.ok(got, 'entry reloaded')
  t.is(got.icon, 'https://example.com/i.png', 'icon preserved across reload')
})
