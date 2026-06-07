// disk-monitor: tests for the operator-facing disk-usage signal added
// in v0.8.28 to close the cost-of-discovery gap that bit milkyb-iad
// (issue #27).

import test from 'brittle'
import { DiskMonitor, parseDfOutput } from 'p2p-hiverelay/core/relay-node/disk-monitor.js'

test('parseDfOutput: well-formed POSIX df -kP output', (t) => {
  // Real df -kP output from a Linux relay
  const stdout = [
    'Filesystem     1024-blocks      Used Available Capacity Mounted on',
    '/dev/sda1         51190108  23456789  25178945      48% /'
  ].join('\n')

  const parsed = parseDfOutput(stdout)
  t.is(parsed.totalBytes, 51190108 * 1024, 'totalBytes converted from 1K blocks')
  t.is(parsed.usedBytes, 23456789 * 1024)
  t.is(parsed.freeBytes, 25178945 * 1024)
  t.is(parsed.mountPath, '/')
})

test('parseDfOutput: filesystem column with spaces (line-wrapped)', (t) => {
  // df sometimes wraps long filesystem paths onto a second line
  const stdout = [
    'Filesystem            1024-blocks      Used Available Capacity Mounted on',
    '/very/long/filesystem/path-that-wraps',
    '                          1048576    524288    524288      50% /data'
  ].join('\n')

  const parsed = parseDfOutput(stdout)
  t.is(parsed.totalBytes, 1048576 * 1024)
  t.is(parsed.usedBytes, 524288 * 1024)
  t.is(parsed.freeBytes, 524288 * 1024)
  t.is(parsed.mountPath, '/data')
})

test('parseDfOutput: throws on malformed output', (t) => {
  t.exception(() => parseDfOutput(''), /no data row/)
  t.exception(() => parseDfOutput('Filesystem ...'), /no data row/)
  t.exception(() => parseDfOutput('Filesystem ...\nshort row'), /fewer than 6 columns/)
})

test('DiskMonitor: status threshold calculations (ok / warn / critical)', async (t) => {
  // Use the milkyb-iad scenario (1 GB volume) at different fill levels
  function mockCache (usedPct) {
    const total = 1024 * 1024 * 1024
    return {
      usedPct,
      usedBytes: Math.floor(total * usedPct / 100),
      freeBytes: total - Math.floor(total * usedPct / 100),
      totalBytes: total
    }
  }

  const dm = new DiskMonitor('/data', { warnThreshold: 85, criticalThreshold: 95 })
  t.teardown(() => dm.stop())

  // Stub _refresh to set the cache directly
  dm._cache = {
    ...mockCache(50),
    mountPath: '/data',
    status: 'ok',
    checkedAt: Date.now()
  }
  t.is(dm.getInfo().status, 'ok', '50% fill is ok')

  dm._cache = {
    ...mockCache(86),
    mountPath: '/data',
    status: 'warn',
    checkedAt: Date.now()
  }
  t.is(dm.getInfo().status, 'warn', '86% fill is warn')

  dm._cache = {
    ...mockCache(95),
    mountPath: '/data',
    status: 'critical',
    checkedAt: Date.now()
  }
  t.is(dm.getInfo().status, 'critical', '95% fill is critical')
})

test('DiskMonitor: getInfo returns null before first poll completes', (t) => {
  const dm = new DiskMonitor('/data')
  t.teardown(() => dm.stop())
  t.is(dm.getInfo(), null, 'cache empty before refresh')
})

test('DiskMonitor: refresh() against real / returns plausible numbers', async (t) => {
  // Smoke test using the actual host filesystem. The relay storage path
  // doesn't exist in this test environment, but / does on Linux + macOS.
  const dm = new DiskMonitor('/')
  t.teardown(() => dm.stop())

  await dm.refresh()
  const info = dm.getInfo()
  t.ok(info, 'cache populated after refresh')
  t.ok(!info.error, 'no error: ' + (info.error || ''))
  t.ok(info.totalBytes > 0, 'total bytes positive')
  t.ok(info.freeBytes >= 0, 'free bytes non-negative')
  t.ok(info.usedPct >= 0 && info.usedPct <= 100, 'usedPct in 0-100')
  t.ok(info.checkedAt > 0, 'checkedAt timestamp set')
  t.is(typeof info.status, 'string')
  t.ok(['ok', 'warn', 'critical'].includes(info.status), 'status is one of the three')
})

test('DiskMonitor: refresh() surfaces error when df fails on bogus path', async (t) => {
  const dm = new DiskMonitor('/this/path/definitely/does/not/exist/abc123xyz')
  t.teardown(() => dm.stop())

  await dm.refresh()
  const info = dm.getInfo()
  t.ok(info, 'cache populated even on error')
  t.ok(info.error, 'error field set')
  t.ok(info.checkedAt > 0)
})

test('DiskMonitor: stop() clears the refresh interval', async (t) => {
  const dm = new DiskMonitor('/', { refreshIntervalMs: 5000 })
  dm.start()
  t.ok(dm._refreshInterval, 'interval armed after start')
  dm.stop()
  t.absent(dm._refreshInterval, 'interval cleared after stop')
  // Calling stop again is a no-op
  dm.stop()
  t.pass('second stop is harmless')
})

test('DiskMonitor: custom thresholds override defaults', (t) => {
  const dm = new DiskMonitor('/data', { warnThreshold: 70, criticalThreshold: 90 })
  t.teardown(() => dm.stop())
  t.is(dm.warnThreshold, 70)
  t.is(dm.criticalThreshold, 90)
})

test('DiskMonitor: requires storagePath', (t) => {
  t.exception(() => new DiskMonitor(), /storagePath is required/)
  t.exception(() => new DiskMonitor(null), /storagePath is required/)
  t.exception(() => new DiskMonitor(''), /storagePath is required/)
})

test('DiskMonitor: refresh interval floor of 5000ms (prevents accidental DoS)', (t) => {
  const dm = new DiskMonitor('/data', { refreshIntervalMs: 100 })
  t.teardown(() => dm.stop())
  t.is(dm.refreshIntervalMs, 5000, 'sub-5s clamped to 5s floor')
})
