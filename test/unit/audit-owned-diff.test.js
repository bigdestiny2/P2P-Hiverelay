import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { buildOwnedDiffReport, parsePorcelainStatus } from '../../scripts/lib/audit-owned-diff.mjs'

function runAudit (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-audit-owned-diff.mjs', ...argv], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH || '' },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

async function tempFile (t, body) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-owned-diff-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const file = path.join(dir, 'status.txt')
  await writeFile(file, body)
  return file
}

test('audit-owned diff command is exposed as a package command', (t) => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
  t.is(pkg.scripts['audit:owned-diff'], 'node scripts/check-audit-owned-diff.mjs')
})

test('audit-owned diff parser normalizes porcelain paths and renames', (t) => {
  const parsed = parsePorcelainStatus(' M README.md\n?? "docs/space name.md"\nR  old.js -> scripts/check-audit-owned-diff.mjs\n')
  t.is(parsed.length, 3)
  t.is(parsed[0].path, 'README.md')
  t.is(parsed[1].path, 'docs/space name.md')
  t.is(parsed[2].path, 'scripts/check-audit-owned-diff.mjs')
})

test('audit-owned diff accepts known audit slice paths', async (t) => {
  const fixture = await tempFile(t, [
    ' M README.md',
    ' M packages/core/core/protocol/seed-request.js',
    ' M package.json',
    ' M packages/core/core/capability-doc.js',
    ' M packages/core/core/relay-node/bare-relay.js',
    ' M packages/core/gateway/hyper-gateway.js',
    ' M docs/SERVICES.md',
    ' M packages/client/README.md',
    ' M packages/client/package.json',
    ' M packages/services/README.md',
    ' M packages/services/index.js',
    '?? docs/PUSH-NOTIFICATION-SERVICE-SPEC.md',
    '?? packages/client/notify.js',
    '?? packages/core/core/relay-node/api-notify.js',
    '?? packages/services/builtin/notify-service.js',
    '?? packages/services/builtin/outboxlog/blind-seal.js',
    '?? packages/services/builtin/outboxlog/hypercore-journal.js',
    '?? packages/services/builtin/outboxlog/http-adapter.js',
    '?? packages/services/builtin/outboxlog/outbox-log.js',
    '?? scripts/check-audit-owned-diff.mjs',
    '?? scripts/bench-outboxlog.mjs',
    '?? test/unit/api-notify.test.js',
    '?? test/unit/capability-doc.test.js',
    '?? test/unit/client-notify.test.js',
    '?? test/unit/hyper-gateway-hardening.test.js',
    '?? test/unit/notify-service.test.js',
    '?? test/unit/outboxlog-blind-seal.test.js',
    '?? test/unit/outboxlog-bench.test.js',
    '?? test/unit/outboxlog-http-adapter.test.js',
    '?? test/unit/outboxlog-seeder-runtime.test.js',
    '?? test/unit/outboxlog.test.js',
    '?? test/unit/audit-owned-diff.test.js'
  ].join('\n') + '\n')
  const res = await runAudit(['--json', '--status-file', fixture])

  t.is(res.status, 0)
  t.is(res.stderr, '')

  const report = JSON.parse(res.stdout)
  t.is(report.kind, 'hiverelay-audit-owned-diff')
  t.is(report.status, 'pass')
  t.is(report.totals.changed, 32)
  t.is(report.totals.unknown, 0)
  t.ok(report.entries.find(entry => entry.path === 'README.md').owners.length > 1)
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/http-adapter.js')
    .owners.some(owner => owner.id === 'outboxlog-sync-event-sse'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/outbox-log.js')
    .owners.some(owner => owner.id === 'outboxlog-append-event-replay'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/outbox-log.js')
    .owners.some(owner => owner.id === 'outboxlog-operation-journal'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/hypercore-journal.js')
    .owners.some(owner => owner.id === 'outboxlog-hypercore-journal'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/hypercore-journal.js')
    .owners.some(owner => owner.id === 'outboxlog-partitioned-hypercore-journal'))
  t.ok(report.entries
    .find(entry => entry.path === 'scripts/bench-outboxlog.mjs')
    .owners.some(owner => owner.id === 'outboxlog-release-budget-gate'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-seeder-runtime.test.js')
    .owners.some(owner => owner.id === 'outboxlog-runtime-seeder-rehearsal'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/outbox-log.js')
    .owners.some(owner => owner.id === 'outboxlog-namespace-registration'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog.test.js')
    .owners.some(owner => owner.id === 'outboxlog-namespace-registration'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/README.md')
    .owners.some(owner => owner.id === 'outboxlog-namespace-registration'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/outbox-log.js')
    .owners.some(owner => owner.id === 'outboxlog-sealed-blind-namespace'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog.test.js')
    .owners.some(owner => owner.id === 'outboxlog-sealed-blind-namespace'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/README.md')
    .owners.some(owner => owner.id === 'outboxlog-sealed-blind-namespace'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/index.js')
    .owners.some(owner => owner.id === 'outboxlog-sealed-blind-namespace'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-seal-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-seal-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/index.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-seal-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-key-wrap'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-key-wrap'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/index.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-key-wrap'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-aad-binding-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-aad-binding-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/README.md')
    .owners.some(owner => owner.id === 'outboxlog-blind-aad-binding-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-directory-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-directory-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/index.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-directory-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-rotation-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-rotation-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/README.md')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-rotation-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/builtin/outboxlog/blind-seal.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-trust-root-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'test/unit/outboxlog-blind-seal.test.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-trust-root-helper'))
  t.ok(report.entries
    .find(entry => entry.path === 'packages/services/index.js')
    .owners.some(owner => owner.id === 'outboxlog-blind-recipient-trust-root-helper'))
})

test('audit-owned diff blocks unknown development paths', async (t) => {
  const fixture = await tempFile(t, '?? stray-release-note.txt\n')
  const res = await runAudit(['--json', '--status-file', fixture])

  t.is(res.status, 1)
  const report = JSON.parse(res.stdout)
  t.is(report.status, 'blocked')
  t.is(report.totals.unknown, 1)
  t.is(report.unknown[0].path, 'stray-release-note.txt')
})

test('audit-owned diff treats a clean status as pass', (t) => {
  const report = buildOwnedDiffReport('')
  t.is(report.status, 'pass')
  t.is(report.totals.changed, 0)
  t.is(report.totals.unknown, 0)
})
