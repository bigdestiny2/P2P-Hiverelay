import test from 'brittle'
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'

const tool = path.resolve('fleet/quarantine-public-gateway.sh')

function fixture (t) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'hr-gateway-quarantine-')))
  const active = path.join(root, 'hiverelay-public-apps.conf')
  const backup = path.join(root, 'hiverelay-public-apps.conf.pre-quarantine')
  const nginx = path.join(root, 'nginx')
  const log = path.join(root, 'nginx.log')
  const original = `server {
  listen 443 ssl default_server;
  ssl_certificate /etc/letsencrypt/live/hive/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/hive/privkey.pem;
  return 421;
}
server {
  listen 443 ssl;
  ssl_certificate /etc/letsencrypt/live/hive/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/hive/privkey.pem;
  proxy_pass http://127.0.0.1:9200;
}
`
  writeFileSync(active, original)
  writeFileSync(nginx, `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NGINX_LOG"
case "$*" in
  '-t') exit "${'$'}{FAKE_NGINX_TEST_STATUS:-0}" ;;
  '-s reload') exit "${'$'}{FAKE_NGINX_RELOAD_STATUS:-0}" ;;
esac
exit 2
`)
  chmodSync(nginx, 0o755)
  t.teardown(() => rmSync(root, { recursive: true, force: true }))
  return {
    root,
    active,
    backup,
    nginx,
    log,
    original,
    run: (env = {}, selectedTool = tool) => spawnSync('bash', [selectedTool, active, backup, nginx], {
      encoding: 'utf8',
      env: { ...process.env, FAKE_NGINX_LOG: log, ...env }
    })
  }
}

function injectedTool (t, f, needle, replacement) {
  const source = readFileSync(tool, 'utf8')
  t.is(source.split(needle).length, 2, 'fault injection point is unique')
  const injected = path.join(f.root, `quarantine-fault-${Math.random().toString(16).slice(2)}.sh`)
  writeFileSync(injected, source.replace(needle, () => replacement))
  chmodSync(injected, 0o755)
  return injected
}

test('gateway quarantine atomically replaces only app edge with TLS reject', (t) => {
  const f = fixture(t)
  const result = f.run()
  t.is(result.status, 0, result.stderr)
  t.is(readFileSync(f.backup, 'utf8'), f.original, 'exact prior edge is retained for recovery')
  const active = readFileSync(f.active, 'utf8')
  t.ok(active.startsWith('# hiverelay-public-gateway-quarantine-v1\n'))
  t.ok(active.includes('return 421;'))
  t.ok(active.includes('listen 443 ssl default_server;'))
  t.absent(active.includes('proxy_pass'), 'public app upstream is no longer reachable')
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s reload'])
  t.absent(readFileSync(tool, 'utf8').includes('systemctl'), 'management service is never stopped or restarted')

  const again = f.run()
  t.is(again.status, 0, again.stderr)
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s reload', '-t', '-s reload'],
    'idempotent containment revalidates and reloads the installed reject config')
})

test('gateway quarantine retains reject config and stops nginx when validation fails', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_NGINX_TEST_STATUS: '1' })
  t.not(result.status, 0)
  t.ok(readFileSync(f.active, 'utf8').startsWith('# hiverelay-public-gateway-quarantine-v1\n'))
  t.is(readFileSync(f.backup, 'utf8'), f.original)
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s stop'])
})

test('gateway quarantine retains reject config and stops nginx when reload fails', (t) => {
  const f = fixture(t)
  const result = f.run({ FAKE_NGINX_RELOAD_STATUS: '1' })
  t.not(result.status, 0)
  t.ok(readFileSync(f.active, 'utf8').startsWith('# hiverelay-public-gateway-quarantine-v1\n'))
  t.is(readFileSync(f.backup, 'utf8'), f.original)
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s reload', '-s stop'])
})

test('gateway quarantine resumes the crash-after-link phase', (t) => {
  const f = fixture(t)
  linkSync(f.active, f.backup)
  const result = f.run()
  t.is(result.status, 0, result.stderr)
  t.is(readFileSync(f.backup, 'utf8'), f.original)
  t.ok(readFileSync(f.active, 'utf8').startsWith('# hiverelay-public-gateway-quarantine-v1\n'))
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s reload'])
})

test('gateway quarantine resumes the crash-after-mv phase with live reload', (t) => {
  const f = fixture(t)
  linkSync(f.active, f.backup)
  const replacement = path.join(f.root, 'quarantine-replacement')
  writeFileSync(replacement, '# hiverelay-public-gateway-quarantine-v1\nserver { return 421; }\n')
  renameSync(replacement, f.active)
  const result = f.run()
  t.is(result.status, 0, result.stderr)
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-t', '-s reload'])
})

test('gateway quarantine stops nginx on a pre-link containment failure', (t) => {
  const f = fixture(t)
  linkSync(f.active, path.join(f.root, 'unexpected-active-hardlink'))
  const result = f.run()
  t.not(result.status, 0)
  t.ok(result.stderr.includes('nginx stop attempted'))
  t.absent(existsSync(f.backup))
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-s stop'])
})

test('gateway quarantine stops nginx when a resumed post-link phase cannot derive TLS identity', (t) => {
  const f = fixture(t)
  writeFileSync(f.active, 'server { listen 443 ssl; return 421; }\n')
  linkSync(f.active, f.backup)
  const result = f.run()
  t.not(result.status, 0)
  t.ok(result.stderr.includes('ssl_certificate'))
  t.ok(result.stderr.includes('nginx stop attempted'))
  t.ok(existsSync(f.backup), 'post-link evidence is preserved')
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-s stop'])
})

test('gateway quarantine rejects writable and lexical-symlink config ancestry before mutation', (t) => {
  const writable = fixture(t)
  chmodSync(writable.root, 0o777)
  const writableResult = writable.run()
  chmodSync(writable.root, 0o700)
  t.not(writableResult.status, 0)
  t.ok(writableResult.stderr.includes('config directory must be canonical, owner-trusted, and non-writable'))
  t.is(readFileSync(writable.active, 'utf8'), writable.original)
  t.absent(existsSync(writable.backup))
  t.absent(existsSync(writable.log), 'nginx is never armed from an unsafe config directory')

  const linked = fixture(t)
  const ancestor = path.join(linked.root, 'swap-capable-ancestor')
  symlinkSync(linked.root, ancestor)
  const result = spawnSync('bash', [
    tool,
    path.join(ancestor, path.basename(linked.active)),
    path.join(ancestor, path.basename(linked.backup)),
    path.join(ancestor, path.basename(linked.nginx))
  ], {
    encoding: 'utf8',
    env: { ...process.env, FAKE_NGINX_LOG: linked.log }
  })
  t.not(result.status, 0)
  t.ok(result.stderr.includes('canonical'))
  t.is(readFileSync(linked.active, 'utf8'), linked.original)
  t.absent(existsSync(linked.backup))
  t.absent(existsSync(linked.log), 'swap-capable ancestor cannot reach nginx execution')
})

for (const fault of [
  {
    name: 'mktemp',
    needle: 'TEMP_CONFIG="$(mktemp "$DIRECTORY/.hiverelay-public-gateway-quarantine.XXXXXX")" || \\\n  die \'could not create temporary quarantine config\'',
    replacement: 'TEMP_CONFIG=\'\'\nfalse || die \'could not create temporary quarantine config\''
  },
  {
    name: 'chmod',
    needle: 'chmod 0644 "$TEMP_CONFIG" || die \'could not set temporary quarantine config permissions\'',
    replacement: 'false || die \'could not set temporary quarantine config permissions\''
  },
  {
    name: 'marker write',
    needle: 'printf \'%s\\n\' "$MARKER" > "$TEMP_CONFIG" || die \'could not initialize temporary quarantine config\'',
    replacement: 'false || die \'could not initialize temporary quarantine config\''
  },
  {
    name: 'heredoc write',
    needle: 'cat >> "$TEMP_CONFIG" <<EOF || die \'could not write temporary quarantine config\'',
    replacement: 'false <<EOF || die \'could not write temporary quarantine config\''
  }
]) {
  test(`gateway quarantine stops nginx when ${fault.name} fails after arming`, (t) => {
    const f = fixture(t)
    const result = f.run({}, injectedTool(t, f, fault.needle, fault.replacement))
    t.not(result.status, 0)
    t.is(readFileSync(f.active, 'utf8'), f.original, 'active gateway remains unchanged')
    t.absent(existsSync(f.backup), 'no recovery link is created before the failed phase')
    t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-s stop'])
  })
}

test('gateway quarantine EXIT trap stops nginx on an otherwise unguarded failure', (t) => {
  const f = fixture(t)
  const needle = 'FAIL_CLOSED_READY=1\n'
  const selectedTool = injectedTool(t, f, needle, `${needle}false\n`)
  const result = f.run({}, selectedTool)
  t.not(result.status, 0)
  t.is(readFileSync(f.active, 'utf8'), f.original)
  t.absent(existsSync(f.backup))
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-s stop'],
    'the EXIT containment path attempts exactly one stop')
})

test('gateway quarantine signal trap terminates and stops nginx after arming', (t) => {
  const f = fixture(t)
  const needle = 'FAIL_CLOSED_READY=1\n'
  const selectedTool = injectedTool(t, f, needle, `${needle}kill -TERM "$$"\n`)
  const result = f.run({}, selectedTool)
  t.is(result.status, 143, result.stderr)
  t.ok(result.stderr.includes('received TERM'), result.stderr)
  t.is(readFileSync(f.active, 'utf8'), f.original, 'signal cannot resume into mutation')
  t.absent(existsSync(f.backup))
  t.alike(readFileSync(f.log, 'utf8').trim().split('\n'), ['-s stop'])
})
