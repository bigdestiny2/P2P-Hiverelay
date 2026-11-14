import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'

function fixture (t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'hiverelay-fleet-status-'))
  t.teardown(() => rmSync(dir, { recursive: true, force: true }))
  const bin = path.join(dir, 'bin')
  const home = path.join(dir, 'home')
  mkdirSync(bin)
  mkdirSync(path.join(home, 'hiverelay'), { recursive: true })
  mkdirSync(path.join(home, 'service'), { recursive: true })
  const script = path.join(dir, 'fleet-status.sh')
  copyFileSync('fleet/fleet-status.sh', script)
  writeFileSync(path.join(dir, 'channels.json'), '{"stable":"v0.27.0-rc.1","canary":"v0.27.0-rc.2"}')
  writeFileSync(path.join(home, 'hiverelay/package.json'), '{"version":"0.25.0-rc.9+build.7"}')
  writeFileSync(path.join(home, 'service/package.json'), '{"version":"0.26.0-rc.2"}')
  const log = path.join(dir, 'calls.jsonl')
  const replies = path.join(dir, 'replies.json')
  writeFileSync(replies, '{}')
  function stub (name, source) {
    const target = path.join(bin, name)
    writeFileSync(target, `#!${process.execPath}\n${source}`)
    chmodSync(target, 0o755)
  }
  const prelude = 'const fs = require(\'node:fs\'); const args = process.argv.slice(2);\n'
  stub('ssh', prelude + `
const input = fs.readFileSync(0, 'utf8')
fs.appendFileSync(process.env.FLEET_TEST_LOG, JSON.stringify({ command: 'ssh', args }) + '\\n')
const host = args.find(a => a.startsWith('root@')).slice(5)
const replies = JSON.parse(fs.readFileSync(process.env.FLEET_TEST_REPLIES))
if (host === 'execute.test') {
  const child = require('node:child_process').spawnSync('bash', ['-s'], { input, env: process.env, encoding: 'utf8' })
  process.stdout.write(child.stdout || '')
  process.stderr.write(child.stderr || '')
  process.exit(child.status ?? 1)
}
const reply = replies[host] || { stdout: 'v0.25.0-rc.9|RUNNING 3 4|76%|HEALTH\\n' }
process.stdout.write(reply.stdout || '')
process.stderr.write(reply.stderr || '')
process.exit(reply.code || 0)
`)
  stub('curl', prelude + `
const remote = args.includes('http://127.0.0.1:9100/health')
const headerArg = args[args.indexOf('-H') + 1]
const header = remote && args.includes('-H') ? headerArg.slice(1) : null
fs.appendFileSync(process.env.FLEET_TEST_LOG, JSON.stringify({ command: 'curl', args,
  header, headerMode: header ? fs.statSync(header).mode & 0o777 : null,
  authorized: header ? fs.readFileSync(header, 'utf8') === 'Authorization: Bearer ' + process.env.FLEET_TEST_KEY + '\\n' : false }) + '\\n')
if (!remote) { process.stdout.write('{"stable":"v0.27.0-rc.1","canary":"v0.27.0-rc.2"}'); process.exit(0) }
process.stdout.write(process.env.FLEET_TEST_HEALTH || '{"running":true,"version":"0.25.0-rc.9+build.7","seededApps":12,"connections":34}')
process.exit(Number(process.env.FLEET_TEST_CURL_EXIT || 0))
`)
  stub('systemctl', `
if (process.argv.includes('--property=WorkingDirectory')) process.stdout.write((process.env.FLEET_TEST_WORKING_DIRECTORY ?? process.env.HOME + '/service') + '\\n')
else process.stdout.write('Environment=OTHER=fixture HIVERELAY_API_KEY=' + process.env.FLEET_TEST_KEY + '\\n')
`)
  stub('df', "process.stdout.write('Filesystem Size Used Avail Use% Mounted on\\nfixture 1G 1G 0G 91% /\\n')")
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    HOME: home,
    FLEET_TEST_LOG: log,
    FLEET_TEST_REPLIES: replies,
    FLEET_TEST_KEY: 'fixture-secret-do-not-display'
  }
  return {
    dir,
    home,
    inventory (name, rows, extra = {}) {
      const file = path.join(dir, name)
      writeFileSync(file, JSON.stringify({ relays: rows, ...extra }))
      return file
    },
    replies (value) { writeFileSync(replies, JSON.stringify(value)) },
    calls () { return existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line)) : [] },
    run (args = [], overrides = {}) {
      return spawnSync('bash', [script, ...args], { cwd: dir, env: { ...env, ...overrides }, encoding: 'utf8', timeout: 15000 })
    }
  }
}

function relay (name, extra = {}) {
  return { name, publicIp: `${name}.test`, channel: 'stable', ...extra }
}

test('fleet status selects local inventory, explicit override and tracked fallback', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('tracked')])
  const local = f.inventory('relays.local.json', [relay('local', { tailnet: 'tailnet.test' })])
  const explicit = f.inventory('reviewed inventory.json', [relay('explicit')])
  t.is(f.run().status, 0)
  t.alike(f.calls().filter(c => c.command === 'ssh').map(c => c.args.find(a => a.startsWith('root@'))), ['root@tailnet.test'])
  const selected = f.run(['--inventory', explicit])
  t.is(selected.status, 0)
  t.ok(selected.stdout.includes('explicit'))
  t.absent(selected.stdout.includes('tracked.test'))
  t.is(f.run([`--inventory=${explicit}`]).status, 0)
  rmSync(local)
  const fallback = f.run()
  t.is(fallback.status, 0)
  t.ok(fallback.stdout.includes('tracked'))
  const args = f.calls().filter(c => c.command === 'ssh')[0].args
  t.ok(args.includes('StrictHostKeyChecking=accept-new'))
  t.ok(args.includes('BatchMode=yes'))
  t.ok(args.includes('ConnectTimeout=10'))
  t.ok(args.includes('ServerAliveCountMax=1'))
  t.absent(args.includes('-i'), 'default identity does not create an empty argument')
})

test('fleet status handles help and inventory option ordering without probing', (t) => {
  const f = fixture(t)
  for (const args of [[], ['--inventory', 'missing.json'], ['--inventory=missing.json']]) {
    for (const help of ['--help', '-h']) {
      t.is(f.run([help, ...args]).status, 0)
      t.is(f.run([...args, help]).status, 0)
    }
  }
  for (const args of [['--inventory'], ['--inventory='], ['--unknown'], ['--inventory', 'a', '--inventory', 'b'], ['--inventory', '--help']]) {
    t.is(f.run(args).status, 2)
  }
  t.is(f.calls().length, 0)
})

test('fleet status rejects malformed inventory before channel fetch or any host probe', (t) => {
  const f = fixture(t)
  const file = f.inventory('relays.json', [relay('valid')])
  const cases = [
    '{', '{}', '{"relays":{}}',
    JSON.stringify({ relays: [relay('valid'), relay('injected', { publicIp: '-oProxyCommand=bad' })] }),
    JSON.stringify({ relays: [relay('injected', { channel: "stable');bad" })] }),
    JSON.stringify({ relays: [relay('injected', { sshKey: 'key\nsecond' })] }),
    JSON.stringify({ relays: [relay('injected|host')] }),
    JSON.stringify({ relays: [relay('injected\u001b[31m')] }),
    JSON.stringify({ relays: [relay('wrong-type', { tailnet: [] })] }),
    JSON.stringify({ relays: [relay('duplicate'), relay('duplicate')] }),
    JSON.stringify({ relays: [], retiredRelays: 'bad' })
  ]
  for (const raw of cases) {
    writeFileSync(file, raw)
    const result = f.run()
    t.is(result.status, 2)
    t.ok(result.stderr.includes('Invalid inventory'))
  }
  t.is(f.calls().length, 0, 'the entire inventory is checked before network I/O')
  writeFileSync(file, JSON.stringify({ relays: [relay('valid')] }))
  writeFileSync(path.join(f.dir, 'relays.local.json'), '{')
  t.is(f.run().status, 2, 'malformed local override cannot silently fall back to tracked inventory')
  t.is(f.run(['--inventory', 'missing.json']).status, 2)
  t.is(f.calls().length, 0)
})

test('fleet status never probes retired or other records, including exclusion overrides', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [
    relay('active'), relay('old-role', { role: 'retired' }),
    relay('old-date', { retiredAt: '2026-08-05' }),
    relay('old-status', { status: 'retired' }), relay('overridden')
  ], {
    retiredRelays: [{ name: 'overridden', retirementReason: 'repurposed' }, { name: 'retired-only', reason: 'low memory' }],
    otherHosts: [{ name: 'missing-provider', disposition: 'unavailable' }],
    otherRelays: [{ name: 'other-relay', reason: 'held outside relay fleet' }]
  })
  const result = f.run()
  t.is(result.status, 0)
  t.alike(f.calls().filter(c => c.command === 'ssh').map(c => c.args.find(a => a.startsWith('root@'))), ['root@active.test'])
  const excluded = result.stdout.split('Excluded inventory')[1]
  for (const name of ['old-role', 'old-date', 'old-status', 'overridden', 'retired-only', 'missing-provider', 'other-relay']) t.ok(excluded.includes(name))
  t.ok(excluded.includes('repurposed'))
  t.ok(excluded.includes('unavailable'))
  t.ok(result.stdout.includes('76%!'))
})

test('fleet status separates safe SSH failure reasons from unobserved service health', (t) => {
  const f = fixture(t)
  const secret = 'sensitive-key-material-do-not-print'
  f.inventory('relays.json', ['auth', 'timeout', 'trust', 'key', 'network', 'other', 'missing'].map(name => relay(name, name === 'missing' ? { sshKey: '~/missing identity' } : {})))
  f.replies({
    'auth.test': { code: 255, stderr: `Permission denied (publickey). ${secret}`, stdout: 'v9.9.9|RUNNING 1 2|1%\n' },
    'timeout.test': { code: 255, stderr: `Connection timed out ${secret}` },
    'trust.test': { code: 255, stderr: `REMOTE HOST IDENTIFICATION HAS CHANGED ${secret}` },
    'key.test': { code: 255, stderr: `Load key /private/key: invalid format ${secret}` },
    'network.test': { code: 255, stderr: `No route to host ${secret}` },
    'other.test': { code: 42, stderr: secret }
  })
  const result = f.run()
  t.is(result.status, 0)
  for (const category of ['SSH-AUTH', 'SSH-TIMEOUT', 'SSH-HOST-TRUST', 'SSH-KEY', 'SSH-NETWORK', 'SSH-ERROR', 'KEY-MISSING']) t.ok(result.stdout.includes(category))
  t.is((result.stdout.match(/unobserved/g) || []).length, 8, 'seven failed rows plus explanatory footer')
  t.absent(result.stdout.includes('v9.9.9'), 'partial output never overrides a failed SSH exit')
  t.absent((result.stdout + result.stderr).includes(secret))
  t.is(f.calls().filter(c => c.command === 'ssh').length, 6, 'missing key is detected before SSH')
})

test('fleet status executes remote probe with exact prerelease/build version and private auth header', (t) => {
  const f = fixture(t)
  const identity = path.join(f.home, 'identity with spaces')
  writeFileSync(identity, 'fixture identity')
  f.inventory('relays.json', [relay('execute', { sshKey: '~/identity with spaces' })])
  const result = f.run()
  t.is(result.status, 0)
  t.ok(result.stdout.includes('v0.25.0-rc.9+build.7'))
  t.ok(result.stdout.includes('RUNNING'))
  t.ok(result.stdout.includes('91%!!'))
  t.absent((result.stdout + result.stderr).includes('fixture-secret-do-not-display'))
  const ssh = f.calls().find(c => c.command === 'ssh')
  t.is(ssh.args[ssh.args.indexOf('-i') + 1], identity)
  const health = f.calls().find(c => c.command === 'curl' && c.header)
  t.ok(health.authorized)
  t.is(health.headerMode, 0o600)
  t.absent(existsSync(health.header), 'temporary header is removed')
  t.absent(health.args.join(' ').includes('fixture-secret-do-not-display'))
})

test('fleet status reports reachable stopped, invalid and unavailable health separately', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('execute')])
  for (const [body, code, expected] of [
    ['{"running":false,"seededApps":0,"connections":0}', '0', 'STOPPED'],
    ['{"running":"true"}', '0', 'HEALTH-INVALID'],
    ['not-json', '0', 'HEALTH-INVALID'],
    ['', '22', 'HEALTH-UNAVAILABLE']
  ]) {
    const result = f.run([], { FLEET_TEST_HEALTH: body || ' ', FLEET_TEST_CURL_EXIT: code })
    t.is(result.status, 0)
    t.ok(result.stdout.includes(expected))
    t.ok(/execute\s+v0\.26\.0-rc\.2\s+SERVICE-PACKAGE\s+OK/.test(result.stdout))
    t.absent(result.stdout.includes('SSH-AUTH'))
  }
})

test('fleet status observes health version instead of stale rollback or configured package versions', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('execute')])
  for (const version of ['0.27.0-rc.1', 'v0.27.0-rc.1+build.42']) {
    const result = f.run([], { FLEET_TEST_HEALTH: JSON.stringify({ running: true, version, seededApps: 2, connections: 9 }) })
    t.is(result.status, 0)
    t.ok(result.stdout.includes(`${version.startsWith('v') ? version : 'v' + version}`))
    t.ok(/execute\s+v0\.27\.0-rc\.1(?:\+build\.42)?\s+HEALTH\s+OK\s+RUNNING/.test(result.stdout))
    t.absent(result.stdout.includes('v0.25.0-rc.9'), 'rollback checkout does not determine running version')
    t.absent(result.stdout.includes('v0.26.0-rc.2'), 'health version wins over configured package')
  }
})

test('fleet status labels missing or invalid health versions as service-package fallback only', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('execute')])
  for (const version of [undefined, null, 27, {}, 'latest', '0.27.0-rc..1', '0.27.0-01', '00.27.0', '0.27.0+bad..build', '0.27.0\u001b[31m', '0.27.0|RUNNING 8 9', '0.27.0-' + 'x'.repeat(81)]) {
    const result = f.run([], { FLEET_TEST_HEALTH: JSON.stringify({ running: true, version, seededApps: 2, connections: 9 }) })
    t.is(result.status, 0)
    t.ok(/execute\s+v0\.26\.0-rc\.2\s+SERVICE-PACKAGE\s+OK\s+RUNNING/.test(result.stdout))
    t.absent(result.stdout.includes('\u001b'))
  }
  const invalidHealth = f.run([], { FLEET_TEST_HEALTH: '{"running":"true","version":"0.27.0-rc.1"}' })
  t.ok(/execute\s+v0\.26\.0-rc\.2\s+SERVICE-PACKAGE\s+OK\s+HEALTH-INVALID/.test(invalidHealth.stdout), 'an invalid health object cannot establish an observed version')
})

test('fleet status never guesses runtime version without valid health or service package', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('execute')])
  for (const workingDirectory of ['', 'relative/path', '/missing-service', f.home + '/service\nnot-a-directory']) {
    const result = f.run([], { FLEET_TEST_CURL_EXIT: '22', FLEET_TEST_WORKING_DIRECTORY: workingDirectory })
    t.is(result.status, 0)
    t.ok(/execute\s+\?\s+UNOBSERVED\s+OK\s+HEALTH-UNAVAILABLE/.test(result.stdout))
    t.absent(result.stdout.includes('v0.25.0-rc.9'), 'does not fall back to HOME/hiverelay')
  }
  for (const raw of ['{', '{"version":"0.27.0-01"}', '{"version":"0.27.0\\n"}', '{"version":"' + 'x'.repeat(65536) + '"}']) {
    writeFileSync(path.join(f.home, 'service/package.json'), raw)
    const result = f.run([], { FLEET_TEST_HEALTH: '{"running":true}' })
    t.is(result.status, 0)
    t.ok(/execute\s+\?\s+UNOBSERVED\s+OK\s+RUNNING/.test(result.stdout))
  }
})

test('fleet status rejects malformed successful probe output without terminal control text', (t) => {
  const f = fixture(t)
  f.inventory('relays.json', [relay('malformed'), relay('empty')])
  f.replies({
    'malformed.test': { stdout: 'banner\nsensitive-probe-text\u001b[31m|bad sensitive-probe-text 1|sensitive-probe-text\n' },
    'empty.test': { stdout: '' }
  })
  const result = f.run()
  t.is(result.status, 0)
  t.is((result.stdout.match(/PROBE-INVALID/g) || []).length, 2)
  t.absent(result.stdout.includes('sensitive-probe-text'))
  t.absent(result.stdout.includes('\u001b'))
})
