import test from 'brittle'
import { spawn } from 'node:child_process'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { delimiter, join } from 'node:path'
import { tmpdir } from 'node:os'

function runProbe (args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/probe-fleet-services.mjs', ...args], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', chunk => { stdout += chunk })
    child.stderr.on('data', chunk => { stderr += chunk })
    child.once('error', reject)
    child.once('close', code => resolve({ code, stdout, stderr }))
  })
}

test('fleet service probe help is local and side-effect free', async (t) => {
  const result = await runProbe(['--help'], { PATH: '' })
  t.is(result.code, 0)
  t.ok(result.stdout.startsWith('Usage: node scripts/probe-fleet-services.mjs'))
  t.is(result.stderr, '')
})

test('fleet service probe distinguishes catalogue, application, and host reachability', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-fleet-probe-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const inventory = join(dir, 'relays.json')
  const ssh = join(dir, 'ssh')
  await writeFile(inventory, JSON.stringify({
    relays: [
      { name: 'legacy-live', publicIp: 'legacy-live.test', sshKey: 'default', region: 'EU' },
      { name: 'blank-host', publicIp: 'blank-host.test', sshKey: 'default', region: 'ME' },
      { name: 'down-host', publicIp: 'down-host.test', sshKey: 'default', region: 'NA' },
      { name: 'restricted-tor', publicIp: 'restricted-tor.test', sshKey: 'default', region: 'EU' }
    ]
  }))
  await writeFile(ssh, `#!/bin/sh
case "$*" in
  *restricted-tor.test*api/v1/services*)
    printf '%s\n' '{"services":["notify"],"total":1}' '__HIVERELAY_CAP__' '{"features":[],"supported_transports":["tor"],"privacyTransports":[{"network":"tor","auth":{"mode":"client-auth-v3"}}],"protocol_profile":{"services":{"notify":{"egress":{"live":false},"watch_sources":[]}}}}'
    exit 0
    ;;
  *legacy-live.test*HIVERELAY_HOST_STATUS*)
    printf '%s\n' 'HIVERELAY_HOST_STATUS|active|present|v0.24.3|present|enabled|active'
    exit 0
    ;;
  *blank-host.test*HIVERELAY_HOST_STATUS*)
    printf '%s\n' 'HIVERELAY_HOST_STATUS|inactive|absent|v?|absent|not-found|inactive'
    exit 0
    ;;
esac
exit 22
`)
  await chmod(ssh, 0o755)

  const result = await runProbe(['--json', '--ssh-only', '--relays', inventory], {
    PATH: `${dir}${delimiter}${process.env.PATH || ''}`
  })
  t.is(result.code, 0, result.stderr)
  const body = JSON.parse(result.stdout)
  const live = body.relays.find(relay => relay.name === 'legacy-live')
  const blank = body.relays.find(relay => relay.name === 'blank-host')
  const down = body.relays.find(relay => relay.name === 'down-host')
  const restrictedTor = body.relays.find(relay => relay.name === 'restricted-tor')

  t.is(live.serviceCatalogueReachable, false)
  t.is(live.hostReachable, true)
  t.is(live.appRunning, true)
  t.is(live.appState, 'active')
  t.is(live.version, 'v0.24.3')
  t.is(live.repoPresent, true)
  t.is(live.updaterPresent, true)
  t.is(live.updaterTimer, 'enabled/active')

  t.is(blank.serviceCatalogueReachable, false)
  t.is(blank.hostReachable, true)
  t.is(blank.appRunning, false)
  t.is(blank.appState, 'inactive')
  t.is(blank.version, '?')
  t.is(blank.repoPresent, false)
  t.is(blank.updaterPresent, false)
  t.is(blank.updaterTimer, 'not-found/inactive')

  t.is(down.serviceCatalogueReachable, false)
  t.is(down.hostReachable, false)
  t.is(down.appRunning, undefined)

  t.is(restrictedTor.serviceCatalogueReachable, true)
  t.is(restrictedTor.torAdvertised, true)
  t.is(restrictedTor.torRestricted, true)
  t.is(restrictedTor.torNegativeProbe, false)
  t.is(restrictedTor.torSignedReady, false)
})
