import test from 'brittle'
import { execFile, spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { encodeHiveAppKey } from '../../packages/core/gateway/hive-host.js'

const TARGET_SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const GATEWAY_FIXTURE_VERIFIER = '#!/usr/bin/env node\nprocess.stdout.write("fixture verifier must not run in dirty-tree test\\n")\n'

function runCheck (argv) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['scripts/check-fleet-rollout.mjs', ...argv], {
      cwd: process.cwd(),
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}

test('fleet rollout evidence writer keeps a closed public schema', async (t) => {
  const script = await readFile('scripts/check-fleet-rollout.mjs', 'utf8')

  t.ok(script.includes('assertFleetRolloutEvidenceSchema(evidence)'))
  t.ok(script.includes('function assertFleetRolloutEvidenceSchema'))
  t.ok(script.includes("requireOnlyKeys('fleet rollout evidence'"))
  t.ok(script.includes('has unsupported fields'))
  t.ok(script.includes('--known-hosts is required for live rollout checks unless an explicit --ssh-command wrapper owns pinned host-key policy.'))
  t.absent(script.includes('accept-new'))
})

test('fleet rollout check verifies target sha and health through ssh probe', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const sshArgsPath = path.join(dir, 'ssh-args.txt')
  const knownHostsPath = path.join(dir, 'known_hosts')
  const channelsPath = await writeFixtureChannels(dir)
  await writeFile(knownHostsPath, '127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnly\n')

  const relaysJson = JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  })
  await writeFile(relaysPath, relaysJson)

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > ${sh(sshArgsPath)}
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  const { stdout } = await runCheck([
    '--target', 'v9.9.9',
    '--target-sha', TARGET_SHA,
    '--channel', 'canary',
    '--relays', relaysPath,
    '--channels', channelsPath,
    '--ssh-command', sshPath,
    '--known-hosts', knownHostsPath,
    '--evidence', evidencePath,
    '--timeout-ms', '600000',
    '--interval-ms', '5000'
  ])

  t.ok(stdout.includes('Checking 1 relay(s) on channel canary: mock-canary'))
  t.ok(stdout.includes('Fleet rollout verified: 1/1 relay(s) on v9.9.9'))
  const sshArgs = await readFile(sshArgsPath, 'utf8')
  t.ok(sshArgs.includes('StrictHostKeyChecking=yes'))
  t.ok(sshArgs.includes('UpdateHostKeys=no'))
  t.ok(sshArgs.includes(`UserKnownHostsFile=${knownHostsPath}`))
  t.ok(sshArgs.includes('GlobalKnownHostsFile=/dev/null'))
  t.absent(sshArgs.includes('accept-new'))

  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(evidence.schemaVersion, 1)
  t.is(evidence.status, 'verified')
  t.is(evidence.target.tag, 'v9.9.9')
  t.is(evidence.target.sha, TARGET_SHA)
  t.is(evidence.target.channel, 'canary')
  t.is(evidence.inventory.path, 'relays.json')
  t.is(evidence.inventory.sha256, crypto.createHash('sha256').update(relaysJson).digest('hex'))
  t.alike(evidence.inventory.relayNames, ['mock-canary'])
  t.is(evidence.channelConfig.path, 'channels.json')
  t.is(evidence.channelConfig.sha256, crypto.createHash('sha256').update(await readFile(channelsPath)).digest('hex'))
  t.alike(evidence.channelConfig.targets, { canary: 'v9.9.9' })
  t.is(evidence.summary.total, 1)
  t.is(evidence.summary.updated, 1)
  t.is(evidence.summary.packageVersionMatches, 1)
  t.is(evidence.summary.healthy, 1)
  t.is(evidence.summary.runtimeVersionMatches, 1)
  t.absent(evidence.summary.gatewayHealthy, 'default rollout evidence keeps the v1 summary schema')
  t.absent(evidence.probes.publicGatewayEvidence, 'gateway proof is opt-in')
  t.is(evidence.relays[0].name, 'mock-canary')
  t.is(evidence.relays[0].headSha, TARGET_SHA)
  t.is(evidence.relays[0].healthVersion, '9.9.9')
  t.is(evidence.relays[0].packageVersionMatches, true)
  t.absent(evidence.relays[0].gatewayHealthy, 'default relay evidence remains schema v1')
  t.absent(evidence.relays[0].gatewayEvidenceSha256, 'default relay evidence has no gateway digest')
  t.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(evidence.relays[0].observedAt), 'relay observation time is recorded')
  t.is(evidence.relays[0].note, 'ok')
  t.absent(evidence.relays[0].host, 'host is not written to public rollout evidence')
  t.absent(evidence.relays[0].sshKey, 'ssh key is not written to public rollout evidence')
})

test('fleet rollout check defaults to both fleet channels', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  const relaysJson = JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      },
      {
        name: 'mock-stable',
        publicIp: '127.0.0.2',
        tailnet: null,
        sshKey: 'default',
        channel: 'stable'
      }
    ]
  })
  await writeFile(relaysPath, relaysJson)

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  const { stdout } = await runCheck([
    '--target', 'v9.9.9',
    '--target-sha', TARGET_SHA,
    '--relays', relaysPath,
    '--channels', channelsPath,
    '--ssh-command', sshPath,
    '--evidence', evidencePath,
    '--timeout-ms', '600000',
    '--interval-ms', '5000'
  ])

  t.ok(stdout.includes('Checking 2 relay(s) on channel both: mock-canary, mock-stable'))
  t.ok(stdout.includes('Fleet rollout verified: 2/2 relay(s) on v9.9.9'))

  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(evidence.target.channel, 'both')
  t.alike(evidence.inventory.relayNames, ['mock-canary', 'mock-stable'])
  t.alike(evidence.channelConfig.targets, { canary: 'v9.9.9', stable: 'v9.9.9' })
  t.is(evidence.summary.total, 2)
  t.is(evidence.summary.updated, 2)
  t.alike(evidence.relays.map((relay) => relay.channel).sort(), ['canary', 'stable'])
})

test('fleet rollout check rejects unsafe verified proof timing before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--evidence', evidencePath,
      '--timeout-ms', '1000',
      '--interval-ms', '100',
      '--ssh-timeout-ms', '5000'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('verified fleet rollout timeoutMs must be an integer between 600000 and 14400000'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'unsafe verified proof timing is rejected before public evidence is written')
})

test('fleet rollout check rejects malformed timing integers before probing', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
printf 'ssh should not run\\n' > ${sh(path.join(dir, 'ssh-ran.txt'))}
exit 1
`)
  await chmod(sshPath, 0o755)

  const cases = [
    ['--timeout-ms', '600000.5'],
    ['--interval-ms', ' 5000'],
    ['--ssh-timeout-ms', '5000\nHIVERELAY_ATTACKER_VALUE=owned'],
    ['--timeout-ms', '1e6']
  ]

  for (const [flag, value] of cases) {
    let err = null
    try {
      await runCheck([
        '--target', 'v9.9.9',
        '--target-sha', TARGET_SHA,
        '--channel', 'canary',
        '--relays', relaysPath,
        '--channels', channelsPath,
        '--ssh-command', sshPath,
        '--evidence', evidencePath,
        flag, value
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, `rejects ${flag}=${JSON.stringify(value)}`)
    t.ok(err.stderr.includes(`Invalid ${flag} value`))
    t.ok(err.stderr.includes('Expected a positive integer without whitespace or control characters.'))
    t.absent(err.stderr.includes('HIVERELAY_ATTACKER_VALUE=owned'))
  }

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'malformed timing values are rejected before public evidence is written')

  let sshErr = null
  try {
    await readFile(path.join(dir, 'ssh-ran.txt'), 'utf8')
  } catch (e) {
    sshErr = e
  }
  t.ok(sshErr, 'malformed timing values are rejected before SSH probing')
})

test('fleet rollout check rejects stale channel targets before probing', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir, { canary: 'v9.9.8' })

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet channel canary target is v9.9.8; expected v9.9.9'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'stale channel metadata is rejected before public evidence is written')
})

test('fleet rollout check rejects duplicate selected relay names before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      },
      {
        name: 'mock-canary',
        publicIp: '127.0.0.2',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('Duplicate relay name "mock-canary" in selected fleet channel "canary"'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'duplicate selected relay names are rejected before public evidence is written')
})

test('fleet rollout check rejects unsafe fleet metadata files before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const channelsPath = await writeFixtureChannels(dir)
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  const symlinkRelaysPath = path.join(dir, 'relays-symlink.json')
  await symlink(relaysPath, symlinkRelaysPath)
  let symlinkErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', symlinkRelaysPath,
      '--channels', channelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    symlinkErr = e
  }
  t.ok(symlinkErr)
  t.ok(symlinkErr.stderr.includes('fleet inventory file must not be a symlink'))

  const directoryChannelsPath = path.join(dir, 'channels-directory.json')
  await mkdir(directoryChannelsPath)
  let directoryErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', directoryChannelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    directoryErr = e
  }
  t.ok(directoryErr)
  t.ok(directoryErr.stderr.includes('fleet channel config file must be a regular file'))

  const oversizedChannelsPath = path.join(dir, 'channels-oversized.json')
  await writeFile(oversizedChannelsPath, '{"canary":"v9.9.9","pad":"' + 'x'.repeat(2 * 1024 * 1024) + '"}\n')
  let oversizedErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', oversizedChannelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    oversizedErr = e
  }
  t.ok(oversizedErr)
  t.ok(oversizedErr.stderr.includes('fleet channel config file must be 2097152 bytes or smaller'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'unsafe fleet metadata files are rejected before public evidence is written')
})

test('fleet rollout check rejects updated repo with stale live health version', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.8\\t{"running":true,"version":"9.9.8"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--evidence', evidencePath,
      '--timeout-ms', '250',
      '--interval-ms', '50'
    ])
    t.fail('stale runtime version should fail rollout verification')
  } catch (err) {
    t.ok(err.stdout.includes('waiting-runtime-version'))
    t.ok(err.stderr.includes('Fleet rollout did not converge'))
    const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
    t.is(evidence.status, 'failed')
    t.is(evidence.summary.updated, 1)
    t.is(evidence.summary.packageVersionMatches, 1)
    t.is(evidence.summary.healthy, 1)
    t.is(evidence.summary.runtimeVersionMatches, 0)
    t.is(evidence.relays[0].note, 'waiting-runtime-version')
  }
})

test('fleet rollout check rejects updated repo with stale package version', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.8\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--evidence', evidencePath,
      '--timeout-ms', '250',
      '--interval-ms', '50'
    ])
    t.fail('stale package version should fail rollout verification')
  } catch (err) {
    t.ok(err.stdout.includes('waiting-package-version'))
    t.ok(err.stderr.includes('Fleet rollout did not converge'))
    const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
    t.is(evidence.status, 'failed')
    t.is(evidence.summary.updated, 1)
    t.is(evidence.summary.packageVersionMatches, 0)
    t.is(evidence.summary.healthy, 1)
    t.is(evidence.summary.runtimeVersionMatches, 1)
    t.is(evidence.relays[0].packageVersionMatches, false)
    t.is(evidence.relays[0].note, 'waiting-package-version')
  }
})

test('fleet rollout check rejects credentialed API URLs before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--api', 'http://operator:secret@127.0.0.1:9100',
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout API URL must not expose URL credentials'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'credentialed API URL is rejected before public evidence is written')
})

test('fleet rollout check rejects non-http API URLs before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--api', 'file:///etc/passwd',
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('Expected an http(s) URL'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'non-http API URL is rejected before public evidence is written')
})

test('fleet rollout check rejects non-loopback API URLs before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  for (const api of ['https://relay.example.com:9100', 'http://128.0.0.1:9100']) {
    let err = null
    try {
      await runCheck([
        '--target', 'v9.9.9',
        '--target-sha', TARGET_SHA,
        '--channel', 'canary',
        '--relays', relaysPath,
        '--channels', channelsPath,
        '--api', api,
        '--evidence', evidencePath,
        '--dry-run'
      ])
    } catch (e) {
      err = e
    }

    t.ok(err, api)
    t.ok(err.stderr.includes('Expected a loopback URL'), api)

    let evidenceErr = null
    try {
      await readFile(evidencePath, 'utf8')
    } catch (e) {
      evidenceErr = e
    }
    t.ok(evidenceErr, `${api} is rejected before public evidence is written`)
  }
})

test('fleet rollout check rejects query-string API bases before writing evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--api', 'http://127.0.0.1:9100?api_key=secret#health',
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('without query strings or fragments'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'query-string API URL is rejected before public evidence is written')
})

test('fleet rollout check rejects SSH option-like relay hosts before probing', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '-oProxyCommand=sh',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('without SSH options'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'unsafe relay host is rejected before public evidence is written')
})

test('fleet rollout check keeps probe config out of SSH command argv', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)
  const argvPath = path.join(dir, 'ssh-argv.txt')
  const stdinPath = path.join(dir, 'ssh-stdin.sh')
  const remoteRepoDir = "/srv/hive relay'; touch /tmp/hiverelay-pwn; echo '"

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$@" > ${sh(argvPath)}
cat > ${sh(stdinPath)}
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\n' '${TARGET_SHA}'
`)
  await chmod(sshPath, 0o755)

  await runCheck([
    '--target', 'v9.9.9',
    '--target-sha', TARGET_SHA,
    '--channel', 'canary',
    '--relays', relaysPath,
    '--channels', channelsPath,
    '--ssh-command', sshPath,
    '--remote-repo-dir', remoteRepoDir,
    '--api', 'http://127.0.0.1:9100/',
    '--evidence', evidencePath,
    '--timeout-ms', '600000',
    '--interval-ms', '5000'
  ])

  const argv = (await readFile(argvPath, 'utf8')).trim().split('\n')
  t.alike(argv.slice(-3), ['root@127.0.0.1', 'bash', '-s'])
  t.absent(argv.some((arg) => arg.includes('touch /tmp/hiverelay-pwn')), 'remote repo value is not passed through SSH argv')

  const script = await readFile(stdinPath, 'utf8')
  t.ok(script.includes(`repo=${sh(remoteRepoDir)}`), 'remote repo value is shell-quoted in stdin probe script')
  t.ok(script.includes('cd -- "$repo"'), 'remote probe uses option-safe cd')

  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(evidence.probes.api, 'http://127.0.0.1:9100', 'API base is normalized before evidence/probe use')
})

test('fleet rollout evidence redacts secret-looking probe errors', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
echo 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' >&2
echo 'APP_SEED=super-secret-seed' >&2
echo 'HIVERELAY_API_KEY=super-secret-key' >&2
echo 'https://operator:secret@relay.example/health' >&2
exit 1
`)
  await chmod(sshPath, 0o755)

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--evidence', evidencePath,
      '--timeout-ms', '120',
      '--interval-ms', '25'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('Fleet rollout did not converge'))
  t.absent(err.stdout.includes('Authorization: Bearer abcdefghijklmnopqrstuvwxyz'))
  t.absent(err.stderr.includes('Authorization: Bearer abcdefghijklmnopqrstuvwxyz'))
  t.absent(err.stdout.includes('APP_SEED=super-secret-seed'))
  t.absent(err.stderr.includes('APP_SEED=super-secret-seed'))
  t.absent(err.stdout.includes('HIVERELAY_API_KEY=super-secret-key'))
  t.absent(err.stderr.includes('HIVERELAY_API_KEY=super-secret-key'))
  t.absent(err.stdout.includes('operator:secret'))
  t.absent(err.stderr.includes('operator:secret'))

  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(evidence.status, 'failed')
  t.ok(evidence.relays[0].error.includes('[redacted authorization header]'))
  t.ok(evidence.relays[0].error.includes('[redacted APP_SEED]'))
  t.ok(evidence.relays[0].error.includes('[redacted HIVERELAY_API_KEY]'))
  t.absent(evidence.relays[0].error.includes('Authorization: Bearer abcdefghijklmnopqrstuvwxyz'))
  t.absent(evidence.relays[0].error.includes('APP_SEED=super-secret-seed'))
  t.absent(evidence.relays[0].error.includes('HIVERELAY_API_KEY=super-secret-key'))
  t.absent(evidence.relays[0].error.includes('operator:secret'))
})

test('fleet rollout evidence rejects control-character relay metadata', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const relaysPath = path.join(dir, 'relays.json')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)

  await writeFile(relaysPath, JSON.stringify({
    relays: [
      {
        name: 'mock\u001b[31m-canary',
        publicIp: '127.0.0.1',
        tailnet: null,
        sshKey: 'default',
        channel: 'canary'
      }
    ]
  }))

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }

  t.ok(err)
  t.ok(err.stderr.includes('fleet rollout relay name must not contain control characters'))

  let evidenceErr = null
  try {
    await readFile(evidencePath, 'utf8')
  } catch (e) {
    evidenceErr = e
  }
  t.ok(evidenceErr, 'control-character relay metadata is rejected before public evidence is written')
})

test('fleet rollout opt-in gateway evidence is remotely verified and gates convergence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fleet-rollout-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const relaysPath = path.join(dir, 'relays.json')
  const sshPath = path.join(dir, 'mock-ssh.sh')
  const stdinPath = path.join(dir, 'remote-probe.sh')
  const argvPath = path.join(dir, 'ssh-argv.txt')
  const evidencePath = path.join(dir, 'fleet-rollout-evidence.json')
  const channelsPath = await writeFixtureChannels(dir)
  const gatewayEvidence = '/root/.hiverelay/gateway-evidence/preflight-live.json'
  const knownHostsPath = path.join(dir, 'known_hosts')
  const gatewayWindowState = path.join(dir, 'gateway-window-state.json')
  const release = await createGatewayReleaseRepo(dir)
  const gatewayToken = gatewayRolloutToken(release)

  await writeFile(relaysPath, JSON.stringify({
    relays: [{
      name: 'mock-canary',
      publicIp: '127.0.0.1',
      sshKey: 'default',
      channel: 'canary'
    }]
  }))
  await writeFile(knownHostsPath, 'mock-canary ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockPinnedKey\n')
  await writeGatewayWindowState(gatewayWindowState, release, gatewayToken)
  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$@" > ${sh(argvPath)}
cat > ${sh(stdinPath)}
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\ttrue\\t%s\\n' '${release.targetSha}' '${gatewayToken}'
`)
  await chmod(sshPath, 0o755)

  const { stdout } = await runCheck([
    '--target', 'v9.9.9',
    '--target-sha', release.targetSha,
    '--repo', release.repo,
    '--allowed-signers', release.allowedSigners,
    '--channel', 'canary',
    '--relays', relaysPath,
    '--channels', channelsPath,
    '--ssh-command', sshPath,
    '--gateway-evidence', gatewayEvidence,
    '--gateway-manifest', release.manifestPath,
    '--gateway-window-state', gatewayWindowState,
    '--known-hosts', knownHostsPath,
    '--evidence', evidencePath,
    '--timeout-ms', '600000',
    '--interval-ms', '5000'
  ])
  t.ok(stdout.includes('Fleet rollout verified: 1/1'))

  const evidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(evidence.schemaVersion, 2)
  t.is(evidence.probes.publicGatewayEvidence, true)
  t.is(evidence.summary.gatewayHealthy, 1)
  t.is(evidence.relays[0].gatewayHealthy, true)
  t.is(evidence.relays[0].gateway.evidenceSha256, gatewayRolloutTokenValue(release).evidenceSha256)
  t.is(evidence.publicGateway.manifest.sha256, release.manifestSha256)
  t.is(evidence.publicGateway.window.complete, true)
  t.absent(JSON.stringify(evidence).includes(gatewayEvidence), 'node-local artifact path is not public evidence')

  const remote = await readFile(stdinPath, 'utf8')
  const remoteSyntax = spawnSync('bash', ['-n', stdinPath], { encoding: 'utf8' })
  t.is(remoteSyntax.status, 0, remoteSyntax.stderr)
  t.ok(remote.includes(`gateway_evidence=${sh(gatewayEvidence)}`))
  t.ok(remote.includes('scripts/verify-public-hive-gateway-evidence.mjs'))
  t.ok(remote.includes('--release-target "$release_target"'))
  t.ok(remote.includes('--release-sha "$release_sha"'))
  t.ok(remote.includes('--require-mode fleet'))
  t.ok(remote.includes(`expected_origin=${sh(release.entry.origin)}`))
  t.ok(remote.includes('--expected-nginx-sha256 "$expected_nginx_sha256"'))
  t.ok(remote.includes('diff --no-ext-diff --quiet "$release_sha" --'))
  t.ok(remote.includes('diff --no-ext-diff --cached --quiet "$release_sha" --'))
  t.ok(remote.indexOf('target worktree is dirty') < remote.indexOf('node "$verifier"'),
    'clean target worktree is required before verifier execution')

  const argv = await readFile(argvPath, 'utf8')
  t.ok(argv.includes('StrictHostKeyChecking=yes'))
  t.ok(argv.includes(`UserKnownHostsFile=${knownHostsPath}`))
  t.ok(argv.includes('GlobalKnownHostsFile=/dev/null'))
  t.absent(argv.includes('accept-new'))

  // Execute the captured remote program against a target whose HEAD is still
  // correct but whose tracked verifier is modified. It must stop before Node.
  const fixtureVerifier = path.join(release.repo, 'scripts', 'verify-public-hive-gateway-evidence.mjs')
  await writeFile(fixtureVerifier, GATEWAY_FIXTURE_VERIFIER + '// tampered\n')
  await writeFile(sshPath, '#!/usr/bin/env bash\nset -euo pipefail\nexec bash -s\n')
  await chmod(sshPath, 0o755)
  let dirtyErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', release.targetSha,
      '--repo', release.repo,
      '--allowed-signers', release.allowedSigners,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--remote-repo-dir', release.repo,
      '--gateway-evidence', gatewayEvidence,
      '--gateway-manifest', release.manifestPath,
      '--gateway-window-state', gatewayWindowState,
      '--known-hosts', knownHostsPath,
      '--evidence', evidencePath,
      '--timeout-ms', '120',
      '--interval-ms', '25'
    ])
  } catch (err) {
    dirtyErr = err
  }
  t.ok(dirtyErr, 'dirty signed-target worktree is rejected')
  const dirtyEvidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.ok(dirtyEvidence.relays[0].error.includes('target worktree is dirty'),
    'remote verifier refuses mutable tracked code before execution')
  await writeFile(fixtureVerifier, GATEWAY_FIXTURE_VERIFIER)
  await writeGatewayWindowState(gatewayWindowState, release, gatewayToken)

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\tfalse\\t\\n' '${release.targetSha}'
`)
  await chmod(sshPath, 0o755)
  let redErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', release.targetSha,
      '--repo', release.repo,
      '--allowed-signers', release.allowedSigners,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--gateway-evidence', gatewayEvidence,
      '--gateway-manifest', release.manifestPath,
      '--gateway-window-state', gatewayWindowState,
      '--known-hosts', knownHostsPath,
      '--evidence', evidencePath,
      '--timeout-ms', '120',
      '--interval-ms', '25'
    ])
  } catch (e) {
    redErr = e
  }
  t.ok(redErr, 'a red gateway artifact prevents rollout convergence')
  const failedEvidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(failedEvidence.status, 'failed')
  t.is(failedEvidence.summary.gatewayHealthy, 0)
  t.is(failedEvidence.relays[0].note, 'waiting-gateway-evidence')

  await writeFile(sshPath, `#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null
printf '%s\\tv9.9.9\\ttrue\\t42%%\\t9.9.9\\t{"running":true,"version":"9.9.9"}\\ttrue\\t%s\\n' '${release.targetSha}' '${gatewayToken}'
`)
  await chmod(sshPath, 0o755)
  let observingErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', release.targetSha,
      '--repo', release.repo,
      '--allowed-signers', release.allowedSigners,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--gateway-evidence', gatewayEvidence,
      '--gateway-manifest', release.manifestPath,
      '--gateway-window-state', gatewayWindowState,
      '--known-hosts', knownHostsPath,
      '--evidence', evidencePath,
      '--timeout-ms', '600000',
      '--interval-ms', '5000'
    ])
  } catch (err) {
    observingErr = err
  }
  t.is(observingErr?.code, 2, 'an incomplete continuity window exits with observing status')
  t.ok(observingErr.stderr.includes('observation window is incomplete'))
  const observingEvidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.is(observingEvidence.status, 'observing')
  t.is(observingEvidence.publicGateway.window.complete, false)
  t.is(observingEvidence.relays[0].note, 'waiting-observation-window')

  let err = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', TARGET_SHA,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--gateway-evidence', 'relative/live.json',
      '--dry-run'
    ])
  } catch (e) {
    err = e
  }
  t.ok(err)
  t.ok(err.stderr.includes('expected an absolute path'))

  // A historically complete window is no longer complete once its last
  // controller collection exceeds the signed maximum gap. A fresh token starts
  // a new window instead of reviving the stale one.
  await writeGatewayWindowState(gatewayWindowState, release, gatewayToken, {
    timelineEndMs: Date.now() - release.manifest.maxProbeGapMs - 1000
  })
  let staleWindowErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', release.targetSha,
      '--repo', release.repo,
      '--allowed-signers', release.allowedSigners,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--gateway-evidence', gatewayEvidence,
      '--gateway-manifest', release.manifestPath,
      '--gateway-window-state', gatewayWindowState,
      '--known-hosts', knownHostsPath,
      '--evidence', evidencePath,
      '--timeout-ms', '600000',
      '--interval-ms', '5000'
    ])
  } catch (err) {
    staleWindowErr = err
  }
  t.is(staleWindowErr?.code, 2, 'stale completed window returns to observing')
  const staleWindowEvidence = JSON.parse(await readFile(evidencePath, 'utf8'))
  t.absent(staleWindowEvidence.publicGateway.window.complete)

  // Relay timestamps cannot manufacture a day of continuity while the
  // controller has collected evidence for only one hour.
  await writeGatewayWindowState(gatewayWindowState, release, gatewayToken, {
    controllerWindowMs: 60 * 60 * 1000
  })
  let compressedClockErr = null
  try {
    await runCheck([
      '--target', 'v9.9.9',
      '--target-sha', release.targetSha,
      '--repo', release.repo,
      '--allowed-signers', release.allowedSigners,
      '--channel', 'canary',
      '--relays', relaysPath,
      '--channels', channelsPath,
      '--ssh-command', sshPath,
      '--gateway-evidence', gatewayEvidence,
      '--gateway-manifest', release.manifestPath,
      '--gateway-window-state', gatewayWindowState,
      '--known-hosts', knownHostsPath,
      '--evidence', evidencePath,
      '--dry-run'
    ])
  } catch (err) {
    compressedClockErr = err
  }
  t.ok(compressedClockErr)
  t.ok(compressedClockErr.stderr.includes('not fresh at controller collection time'))
})

function sh (value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'"
}

async function writeFixtureChannels (dir, overrides = {}) {
  const file = path.join(dir, 'channels.json')
  await writeFile(file, JSON.stringify({
    _doc: 'fixture channels',
    canary: 'v9.9.9',
    stable: 'v9.9.9',
    ...overrides
  }))
  return file
}

async function createGatewayReleaseRepo (dir) {
  const repo = path.join(dir, 'release-repo')
  const fleetDir = path.join(repo, 'fleet')
  const signingKey = path.join(dir, 'release-signing-key')
  const allowedSigners = path.join(fleetDir, 'allowed-signers')
  const manifestPath = 'fleet/gateway.json'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive-canary.operator.example'
  const origin = `https://${encodeHiveAppKey(Buffer.from(appKey, 'hex'))}.${suffix}`
  const peerFingerprint256 = Array(32).fill('AA').join(':')
  const entry = {
    relay: 'mock-canary',
    channel: 'canary',
    suffix,
    origin,
    connectAddress: '127.0.0.1',
    appKey,
    path: '/index.html',
    contentSha256: 'b'.repeat(64),
    driveVersion: '7',
    peerFingerprint256,
    nginxConfigSha256: 'c'.repeat(64),
    deploymentProfile: 'public-t1-gateway',
    operatorContractSha256: 'e'.repeat(64)
  }
  const manifest = {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: 'v9.9.9',
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 20 * 60 * 1000,
    cohort: [entry]
  }
  await mkdir(fleetDir, { recursive: true })
  await mkdir(path.join(repo, 'scripts'), { recursive: true })
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
  await writeFile(path.join(repo, manifestPath), manifestBytes)
  await writeFile(path.join(repo, 'package.json'), JSON.stringify({ version: '9.9.9' }) + '\n')
  await writeFile(path.join(repo, 'scripts', 'verify-public-hive-gateway-evidence.mjs'), GATEWAY_FIXTURE_VERIFIER)
  command('ssh-keygen', ['-t', 'ed25519', '-f', signingKey, '-N', '', '-q', '-C', 'release@hiverelay'])
  await writeFile(allowedSigners, `release@hiverelay ${(await readFile(signingKey + '.pub', 'utf8')).trim()}\n`)
  command('git', ['init', '-q', repo])
  command('git', ['-C', repo, 'config', 'user.name', 'tester'])
  command('git', ['-C', repo, 'config', 'user.email', 'release@hiverelay'])
  command('git', ['-C', repo, 'config', 'gpg.format', 'ssh'])
  command('git', ['-C', repo, 'add', 'package.json', manifestPath, 'fleet/allowed-signers', 'scripts/verify-public-hive-gateway-evidence.mjs'])
  command('git', ['-C', repo, 'commit', '-qm', 'gateway release'])
  command('git', ['-C', repo, '-c', `user.signingkey=${signingKey}.pub`, 'tag', '-s', '-m', 'release', 'v9.9.9'])
  return {
    repo,
    allowedSigners,
    manifestPath,
    manifestSha256: crypto.createHash('sha256').update(manifestBytes).digest('hex'),
    targetSha: command('git', ['-C', repo, 'rev-parse', 'v9.9.9^{commit}']).stdout.trim(),
    entry,
    manifest
  }
}

function gatewayRolloutTokenValue (release) {
  const now = new Date().toISOString()
  return {
    schema: 'hiverelay-public-gateway-evidence-verification-v2',
    status: 'verified',
    mode: 'fleet',
    admissionProfile: release.manifest.admissionProfile,
    publicSuffixReady: false,
    physicalEnforcementRequired: true,
    releaseTarget: 'v9.9.9',
    releaseSha: release.targetSha,
    checkedAt: now,
    probeObservedAt: now,
    origin: release.entry.origin,
    connectAddress: release.entry.connectAddress,
    appKey: release.entry.appKey,
    path: release.entry.path,
    contentSha256: release.entry.contentSha256,
    driveVersion: release.entry.driveVersion,
    tlsProtocol: 'TLSv1.3',
    peerFingerprint256: release.entry.peerFingerprint256,
    nginxSha256: release.entry.nginxConfigSha256,
    checks: {
      metadata: true,
      exactBytes: true,
      range: true,
      head: true,
      canonicalIdentity: true,
      managementIsolation: true,
      forwardedHostIsolation: true,
      unavailableAppIsolation: true,
      defaultSniRejection: true,
      sniHostBinding: true
    },
    evidenceSha256: 'd'.repeat(64)
  }
}

function gatewayRolloutToken (release) {
  return Buffer.from(JSON.stringify(gatewayRolloutTokenValue(release))).toString('base64url')
}

async function writeGatewayWindowState (file, release, encodedToken, opts = {}) {
  const token = JSON.parse(Buffer.from(encodedToken, 'base64url').toString('utf8'))
  const windowMs = release.manifest.observationWindowMs
  const end = opts.timelineEndMs ?? Date.parse(token.probeObservedAt)
  const controllerWindowMs = opts.controllerWindowMs ?? windowMs
  const controllerEnd = opts.controllerEndMs ?? end
  const samples = []
  for (let offset = 24 * 60; offset >= 0; offset -= 20) {
    const observedAt = new Date(end - offset * 60 * 1000).toISOString()
    const collectedAt = controllerWindowMs === windowMs && controllerEnd === end
      ? observedAt
      : new Date(controllerEnd - Math.round((offset * 60 * 1000 / windowMs) * controllerWindowMs)).toISOString()
    samples.push({
      observedAt,
      collectedAt,
      evidenceSha256: offset === 0
        ? token.evidenceSha256
        : crypto.createHash('sha256').update(`gateway-sample-${offset}`).digest('hex')
    })
  }
  await writeFile(file, JSON.stringify({
    schema: 'hiverelay-public-gateway-window-state-v1',
    releaseTarget: 'v9.9.9',
    releaseSha: release.targetSha,
    channel: 'canary',
    manifestSha256: release.manifestSha256,
    observationWindowMs: release.manifest.observationWindowMs,
    maxProbeGapMs: release.manifest.maxProbeGapMs,
    cohortNames: ['mock-canary'],
    relays: [{ name: 'mock-canary', samples }]
  }, null, 2) + '\n')
}

function command (name, args) {
  const result = spawnSync(name, args, { encoding: 'utf8', timeout: 20000 })
  if (result.status !== 0) throw new Error(`${name} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  return result
}
