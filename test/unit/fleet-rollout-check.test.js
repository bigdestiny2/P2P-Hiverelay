import test from 'brittle'
import { execFile } from 'node:child_process'
import crypto from 'node:crypto'
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const TARGET_SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

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
})

test('fleet rollout check verifies target sha and health through ssh probe', async (t) => {
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
    '--channel', 'canary',
    '--relays', relaysPath,
    '--channels', channelsPath,
    '--ssh-command', sshPath,
    '--evidence', evidencePath,
    '--timeout-ms', '600000',
    '--interval-ms', '5000'
  ])

  t.ok(stdout.includes('Checking 1 relay(s) on channel canary: mock-canary'))
  t.ok(stdout.includes('Fleet rollout verified: 1/1 relay(s) on v9.9.9'))

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
  t.is(evidence.relays[0].name, 'mock-canary')
  t.is(evidence.relays[0].headSha, TARGET_SHA)
  t.is(evidence.relays[0].healthVersion, '9.9.9')
  t.is(evidence.relays[0].packageVersionMatches, true)
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
