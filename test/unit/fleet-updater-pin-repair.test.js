import test from 'brittle'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'

const root = path.resolve('.')
const repair = path.join(root, 'scripts', 'repair-fleet-updater-pin.mjs')
const updater = path.join(root, 'fleet', 'updater.sh')
const applyHelper = readFileSync(path.join(root, 'scripts', 'lib', 'repair-fleet-updater-apply.sh'), 'utf8')

test('fleet updater pin repair is exact-target, dry-run-first, and application-immutable', (t) => {
  const work = mkdtempSync(path.join(tmpdir(), 'hr-fleet-pin-repair-'))
  t.teardown(() => rmSync(work, { recursive: true, force: true }))
  const bin = path.join(work, 'bin')
  const inventory = path.join(work, 'relays.json')
  const log = path.join(work, 'commands.log')
  mkdirSync(bin)

  writeFileSync(inventory, JSON.stringify({
    relays: [
      { name: 'utah-8gb', publicIp: '10.0.0.8', sshKey: 'default' },
      { name: 'sydney', publicIp: '10.0.0.9', sshKey: 'default' },
      { name: 'dallas', publicIp: '10.0.0.10', sshKey: 'default' }
    ]
  }))

  const ssh = path.join(bin, 'ssh')
  const scp = path.join(bin, 'scp')
  writeFileSync(ssh, `#!/bin/sh
printf 'ssh %s\\n' "$*" >> "$FLEET_REPAIR_TEST_LOG"
payload="$(cat)"
printf '%s\\n' "$payload" >> "$FLEET_REPAIR_TEST_LOG"
case "$payload" in
  *HIVERELAY_REPAIR_PROBE*) printf 'HIVERELAY_REPAIR_PROBE|v0.25.0-rc.4|true|disabled|inactive|stable|-|true|true|0.25.0-rc.4|true|true\\n' ;;
  *HIVERELAY_REPAIR_OK*) printf 'HIVERELAY_REPAIR_OK|v0.25.0-rc.4|v0.25.0-rc.4|enabled|active\\n' ;;
esac
`)
  writeFileSync(scp, `#!/bin/sh
printf 'scp %s\\n' "$*" >> "$FLEET_REPAIR_TEST_LOG"
`)
  chmodSync(ssh, 0o755)
  chmodSync(scp, 0o755)

  const run = (args) => spawnSync(process.execPath, [repair, '--inventory', inventory, '--updater', updater, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      FLEET_REPAIR_TEST_LOG: log
    }
  })

  const dryRun = run(['--relay', 'utah-8gb', '--pin', 'v0.25.0-rc.4'])
  t.is(dryRun.status, 0, 'default probe succeeds')
  const proof = JSON.parse(dryRun.stdout)
  t.is(proof.relay, 'utah-8gb')
  t.is(proof.mutation, false, 'default mode is read-only')
  t.is(proof.verification.readyToApply, true, 'probe proves signature, HEAD, and health alignment')
  let calls = readFileSync(log, 'utf8')
  t.ok(calls.includes('root@10.0.0.8'))
  t.absent(calls.includes('10.0.0.9'), 'Sydney is never contacted')
  t.absent(calls.includes('10.0.0.10'), 'Dallas is never contacted')
  t.absent(calls.includes('\nscp '), 'dry run transfers nothing')

  writeFileSync(log, '')
  const unconfirmed = run(['--relay', 'utah-8gb', '--pin', 'v0.25.0-rc.4', '--apply'])
  t.not(unconfirmed.status, 0, 'apply fails without repeated exact relay confirmation')
  t.is(readFileSync(log, 'utf8'), '', 'failed confirmation opens no connection')

  const applied = run([
    '--relay', 'utah-8gb',
    '--pin', 'v0.25.0-rc.4',
    '--channel', 'stable',
    '--apply',
    '--confirm-relay', 'utah-8gb'
  ])
  t.is(applied.status, 0, 'confirmed exact-target apply reaches the remote transaction')
  calls = readFileSync(log, 'utf8')
  t.ok(calls.includes('scp '), 'apply transfers the audited updater')
  t.ok(calls.includes('root@10.0.0.8'))
  t.absent(calls.includes('10.0.0.9'))
  t.absent(calls.includes('10.0.0.10'))
  t.ok(calls.includes('refusing application mutation'))
  t.ok(calls.includes('git rev-parse HEAD'))
  t.ok(calls.includes('systemctl enable --now hiverelay-updater.timer'))
})

test('remote updater pin repair rolls back control-plane state and never restarts the application', (t) => {
  t.ok(applyHelper.includes("trap 'cleanup $?' EXIT"))
  t.ok(applyHelper.includes('install -m 0755 "$backup" "$updater"'))
  t.ok(applyHelper.includes('install -m 0644 "$config_backup" "$conf"'))
  t.ok(applyHelper.includes('systemctl disable --now hiverelay-updater.timer'))
  t.ok(applyHelper.includes('HIVERELAY_ALLOWED_SIGNERS="$allowed"'))
  t.ok(applyHelper.includes('bash "$candidate" --verify-only "$pin"'))
  t.ok(applyHelper.includes('git status --porcelain=v1 --untracked-files=normal'))
  t.ok(applyHelper.includes('[ "$current_sha" = "$target_sha" ]'))
  t.ok(applyHelper.includes('[ "$(git rev-parse HEAD)" = "$current_sha" ]'))
  t.absent(applyHelper.includes('systemctl restart hiverelay'))
  t.absent(applyHelper.includes('systemctl restart "$SERVICE"'))
})
