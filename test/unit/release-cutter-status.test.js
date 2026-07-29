import test from 'brittle'
import { spawn } from 'node:child_process'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { delimiter, join } from 'node:path'
import { tmpdir } from 'node:os'

function runRelease (args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('bash', ['scripts/release.sh', ...args], {
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

async function fakeKeyvault (t, state, hasKey) {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-release-status-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const keyvault = join(dir, 'keyvault')
  await writeFile(keyvault, `#!/bin/sh
case "$1" in
  status) printf '%s\n' '${state}'; exit 0 ;;
  get) ${hasKey ? "printf '%s\\n' 'FAKE-KEY'; exit 0" : 'exit 1'} ;;
esac
exit 1
`)
  await chmod(keyvault, 0o755)
  return `${dir}${delimiter}${process.env.PATH || ''}`
}

test('release status distinguishes a locked vault from an absent signing key', async (t) => {
  const path = await fakeKeyvault(t, 'locked: no agent running for test vault', false)
  const result = await runRelease(['status'], {
    PATH: path,
    HIVERELAY_RELEASE_SIGNER_EMAIL: 'bigdestiny2@users.noreply.github.com'
  })
  t.is(result.code, 0)
  t.ok(result.stdout.includes('signing key:    unavailable while vault is locked'))
  t.absent(result.stdout.includes('NOT found in unlocked vault'))
  t.ok(result.stdout.includes('(trusted by fleet/allowed-signers)'))
})

test('release status reports a missing key only when the vault is unlocked', async (t) => {
  const path = await fakeKeyvault(t, 'unlocked: agent ready', false)
  const result = await runRelease(['status'], {
    PATH: path,
    HIVERELAY_RELEASE_SIGNER_EMAIL: 'not-trusted@example.com'
  })
  t.is(result.code, 0)
  t.ok(result.stdout.includes('signing key:    NOT found in unlocked vault'))
  t.ok(result.stdout.includes('(NOT trusted by fleet/allowed-signers)'))
})

test('release status recognizes a key in an unlocked vault', async (t) => {
  const path = await fakeKeyvault(t, 'unlocked: agent ready', true)
  const result = await runRelease(['status'], {
    PATH: path,
    HIVERELAY_RELEASE_SIGNER_EMAIL: 'bigdestiny2@users.noreply.github.com'
  })
  t.is(result.code, 0)
  t.ok(result.stdout.includes('signing key:    present in vault (hiverelay-release/tag-signing-key)'))
})

test('release setup refuses to infer key absence from a locked vault', async (t) => {
  const path = await fakeKeyvault(t, 'locked: no agent running for test vault', false)
  const result = await runRelease(['setup'], {
    PATH: path,
    HIVERELAY_RELEASE_SIGNER_EMAIL: 'bigdestiny2@users.noreply.github.com'
  })
  t.is(result.code, 1)
  t.ok(result.stderr.includes('setup cannot prove the signing key is absent'))
})

test('release cut rejects an untrusted signer principal before tagging', async (t) => {
  const result = await runRelease(['cut', 'v0.25.0-rc.8', '-y'], {
    HIVERELAY_RELEASE_SIGNER_EMAIL: 'not-trusted@example.com'
  })
  t.is(result.code, 1)
  t.ok(result.stderr.includes("signer principal 'not-trusted@example.com' is not trusted"))
})
