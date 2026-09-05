import test from 'brittle'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const fixture = fileURLToPath(new URL('./fixtures/offline-discovery-shutdown.mjs', import.meta.url))

for (const mode of ['enabled', 'disabled', 'online', 'pending-success', 'pending-failure', 'cancel-failure', 'rollback']) {
  test('RelayNode offline discovery shutdown: ' + mode, async t => {
    const child = spawn(process.execPath, [fixture, mode], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', data => { stdout += data })
    child.stderr.on('data', data => { stderr += data })
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, 18000)
    const [code, signal] = await new Promise((resolve, reject) => {
      child.once('error', reject)
      child.once('close', (code, signal) => resolve([code, signal]))
    }).finally(() => clearTimeout(timer))
    t.absent(timedOut, 'real transport process exits without retained timers')
    t.is(code, 0, stderr || 'child exits successfully')
    t.is(signal, null)
    const receipt = stdout.trim() ? JSON.parse(stdout.trim().split('\n').pop()) : null
    t.ok(receipt?.ok, 'structured lifecycle receipt')
    t.comment(JSON.stringify({ ...receipt, stderr }))
  })
}
