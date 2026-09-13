// Explicit local-only smoke for the source development command. No public DHT
// bootstrap or fleet is used; the CLI creates an isolated localhost testnet.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import os from 'node:os'
import { once } from 'node:events'
import { stripVTControlCharacters } from 'node:util'

const root = path.resolve(process.argv[2] || process.cwd())
const results = []
for (const noClient of [true, false]) {
  const reserve = net.createServer()
  reserve.listen(0, '127.0.0.1')
  await once(reserve, 'listening')
  const port = reserve.address().port
  await new Promise(resolve => reserve.close(resolve))
  const args = ['packages/core/cli/index.js', 'testnet', '--nodes', '1', '--port', String(port), ...(noClient ? ['--no-client'] : [])]
  const child = spawn(process.execPath, args, { cwd: root, env: { ...process.env, NODE_PATH: '', NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'] })
  let output = ''
  let ready = false
  let health = null
  let stopped = false
  let rejectReady, resolveReady
  const readyPromise = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  const timer = setTimeout(() => { child.kill('SIGTERM'); rejectReady(new Error('local source testnet timed out')) }, 90000)
  const observe = bytes => {
    output += bytes.toString()
    if (!ready && output.includes('Press Ctrl+C to shut down the testnet.')) { ready = true; resolveReady() }
  }
  child.stdout.on('data', observe); child.stderr.on('data', observe)
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => { if (!ready) rejectReady(new Error(`source testnet exited ${code}/${signal}: ${output}`)); resolve({ code, signal }) })
  })
  try {
    await readyPromise
    const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(5000) })
    assert.equal(response.status, 200)
    health = await response.json()
    const storage = stripVTControlCharacters(output).match(/Storage:\s+([^\r\n]+)/)?.[1]?.trim()
    assert(storage?.startsWith(path.join(os.tmpdir(), 'hiverelay-testnet-')))
    child.kill('SIGINT')
    const exit = await exited
    stopped = true
    assert(exit.code === 0 || (exit.code === null && exit.signal === 'SIGINT'), output)
    assert.match(output, /Testnet stopped\./)
    assert.equal(fs.existsSync(storage), false, 'ephemeral source-testnet storage was removed')
    if (noClient) assert.doesNotMatch(output, /Starting test client/)
    else {
      assert.match(output, /Starting test client/)
      assert.match(output, /seeded! 1 relay\(s\) accepted/)
      assert.match(output, /read back \/hello.txt: "Hello from HiveRelay testnet!"/)
    }
    results.push({ noClient, args, status: 'passed', health, gracefulExit: exit, storageRemoved: true, output })
  } finally {
    clearTimeout(timer)
    if (!stopped) child.kill('SIGTERM')
  }
}
console.log(JSON.stringify({ status: 'passed', source: root, scenarios: results }, null, 2))
