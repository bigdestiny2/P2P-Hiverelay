import test from 'brittle'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const child = new URL('../fixtures/blind-reserved-profile-child.mjs', import.meta.url)

test('reserved release operations fail closed in independent runtime processes', async t => {
  const reports = await Promise.all(Array.from({ length: 3 }, async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [child.pathname], {
      maxBuffer: 1024 * 1024,
      timeout: 30_000
    })
    t.is(stderr, '')
    return JSON.parse(stdout)
  }))
  t.is(new Set(reports.map(report => report.pid)).size, 3)
  for (const report of reports) {
    t.is(report.realEdgeProcess, true)
    t.is(report.daemonConnections, 0)
    t.is(report.results.length, 5)
    t.ok(report.results.every(result =>
      result.clientRejected && result.daemonRejected && result.budgetRejected &&
      result.edgeStatus === 400 && result.edgeReleasedMemory))
  }
})
