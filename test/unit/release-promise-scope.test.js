import test from 'brittle'
import { execFile } from 'child_process'
import { readFile } from 'fs/promises'
import {
  assertNarrowReleasePromise,
  findOverbroadReleasePromises,
  NARROW_RELEASE_PROMISE_LABEL
} from '../../scripts/lib/release-promise-scope.mjs'
import {
  checkReleasePromiseScope
} from '../../scripts/check-release-promise-scope.mjs'

function runScript (args = []) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-release-promise-scope.mjs', ...args], {
      cwd: process.cwd(),
      env: process.env
    }, (error, stdout, stderr) => {
      resolve({
        code: error && typeof error.code === 'number' ? error.code : 0,
        stdout,
        stderr
      })
    })
  })
}

test('release-promise scope audit is exposed as a package command', async (t) => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'))
  t.is(pkg.scripts['audit:release-promise'], 'node scripts/check-release-promise-scope.mjs')
})

test('release-promise scope accepts current public handoff surfaces', (t) => {
  const report = checkReleasePromiseScope()

  t.is(report.status, 'pass')
  t.is(report.scope, NARROW_RELEASE_PROMISE_LABEL)
  t.ok(report.items.some(item => item.id === 'prepare-release.default-notes'))
  t.ok(report.items.some(item => item.id === 'release-surfaces.official-umbrel-pr-body'))
})

test('release-promise scope rejects overbroad product claims', (t) => {
  const findings = findOverbroadReleasePromises('Launch the AI poker custody marketplace now.')

  t.ok(findings.some(finding => finding.name === 'AI/QVAC/Ollama product claim'))
  t.ok(findings.some(finding => finding.name === 'poker product claim'))
  t.ok(findings.some(finding => finding.name === 'custody product claim'))
  t.exception(
    () => assertNarrowReleasePromise('Launch the AI poker custody marketplace now.', { label: 'release notes' }),
    /release notes must stay scoped/
  )
})

test('release-promise scope CLI emits JSON and fails overbroad inline text', async (t) => {
  const ok = await runScript(['--json'])
  t.is(ok.code, 0)
  t.is(ok.stderr, '')
  t.is(JSON.parse(ok.stdout).status, 'pass')

  const bad = await runScript(['--text', 'Promotes AI poker custody as the public release.'])
  t.is(bad.code, 1)
  t.ok(bad.stdout.includes('AI/QVAC/Ollama product claim'))
  t.ok(bad.stdout.includes('poker product claim'))
  t.ok(bad.stdout.includes('custody product claim'))
})
