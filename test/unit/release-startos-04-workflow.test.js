import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const WORKFLOW = path.join(process.cwd(), '.github/workflows/release-startos-0.4.yml')

test('StartOS 0.4 release workflow copies the generated ephemeral key', async (t) => {
  const fixture = await workflowFixture(t, 'generated-key')
  const result = await runConfigureKey(fixture, '')

  t.is(result.status, 0)
  t.is(await readFile(path.join(fixture.work, '.startos/build-key'), 'utf8'), 'ephemeral-key')
  t.is((await stat(path.join(fixture.work, '.startos/build-key'))).mode & 0o777, 0o600)
})

test('StartOS 0.4 release workflow keeps the configured developer key path', async (t) => {
  const fixture = await workflowFixture(t, 'unexpected-cli')
  const result = await runConfigureKey(fixture, 'configured-key')

  t.is(result.status, 0)
  t.is(await readFile(path.join(fixture.home, '.startos/developer.key.pem'), 'utf8'), 'configured-key')
  t.is(await readFile(path.join(fixture.work, '.startos/build-key'), 'utf8'), 'configured-key')
})

test('StartOS 0.4 release workflow fails closed when key generation writes no key', async (t) => {
  const fixture = await workflowFixture(t, 'missing-key')
  const result = await runConfigureKey(fixture, '')

  t.is(result.status, 1)
  t.ok(result.stderr.includes('StartOS developer key is missing or empty'))
})

async function workflowFixture (t, startCliMode) {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-workflow-'))
  t.teardown(async () => {
    await rm(root, { recursive: true, force: true })
  })

  const home = path.join(root, 'home')
  const work = path.join(root, 'startos-0.4')
  const bin = path.join(root, 'bin')
  await Promise.all([mkdir(home), mkdir(work), mkdir(bin)])

  const startCli = path.join(bin, 'start-cli')
  await writeFile(startCli, startCliStub(startCliMode))
  await chmod(startCli, 0o755)

  return { bin, home, work }
}

function startCliStub (mode) {
  if (mode === 'generated-key') {
    return '#!/bin/sh\nset -eu\n[ "$1" = "init-key" ]\nmkdir -p "$HOME/.startos"\nprintf %s ephemeral-key > "$HOME/.startos/id.key.pem"\n'
  }
  if (mode === 'missing-key') return '#!/bin/sh\nexit 0\n'
  return '#!/bin/sh\nexit 97\n'
}

async function runConfigureKey (fixture, secret) {
  const script = await configureKeyScript()
  return new Promise((resolve) => {
    execFile('/bin/bash', ['-c', script], {
      cwd: fixture.work,
      env: {
        HOME: fixture.home,
        PATH: `${fixture.bin}:${process.env.PATH || ''}`,
        STARTOS_DEV_KEY: secret
      },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

async function configureKeyScript () {
  const workflow = await readFile(WORKFLOW, 'utf8')
  const stepStart = workflow.indexOf('      - name: Configure StartOS developer key')
  const nextStep = workflow.indexOf('\n      - name:', stepStart + 1)
  const step = workflow.slice(stepStart, nextStep)
  const marker = '        run: |\n'
  const runStart = step.indexOf(marker)
  if (stepStart < 0 || nextStep < 0 || runStart < 0) throw new Error('Configure StartOS developer key run block is missing')

  const indented = step.slice(runStart + marker.length).trimEnd()
  if (indented.split('\n').some(line => !line.startsWith('          '))) {
    throw new Error('Configure StartOS developer key run block has unexpected indentation')
  }
  return indented.replace(/^ {10}/gm, '') + '\n'
}
