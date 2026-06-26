import test from 'brittle'
import { execFile, spawn } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

async function importLoaderWithHome (home) {
  const oldHome = process.env.HOME
  process.env.HOME = home
  try {
    const url = pathToFileURL(path.resolve('packages/core/config/loader.js'))
    url.searchParams.set('t', `${Date.now()}-${Math.random()}`)
    return await import(url.href)
  } finally {
    if (oldHome === undefined) delete process.env.HOME
    else process.env.HOME = oldHome
  }
}

test('config loader: saving nested default edits does not mutate defaults away', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-config-loader-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { loadConfig, saveConfig } = await importLoaderWithHome(home)
  const config = loadConfig()
  config.subsidy.payoutDestination = 'operator@example.com'

  const savedPath = saveConfig(config)
  const saved = JSON.parse(await readFile(savedPath, 'utf8'))

  t.is(saved.subsidy.payoutDestination, 'operator@example.com')
  t.is(loadConfig().subsidy.payoutDestination, 'operator@example.com')
})

test('cli start rejects invalid HIVERELAY_ACCEPT_MODE before boot', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-env-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCli(['start'], {
    ...process.env,
    HOME: home,
    HIVERELAY_ACCEPT_MODE: 'surprise'
  })

  t.is(res.code, 1)
  t.ok(res.stderr.includes('Invalid HIVERELAY_ACCEPT_MODE'))
})

test('cli start rejects invalid HIVERELAY_MAX_STORAGE before boot', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-env-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCli(['start'], {
    ...process.env,
    HOME: home,
    HIVERELAY_MAX_STORAGE: 'ten-ish'
  })

  t.is(res.code, 1)
  t.ok(res.stderr.includes('Invalid HIVERELAY_MAX_STORAGE'))
})

test('cli start uses HIVERELAY_MAX_STORAGE only before saved operator config exists', async (t) => {
  const freshHome = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-env-fresh-'))
  const savedHome = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-env-saved-'))
  t.teardown(async () => {
    await rm(freshHome, { recursive: true, force: true })
    await rm(savedHome, { recursive: true, force: true })
  })

  const startArgs = ['start', '--no-api', '--no-relay', '--no-seeding', '--quiet']
  const fresh = await execCliUntil(startArgs, {
    ...process.env,
    HOME: freshHome,
    HIVERELAY_MAX_STORAGE: '10GB'
  }, 'Max Store:')

  t.ok(fresh.sawNeedle)
  t.ok(fresh.stdout.includes('Max Store:  10.0 GB'))

  const configDir = path.join(savedHome, '.hiverelay')
  await mkdir(configDir, { recursive: true })
  await writeFile(path.join(configDir, 'config.json'), JSON.stringify({ maxConnections: 64 }, null, 2) + '\n')

  const saved = await execCliUntil(startArgs, {
    ...process.env,
    HOME: savedHome,
    HIVERELAY_MAX_STORAGE: '10GB'
  }, 'Max Store:')

  t.ok(saved.sawNeedle)
  t.ok(saved.stdout.includes('Max Store:  50.0 GB'))
})

test('cli start uses HIVERELAY_STORAGE when --storage is absent', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-storage-env-'))
  const storage = path.join(home, 'env-storage')
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCliUntil(['start', '--no-api', '--no-relay', '--no-seeding', '--quiet'], {
    ...process.env,
    HOME: home,
    HIVERELAY_STORAGE: storage
  }, 'Storage:')

  t.ok(res.sawNeedle)
  t.ok(res.stdout.includes(`Storage:    ${storage}`))
})

test('cli start --storage overrides HIVERELAY_STORAGE', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-storage-flag-'))
  const envStorage = path.join(home, 'env-storage')
  const flagStorage = path.join(home, 'flag-storage')
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCliUntil(['start', '--storage', flagStorage, '--no-api', '--no-relay', '--no-seeding', '--quiet'], {
    ...process.env,
    HOME: home,
    HIVERELAY_STORAGE: envStorage
  }, 'Storage:')

  t.ok(res.sawNeedle)
  t.ok(res.stdout.includes(`Storage:    ${flagStorage}`))
  t.absent(res.stdout.includes(`Storage:    ${envStorage}`))
})

function execCli (argv, env) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['packages/core/cli/index.js', ...argv], {
      cwd: process.cwd(),
      env,
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err && err.killed) return reject(err)
      resolve({
        code: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

function execCliUntil (argv, env, needle, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['packages/core/cli/index.js', ...argv], {
      cwd: process.cwd(),
      env
    })
    let stdout = ''
    let stderr = ''
    let sawNeedle = false
    let timedOut = false
    let closed = false
    let forceTimer = null

    const stopChild = () => {
      if (!child.killed) child.kill('SIGTERM')
      forceTimer = setTimeout(() => {
        if (!closed) child.kill('SIGKILL')
      }, 1000)
      if (forceTimer.unref) forceTimer.unref()
    }

    const timer = setTimeout(() => {
      timedOut = true
      stopChild()
    }, timeoutMs)
    if (timer.unref) timer.unref()

    child.stdout.on('data', (chunk) => {
      stdout += chunk
      if (!sawNeedle && stdout.includes(needle)) {
        sawNeedle = true
        stopChild()
      }
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', reject)
    child.on('close', (code, signal) => {
      closed = true
      clearTimeout(timer)
      if (forceTimer) clearTimeout(forceTimer)
      const result = { code, signal, stdout, stderr, sawNeedle }
      if (timedOut) {
        const err = new Error(`Timed out waiting for CLI output: ${needle}`)
        Object.assign(err, result)
        reject(err)
        return
      }
      resolve(result)
    })
  })
}
