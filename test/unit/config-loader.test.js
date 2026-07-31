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

test('config loader: a default relay grants anonymous peers the anonymous role', async (t) => {
  // Regression guard for a security default that silently reverted. Commit
  // 9125f3c set 'anonymous' in relay-node/index.js and bare-relay.js but not in
  // config/default.js — and config/default.js is the one the CLI loads, merged
  // last, so it won. Every default install was back on 'authenticated-user',
  // which hands any anonymous swarm peer the rights of a known user (notably
  // arbitration.submit, whose pending Map is uncapped).
  //
  // Nothing asserted this value in either file, which is exactly why the
  // revert went unnoticed. Assert the EFFECTIVE value, not the literal, so this
  // still fails if the precedence between the two defaults changes again.
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-peer-role-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { loadConfig } = await importLoaderWithHome(home)

  t.is(loadConfig().serviceDefaultPeerRole, 'anonymous',
    'default install must not grant authenticated-user to anonymous peers')
  t.is(loadConfig({ serviceDefaultPeerRole: 'authenticated-user' }).serviceDefaultPeerRole,
    'authenticated-user',
    'an operator can still raise it deliberately')
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

test('cli start keeps HIVERELAY_MAX_STORAGE explicit until a cap is persisted', async (t) => {
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
  t.ok(saved.stdout.includes('Max Store:  10.0 GB'), 'an unrelated config file does not erase the env designation')

  await writeFile(path.join(configDir, 'config.json'), JSON.stringify({ maxStorageBytes: 50 * 1024 ** 3 }, null, 2) + '\n')
  const persisted = await execCliUntil(startArgs, {
    ...process.env,
    HOME: savedHome,
    HIVERELAY_MAX_STORAGE: '10GB'
  }, 'Max Store:')

  t.ok(persisted.sawNeedle)
  t.ok(persisted.stdout.includes('Max Store:  50.0 GB'), 'persisted explicit cap wins over env')
})

test('cli start preserves an explicit --max-storage equal to 50 GiB', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-explicit-default-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCliUntil([
    'start',
    '--max-storage', '50GB',
    '--no-api',
    '--no-relay',
    '--no-seeding',
    '--quiet'
  ], { ...process.env, HOME: home }, 'Max Store:')

  t.ok(res.sawNeedle)
  t.ok(res.stdout.includes('Max Store:  50.0 GB'))
})

test('cli restart with --no-seeding recovers existing bare-core debt without serving it', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-no-seeding-recovery-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })
  const storage = path.join(home, '.hiverelay', 'storage')
  await mkdir(storage, { recursive: true })
  await writeFile(path.join(storage, 'seeded-cores.json'), JSON.stringify({
    schemaVersion: 3,
    cores: [{
      key: 'a'.repeat(64),
      maxStorageBytes: 1024 * 1024,
      state: 'bounded'
    }]
  }))

  const res = await execCliUntil([
    'start',
    '--no-api',
    '--no-relay',
    '--no-seeding',
    '--quiet'
  ], { ...process.env, HOME: home }, 'Node is running.')

  t.ok(res.sawNeedle, 'core inventory sealed without starting Seeder serving')
  t.ok(res.stdout.includes('Seeding:    disabled'))
})

test('config loader: explicit-equals-default persists and reloads its provenance', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-config-cap-explicit-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const {
    getStorageCapProvenance,
    loadConfig,
    resolveStorageCap,
    saveConfig
  } = await importLoaderWithHome(home)
  const bytes = 50 * 1024 ** 3
  const config = loadConfig({ maxStorageBytes: bytes })
  resolveStorageCap(config, {
    stat: () => ({ dev: 9, isDirectory: () => true }),
    realpath: p => p,
    statfs: () => ({ blocks: 100 * 1024 ** 3, bavail: 5 * 1024 ** 3, bsize: 1 }),
    measureStorageBytes: () => 0
  })

  t.is(config.maxStorageBytes, bytes, 'low available space never enlarges or rewrites explicit bytes')
  saveConfig(config)
  const saved = JSON.parse(await readFile(path.join(home, '.hiverelay', 'config.json'), 'utf8'))
  t.is(saved.maxStorageBytes, bytes, 'numeric equality with the default is still persisted')

  const restarted = loadConfig()
  t.is(restarted.maxStorageBytes, bytes)
  t.is(getStorageCapProvenance(restarted).explicit, true)
  t.is(getStorageCapProvenance(restarted).source, 'persisted')
})

test('config loader: setup-style plain config persists explicit 50 GiB', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-config-cap-setup-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { saveConfig } = await importLoaderWithHome(home)
  saveConfig({ maxStorageBytes: 50 * 1024 ** 3 })
  const saved = JSON.parse(await readFile(path.join(home, '.hiverelay', 'config.json'), 'utf8'))
  t.is(saved.maxStorageBytes, 50 * 1024 ** 3)
})

test('config loader: a resolved unset cap is not persisted as an operator designation', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-config-cap-derived-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { loadConfig, resolveStorageCap, saveConfig } = await importLoaderWithHome(home)
  const config = loadConfig()
  resolveStorageCap(config, {
    stat: () => ({ dev: 10, isDirectory: () => true }),
    realpath: p => p,
    statfs: () => ({ blocks: 100 * 1024 ** 3, bavail: 18 * 1024 ** 3, bsize: 1 }),
    measureStorageBytes: () => 0
  })
  t.is(config.maxStorageBytes, 8 * 1024 ** 3)

  saveConfig(config)
  const saved = JSON.parse(await readFile(path.join(home, '.hiverelay', 'config.json'), 'utf8'))
  t.absent(Object.prototype.hasOwnProperty.call(saved, 'maxStorageBytes'), 'derived value stays derived after restart')
})

test('cli init persists an explicit cap equal to the built-in default', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-init-cap-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const res = await execCli(['init', '--max-storage', '50GB'], { ...process.env, HOME: home })
  t.is(res.code, 0)
  const saved = JSON.parse(await readFile(path.join(home, '.hiverelay', 'config.json'), 'utf8'))
  t.is(saved.maxStorageBytes, 50 * 1024 ** 3)
})

test('cli start uses HIVERELAY_STORAGE when --storage is absent', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-cli-storage-env-'))
  const storage = path.join(home, 'env-storage')
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })
  await mkdir(storage, { recursive: true })

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
  await mkdir(envStorage, { recursive: true })
  await mkdir(flagStorage, { recursive: true })

  const res = await execCliUntil(['start', '--storage', flagStorage, '--no-api', '--no-relay', '--no-seeding', '--quiet'], {
    ...process.env,
    HOME: home,
    HIVERELAY_STORAGE: envStorage
  }, 'Storage:')

  t.ok(res.sawNeedle)
  t.ok(res.stdout.includes(`Storage:    ${flagStorage}`))
  t.absent(res.stdout.includes(`Storage:    ${envStorage}`))
})

test('applyOutboxlogNamespaceEnv: env sets config.outboxlog.namespace on a fresh box', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-outboxlog-ns-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { loadConfig, applyOutboxlogNamespaceEnv } = await importLoaderWithHome(home)

  // Fresh box (no persisted config.json) → env is applied.
  const cliOverrides = {}
  applyOutboxlogNamespaceEnv(cliOverrides, 'peerit', false)
  t.is(cliOverrides.outboxlog.namespace, 'peerit', 'env value lands on cliOverrides')

  const config = loadConfig(cliOverrides)
  t.is(config.outboxlog.namespace, 'peerit', 'loadConfig surfaces it as config.outboxlog.namespace')
})

test('applyOutboxlogNamespaceEnv: unset env leaves config unchanged (default behavior)', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-outboxlog-ns-unset-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const { loadConfig, applyOutboxlogNamespaceEnv } = await importLoaderWithHome(home)

  const cliOverrides = {}
  applyOutboxlogNamespaceEnv(cliOverrides, undefined, false)
  t.absent(cliOverrides.outboxlog, 'no env → no outboxlog override created')

  const config = loadConfig(cliOverrides)
  // Default config carries no outboxlog.namespace; the engine falls back to
  // the app-neutral DEFAULT_OUTBOXLOG_NAMESPACE. Assert we did not invent one.
  t.absent(config.outboxlog && config.outboxlog.namespace, 'default config has no forced namespace')
})

test('applyOutboxlogNamespaceEnv: a persisted config.json namespace wins over env (precedence)', async (t) => {
  const home = await mkdtemp(path.join(tmpdir(), 'hiverelay-outboxlog-ns-persisted-'))
  t.teardown(async () => {
    await rm(home, { recursive: true, force: true })
  })

  const configDir = path.join(home, '.hiverelay')
  await mkdir(configDir, { recursive: true })
  await writeFile(
    path.join(configDir, 'config.json'),
    JSON.stringify({ outboxlog: { namespace: 'saved-ns' } }, null, 2) + '\n'
  )

  const { loadConfig, applyOutboxlogNamespaceEnv } = await importLoaderWithHome(home)

  // hasPersistedNamespace === true → env is a no-op, the saved value survives.
  const cliOverrides = {}
  applyOutboxlogNamespaceEnv(cliOverrides, 'peerit', true)
  t.absent(cliOverrides.outboxlog, 'env skipped when a namespace is already persisted')

  const config = loadConfig(cliOverrides)
  t.is(config.outboxlog.namespace, 'saved-ns', 'persisted namespace wins over the env default')
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
