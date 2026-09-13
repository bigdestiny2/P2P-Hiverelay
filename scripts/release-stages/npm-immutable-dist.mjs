import { setTimeout as sleepTimer } from 'node:timers/promises'
import { execOutputWithTimeout, normalizeNpmCommandError } from '../ensure-npm-dist-tag.mjs'

export async function waitForImmutableNpmDist ({ packageName, version, expected, attempts = 12, initialDelayMs = 2000, maxDelayMs = 15000, readDist, sleep = sleepTimer }) {
  for (const value of [attempts, initialDelayMs, maxDelayMs]) if (!Number.isSafeInteger(value) || value < 1) throw new TypeError('Bounded visibility retry limits required')
  const read = readDist || (async () => JSON.parse(await execOutputWithTimeout('npm', ['view', `${packageName}@${version}`, 'dist', '--json'], { timeoutMs: 30000 })))
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let actual
    try { actual = await read() } catch (error) {
      // Retry only the explicit npm absence response; transport/auth ambiguity
      // cannot authorize a tag change or substitute immutable bytes.
      if (normalizeNpmCommandError(error)?.code !== 'E404') throw new Error('Could not verify immutable npm dist metadata')
      if (attempt === attempts) throw new Error('Immutable npm dist metadata remained unavailable within the visibility bound')
      await sleep(Math.min(initialDelayMs * (2 ** Math.min(attempt - 1, 30)), maxDelayMs))
      continue
    }
    if (!actual || actual.integrity !== expected.integrity || actual.shasum !== expected.shasum) throw new Error('Published npm version differs from exact packed source bytes')
    return actual
  }
}
