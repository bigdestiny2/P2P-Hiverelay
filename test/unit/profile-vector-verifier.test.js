import test from 'brittle'
import { execFile } from 'child_process'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'
import {
  SUPPORTED_PROFILE_VECTOR_NAMES,
  verifyProfileVector,
  verifyProfileVectors
} from 'p2p-hiverelay/core/protocol/profile-vector-verifier.js'

const FIXTURE_DIR = new URL('../fixtures/relaykernel-profile/', import.meta.url)

async function loadVectors () {
  const dir = FIXTURE_DIR
  const names = (await readdir(dir)).filter(name => name.endsWith('.json')).sort()
  const vectors = []
  for (const name of names) {
    vectors.push(JSON.parse(await readFile(new URL(name, dir), 'utf8')))
  }
  return vectors
}

function runScript (args = []) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/verify-profile-vectors.mjs', ...args], {
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

test('profile vector verifier accepts all checked-in transplant vectors', async (t) => {
  const vectors = await loadVectors()
  const summary = verifyProfileVectors(vectors, { requireSupportedSet: true })
  const names = new Set(vectors.map(vector => vector.name))

  t.ok(vectors.length >= 4, 'fixture set includes all transplant vectors')
  t.is(vectors.length, SUPPORTED_PROFILE_VECTOR_NAMES.length, 'fixture count matches supported verifier table')
  t.ok(SUPPORTED_PROFILE_VECTOR_NAMES.includes('relaykernel-http-route-matrix-v1-blindspark-compat'), 'supported vector inventory includes RelayKernel route matrix vector')
  t.ok(names.has('relaykernel-profile-v1-app-module-boundary'), 'fixture set includes RelayKernel app-module boundary vector')
  t.ok(names.has('capability-doc-signature-v1'), 'fixture set includes signed capability-doc conformance vector')
  t.ok(names.has('relaykernel-http-route-matrix-v1-blindspark-compat'), 'fixture set includes RelayKernel HTTP route matrix vector')
  t.ok(names.has('seed-protocol-binary-v1'), 'fixture set includes seed protocol binary conformance vector')
  t.ok(names.has('seed-protocol-handshake-v1'), 'fixture set includes seed protocol version-negotiation vector')
  t.ok(names.has('circuit-protocol-binary-v1'), 'fixture set includes circuit protocol binary conformance vector')
  t.alike(summary.inventory.names, [...SUPPORTED_PROFILE_VECTOR_NAMES].sort(), 'fixture names match supported verifier table')
  t.alike(summary.inventory.missingNames, [], 'full fixture set has every supported profile vector')
  t.alike(summary.inventory.duplicateNames, [], 'full fixture set has no duplicate profile vector names')
  t.ok(summary.valid, 'all vectors pass')
  t.is(summary.count, vectors.length)
  t.is(summary.failed, 0)
  for (const result of summary.results) t.ok(result.valid, result.name + ' verifies')
})

test('profile vector verifier enforces full fixture inventory only when requested', async (t) => {
  const vectors = await loadVectors()
  const accounting = vectors.find(vector => vector.name === 'accounting-receipt-v1-os-grounded')
  const withoutRouteMatrix = vectors.filter(vector => vector.name !== 'relaykernel-http-route-matrix-v1-blindspark-compat')
  const missing = verifyProfileVectors(withoutRouteMatrix, { requireSupportedSet: true })

  t.absent(missing.valid, 'missing supported fixture fails full inventory')
  t.ok(missing.inventory.errors.includes('missing supported profile vector: relaykernel-http-route-matrix-v1-blindspark-compat'))

  const focused = verifyProfileVectors([accounting])
  t.ok(focused.valid, 'single-file debug verification does not require the full inventory')
  t.alike(focused.inventory.missingNames, [])

  const duplicate = verifyProfileVectors([accounting, { ...accounting }])
  t.absent(duplicate.valid, 'duplicate vector names fail even outside full inventory mode')
  t.ok(duplicate.inventory.errors.includes('duplicate profile vector name: accounting-receipt-v1-os-grounded'))
})

test('profile vector verifier rejects tampered accounting and unknown vectors', async (t) => {
  const vectors = await loadVectors()
  const accounting = vectors.find(vector => vector.name === 'accounting-receipt-v1-os-grounded')
  const tampered = {
    ...accounting,
    receipt: {
      ...accounting.receipt,
      diskBytes: accounting.receipt.diskBytes + 1
    }
  }
  const tamperedResult = verifyProfileVector(tampered)
  t.absent(tamperedResult.valid, 'tampered receipt vector fails')
  t.ok(tamperedResult.errors.some(error => error.includes('failed verification') || error.includes('signableHex')))

  const routeMatrix = vectors.find(vector => vector.name === 'relaykernel-http-route-matrix-v1-blindspark-compat')
  const missingSurface = {
    ...routeMatrix,
    surfaces: routeMatrix.surfaces.filter(surface => surface !== '/catalog.json')
  }
  const routeMatrixResult = verifyProfileVector(missingSurface)
  t.absent(routeMatrixResult.valid, 'tampered route matrix vector fails')
  t.ok(routeMatrixResult.errors.includes('relaykernel http route surfaces mismatch'))

  const rangeWithoutHead = {
    ...routeMatrix,
    matrix: routeMatrix.matrix.map(row => row.surface === '/v1/hyper/:driveKey/*path'
      ? {
          ...row,
          methods: row.methods.filter(method => method !== 'HEAD')
        }
      : row)
  }
  const rangeWithoutHeadResult = verifyProfileVector(rangeWithoutHead)
  t.absent(rangeWithoutHeadResult.valid, 'Range-capable route matrix row without HEAD fails')
  t.ok(rangeWithoutHeadResult.errors.includes(
    'relaykernel route matrix Range surface missing HEAD: /v1/hyper/:driveKey/*path'
  ))

  const appModuleBoundary = vectors.find(vector => vector.name === 'relaykernel-profile-v1-app-module-boundary')
  const hiddenAppModules = {
    ...appModuleBoundary,
    profile: {
      ...appModuleBoundary.profile,
      security: {
        ...appModuleBoundary.profile.security,
        appModulesExcludedFromKernel: true
      },
      appModules: []
    },
    verdict: {
      ...appModuleBoundary.verdict,
      warnings: []
    }
  }
  const appModuleBoundaryResult = verifyProfileVector(hiddenAppModules)
  t.absent(appModuleBoundaryResult.valid, 'tampered app-module boundary vector fails')
  t.ok(appModuleBoundaryResult.errors.includes('relaykernel profile mismatch'))
  t.ok(appModuleBoundaryResult.errors.includes('relaykernel verdict mismatch'))

  const unknown = verifyProfileVector({ name: 'future-vector' })
  t.absent(unknown.valid, 'unknown vector fails closed')
  t.ok(unknown.errors.includes('unsupported vector: future-vector'))

  const malformed = verifyProfileVector({
    name: 'retrievability-proof-signable-v1',
    seedHex: 'not-hex',
    coreKey: 'not-hex',
    nonce: 'not-hex',
    blockValueHex: 'not-hex'
  })
  t.absent(malformed.valid, 'malformed vector fails closed')
  t.ok(malformed.errors.some(error => error.startsWith('vector verification error:')))
})

test('profile vector CLI verifies fixture directory', async (t) => {
  const result = await runScript()
  t.is(result.code, 0)
  t.ok(result.stdout.includes('profile vectors:'))
  t.ok(result.stdout.includes('passed'))
  t.is(result.stderr, '')
})

test('profile vector CLI emits JSON summary', async (t) => {
  const result = await runScript(['--json'])
  t.is(result.code, 0)
  const summary = JSON.parse(result.stdout)
  t.ok(summary.valid)
  t.is(summary.failed, 0)
})

test('profile vector CLI fails on a tampered fixture file', async (t) => {
  // Portable, isolated temp dir with awaited cleanup. The previous hardcoded
  // '/private/tmp' path is a macOS-only symlink; on the Linux CI runner that
  // directory does not exist, so the write rejected ENOENT and surfaced as an
  // "async activity after the test ended" unhandledRejection that failed the
  // whole unit-tests job even though every assertion passed.
  const dir = await mkdtemp(path.join(tmpdir(), 'tampered-profile-vector-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'tampered.json')
  const vectors = await loadVectors()
  const proof = vectors.find(vector => vector.name === 'retrievability-proof-signable-v1')
  const tampered = { ...proof, signature: '00'.repeat(64) }

  await writeFile(file, JSON.stringify(tampered), 'utf8')
  const result = await runScript([file])
  t.is(result.code, 1)
  t.ok(result.stderr.includes('retrievability-proof-signable-v1'))
})
