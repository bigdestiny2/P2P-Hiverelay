import test from 'brittle'
import { execFile } from 'child_process'
import { readFile } from 'fs/promises'
import {
  BLINDSPARK_HTTP_ROUTE_MATRIX,
  BLINDSPARK_HTTP_SURFACES
} from 'p2p-hiverelay/core/protocol/relaykernel-profile.js'
import {
  checkRelayKernelGatewayCompatibility
} from '../../scripts/check-relaykernel-gateway-compat.mjs'

function runScript (args = []) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-relaykernel-gateway-compat.mjs', ...args], {
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

test('RelayKernel gateway compatibility audit is exposed as a package command', async (t) => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'))
  t.is(pkg.scripts['audit:relaykernel-gateway'], 'node scripts/check-relaykernel-gateway-compat.mjs')
})

test('RelayKernel gateway compatibility matrix is bound to checked-in handlers', (t) => {
  const report = checkRelayKernelGatewayCompatibility()

  t.is(report.status, 'pass')
  t.alike(report.surfaces, BLINDSPARK_HTTP_SURFACES)
  t.ok(report.items.length >= BLINDSPARK_HTTP_ROUTE_MATRIX.length, 'matrix has concrete handler rows')
  for (const surface of BLINDSPARK_HTTP_SURFACES) {
    t.ok(report.items.some(item => item.surface === surface && item.status === 'pass'), `${surface} has a passing handler`)
  }
  t.ok(
    report.items.some(item => item.surface === '/v1/hyper/:driveKey/*path' &&
      item.runtime === 'hyper-gateway-core' &&
      item.status === 'pass'),
    'hyper gateway core HEAD/Range behavior is pinned'
  )
})

test('RelayKernel gateway compatibility matrix fails when a route term drifts', async (t) => {
  const catalogRow = BLINDSPARK_HTTP_ROUTE_MATRIX.find(row => row.surface === '/catalog.json')
  const nodeHandler = catalogRow.handlers.find(handler => handler.runtime === 'node-api')
  const original = await readFile(nodeHandler.file, 'utf8')
  const requiredTerm = "catalogReadRoute && catalogReadRoute.kind === 'catalog'"
  const sourceTextByFile = {
    [nodeHandler.file]: original.replace(
      requiredTerm,
      "catalogReadRoute && catalogReadRoute.kind === 'not-catalog'"
    )
  }

  const report = checkRelayKernelGatewayCompatibility({ sourceTextByFile })
  const item = report.items.find(row => row.surface === '/catalog.json' && row.runtime === 'node-api')

  t.is(report.status, 'fail')
  t.is(item.status, 'fail')
  t.ok(item.detail.includes(requiredTerm), 'failure names the missing route term')
})

test('RelayKernel gateway compatibility matrix follows extracted hyper route predicate', async (t) => {
  const hyperRow = BLINDSPARK_HTTP_ROUTE_MATRIX.find(row => row.surface === '/v1/hyper/:driveKey/*path')
  const routeTable = hyperRow.handlers.find(handler => handler.runtime === 'node-api-route-table')
  const original = await readFile(routeTable.file, 'utf8')
  const sourceTextByFile = {
    [routeTable.file]: original.replace("'/v1/hyper/'", "'/v1/not-hyper/'")
  }

  const report = checkRelayKernelGatewayCompatibility({ sourceTextByFile })
  const item = report.items.find(row => row.surface === '/v1/hyper/:driveKey/*path' && row.runtime === 'node-api-route-table')

  t.is(report.status, 'fail')
  t.is(item.status, 'fail')
  t.ok(item.detail.includes("'/v1/hyper/'"), 'failure names the missing hyper gateway route prefix')
})

test('RelayKernel gateway compatibility matrix pins HyperGateway HEAD and Range handling', async (t) => {
  const hyperRow = BLINDSPARK_HTTP_ROUTE_MATRIX.find(row => row.surface === '/v1/hyper/:driveKey/*path')
  const gatewayCore = hyperRow.handlers.find(handler => handler.runtime === 'hyper-gateway-core')
  const original = await readFile(gatewayCore.file, 'utf8')
  const requiredTerm = "req.method !== 'GET' && req.method !== 'HEAD'"
  const sourceTextByFile = {
    [gatewayCore.file]: original.replace(
      requiredTerm,
      "req.method !== 'GET'"
    )
  }

  const report = checkRelayKernelGatewayCompatibility({ sourceTextByFile })
  const item = report.items.find(row => row.surface === '/v1/hyper/:driveKey/*path' && row.runtime === 'hyper-gateway-core')

  t.is(report.status, 'fail')
  t.is(item.status, 'fail')
  t.ok(item.detail.includes(requiredTerm), 'failure names the missing HEAD method guard')
})

test('RelayKernel gateway compatibility matrix rejects Range without HEAD', (t) => {
  const matrix = BLINDSPARK_HTTP_ROUTE_MATRIX.map(row => row.surface === '/v1/hyper/:driveKey/*path'
    ? {
        ...row,
        methods: row.methods.filter(method => method !== 'HEAD')
      }
    : row)

  const report = checkRelayKernelGatewayCompatibility({ matrix })
  const item = report.items.find(row => row.id === 'matrix./v1/hyper/:driveKey/*path.range-head')

  t.is(report.status, 'fail')
  t.is(item.status, 'fail')
  t.is(item.summary, 'Range-capable surface does not declare HEAD support')
})

test('RelayKernel gateway compatibility CLI emits JSON pass report', async (t) => {
  const result = await runScript(['--json'])

  t.is(result.code, 0)
  t.is(result.stderr, '')
  const report = JSON.parse(result.stdout)
  t.is(report.kind, 'relaykernel-gateway-compatibility')
  t.is(report.status, 'pass')
  t.alike(report.surfaces, BLINDSPARK_HTTP_SURFACES)
})
