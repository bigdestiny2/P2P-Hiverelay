#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  BLINDSPARK_HTTP_ROUTE_MATRIX,
  BLINDSPARK_HTTP_SURFACES
} from '../packages/core/core/protocol/relaykernel-profile.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')

const usage = `
Usage:
  node scripts/check-relaykernel-gateway-compat.mjs [--json] [--root <repo-root>]

Verifies that the RelayKernel-profile Blindspark HTTP compatibility matrix is
still bound to the concrete Node/Bare/data-plane gateway route handlers. This
is intentionally source-level: it catches route-contract drift before a future
RelayKernel extraction drops PearBrowser's browser bootstrap surfaces.
`

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    console.error(usage.trim())
    process.exit(1)
  }

  if (args.help) {
    console.log(usage.trim())
    return
  }

  const report = checkRelayKernelGatewayCompatibility({
    repoRoot: path.resolve(args.root || repoRoot)
  })

  if (args.json) console.log(JSON.stringify(report, null, 2))
  else console.log(formatReport(report))

  if (report.status !== 'pass') process.exit(1)
}

export function checkRelayKernelGatewayCompatibility ({
  repoRoot = path.resolve(here, '..'),
  matrix = BLINDSPARK_HTTP_ROUTE_MATRIX,
  surfaces = BLINDSPARK_HTTP_SURFACES,
  sourceTextByFile = null
} = {}) {
  const items = []
  const matrixSurfaces = new Set()
  const exportedSurfaces = new Set(surfaces)

  for (const row of Array.isArray(matrix) ? matrix : []) {
    const surface = typeof row?.surface === 'string' ? row.surface : '(missing surface)'
    matrixSurfaces.add(surface)

    if (!exportedSurfaces.has(surface)) {
      items.push(failItem({
        id: `matrix.${surface}`,
        surface,
        summary: 'surface is missing from BLINDSPARK_HTTP_SURFACES',
        detail: 'RelayKernel validation would no longer require this route.'
      }))
    }

    if (!Array.isArray(row?.methods) || !row.methods.includes('GET')) {
      items.push(failItem({
        id: `matrix.${surface}.methods`,
        surface,
        summary: 'surface does not declare GET support',
        detail: 'PearBrowser and browser clients rely on GET bootstrap reads.'
      }))
    }

    if (Array.isArray(row?.capabilities) && row.capabilities.includes('Range') &&
      (!Array.isArray(row?.methods) || !row.methods.includes('HEAD'))) {
      items.push(failItem({
        id: `matrix.${surface}.range-head`,
        surface,
        summary: 'Range-capable surface does not declare HEAD support',
        detail: 'Browser bootstrap probes and range-aware media fetches depend on HEAD staying paired with Range.'
      }))
    }

    const handlers = Array.isArray(row?.handlers) ? row.handlers : []
    if (handlers.length === 0) {
      items.push(failItem({
        id: `matrix.${surface}.handlers`,
        surface,
        summary: 'surface has no concrete route handlers',
        detail: 'Compatibility surfaces must point at at least one implementation file.'
      }))
      continue
    }

    for (const handler of handlers) {
      items.push(checkHandler({ repoRoot, sourceTextByFile, surface, handler }))
    }
  }

  for (const surface of exportedSurfaces) {
    if (!matrixSurfaces.has(surface)) {
      items.push(failItem({
        id: `surfaces.${surface}`,
        surface,
        summary: 'exported surface is missing from route matrix',
        detail: 'BLINDSPARK_HTTP_SURFACES and BLINDSPARK_HTTP_ROUTE_MATRIX must stay in lockstep.'
      }))
    }
  }

  if (!Array.isArray(matrix) || matrix.length === 0) {
    items.push(failItem({
      id: 'matrix.present',
      surface: '(all)',
      summary: 'route matrix is empty or malformed',
      detail: 'RelayKernel gateway compatibility cannot be proven.'
    }))
  }

  const failed = items.filter(item => item.status === 'fail')
  const passed = items.filter(item => item.status === 'pass')

  return {
    schemaVersion: 1,
    kind: 'relaykernel-gateway-compatibility',
    status: failed.length === 0 ? 'pass' : 'fail',
    surfaces: [...exportedSurfaces],
    totals: {
      pass: passed.length,
      fail: failed.length
    },
    items
  }
}

function checkHandler ({ repoRoot, sourceTextByFile, surface, handler }) {
  const runtime = typeof handler?.runtime === 'string' ? handler.runtime : '(missing runtime)'
  const file = typeof handler?.file === 'string' ? handler.file : ''
  const id = `${surface}:${runtime}`
  const requiredTerms = Array.isArray(handler?.requiredTerms) ? handler.requiredTerms : []

  if (!file) {
    return failItem({
      id,
      surface,
      runtime,
      file,
      summary: 'handler file is missing from matrix row',
      detail: 'Each compatibility handler must name its implementation file.'
    })
  }

  const source = readSource({ repoRoot, sourceTextByFile, file })
  if (!source.ok) {
    return failItem({
      id,
      surface,
      runtime,
      file,
      summary: 'handler source is not readable',
      detail: source.error
    })
  }

  const missingTerms = requiredTerms.filter(term => !source.text.includes(term))
  if (missingTerms.length > 0) {
    return failItem({
      id,
      surface,
      runtime,
      file,
      summary: 'handler source is missing required route terms',
      detail: missingTerms.map(term => JSON.stringify(term)).join(', ')
    })
  }

  return {
    id,
    status: 'pass',
    surface,
    runtime,
    file,
    summary: 'handler preserves RelayKernel gateway compatibility',
    requiredTerms
  }
}

function readSource ({ repoRoot, sourceTextByFile, file }) {
  if (sourceTextByFile) {
    if (typeof sourceTextByFile.get === 'function' && sourceTextByFile.has(file)) {
      return { ok: true, text: sourceTextByFile.get(file) }
    }
    if (Object.prototype.hasOwnProperty.call(sourceTextByFile, file)) {
      return { ok: true, text: sourceTextByFile[file] }
    }
  }

  const abs = path.resolve(repoRoot, file)
  try {
    const stat = fs.lstatSync(abs)
    if (stat.isSymbolicLink()) return { ok: false, error: 'handler source must not be a symlink' }
    if (!stat.isFile()) return { ok: false, error: 'handler source is not a regular file' }
    return { ok: true, text: fs.readFileSync(abs, 'utf8') }
  } catch (err) {
    return { ok: false, error: err.message }
  }
}

function failItem ({ id, surface, runtime = null, file = null, summary, detail }) {
  return {
    id,
    status: 'fail',
    surface,
    runtime,
    file,
    summary,
    detail
  }
}

function formatReport (report) {
  const lines = [
    'RelayKernel gateway compatibility check',
    `status=${report.status}`,
    `surfaces=${report.surfaces.join(', ')}`,
    `pass=${report.totals.pass} fail=${report.totals.fail}`
  ]

  for (const item of report.items) {
    const location = [item.surface, item.runtime, item.file].filter(Boolean).join(' ')
    lines.push(`${item.status.toUpperCase()} ${location} — ${item.summary}`)
    if (item.status === 'fail') lines.push(`  ${item.detail}`)
  }

  return lines.join('\n')
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--json') {
      out.json = true
      continue
    }
    if (arg === '--root') {
      out.root = readValue(argv, ++i, arg)
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`)
  return value
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main()
