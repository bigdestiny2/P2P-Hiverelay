import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'brittle'
import * as limited from '../src/cell-get-control.js'

const here = path.dirname(fileURLToPath(import.meta.url))

test('limited successor has exactly two exports and a narrow source graph', t => {
  t.alike(Object.keys(limited).sort(), [
    'createBlindCellGetControl',
    'createBrowserCryptoRuntime'
  ])

  const paths = [
    '../src/cell-get-control.js',
    '../src/cell-get-requests.js',
    '../src/cell-get-results.js'
  ]
  const source = paths.map(relative => fs.readFileSync(path.join(here, relative), 'utf8')).join('\n')
  for (const token of [
    './browser-control.js',
    '../../blind-client/control.js',
    '../../blind-client/requests.js',
    '../../blind-client/results.js',
    '../../blind-client/inbox.js',
    '../../blind-client/forward.js',
    'CELL.PUT',
    'INBOX.'
  ]) t.absent(source.includes(token), token)
})

test('bounded reconstruction retains an explicit repeated-hash cycle guard', t => {
  const source = fs.readFileSync(path.join(here, '../src/cell-get-control.js'), 'utf8')
  t.ok(source.includes("const seen = new Set([b4a.toString(head.descriptorHash, 'hex')])"))
  t.ok(source.includes("if (seen.has(requestedHex)) fail('DESCRIPTOR_CHAIN_INVALID', 'descriptor chain repeats a hash')"))
  t.ok(source.includes('seen.add(requestedHex)'))
  // A genuinely signed finite cycle would require a BLAKE2b preimage/fixed point:
  // every descriptor hash commits its previousDescriptorHash. The reachable
  // black-box duplicate case is therefore a server returning bytes under the
  // wrong requested hash, which the descriptor-chain tests exercise.
})

test('genesis pinning and final CELL.GET context remain mandatory and internal', t => {
  const source = fs.readFileSync(path.join(here, '../src/cell-get-control.js'), 'utf8')
  t.ok(source.includes('? { pinnedDescriptorHash: entry.verified.descriptorHash }'))
  t.ok(source.includes('continuityRootRelayPublicKey'))
  t.ok(source.includes('context.familyId !== FAMILY.CELL'))
  t.ok(source.includes('context.operationId !== OPERATION.CELL.GET'))
  t.absent(source.includes('endpointContext ()'))
})
