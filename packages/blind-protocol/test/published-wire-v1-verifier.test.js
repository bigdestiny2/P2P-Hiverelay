import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import test from 'brittle'
import { decodeVectorManifest } from '../hashes.js'
import {
  PUBLISHED_WIRE_V1_AUTHORITY,
  PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES,
  verifyBlindPublishedWireV1
} from '../../../scripts/lib/blind-published-wire-v1.mjs'

const root = path.resolve(fileURLToPath(new URL('../../../', import.meta.url)))
const wrapper = path.join(root, 'scripts/verify-blind-published-wire-v1.mjs')
const masterPath = path.join(root,
  'docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md')
const metadataPath = path.join(root,
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json')
const manifestPath = path.join(root, 'packages/blind-protocol/vector-manifest-v1.cenc')

function withReadOverride (target, transform, extra = {}) {
  return {
    ...extra,
    readFile (absolute) {
      const bytes = fs.readFileSync(absolute)
      return path.resolve(absolute) === path.resolve(target) ? transform(b4a.from(bytes)) : bytes
    }
  }
}

test('fixed published WIRE v1 tuple and documented candidate boundary verify', t => {
  const result = verifyBlindPublishedWireV1({ root })
  t.is(result.schema, 'hiverelay-blind-published-wire-v1-verification-v1')
  t.is(result.profile, 'wire-authority-v1')
  t.is(result.specHash, PUBLISHED_WIRE_V1_AUTHORITY.specHash)
  t.is(result.abiHash, PUBLISHED_WIRE_V1_AUTHORITY.abiHash)
  t.is(result.vectorSetHash, PUBLISHED_WIRE_V1_AUTHORITY.vectorSetHash)
  t.is(result.publishedWireSchemaCount, 71)
  t.is(result.currentWireInventoryCount, 73)
  t.is(result.vectorCount, 233)
  t.alike(result.deferredSchemaNames, PUBLISHED_WIRE_V1_DEFERRED_SCHEMA_NAMES)
  t.alike(result.currentReleaseBlockers,
    ['FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING'])
  t.ok(Object.isFrozen(result))
  t.ok(Object.isFrozen(result.deferredSchemaNames))
})

test('wrapper is check-only and rejects unknown or omitted flags', t => {
  const checked = spawnSync(process.execPath, [wrapper, '--check'], {
    cwd: root,
    encoding: 'utf8'
  })
  t.is(checked.status, 0)
  t.is(checked.stderr, '')
  const report = JSON.parse(checked.stdout)
  t.is(report.status, 'pass')
  t.is(report.specHash, PUBLISHED_WIRE_V1_AUTHORITY.specHash)

  for (const args of [[], ['--write'], ['--check', '--extra']]) {
    const rejected = spawnSync(process.execPath, [wrapper, ...args], {
      cwd: root,
      encoding: 'utf8'
    })
    t.is(rejected.status, 1)
    t.ok(rejected.stderr.includes('requires exactly --check'))
  }
})

test('verifier rejects tuple metadata and vector byte drift', t => {
  const metadataIo = withReadOverride(metadataPath, bytes => {
    const value = JSON.parse(b4a.toString(bytes, 'utf8'))
    value.vectorCount--
    return b4a.from(JSON.stringify(value, null, 2) + '\n')
  })
  t.exception(() => verifyBlindPublishedWireV1({ root, io: metadataIo }),
    /does not equal the fixed published WIRE v1 authority/)

  const vectorPath = path.join(root,
    'packages/blind-protocol/vectors/dispatch/cell-get-request.bin')
  const vectorIo = withReadOverride(vectorPath, bytes => {
    bytes[0] ^= 1
    return bytes
  })
  t.exception(() => verifyBlindPublishedWireV1({ root, io: vectorIo }),
    /WIRE vector dispatch\/cell-get-request\.bin changed hash/)
})

test('verifier rejects any expansion or contraction of the deferred candidate set', t => {
  const candidateIo = withReadOverride(masterPath, bytes => b4a.concat([
    bytes,
    b4a.from('BlindForwardRouteHopV1 {\n  version: u8 = 1\n}\n')
  ]))
  t.exception(() => verifyBlindPublishedWireV1({ root, io: candidateIo }),
    /not missing exactly the two documented FORWARD candidates/)

  const unrelatedIo = withReadOverride(masterPath, bytes => {
    const text = b4a.toString(bytes, 'utf8')
    return b4a.from(text.replace('PutCellV1 {', 'PutCellV1Removed {'))
  })
  t.exception(() => verifyBlindPublishedWireV1({ root, io: unrelatedIo }),
    /not missing exactly the two documented FORWARD candidates/)
})

test('verifier rejects extra vector paths and unknown library options', t => {
  const manifest = decodeVectorManifest(fs.readFileSync(manifestPath))
  const io = {
    listWireVectorPaths () {
      return [...manifest.map(entry => entry.path), 'unexpected/extra.bin']
    }
  }
  t.exception(() => verifyBlindPublishedWireV1({ root, io }),
    /missing or unmanifested files/)
  t.exception(() => verifyBlindPublishedWireV1({ root, deferredSchemaNames: [] }),
    /unknown key/)
  t.exception(() => verifyBlindPublishedWireV1({ root, io: { allowMissing: true } }),
    /unknown key/)
})
