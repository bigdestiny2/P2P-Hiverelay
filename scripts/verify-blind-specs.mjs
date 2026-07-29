import fs from 'fs'
import path from 'path'
import process from 'process'
import {
  ABI_STATUS,
  EXECUTABLE_SCHEMA_FIELD_STATUS,
  FAMILY_ROUTES
} from '@hiverelay/blind-protocol'
import { PRIVATE_IPC_STATUS } from '@hiverelay/blind-ipc'

const root = process.cwd()
const masterPath = path.join(root, 'docs', 'protocol', 'BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md')
const buildPath = path.join(root, 'docs', 'protocol', 'BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md')
const adoptionPath = path.join(root, 'docs', 'protocol', 'BLIND-SUBSTRATE-APPLICATION-ADOPTION.md')
const wirePath = path.join(root, 'docs', 'protocol', 'HIVERELAY-BLIND-WIRE-V1.md')
const privateIpcPath = path.join(root, 'docs', 'protocol', 'HIVERELAY-BLIND-PRIVATE-IPC-V1.md')

function readCanonicalText (file) {
  const bytes = fs.readFileSync(file)
  if (bytes.length === 0) throw new Error(`${file}: empty`)
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error(`${file}: BOM forbidden`)
  if (bytes.includes(0x0d)) throw new Error(`${file}: CR bytes forbidden`)
  if (bytes[bytes.length - 1] !== 0x0a || (bytes.length > 1 && bytes[bytes.length - 2] === 0x0a)) {
    throw new Error(`${file}: requires exactly one final LF`)
  }
  const text = bytes.toString('utf8')
  const fences = (text.match(/^```/gm) || []).length
  if (fences % 2 !== 0) throw new Error(`${file}: unbalanced code fences`)
  if (text.split('\n').some(line => /[ \t]+$/.test(line))) throw new Error(`${file}: trailing whitespace`)
  return text
}

function requireText (text, needle, file) {
  if (!text.includes(needle)) throw new Error(`${file}: missing required text: ${needle}`)
}

function forbidText (text, needle, file) {
  if (text.includes(needle)) throw new Error(`${file}: forbidden stale/app-specific text: ${needle}`)
}

const master = readCanonicalText(masterPath)
const build = readCanonicalText(buildPath)
const adoption = readCanonicalText(adoptionPath)
const wire = readCanonicalText(wirePath)
const privateIpc = readCanonicalText(privateIpcPath)

for (const route of Object.values(FAMILY_ROUTES)) {
  requireText(master, route, masterPath)
  requireText(build, route, buildPath)
}
for (const family of ['DESCRIBE', 'CELL', 'INBOX', 'CORE', 'FORWARD']) {
  requireText(master, family, masterPath)
  requireText(build, family, buildPath)
}
for (const stale of [
  '/api/blind/v1/health',
  'schemaSetHash',
  'gitCommit',
  'AuthorBindV1',
  'MigrationGenesisV1',
  'peerit.hiverelay.author-bind.v1'
]) forbidText(master, stale, masterPath)
for (const stale of [
  'closed signed write phases',
  'internal/invited dual commit',
  'nested blind-only 1/10/50/100',
  'signed `PAUSED`',
  'CUTOFF_DRAIN'
]) forbidText(master, stale, masterPath)
for (const stale of ['/api/blind/v1/health', 'schemaSetHash', 'gitCommit']) {
  forbidText(build, stale, buildPath)
}

requireText(master, 'A permissionless opaque-byte service cannot stop a malicious producer', masterPath)
requireText(master, 'client-only', masterPath)
requireText(master, 'RFC 9458', masterPath)
requireText(master, 'Noise_XX_25519_ChaChaPoly_BLAKE2b', masterPath)
requireText(master, '65,536', masterPath)
requireText(build, 'fail startup', buildPath)
requireText(master, '`LIVE_DUAL_READ -> FROZEN_CUTOFF -> ARCHIVE_ONLY`', masterPath)
requireText(master, 'release/bootstrap outage cannot disable local signing and', masterPath)
requireText(master, 'controlSnapshotHash = BLAKE2b-256(', masterPath)
requireText(master, '"hiverelay.blind.control-snapshot.v1" ||', masterPath)
requireText(master, '`store/control-state-snapshot-v1.bin`', masterPath)
requireText(master, '`hiverelay-blind-store-format-authority-v1.draft.cenc`', masterPath)
requireText(master, 'No hash-only catalog reference substitutes for the catalog bytes.', masterPath)
requireText(master, 'checkpoint/snapshot GC, WAL pruning or segment', masterPath)
requireText(build, 'controlSnapshotHash = BLAKE2b-256(', buildPath)
requireText(build, '"hiverelay.blind.control-snapshot.v1" ||', buildPath)
requireText(build, '`store/control-state-snapshot-v1.bin`', buildPath)
requireText(build, '`packages/blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc`', buildPath)
requireText(build, 'hashing only the', buildPath)
requireText(build, 'genesis publication, and online/offline format migration are explicitly', buildPath)
requireText(adoption, 'DRAFT_LOCAL -> IDENTITY_COMMITTED -> INNER_EVENT_SIGNED', adoptionPath)
requireText(adoption, 'MUST NOT authorize authors, approve relay membership', adoptionPath)
requireText(wire, 'hiverelay-blind-abi-v1.cenc', wirePath)
requireText(wire, 'vector-manifest-v1.cenc', wirePath)
requireText(wire, 'The ABI artifact contains exactly the 73 category-1 WIRE schemas', wirePath)
requireText(wire, 'This public WIRE authority does not claim that a daemon store', wirePath)
requireText(privateIpc, 'hiverelay-blind-private-ipc-v1.cenc', privateIpcPath)
requireText(privateIpc, 'vector-manifest-v1.cenc', privateIpcPath)
requireText(privateIpc, 'privateIpcFormatHash', privateIpcPath)
requireText(privateIpc, 'privateIpcVectorSetHash', privateIpcPath)
requireText(privateIpc, 'does not prove the production daemon storage engines', privateIpcPath)

if (!ABI_STATUS.releaseReady) {
  throw new Error(`blind public WIRE authority gate failed: ${ABI_STATUS.wireMissingSchemaNames.length} schemas remain; release blockers=${ABI_STATUS.releaseBlockers.join(',') || 'none'}`)
}
if (!EXECUTABLE_SCHEMA_FIELD_STATUS.complete) {
  throw new Error(`blind executable schema field metadata drifted: ${EXECUTABLE_SCHEMA_FIELD_STATUS.mismatches.map(row => row.schemaName).join(',')}`)
}
if (!PRIVATE_IPC_STATUS.releaseReady) {
  throw new Error(`blind private IPC authority gate failed: ${PRIVATE_IPC_STATUS.releaseBlockers.length} blockers remain`)
}

process.stdout.write(`blind draft candidates are internally consistent across ${ABI_STATUS.wireRequiredSchemaNames.length} public WIRE and ${PRIVATE_IPC_STATUS.schemaCount} private IPC schemas; this does not authorize freeze or release\n`)
