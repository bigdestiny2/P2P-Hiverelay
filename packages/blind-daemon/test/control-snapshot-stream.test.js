import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  blindControlStateSnapshotV1,
  controlSnapshotHash,
  encodeCanonical
} from '@hiverelay/blind-protocol'
import { verifyBlindControlStateSnapshotFile } from '../control-snapshot-stream.js'

function bytes (length, fill) {
  return b4a.alloc(length, fill)
}

async function fixture (t) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-control-snapshot-'))
  const root = await fs.realpath(created)
  await fs.chmod(root, 0o700)
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  const value = {
    version: 1,
    relayPublicKey: bytes(32, 0x11),
    storeId: bytes(32, 0x22),
    durabilityContinuityHash: bytes(32, 0x33),
    walSequence: 7n,
    walHash: bytes(32, 0x44),
    entries: [
      { entryKind: 1, key: b4a.from('a'), value: b4a.from('alpha') },
      { entryKind: 1, key: b4a.from('b'), value: b4a.alloc(0) },
      { entryKind: 8, key: b4a.from('z'), value: b4a.alloc(0xffff, 0x5a) }
    ]
  }
  const canonical = encodeCanonical(blindControlStateSnapshotV1, value)
  const filePath = path.join(root, `snapshot-${b4a.toString(controlSnapshotHash(canonical), 'hex')}.v1`)
  await fs.writeFile(filePath, canonical, { mode: 0o600 })
  return { root, value, canonical, filePath }
}

function semanticEchoVerifier (observed = []) {
  return async ({ header, declaredEntryCount, entries }) => {
    for await (const entry of entries) {
      observed.push({
        entryKind: entry.entryKind,
        key: b4a.from(entry.key),
        value: b4a.from(entry.value)
      })
    }
    return {
      ...header,
      entryCount: declaredEntryCount
    }
  }
}

test('control snapshot validation streams canonical entries and binds the semantic reconstruction echo', async t => {
  const state = await fixture(t)
  const observed = []
  const before = await fs.readFile(state.filePath)
  const verified = await verifyBlindControlStateSnapshotFile({
    filePath: state.filePath,
    maximumSnapshotBytes: 1024 * 1024,
    expectedByteLength: BigInt(state.canonical.byteLength),
    expectedHash: controlSnapshotHash(state.canonical),
    expected: {
      relayPublicKey: state.value.relayPublicKey,
      storeId: state.value.storeId,
      durabilityContinuityHash: state.value.durabilityContinuityHash,
      walSequence: state.value.walSequence,
      walHash: state.value.walHash
    },
    semanticVerifier: semanticEchoVerifier(observed)
  })
  t.is(verified.entryCount, state.value.entries.length)
  t.alike(verified.snapshotHash, controlSnapshotHash(state.canonical))
  t.alike(observed, state.value.entries)
  t.alike(await fs.readFile(state.filePath), before)
})

test('hostile declared entry counts fail before semantic allocation or iteration', async t => {
  const state = await fixture(t)
  const empty = encodeCanonical(blindControlStateSnapshotV1, { ...state.value, entries: [] })
  const hostile = b4a.concat([
    empty.subarray(0, empty.byteLength - 1),
    b4a.from([0xfe, 0x00, 0x00, 0x00, 0x01])
  ])
  const hostilePath = path.join(state.root, 'snapshot-hostile.v1')
  await fs.writeFile(hostilePath, hostile, { mode: 0o600 })
  let invoked = false
  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: hostilePath,
    maximumSnapshotBytes: 1024,
    semanticVerifier: async () => { invoked = true }
  }), /entry count cannot fit/)
  t.is(invoked, false)
})

test('partial semantic consumption and forged reconstruction tuples fail closed', async t => {
  const state = await fixture(t)
  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: state.filePath,
    maximumSnapshotBytes: 1024 * 1024,
    semanticVerifier: async ({ header, entries }) => {
      await entries.next()
      return { ...header, entryCount: state.value.entries.length }
    }
  }), /did not consume the complete/)

  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: state.filePath,
    maximumSnapshotBytes: 1024 * 1024,
    semanticVerifier: async ({ header, declaredEntryCount, entries }) => {
      for await (const entry of entries) b4a.from(entry.value)
      return { ...header, walSequence: header.walSequence + 1n, entryCount: declaredEntryCount }
    }
  }), /semantic reconstruction walSequence does not match/)
})

test('trailing bytes, wrong hash, and changed private-file invariants are rejected', async t => {
  const state = await fixture(t)
  const trailingPath = path.join(state.root, 'snapshot-trailing.v1')
  await fs.writeFile(trailingPath, b4a.concat([state.canonical, b4a.from([0])]), { mode: 0o600 })
  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: trailingPath,
    maximumSnapshotBytes: 1024 * 1024,
    semanticVerifier: semanticEchoVerifier()
  }), /trailing bytes/)

  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: state.filePath,
    maximumSnapshotBytes: 1024 * 1024,
    expectedHash: bytes(32, 0xaa),
    semanticVerifier: semanticEchoVerifier()
  }), /hash does not match/)

  const linkedPath = path.join(state.root, 'snapshot-linked.v1')
  await fs.link(state.filePath, linkedPath)
  await t.exception(verifyBlindControlStateSnapshotFile({
    filePath: state.filePath,
    maximumSnapshotBytes: 1024 * 1024,
    semanticVerifier: semanticEchoVerifier()
  }), /single-link regular file/)
})
