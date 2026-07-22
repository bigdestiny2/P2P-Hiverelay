/**
 * Crash-safe Corestore 6 -> 7 storage-root migration guard.
 *
 * Corestore 7 synchronously relocates every unrecognised top-level entry of a
 * pre-7 root into db/. HiveRelay has durable relay state at that same level,
 * so opening the root in place can otherwise strand app-registry.json,
 * identities, and service sidecars. The old wrapper tried to move the files
 * back after constructing Corestore, but a process crash in that interval made
 * the next boot unable to distinguish a migrated sidecar from Corestore data.
 *
 * Before Corestore is allowed to touch a legacy root, this guard atomically
 * records a journal in a sibling directory and moves foreign entries there.
 * Corestore then creates its new layout without seeing relay state. Only after
 * that constructor completes are the entries restored. The journal remains
 * until every restore succeeds, so any interrupted run resumes before another
 * Corestore constructor is called. Restore failures are deliberately fatal:
 * booting with a missing registry is worse than requiring operator repair.
 */

import Corestore from 'corestore'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync
} from 'fs'
import { basename, dirname, join, resolve } from 'path'

const CORESTORE_OWNED = new Set(['CORESTORE', 'primary-key', 'cores', 'db'])
const STAGING_SUFFIX = '.hiverelay-corestore7-state'
const JOURNAL_NAME = 'journal.json'

function stageDir (storage) {
  // `storage + suffix` makes a trailing-slash path place staging *inside* the
  // Corestore root. Corestore would then sweep the journal itself into db/.
  // Resolve once so all entrypoints use the same sibling directory.
  return join(dirname(storage), `${basename(storage)}${STAGING_SUFFIX}`)
}

function journalFile (stage) {
  return join(stage, JOURNAL_NAME)
}

function isForeignName (name) {
  return typeof name === 'string' && name !== '' && name === name.split('/').pop() && !CORESTORE_OWNED.has(name)
}

function readJournal (stage) {
  const file = journalFile(stage)
  if (!existsSync(file)) return null

  let journal
  try {
    journal = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    throw new Error(`HiveRelay storage migration journal is unreadable: ${file}`, { cause: error })
  }

  if (journal?.version !== 1 || !Array.isArray(journal.entries) || journal.entries.some((name) => !isForeignName(name))) {
    throw new Error(`HiveRelay storage migration journal is invalid: ${file}`)
  }
  return journal
}

function writeJournal (stage, entries) {
  mkdirSync(stage, { recursive: true })
  const file = journalFile(stage)
  const temporary = `${file}.tmp`
  writeFileSync(temporary, `${JSON.stringify({ version: 1, entries })}\n`, { mode: 0o600 })
  renameSync(temporary, file)
}

function restoreJournal (storage, stage, journal) {
  for (const name of journal.entries) {
    const staged = join(stage, name)
    const target = join(storage, name)
    if (!existsSync(staged)) continue // restored before an earlier interruption
    if (existsSync(target)) {
      throw new Error(`HiveRelay storage migration cannot restore ${name}: destination already exists`)
    }
    renameSync(staged, target)
  }

  for (const name of journal.entries) {
    if (!existsSync(join(storage, name))) {
      throw new Error(`HiveRelay storage migration cannot verify restored state: ${name}`)
    }
  }

  unlinkSync(journalFile(stage))
  rmdirSync(stage)
}

function recoverInterruptedMigration (storage) {
  const stage = stageDir(storage)
  const journal = readJournal(stage)
  if (journal) restoreJournal(storage, stage, journal)
}

function stageLegacyRoot (storage) {
  recoverInterruptedMigration(storage)

  if (existsSync(join(storage, 'CORESTORE'))) return null

  let entries
  try {
    entries = readdirSync(storage).filter(isForeignName)
  } catch {
    return null // brand-new or unreadable root — Corestore owns its outcome
  }
  if (entries.length === 0) return null

  const stage = stageDir(storage)
  writeJournal(stage, entries)
  for (const name of entries) renameSync(join(storage, name), join(stage, name))
  return stage
}

/**
 * Open a state-bearing Corestore without allowing Corestore 7 to absorb relay
 * sidecars. `hooks.afterCorestoreOpen` is an internal fault-injection seam for
 * the interruption regression test; production callers use two arguments.
 */
export function openCorestore (storage, opts, hooks = {}) {
  const root = typeof storage === 'string' ? resolve(storage) : storage
  const stage = typeof root === 'string' ? stageLegacyRoot(root) : null
  const store = new Corestore(root, opts)
  if (typeof hooks.afterCorestoreOpen === 'function') hooks.afterCorestoreOpen({ storage: root, store, stage })
  if (stage) restoreJournal(root, stage, readJournal(stage))
  return store
}
