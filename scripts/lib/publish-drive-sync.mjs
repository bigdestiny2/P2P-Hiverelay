import b4a from 'b4a'

function normalizeFile (file) {
  if (!file || typeof file.path !== 'string' || !file.path.startsWith('/')) {
    throw new TypeError('publish file path must be an absolute Hyperdrive path')
  }
  if (file.path === '/' || file.path.endsWith('/') || file.path.includes('\\')) {
    throw new TypeError('publish file path must identify a file')
  }
  const parts = file.path.slice(1).split('/')
  if (parts.some(part => part === '' || part === '.' || part === '..')) {
    throw new TypeError('publish file path must be canonical')
  }
  const content = b4a.isBuffer(file.content) ? file.content : b4a.from(file.content)
  return { path: file.path, content }
}

async function sameContent (drive, entry, content) {
  const blob = entry && entry.value && entry.value.blob
  if (!blob) return false
  const current = await drive.get(entry.key, { wait: false })
  return current !== null && b4a.equals(current, content)
}

function writeDeduplicated (drive, path, content) {
  return new Promise((resolve, reject) => {
    const stream = drive.createWriteStream(path, { dedup: true })
    stream.once('error', reject)
    stream.once('finish', resolve)
    stream.end(content)
  })
}

/**
 * Make a Hyperdrive's live file tree exactly match a release file set.
 *
 * Unchanged files are not written at all. Changed files use Hyperblobs block
 * deduplication against the previous value, so an update only appends changed
 * blocks plus its new block map. Paths absent from the release are deleted.
 * Metadata changes are committed together through one Hyperbee batch.
 */
export async function planPublishedFiles (drive, files) {
  const desired = new Map()
  for (const input of files) {
    const file = normalizeFile(input)
    if (desired.has(file.path)) throw new Error(`duplicate publish path: ${file.path}`)
    desired.set(file.path, file.content)
  }

  const existing = new Map()
  for await (const entry of drive.list('/')) existing.set(entry.key, entry)

  const removed = []
  for (const path of existing.keys()) {
    if (!desired.has(path)) removed.push(path)
  }

  const writes = []
  let unchanged = 0
  for (const [path, content] of desired) {
    const entry = existing.get(path)
    if (entry && await sameContent(drive, entry, content)) {
      unchanged++
      continue
    }
    writes.push({ path, content, type: entry ? 'change' : 'add' })
  }

  return {
    desired,
    writes,
    removed,
    unchanged,
    contentBytes: writes.reduce((total, file) => total + file.content.byteLength, 0)
  }
}

export async function syncPublishedFiles (drive, files, opts = {}) {
  const plan = opts.plan || await planPublishedFiles(drive, files)
  const { writes, removed, unchanged } = plan

  if (removed.length === 0 && writes.length === 0) {
    return { added: 0, changed: 0, removed: 0, unchanged }
  }

  const batch = drive.batch()
  try {
    for (const path of removed) await batch.del(path)
    for (const file of writes) await writeDeduplicated(batch, file.path, file.content)
    await batch.flush()
  } catch (err) {
    try { await batch.close() } catch {}
    throw err
  }

  return {
    added: writes.filter(file => file.type === 'add').length,
    changed: writes.filter(file => file.type === 'change').length,
    removed: removed.length,
    unchanged
  }
}
