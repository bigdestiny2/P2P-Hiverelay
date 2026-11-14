import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'

export const PUBLIC_BROWSER_PREDECESSOR = Object.freeze({
  commit: 'd96389fad63f522b429ba182a3adc4d632ab150f',
  tree: 'ee3ea9c9f6f1622df508ab63ffb20db6d2a652e3',
  referencePath: 'packages/blind-client-public-browser/predecessors/rc9/reference.json',
  referenceSha256: 'c3e0fcc0d87841a64f866dcfa8c6482fa4a8c85540cb2296a3f7cbbca936f2de'
})

export async function verifyPublicBrowserPredecessor (root) {
  const bytes = await fs.readFile(path.join(root, PUBLIC_BROWSER_PREDECESSOR.referencePath))
  if (createHash('sha256').update(bytes).digest('hex') !== PUBLIC_BROWSER_PREDECESSOR.referenceSha256) {
    throw new Error('public browser predecessor reference changed')
  }
  const reference = JSON.parse(bytes)
  for (const entry of reference.files) {
    const bytes = await fs.readFile(path.join(root, entry.snapshotPath))
    if (bytes.length !== entry.bytes || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) {
      throw new Error(`public browser predecessor snapshot changed: ${entry.originalPath}`)
    }
  }
  return reference
}
