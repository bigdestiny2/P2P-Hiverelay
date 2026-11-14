import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'brittle'
import { PUBLIC_BROWSER_PREDECESSOR, verifyPublicBrowserPredecessor } from '../predecessor-reference.js'
import {
  decodeBlindClientPublicBrowserArtifactManifestV2,
  decodeBlindClientPublicBrowserChromiumEvidenceV2,
  decodeBlindClientPublicBrowserCrossHostEvidenceV2
} from '../browser-artifact.js'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

test('browser predecessor reference preserves historical manifests separately from current dependencies', async t => {
  const reference = await verifyPublicBrowserPredecessor(root)
  t.is(reference.sourceCommit, 'd96389fad63f522b429ba182a3adc4d632ab150f')
  t.is(reference.sourceTree, 'ee3ea9c9f6f1622df508ab63ffb20db6d2a652e3')
  for (const originalPath of ['package.json', 'package-lock.json']) {
    const entry = reference.files.find(entry => entry.originalPath === originalPath)
    const historical = await fs.readFile(path.join(root, entry.snapshotPath))
    const current = await fs.readFile(path.join(root, originalPath))
    t.absent(historical.equals(current), 'current upgraded manifest is not substituted by historical bytes')
  }
})

test('browser predecessor verification rejects modified, missing, and retargeted reference bytes', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'hr-pred-'))
  t.teardown(() => fs.rm(temporary, { recursive: true, force: true }))
  const reference = await verifyPublicBrowserPredecessor(root)
  for (const relative of [PUBLIC_BROWSER_PREDECESSOR.referencePath, ...reference.files.map(entry => entry.snapshotPath)]) {
    const destination = path.join(temporary, relative)
    await fs.mkdir(path.dirname(destination), { recursive: true })
    await fs.copyFile(path.join(root, relative), destination)
  }
  await verifyPublicBrowserPredecessor(temporary)
  const entry = reference.files.find(entry => entry.originalPath === 'package.json')
  const target = path.join(temporary, entry.snapshotPath)
  await fs.appendFile(target, '\n')
  await t.exception(verifyPublicBrowserPredecessor(temporary), /snapshot changed/)
  await fs.unlink(target)
  await t.exception(verifyPublicBrowserPredecessor(temporary), /ENOENT/)
  await fs.copyFile(path.join(root, entry.snapshotPath), target)
  await fs.writeFile(path.join(temporary, PUBLIC_BROWSER_PREDECESSOR.referencePath), JSON.stringify({ ...reference, sourceCommit: '0'.repeat(40) }))
  await t.exception(verifyPublicBrowserPredecessor(temporary), /reference changed/)
})

test('predecessor build manifests and observed evidence cannot qualify the successor revision', async t => {
  const reference = await verifyPublicBrowserPredecessor(root)
  for (const [suffix, decode] of [
    ['.manifest.cenc', decodeBlindClientPublicBrowserArtifactManifestV2],
    ['.chromium-evidence.json', decodeBlindClientPublicBrowserChromiumEvidenceV2],
    ['.cross-host-evidence.json', decodeBlindClientPublicBrowserCrossHostEvidenceV2]
  ]) {
    const entries = reference.files.filter(entry => entry.originalPath.endsWith(suffix))
    t.is(entries.length, 2)
    for (const entry of entries) {
      const bytes = await fs.readFile(path.join(root, entry.snapshotPath))
      t.exception(() => decode(bytes), /wrong|changed|identity|schema|authority/i, 'historical build metadata is not successor evidence')
    }
  }
})
