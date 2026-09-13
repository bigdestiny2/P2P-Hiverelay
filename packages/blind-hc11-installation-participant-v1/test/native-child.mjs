import fs from 'node:fs'
import path from 'node:path'
import FDLock from 'fd-lock'
import { Corestore } from './helpers.mjs'
import { Hc11InstallationParticipantV1, readPreparedHc11Participant } from '../index.js'
import { PROFILE_DIGEST } from '../../blind-core-upstream-hc11-v1/format.js'
const [mode, root] = process.argv.slice(2)
if (mode === 'lock') {
  const fd = fs.openSync(path.join(root, '.hiverelay-generation/installation-id.v1'), 'r+')
  const lock = new FDLock(fd)
  let locked = false
  try { await lock.ready(); locked = lock.locked } catch {}
  await lock.close().catch(() => {})
  console.log(JSON.stringify({ locked }))
} else if (mode === 'failed-close') {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, '.hiverelay-generation/envelope.v1.json')))
  const { mac, ...body } = manifest
  const { createHash } = await import('node:crypto')
  const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value
  const digest = value => 'sha256:' + createHash('sha256').update(value).digest('hex')
  const options = { root, rootId: Buffer.alloc(32, 17), profileDigest: Buffer.from(PROFILE_DIGEST), envelope: { mode: manifest.mode, expectedInstallationId: manifest.installationId, expectedAuthorityKeySha256: manifest.authorityKeySha256, expectedManifestSha256: digest(Buffer.from(JSON.stringify(stable(body)) + '\n')), participant: 'private-shared-v1' } }
  const owner = new Hc11InstallationParticipantV1(options)
  const token = await owner.prepare()
  Corestore.prototype.close = async () => { throw new Error('owned native close failure') }
  const closed = await owner.close()
  let refused = false
  try { await readPreparedHc11Participant(token) } catch { refused = true }
  const next = new Hc11InstallationParticipantV1(options)
  let replacementRefused = false
  try { await next.prepare() } catch { replacementRefused = true }
  console.log(JSON.stringify({ closed, refused, replacementRefused, status: owner.status() }))
  process.exit(0) // Actual native custody releases only with this isolated process.
} else throw new Error('Unsupported child case')
