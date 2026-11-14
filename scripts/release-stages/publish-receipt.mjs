#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { RELEASE_PROMOTION_EVIDENCE, promotionAssetNames } from '../lib/release-evidence-contract.mjs'
import { RELEASE_REPOSITORY } from './distribution.mjs'
import { verifyQualification } from './qualification.mjs'
import { run, parseArgs, readJson, digest } from './io.mjs'
const args = parseArgs(process.argv.slice(2), ['--bundle-dir'])
const dir = path.resolve(args['--bundle-dir'] || '')
const receipt = readJson(path.join(dir, RELEASE_PROMOTION_EVIDENCE))
const tag = receipt.artifact?.version
if (receipt.kind !== 'hiverelay-stable-promotion-v1' || receipt.status !== 'verified' || !/^v\d+\.\d+\.\d+$/.test(tag || '') || receipt.fleetEvidence?.path !== 'stable-promotion-fleet-evidence.json') throw new Error('A complete promotion receipt is required')
const names = promotionAssetNames(receipt.workflow)
const files = Object.keys(names)
const release = JSON.parse(run('gh', ['api', `repos/${RELEASE_REPOSITORY}/releases/tags/${tag}`]))
if (release.tag_name !== tag || release.draft !== false || release.prerelease !== false || !Number.isSafeInteger(release.id)) throw new Error('Release identity changed before receipt publication')
function assets () {
  const pages = JSON.parse(run('gh', ['api', '--paginate', '--slurp', `repos/${RELEASE_REPOSITORY}/releases/${release.id}/assets?per_page=100`]))
  if (!Array.isArray(pages) || !pages.every(Array.isArray)) throw new Error('Receipt asset inventory is unavailable')
  return pages.flat()
}
function verify (name, inventory) {
  const rows = inventory.filter(a => a.name === names[name])
  if (!rows.length) return false
  const local = path.join(dir, name)
  if (rows.length !== 1 || rows[0].state !== 'uploaded' || rows[0].size !== fs.statSync(local).size || rows[0].digest !== `sha256:${digest(local)}` || !Number.isSafeInteger(rows[0].id)) throw new Error('Occupied promotion asset differs from immutable local receipt')
  const bytes = run('gh', ['api', '-H', 'Accept: application/octet-stream', `repos/${RELEASE_REPOSITORY}/releases/assets/${rows[0].id}`], { encoding: null })
  if (crypto.createHash('sha256').update(bytes).digest('hex') !== digest(local)) throw new Error('Published promotion receipt bytes differ')
  return true
}
const before = assets()
const missing = files.filter(name => !verify(name, before))
if (missing.length) {
  const releaseEvidence = readJson(path.join(dir, 'release-evidence.json'))
  const qualified = verifyQualification({ bundleDir: dir, release: releaseEvidence, allowedSigners: process.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_FILE })
  if (receipt.qualification?.sha256 !== digest(path.join(dir, 'release-qualification.json')) || receipt.qualification?.signatureSha256 !== digest(path.join(dir, 'release-qualification.json.sig')) || receipt.qualification?.trustSha256 !== qualified.trustHash || receipt.artifact.releaseEvidenceSha256 !== digest(path.join(dir, 'release-evidence.json')) || receipt.fleetEvidence.sha256 !== digest(path.join(dir, receipt.fleetEvidence.path))) throw new Error('Publication receipt is not bound to independently signed qualification and retained evidence')
}
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-promotion-assets-'))
try {
  for (const name of missing) {
    const upload = path.join(temp, names[name])
    fs.copyFileSync(path.join(dir, name), upload)
    run('gh', ['release', 'upload', tag, upload, '--repo', RELEASE_REPOSITORY])
  }
  const after = assets()
  for (const name of files) if (!verify(name, after)) throw new Error('Promotion receipt publication is incomplete')
  console.log('Distinct promotion receipts published and exact bytes reread')
} finally { fs.rmSync(temp, { recursive: true, force: true }) }
