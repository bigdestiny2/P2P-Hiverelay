#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { run, parseArgs } from './io.mjs'

const args = parseArgs(process.argv.slice(2), ['--tag', '--prerelease'])
const tag = args['--tag']
const prerelease = args['--prerelease']
const repository = 'bigdestiny2/P2P-Hiverelay'
if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag || '') || !['true', 'false'].includes(prerelease)) {
  throw new Error('Exact tag and prerelease identity are required')
}
let release = get(`repos/${repository}/releases/tags/${tag}`)
if (release == null) {
  const command = ['release', 'create', tag, '--repo', repository, '--verify-tag', '--latest=false', '--title', tag,
    '--notes', `Versioned artifacts for ${tag}. Consumer, canary, fleet and stable distribution qualification remain pending.`]
  if (prerelease === 'true') command.push('--prerelease')
  run('gh', command)
  release = get(`repos/${repository}/releases/tags/${tag}`)
}
if (!release || release.tag_name !== tag || release.draft !== false || release.prerelease !== (prerelease === 'true')) {
  throw new Error('GitHub Release differs from immutable tag/prerelease identity')
}
const latest = get(`repos/${repository}/releases/latest`)
if (latest?.id === release.id) throw new Error('Artifact Release is already latest; ordinary artifact execution cannot alter a stable pointer')
console.log('GitHub artifact Release identity and explicit non-latest state verified')

function get (endpoint) {
  const result = spawnSync('gh', ['api', '--include', endpoint], { encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024 })
  const match = /^HTTP\/[^ ]+ (\d{3})[^\r\n]*\r?\n[\s\S]*?\r?\n\r?\n([\s\S]*)$/.exec(result.stdout || '')
  if (!result.error && !result.signal && match && match[1] === '404') return null
  if (result.error || result.signal || result.status !== 0 || !match || match[1] !== '200') throw new Error('Authenticated GitHub Release readback failed')
  return JSON.parse(match[2])
}
