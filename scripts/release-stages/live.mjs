import path from 'node:path'
import { run } from './io.mjs'
import { RELEASE_REPOSITORY } from './distribution.mjs'

export function verifyNpmBytes (release, { latest = false, execute = run, env = process.env } = {}) {
  for (const row of release.release.stage.packages) {
    const actual = JSON.parse(execute('npm', ['view', `${row.name}@${row.version}`, 'dist', '--json'], { env }))
    if (actual.integrity !== row.integrity || actual.shasum !== row.shasum) throw new Error('Live npm immutable bytes differ from accepted artifact')
    if (latest && JSON.parse(execute('npm', ['view', row.name, 'dist-tags.latest', '--json'], { env })) !== row.version) throw new Error('npm latest readback differs from accepted version')
  }
}

export function verifyImageBytes (release, manifest, repoRoot, { latest = false, execute = run, env = process.env } = {}) {
  const children = ['amd64', 'arm64'].map(architecture => {
    const rows = manifest.platforms.filter(r => r.os === 'linux' && r.architecture === architecture)
    if (rows.length !== 1) throw new Error('Artifact image lacks an exact required platform')
    return rows[0]
  })
  const raw = execute('docker', ['buildx', 'imagetools', 'inspect', latest ? `${release.image.name}:latest` : release.image.ref, '--raw'], { env })
  execute(process.execPath, [path.join(repoRoot, 'scripts/verify-startos-04-image-index.mjs'), '--index-digest', release.image.digest, '--amd64-digest', children[0].digest, '--arm64-digest', children[1].digest], { input: raw, env })
  for (const child of children) {
    const image = execute('docker', ['buildx', 'imagetools', 'inspect', `${release.image.name}@${child.digest}`, '--format', '{{json .Image}}'], { env })
    execute(process.execPath, [path.join(repoRoot, 'scripts/verify-startos-04-image-revision.mjs'), '--os', 'linux', '--architecture', child.architecture, '--revision', release.release.tagSha], { input: image, env })
  }
  return children
}

export function githubRelease (release, { latest = false, execute = run, env = process.env } = {}) {
  const value = JSON.parse(execute('gh', ['api', `repos/${RELEASE_REPOSITORY}/releases/${latest ? 'latest' : `tags/${release.release.version}`}`], { env }))
  if (!Number.isSafeInteger(value.id) || value.id < 1 || value.tag_name !== release.release.version || value.draft !== false || value.prerelease !== release.release.prerelease) throw new Error('GitHub release identity changed')
  return value.id
}

export function promoteLabels (release, manifest, repoRoot, options = {}) {
  const { execute = run, env = process.env } = options
  verifyNpmBytes(release, options)
  verifyImageBytes(release, manifest, repoRoot, options)
  const id = githubRelease(release, options)
  for (const row of release.release.stage.packages) {
    execute(process.execPath, [path.join(repoRoot, 'scripts/ensure-npm-dist-tag.mjs'), '--package', row.name, '--version', row.version, '--tag', 'latest'], { env, timeout: 300000 })
  }
  execute('docker', ['buildx', 'imagetools', 'create', '--tag', `${release.image.name}:latest`, release.image.ref], { env, timeout: 120000 })
  execute('gh', ['api', '--method', 'PATCH', `repos/${RELEASE_REPOSITORY}/releases/${id}`, '-f', 'make_latest=true'], { env })
  verifyNpmBytes(release, { ...options, latest: true })
  verifyImageBytes(release, manifest, repoRoot, { ...options, latest: true })
  if (githubRelease(release, { ...options, latest: true }) !== id) throw new Error('GitHub latest points to a different release')
  return { npm: 'verified', image: 'verified', githubReleaseId: id }
}
