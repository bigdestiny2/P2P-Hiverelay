import fs from 'node:fs'
import path from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { EXPECTED_CURRENT_CONSUMERS } from '../audit-ecosystem-consumers.mjs'
import { boundFile } from './qualification.mjs'
import { run, digest, exactKeys } from './io.mjs'

export const RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'
const SHA = /^[a-f0-9]{40}$/
const METADATA = ['package.json', 'package-lock.json', 'README.md', 'packages/core/package.json', 'packages/client/package.json', 'packages/verifier/package.json', 'packages/services/package.json', 'umbrel-app/docker-compose.yml', 'umbrel-app/umbrel-app.yml', 'startos/manifest.yaml', 'startos/Makefile', 'startos/README.md', 'truenas-app/app.yaml', 'truenas-app/ix_values.yaml', 'truenas-app/README.md', 'unraid-app/templates/blindspark.xml', 'zimaos-app/Apps/Blindspark/docker-compose.yml', 'runtipi-app/apps/blindspark/config.json', 'runtipi-app/apps/blindspark/docker-compose.yml', 'hexos-app/blindspark.json']
const COMMUNITY = ['hiverelay-blindspark/docker-compose.yml', 'hiverelay-blindspark/umbrel-app.yml', 'package.json', 'README.md', 'index.html']

export function distributionTargets (release, env) {
  const targets = [
    { role: 'metadata', repository: RELEASE_REPOSITORY, branch: release.release.stage.metadataBranch, allowed: METADATA },
    { role: 'umbrel-community', repository: 'bigdestiny2/blindspark-umbrel-store', branch: 'main', allowed: COMMUNITY },
    { role: 'umbrel-official', repository: env.UMBREL_OFFICIAL_FORK, branch: `blindspark-${release.release.version}`, allowed: ['blindspark/'] }
  ]
  if (!/^[A-Za-z0-9_.-]+\/umbrel-apps$/.test(env.UMBREL_OFFICIAL_FORK || '')) throw new Error('Protected official Umbrel fork is required')
  for (const consumer of EXPECTED_CURRENT_CONSUMERS.filter(c => c.release)) {
    const r = consumer.release
    let target = targets.find(t => t.repository === r.repository)
    if (!target) targets.push((target = { role: 'ecosystem-consumer', repository: r.repository, branch: r.ref, allowed: ['package.json', 'package-lock.json'] }))
    target.allowed.push(path.relative(r.checkoutPath, consumer.path))
    for (const term of consumer.sourceChecks || []) target.allowed.push(path.relative(r.checkoutPath, term.file))
  }
  return targets
}

export function prepareDistribution ({ qualification, bundleDir, release, workDir, env = process.env, execute = run }) {
  const plan = qualification.distribution
  exactKeys(plan, ['repositories', 'startosRegistry', 'officialPr'], 'distribution plan')
  const targets = distributionTargets(release, env)
  if (!Array.isArray(plan.repositories) || !isDeepStrictEqual(plan.repositories.map(r => r.repository).sort(), targets.map(r => r.repository).sort())) throw new Error('Reviewed distribution inventory omits or adds a repository')
  const prepared = []
  for (const [i, target] of targets.entries()) {
    const row = plan.repositories.find(r => r.repository === target.repository)
    exactKeys(row, ['role', 'repository', 'branch', 'baseCommit', 'treeSha', 'patch', 'files'], 'distribution repository')
    if (row.role !== target.role || row.branch !== target.branch || !SHA.test(row.baseCommit) || !SHA.test(row.treeSha) || !Array.isArray(row.files)) throw new Error('Reviewed distribution target differs from fixed release target')
    if (new Set(row.files.map(f => f.path)).size !== row.files.length || row.files.some(f => typeof f.path !== 'string' || !target.allowed.some(a => a.endsWith('/') ? f.path.startsWith(a) : f.path === a))) throw new Error('Reviewed file inventory is duplicated or unmanaged')
    const patch = boundFile(bundleDir, row.patch)
    const cwd = path.join(workDir, `repository-${i}`)
    execute('git', ['clone', '--no-checkout', '--', `https://github.com/${target.repository}.git`, cwd], { env, timeout: 120000 })
    const git = argv => execute('git', argv, { cwd, env }).trim()
    const remoteHead = git(['ls-remote', 'origin', `refs/heads/${row.branch}`]).split(/\s/)[0]
    const freshOfficialBranch = !remoteHead && row.role === 'umbrel-official'
    if (!SHA.test(remoteHead) && !freshOfficialBranch) throw new Error('Distribution branch is absent or ambiguous')
    git(['fetch', 'origin', remoteHead || row.baseCommit])
    git(['checkout', '--detach', remoteHead || row.baseCommit])
    const currentTree = git(['rev-parse', 'HEAD^{tree}'])
    if (remoteHead && currentTree === row.treeSha) {
      verifyPreparedFiles(cwd, row.files)
      prepared.push({ row, cwd, commit: remoteHead, alreadyCurrent: true })
      continue
    }
    if (!freshOfficialBranch && remoteHead !== row.baseCommit) throw new Error('Distribution branch moved beyond its reviewed base')
    git(['apply', '--index', '--whitespace=error', patch])
    const changed = git(['diff', '--cached', '--name-only', '-z']).split('\0').filter(Boolean).sort()
    if (!isDeepStrictEqual(changed, row.files.map(f => f.path).sort()) || changed.some(file => !target.allowed.some(a => a.endsWith('/') ? file.startsWith(a) : file === a))) throw new Error('Reviewed distribution patch touches an unmanaged path')
    verifyPreparedFiles(cwd, row.files)
    if (git(['write-tree']) !== row.treeSha) throw new Error('Prepared distribution tree differs from reviewed tree')
    // Same bounded commit/push operations as the existing workflow publishers;
    // stage only the reviewed index, never the consumer helper's broad `add -A`.
    git(['-c', 'user.name=hiverelay-release-bot', '-c', 'user.email=hiverelay-release-bot@users.noreply.github.com', 'commit', '-m', `chore: promote HiveRelay ${release.release.version}`])
    prepared.push({ row, cwd, commit: git(['rev-parse', 'HEAD']), alreadyCurrent: false, freshOfficialBranch })
  }
  const registry = plan.startosRegistry
  exactKeys(registry, ['url', 'packageUrl', 'packageSha256'], 'registry plan')
  if (registry.url !== env.STARTOS_REGISTRY_URL || registry.packageSha256 !== release.artifacts.startosPackage.sha256) throw new Error('Registry target or exact package hash differs from protected authority/artifact')
  const base = new URL(registry.url)
  const download = new URL(registry.packageUrl)
  if (base.protocol !== 'https:' || download.protocol !== 'https:' || base.origin !== download.origin || base.username || base.password || download.username || download.password || download.hash) throw new Error('Registry readback URL must use the authorized HTTPS registry origin')
  exactKeys(plan.officialPr, ['url', 'base', 'headOwner', 'headRef', 'reviewUrl', 'reviewHeadSha', 'reviewTreeSha'], 'official PR plan')
  if ((plan.officialPr.url !== '' && !/^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(plan.officialPr.url)) || plan.officialPr.base !== 'master' || plan.officialPr.headOwner !== env.UMBREL_OFFICIAL_FORK.split('/')[0] || plan.officialPr.headRef !== `blindspark-${release.release.version}`) throw new Error('Official draft PR must match the reviewed runtime handoff')
  verifyOriginalDeviceTree({ plan, release, env, execute })
  return prepared
}

export function publishDistribution ({ prepared, qualification, bundleDir, release, workDir, env = process.env, execute = run }) {
  const rows = []
  for (const item of prepared) {
    const { row, cwd, commit } = item
    if (!item.alreadyCurrent) execute('git', ['push', ...(item.freshOfficialBranch ? [`--force-with-lease=refs/heads/${row.branch}:`] : []), 'origin', `HEAD:refs/heads/${row.branch}`], { cwd, env, timeout: 120000 })
    const remote = execute('git', ['ls-remote', '--exit-code', 'origin', `refs/heads/${row.branch}`], { cwd, env }).trim().split(/\s/)[0]
    if (remote !== commit) throw new Error('Published repository readback differs from reviewed result')
    rows.push({ role: row.role, repository: row.repository, branch: row.branch, commit, treeSha: row.treeSha })
  }
  const plan = qualification.distribution
  const official = rows.find(r => r.role === 'umbrel-official')
  const head = `${plan.officialPr.headOwner}:${plan.officialPr.headRef}`
  const existing = JSON.parse(execute('gh', ['pr', 'list', '--repo', 'getumbrel/umbrel-apps', '--head', head, '--state', 'open', '--json', 'url'], { env }))
  if (!Array.isArray(existing) || existing.length > 1) throw new Error('Official PR lookup is ambiguous')
  let prUrl = existing[0]?.url || ''
  if (!prUrl) {
    if (plan.officialPr.url) throw new Error('Previously reviewed distribution PR is absent')
    const body = path.join(workDir, 'official-pr-body.md')
    fs.writeFileSync(body, `Promote the exact independently reviewed Blindspark tree for ${release.release.version}.\n\nDevice-review source: ${plan.officialPr.reviewUrl} at ${plan.officialPr.reviewHeadSha}.\nTree: ${plan.officialPr.reviewTreeSha}.\nImage: ${release.image.ref}.\nThe new PR URL is a distribution handoff; device evidence remains bound to its original review revision.\n`)
    prUrl = execute('gh', ['pr', 'create', '--repo', 'getumbrel/umbrel-apps', '--base', plan.officialPr.base, '--head', head, '--draft', '--title', `Blindspark ${release.release.version}`, '--body-file', body], { env }).trim()
  }
  if (!/^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(prUrl) || (plan.officialPr.url && plan.officialPr.url !== prUrl)) throw new Error('Official PR publication returned a conflicting URL')
  const pr = JSON.parse(execute('gh', ['pr', 'view', prUrl, '--json', 'state,isDraft,baseRefName,headRepositoryOwner,headRefName,headRefOid'], { env }))
  if (pr.state !== 'OPEN' || pr.isDraft !== true || pr.baseRefName !== plan.officialPr.base || pr.headRepositoryOwner?.login !== plan.officialPr.headOwner || pr.headRefName !== plan.officialPr.headRef || pr.headRefOid !== official.commit) throw new Error('Official Umbrel draft readback differs from published reviewed tree')
  const registry = plan.startosRegistry
  const packageFile = path.join(bundleDir, 'blindspark.s9pk')
  if (digest(packageFile) !== registry.packageSha256) throw new Error('StartOS package changed before registry publication')
  const downloaded = path.join(workDir, 'registry-readback.s9pk')
  const status = execute('curl', ['--silent', '--show-error', '--proto', '=https', '--max-time', '60', '--write-out', '%{http_code}', '--output', downloaded, registry.packageUrl], { env }).trim()
  if (status === '404') {
    execute('start-sdk', ['publish', registry.url, packageFile], { env, timeout: 300000 })
    execute('curl', ['--fail', '--silent', '--show-error', '--proto', '=https', '--max-time', '60', '--output', downloaded, registry.packageUrl], { env })
  } else if (status !== '200') throw new Error('Registry package probe is ambiguous')
  if (digest(downloaded) !== registry.packageSha256) throw new Error('Registry package readback differs from immutable artifact')
  return { repositories: rows, officialPr: { ...plan.officialPr, url: prUrl, commit: official.commit }, startosRegistry: registry }
}

export function verifyOriginalDeviceTree ({ plan, release, env = process.env, execute = run }) {
  const p = plan.officialPr
  const target = plan.repositories.find(r => r.role === 'umbrel-official')
  if (!/^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(p.reviewUrl) || !SHA.test(p.reviewHeadSha) || !SHA.test(p.reviewTreeSha) || p.reviewTreeSha !== target.treeSha) throw new Error('Device-reviewed and planned official trees differ')
  const prior = JSON.parse(execute('gh', ['pr', 'view', p.reviewUrl, '--json', 'headRepositoryOwner,headRepository,headRefOid'], { env }))
  if (prior.headRefOid !== p.reviewHeadSha || `${prior.headRepositoryOwner?.login}/${prior.headRepository?.name}` !== target.repository) throw new Error('Live original device-reviewed PR revision moved')
  const commit = JSON.parse(execute('gh', ['api', `repos/${target.repository}/git/commits/${p.reviewHeadSha}`], { env }))
  if (commit.tree?.sha !== p.reviewTreeSha) throw new Error('Original reviewed PR tree differs from approved distribution bytes')
  const compose = execute('gh', ['api', '-H', 'Accept: application/vnd.github.raw+json', `repos/${target.repository}/contents/blindspark/docker-compose.yml?ref=${p.reviewHeadSha}`], { env })
  if (!compose.includes(release.image.ref)) throw new Error('Original device-reviewed appliance image differs from artifact digest')
}

function verifyPreparedFiles (cwd, files) {
  for (const file of files) {
    exactKeys(file, ['path', 'sha256'], 'distribution file')
    const local = path.resolve(cwd, file.path)
    if (!local.startsWith(cwd + path.sep) || fs.realpathSync(local) !== local || !fs.lstatSync(local).isFile() || digest(local) !== file.sha256) throw new Error('Prepared distribution bytes differ from review')
  }
}
