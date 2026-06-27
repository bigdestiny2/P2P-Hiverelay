import test from 'brittle'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { scanPublicArtifacts } from '../../scripts/check-public-artifact-secrets.mjs'

async function tempRepo (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-public-artifacts-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  await mkdir(path.join(dir, 'docs', 'assets'), { recursive: true })
  await mkdir(path.join(dir, '.github', 'workflows'), { recursive: true })
  return dir
}

test('public artifact secret scan passes scanner-safe docs and workflows', async (t) => {
  const dir = await tempRepo(t)
  await writeFile(path.join(dir, 'README.md'), 'Use PASTE_GITHUB_TOKEN_HERE.\n')
  await writeFile(path.join(dir, 'docs', 'release.md'), 'Paste the full private key block locally.\n')
  await writeFile(path.join(dir, '.github', 'workflows', 'release.yml'), 'name: release\n')
  await writeFile(path.join(dir, 'docs', 'assets', 'diagram.svg'), '-----BEGIN OPENSSH PRIVATE KEY-----\n')

  const result = scanPublicArtifacts({ root: dir })
  t.ok(result.ok)
  t.is(result.findings.length, 0)
})

test('public artifact secret scan reports token, bearer, and key examples', async (t) => {
  const dir = await tempRepo(t)
  await writeFile(path.join(dir, 'README.md'), 'token=ghp_example\n')
  await writeFile(path.join(dir, 'docs', 'release.md'), '-----BEGIN PRIVATE KEY-----\n')
  await writeFile(path.join(dir, '.github', 'workflows', 'release.yml'), 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n')

  const result = scanPublicArtifacts({ root: dir })
  t.absent(result.ok)
  t.is(result.findings.length, 3)
  t.ok(result.findings.some(finding => finding.path === 'README.md' && finding.pattern === 'GitHub token prefix example'))
  t.ok(result.findings.some(finding => finding.path === 'docs/release.md' && finding.pattern === 'private key delimiter example'))
  t.ok(result.findings.some(finding => finding.path === '.github/workflows/release.yml' && finding.pattern === 'Bearer authorization example'))
})
