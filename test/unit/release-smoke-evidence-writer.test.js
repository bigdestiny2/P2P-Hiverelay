import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

async function readScript (path) {
  return readFile(path, 'utf8')
}

function runNode (argv, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, argv, {
      cwd: process.cwd(),
      timeout: 10000,
      env: { ...process.env, ...(opts.env || {}) }
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve({ stdout, stderr })
      }
    })
  })
}

async function fileExists (file) {
  try {
    await readFile(file)
    return true
  } catch {
    return false
  }
}

function assertSmokeWriterPublicSafety (t, source, label) {
  t.ok(source.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS'), `${label} scans secret-looking values`)
  t.ok(source.includes('FORBIDDEN_PUBLIC_SMOKE_KEYS'), `${label} rejects forbidden public evidence keys`)
  t.ok(source.includes('assertPublicSafeSmoke'), `${label} has a smoke evidence safety assertion`)
  t.ok(source.includes('hasControlChars'), `${label} rejects control-character public evidence values`)
  t.ok(source.includes('must not contain control characters'), `${label} reports control-character evidence values`)
  t.ok(source.includes('must not expose URL credentials'), `${label} rejects credentialed URLs`)
  t.ok(source.includes('writeSmokeEvidence'), `${label} writes a smoke evidence sidecar`)
  t.ok(source.includes('redactSensitiveOutput'), `${label} redacts failure output`)
  t.ok(source.includes('writeRedactedOutput'), `${label} redacts docker logs before printing`)
  t.ok(source.includes('formatCommand(cmd, argv)'), `${label} redacts command errors`)
  t.ok(source.includes('redactSensitiveOutput(stderr)'), `${label} redacts subprocess stderr`)
  t.ok(source.includes('isDigestPinnedImageRef'), `${label} requires digest-pinned refs for public evidence`)
  t.ok(source.includes('DIGEST_PINNED_IMAGE_REF_PATTERN'), `${label} parses digest-pinned refs`)
  t.ok(source.includes('parseDigestPinnedImageRef'), `${label} records parsed image provenance`)
  t.ok(source.includes('imageName'), `${label} records the image repository`)
  t.ok(source.includes('imageTag'), `${label} records the release image tag`)
  t.ok(source.includes('imageDigest'), `${label} records the image digest`)
  t.ok(source.includes('requires a GHCR semver tag plus sha256 digest image ref'), `${label} reports mutable evidence image refs`)
  t.ok(source.includes('assertDashboardWebSocket'), `${label} verifies authenticated dashboard live feed`)
  t.ok(source.includes('queryTokenRejected'), `${label} proves dashboard live feed rejects URL tokens`)
  t.ok(source.includes('isHttpClientErrorStatus'), `${label} accepts HTTP 4xx query-token rejection statuses`)
  t.ok(source.includes('headers: { Origin: baseUrl }'), `${label} sends browser-like same-origin WebSocket origin`)
  t.ok(source.includes("JSON.stringify({ type: 'auth', token })"), `${label} authenticates dashboard live feed in-band`)
  t.ok(source.includes('assertDashboardUiHardening'), `${label} verifies packaged dashboard UI-hardening contracts`)
  t.ok(source.includes('assertSetupWizardUiHardening'), `${label} verifies packaged setup wizard UI-hardening contracts`)

  if (label === 'release image smoke') {
    t.ok(source.includes('walletBusyState'), `${label} records wallet busy-state proof`)
    t.ok(source.includes('serviceActionState'), `${label} records service action-state proof`)
    t.ok(source.includes('aiModelAddState'), `${label} records AI model action-state proof`)
    t.ok(source.includes('appProxyWrites'), `${label} records app-proxy write proof`)
    t.ok(source.includes('leasePollingBounded'), `${label} records bounded lease polling proof`)
    t.ok(source.includes('staticMarkupSafe'), `${label} records static-markup safety proof`)
    t.ok(source.includes('statusRegion'), `${label} records setup status-region proof`)
    t.ok(source.includes('actionLock'), `${label} records setup action-lock proof`)
    t.ok(source.includes('dashboardLinkAppPath'), `${label} records setup dashboard-link proof`)
  }

  if (label === 'Umbrel package smoke') {
    t.ok(source.includes('dashboardUiHardening'), `${label} records dashboard UI-hardening proof`)
    t.ok(source.includes('setupUiHardening'), `${label} records setup UI-hardening proof`)
    t.ok(source.includes('appProxyWrites'), `${label} records app-proxy write proof`)
    t.ok(source.includes('leasePollingBounded'), `${label} records bounded lease polling proof`)
    t.ok(source.includes('dashboardStaticMarkupSafe'), `${label} records dashboard static-markup proof`)
    t.ok(source.includes('dashboardLinkAppPath'), `${label} records setup dashboard-link proof`)
    t.ok(source.includes('setupStaticMarkupSafe'), `${label} records setup static-markup proof`)
  }

  const checkIndex = source.indexOf('assertPublicSafeSmoke(body')
  const writeIndex = source.search(/(?:fs\.)?writeFileSync\(tmp/)
  t.ok(checkIndex !== -1, `${label} calls public-safety assertion`)
  t.ok(writeIndex !== -1, `${label} writes the public sidecar`)
  t.ok(checkIndex < writeIndex, `${label} scans the public body before writing it`)
}

test('release smoke evidence writers scan public sidecars before writing', async (t) => {
  assertSmokeWriterPublicSafety(
    t,
    await readScript('scripts/smoke-release-image.mjs'),
    'release image smoke'
  )

  assertSmokeWriterPublicSafety(
    t,
    await readScript('scripts/smoke-umbrel-package.mjs'),
    'Umbrel package smoke'
  )
})

test('release smoke scripts reject malformed timeout values before side effects', async (t) => {
  const cases = [
    ['scripts/smoke-release-image.mjs', ['ghcr.io/example/hiverelay:9.9.9', '--timeout-ms', '1000.5']],
    ['scripts/smoke-release-image.mjs', ['ghcr.io/example/hiverelay:9.9.9', '--timeout-ms', '999999999999999999999']],
    ['scripts/smoke-umbrel-package.mjs', ['--timeout-ms', '1000.5']],
    ['scripts/smoke-umbrel-package.mjs', ['--timeout-ms', '999999999999999999999']]
  ]

  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args])
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects ${args.at(-1)}`)
    t.ok(err.stderr.includes('--timeout-ms must be an integer between 1000 and 1800000'), `${script} reports bounded integer timeout`)
  }
})

test('release smoke scripts require digest-pinned image refs before writing public evidence', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-smoke-digest-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const cases = [
    [
      'scripts/smoke-release-image.mjs',
      [
        'ghcr.io/example/hiverelay:9.9.9',
        '--evidence', path.join(dir, 'release-image-smoke-evidence.json'),
        '--timeout-ms', '1000'
      ],
      'release image smoke evidence requires a GHCR semver tag plus sha256 digest image ref',
      path.join(dir, 'release-image-smoke-evidence.json')
    ],
    [
      'scripts/smoke-umbrel-package.mjs',
      [
        '--image-ref', 'ghcr.io/example/hiverelay:9.9.9',
        '--evidence', path.join(dir, 'umbrel-package-smoke-evidence.json'),
        '--timeout-ms', '1000'
      ],
      'Umbrel package smoke evidence requires a GHCR semver tag plus sha256 digest image ref',
      path.join(dir, 'umbrel-package-smoke-evidence.json')
    ]
  ]

  for (const [script, args, message, evidenceFile] of cases) {
    let err = null
    try {
      await runNode([script, ...args])
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects mutable tag refs for evidence`)
    t.ok(err.stderr.includes(message), `${script} reports the digest-pin requirement`)
    t.absent(await fileExists(evidenceFile), `${script} does not write failed evidence`)
  }
})

test('release smoke scripts require release image manifest evidence before writing public evidence', async (t) => {
  const dir = await mkdtemp(path.join(process.cwd(), '.tmp-hiverelay-smoke-manifest-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const digestRef = `ghcr.io/example/hiverelay:9.9.9@sha256:${'a'.repeat(64)}`
  const cases = [
    [
      'scripts/smoke-release-image.mjs',
      [digestRef, '--evidence', path.join(dir, 'release-image-smoke-evidence.json'), '--timeout-ms', '1000']
    ],
    [
      'scripts/smoke-umbrel-package.mjs',
      ['--image-ref', digestRef, '--evidence', path.join(dir, 'umbrel-package-smoke-evidence.json'), '--timeout-ms', '1000']
    ]
  ]

  const missingManifest = path.relative(process.cwd(), path.join(dir, 'missing-manifest.json'))
  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], {
        env: { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: missingManifest }
      })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects missing manifest evidence`)
    t.ok(err.stderr.includes(`release image manifest evidence file is required before writing smoke evidence: ${missingManifest}`), `${script} reports missing manifest evidence`)
  }

  const targetManifest = path.join(dir, 'manifest-target.json')
  const symlinkManifest = path.join(dir, 'symlink-manifest.json')
  await writeFile(targetManifest, '{}\n')
  await symlink('manifest-target.json', symlinkManifest)
  const symlinkManifestRel = path.relative(process.cwd(), symlinkManifest)
  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], {
        env: { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: symlinkManifestRel }
      })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects symlinked manifest evidence`)
    t.ok(err.stderr.includes(`release image manifest evidence file must not be a symlink: ${symlinkManifestRel}`), `${script} reports symlinked manifest evidence`)
  }

  const oversizedManifest = path.join(dir, 'oversized-manifest.json')
  await writeFile(oversizedManifest, Buffer.alloc(2 * 1024 * 1024 + 1, 'x'))
  const oversizedManifestRel = path.relative(process.cwd(), oversizedManifest)
  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], {
        env: { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: oversizedManifestRel }
      })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects oversized manifest evidence`)
    t.ok(err.stderr.includes('release image manifest evidence file must be 2097152 bytes or smaller'), `${script} reports oversized manifest evidence`)
  }

  const staleManifest = path.join(dir, 'stale-manifest.json')
  await writeFile(staleManifest, JSON.stringify(imageManifestEvidence(digestRef, {
    image: { digest: `sha256:${'b'.repeat(64)}` }
  })) + '\n')
  const staleManifestRel = path.relative(process.cwd(), staleManifest)
  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], {
        env: { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: staleManifestRel }
      })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects stale manifest image provenance`)
    t.ok(err.stderr.includes('release image manifest image ref must match smoke image ref'), `${script} reports stale manifest image provenance`)
  }

  const missingPlatformManifest = path.join(dir, 'missing-platform-manifest.json')
  const missingPlatform = imageManifestEvidence(digestRef)
  missingPlatform.platforms = missingPlatform.platforms.filter((platform) => platform.architecture !== 'arm64')
  await writeFile(missingPlatformManifest, JSON.stringify(missingPlatform) + '\n')
  const missingPlatformRel = path.relative(process.cwd(), missingPlatformManifest)
  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], {
        env: { HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE: missingPlatformRel }
      })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} rejects incomplete manifest platforms`)
    t.ok(err.stderr.includes('release image manifest evidence is missing required platform linux/arm64'), `${script} reports incomplete manifest platforms`)
  }
})

test('release smoke scripts redact failed docker logs and command output', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-smoke-redaction-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const dockerPath = path.join(dir, 'docker')
  await writeFile(dockerPath, `#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  run)
    exit 0
    ;;
  logs)
    printf '%s\\n' 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'
    printf '%s\\n' 'APP_SEED=super-secret-seed'
    printf '%s\\n' 'HIVERELAY_API_KEY=super-secret-key'
    printf '%s\\n' 'sk-abcdefghijklmnopqrstuvwxyz'
    exit 0
    ;;
  rm)
    exit 0
    ;;
esac
exit 0
`)
  await chmod(dockerPath, 0o755)

  const env = { PATH: dir + path.delimiter + process.env.PATH }
  const cases = [
    ['scripts/smoke-release-image.mjs', ['ghcr.io/example/hiverelay:9.9.9', '--timeout-ms', '1000']],
    ['scripts/smoke-umbrel-package.mjs', ['--image-ref', 'ghcr.io/example/hiverelay:9.9.9', '--timeout-ms', '1000']]
  ]

  for (const [script, args] of cases) {
    let err = null
    try {
      await runNode([script, ...args], { env })
    } catch (e) {
      err = e
    }

    t.ok(err, `${script} fails because mock container never serves health`)
    const combined = `${err.stdout}\n${err.stderr}`
    t.absent(combined.includes('Authorization: Bearer abcdefghijklmnopqrstuvwxyz'), `${script} redacts authorization header`)
    t.absent(combined.includes('abcdefghijklmnopqrstuvwxyz'), `${script} redacts bearer/API token body`)
    t.absent(combined.includes('APP_SEED=super-secret-seed'), `${script} redacts app seed`)
    t.absent(combined.includes('HIVERELAY_API_KEY=super-secret-key'), `${script} redacts API key env`)
    t.ok(combined.includes('[redacted'), `${script} leaves an explicit redaction marker`)
  }
})

function imageManifestEvidence (imageRef, overrides = {}) {
  const match = /^(ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9._/-]+):(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)@(sha256:[a-f0-9]{64})$/.exec(imageRef)
  const image = {
    name: match[1],
    tag: match[2],
    digest: match[3],
    ref: imageRef,
    ...(overrides.image || {})
  }
  if (overrides.image) image.ref = `${image.name}:${image.tag}@${image.digest}`
  return {
    schemaVersion: 1,
    generatedAt: '2026-06-24T00:00:00.000Z',
    kind: 'release-image-manifest',
    status: 'verified',
    image,
    requiredPlatforms: ['linux/amd64', 'linux/arm64'],
    platforms: [
      { os: 'linux', architecture: 'amd64', variant: '', digest: `sha256:${'c'.repeat(64)}` },
      { os: 'linux', architecture: 'arm64', variant: 'v8', digest: `sha256:${'d'.repeat(64)}` }
    ],
    manifest: {
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifestCount: 2
    },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => key !== 'image'))
  }
}
