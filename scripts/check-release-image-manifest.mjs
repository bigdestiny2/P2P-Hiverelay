#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const usage = `
Usage:
  node scripts/check-release-image-manifest.mjs --image ghcr.io/bigdestiny2/p2p-hiverelay:X.Y.Z@sha256:<digest> --out release-image-manifest-evidence.json
  node scripts/check-release-image-manifest.mjs --image ... --raw imagetools-raw.json --out release-image-manifest-evidence.json

Verifies that a pushed release image digest is a multi-platform manifest with
linux/amd64 and linux/arm64 entries, then writes public-safe evidence.
`

const EXPECTED_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const MAX_RAW_MANIFEST_BYTES = 2 * 1024 * 1024
const REQUIRED_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])
const DIGEST_PINNED_IMAGE_REF_PATTERN = /^(ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9._/-]+):(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)@(sha256:[a-f0-9]{64})$/
const INDEX_MEDIA_TYPES = new Set([
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.index.v1+json'
])

const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log(usage.trim())
  process.exit(0)
}

const image = parseImageRef(args.image || '')
const raw = args.raw ? readRawManifest(args.raw) : inspectImageRaw(args.image)
const manifest = parseRawJson(raw, 'image manifest')
const evidence = buildEvidence(image, manifest)
validateEvidence(evidence)
writeJson(path.resolve(args.out || 'release-image-manifest-evidence.json'), evidence)
console.log(`Release image manifest evidence written for ${evidence.image.ref}`)

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--image') {
      out.image = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--raw') {
      out.raw = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--out') {
      out.out = readValue(argv, ++i, arg)
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function parseImageRef (value) {
  const match = DIGEST_PINNED_IMAGE_REF_PATTERN.exec(String(value || ''))
  if (!match) {
    die('release image manifest check requires a GHCR semver tag plus sha256 digest image ref')
  }
  const image = {
    ref: value,
    name: match[1],
    tag: match[2],
    digest: match[3]
  }
  if (image.name !== EXPECTED_IMAGE_NAME) {
    die(`release image name must be ${EXPECTED_IMAGE_NAME}; got ${image.name}`)
  }
  return image
}

function readRawManifest (file) {
  const resolved = path.resolve(file)
  const stat = fs.lstatSync(resolved)
  if (stat.isSymbolicLink()) die(`raw manifest file must not be a symlink: ${resolved}`)
  if (!stat.isFile()) die(`raw manifest file must be a regular file: ${resolved}`)
  if (stat.size > MAX_RAW_MANIFEST_BYTES) {
    die(`raw manifest file must be ${MAX_RAW_MANIFEST_BYTES} bytes or smaller: ${resolved} is ${stat.size} bytes`)
  }
  return fs.readFileSync(resolved, 'utf8')
}

function inspectImageRaw (imageRef) {
  const result = spawnSync('docker', ['buildx', 'imagetools', 'inspect', '--raw', imageRef], {
    encoding: 'utf8',
    maxBuffer: MAX_RAW_MANIFEST_BYTES
  })
  if (result.status !== 0) {
    const message = redactSensitiveOutput(result.stderr || result.stdout || `docker exited ${result.status}`)
    die(`docker buildx imagetools inspect failed: ${message}`)
  }
  return result.stdout
}

function parseRawJson (value, label) {
  assertRawDoesNotContainSecrets(value, `${label} raw JSON`)
  try {
    return JSON.parse(value)
  } catch (err) {
    die(`${label} must be JSON: ${err.message}`)
  }
}

function buildEvidence (image, manifest) {
  if (!INDEX_MEDIA_TYPES.has(manifest?.mediaType)) {
    die(`release image manifest must be a Docker manifest list or OCI image index; got ${JSON.stringify(manifest?.mediaType)}`)
  }
  if (!Array.isArray(manifest.manifests) || manifest.manifests.length === 0) {
    die('release image manifest must include platform manifests')
  }

  const platforms = []
  for (const entry of manifest.manifests) {
    if (isAttestationManifest(entry)) continue
    const platform = entry?.platform || {}
    const os = String(platform.os || '')
    const architecture = String(platform.architecture || '')
    const variant = String(platform.variant || '')
    const digest = String(entry?.digest || '')
    if (!os || !architecture) continue
    if (!/^sha256:[a-f0-9]{64}$/i.test(digest)) {
      die(`release image platform ${os}/${architecture} has malformed digest ${JSON.stringify(digest)}`)
    }
    platforms.push({ os, architecture, variant, digest })
  }

  const labels = new Set()
  for (const platform of platforms) {
    const label = platformLabel(platform)
    if (labels.has(label)) die(`release image manifest has duplicate platform ${label}`)
    labels.add(label)
  }
  for (const required of REQUIRED_PLATFORMS) {
    if (!labels.has(required)) die(`release image manifest is missing required platform ${required}`)
  }

  platforms.sort((a, b) => platformLabel(a).localeCompare(platformLabel(b)))

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    kind: 'release-image-manifest',
    status: 'verified',
    image: {
      name: image.name,
      tag: image.tag,
      digest: image.digest,
      ref: image.ref
    },
    requiredPlatforms: [...REQUIRED_PLATFORMS],
    platforms,
    manifest: {
      mediaType: manifest.mediaType,
      manifestCount: manifest.manifests.length
    }
  }
}

function validateEvidence (body) {
  assertPublicSafeValues(body, 'release image manifest evidence')
  assertEvidenceSchema(body)
  requireEqual('release image manifest evidence schemaVersion', body.schemaVersion, 1)
  requireEqual('release image manifest evidence kind', body.kind, 'release-image-manifest')
  requireEqual('release image manifest evidence status', body.status, 'verified')
  requirePattern('release image manifest evidence generatedAt', body.generatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  requireEqual('release image manifest image name', body.image.name, EXPECTED_IMAGE_NAME)
  requirePattern('release image manifest image tag', body.image.tag, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
  requirePattern('release image manifest image digest', body.image.digest, /^sha256:[a-f0-9]{64}$/i)
  requireEqual('release image manifest image ref', body.image.ref, `${body.image.name}:${body.image.tag}@${body.image.digest}`)
  requireArrayEqual('release image manifest required platforms', body.requiredPlatforms, REQUIRED_PLATFORMS)
  if (!Array.isArray(body.platforms) || body.platforms.length < REQUIRED_PLATFORMS.length) {
    die('release image manifest evidence must include platform entries')
  }
  const labels = new Set()
  for (const platform of body.platforms) {
    requirePattern('release image manifest platform os', platform.os, /^[a-z0-9._-]{1,32}$/)
    requirePattern('release image manifest platform architecture', platform.architecture, /^[a-z0-9._-]{1,32}$/)
    if (platform.variant) requirePattern('release image manifest platform variant', platform.variant, /^[A-Za-z0-9._-]{1,32}$/)
    requirePattern('release image manifest platform digest', platform.digest, /^sha256:[a-f0-9]{64}$/i)
    const label = platformLabel(platform)
    if (labels.has(label)) die(`release image manifest evidence has duplicate platform ${label}`)
    labels.add(label)
  }
  for (const required of REQUIRED_PLATFORMS) {
    if (!labels.has(required)) die(`release image manifest evidence is missing required platform ${required}`)
  }
  requireOneOf('release image manifest media type', body.manifest.mediaType, [...INDEX_MEDIA_TYPES])
  if (!Number.isSafeInteger(body.manifest.manifestCount) || body.manifest.manifestCount < body.platforms.length) {
    die('release image manifest manifestCount is malformed')
  }
}

function assertEvidenceSchema (body) {
  requireOnlyKeys('release image manifest evidence', body, [
    'schemaVersion',
    'generatedAt',
    'kind',
    'status',
    'image',
    'requiredPlatforms',
    'platforms',
    'manifest'
  ])
  requireOnlyKeys('release image manifest image', body.image, ['name', 'tag', 'digest', 'ref'])
  if (Array.isArray(body.platforms)) {
    for (const platform of body.platforms) {
      requireOnlyKeys(`release image manifest platform ${platform?.os || ''}/${platform?.architecture || ''}`, platform, [
        'os',
        'architecture',
        'variant',
        'digest'
      ])
    }
  }
  requireOnlyKeys('release image manifest manifest', body.manifest, ['mediaType', 'manifestCount'])
}

function isAttestationManifest (entry) {
  return entry?.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest'
}

function platformLabel (platform) {
  return `${platform.os}/${platform.architecture}`
}

function writeJson (file, body) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n')
  fs.renameSync(tmp, file)
}

function requireEqual (label, actual, expected) {
  if (actual === expected) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requirePattern (label, value, pattern) {
  if (typeof value === 'string' && pattern.test(value)) return
  die(`${label} is required and malformed; got ${JSON.stringify(value)}`)
}

function requireOneOf (label, value, allowed) {
  if (allowed.includes(value)) return
  die(`${label} must be ${allowed.join(' or ')}; got ${JSON.stringify(value)}`)
}

function requireArrayEqual (label, actual, expected) {
  if (Array.isArray(actual) && actual.length === expected.length && actual.every((item, i) => item === expected[i])) return
  die(`${label} must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`)
}

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function assertPublicSafeValues (value, label) {
  visit(value, '$')

  function visit (node, at) {
    if (node == null) return
    if (typeof node === 'string') {
      assertPublicSafeString(node, label, at)
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
    }
  }
}

function assertPublicSafeString (value, label, at) {
  if (hasControlChars(value)) die(`${label} must not contain control characters at ${at}`)
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) die(`${label} must not contain ${name} at ${at}`)
  }
  try {
    const url = new URL(value)
    if (url.username || url.password) die(`${label} must not expose URL credentials at ${at}`)
  } catch (_) {}
}

function assertRawDoesNotContainSecrets (value, label) {
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) die(`${label} must not contain ${name}`)
  }
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function redactSensitiveOutput (value) {
  return String(value)
    .replace(/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----[\s\S]*?-----END [A-Z ]*(?:PRIVATE|SECRET) KEY-----/g, '[redacted key block]')
    .replace(/\bAuthorization\s*:\s*[^\r\n]*/gi, '[redacted authorization header]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, '[redacted bearer token]')
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bAPP_SEED=[^\s'"]+/gi, '[redacted APP_SEED]')
    .replace(/\bHIVERELAY_API_KEY=[^\s'"]+/gi, '[redacted HIVERELAY_API_KEY]')
    .replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, '[redacted API key]')
    .replace(/(\bhttps?:\/\/)([^/\s:@]+):([^@\s/]+)@/gi, '$1[redacted]@')
}

function die (message) {
  console.error(message)
  process.exit(1)
}
