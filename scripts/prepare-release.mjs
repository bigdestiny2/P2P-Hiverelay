#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_DEPENDENCY_MODE
} from './audit-ecosystem-consumers.mjs'
import { checkEcosystemWorkspace } from './check-ecosystem-workspace.mjs'
import { assertNarrowReleasePromise } from './lib/release-promise-scope.mjs'
import { syncEcosystemConsumers } from './sync-ecosystem-consumers.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')
const workspaceRoot = path.resolve(repoRoot, '..')
const ecosystemWorkspaceRootDefault = path.resolve(repoRoot, '..', '..')
const imageName = 'ghcr.io/bigdestiny2/p2p-hiverelay'
const README_STATUS_REGEX = /Status:\s*v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:[^\n*|]*)?/

const FORBIDDEN_PUBLIC_RELEASE_NOTES_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key'],
  [/\bhttps?:\/\/[^/\s:@]+:[^@\s/]+@/i, 'URL credentials']
]

const usage = `
Usage:
  node scripts/prepare-release.mjs vX.Y.Z --image-digest sha256:<digest> [options]

Options:
  --channel <canary|stable|both|none>  Fleet channel to bump (default: both; prereleases: none)
  --image-digest <sha256:...>          Multi-arch GHCR image digest for app-store pins
  --release-notes <text>               Release notes for Umbrel/StartOS metadata
  --release-notes-file <path>          Read release notes from a file
  --umbrel-store <path>                Community Umbrel store checkout to sync
  --no-umbrel-store                    Skip the sibling community-store checkout
  --no-ecosystem-consumers             Skip sibling app consumer default sync
  --ecosystem-workspace-root <path>     Sibling app workspace root (default: ../../)
  --ecosystem-consumer-scope <scope>    Consumer sync scope: all or release (default: all)
  --ecosystem-dependency-mode <mode>    Consumer defaults: local or npm-latest (default: npm-latest)
  --allow-unpinned-image               Permit tag-only app-store image refs (not for review)
  --check                              Report drift without writing files
`

const args = parseArgs(process.argv.slice(2))
const versionInput = args._[0] || process.env.HIVERELAY_RELEASE_VERSION
const version = normalizeVersion(versionInput)
const tag = `v${version}`
const isPrerelease = version.includes('-')
const channel = args.channel || process.env.HIVERELAY_RELEASE_CHANNEL || defaultChannelForVersion(version)
const publicGatewayRelease = readPublicGatewayReleaseControl()
const imageDigest = normalizeDigest(args.imageDigest || process.env.HIVERELAY_IMAGE_DIGEST || '')
const checkOnly = Boolean(args.check)
const allowUnpinnedImage = Boolean(args.allowUnpinnedImage)
const releaseNotesInline = args.releaseNotes || process.env.HIVERELAY_RELEASE_NOTES || ''
const releaseNotesPath = args.releaseNotesFile || process.env.HIVERELAY_RELEASE_NOTES_FILE || ''
const releaseNotesProvided = Boolean(releaseNotesInline || releaseNotesPath)
const releaseNotes = loadReleaseNotes(releaseNotesInline, releaseNotesPath) ||
  `Blindspark ${tag}: synchronized HiveRelay release metadata for Docker, Umbrel, StartOS, TrueNAS, Unraid, ZimaOS/CasaOS, Runtipi, and HexOS.`
assertPublicReleaseNotes(releaseNotes)
// The community Umbrel store syncs on EVERY release so it never lags the fleet.
// For a full release it syncs by default; for a prerelease it syncs only when an
// explicit --umbrel-store target is given (the release workflow passes it
// whenever the store checkout is present). --no-umbrel-store always wins.
const syncUmbrelStore = !args.noUmbrelStore && (!isPrerelease || Boolean(args.umbrelStore))
const syncEcosystemDefaults = !args.noEcosystemConsumers && !isPrerelease
const ecosystemDependencyMode = args.ecosystemDependencyMode || process.env.HIVERELAY_ECOSYSTEM_DEPENDENCY_MODE || DEFAULT_DEPENDENCY_MODE
const ecosystemConsumerScope = args.ecosystemConsumerScope || process.env.HIVERELAY_ECOSYSTEM_CONSUMER_SCOPE || 'all'
const ecosystemWorkspaceRoot = args.ecosystemWorkspaceRoot
  ? path.resolve(args.ecosystemWorkspaceRoot)
  : ecosystemWorkspaceRootDefault
const umbrelStoreRoot = args.umbrelStore
  ? path.resolve(args.umbrelStore)
  : path.resolve(workspaceRoot, 'blindspark-umbrel-store')

const changes = []
const notes = []

if (!['canary', 'stable', 'both', 'none'].includes(channel)) {
  die(`Invalid --channel "${channel}". Expected canary, stable, both, or none.`)
}
if (isPrerelease && channel !== 'none') {
  die(`Pre-release ${tag} cannot promote fleet/app-store channel "${channel}"; use --channel none.`)
}
if (publicGatewayRelease.enabled && publicGatewayRelease.releaseTarget !== tag) {
  die(`Enabled public gateway release manifest targets ${publicGatewayRelease.releaseTarget}; expected ${tag}.`)
}
if (publicGatewayRelease.enabled && channel !== 'none') {
  die(`Public gateway release ${tag} cannot move fleet channel "${channel}" during release preparation; use --channel none and the evidence-gated fleet promotion tool.`)
}
// A prerelease MAY sync the community Umbrel store (so it never lags the fleet)
// when an explicit --umbrel-store target is provided. It still cannot promote a
// fleet/app-store channel (enforced above).
if (!['local', 'npm-latest'].includes(ecosystemDependencyMode)) {
  die(`Invalid --ecosystem-dependency-mode "${ecosystemDependencyMode}". Expected local or npm-latest.`)
}

syncPackageVersions()
syncEcosystemConsumerDefaults()
syncFleetChannel()
syncDockerAndPackageMetadata()
syncStartOs()
syncTrueNas()
syncCommunityAppliancePackages()
if (syncUmbrelStore && fs.existsSync(umbrelStoreRoot)) syncCommunityUmbrelStore()
else if (syncUmbrelStore) notes.push(`community Umbrel store not found at ${umbrelStoreRoot}; skipped`)
else if (isPrerelease) notes.push('community Umbrel store skipped for pre-release')

if (checkOnly && changes.length) {
  console.error('Release surfaces are out of sync:')
  for (const file of changes) console.error(`- ${file}`)
  process.exit(1)
}

const verb = checkOnly ? 'checked' : 'updated'
console.log(`Release surfaces ${verb} for ${tag}.`)
if (changes.length) {
  for (const file of changes) console.log(`- ${file}`)
} else {
  console.log('- no file changes needed')
}
for (const note of notes) console.log(`- ${note}`)

function parseArgs (argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (!arg.startsWith('--')) {
      out._.push(arg)
      continue
    }
    const key = camel(arg.slice(2))
    if (['check', 'noUmbrelStore', 'noEcosystemConsumers', 'allowUnpinnedImage'].includes(key)) {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
    out[key] = value
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function normalizeVersion (input) {
  if (!input) die(usage.trim())
  const match = String(input).trim().match(/^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/)
  if (!match) die(`Invalid release version "${input}". Expected vX.Y.Z or X.Y.Z.`)
  return match[1]
}

function defaultChannelForVersion (semver) {
  return semver.includes('-') ? 'none' : 'both'
}

function readPublicGatewayReleaseControl () {
  const file = path.join(repoRoot, 'fleet', 'public-hive-gateway-release.json')
  if (!fs.existsSync(file)) return { enabled: false, releaseTarget: null }
  let value
  try {
    value = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    die('fleet/public-hive-gateway-release.json must contain valid JSON')
  }
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      value.schema !== 'hiverelay-public-gateway-release-v1' || typeof value.enabled !== 'boolean') {
    die('fleet/public-hive-gateway-release.json has an invalid release-control schema')
  }
  if (value.enabled && !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.releaseTarget || '')) {
    die('enabled public gateway release manifest must name a valid releaseTarget')
  }
  return { enabled: value.enabled, releaseTarget: value.releaseTarget || null }
}

function normalizeDigest (input) {
  const value = String(input || '').trim()
  if (!value) return ''
  const bare = value.startsWith('sha256:') ? value.slice('sha256:'.length) : value
  if (!/^[a-f0-9]{64}$/i.test(bare)) die(`Invalid image digest "${input}". Expected sha256:<64 hex chars>.`)
  return `sha256:${bare.toLowerCase()}`
}

function loadReleaseNotes (inline, file) {
  if (inline && file) die('Use only one of --release-notes or --release-notes-file.')
  if (inline) return inline.trim()
  if (!file) return ''
  return read(path.resolve(file)).trim()
}

function assertPublicReleaseNotes (value) {
  if (hasUnsafeReleaseNoteControlChars(value)) {
    die('release notes must not contain unsafe control characters')
  }
  for (const [pattern, name] of FORBIDDEN_PUBLIC_RELEASE_NOTES_PATTERNS) {
    if (pattern.test(value)) die(`release notes must not expose ${name}`)
  }
  try {
    assertNarrowReleasePromise(value, { label: 'release notes' })
  } catch (err) {
    die(err.message)
  }
}

function hasUnsafeReleaseNoteControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if ((code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127) return true
  }
  return false
}

function syncPackageVersions () {
  const internalDependency = isPrerelease ? version : `^${version}`
  const packageFiles = [
    'package.json',
    'packages/core/package.json',
    'packages/services/package.json',
    'packages/client/package.json',
    'packages/verifier/package.json'
  ]

  for (const rel of packageFiles) {
    updateJson(path.join(repoRoot, rel), (json) => {
      json.version = version
      if (json.dependencies && json.dependencies['p2p-hiverelay']) {
        json.dependencies['p2p-hiverelay'] = internalDependency
      }
    })
  }

  updateJson(path.join(repoRoot, 'package-lock.json'), (lock) => {
    lock.version = version
    if (lock.packages && lock.packages['']) lock.packages[''].version = version
    for (const rel of ['packages/core', 'packages/services', 'packages/client', 'packages/verifier']) {
      if (!lock.packages || !lock.packages[rel]) continue
      lock.packages[rel].version = version
      const deps = lock.packages[rel].dependencies
      if (deps && deps['p2p-hiverelay']) deps['p2p-hiverelay'] = internalDependency
    }
  })

  replaceInFile(
    path.join(repoRoot, 'README.md'),
    README_STATUS_REGEX,
    `Status: ${tag}`,
    'README status badge'
  )
}

function syncFleetChannel () {
  if (channel === 'none') return
  updateJson(path.join(repoRoot, 'fleet', 'channels.json'), (json) => {
    if (channel === 'both') {
      json.stable = tag
      json.canary = tag
    } else {
      json[channel] = tag
    }
  })
}

function syncEcosystemConsumerDefaults () {
  if (!syncEcosystemDefaults) {
    if (isPrerelease) notes.push('ecosystem consumer defaults skipped for pre-release')
    else notes.push('ecosystem consumer defaults skipped by --no-ecosystem-consumers')
    return
  }

  const workspaceCheck = checkEcosystemWorkspace({
    workspaceRoot: ecosystemWorkspaceRoot,
    consumerScope: ecosystemConsumerScope
  })
  if (!workspaceCheck.ok) {
    die(`Cannot sync ecosystem consumer defaults from ${workspaceCheck.workspaceRoot}; ${workspaceCheck.errors.join('; ')}. Use --no-ecosystem-consumers only for sparse local checks or intentional release-candidate skips.`)
  }

  const result = syncEcosystemConsumers({
    workspaceRoot: ecosystemWorkspaceRoot,
    expectedVersion: version,
    dependencyMode: ecosystemDependencyMode,
    consumerScope: ecosystemConsumerScope,
    snapshotChecks: false,
    check: checkOnly
  })

  for (const change of result.changes) {
    const rel = `ecosystem/${change}`
    if (!changes.includes(rel)) changes.push(rel)
  }

  if (!result.ok) {
    die([
      'Ecosystem consumer default sync failed:',
      ...result.errors.map(error => `- ${error}`)
    ].join('\n'))
  }

  if (result.changes.length === 0) {
    notes.push('ecosystem consumer defaults already point at the release version')
  }
}

function syncDockerAndPackageMetadata () {
  replaceImagePin(path.join(repoRoot, 'umbrel-app', 'docker-compose.yml'), 'workspace Umbrel app')
  const umbrelManifest = path.join(repoRoot, 'umbrel-app', 'umbrel-app.yml')
  const manifestText = read(umbrelManifest)
  const oldVersion = readYamlScalar(umbrelManifest, 'version')
  replaceYamlScalar(umbrelManifest, 'version', `"${version}"`)
  if (manifestText.includes('https://github.com/getumbrel/umbrel-apps/pull/PENDING')) {
    replaceYamlScalarOrBlock(umbrelManifest, 'releaseNotes', '""')
    notes.push('workspace Umbrel releaseNotes left empty while official submission URL is pending')
  } else if (releaseNotesProvided || oldVersion !== version) {
    replaceYamlFoldedBlock(umbrelManifest, 'releaseNotes', releaseNotes)
  }
}

function syncStartOs () {
  const manifest = path.join(repoRoot, 'startos', 'manifest.yaml')
  const oldVersion = readYamlScalar(manifest, 'version')
  replaceYamlScalar(manifest, 'version', version)
  if (releaseNotesProvided || oldVersion !== version) {
    replaceYamlLiteralBlock(manifest, 'release-notes', releaseNotes)
  }
  replaceInFile(
    path.join(repoRoot, 'startos', 'README.md'),
    /v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?, one-page dashboard/,
    `${tag}, one-page dashboard`,
    'StartOS README status version'
  )
}

function syncTrueNas () {
  const appManifest = path.join(repoRoot, 'truenas-app', 'app.yaml')
  const imageValues = path.join(repoRoot, 'truenas-app', 'ix_values.yaml')
  const appReadme = path.join(repoRoot, 'truenas-app', 'README.md')
  const oldAppVersion = readYamlScalar(appManifest, 'app_version')
  const oldCatalogVersion = readYamlScalar(appManifest, 'version')
  const oldImageVersion = readTrueNasImageVersion(imageValues)
  const oldReadmeVersion = readTrueNasReadmeVersion(appReadme)
  const needsCatalogRevision = oldAppVersion !== version || oldImageVersion !== version || oldReadmeVersion !== version

  replaceYamlScalar(appManifest, 'app_version', version)
  replaceTrueNasImageVersion(imageValues)
  replaceInFile(
    appReadme,
    /Upstream HiveRelay release:\s*`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?`/,
    `Upstream HiveRelay release: \`${version}\``,
    'TrueNAS app README upstream version'
  )
  if (needsCatalogRevision) replaceYamlScalar(appManifest, 'version', bumpPatchVersion(oldCatalogVersion))
}

function syncCommunityAppliancePackages () {
  syncUnraid()
  syncZimaOs()
  syncRuntipi()
  syncHexOs()
}

function syncUnraid () {
  const template = path.join(repoRoot, 'unraid-app', 'templates', 'blindspark.xml')
  const text = read(template)
  const currentReference = readXmlValue(text, 'Repository', template)
  const current = parseImage(currentReference)
  const nextReference = releaseImageReference(current, 'Unraid template')
  const runtimeChanged = currentReference !== nextReference

  replaceInFile(
    template,
    /<Repository>ghcr\.io\/bigdestiny2\/p2p-hiverelay:[^<]+<\/Repository>/,
    `<Repository>${nextReference}</Repository>`,
    'Unraid image repository'
  )
  replaceInFile(template, /<Changes>[^<]*<\/Changes>/, `<Changes>HiveRelay ${version}</Changes>`, 'Unraid release changes')
  if (runtimeChanged) {
    replaceInFile(template, /<Date>\d{4}-\d{2}-\d{2}<\/Date>/, `<Date>${new Date().toISOString().slice(0, 10)}</Date>`, 'Unraid release date')
  }
}

function syncZimaOs () {
  const compose = path.join(repoRoot, 'zimaos-app', 'Apps', 'Blindspark', 'docker-compose.yml')
  const oldVersion = readIndentedYamlScalar(compose, 2, 'version')
  const imageChanged = replaceImagePin(compose, 'ZimaOS/CasaOS package')
  const runtimeChanged = oldVersion !== version || imageChanged

  replaceInFile(compose, /^ {2}version:\s*["']?[^"'\n]+["']?\s*$/m, `  version: "${version}"`, 'ZimaOS upstream version')
  if (runtimeChanged) {
    replaceInFile(compose, /^ {2}update_at:\s*["']?\d{4}-\d{2}-\d{2}["']?\s*$/m, `  update_at: "${new Date().toISOString().slice(0, 10)}"`, 'ZimaOS update date')
    replaceInFile(compose, /( {2}release_notes:\n {4}en_US:\s*)[^\n]*/, `$1HiveRelay ${version} package`, 'ZimaOS release notes')
  }
}

function syncRuntipi () {
  const appRoot = path.join(repoRoot, 'runtipi-app', 'apps', 'blindspark')
  const configFile = path.join(appRoot, 'config.json')
  const compose = path.join(appRoot, 'docker-compose.yml')
  const config = JSON.parse(read(configFile))
  const imageChanged = replaceImagePin(compose, 'Runtipi package')
  const runtimeChanged = config.version !== version || imageChanged

  updateJson(configFile, (json) => {
    json.version = version
    if (runtimeChanged) {
      json.tipi_version = Number(json.tipi_version) + 1
      json.updated_at = Date.now()
    }
  })
}

function syncHexOs () {
  const configFile = path.join(repoRoot, 'hexos-app', 'blindspark.json')
  const config = JSON.parse(read(configFile))
  const changeLog = String(config.script && config.script.changeLog)
  const runtimeChanged = !changeLog.includes(`HiveRelay ${version}`)

  updateJson(configFile, (json) => {
    if (runtimeChanged) json.script.version = bumpPatchVersion(json.script.version, 'HexOS curation')
    json.script.changeLog = `Sync Blindspark for HiveRelay ${version}`
  })
}

function readTrueNasImageVersion (file) {
  const match = read(file).match(/repository:\s*ghcr\.io\/bigdestiny2\/p2p-hiverelay\s*\n\s+tag:\s*["']?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/m)
  if (!match) die(`Could not find HiveRelay image tag in ${relative(file)}.`)
  return match[1]
}

function readTrueNasReadmeVersion (file) {
  const match = read(file).match(/Upstream HiveRelay release:\s*`(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`/)
  if (!match) die(`Could not find upstream HiveRelay release in ${relative(file)}.`)
  return match[1]
}

function replaceTrueNasImageVersion (file) {
  replaceInFile(
    file,
    /(repository:\s*ghcr\.io\/bigdestiny2\/p2p-hiverelay\s*\n\s+tag:\s*)["']?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?["']?/m,
    `$1${version}`,
    'TrueNAS HiveRelay image tag'
  )
}

function bumpPatchVersion (value, label = 'TrueNAS catalog') {
  const match = String(value).match(/^(\d+)\.(\d+)\.(\d+)$/)
  if (!match) die(`Invalid ${label} version "${value}". Expected X.Y.Z.`)
  return `${match[1]}.${match[2]}.${Number(match[3]) + 1}`
}

function syncCommunityUmbrelStore () {
  updateJson(path.join(umbrelStoreRoot, 'package.json'), (json) => {
    json.version = version
  })
  replaceImagePin(path.join(umbrelStoreRoot, 'hiverelay-blindspark', 'docker-compose.yml'), 'community Umbrel store')
  const storeManifest = path.join(umbrelStoreRoot, 'hiverelay-blindspark', 'umbrel-app.yml')
  const oldVersion = readYamlScalar(storeManifest, 'version')
  replaceYamlScalar(storeManifest, 'version', `"${version}"`)
  if (releaseNotesProvided || oldVersion !== version) {
    replaceYamlFoldedBlock(storeManifest, 'releaseNotes', releaseNotes)
  }
  replaceInFile(
    path.join(umbrelStoreRoot, 'README.md'),
    /Image:\s*`ghcr\.io\/bigdestiny2\/p2p-hiverelay:[^`]+`/,
    `Image: \`${imageName}:${version}\``,
    'community store README image version'
  )
  replaceInFile(
    path.join(umbrelStoreRoot, 'index.html'),
    /ghcr\.io\/bigdestiny2\/p2p-hiverelay:\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/g,
    `${imageName}:${version}`,
    'community store landing page image version'
  )
}

function replaceImagePin (file, label) {
  const text = read(file)
  const match = text.match(/image:\s*ghcr\.io\/bigdestiny2\/p2p-hiverelay:([^\s]+)/)
  if (!match) die(`Could not find image pin in ${label}: ${relative(file)}`)

  const current = parseImage(match[0])
  const currentReference = match[0].replace(/^image:\s*/, '')
  const nextImage = releaseImageReference(current, label)

  write(file, text.replace(/image:\s*ghcr\.io\/bigdestiny2\/p2p-hiverelay:[^\s]+/, `image: ${nextImage}`))
  return currentReference !== nextImage
}

function releaseImageReference (current, label) {
  if (imageDigest) return `${imageName}:${version}@${imageDigest}`
  if (current.version === version && current.digest) return `${imageName}:${version}@${current.digest}`
  if (allowUnpinnedImage) {
    if (current.digest) {
      notes.push(`${label} preserved at the last immutable ${current.version}@${current.digest} binding; it is not bound to ${version} and is not release-ready`)
      return `${imageName}:${current.version}@${current.digest}`
    }
    notes.push(`${label} image left tag-only because --allow-unpinned-image was set`)
    return `${imageName}:${version}`
  }
  die(`--image-digest is required to update ${label} image pin to ${version}.`)
}

function parseImage (line) {
  const match = line.match(/p2p-hiverelay:(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:@(sha256:[a-f0-9]{64}))?/i)
  if (!match) die(`Could not parse image reference: ${line}`)
  return { version: match[1], digest: match[2] || '' }
}

function replaceYamlScalar (file, key, value) {
  replaceInFile(file, new RegExp(`^${escapeRegExp(key)}:\\s*.*$`, 'm'), `${key}: ${value}`, `${key} in ${relative(file)}`)
}

function replaceYamlScalarOrBlock (file, key, value) {
  replaceInFile(file, yamlValueRegex(key), `${key}: ${value}`, `${key} in ${relative(file)}`)
}

function readYamlScalar (file, key) {
  const match = read(file).match(new RegExp(`^${escapeRegExp(key)}:\\s*"?([^"\\n]+)"?\\s*$`, 'm'))
  if (!match) die(`Could not find ${key} in ${relative(file)}.`)
  return match[1].trim()
}

function readIndentedYamlScalar (file, spaces, key) {
  const match = read(file).match(new RegExp(`^${' '.repeat(spaces)}${escapeRegExp(key)}:\\s*["']?([^"'\\n]+)["']?\\s*$`, 'm'))
  if (!match) die(`Could not find ${key} in ${relative(file)}.`)
  return match[1].trim()
}

function readXmlValue (text, key, file) {
  const match = text.match(new RegExp(`<${escapeRegExp(key)}>([^<]+)</${escapeRegExp(key)}>`))
  if (!match) die(`Could not find ${key} in ${relative(file)}.`)
  return match[1].trim()
}

function replaceYamlFoldedBlock (file, key, text) {
  const block = `${key}: >-\n${indent(wrapText(text, 78), 2)}\n`
  replaceInFile(file, yamlValueRegex(key), block, `${key} in ${relative(file)}`)
}

function replaceYamlLiteralBlock (file, key, text) {
  const block = `${key}: |\n${indent(wrapText(text, 78), 2)}\n`
  replaceInFile(file, yamlValueRegex(key), block, `${key} in ${relative(file)}`)
}

function yamlValueRegex (key) {
  return new RegExp(`^${escapeRegExp(key)}:\\s*(?:[>|]-?\\n(?:  .*\\n?)*|.*$)`, 'm')
}

function replaceInFile (file, regex, replacement, label) {
  const text = read(file)
  if (!regex.test(text)) die(`Could not find ${label}.`)
  regex.lastIndex = 0
  write(file, text.replace(regex, replacement))
}

function updateJson (file, mutate) {
  const before = read(file)
  const json = JSON.parse(before)
  mutate(json)
  const body = /\\u[0-9a-fA-F]{4}/.test(before)
    ? stringifyAsciiJson(json)
    : JSON.stringify(json, null, 2)
  write(file, `${body}\n`)
}

function stringifyAsciiJson (json) {
  let out = ''
  for (const char of JSON.stringify(json, null, 2)) {
    const code = char.charCodeAt(0)
    out += code > 127 ? `\\u${code.toString(16).padStart(4, '0')}` : char
  }
  return out
}

function wrapText (text, width) {
  const words = text.replace(/\s+/g, ' ').trim().split(' ')
  const lines = []
  let line = ''
  for (const word of words) {
    if (!line) {
      line = word
    } else if (`${line} ${word}`.length <= width) {
      line += ` ${word}`
    } else {
      lines.push(line)
      line = word
    }
  }
  if (line) lines.push(line)
  return lines
}

function indent (lines, spaces) {
  const prefix = ' '.repeat(spaces)
  return lines.map((line) => `${prefix}${line}`).join('\n')
}

function read (file) {
  return fs.readFileSync(file, 'utf8')
}

function write (file, next) {
  const before = read(file)
  if (before === next) return
  const rel = relative(file)
  if (!changes.includes(rel)) changes.push(rel)
  if (!checkOnly) fs.writeFileSync(file, next)
}

function relative (file) {
  return path.relative(workspaceRoot, file)
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function die (message) {
  console.error(message)
  process.exit(1)
}
