#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRoot = path.resolve(here, '..')

if (isMain()) main()

export function validateCommunityAppliancePackages (opts = {}) {
  const root = path.resolve(opts.root || defaultRoot)
  const errors = []
  const tagOnlyImages = []
  const rootPackage = readJson(path.join(root, 'package.json'), errors)
  const version = rootPackage && rootPackage.version

  requireFiles(root, [
    'unraid-app/README.md',
    'unraid-app/ca_profile.xml',
    'unraid-app/icon.svg',
    'unraid-app/templates/blindspark.xml',
    'zimaos-app/README.md',
    'zimaos-app/Apps/Blindspark/docker-compose.yml',
    'zimaos-app/Apps/Blindspark/icon.svg',
    'runtipi-app/README.md',
    'runtipi-app/apps/blindspark/config.json',
    'runtipi-app/apps/blindspark/docker-compose.yml',
    'runtipi-app/apps/blindspark/metadata/description.md',
    'runtipi-app/apps/blindspark/metadata/logo.jpg',
    'hexos-app/README.md',
    'hexos-app/blindspark.json'
  ], errors)

  if (errors.length === 0) {
    validateUnraid(root, version, errors, tagOnlyImages)
    validateZimaOs(root, version, errors, tagOnlyImages)
    validateRuntipi(root, version, errors, tagOnlyImages)
    validateHexOs(root, version, errors)
  }

  return {
    ok: errors.length === 0,
    packages: ['unraid', 'zimaos-casaos', 'runtipi', 'hexos'],
    tagOnlyImages,
    errors
  }
}

function main () {
  const result = validateCommunityAppliancePackages()
  if (!result.ok) {
    console.error('Community appliance package validation failed:')
    for (const error of result.errors) console.error(`- ${error}`)
    process.exit(1)
  }

  console.log('Community appliance packages validate for Unraid, ZimaOS/CasaOS, Runtipi, and HexOS.')
  if (result.tagOnlyImages.length) {
    console.log(`Release preparation will replace ${result.tagOnlyImages.length} authoring tag(s) with the released image digest.`)
  }
}

function validateUnraid (root, version, errors, tagOnlyImages) {
  const profile = read(path.join(root, 'unraid-app', 'ca_profile.xml'))
  const template = read(path.join(root, 'unraid-app', 'templates', 'blindspark.xml'))

  includesAll(profile, [
    '<CommunityApplications>',
    '<Profile>',
    'P2P-Hiverelay/main/unraid-app/icon.svg'
  ], 'Unraid repository profile', errors)
  includesAll(template, [
    '<Container version="2">',
    '<Name>Blindspark</Name>',
    '<Network>bridge</Network>',
    '<Privileged>false</Privileged>',
    '<WebUI>http://[IP]:[PORT:9100]</WebUI>',
    '<TemplateURL>https://raw.githubusercontent.com/bigdestiny2/P2P-Hiverelay/main/unraid-app/templates/blindspark.xml</TemplateURL>',
    '<License>Apache-2.0</License>',
    'Target="HIVERELAY_API_KEY"',
    'Required="true" Mask="true"',
    'Target="HIVERELAY_ACCEPT_MODE" Default="review"',
    'Target="HIVERELAY_UI_EXPOSE_TOKEN" Default="true"'
  ], 'Unraid application template', errors)
  excludesAll(template, ['YOUR_', '<Privileged>true</Privileged>'], 'Unraid application template', errors)
  matches(template, /<Date>\d{4}-\d{2}-\d{2}<\/Date>/, 'Unraid release date', errors)
  includesAll(template, [`<Changes>HiveRelay ${version}</Changes>`], 'Unraid release metadata', errors)
  const repository = xmlValue(template, 'Repository', errors, 'Unraid image repository')
  validateImage(repository, version, 'Unraid', errors, tagOnlyImages)
}

function validateZimaOs (root, version, errors, tagOnlyImages) {
  const compose = read(path.join(root, 'zimaos-app', 'Apps', 'Blindspark', 'docker-compose.yml'))
  const metadataVersion = scalar(compose, /^ {2}version:\s*["']?([^"'\n]+)["']?\s*$/m, errors, 'ZimaOS metadata version')

  includesAll(compose, [
    'name: blindspark',
    'source: /DATA/AppData/$AppID/data',
    'target: /data',
    'key_file=/data/.management-key',
    'randomBytes(32)',
    'export HIVERELAY_API_KEY=',
    'HIVERELAY_ACCEPT_MODE: review',
    'HIVERELAY_UI_EXPOSE_TOKEN: "true"',
    'id: com.hiverelay.blindspark',
    'main: blindspark',
    'port_map: "30452"',
    'category: Networking',
    'architectures:',
    'update_at: "'
  ], 'ZimaOS/CasaOS package', errors)
  excludesAll(compose, ['privileged: true', 'network_mode: host'], 'ZimaOS/CasaOS package', errors)
  equal(metadataVersion, version, 'ZimaOS metadata version', errors)
  const image = scalar(compose, /^\s+image:\s*(\S+)\s*$/m, errors, 'ZimaOS image')
  validateImage(image, version, 'ZimaOS', errors, tagOnlyImages)
}

function validateRuntipi (root, version, errors, tagOnlyImages) {
  const appRoot = path.join(root, 'runtipi-app', 'apps', 'blindspark')
  const config = readJson(path.join(appRoot, 'config.json'), errors)
  const compose = read(path.join(appRoot, 'docker-compose.yml'))
  if (!config) return

  equal(config.id, 'blindspark', 'Runtipi app id', errors)
  equal(config.name, 'Blindspark', 'Runtipi app name', errors)
  equal(config.version, version, 'Runtipi upstream version', errors)
  equal(config.available, true, 'Runtipi availability', errors)
  equal(config.dynamic_config, true, 'Runtipi dynamic Compose flag', errors)
  equal(config.port, 30452, 'Runtipi default host port', errors)
  matches(String(config.tipi_version), /^[1-9]\d*$/, 'Runtipi package revision', errors)
  matches(String(config.updated_at), /^[1-9]\d{11,}$/, 'Runtipi update timestamp', errors)
  includesAll(JSON.stringify(config), [
    '"type":"random"',
    '"min":48',
    '"required":true',
    '"env_variable":"HIVERELAY_API_KEY"'
  ], 'Runtipi management key field', errors)
  includesAll(compose, [
    'HIVERELAY_API_KEY=$' + '{HIVERELAY_API_KEY}',
    'HIVERELAY_ACCEPT_MODE=review',
    'HIVERELAY_UI_EXPOSE_TOKEN=true',
    'internal_port: 9100',
    'is_main: true',
    'schema_version: 2'
  ], 'Runtipi Compose package', errors)
  excludesAll(compose, ['privileged: true', 'network_mode: host'], 'Runtipi Compose package', errors)
  const image = scalar(compose, /^\s+image:\s*['"]?([^'"\s]+)['"]?\s*$/m, errors, 'Runtipi image')
  validateImage(image, version, 'Runtipi', errors, tagOnlyImages)
}

function validateHexOs (root, version, errors) {
  const config = readJson(path.join(root, 'hexos-app', 'blindspark.json'), errors)
  if (!config) return

  equal(config.version, 4, 'HexOS script format', errors)
  matches(config.script && config.script.version, /^\d+\.\d+\.\d+$/, 'HexOS curation revision', errors)
  includesAll(config.script && config.script.changeLog, [`HiveRelay ${version}`], 'HexOS upstream version', errors)
  includesAll(JSON.stringify(config), [
    '"ports":[30452]',
    '"api_key":"$RANDOM_STRING(48)"',
    '"accept_mode":"review"',
    '"expose_token":true',
    '"port_number":30452',
    '"memory":"$MEMORY(5%, 2048)"'
  ], 'HexOS curation', errors)
}

function validateImage (value, version, label, errors, tagOnlyImages) {
  const match = String(value || '').match(/^ghcr\.io\/bigdestiny2\/p2p-hiverelay:(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:@(sha256:[a-f0-9]{64}))?$/i)
  if (!match) {
    errors.push(`${label} image reference is invalid: ${value || '<missing>'}`)
    return
  }
  equal(match[1], version, `${label} image version`, errors)
  if (!match[2]) tagOnlyImages.push(label)
}

function requireFiles (root, files, errors) {
  for (const rel of files) {
    if (!fs.existsSync(path.join(root, rel))) errors.push(`missing ${rel}`)
  }
}

function readJson (file, errors) {
  try {
    return JSON.parse(read(file))
  } catch (err) {
    errors.push(`invalid JSON in ${path.basename(file)}: ${err.message}`)
    return null
  }
}

function read (file) {
  return fs.readFileSync(file, 'utf8')
}

function xmlValue (text, key, errors, label) {
  return scalar(text, new RegExp(`<${key}>([^<]+)</${key}>`), errors, label)
}

function scalar (text, pattern, errors, label) {
  const match = String(text || '').match(pattern)
  if (!match) {
    errors.push(`${label} is missing`)
    return ''
  }
  return match[1].trim()
}

function equal (actual, expected, label, errors) {
  if (actual !== expected) errors.push(`${label} must be ${expected}; found ${actual ?? '<missing>'}`)
}

function matches (actual, pattern, label, errors) {
  if (!pattern.test(String(actual || ''))) errors.push(`${label} is invalid: ${actual || '<missing>'}`)
}

function includesAll (text, terms, label, errors) {
  for (const term of terms) {
    if (!String(text || '').includes(term)) errors.push(`${label} is missing ${JSON.stringify(term)}`)
  }
}

function excludesAll (text, terms, label, errors) {
  for (const term of terms) {
    if (String(text || '').includes(term)) errors.push(`${label} must not contain ${JSON.stringify(term)}`)
  }
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}
