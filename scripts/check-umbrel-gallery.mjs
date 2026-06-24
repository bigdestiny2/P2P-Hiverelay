#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const MAX_GALLERY_IMAGE_BYTES = 8 * 1024 * 1024

const usage = `
Usage:
  node scripts/check-umbrel-gallery.mjs [--manifest <path>] [--gallery-dir <path>]

Checks the optional Umbrel gallery handoff assets. Empty gallery lists are valid
for first official submission; populated lists must contain safe 1440x900 PNG or
JPEG screenshots.
`

const args = parseArgs(process.argv.slice(2))
const manifestFile = args.manifest ? path.resolve(args.manifest) : path.join(repoRoot, 'umbrel-app', 'umbrel-app.yml')
const galleryDir = args.galleryDir ? path.resolve(args.galleryDir) : path.join(path.dirname(manifestFile), 'gallery')
const gallery = readGallery(manifestFile)

if (gallery.length === 0) {
  console.log('umbrel-app.yml gallery is empty for the first official submission; attach screenshots in the PR/reviewer handoff.')
  process.exit(0)
}

if (gallery.length < 3) die(`populated gallery must list at least 3 images, got ${gallery.length}`)
if (gallery.length > 5) die(`gallery must list at most 5 images, got ${gallery.length}`)

const galleryRoot = validateGalleryDir(galleryDir)
const seen = new Set()
for (const name of gallery) {
  if (!/^[1-5]\.(png|jpe?g)$/i.test(name)) {
    die(`gallery image name must be a numbered PNG/JPEG filename like 1.png or 1.jpg; got ${JSON.stringify(name)}`)
  }
  if (seen.has(name.toLowerCase())) die(`gallery image is listed more than once: ${name}`)
  seen.add(name.toLowerCase())

  const file = path.join(galleryRoot, name)
  if (path.basename(file) !== name || path.dirname(file) !== galleryRoot) {
    die(`gallery image must not include path traversal: ${JSON.stringify(name)}`)
  }
  if (!fs.existsSync(file)) die(`Gallery image listed but missing: ${file}`)
  const stat = fs.lstatSync(file)
  if (stat.isSymbolicLink()) die(`gallery image must not be a symlink: ${file}`)
  if (!stat.isFile()) die(`gallery image must be a regular file: ${file}`)
  if (stat.size > MAX_GALLERY_IMAGE_BYTES) {
    die(`gallery image must be ${MAX_GALLERY_IMAGE_BYTES} bytes or smaller: ${file} is ${stat.size} bytes`)
  }

  const realFile = fs.realpathSync(file)
  if (!isPathInside(galleryRoot, realFile)) die(`gallery image must stay inside gallery directory: ${file}`)

  const size = imageSize(realFile)
  if (size.width !== 1440 || size.height !== 900) {
    die(`gallery image must be 1440x900 px: ${file} is ${size.width}x${size.height}`)
  }
}

console.log(`Umbrel gallery validates: ${gallery.length} image${gallery.length === 1 ? '' : 's'}.`)

function validateGalleryDir (dir) {
  if (!fs.existsSync(dir)) die(`Gallery directory missing: ${dir}`)
  const stat = fs.lstatSync(dir)
  if (stat.isSymbolicLink()) die(`gallery directory must not be a symlink: ${dir}`)
  if (!stat.isDirectory()) die(`gallery directory must be a directory: ${dir}`)
  return fs.realpathSync(dir)
}

function isPathInside (root, child) {
  const relative = path.relative(root, child)
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative)
}

function readGallery (file) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/^gallery:\s*(.*)$/)
    if (!match) continue
    const rest = match[1].trim()
    if (rest) return parseInlineGallery(rest)

    const out = []
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j]
      if (/^\S/.test(line)) break
      if (!line.trim() || /^\s*#/.test(line)) continue
      const item = line.match(/^\s*-\s*(.+?)\s*$/)
      if (!item) die(`unsupported gallery YAML line: ${line}`)
      out.push(unquoteYamlScalar(item[1].trim()))
    }
    return out
  }
  die(`Could not find gallery in ${file}.`)
}

function parseInlineGallery (value) {
  if (value === '[]') return []
  if (!value.startsWith('[') || !value.endsWith(']')) die(`unsupported inline gallery value: ${value}`)
  const inner = value.slice(1, -1).trim()
  if (!inner) return []
  return inner.split(',').map(part => unquoteYamlScalar(part.trim())).filter(Boolean)
}

function unquoteYamlScalar (value) {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1)
  }
  return value
}

function imageSize (file) {
  const buf = fs.readFileSync(file)
  if (isPng(buf)) {
    return {
      width: buf.readUInt32BE(16),
      height: buf.readUInt32BE(20)
    }
  }
  if (isJpeg(buf)) return jpegSize(buf, file)
  die(`gallery image must be PNG or JPEG: ${file}`)
}

function isPng (buf) {
  return buf.length >= 24 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
}

function isJpeg (buf) {
  return buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8
}

function jpegSize (buf, file) {
  let offset = 2
  while (offset + 9 < buf.length) {
    if (buf[offset] !== 0xff) die(`invalid JPEG marker while reading ${file}`)
    const marker = buf[offset + 1]
    offset += 2
    if (marker === 0xd9 || marker === 0xda) break
    if (offset + 2 > buf.length) break
    const length = buf.readUInt16BE(offset)
    if (length < 2 || offset + length > buf.length) break
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      return {
        height: buf.readUInt16BE(offset + 3),
        width: buf.readUInt16BE(offset + 5)
      }
    }
    offset += length
  }
  die(`could not read JPEG dimensions from ${file}`)
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--manifest' || arg === '--gallery-dir') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
      out[camel(arg.slice(2))] = value
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function die (message) {
  console.error(message)
  process.exit(1)
}
