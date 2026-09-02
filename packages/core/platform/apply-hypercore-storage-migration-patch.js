#!/usr/bin/env node

import { createHash } from 'crypto'
import { lstatSync, readFileSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const VERSION = '3.2.0'
const PATCH_SHA256 = 'fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53'
const ORIGINAL_SOURCE_SHA256 = 'f3ff8483854e93fd30e1db9e2228ac535bf29b057a978b1d157955cfd8bb4d7c'
const PATCHED_SOURCE_SHA256 = '04153bfa8de76c0dc2a802936cbbeea6c22f20a1a79035cd65ed1957cc8ff2d5'
const PATCH_FILE = join(dirname(fileURLToPath(import.meta.url)), '..', 'patches', 'hypercore-storage+3.2.0.patch')

const resolved = import.meta.resolve('hypercore-storage/migrations/0/index.js')
if (!resolved.startsWith('file://')) fatal('hypercore-storage migration source did not resolve to a file')
const sourceFile = fileURLToPath(resolved)
const packageFile = fileURLToPath(new URL('../../package.json', resolved))

const patchBytes = regularBytes(PATCH_FILE, 'tracked hypercore-storage patch')
if (sha256(patchBytes) !== PATCH_SHA256) fatal('packed hypercore-storage patch bytes do not match the accepted patch binding')

let dependencyManifest
try {
  dependencyManifest = JSON.parse(regularBytes(packageFile, 'hypercore-storage package manifest').toString('utf8'))
} catch (error) {
  fatal(`hypercore-storage package manifest is invalid: ${error?.message || String(error)}`)
}
if (dependencyManifest.version !== VERSION) {
  fatal(`hypercore-storage must be exactly ${VERSION}; installed ${dependencyManifest.version || '<missing>'}`)
}

const sourceBytes = regularBytes(sourceFile, 'hypercore-storage migration source')
const sourceSha256 = sha256(sourceBytes)
if (sourceSha256 === PATCHED_SOURCE_SHA256) {
  process.stdout.write(`hypercore-storage ${VERSION} migration patch verified (${sourceSha256})\n`)
  process.exit(0)
}
if (sourceSha256 !== ORIGINAL_SOURCE_SHA256) {
  fatal(`hypercore-storage migration source is neither the accepted original nor patched bytes (${sourceSha256})`)
}

let source = sourceBytes.toString('utf8')
source = replaceOnce(source, 'corePointer: head.allocated.cores++,', 'corePointer: head.cores++,')
source = replaceOnce(source, 'dataPointer: head.allocated.datas++,', 'dataPointer: head.datas++,')
const patched = Buffer.from(source, 'utf8')
if (sha256(patched) !== PATCHED_SOURCE_SHA256) fatal('computed migration patch output does not match the accepted patched source')
writeFileSync(sourceFile, patched)
const installedSha256 = sha256(regularBytes(sourceFile, 'patched hypercore-storage migration source'))
if (installedSha256 !== PATCHED_SOURCE_SHA256) fatal('installed migration patch did not persist exact accepted bytes')
process.stdout.write(`hypercore-storage ${VERSION} migration patch applied (${installedSha256})\n`)

function regularBytes (file, label) {
  const stat = lstatSync(file)
  if (stat.isSymbolicLink() || !stat.isFile()) fatal(`${label} must be a regular non-symlink file`)
  return readFileSync(file)
}

function replaceOnce (source, before, after) {
  const first = source.indexOf(before)
  if (first === -1 || source.indexOf(before, first + before.length) !== -1) {
    fatal(`accepted migration source must contain exactly one ${before}`)
  }
  return source.slice(0, first) + after + source.slice(first + before.length)
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function fatal (message) {
  process.stderr.write(`p2p-hiverelay postinstall: ${message}\n`)
  process.exit(1)
}
