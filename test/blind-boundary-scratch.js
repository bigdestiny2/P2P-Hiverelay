import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Boundary tests create Unix sockets and persistence fixtures. Keep every one
// below the checkout even when a caller provides a custom scratch root.
const repositoryRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const scratchEnvironment = 'HIVERELAY_BLIND_BOUNDARY_TEST_ROOT'
const defaultScratchRoot = path.join(repositoryRoot, '.t')

function isContained (parent, candidate) {
  const relative = path.relative(parent, candidate)
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)
}

function configuredScratchRoot () {
  const configured = process.env[scratchEnvironment]
  const root = configured
    ? path.resolve(repositoryRoot, configured)
    : defaultScratchRoot
  if (!isContained(repositoryRoot, root)) {
    throw new Error(`${scratchEnvironment} must remain inside the repository checkout`)
  }
  return root
}

function scratchPathParts (root) {
  const relative = path.relative(repositoryRoot, root)
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`${scratchEnvironment} must remain inside the repository checkout`)
  }
  return relative.split(path.sep)
}

function missing (error) {
  return error && error.code === 'ENOENT'
}

// Do not use one recursive mkdir for a caller-supplied nested root. A
// pre-existing symlink ancestor would make mkdir create children outside the
// checkout before a later realpath check could reject it. Walk each component
// first and create only the next child of an already verified real directory.
async function ensureScratchRootInsideCheckout (root) {
  const realRepositoryRoot = await fs.realpath(repositoryRoot)
  const parts = scratchPathParts(root)
  let lexical = repositoryRoot
  let realRoot = realRepositoryRoot

  for (const part of parts) {
    lexical = path.join(lexical, part)
    let stat
    try {
      stat = await fs.lstat(lexical)
    } catch (error) {
      if (!missing(error)) throw error
      try {
        await fs.mkdir(lexical, { mode: 0o700 })
      } catch (createError) {
        if (createError?.code !== 'EEXIST') throw createError
      }
      stat = await fs.lstat(lexical)
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('blind boundary scratch root must not traverse a symbolic-link or non-directory ancestor')
    }
    realRoot = await fs.realpath(lexical)
    if (!isContained(realRepositoryRoot, realRoot)) {
      throw new Error(`${scratchEnvironment} resolves outside the repository checkout`)
    }
  }

  await fs.chmod(realRoot, 0o700)
  return realRoot
}

function assertPrefix (prefix) {
  if (typeof prefix !== 'string' || prefix.length === 0 || prefix === '.' || prefix === '..' || path.basename(prefix) !== prefix) {
    throw new TypeError('blind boundary scratch prefix must be one basename')
  }
}

function assertParts (parts) {
  if (parts.length === 0 || parts.some(part => typeof part !== 'string' || part.length === 0 || part === '.' || part === '..' || path.basename(part) !== part)) {
    throw new TypeError('blind boundary scratch path must contain only basename segments')
  }
}

export async function blindBoundaryScratchRoot () {
  const root = configuredScratchRoot()
  return ensureScratchRootInsideCheckout(root)
}

export async function createBlindBoundaryScratch (prefix) {
  assertPrefix(prefix)
  const root = await blindBoundaryScratchRoot()
  const created = await fs.mkdtemp(path.join(root, prefix))
  const realCreated = await fs.realpath(created)
  if (!isContained(root, realCreated)) {
    throw new Error('blind boundary scratch allocation escaped its configured root')
  }
  await fs.chmod(realCreated, 0o700)
  return realCreated
}

export async function blindBoundaryScratchPath (...parts) {
  assertParts(parts)
  const root = await blindBoundaryScratchRoot()
  const candidate = path.resolve(root, ...parts)
  if (!isContained(root, candidate)) throw new Error('blind boundary scratch path escaped its configured root')
  return candidate
}

export async function removeBlindBoundaryScratch (candidate) {
  const root = await blindBoundaryScratchRoot()
  let realCandidate
  try {
    realCandidate = await fs.realpath(candidate)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  if (!isContained(root, realCandidate)) throw new Error('refusing to remove a path outside blind boundary scratch')
  await fs.rm(realCandidate, { recursive: true, force: true })
}
