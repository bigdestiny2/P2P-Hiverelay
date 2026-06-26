import fs from 'node:fs'

const MAX_ENV_FILE_BYTES = 64 * 1024
const ENV_NAME_RE = /^[A-Z_][A-Z0-9_]*$/
const ENV_HEREDOC_DELIMITER_RE = /^[A-Za-z0-9_.-]{1,64}$/

export function readEnvFile (file) {
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (err) {
    throw new Error(`Unable to read env file: ${sanitizeFileError(err)}`)
  }
  if (stat.isSymbolicLink()) throw new Error('Refusing to read symlinked env file')
  if (!stat.isFile()) throw new Error('Refusing to read env file because it is not a regular file')
  if (stat.size > MAX_ENV_FILE_BYTES) {
    throw new Error(`Refusing to read env file larger than ${MAX_ENV_FILE_BYTES} bytes`)
  }

  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (err) {
    throw new Error(`Unable to read env file: ${sanitizeFileError(err)}`)
  }
  return parseEnvFile(text)
}

export function parseEnvFile (text) {
  if (text.includes('\u0000')) throw new Error('Env file contains a NUL byte')
  const env = {}
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (!line.trim() || line.trimStart().startsWith('#')) continue

    const heredoc = /^([A-Z_][A-Z0-9_]*)<<([A-Za-z0-9_.-]+)$/.exec(line)
    if (heredoc) {
      const [, name, delimiter] = heredoc
      assertEnvName(name, i + 1)
      if (!ENV_HEREDOC_DELIMITER_RE.test(delimiter)) {
        throw new Error(`Malformed env-file heredoc delimiter on line ${i + 1}`)
      }
      assertEnvKeyUnset(env, name)
      const valueLines = []
      let closed = false
      for (i = i + 1; i < lines.length; i++) {
        if (lines[i] === delimiter) {
          closed = true
          break
        }
        valueLines.push(lines[i])
      }
      if (!closed) throw new Error(`Unterminated env-file heredoc for ${name}`)
      env[name] = valueLines.join('\n')
      continue
    }

    const assignment = /^([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line)
    if (!assignment) throw new Error(`Malformed env-file line ${i + 1}`)
    const [, name, value] = assignment
    assertEnvName(name, i + 1)
    assertEnvKeyUnset(env, name)
    env[name] = value
  }

  return env
}

function assertEnvName (name, lineNumber) {
  if (!ENV_NAME_RE.test(name)) throw new Error(`Malformed env-file variable name on line ${lineNumber}`)
}

function assertEnvKeyUnset (env, name) {
  if (Object.hasOwn(env, name)) throw new Error(`Duplicate env-file variable: ${name}`)
}

function sanitizeFileError (err) {
  return err && err.code ? String(err.code) : 'unknown error'
}
