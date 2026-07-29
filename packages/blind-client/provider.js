import b4a from 'b4a'
import { asBytes } from './bytes.js'
import { fail } from './errors.js'

function snapshotValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (b4a.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return b4a.from(asBytes(value, 'provider context bytes'))
  }
  if (Array.isArray(value)) return Object.freeze(value.map(snapshotValue))
  const output = {}
  for (const [key, child] of Object.entries(value)) output[key] = snapshotValue(child)
  return Object.freeze(output)
}

function copyAdmission (value) {
  if (!value || typeof value !== 'object') fail('BAD_CLIENT_INPUT', 'admission must be an object')
  return Object.freeze({
    profileId: value.profileId,
    schemeId: value.schemeId,
    parameterHash: b4a.from(asBytes(value.parameterHash, 'admission parameterHash', 32)),
    token: b4a.from(asBytes(value.token, 'admission token'))
  })
}

export async function resolveAdmission (options, context, required, message) {
  if (options.admission != null) return copyAdmission(options.admission)
  if (typeof options.admissionProvider === 'function') {
    const value = await options.admissionProvider(snapshotValue(context))
    if (value != null) return copyAdmission(value)
  }
  if (required) fail('ADMISSION_REQUIRED', message)
  return null
}
