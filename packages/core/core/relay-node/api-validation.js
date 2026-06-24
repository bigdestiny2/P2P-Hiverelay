export function queryInt (url, name, defaultValue, min, max) {
  const raw = url.searchParams.get(name)
  if (raw === null || raw === '') return defaultValue
  const text = String(raw).trim()
  if (!/^[+-]?\d+$/.test(text)) return defaultValue
  const parsed = Number(text)
  if (!Number.isSafeInteger(parsed)) {
    return text.startsWith('-') ? min : max
  }
  return Math.min(max, Math.max(min, parsed))
}

export function validatePositiveInt (value, min, max, name) {
  let parsed
  if (typeof value === 'number') {
    parsed = value
  } else if (typeof value === 'string') {
    const text = value.trim()
    if (!/^\d+$/.test(text)) {
      return { ok: false, value: null, error: name + ' must be a valid integer' }
    }
    parsed = Number(text)
  } else {
    return { ok: false, value: null, error: name + ' must be a valid integer' }
  }
  if (!Number.isSafeInteger(parsed)) {
    return { ok: false, value: null, error: name + ' must be a valid integer' }
  }
  if (parsed < min || parsed > max) {
    return { ok: false, value: null, error: name + ' must be between ' + min + ' and ' + max }
  }
  return { ok: true, value: parsed, error: null }
}

export function validatePositiveNumber (value, min, max, name) {
  let parsed
  if (typeof value === 'number') {
    parsed = value
  } else if (typeof value === 'string') {
    const text = value.trim()
    if (!/^-?(?:\d+(?:\.\d+)?|\.\d+)$/.test(text)) {
      return { ok: false, value: null, error: name + ' must be a valid number' }
    }
    parsed = Number(text)
  } else {
    return { ok: false, value: null, error: name + ' must be a valid number' }
  }
  if (Number.isNaN(parsed) || !Number.isFinite(parsed)) {
    return { ok: false, value: null, error: name + ' must be a valid number' }
  }
  if (parsed < min || parsed > max) {
    return { ok: false, value: null, error: name + ' must be between ' + min + ' and ' + max }
  }
  return { ok: true, value: parsed, error: null }
}
