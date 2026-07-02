import { formatErr } from '../error-prefixes.js'

export const CUSTODY_DISABLED_MESSAGE = 'custody pipeline is disabled for this relay profile'

export function custodyDisabledResult () {
  return {
    ok: false,
    kind: 'disabled-profile',
    status: 409,
    payload: {
      error: formatErr('NOT_ENABLED', CUSTODY_DISABLED_MESSAGE)
    }
  }
}
