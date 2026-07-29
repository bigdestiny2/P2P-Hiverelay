import { assertAdvertisedOperation } from '@hiverelay/blind-protocol/wire-runtime-authority'
import { fail } from './errors.js'

export function selectedOperationProfile (familyId, operationId) {
  try {
    return assertAdvertisedOperation(familyId, operationId)
  } catch {
    fail('BAD_CLIENT_INPUT', 'operation is unknown or reserved by the active release profile')
  }
}
