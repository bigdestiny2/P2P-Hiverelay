import {
  FAMILY,
  OPERATION,
  RESERVED_OPERATION_PAIRS
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { encodeUnaryRequest } from '@hiverelay/blind-client/wire'
import { daemonOperationProfile } from '../../packages/blind-daemon/operation-catalog.js'
import { ResourceBudget } from '../../packages/blind-daemon/resource-budget.js'

const results = []
for (const pair of RESERVED_OPERATION_PAIRS) {
  let clientRejected = false
  try {
    encodeUnaryRequest({ familyId: pair.familyId, operationId: pair.operationId })
  } catch (error) {
    clientRejected = error?.code === 'BAD_CLIENT_INPUT'
  }
  let budgetRejected = false
  try {
    new ResourceBudget().acquire({ familyId: pair.familyId, operationId: pair.operationId, bytes: 1 })
  } catch (error) {
    budgetRejected = /reserved operation/.test(error.message)
  }
  results.push({
    pair,
    clientRejected,
    daemonRejected: daemonOperationProfile(pair.familyId, pair.operationId) === null,
    budgetRejected
  })
}

if (results.length !== 5 || results.some(result =>
  !result.clientRejected || !result.daemonRejected || !result.budgetRejected) ||
  results[0].pair.familyId !== FAMILY.CORE ||
  results[0].pair.operationId !== OPERATION.CORE.OPEN_REPLICATION) process.exitCode = 1
else process.stdout.write(JSON.stringify({ pid: process.pid, results }))
