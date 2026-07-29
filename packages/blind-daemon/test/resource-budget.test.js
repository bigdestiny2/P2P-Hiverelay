import test from 'brittle'
import { FAMILY, OPERATION } from '@hiverelay/blind-protocol'
import { ResourceBudget } from '../resource-budget.js'

test('resource budget reserves request, response, staging, per-operation quota, and critical reserve', t => {
  const budget = new ResourceBudget({
    maxItems: 4,
    maxBytes: 1000,
    reservePercent: 25,
    operationQuotas: [{ familyId: FAMILY.CELL, operationId: OPERATION.CELL.GET, maxItems: 1, maxBytes: 500 }]
  })
  const reservation = budget.acquire({
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    requestBytes: 100,
    responseBytes: 200,
    stagingBytes: 50
  })
  t.is(reservation.bytes, 350)
  t.is(budget.bytes, 350)
  t.exception(() => budget.acquire({
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    bytes: 1
  }), /quota|saturated/)
  reservation.release()
  reservation.release()
  t.is(budget.bytes, 0)

  const ordinary = []
  for (let index = 0; index < 3; index++) {
    ordinary.push(budget.acquire({
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.GET,
      bytes: 1
    }))
  }
  t.exception(() => budget.acquire({
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    bytes: 1
  }), /saturated/)
  const critical = budget.acquire({
    familyId: FAMILY.DESCRIBE,
    operationId: OPERATION.DESCRIBE.GET,
    bytes: 1,
    critical: true
  })
  t.is(budget.items, 4)
  critical.release()
  for (const item of ordinary) item.release()
})
