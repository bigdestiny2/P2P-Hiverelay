import test from 'brittle'
import {
  EXECUTABLE_SCHEMA_CODECS,
  EXECUTABLE_SCHEMA_FIELD_STATUS,
  IMPLEMENTED_SCHEMAS,
  validateExecutableSchemaFieldMetadata
} from '../../packages/blind-protocol/index.js'

test('blind protocol executable struct metadata rejects field-name and order drift', t => {
  t.ok(EXECUTABLE_SCHEMA_FIELD_STATUS.checkedSchemaNames.length > 80)
  t.alike(EXECUTABLE_SCHEMA_FIELD_STATUS.mismatches, [])
  t.ok(EXECUTABLE_SCHEMA_FIELD_STATUS.complete)

  const drifted = IMPLEMENTED_SCHEMAS.map(row => row.name === 'BlindForwardOpenResultV1'
    ? {
        ...row,
        fields: row.fields.map(field => [...field]).with(2, ['selectedRouteId', 'optional(fixed16)'])
      }
    : row)
  const status = validateExecutableSchemaFieldMetadata(drifted, EXECUTABLE_SCHEMA_CODECS)
  t.absent(status.complete)
  t.alike(status.mismatches.map(row => row.schemaName), ['BlindForwardOpenResultV1'])
})
