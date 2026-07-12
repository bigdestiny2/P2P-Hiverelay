import fs from 'fs'
import b4a from 'b4a'
import { computeClientCompositionRuntimeVectors } from '../packages/blind-protocol/client-composition-runtime-vectors.js'
import {
  hashClientCompositionFormat,
  hashClientCompositionVectorSet
} from '../packages/blind-protocol/hashes.js'

const format = fs.readFileSync(new URL(
  '../packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc', import.meta.url))
const manifest = fs.readFileSync(new URL(
  '../packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc', import.meta.url))

console.log(JSON.stringify({
  runtimeVectors: computeClientCompositionRuntimeVectors(),
  checkedFormatHash: b4a.toString(hashClientCompositionFormat(format), 'hex'),
  checkedVectorSetHash: b4a.toString(hashClientCompositionVectorSet(manifest), 'hex')
}))
