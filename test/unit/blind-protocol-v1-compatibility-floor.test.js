import test from 'brittle'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

const FROZEN_SHA256 = Object.freeze({
  'packages/blind-protocol/hiverelay-blind-abi-v1.cenc': '8fcc75ed7f32af8f118a521fe230d77ec1e4b2b209296adda2e73e87b74ff5b6',
  'packages/blind-protocol/hiverelay-blind-abi-v1.draft.cenc': '8fcc75ed7f32af8f118a521fe230d77ec1e4b2b209296adda2e73e87b74ff5b6',
  'packages/blind-protocol/vector-manifest-v1.cenc': 'e23137dc90f52a1c9c3c8ac1e6ecb98eb32b653260fe1049f078ff8cebabc522',
  'packages/blind-protocol/vectors/draft/vector-manifest-v1.draft.cenc': 'e23137dc90f52a1c9c3c8ac1e6ecb98eb32b653260fe1049f078ff8cebabc522',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json': 'd6b757334bbec7b85d949085ce4b896a5fe960bc4c86c7f9001f81be78d0cefc',
  'packages/blind-protocol/schema-catalog-runtime-authority.js': '6c0c7a8be1f77709cd60edad083606fa3e3889f2f50396592bfe290db6404fcc',
  'packages/blind-protocol/wire-runtime-authority.js': '3c861d390f8f6b60a390334e3320cd22cdce6071dfe3a5f42231460e73f52cea',
  'packages/blind-protocol/hiverelay-blind-release-closure-v1.json': '9f82a7dbe4aee8cc4dd2c7e22864314a7489280b8ceb3fbf2dd68e71d095a663',
  'packages/blind-ipc/hiverelay-blind-private-ipc-v1.cenc': '116c78ad151543ff9973d4cb92089ddfbc2e3f861b1f502b9aa0c85a5a52e4f6',
  'packages/blind-ipc/hiverelay-blind-private-ipc-v1.draft.cenc': '116c78ad151543ff9973d4cb92089ddfbc2e3f861b1f502b9aa0c85a5a52e4f6',
  'packages/blind-ipc/vector-manifest-v1.cenc': 'd9949afeeb9fc06db9864d388a6917ca99bbec244395932a707cd8ab9736e29e',
  'packages/blind-ipc/vectors/draft/vector-manifest-v1.draft.cenc': 'd9949afeeb9fc06db9864d388a6917ca99bbec244395932a707cd8ab9736e29e',
  'packages/blind-ipc/hiverelay-blind-private-ipc-authority-v1.json': 'cba3f4be2f616a66730a90ce92ce78a963cf5389d18e41b9cdfe4ae1eeb5a59d',
  'packages/blind-ipc/hiverelay-blind-private-ipc-v2.cenc': '3475a93f8d6da4d5c516ec0017f4eb8337a2397f89dbb0000ea004f225461344',
  'packages/blind-ipc/vector-manifest-v2.cenc': '0abb90824d9e5388d538ae6a49cee67437056987601717bb9bdb003218deccff',
  'packages/blind-ipc/hiverelay-blind-private-ipc-authority-v2.json': '9e2abeed720afcea9165775bca0dff165901a1eab97251a7677d66e6292143a7',
  'packages/blind-protocol/hiverelay-blind-client-composition-authority-v1.json': '4b1cd5835a2952b5e06914e59890ad2ebb4fa085cbc294a79e24b91ff20ed160',
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc': 'a525dc297bf8771ecb7a9204b5b3c031bd292991b210421f3fa713619e296b60',
  'packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v1.cenc': '8ff920aece109f681f94ee655c9f273f78c66013fcff818bc40df86b867bb97f',
  'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc': 'b26ab9a86ccd665255ee17dd742ffc39acceeb670bc01a7f7633460cb9d7cee9',
  'packages/blind-protocol/client-composition-authority-generated.js': 'a66d7211bdedd3b0d0e580c7d6c504584001ee1bf5747ad9b27d8ee5e2b566aa',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.mjs': '10425bb00fb8045e63ce2869b5e6bf88af39dc0723963203a6b021e0fd28090a',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.manifest.cenc': '76a7ea97db644971203c2f94c476614a95b0320980a58504b927f04b152aadf1',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.chromium-evidence.json': '1382b24b21cae661392a199b0470a22768b85f62215db6fb943ed17b66859c2e',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.cross-host-evidence.json': '3cfd3c12a7664899a0901eff7b613f85da6fd039b930f74ade5bc820d215dcd2'
})

test('blind v1 compatibility floor: frozen authority and mirror bytes remain exact', t => {
  for (const [relative, expected] of Object.entries(FROZEN_SHA256)) {
    const bytes = fs.readFileSync(path.join(root, relative))
    const actual = createHash('sha256').update(bytes).digest('hex')
    t.is(actual, expected, relative)
  }
})
