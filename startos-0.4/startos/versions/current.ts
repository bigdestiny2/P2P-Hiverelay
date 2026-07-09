import { VersionInfo, IMPOSSIBLE } from '@start9labs/start-sdk'

// StartOS version format is MAJOR.MINOR.PATCH:BUILD. The MAJOR.MINOR.PATCH
// tracks the HiveRelay monorepo version; :BUILD is the packaging revision.
// This is a fresh 0.4-line package — no prior 0.4 version to migrate from
// (the 0.3.x YAML package is a separate distribution channel), so `up` is a
// no-op and `down` is impossible.
export const current = VersionInfo.of({
  version: '0.24.3:0',
  releaseNotes: {
    en_US:
      'Initial StartOS 0.4 (start-sdk 2.x) build of Blindspark — the HiveRelay ' +
      'blind relay appliance, ported from the 0.3.5.x YAML package. Same GHCR ' +
      'image, same /data layout, same review-mode + 10 GB defaults.',
  },
  migrations: {
    up: async ({ effects }) => {},
    down: IMPOSSIBLE,
  },
})
