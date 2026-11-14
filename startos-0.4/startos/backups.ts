import { sdk } from './sdk'

// The relay's identity, config, and seeded content all live on the `main`
// data volume (HOME=/data → ~/.hiverelay). Backing it up captures the whole
// node; a restore brings the relay back as itself (same identity + seed).
export const { createBackup, restoreInit } = sdk.setupBackups(
  async ({ effects }) => sdk.Backups.ofVolumes('main', 'generation'),
)
