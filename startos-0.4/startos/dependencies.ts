import { sdk } from './sdk'

// Blindspark is self-contained — it depends on no other StartOS service.
export const setDependencies = sdk.setupDependencies(
  async ({ effects }) => ({}),
)
