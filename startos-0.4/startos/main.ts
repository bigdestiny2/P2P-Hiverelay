import { sdk } from './sdk'
import { uiPort } from './utils'

// StartOS has no APP_SEED equivalent (Umbrel derives one from the device
// seed), so — exactly as the 0.3.x docker_entrypoint.sh did — we persist our
// own 32-byte seed on the data volume: first boot generates it, every later
// boot reuses it. That seed derives the dashboard's proxy-auth token AND keeps
// the relay identity stable across reinstalls (as long as /data survives).
//
// We run this inline via `sh -c` instead of a baked-in entrypoint script,
// because the image is the unmodified published GHCR image (referenced by
// dockerTag in the manifest) — we never rebuild it. `exec node …` becomes the
// container's PID 1 (runAsInit) so SIGTERM reaches the relay for clean
// shutdown. Byte-for-byte the same seed derivation as the 0.3.x package.
const SEED_AND_START =
  'if [ ! -f /data/.app-seed ]; then ' +
  "head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > /data/.app-seed; " +
  'chmod 600 /data/.app-seed; ' +
  'fi; ' +
  'export APP_SEED="$(cat /data/.app-seed)"; ' +
  'exec node /app/packages/core/cli/index.js start'

export const main = sdk.setupMain(async ({ effects }) => {
  return sdk.Daemons.of(effects).addDaemon('primary', {
    subcontainer: sdk.SubContainer.of(
      effects,
      { imageId: 'blindspark' },
      sdk.Mounts.of()
        .mountVolume({
          volumeId: 'main',
          subpath: null,
          mountpoint: '/data',
          readonly: false,
        })
        .mountVolume({
          volumeId: 'generation',
          subpath: null,
          mountpoint: '/config',
          readonly: true,
        }),
      'blindspark-sub',
    ),
    exec: {
      command: ['/bin/sh', '-c', SEED_AND_START],
      runAsInit: true,
      // Large nodes can take a while to flush on shutdown; give the relay room.
      sigtermTimeout: 60000,
      env: {
        HOME: '/data',
        HIVERELAY_API_HOST: '0.0.0.0',
        HIVERELAY_API_PORT: String(uiPort),
        // StartOS fronts the UI through its Tor/LAN proxy — same as Umbrel's
        // app_proxy — so the dashboard embeds a seed-derived bearer token in
        // served HTML to authenticate itself.
        HIVERELAY_UI_EXPOSE_TOKEN: '1',
        // Single-page appliance dashboard (no operator tabs, no Docs/GitHub).
        HIVERELAY_UI_SIMPLE: '1',
        // Sovereignty default: review every incoming seed request until the
        // operator explicitly switches modes from the dashboard.
        HIVERELAY_ACCEPT_MODE: 'review',
        // Conservative home-server default; the CLI only applies this before a
        // saved operator config exists, so dashboard changes win later.
        HIVERELAY_MAX_STORAGE: '10GB',
        HIVERELAY_LOG_LEVEL: 'info',
        HIVERELAY_REQUIRE_GENERATION_RECEIPT: '1',
        HIVERELAY_GENERATION_RECEIPT:
          '/config/storage-generation-receipt.v1.json',
        HIVERELAY_GENERATION_RECEIPT_SHA256_FILE:
          '/config/storage-generation-receipt.v1.sha256',
      },
    },
    ready: {
      display: 'Web Interface',
      // Matches the 0.3.x check: the dashboard actually answers on /health,
      // not merely that the port is open.
      fn: () =>
        sdk.healthCheck.checkWebUrl(
          effects,
          `http://localhost:${uiPort}/health`,
          {
            timeout: 10000,
            successMessage: 'The Blindspark dashboard is reachable',
            errorMessage:
              'The dashboard is not responding yet — large nodes can take a couple of minutes after a restart.',
          },
        ),
    },
    requires: [],
  })
})
