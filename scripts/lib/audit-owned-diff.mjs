export const AUDIT_OWNED_DIFF_SLICES = Object.freeze([
  {
    id: 'release-blocker-closure',
    title: 'Release blocker closure board',
    files: [
      'README.md',
      'docs/RELEASE_AUTOMATION.md',
      'docs/TEST-COMMAND-MATRIX-2026-06-27.md',
      'package.json',
      'scripts/check-release-blockers.mjs',
      'scripts/check-npm-latest.mjs',
      'test/unit/release-blockers-check.test.js',
      'test/unit/npm-latest-check.test.js'
    ]
  },
  {
    id: 'seed-protocol-handshake-alias',
    title: 'Seed protocol handshake cap and compatibility alias',
    files: [
      'packages/core/core/index.js',
      'packages/core/core/protocol/seed-request.js',
      'test/unit/seed-protocol-encoding.test.js'
    ]
  },
  {
    id: 'relaykernel-gateway-compatibility',
    title: 'RelayKernel gateway compatibility matrix',
    files: [
      'README.md',
      'docs/RELAYKERNEL-GATEWAY-COMPATIBILITY.md',
      'docs/TEST-COMMAND-MATRIX-2026-06-27.md',
      'package.json',
      'packages/core/core/index.js',
      'packages/core/core/protocol/profile-vector-verifier.js',
      'packages/core/core/protocol/relaykernel-profile.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/check-relaykernel-gateway-compat.mjs',
      'scripts/verify-profile-vectors.mjs',
      'test/fixtures/relaykernel-profile/relaykernel-http-route-matrix-v1-blindspark-compat.json',
      'test/unit/profile-vector-verifier.test.js',
      'test/unit/relaykernel-gateway-compat.test.js'
    ]
  },
  {
    id: 'relaykernel-app-module-boundary-vector',
    title: 'RelayKernel app-module boundary profile vector',
    files: [
      'packages/core/core/protocol/profile-vector-verifier.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/fixtures/relaykernel-profile/relaykernel-profile-v1-app-module-boundary.json',
      'test/unit/profile-vector-verifier.test.js'
    ]
  },
  {
    id: 'public-release-promise-scope',
    title: 'Public release promise scope gate',
    files: [
      'README.md',
      'docs/RELEASE_AUTOMATION.md',
      'docs/TEST-COMMAND-MATRIX-2026-06-27.md',
      'package.json',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/check-release-promise-scope.mjs',
      'scripts/lib/release-promise-scope.mjs',
      'scripts/prepare-release.mjs',
      'test/unit/prepare-release.test.js',
      'test/unit/release-promise-scope.test.js'
    ]
  },
  {
    id: 'release-worktree-owned-diff',
    title: 'Release worktree owned-diff audit',
    files: [
      'README.md',
      'docs/RELEASE_AUTOMATION.md',
      'docs/TEST-COMMAND-MATRIX-2026-06-27.md',
      'package.json',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/check-audit-owned-diff.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js'
    ]
  },
  {
    id: 'hyperdrive-release-lifecycle',
    title: 'Bounded Hyperdrive release rotation and scoped reclamation',
    files: [
      'CHANGELOG.md',
      'docs/APP-RELEASE-LIFECYCLE.md',
      'docs/LADDER-SHIP-MAP.md',
      'docs/PEAR-INTEGRATION.md',
      'packages/core/core/app-registry.js',
      'packages/core/core/index.js',
      'packages/core/core/release-lifecycle.js',
      'packages/core/core/relay-node/app-lifecycle.js',
      'packages/core/core/relay-node/dedup-report.js',
      'packages/core/core/relay-node/eviction.js',
      'packages/core/core/relay-node/index.js',
      'scripts/lib/audit-owned-diff.mjs',
      'scripts/lib/publish-drive-sync.mjs',
      'scripts/lib/release-publisher.mjs',
      'scripts/publish-app.js',
      'test/integration/publish-release-rotation.test.js',
      'test/unit/app-release-rotation.test.js',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/dedup-reclaim.test.js',
      'test/unit/dedup-report.test.js',
      'test/unit/publish-drive-sync.test.js',
      'test/unit/release-lifecycle.test.js',
      'test/unit/release-publisher.test.js'
    ]
  },
  {
    id: 'dispatch-route-helper',
    title: 'HTTP dispatch route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-dispatch.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-dispatch.test.js'
    ]
  },
  {
    id: 'poker-usage-telemetry-helper',
    title: 'Poker usage telemetry helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-usage-telemetry.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-usage-telemetry.test.js'
    ]
  },
  {
    id: 'overview-route-helper',
    title: 'Overview route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-overview.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-overview.test.js'
    ]
  },
  {
    id: 'registry-status-route-helper',
    title: 'Registry status route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-registry-status.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-registry-status.test.js'
    ]
  },
  {
    id: 'status-route-helper',
    title: 'Public status route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-status-read.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-status-read.test.js',
      'test/unit/status-secrets-redaction.test.js'
    ]
  },
  {
    id: 'metrics-route-helper',
    title: 'Public metrics route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-metrics.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-metrics.test.js',
      'test/unit/api-response.test.js',
      'test/unit/metrics.test.js'
    ]
  },
  {
    id: 'seed-core-route-helper',
    title: 'Seed core route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-seed-core.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-seed-core.test.js'
    ]
  },
  {
    id: 'accounting-receipt-helper',
    title: 'Accounting receipt route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-accounting-receipt.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/accounting-receipt-runtime.test.js'
    ]
  },
  {
    id: 'usage-receipt-helper',
    title: 'Usage receipt helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-usage-telemetry.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-usage-telemetry.test.js',
      'test/unit/api-usage.test.js'
    ]
  },
  {
    id: 'usage-telemetry-route-helper',
    title: 'Usage telemetry route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-usage-telemetry.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-usage-telemetry.test.js'
    ]
  },
  {
    id: 'api-private-shim-cleanup',
    title: 'Relay API dead private helper shim cleanup',
    files: [
      'packages/core/core/relay-node/api.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-service-config-helpers.test.js',
      'test/unit/api-service-management.test.js',
      'test/unit/api-usage-telemetry.test.js',
      'test/unit/audit-owned-diff.test.js'
    ]
  },
  {
    id: 'capability-route-helper',
    title: 'Capability route helper extraction',
    files: [
      'packages/core/core/protocol/relaykernel-profile.js',
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-capabilities.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/capability-endpoints.test.js'
    ]
  },
  {
    id: 'management-read-helper',
    title: 'Management read payload helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-management-snapshots.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-management-snapshots.test.js'
    ]
  },
  {
    id: 'persist-failure-helper',
    title: 'Shared config and wizard persist failure helper',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-persist-failures.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-persist-failures.test.js'
    ]
  },
  {
    id: 'service-config-update-helper',
    title: 'Service config update helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-service-config.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-service-config-helpers.test.js'
    ]
  },
  {
    id: 'service-management-route-helper',
    title: 'Service management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-service-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-service-management.test.js'
    ]
  },
  {
    id: 'config-update-route-helper',
    title: 'Config update route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-config-update.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-config-update.test.js'
    ]
  },
  {
    id: 'mode-transport-route-helper',
    title: 'Mode and transport route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-mode-transport.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-mode-transport.test.js'
    ]
  },
  {
    id: 'device-pairing-route-helper',
    title: 'Device and pairing route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-device-pairing.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-device-pairing.test.js'
    ]
  },
  {
    id: 'custody-status-route-helper',
    title: 'Custody status route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-custody-disabled.js',
      'packages/core/core/relay-node/api-custody-status.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-custody-status.test.js'
    ]
  },
  {
    id: 'ai-model-actions-helper',
    title: 'AI model management action helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-ai-models.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-ai-models.test.js'
    ]
  },
  {
    id: 'service-provider-helper',
    title: 'AI and Poker service provider lookup helper',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-service-provider.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-ai-models.test.js',
      'test/unit/api-management-snapshots.test.js',
      'test/unit/api-poker.test.js',
      'test/unit/api-service-provider.test.js'
    ]
  },
  {
    id: 'poker-http-adapter-helper',
    title: 'Poker HTTP adapter load helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-poker-http-adapter.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-poker-http-adapter.test.js',
      'test/unit/api-poker.test.js'
    ]
  },
  {
    id: 'outboxlog-additive-engine',
    title: 'OutboxLog additive engine and single-writer verification',
    files: [
      'packages/services/builtin/outboxlog/',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-http-adapter',
    title: 'OutboxLog Peerit-compatible HTTP and SSE adapter',
    files: [
      'packages/services/builtin/outboxlog/http-adapter.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'packages/services/builtin/outboxlog/swarm-hub.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/outboxlog-http-adapter.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-relayapi-mount',
    title: 'OutboxLog RelayAPI optional adapter mount',
    files: [
      'packages/core/core/plugin-loader.js',
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-outboxlog-http-adapter.js',
      'packages/core/core/relay-node/api-route-mounts.js',
      'packages/core/core/relay-node/api-service-provider.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-outboxlog-http-adapter.test.js',
      'test/unit/api-outboxlog.test.js',
      'test/unit/api-route-mounts.test.js',
      'test/unit/api-service-provider.test.js',
      'test/unit/plugin-loader.test.js'
    ]
  },
  {
    id: 'outboxlog-bench-gate',
    title: 'OutboxLog Phase 3 benchmark gate',
    files: [
      'package.json',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/bench-outboxlog.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-bench.test.js'
    ]
  },
  {
    id: 'outboxlog-release-budget-gate',
    title: 'OutboxLog release/runtime benchmark budgets',
    files: [
      'package.json',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/bench-outboxlog.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-bench.test.js'
    ]
  },
  {
    id: 'outboxlog-directory-pagination',
    title: 'OutboxLog directory pagination and delta watermark',
    files: [
      'packages/services/builtin/outboxlog/http-adapter.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/outboxlog-http-adapter.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-append-event-replay',
    title: 'OutboxLog bounded append event replay markers',
    files: [
      'packages/services/builtin/outboxlog/http-adapter.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-http-adapter.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-sync-event-sse',
    title: 'OutboxLog sync event SSE marker stream',
    files: [
      'packages/services/builtin/outboxlog/http-adapter.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-http-adapter.test.js'
    ]
  },
  {
    id: 'outboxlog-operation-journal',
    title: 'OutboxLog replayable operation journal',
    files: [
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-hypercore-journal',
    title: 'OutboxLog Corestore-backed Hypercore journal',
    files: [
      'packages/services/builtin/outboxlog/hypercore-journal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-partitioned-hypercore-journal',
    title: 'OutboxLog partitioned per-outbox Hypercore journal',
    files: [
      'packages/services/builtin/outboxlog/hypercore-journal.js',
      'packages/services/builtin/outboxlog/index.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-runtime-seeder-rehearsal',
    title: 'OutboxLog runtime seeder pickup rehearsal',
    files: [
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-seeder-runtime.test.js'
    ]
  },
  {
    id: 'outboxlog-namespace-registration',
    title: 'OutboxLog app-agnostic namespace registration',
    files: [
      'packages/services/builtin/outboxlog/http-adapter.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-sealed-blind-namespace',
    title: 'OutboxLog sealed blind namespace body contract',
    files: [
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/builtin/outboxlog/outbox-log.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-seal-helper',
    title: 'OutboxLog client-owned blind payload seal helper',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-recipient-key-wrap',
    title: 'OutboxLog recipient key wrapping helper',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-aad-binding-helper',
    title: 'OutboxLog canonical blind payload AAD binding helper',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-recipient-directory-helper',
    title: 'OutboxLog app-owned recipient directory entry helper',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-recipient-rotation-helper',
    title: 'OutboxLog app-owned recipient key rotation verifier',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'outboxlog-blind-recipient-trust-root-helper',
    title: 'OutboxLog app-owned recipient directory trust-root verifier',
    files: [
      'packages/services/builtin/outboxlog/blind-seal.js',
      'packages/services/builtin/outboxlog/index.js',
      'packages/services/index.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/audit-owned-diff.test.js',
      'test/unit/outboxlog-blind-seal.test.js'
    ]
  },
  {
    id: 'notify-service-mvp',
    title: 'Notify service encrypted wake-only MVP',
    files: [
      'docs/PUSH-NOTIFICATION-SERVICE-SPEC.md',
      'packages/core/core/plugin-loader.js',
      'packages/services/builtin/notify-service.js',
      'packages/services/index.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/notify-service.test.js',
      'test/unit/plugin-loader.test.js'
    ]
  },
  {
    id: 'service-capability-profile',
    title: 'Optional service capability profile discovery',
    files: [
      'packages/core/core/capability-doc.js',
      'packages/core/core/relay-node/bare-relay.js',
      'packages/services/index.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/capability-doc.test.js'
    ]
  },
  {
    id: 'notify-http-client-api',
    title: 'Notify HTTP facade and client helper surface',
    files: [
      'docs/SERVICES.md',
      'packages/client/README.md',
      'packages/client/package.json',
      'packages/client/notify.js',
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-notify.js',
      'packages/core/core/relay-node/api-service-provider.js',
      'packages/services/README.md',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-notify.test.js',
      'test/unit/api-service-provider.test.js',
      'test/unit/client-notify.test.js'
    ]
  },
  {
    id: 'hyper-gateway-head-semantics',
    title: 'HyperGateway HEAD response semantics',
    files: [
      'packages/core/gateway/hyper-gateway.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/hyper-gateway-hardening.test.js'
    ]
  },
  {
    id: 'anchor-route-helper',
    title: 'Anchor proof/status route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-anchor-status.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-anchor-status.test.js'
    ]
  },
  {
    id: 'retrievability-proof-route-helper',
    title: 'Retrievability proof route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/retrievability-proof.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/retrievability-proof-api.test.js'
    ]
  },
  {
    id: 'eviction-purge-route-helper',
    title: 'Eviction purge route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-eviction-purge.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-eviction-purge.test.js'
    ]
  },
  {
    id: 'dedup-reclaim-route-helper',
    title: 'Dedup reclaim route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-dedup-reclaim.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-dedup-reclaim.test.js'
    ]
  },
  {
    id: 'index-room-route-helper',
    title: 'Index-room route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-index-room.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-index-room.test.js',
      'test/unit/index-room.test.js'
    ]
  },
  {
    id: 'unseed-route-helper',
    title: 'Unseed route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-unseed-actions.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-unseed-actions.test.js'
    ]
  },
  {
    id: 'seed-publish-route-helper',
    title: 'Seed and registry publish route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-seed-publish.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-publisher-signed.test.js',
      'test/unit/api-seed-publish.test.js'
    ]
  },
  {
    id: 'health-route-helper',
    title: 'Public health route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-health.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-auth.test.js',
      'test/unit/api-health.test.js'
    ]
  },
  {
    id: 'network-route-helper',
    title: 'Network state route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-network-state.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-network-state.test.js'
    ]
  },
  {
    id: 'reputation-record-route-helper',
    title: 'Reputation record route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-reputation-read.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-reputation-read.test.js'
    ]
  },
  {
    id: 'custody-management-route-helper',
    title: 'Custody management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-custody-disabled.js',
      'packages/core/core/relay-node/api-custody-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-custody-management.test.js'
    ]
  },
  {
    id: 'signed-ingress-route-helper',
    title: 'Signed ingress route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-signed-ingress.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-signed-ingress.test.js'
    ]
  },
  {
    id: 'wizard-action-route-helper',
    title: 'Wizard snapshot/action route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-wizard-actions.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-wizard-actions.test.js'
    ]
  },
  {
    id: 'route-mount-predicate-helper',
    title: 'Route mount and poker policy predicate helper extraction',
    files: [
      'packages/core/core/protocol/relaykernel-profile.js',
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-route-mounts.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-route-mounts.test.js'
    ]
  },
  {
    id: 'federation-management-route-helper',
    title: 'Federation management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-federation-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-federation-management.test.js'
    ]
  },
  {
    id: 'catalog-management-route-helper',
    title: 'Catalog management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-catalog-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-catalog-management.test.js'
    ]
  },
  {
    id: 'catalog-read-route-helper',
    title: 'Catalog read route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-catalog-read.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-catalog-read.test.js'
    ]
  },
  {
    id: 'public-discovery-route-helper',
    title: 'Public service/router discovery route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-router-read.js',
      'packages/core/core/relay-node/api-service-read.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-router-read.test.js',
      'test/unit/api-service-read.test.js'
    ]
  },
  {
    id: 'gateway-stats-route-helper',
    title: 'Gateway stats route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-gateway-stats.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-gateway-stats.test.js'
    ]
  },
  {
    id: 'peer-state-route-helper',
    title: 'Peer state route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-peer-state.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-peer-state.test.js'
    ]
  },
  {
    id: 'fork-proof-read-route-helper',
    title: 'Fork-proof read route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-fork-proofs.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-fork-proofs.test.js'
    ]
  },
  {
    id: 'delegation-management-route-helper',
    title: 'Delegation management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-delegation-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-delegation-management.test.js'
    ]
  },
  {
    id: 'lifecycle-management-route-helper',
    title: 'Lifecycle management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-lifecycle-actions.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-lifecycle-actions.test.js'
    ]
  },
  {
    id: 'lease-route-helper',
    title: 'Lease route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-lease.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-lease.test.js'
    ]
  },
  {
    id: 'subsidy-route-helper',
    title: 'Subsidy route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-subsidy.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-service-config.test.js',
      'test/unit/api-subsidy.test.js'
    ]
  },
  {
    id: 'alert-management-route-helper',
    title: 'Alert management route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-alert-management.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-alert-management.test.js'
    ]
  },
  {
    id: 'operator-telemetry-route-helper',
    title: 'Operator telemetry route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-operator-telemetry.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-operator-telemetry.test.js'
    ]
  },
  {
    id: 'index-proxy-route-helper',
    title: 'Index sidecar proxy route helper extraction',
    files: [
      'packages/core/core/relay-node/api.js',
      'packages/core/core/relay-node/api-index-proxy.js',
      'scripts/audit-workspace-alignment.mjs',
      'scripts/lib/audit-owned-diff.mjs',
      'test/unit/api-index-proxy.test.js'
    ]
  }
])

export function parsePorcelainStatus (text) {
  const lines = String(text || '').split(/\r?\n/).filter(Boolean)
  return lines.map((line) => {
    const status = line.slice(0, 2)
    const rawPath = line.slice(3)
    return {
      status,
      path: normalizePorcelainPath(rawPath),
      raw: line
    }
  }).filter(change => change.path)
}

export function classifyOwnedDiffPath (filePath, slices = AUDIT_OWNED_DIFF_SLICES) {
  return slices
    .filter(slice => (slice.files || []).includes(filePath))
    .map(slice => ({
      id: slice.id,
      title: slice.title
    }))
}

export function buildOwnedDiffReport (statusText, opts = {}) {
  const slices = opts.slices || AUDIT_OWNED_DIFF_SLICES
  const changes = parsePorcelainStatus(statusText)
  const entries = changes.map(change => {
    const owners = classifyOwnedDiffPath(change.path, slices)
    return {
      status: change.status,
      path: change.path,
      owners
    }
  })
  const unknown = entries.filter(entry => entry.owners.length === 0)
  const owned = entries.filter(entry => entry.owners.length > 0)

  return {
    schemaVersion: 1,
    kind: 'hiverelay-audit-owned-diff',
    scope: 'audit-owned development diff only; release closure still requires a clean worktree',
    status: unknown.length === 0 ? 'pass' : 'blocked',
    totals: {
      changed: entries.length,
      owned: owned.length,
      unknown: unknown.length,
      slices: slices.length
    },
    entries,
    unknown
  }
}

function normalizePorcelainPath (rawPath) {
  const renameTarget = rawPath.includes(' -> ')
    ? rawPath.slice(rawPath.lastIndexOf(' -> ') + 4)
    : rawPath
  return unquotePorcelainPath(renameTarget.trim())
}

function unquotePorcelainPath (value) {
  if (value.length < 2 || value[0] !== '"' || value[value.length - 1] !== '"') return value
  try {
    return JSON.parse(value)
  } catch {
    return value.slice(1, -1)
  }
}
