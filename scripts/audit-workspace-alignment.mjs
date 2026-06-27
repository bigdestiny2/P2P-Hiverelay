import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const hiverelayRoot = path.resolve(here, '..')
const workspaceRoot = path.resolve(hiverelayRoot, '..', '..')

const checks = []
const warnings = []

function readText (...parts) {
  return fs.readFileSync(path.join(...parts), 'utf8')
}

function readJson (...parts) {
  return JSON.parse(readText(...parts))
}

function literalButtonsHaveTypeButton (html) {
  return (html.match(/<button\b[^>]*>/gi) || [])
    .every(tag => /\btype\s*=\s*["']button["']/i.test(tag))
}

function pass (message) {
  checks.push({ level: 'pass', message })
}

function fail (message) {
  checks.push({ level: 'fail', message })
}

function warn (message) {
  warnings.push(message)
}

function missingTerms (text, terms) {
  return terms.filter(term => !text.includes(term))
}

function htmlIds (text) {
  return Array.from(text.matchAll(/\bid\s*=\s*["']([^"']+)["']/gi), match => match[1])
}

function duplicateHtmlIds (text) {
  const seen = new Set()
  const duplicates = new Set()
  for (const id of htmlIds(text)) {
    if (seen.has(id)) duplicates.add(id)
    else seen.add(id)
  }
  return [...duplicates].sort()
}

const monorepoPkg = readJson(hiverelayRoot, 'package.json')
const corePkg = readJson(hiverelayRoot, 'packages', 'core', 'package.json')
const clientPkg = readJson(hiverelayRoot, 'packages', 'client', 'package.json')
const verifierPkg = readJson(hiverelayRoot, 'packages', 'verifier', 'package.json')
const servicesPkg = readJson(hiverelayRoot, 'packages', 'services', 'package.json')
const pearBrowserDemoManifest = readJson(hiverelayRoot, 'examples', 'pearbrowser-marketplace-demo', 'manifest.json')
const pearBrowserDemoReadme = readText(hiverelayRoot, 'examples', 'pearbrowser-marketplace-demo', 'README.md')
const pearBrowserDemoHtml = readText(hiverelayRoot, 'examples', 'pearbrowser-marketplace-demo', 'index.html')
const releaseAutomationDocs = readText(hiverelayRoot, 'docs', 'RELEASE_AUTOMATION.md')
const architectureGraphDoc = readText(hiverelayRoot, 'docs', 'HIVERELAY-ARCHITECTURE-GRAPH.md')
const architectureGraphSvg = readText(hiverelayRoot, 'docs', 'assets', 'hiverelay-core3-architecture.svg')
const readme = readText(hiverelayRoot, 'README.md')
const auditDoc = readText(hiverelayRoot, 'docs', 'AUDIT-2026-06-22.md')
const auditRoadmap = readText(hiverelayRoot, 'docs', 'AUDIT-ROADMAP.md')
const threatModelDoc = readText(hiverelayRoot, 'docs', 'THREAT-MODEL.md')
const reverseProxyDocs = readText(hiverelayRoot, 'docs', 'REVERSE-PROXY.md')
const protocolSpecDocs = readText(hiverelayRoot, 'docs', 'PROTOCOL-SPEC.md')
const developerDocs = readText(hiverelayRoot, 'docs', 'DEVELOPER.md')
const readmeMainUpdateAudit = readText(hiverelayRoot, 'docs', 'README-MAIN-UPDATE-AUDIT.md')
const shipHandoff20260626 = readText(hiverelayRoot, 'docs', 'SHIP-HANDOFF-2026-06-26.md')
const testCommandMatrix20260627 = readText(hiverelayRoot, 'docs', 'TEST-COMMAND-MATRIX-2026-06-27.md')
const startOsManifest = readText(hiverelayRoot, 'startos', 'manifest.yaml')
const startOsMakefile = readText(hiverelayRoot, 'startos', 'Makefile')
const startOsReadme = readText(hiverelayRoot, 'startos', 'README.md')
const startOsEntrypoint = readText(hiverelayRoot, 'startos', 'docker_entrypoint.sh')
const releaseWorkflow = readText(hiverelayRoot, '.github', 'workflows', 'release-surfaces.yml')
const releasePreflightWorkflow = readText(hiverelayRoot, '.github', 'workflows', 'release-distribution-preflight.yml')
const dockerPublishWorkflow = readText(hiverelayRoot, '.github', 'workflows', 'docker-publish.yml')
const umbrelAppValidateWorkflow = readText(hiverelayRoot, '.github', 'workflows', 'umbrel-app-validate.yml')
const testWorkflow = readText(hiverelayRoot, '.github', 'workflows', 'test.yml')
const workflowTexts = [
  releaseWorkflow,
  releasePreflightWorkflow,
  dockerPublishWorkflow,
  umbrelAppValidateWorkflow,
  testWorkflow
].join('\n')
const dockerignore = readText(hiverelayRoot, '.dockerignore')
const dockerfile = readText(hiverelayRoot, 'Dockerfile')
const dockerEntrypoint = readText(hiverelayRoot, 'docker-entrypoint.sh')
const gitattributes = readText(hiverelayRoot, '.gitattributes')
const prepareRelease = readText(hiverelayRoot, 'scripts', 'prepare-release.mjs')
const officialUmbrelExport = readText(hiverelayRoot, 'scripts', 'export-official-umbrel-app.mjs')
const officialUmbrelGalleryCheck = readText(hiverelayRoot, 'scripts', 'check-umbrel-gallery.mjs')
const umbrelRuntimeReviewEvidence = readText(hiverelayRoot, 'scripts', 'write-umbrel-runtime-review-evidence.mjs')
const umbrelRuntimeReviewEvidenceVerify = readText(hiverelayRoot, 'scripts', 'verify-umbrel-runtime-review-evidence.mjs')
const releaseDistributionEnvCheck = readText(hiverelayRoot, 'scripts', 'check-release-distribution-env.mjs')
const releaseEnvFileLib = readText(hiverelayRoot, 'scripts', 'lib', 'release-env-file.mjs')
const githubReleaseSetupCheck = readText(hiverelayRoot, 'scripts', 'check-github-release-setup.mjs')
const githubReleaseSecretsApply = readText(hiverelayRoot, 'scripts', 'apply-github-release-secrets.mjs')
const releaseSecretsTemplate = readText(hiverelayRoot, 'scripts', 'write-release-secrets-template.mjs')
const ecosystemConsumersAudit = readText(hiverelayRoot, 'scripts', 'audit-ecosystem-consumers.mjs')
const ecosystemConsumersSync = readText(hiverelayRoot, 'scripts', 'sync-ecosystem-consumers.mjs')
const publicArtifactSecretsAudit = readText(hiverelayRoot, 'scripts', 'check-public-artifact-secrets.mjs')
const shipHandoffUpdate = readText(hiverelayRoot, 'scripts', 'update-ship-handoff.mjs')
const shipHandoffIssue120Log = readText(hiverelayRoot, 'docs', 'ship-handoff', 'issue-120-release-distribution-preflight.txt')
const releaseImageManifestCheck = readText(hiverelayRoot, 'scripts', 'check-release-image-manifest.mjs')
const githubEnvWriter = readText(hiverelayRoot, 'scripts', 'write-github-env.mjs')
const releaseEvidence = readText(hiverelayRoot, 'scripts', 'write-release-evidence.mjs')
const releaseEvidenceVerify = readText(hiverelayRoot, 'scripts', 'verify-release-evidence.mjs')
const releaseHandoffEvidenceVerify = readText(hiverelayRoot, 'scripts', 'verify-release-handoff-evidence.mjs')
const officialUmbrelPrEvidence = readText(hiverelayRoot, 'scripts', 'write-official-umbrel-pr-evidence.mjs')
const startosRegistryEvidence = readText(hiverelayRoot, 'scripts', 'write-startos-registry-evidence.mjs')
const umbrelManifest = readText(hiverelayRoot, 'umbrel-app', 'umbrel-app.yml')
const umbrelCompose = readText(hiverelayRoot, 'umbrel-app', 'docker-compose.yml')
const umbrelReadme = readText(hiverelayRoot, 'umbrel-app', 'README.md')
const umbrelSubmissionChecklist = readText(hiverelayRoot, 'umbrel-app', 'SUBMISSION-CHECKLIST.md')
const releaseImageSmoke = readText(hiverelayRoot, 'scripts', 'smoke-release-image.mjs')
const umbrelSmokePackage = readText(hiverelayRoot, 'scripts', 'smoke-umbrel-package.mjs')
const fleetRolloutCheck = readText(hiverelayRoot, 'scripts', 'check-fleet-rollout.mjs')
const fleetStatusScript = readText(hiverelayRoot, 'fleet', 'fleet-status.sh')
const fleetUpdaterScript = readText(hiverelayRoot, 'fleet', 'updater.sh')
const deployVpsScript = readText(hiverelayRoot, 'scripts', 'deploy-vps.sh')
const relayJanitorScript = readText(hiverelayRoot, 'scripts', 'relay-janitor.js')
const cliIndex = readText(hiverelayRoot, 'packages', 'core', 'cli', 'index.js')
const cliCatalog = readText(hiverelayRoot, 'packages', 'core', 'cli', 'catalog.js')
const cliSetup = readText(hiverelayRoot, 'packages', 'core', 'cli', 'setup.js')
const cliManage = readText(hiverelayRoot, 'packages', 'core', 'cli', 'manage.js')
const defaultConfig = readText(hiverelayRoot, 'packages', 'core', 'config', 'default.js')
const constantsCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'constants.js')
const blindsparkDashboard = readText(hiverelayRoot, 'dashboard', 'blindspark.html')
const fullDashboard = readText(hiverelayRoot, 'dashboard', 'index.html')
const wizardDashboard = readText(hiverelayRoot, 'dashboard', 'wizard.html')
const relayApi = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api.js')
const bareHttpServer = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'bare-http-server.js')
const relayMetrics = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'metrics.js')
const relayApiAlertManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-alert-management.js')
const relayApiAiModels = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-ai-models.js')
const relayApiAnchorStatus = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-anchor-status.js')
const relayApiAuthFailures = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-auth-failures.js')
const relayApiAuthHelpers = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-auth-helpers.js')
const relayApiBody = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-body.js')
const relayApiCatalogManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-catalog-management.js')
const relayApiCatalogRead = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-catalog-read.js')
const relayApiConfigUpdate = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-config-update.js')
const relayApiCors = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-cors.js')
const relayApiCustodyManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-custody-management.js')
const relayApiCustodyStatus = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-custody-status.js')
const relayApiDashboardHtml = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-dashboard-html.js')
const relayApiDashboardRoutes = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-dashboard-routes.js')
const relayApiDevicePairing = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-device-pairing.js')
const relayApiDelegationManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-delegation-management.js')
const relayApiDispatch = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-dispatch.js')
const relayApiEvictionPurge = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-eviction-purge.js')
const relayApiFederationManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-federation-management.js')
const relayApiForkProofs = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-fork-proofs.js')
const relayApiGatewayStats = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-gateway-stats.js')
const relayApiHealth = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-health.js')
const relayApiLifecycleActions = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-lifecycle-actions.js')
const relayApiManagementSnapshots = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-management-snapshots.js')
const relayApiNetworkState = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-network-state.js')
const relayApiOverview = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-overview.js')
const relayApiOperatorTelemetry = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-operator-telemetry.js')
const relayApiPeerState = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-peer-state.js')
const relayApiRegistryStatus = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-registry-status.js')
const relayApiReputationRead = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-reputation-read.js')
const relayApiRequest = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-request.js')
const relayApiRateLimit = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-rate-limit.js')
const relayApiResponse = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-response.js')
const relayApiRouterRead = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-router-read.js')
const relayApiSafeConfig = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-safe-config.js')
const relayApiSeedPublish = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-seed-publish.js')
const relayApiSignedIngress = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-signed-ingress.js')
const relayApiServiceConfig = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-service-config.js')
const relayApiServiceManagement = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-service-management.js')
const relayApiServiceRead = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-service-read.js')
const relayApiStatusRead = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-status-read.js')
const relayApiModeTransport = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-mode-transport.js')
const relayApiSubsidy = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-subsidy.js')
const relayApiLease = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-lease.js')
const relayApiUnseedActions = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-unseed-actions.js')
const relayApiUsageTelemetry = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-usage-telemetry.js')
const relayApiValidation = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-validation.js')
const relayApiWizardActions = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'api-wizard-actions.js')
const leaseManager = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'lease', 'index.js')
const relayNode = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'index.js')
const bareRelay = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'bare-relay.js')
const routerCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'router', 'index.js')
const serviceRegistryCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'services', 'registry.js')
const serviceCatalogCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'services', 'service-catalog.js')
const serviceProtocol = readText(hiverelayRoot, 'packages', 'core', 'core', 'services', 'protocol.js')
const appRegistryCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'app-registry.js')
const appLifecycleCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'app-lifecycle.js')
const pluginLoader = readText(hiverelayRoot, 'packages', 'core', 'core', 'plugin-loader.js')
const accessControl = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'access-control.js')
const federationCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'federation.js')
const networkDiscoveryCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'network-discovery.js')
const quorumSelector = readText(hiverelayRoot, 'packages', 'core', 'core', 'quorum-selector.js')
const manifestStoreCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'manifest-store.js')
const forkDetectorCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'fork-detector.js')
const wsFeed = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'ws-feed.js')
const websocketTransport = readText(hiverelayRoot, 'packages', 'core', 'transports', 'websocket', 'index.js')
const gatewayServer = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'gateway-server.js')
const hyperGateway = readText(hiverelayRoot, 'packages', 'core', 'gateway', 'hyper-gateway.js')
const standaloneGatewayServer = readText(hiverelayRoot, 'packages', 'core', 'gateway', 'server.js')
const autoHealCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'auto-heal.js')
const proofOfRelay = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'proof-of-relay.js')
const protocolMessages = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'messages.js')
const seedRequestProtocol = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'seed-request.js')
const relayCircuitProtocol = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'relay-circuit.js')
const forwardRelayProtocol = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'forward-relay.js')
const jsonMessageEncoding = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'json-message-encoding.js')
const anchorChannel = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'anchor-channel.js')
const custodyChannel = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'custody-channel.js')
const publishChannel = readText(hiverelayRoot, 'packages', 'core', 'core', 'protocol', 'publish-channel.js')
const signedDirectory = readText(hiverelayRoot, 'packages', 'core', 'core', 'services', 'signed-directory.js')
const seedingRegistry = readText(hiverelayRoot, 'packages', 'core', 'core', 'registry', 'index.js')
const pokerHttpAdapter = readText(hiverelayRoot, 'packages', 'services', 'builtin', 'poker', 'http-adapter.js')
const pokerWsAdapter = readText(hiverelayRoot, 'packages', 'services', 'builtin', 'poker', 'ws-adapter.js')
const pokerReadme = readText(hiverelayRoot, 'packages', 'services', 'builtin', 'poker', 'README.md')
const servedAccounting = readText(hiverelayRoot, 'packages', 'core', 'core', 'relay-node', 'served-accounting.js')
const clientSdk = readText(hiverelayRoot, 'packages', 'client', 'index.js')
const clientPairing = readText(hiverelayRoot, 'packages', 'client', 'pairing.js')
const errorPrefixes = readText(hiverelayRoot, 'packages', 'core', 'core', 'error-prefixes.js')
const subsidyCore = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'subsidy', 'index.js')
const reputationCore = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'reputation', 'index.js')
const lightningProvider = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'payment', 'lightning-provider.js')
const blindMintCore = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'payment', 'blind-mint.js')
const cashuCore = readText(hiverelayRoot, 'packages', 'core', 'incentive', 'payment', 'cashu.js')
const pvssCore = readText(hiverelayRoot, 'packages', 'core', 'core', 'pvss.js')
const clientSecretSharing = readText(hiverelayRoot, 'packages', 'client', 'secret-sharing.js')
const servicesIdentityCrypto = readText(hiverelayRoot, 'packages', 'services', 'identity', 'crypto.js')
const servicesVrfEcv = readText(hiverelayRoot, 'packages', 'services', 'builtin', 'vrf', 'ecvrf.js')
const pokerChaumPedersen = readText(hiverelayRoot, 'packages', 'services', 'builtin', 'poker', 'crypto', 'chaum-pedersen.js')
const privateModeTest = readText(hiverelayRoot, 'test', 'unit', 'private-mode.test.js')
const discoveryTopicsTest = readText(hiverelayRoot, 'test', 'unit', 'discovery-topics.test.js')
const protocolSecurityTest = readText(hiverelayRoot, 'test', 'unit', 'protocol-security.test.js')
const servicesTest = readText(hiverelayRoot, 'test', 'unit', 'services.test.js')
const errorPrefixesTest = readText(hiverelayRoot, 'test', 'unit', 'error-prefixes.test.js')
const protocolJsonEncodingTest = readText(hiverelayRoot, 'test', 'unit', 'protocol-json-encoding.test.js')
const pairingProtocolTest = readText(hiverelayRoot, 'test', 'unit', 'pairing-protocol.test.js')
const seedProtocolEncodingTest = readText(hiverelayRoot, 'test', 'unit', 'seed-protocol-encoding.test.js')
const forwardRelayEncodingTest = readText(hiverelayRoot, 'test', 'unit', 'forward-relay-encoding.test.js')
const circuitRelayEncodingTest = readText(hiverelayRoot, 'test', 'unit', 'circuit-relay-encoding.test.js')
const proofOfRelayTest = readText(hiverelayRoot, 'test', 'unit', 'proof-of-relay.test.js')
const autoHealTest = readText(hiverelayRoot, 'test', 'unit', 'auto-heal.test.js')
const evictionTest = readText(hiverelayRoot, 'test', 'unit', 'eviction.test.js')
const unseedVerifyTest = readText(hiverelayRoot, 'test', 'unit', 'unseed-verify.test.js')
const clientServiceTest = readText(hiverelayRoot, 'test', 'unit', 'client-service.test.js')
const apiAlertManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-alert-management.test.js')
const apiAiModelsTest = readText(hiverelayRoot, 'test', 'unit', 'api-ai-models.test.js')
const apiAnchorStatusTest = readText(hiverelayRoot, 'test', 'unit', 'api-anchor-status.test.js')
const apiAuthTest = readText(hiverelayRoot, 'test', 'unit', 'api-auth.test.js')
const apiQvacModelsTest = readText(hiverelayRoot, 'test', 'unit', 'api-qvac-models.test.js')
const apiAuthFailuresTest = readText(hiverelayRoot, 'test', 'unit', 'api-auth-failures.test.js')
const apiAuthHelpersTest = readText(hiverelayRoot, 'test', 'unit', 'api-auth-helpers.test.js')
const apiBodyTest = readText(hiverelayRoot, 'test', 'unit', 'api-body.test.js')
const apiCatalogManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-catalog-management.test.js')
const apiCatalogReadTest = readText(hiverelayRoot, 'test', 'unit', 'api-catalog-read.test.js')
const apiConfigUpdateTest = readText(hiverelayRoot, 'test', 'unit', 'api-config-update.test.js')
const apiCorsTest = readText(hiverelayRoot, 'test', 'unit', 'api-cors.test.js')
const apiCustodyManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-custody-management.test.js')
const apiCustodyStatusTest = readText(hiverelayRoot, 'test', 'unit', 'api-custody-status.test.js')
const apiDashboardHtmlTest = readText(hiverelayRoot, 'test', 'unit', 'api-dashboard-html.test.js')
const apiDashboardRoutesTest = readText(hiverelayRoot, 'test', 'unit', 'api-dashboard-routes.test.js')
const apiDevicePairingTest = readText(hiverelayRoot, 'test', 'unit', 'api-device-pairing.test.js')
const apiDelegationManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-delegation-management.test.js')
const apiDispatchTest = readText(hiverelayRoot, 'test', 'unit', 'api-dispatch.test.js')
const apiEvictionPurgeTest = readText(hiverelayRoot, 'test', 'unit', 'api-eviction-purge.test.js')
const apiFederationManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-federation-management.test.js')
const apiGatewayStatsTest = readText(hiverelayRoot, 'test', 'unit', 'api-gateway-stats.test.js')
const federationHardeningTest = readText(hiverelayRoot, 'test', 'unit', 'federation-hardening.test.js')
const federationPollManyTest = readText(hiverelayRoot, 'test', 'integration', 'federation-poll-many.test.js')
const apiHealthTest = readText(hiverelayRoot, 'test', 'unit', 'api-health.test.js')
const apiLifecycleActionsTest = readText(hiverelayRoot, 'test', 'unit', 'api-lifecycle-actions.test.js')
const apiManagementSnapshotsTest = readText(hiverelayRoot, 'test', 'unit', 'api-management-snapshots.test.js')
const apiNetworkStateTest = readText(hiverelayRoot, 'test', 'unit', 'api-network-state.test.js')
const networkDiscoveryTest = readText(hiverelayRoot, 'test', 'unit', 'network-discovery.test.js')
const apiOverviewTest = readText(hiverelayRoot, 'test', 'unit', 'api-overview.test.js')
const apiOperatorTelemetryTest = readText(hiverelayRoot, 'test', 'unit', 'api-operator-telemetry.test.js')
const apiPeerStateTest = readText(hiverelayRoot, 'test', 'unit', 'api-peer-state.test.js')
const apiForkProofsTest = readText(hiverelayRoot, 'test', 'unit', 'api-fork-proofs.test.js')
const apiRegistryStatusTest = readText(hiverelayRoot, 'test', 'unit', 'api-registry-status.test.js')
const apiReputationReadTest = readText(hiverelayRoot, 'test', 'unit', 'api-reputation-read.test.js')
const apiRequestTest = readText(hiverelayRoot, 'test', 'unit', 'api-request.test.js')
const apiRateLimitTest = readText(hiverelayRoot, 'test', 'unit', 'api-rate-limit.test.js')
const apiResponseTest = readText(hiverelayRoot, 'test', 'unit', 'api-response.test.js')
const apiRouterReadTest = readText(hiverelayRoot, 'test', 'unit', 'api-router-read.test.js')
const routerTest = readText(hiverelayRoot, 'test', 'unit', 'router.test.js')
const apiSafeConfigTest = readText(hiverelayRoot, 'test', 'unit', 'api-safe-config.test.js')
const apiSeedPublishTest = readText(hiverelayRoot, 'test', 'unit', 'api-seed-publish.test.js')
const apiSignedIngressTest = readText(hiverelayRoot, 'test', 'unit', 'api-signed-ingress.test.js')
const apiStatusReadTest = readText(hiverelayRoot, 'test', 'unit', 'api-status-read.test.js')
const apiSubsidyTest = readText(hiverelayRoot, 'test', 'unit', 'api-subsidy.test.js')
const apiLeaseTest = readText(hiverelayRoot, 'test', 'unit', 'api-lease.test.js')
const apiUnseedActionsTest = readText(hiverelayRoot, 'test', 'unit', 'api-unseed-actions.test.js')
const apiValidationTest = readText(hiverelayRoot, 'test', 'unit', 'api-validation.test.js')
const apiWizardActionsTest = readText(hiverelayRoot, 'test', 'unit', 'api-wizard-actions.test.js')
const apiModeTransportTest = readText(hiverelayRoot, 'test', 'unit', 'api-mode-transport.test.js')
const apiUsageTelemetryTest = readText(hiverelayRoot, 'test', 'unit', 'api-usage-telemetry.test.js')
const apiUiTokenTest = readText(hiverelayRoot, 'test', 'unit', 'api-ui-token.test.js')
const manageCliClientTest = readText(hiverelayRoot, 'test', 'unit', 'manage-cli-client.test.js')
const configLoaderTest = readText(hiverelayRoot, 'test', 'unit', 'config-loader.test.js')
const relayNodeTest = readText(hiverelayRoot, 'test', 'unit', 'relay-node.test.js')
const bareRelaySurfaceTest = readText(hiverelayRoot, 'test', 'unit', 'bare-relay-surface.test.js')
const bareRuntimeTest = readText(hiverelayRoot, 'test', 'bare', 'index.js')
const bareHttpServerTest = readText(hiverelayRoot, 'test', 'unit', 'bare-http-server.test.js')
const apiServiceConfigHelpersTest = readText(hiverelayRoot, 'test', 'unit', 'api-service-config-helpers.test.js')
const apiServiceManagementTest = readText(hiverelayRoot, 'test', 'unit', 'api-service-management.test.js')
const apiServiceConfigTest = readText(hiverelayRoot, 'test', 'unit', 'api-service-config.test.js')
const serviceCatalogSanitizerTest = readText(hiverelayRoot, 'test', 'unit', 'service-catalog-sanitizer.test.js')
const apiPublisherSignedTest = readText(hiverelayRoot, 'test', 'unit', 'api-publisher-signed.test.js')
const apiTransientErrorsTest = readText(hiverelayRoot, 'test', 'unit', 'api-transient-errors.test.js')
const subsidyTest = readText(hiverelayRoot, 'test', 'unit', 'subsidy.test.js')
const capabilityEndpointsTest = readText(hiverelayRoot, 'test', 'unit', 'capability-endpoints.test.js')
const custodyStatusRedactionTest = readText(hiverelayRoot, 'test', 'unit', 'custody-status-redaction.test.js')
const statusSecretsRedactionTest = readText(hiverelayRoot, 'test', 'unit', 'status-secrets-redaction.test.js')
const quorumSelectorTest = readText(hiverelayRoot, 'test', 'unit', 'quorum-selector.test.js')
const reputationTest = readText(hiverelayRoot, 'test', 'unit', 'reputation.test.js')
const blindMintTest = readText(hiverelayRoot, 'test', 'unit', 'blind-mint.test.js')
const cashuTest = readText(hiverelayRoot, 'test', 'unit', 'cashu.test.js')
const appRegistryTest = readText(hiverelayRoot, 'test', 'unit', 'app-registry.test.js')
const signedDirectoryTest = readText(hiverelayRoot, 'test', 'unit', 'signed-directory.test.js')
const appLifecyclePersistenceTest = readText(hiverelayRoot, 'test', 'unit', 'app-lifecycle-persistence.test.js')
const manifestStoreTest = readText(hiverelayRoot, 'test', 'unit', 'manifest-store.test.js')
const forkDetectorTest = readText(hiverelayRoot, 'test', 'unit', 'fork-detector.test.js')
const pluginLoaderTest = readText(hiverelayRoot, 'test', 'unit', 'plugin-loader.test.js')
const prepareReleaseTest = readText(hiverelayRoot, 'test', 'unit', 'prepare-release.test.js')
const fleetRolloutCheckTest = readText(hiverelayRoot, 'test', 'unit', 'fleet-rollout-check.test.js')
const fleetShellSafetyTest = readText(hiverelayRoot, 'test', 'unit', 'fleet-shell-safety.test.js')
const officialUmbrelExportTest = readText(hiverelayRoot, 'test', 'unit', 'official-umbrel-export.test.js')
const officialUmbrelGalleryCheckTest = readText(hiverelayRoot, 'test', 'unit', 'umbrel-gallery-check.test.js')
const umbrelRuntimeReviewEvidenceTest = readText(hiverelayRoot, 'test', 'unit', 'umbrel-runtime-review-evidence.test.js')
const umbrelRuntimeReviewEvidenceVerifyTest = readText(hiverelayRoot, 'test', 'unit', 'umbrel-runtime-review-verify.test.js')
const releaseDistributionEnvCheckTest = readText(hiverelayRoot, 'test', 'unit', 'release-distribution-env.test.js')
const githubReleaseSetupCheckTest = readText(hiverelayRoot, 'test', 'unit', 'github-release-setup.test.js')
const githubReleaseSecretsApplyTest = readText(hiverelayRoot, 'test', 'unit', 'github-release-secrets-apply.test.js')
const releaseSecretsTemplateTest = readText(hiverelayRoot, 'test', 'unit', 'release-secret-template.test.js')
const ecosystemConsumersAuditTest = readText(hiverelayRoot, 'test', 'unit', 'ecosystem-consumers.test.js')
const publicArtifactSecretsAuditTest = readText(hiverelayRoot, 'test', 'unit', 'public-artifact-secret-scan.test.js')
const releaseEvidenceTest = readText(hiverelayRoot, 'test', 'unit', 'release-evidence.test.js')
const releaseEvidenceVerifyTest = readText(hiverelayRoot, 'test', 'unit', 'release-evidence-verify.test.js')
const releaseHandoffEvidenceVerifyTest = readText(hiverelayRoot, 'test', 'unit', 'release-handoff-evidence-verify.test.js')
const releaseImageManifestCheckTest = readText(hiverelayRoot, 'test', 'unit', 'release-image-manifest-check.test.js')
const packageEntryPointsTest = readText(hiverelayRoot, 'test', 'unit', 'package-entrypoints.test.js')
const officialUmbrelPrEvidenceTest = readText(hiverelayRoot, 'test', 'unit', 'official-umbrel-pr-evidence.test.js')
const startosRegistryEvidenceTest = readText(hiverelayRoot, 'test', 'unit', 'startos-registry-evidence.test.js')
const startosPackageGuardTest = readText(hiverelayRoot, 'test', 'unit', 'startos-package-guard.test.js')
const releaseSmokeEvidenceWriterTest = readText(hiverelayRoot, 'test', 'unit', 'release-smoke-evidence-writer.test.js')
const umbrelUiControlsTest = readText(hiverelayRoot, 'test', 'unit', 'umbrel-ui-controls.test.js')
const dashboardIndexUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-index-ui.test.js')
const dashboardDocsUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-docs-ui.test.js')
const dashboardWizardUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-wizard-ui.test.js')
const dashboardCatalogUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-catalog-ui.test.js')
const dashboardNetworkUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-network-ui.test.js')
const dashboardLeaderboardUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-leaderboard-ui.test.js')
const dashboardPaymentsUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-payments-ui.test.js')
const dashboardPollingVisibilityTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-polling-visibility.test.js')
const dashboardCalculatorUiTest = readText(hiverelayRoot, 'test', 'unit', 'dashboard-calculator-ui.test.js')
const metricsTest = readText(hiverelayRoot, 'test', 'unit', 'metrics.test.js')
const wsFeedPayloadTest = readText(hiverelayRoot, 'test', 'unit', 'ws-feed-payload.test.js')
const websocketTransportTest = readText(hiverelayRoot, 'test', 'unit', 'websocket-transport.test.js')
const gatewayServerTest = readText(hiverelayRoot, 'test', 'unit', 'gateway-server.test.js')
const hyperGatewayHardeningTest = readText(hiverelayRoot, 'test', 'unit', 'hyper-gateway-hardening.test.js')
const standaloneGatewayServerTest = readText(hiverelayRoot, 'test', 'unit', 'gateway-standalone-server.test.js')
const pokerHttpAdapterTest = readText(hiverelayRoot, 'test', 'unit', 'poker-http-adapter.test.js')
const pokerWsAdapterTest = readText(hiverelayRoot, 'test', 'unit', 'poker-ws-adapter.test.js')
const docsDashboard = readText(hiverelayRoot, 'dashboard', 'docs.html')
const catalogDashboard = readText(hiverelayRoot, 'dashboard', 'catalog.html')
const networkDashboard = readText(hiverelayRoot, 'dashboard', 'network.html')
const leaderboardDashboard = readText(hiverelayRoot, 'dashboard', 'leaderboard.html')
const paymentsDashboard = readText(hiverelayRoot, 'dashboard', 'payments.html')
const calculatorDashboard = readText(hiverelayRoot, 'dashboard', 'calculator.html')

const expectedVersion = monorepoPkg.version
for (const pkg of [
  ['packages/core', corePkg.version],
  ['packages/client', clientPkg.version],
  ['packages/verifier', verifierPkg.version],
  ['packages/services', servicesPkg.version]
]) {
  const [name, version] = pkg
  if (version === expectedVersion) pass(`${name} version matches monorepo (${version})`)
  else fail(`${name} version ${version} does not match monorepo ${expectedVersion}`)
}

const dashboardFiles = [
  'index.html',
  'docs.html',
  'catalog.html',
  'network.html',
  'leaderboard.html',
  'payments.html',
  'calculator.html',
  'wizard.html'
]

for (const file of dashboardFiles) {
  const fullPath = path.join(hiverelayRoot, 'dashboard', file)
  const html = readText(fullPath)
  if (html.includes('Blindspark')) fail(`dashboard/${file} still contains legacy Blindspark branding`)
  else pass(`dashboard/${file} is HiveRelay-branded`)

  if (html.includes('p2p-hiverelay/client')) fail(`dashboard/${file} still documents the legacy p2p-hiverelay/client import path`)
  else pass(`dashboard/${file} uses current SDK import paths`)
}

if (
  duplicateHtmlIds(blindsparkDashboard).length === 0 &&
  umbrelUiControlsTest.includes('umbrel dashboard has unique element ids for interactive controls') &&
  umbrelUiControlsTest.includes("countId(dashboard, 'servicesCard'), 1")
) {
  pass('Umbrel dashboard has unique interactive element ids')
} else {
  fail(`Umbrel dashboard has duplicate interactive element ids: ${duplicateHtmlIds(blindsparkDashboard).join(', ') || 'test coverage missing'}`)
}

if (
  blindsparkDashboard.includes('id="svcBody"') &&
  blindsparkDashboard.includes('Select preset') &&
  blindsparkDashboard.includes('Save selection') &&
  blindsparkDashboard.includes('Restart now') &&
  blindsparkDashboard.includes('id="svcStatus" role="status" aria-live="polite" aria-atomic="true"') &&
  blindsparkDashboard.includes('background:transparent;border:0;border-radius:0;padding:0') &&
  blindsparkDashboard.includes('.svc-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.55rem') &&
  blindsparkDashboard.includes('.svc-card:focus-within{outline:2px solid var(--cyan);outline-offset:2px}') &&
  blindsparkDashboard.includes('function svcVisualState(name, configured, active)') &&
  blindsparkDashboard.includes("appendServiceSummary(summary, 'Selected', metricCount(configured.length)") &&
  blindsparkDashboard.includes("appendEl(content, 'span', 'svc-state ' + visualState.className, visualState.label)") &&
  blindsparkDashboard.includes("meterBox.className = 'svc-meter-box';") &&
  blindsparkDashboard.includes('Poker preset selected; save to apply') &&
  blindsparkDashboard.includes('/api/manage/services/available') &&
  blindsparkDashboard.includes('/api/manage/services/config') &&
  blindsparkDashboard.includes('refreshServices(true);') &&
  blindsparkDashboard.includes("$('servicesCard').setAttribute('aria-busy', controlsDisabled ? 'true' : 'false');") &&
  blindsparkDashboard.includes("progress.setAttribute('role', 'status');") &&
  blindsparkDashboard.includes("hint.setAttribute('role', 'status');") &&
  umbrelUiControlsTest.includes('umbrel wallet and service controls expose accessible busy/error state') &&
  umbrelUiControlsTest.includes('umbrel service manager shows saved-vs-live service state') &&
  !blindsparkDashboard.includes('fetchServices();') &&
  !blindsparkDashboard.includes('id="servicesList"') &&
  !blindsparkDashboard.includes('meterBox.style.marginTop')
) {
  pass('Umbrel dashboard exposes the flattened service manager with save/restart controls')
} else {
  fail('Umbrel dashboard is missing the flattened service manager controls')
}

if (
  blindsparkDashboard.includes('var svcModelBusy = false;') &&
  blindsparkDashboard.includes("var svcModelMessageText = '';") &&
  blindsparkDashboard.includes('function setSvcModelMessage(message, kind)') &&
  blindsparkDashboard.includes('svcModelMessageText = message ||') &&
  blindsparkDashboard.includes('function setSvcModelBusy(busy)') &&
  blindsparkDashboard.includes("msg.setAttribute('aria-live', 'polite');") &&
  blindsparkDashboard.includes('msg.textContent = svcModelMessageText;') &&
  blindsparkDashboard.includes("add.id = 'svcModelAdd';") &&
  blindsparkDashboard.includes('if (svcModelBusy) return;') &&
  blindsparkDashboard.includes("setSvcModelMessage('Model ID and source required.', 'error');") &&
  blindsparkDashboard.includes('refreshServices(true);') &&
  umbrelUiControlsTest.includes('umbrel AI model add blocks duplicate writes and reports inline status')
) {
  pass('Umbrel AI model add flow shows inline status and blocks duplicate writes')
} else {
  fail('Umbrel AI model add flow can still duplicate writes or hide field-level errors')
}

if (
  blindsparkDashboard.includes('function metricCount(value)') &&
  blindsparkDashboard.includes('function writeClipboard(text, successMessage)') &&
  blindsparkDashboard.includes("toast('Clipboard unavailable')") &&
  blindsparkDashboard.includes("toast('Copy failed')") &&
  blindsparkDashboard.includes("writeClipboard(pubKey, 'Public key copied')") &&
  blindsparkDashboard.includes("writeClipboard(addr, 'Payout destination copied')") &&
  blindsparkDashboard.includes('function clearNode(node)') &&
  blindsparkDashboard.includes('function appendMeterRow(parent, label, value)') &&
  blindsparkDashboard.includes('clearNode(pay)') &&
  blindsparkDashboard.includes('clearNode(box)') &&
  blindsparkDashboard.includes('clearNode(v)') &&
  blindsparkDashboard.includes("appendMeterRow(meter, 'Signed receipts', metricCount(verified.count))") &&
  blindsparkDashboard.includes("var row = appendEl(box, 'div', 'app')") &&
  blindsparkDashboard.includes("var nameEl = appendEl(row, 'span', 'app-name', name)") &&
  blindsparkDashboard.includes('nameEl.title = appKey') &&
  blindsparkDashboard.includes("appendEl(row, 'span', 'app-key', shortKey(idKey))") &&
  blindsparkDashboard.includes("appendEl(content, 'span', 'svc-name', meta.label)") &&
  blindsparkDashboard.includes("appendEl(row, 'span', 'svc-live-status', status)") &&
  blindsparkDashboard.includes("appendModelField(form, 'svcModelId', 'Model ID', 'qvac-small')") &&
  blindsparkDashboard.includes('function handleSvcModelInputKey(event)') &&
  blindsparkDashboard.includes("modelId.addEventListener('keydown', handleSvcModelInputKey);") &&
  blindsparkDashboard.includes("modelSrc.addEventListener('keydown', handleSvcModelInputKey);") &&
  blindsparkDashboard.includes('class="row" id="leaseRow" hidden') &&
  blindsparkDashboard.includes('class="apps-head-actions"') &&
  blindsparkDashboard.includes('class="seed-optional"') &&
  blindsparkDashboard.includes("$('walletClear').hidden = !payoutDestination;") &&
  !blindsparkDashboard.includes(' style=') &&
  !blindsparkDashboard.includes('.style.cssText') &&
  !blindsparkDashboard.includes('onerror=') &&
  !blindsparkDashboard.includes('function appGlyph') &&
  !blindsparkDashboard.includes('function escapeHtml') &&
  !blindsparkDashboard.includes('pay.innerHTML') &&
  !blindsparkDashboard.includes('box.innerHTML') &&
  !blindsparkDashboard.includes('v.innerHTML') &&
  !blindsparkDashboard.includes('content.innerHTML =') &&
  !blindsparkDashboard.includes('row.innerHTML =') &&
  !blindsparkDashboard.includes('form.innerHTML =') &&
  blindsparkDashboard.includes('metricCount(verified.count)') &&
  blindsparkDashboard.includes('metricCount(poker.appends)') &&
  blindsparkDashboard.includes('metricCount(poker.seats)') &&
  umbrelUiControlsTest.includes('umbrel apps list escapes app names and app-key attributes') &&
  umbrelUiControlsTest.includes('umbrel service manager builds service UI without HTML-string metadata injection') &&
  umbrelUiControlsTest.includes('umbrel service manager renders untrusted service metadata as text') &&
  umbrelUiControlsTest.includes('umbrel appliance copy controls report missing or rejected clipboard writes') &&
  umbrelUiControlsTest.includes('umbrel service usage meter normalizes untrusted metric values') &&
  umbrelUiControlsTest.includes('umbrel AI model fields add on Enter without form navigation') &&
  umbrelUiControlsTest.includes('appsList.innerHTMLAssignments') &&
  umbrelUiControlsTest.includes('svcMeterBox.innerHTMLAssignments')
) {
  pass('Umbrel dashboard renders app, service metadata, payout, and usage-meter values through DOM/text paths and handles copy failures')
} else {
  fail('Umbrel dashboard can render untrusted app catalog, service metadata, usage metric values, or copy failures unsafely')
}

if (
  docsDashboard.includes('data-docs-action="copy-code"') &&
  docsDashboard.includes('<button type="button" class="hamburger"') &&
  docsDashboard.includes('function getCodeText(btn)') &&
  docsDashboard.includes('function writeClipboard(text)') &&
  docsDashboard.includes("typeof navigator !== 'undefined'") &&
  docsDashboard.includes("const copied = document.execCommand('copy')") &&
  docsDashboard.includes("err.code = 'clipboard-unavailable'") &&
  docsDashboard.includes("err.code = 'copy-failed'") &&
  docsDashboard.includes('function markCopyFailed(btn, message)') &&
  docsDashboard.includes('function copyCode(btn)') &&
  docsDashboard.includes('event.target.closest(\'[data-docs-action="copy-code"]\')') &&
  docsDashboard.includes('target="_blank" rel="noopener noreferrer"') &&
  !docsDashboard.includes('onclick=') &&
  dashboardDocsUiTest.includes('docs copy buttons avoid inline handlers and protect external tabs') &&
  dashboardDocsUiTest.includes('docs copy handler writes the adjacent code block') &&
  dashboardDocsUiTest.includes('docs copy handler uses legacy fallback and reports fallback failures')
) {
  pass('docs dashboard copy controls avoid inline handlers, protect external tabs, and report copy fallback failures')
} else {
  fail('docs dashboard can regress to inline copy handlers, unsafe new-tab links, or false-success copy fallback')
}

if (
  catalogDashboard.includes('function normalizeCatalogType') &&
  catalogDashboard.includes('function catalogCategories') &&
  catalogDashboard.includes('function renderEmptyState') &&
  catalogDashboard.includes('function showCopyToast') &&
  literalButtonsHaveTypeButton(catalogDashboard) &&
  catalogDashboard.includes("showCopyToast('Clipboard unavailable')") &&
  catalogDashboard.includes("showCopyToast('Copy failed')") &&
  catalogDashboard.includes('const gatewayUrl = key ? `/v1/hyper/$' + '{encodeURIComponent(key)}/` : \'#\'') &&
  catalogDashboard.includes('for (const item of pageItems) grid.appendChild(renderCard(item))') &&
  catalogDashboard.includes('appendEl(header, \'div\', \'card-title\', item.name || \'Unnamed\')') &&
  catalogDashboard.includes('appendEl(card, \'div\', \'card-description\', item.description || \'No description available.\')') &&
  catalogDashboard.includes('browse.rel = \'noopener noreferrer\'') &&
  catalogDashboard.includes('copy.addEventListener(\'click\', () => copyToClipboard(key))') &&
  catalogDashboard.includes('...catalogCategories(item.categories), item.author') &&
  !catalogDashboard.includes('grid.innerHTML') &&
  !catalogDashboard.includes('catalog-grid\').innerHTML') &&
  !catalogDashboard.includes('onclick="copyToClipboard') &&
  dashboardCatalogUiTest.includes('catalog literal controls avoid submit-default buttons') &&
  dashboardCatalogUiTest.includes('catalog cards render untrusted metadata as DOM text and avoid inline copy handlers') &&
  dashboardCatalogUiTest.includes('catalog grid uses DOM rendering and tolerates malformed category metadata') &&
  dashboardCatalogUiTest.includes('catalog copy controls tolerate missing or rejected clipboard writes')
) {
  pass('catalog dashboard renders untrusted metadata through DOM/text paths, avoids submit-default/inline copy handlers, and handles clipboard failures')
} else {
  fail('catalog dashboard can render untrusted catalog metadata, submit-default controls, inline copy handlers, or clipboard failures unsafely')
}

if (
  fullDashboard.includes('function bindRegistryActionTable') &&
  fullDashboard.includes('function appendRegistryButton(parent, action, appKey, className, label)') &&
  fullDashboard.includes('function renderDevNode(parent, appKey)') &&
  fullDashboard.includes('function renderAppNameNode(parent, appKey, appId)') &&
  fullDashboard.includes('clearNode(tbody)') &&
  fullDashboard.includes("renderAppNameNode(appendEl(row, 'td'), appKey, app.appId)") &&
  fullDashboard.includes("renderDevNode(appendEl(row, 'td'), appKey)") &&
  fullDashboard.includes("appendEl(row, 'td', '', truncateKey(appKey))") &&
  fullDashboard.includes("appendRegistryButton(actions, 'unseed', appKey, 'btn btn-red', 'UNSEED')") &&
  fullDashboard.includes("appendRegistryButton(actions, 'approve', appKey, 'btn btn-green', 'APPROVE')") &&
  fullDashboard.includes("appendRegistryButton(actions, 'reject', appKey, 'btn btn-red', 'REJECT')") &&
  fullDashboard.includes("appendEl(row, 'td', '', truncateKey(publisher))") &&
  fullDashboard.includes("appendEl(row, 'td', '', geoPreference)") &&
  fullDashboard.includes('var destSaveBusy = false;') &&
  fullDashboard.includes('if (destSaveBusy) return;') &&
  fullDashboard.includes("fetchWithTimeout('/api/subsidy/destination'") &&
  fullDashboard.includes("destDialog.setAttribute('aria-busy', 'true');") &&
  fullDashboard.includes("destDialog.setAttribute('aria-busy', 'false');") &&
  fullDashboard.includes('function postJson(path, body)') &&
  fullDashboard.includes('return fetchWithTimeout(path, {') &&
  fullDashboard.includes("postJson('/registry/auto-accept', { enabled: enabled })") &&
  fullDashboard.includes('autoAcceptToggle.disabled = true;') &&
  fullDashboard.includes('autoAcceptToggle.checked = previous;') &&
  fullDashboard.includes('autoAcceptToggle.disabled = false;') &&
  fullDashboard.includes('function setRegistryActionBusy(btn, busy)') &&
  fullDashboard.includes('function runRegistryAction(btn, path, body, onSuccess, label)') &&
  fullDashboard.includes('if (btn && btn.disabled) return Promise.resolve();') &&
  fullDashboard.includes('setRegistryActionBusy(btn, true);') &&
  fullDashboard.includes("btn.setAttribute('aria-busy', busy ? 'true' : 'false');") &&
  fullDashboard.includes('return postJson(path, body)') &&
  fullDashboard.includes("runRegistryAction(btn, '/unseed'") &&
  fullDashboard.includes("runRegistryAction(btn, '/registry/approve'") &&
  fullDashboard.includes("runRegistryAction(btn, '/registry/reject'") &&
  fullDashboard.includes('if (btn.disabled) return;') &&
  fullDashboard.includes('unseedApp(appKey, btn);') &&
  fullDashboard.includes('approveRequest(appKey, btn);') &&
  fullDashboard.includes('rejectRequest(appKey, btn);') &&
  !fullDashboard.includes('data-registry-action="unseed" data-app-key="\' + keyAttr + \'"') &&
  !fullDashboard.includes('data-registry-action="approve" data-app-key="\' + keyAttr + \'"') &&
  !fullDashboard.includes('data-registry-action="reject" data-app-key="\' + keyAttr + \'"') &&
  !fullDashboard.includes("fetch('/registry/auto-accept'") &&
  !fullDashboard.includes("fetch('/unseed'") &&
  !fullDashboard.includes("fetch('/registry/approve'") &&
  !fullDashboard.includes("fetch('/registry/reject'") &&
  !fullDashboard.includes('onclick="unseedApp') &&
  !fullDashboard.includes('onclick="approveRequest') &&
  !fullDashboard.includes('onclick="rejectRequest') &&
  dashboardIndexUiTest.includes('operator registry tables escape untrusted app keys and avoid inline action handlers') &&
  dashboardIndexUiTest.includes('operator registry and payout writes are timeout bounded and block duplicate submits') &&
  dashboardIndexUiTest.includes('renderRegistryDomWith') &&
  dashboardIndexUiTest.includes('seeded.assignments') &&
  dashboardIndexUiTest.includes('pending.assignments')
) {
  pass('operator dashboard registry tables render untrusted fields safely through DOM text paths and avoid inline action handlers')
} else {
  fail('operator dashboard registry tables can render untrusted registry fields or inline action handlers unsafely')
}

if (
  fullDashboard.includes('function safeHttpUrl') &&
  fullDashboard.includes('function renderHeaderMeta') &&
  fullDashboard.includes('function renderHeaderCopyMessage') &&
  fullDashboard.includes('function renderHeaderCopied') &&
  fullDashboard.includes('function copyHeaderPubkey') &&
  fullDashboard.includes('function renderPeersList') &&
  fullDashboard.includes('function renderAppsTable()') &&
  fullDashboard.includes('function renderDevNode(parent, appKey)') &&
  fullDashboard.includes('function renderAppNameNode(parent, appKey, appId)') &&
  fullDashboard.includes('type="button" class="pk-chip" id="headerMeta"') &&
  fullDashboard.includes("renderHeaderCopyMessage(chip, 'Clipboard unavailable')") &&
  fullDashboard.includes("renderHeaderCopyMessage(chip, 'Copy failed')") &&
  fullDashboard.includes("avatar.referrerPolicy = 'no-referrer'") &&
  fullDashboard.includes("appendEl(chip, 'span', '', truncateKey(pk) + (region ? ' · ' + region : ''))") &&
  fullDashboard.includes("appendEl(pl, 'div', 'peer-item', truncateKey(String(key), 16))") &&
  fullDashboard.includes("renderAppNameNode(appendEl(row, 'td'), appKey, app.appId)") &&
  fullDashboard.includes("renderDevNode(appendEl(row, 'td'), appKey)") &&
  fullDashboard.includes("appendEl(row, 'td', '', hasStartedAt ? formatTime(app.started) : '--')") &&
  fullDashboard.includes('renderPeersList(document.getElementById(\'peersList\'), peers)') &&
  fullDashboard.includes('renderAppsTable()') &&
  fullDashboard.includes('copyHeaderPubkey(this)') &&
  !fullDashboard.includes('innerHTML') &&
  !fullDashboard.includes('chip.innerHTML') &&
  !fullDashboard.includes('pl.innerHTML') &&
  !fullDashboard.includes('onerror=') &&
  dashboardIndexUiTest.includes('operator apps table and developer metadata render untrusted values as DOM text') &&
  dashboardIndexUiTest.includes('apps.assignments') &&
  dashboardIndexUiTest.includes('operator header and peer list render untrusted overview fields as text') &&
  dashboardIndexUiTest.includes('operator header public-key copy reports missing or rejected clipboard writes')
) {
  pass('operator dashboard renders header, peers, app rows, and developer metadata through DOM text paths and handles copy failures')
} else {
  fail('operator dashboard can render header, peer, app-key, developer metadata, or copy failures unsafely')
}

if (
  networkDashboard.includes('function safeHttpUrl') &&
  networkDashboard.includes('function clearNode') &&
  networkDashboard.includes('function makeEl') &&
  networkDashboard.includes('function appendEl') &&
  networkDashboard.includes('function writeClipboard') &&
  networkDashboard.includes("showToast('Clipboard unavailable')") &&
  networkDashboard.includes("showToast('Copy failed')") &&
  networkDashboard.includes('function bindRelayGridActions') &&
  networkDashboard.includes('function metricCount(value)') &&
  networkDashboard.includes("pubkey.dataset.networkAction = 'copy-pubkey'") &&
  networkDashboard.includes("connect.dataset.networkAction = 'connect'") &&
  networkDashboard.includes("dashboard.rel = 'noopener noreferrer'") &&
  networkDashboard.includes("api.rel = 'noopener noreferrer'") &&
  networkDashboard.includes('clearNode(grid)') &&
  networkDashboard.includes('grid.appendChild(renderRelayCard(result))') &&
  networkDashboard.includes('metricCount(data.connections)') &&
  networkDashboard.includes('metricCount(data.seededApps)') &&
  networkDashboard.includes('metricCount(data.relay.totalCircuitsServed)') &&
  networkDashboard.includes('totalConns += metricCount(r.connections)') &&
  !networkDashboard.includes('grid.innerHTML') &&
  !networkDashboard.includes('onclick=') &&
  dashboardNetworkUiTest.includes('network relay cards render untrusted relay data as DOM text and avoid inline handlers') &&
  dashboardNetworkUiTest.includes('network relay cards disable unsafe relay links') &&
  dashboardNetworkUiTest.includes('network copy controls tolerate missing or rejected clipboard writes')
) {
  pass('network dashboard relay cards render untrusted fields as DOM text, validate links, avoid inline handlers, and handle clipboard failures')
} else {
  fail('network dashboard relay cards can render untrusted relay fields, unsafe links, inline handlers, or clipboard failures unsafely')
}

if (
  leaderboardDashboard.includes('function normalizeRelay') &&
  leaderboardDashboard.includes('function bindLeaderboardActions') &&
  leaderboardDashboard.includes('function clearNode(node)') &&
  leaderboardDashboard.includes('function makeEl(tag, className, text)') &&
  leaderboardDashboard.includes('function appendEl(parent, tag, className, text)') &&
  leaderboardDashboard.includes('function writeClipboard(text, successMessage)') &&
  leaderboardDashboard.includes("showToast('Clipboard unavailable')") &&
  leaderboardDashboard.includes("showToast('Copy failed')") &&
  leaderboardDashboard.includes('function renderRelayRow(r)') &&
  leaderboardDashboard.includes('function metricNumber(value)') &&
  leaderboardDashboard.includes('function clampPercent(value)') &&
  leaderboardDashboard.includes('copy.dataset.copyPubkey = pubkey') &&
  leaderboardDashboard.includes("appendEl(pubWrap, 'span', 'pubkey', truncatePubkey(pubkey))") &&
  leaderboardDashboard.includes('tbody.appendChild(renderRelayRow(relays[j]))') &&
  leaderboardDashboard.includes("th.querySelector('.sort-arrow').textContent") &&
  leaderboardDashboard.includes('relays = list.map(normalizeRelay)') &&
  !leaderboardDashboard.includes('tbody.innerHTML') &&
  !leaderboardDashboard.includes("'.innerHTML = '&#9650;'") &&
  !leaderboardDashboard.includes('onclick=') &&
  dashboardLeaderboardUiTest.includes('leaderboard rows escape relay metadata and avoid inline copy handlers') &&
  dashboardLeaderboardUiTest.includes('leaderboard copy control tolerates missing or rejected clipboard writes') &&
  dashboardLeaderboardUiTest.includes('innerHTMLAssignments') &&
  dashboardLeaderboardUiTest.includes('leaderboard normalization clamps percentages and preserves safe percent strings')
) {
  pass('leaderboard dashboard rows render untrusted relay fields as DOM text, avoid inline copy handlers, and handle clipboard failures')
} else {
  fail('leaderboard dashboard rows can render untrusted relay fields, inline copy handlers, or clipboard failures unsafely')
}

if (
  paymentsDashboard.includes('function clearNode(node)') &&
  paymentsDashboard.includes('function makeEl(tag, className, text)') &&
  paymentsDashboard.includes('function appendEl(parent, tag, className, text)') &&
  paymentsDashboard.includes('function appendCell(row, text, className)') &&
  paymentsDashboard.includes('function metricNumber(value)') &&
  paymentsDashboard.includes('function metricCount(value)') &&
  paymentsDashboard.includes('function clampPercent(value)') &&
  paymentsDashboard.includes('function formatUsd(value)') &&
  paymentsDashboard.includes('function renderRateCard(rateCard, rates)') &&
  paymentsDashboard.includes('function renderPricingComparison(tbody, compare)') &&
  paymentsDashboard.includes("appendEl(meta, 'div', 'rate-name', route)") &&
  paymentsDashboard.includes("appendEl(meta, 'div', 'rate-desc', rate.description || '')") &&
  paymentsDashboard.includes("appendCell(savingsRow, ai.savingsVsClaude || '', 'savings')") &&
  paymentsDashboard.includes("renderRateCard(document.getElementById('rateCard'), rates)") &&
  paymentsDashboard.includes("renderPricingComparison(document.getElementById('compareBody'), compare)") &&
  !paymentsDashboard.includes("document.getElementById('rateCard').innerHTML") &&
  !paymentsDashboard.includes('tbody.innerHTML') &&
  paymentsDashboard.includes('var heldPct = clampPercent(acc.heldPercentage)') &&
  paymentsDashboard.includes('metricCount(stats.credits.totalWallets)') &&
  dashboardPaymentsUiTest.includes('payments pricing tables render untrusted API strings as DOM text and normalize malformed prices') &&
  dashboardPaymentsUiTest.includes('payments pricing renderer avoids rate card and comparison innerHTML') &&
  dashboardPaymentsUiTest.includes('innerHTMLAssignments') &&
  dashboardPaymentsUiTest.includes('payments overview clamps percentages and normalizes counts')
) {
  pass('payments dashboard renders untrusted pricing strings as DOM text and normalizes payment metrics')
} else {
  fail('payments dashboard can render untrusted pricing or malformed payment metrics unsafely')
}

if (
  [fullDashboard, networkDashboard, paymentsDashboard, leaderboardDashboard, catalogDashboard].every(html =>
    html.includes('document.hidden === true') &&
    html.includes("document.addEventListener('visibilitychange'") &&
    html.includes('REQUEST_TIMEOUT_MS = 10000') &&
    html.includes('fetchWithTimeout') &&
    html.includes('AbortController') &&
    html.includes('clearTimeout(timeout)')
  ) &&
  fullDashboard.includes('function refreshData(force)') &&
  fullDashboard.includes('function refreshPending(force)') &&
  fullDashboard.includes('function fetchWithTimeout(path, opts)') &&
  fullDashboard.includes("fetchWithTimeout('/api/overview')") &&
  fullDashboard.includes("fetchWithTimeout('/api/history?minutes=60')") &&
  fullDashboard.includes("fetchWithTimeout('/api/apps')") &&
  fullDashboard.includes("fetchWithTimeout('/catalog.json')") &&
  fullDashboard.includes('var dataRefreshBusy = false;') &&
  fullDashboard.includes('var pendingRefreshBusy = false;') &&
  fullDashboard.includes('if (dataRefreshBusy) return;') &&
  fullDashboard.includes('fetchData().finally(function()') &&
  fullDashboard.includes('if (pendingRefreshBusy) return;') &&
  fullDashboard.includes('if (autoAcceptToggle.checked) return;') &&
  fullDashboard.includes("return fetchWithTimeout('/api/registry/pending')") &&
  fullDashboard.includes('fetchPending().finally(function()') &&
  fullDashboard.includes('setInterval(function() { refreshData(false); }, ms);') &&
  fullDashboard.includes('setInterval(function() { refreshPending(false); }, 10000);') &&
  fullDashboard.includes('if (document.hidden !== true) setTimeout(connectWS, 3000);') &&
  !fullDashboard.includes('setInterval(fetchData, ms);') &&
  !fullDashboard.includes('setInterval(function() { if (!autoAcceptToggle.checked) fetchPending(); }, 10000);') &&
  networkDashboard.includes('function refreshNetwork(force)') &&
  networkDashboard.includes('function fetchWithTimeout(path, opts)') &&
  networkDashboard.includes("fetchWithTimeout('/api/network?detailed=1'") &&
  networkDashboard.includes("fetchWithTimeout('/api/network')") &&
  !networkDashboard.includes('AbortSignal.timeout') &&
  networkDashboard.includes('var networkRefreshBusy = false;') &&
  networkDashboard.includes('if (networkRefreshBusy) return;') &&
  networkDashboard.includes('refresh().finally(function()') &&
  networkDashboard.includes('setInterval(function() { refreshNetwork(false); }, ms);') &&
  !networkDashboard.includes('setInterval(refresh, ms);') &&
  paymentsDashboard.includes('function refreshOverview(force)') &&
  paymentsDashboard.includes('function refreshWallets(force)') &&
  paymentsDashboard.includes('function fetchWithTimeout(path, opts)') &&
  paymentsDashboard.includes("fetchWithTimeout('/api/v1/credits/pricing')") &&
  paymentsDashboard.includes("fetchWithTimeout('/api/v1/credits/pricing/compare')") &&
  paymentsDashboard.includes("fetchWithTimeout('/api/v1/credits/stats'") &&
  paymentsDashboard.includes("fetchWithTimeout('/api/overview')") &&
  paymentsDashboard.includes('var overviewRefreshBusy = false;') &&
  paymentsDashboard.includes('var walletsRefreshBusy = false;') &&
  paymentsDashboard.includes('if (overviewRefreshBusy) return;') &&
  paymentsDashboard.includes('if (walletsRefreshBusy) return;') &&
  paymentsDashboard.includes('fetchOverview().finally(function()') &&
  paymentsDashboard.includes('fetchWallets().finally(function()') &&
  paymentsDashboard.includes('setInterval(function() { refreshOverview(false); }, 10000);') &&
  paymentsDashboard.includes('setInterval(function() { refreshWallets(false); }, 30000);') &&
  !paymentsDashboard.includes('setInterval(fetchOverview, 10000);') &&
  !paymentsDashboard.includes('setInterval(fetchWallets, 30000);') &&
  leaderboardDashboard.includes('function refreshLeaderboardState(force)') &&
  leaderboardDashboard.includes('function fetchWithTimeout(path, opts)') &&
  leaderboardDashboard.includes('var leaderboardRefreshBusy = false;') &&
  leaderboardDashboard.includes('if (leaderboardRefreshBusy) return;') &&
  leaderboardDashboard.includes("return fetchWithTimeout('/api/reputation')") &&
  leaderboardDashboard.includes("return fetchWithTimeout('/api/overview')") &&
  leaderboardDashboard.includes('Promise.all([fetchLeaderboard(), fetchMyPubkey()]).finally(function()') &&
  leaderboardDashboard.includes('refreshLeaderboardState(false);') &&
  leaderboardDashboard.includes('if (document.hidden !== true) setTimeout(connectWS, 5000);') &&
  catalogDashboard.includes('function refreshCatalog (force)') &&
  catalogDashboard.includes('function fetchWithTimeout (path, opts = {})') &&
  catalogDashboard.includes("fetchWithTimeout('/catalog.json?pageSize=200'") &&
  catalogDashboard.includes('let catalogRefreshBusy = false') &&
  catalogDashboard.includes('if (catalogRefreshBusy) return') &&
  catalogDashboard.includes('loadCatalog().finally(() =>') &&
  catalogDashboard.includes('setInterval(() => { refreshCatalog(false) }, 30_000)') &&
  !catalogDashboard.includes('setInterval(loadCatalog, 30_000)') &&
  dashboardPollingVisibilityTest.includes('operator dashboards pause automatic polling while hidden') &&
  dashboardPollingVisibilityTest.includes('operator dashboards avoid overlapping automatic refreshes') &&
  dashboardPollingVisibilityTest.includes('operator dashboards bound automatic HTTP refresh latency') &&
  dashboardPollingVisibilityTest.includes('setInterval(fetchData, ms);') &&
  dashboardPollingVisibilityTest.includes('setInterval(fetchOverview, 10000);') &&
  dashboardPollingVisibilityTest.includes('setInterval(loadCatalog, 30_000)')
) {
  pass('operator dashboards pause hidden-tab polling and avoid overlapping automatic refreshes')
} else {
  fail('operator dashboards can still run hidden-tab polling, reconnect loops, or overlapping automatic refreshes')
}

if (
  calculatorDashboard.includes('data-calculator-preset="hobby"') &&
  calculatorDashboard.includes('data-slider-display="appsVal"') &&
  calculatorDashboard.includes('data-calculator-recalculate') &&
  calculatorDashboard.includes('function bindCalculatorControls()') &&
  calculatorDashboard.includes("document.querySelectorAll('[data-calculator-preset]')") &&
  calculatorDashboard.includes("document.querySelectorAll('[data-slider-display]')") &&
  calculatorDashboard.includes('function renderBreakdown(breakdown, dailySats, btcPrice)') &&
  calculatorDashboard.includes('function pctWidth(value)') &&
  calculatorDashboard.includes("appendEl(left, 'div', 'breakdown-name', b.name)") &&
  calculatorDashboard.includes('fill.style.width = pctWidth(pct)') &&
  !calculatorDashboard.includes('onclick=') &&
  !calculatorDashboard.includes('oninput=') &&
  !calculatorDashboard.includes('innerHTML') &&
  dashboardCalculatorUiTest.includes('calculator controls avoid inline handlers and use delegated data hooks') &&
  dashboardCalculatorUiTest.includes('calculator delegated control binding preserves preset, slider, and recalculate behavior') &&
  dashboardCalculatorUiTest.includes('calculator breakdown renders untrusted labels as text and clamps widths')
) {
  pass('calculator dashboard uses delegated controls and renders breakdown rows as text')
} else {
  fail('calculator dashboard can still regress to inline handlers or HTML-string breakdown rendering')
}

if (
  blindsparkDashboard.includes('@media(max-width:440px)') &&
  blindsparkDashboard.includes('.hdr{align-items:flex-start;flex-wrap:wrap}') &&
  blindsparkDashboard.includes('.hdr-right{width:100%;margin-left:0;justify-content:space-between}') &&
  blindsparkDashboard.includes('.svc-btn,.row-btn,.setup-link,.status,.pk,.addr{min-height:34px}') &&
  blindsparkDashboard.includes('.svc-model-field input,.dlg-field input{min-height:38px}') &&
  blindsparkDashboard.includes('dialog{width:calc(100vw - 2rem);max-width:calc(100vw - 2rem)}') &&
  umbrelUiControlsTest.includes('umbrel dashboard mobile controls avoid cramped appliance layout')
) {
  pass('Umbrel dashboard mobile breakpoint avoids cramped header, dialog, model, and action controls')
} else {
  fail('Umbrel dashboard mobile breakpoint can still render cramped appliance controls')
}

if (
  blindsparkDashboard.includes('var svcDraftDirty = false;') &&
  blindsparkDashboard.includes('svcDraftDirty = true;') &&
  blindsparkDashboard.includes('svcDraftDirty = false;') &&
  blindsparkDashboard.includes('var REQUEST_TIMEOUT_MS = 10000;') &&
  blindsparkDashboard.includes('function fetchWithTimeout(path, opts)') &&
  blindsparkDashboard.includes("typeof AbortController === 'function'") &&
  blindsparkDashboard.includes('controller.abort();') &&
  blindsparkDashboard.includes('if (timeout) clearTimeout(timeout);') &&
  blindsparkDashboard.includes("fetchWithTimeout(path, { headers: { 'Accept': 'application/json' } })") &&
  blindsparkDashboard.includes("fetchWithTimeout('/api/subsidy/destination'") &&
  blindsparkDashboard.includes("fetchWithTimeout('/seed'") &&
  blindsparkDashboard.includes("fetchWithTimeout('/api/lease/config'") &&
  blindsparkDashboard.includes('return fetchWithTimeout(path, {') &&
  blindsparkDashboard.includes('function refreshServices(force)') &&
  blindsparkDashboard.includes('if (svcDraftDirty && force !== true) return;') &&
  blindsparkDashboard.includes('var overviewRefreshBusy = false;') &&
  blindsparkDashboard.includes('var wizardRefreshBusy = false;') &&
  blindsparkDashboard.includes('var servicesRefreshBusy = false;') &&
  blindsparkDashboard.includes('var servicesRefreshPendingForce = false;') &&
  blindsparkDashboard.includes('var leaseRefreshBusy = false;') &&
  blindsparkDashboard.includes('function canPoll(force, busy)') &&
  blindsparkDashboard.includes('document.hidden === true') &&
  blindsparkDashboard.includes('function fetchLease(force)') &&
  blindsparkDashboard.includes('if (!canPoll(force, leaseRefreshBusy)) return Promise.resolve(null);') &&
  blindsparkDashboard.includes('fetchLease(force);') &&
  blindsparkDashboard.includes('setInterval(function(){ fetchLease(false); }, 30000);') &&
  !blindsparkDashboard.includes("fetch('/seed'") &&
  !blindsparkDashboard.includes("fetch('/api/lease/config'") &&
  !blindsparkDashboard.includes('setInterval(function(){ fetchLease(); }, 30000);') &&
  blindsparkDashboard.includes('if (force === true) servicesRefreshPendingForce = true;') &&
  blindsparkDashboard.includes('refreshVisible(true);') &&
  blindsparkDashboard.includes("document.addEventListener('visibilitychange'") &&
  !blindsparkDashboard.includes('setInterval(refresh, 5000);') &&
  umbrelUiControlsTest.includes('umbrel dashboard polling avoids hidden-tab and overlapping refresh churn') &&
  umbrelUiControlsTest.includes('umbrel seed and lease writes use app-proxy-aware fetch helpers')
) {
  pass('Umbrel service auto refresh preserves drafts and keeps appliance API polling/writes bounded')
} else {
  fail('Umbrel service auto refresh can clobber drafts or leave appliance API polling/writes unbounded')
}

if (
  blindsparkDashboard.includes('var svcRestartPending = false;') &&
  blindsparkDashboard.includes('var svcConfigBusy = false;') &&
  blindsparkDashboard.includes('var svcRestartStartedAt = 0;') &&
  blindsparkDashboard.includes('function setSvcConfigBusy(busy)') &&
  blindsparkDashboard.includes('function beginSvcRestartWatch(expected)') &&
  blindsparkDashboard.includes('function checkSvcRestart()') &&
  blindsparkDashboard.includes('function svcRestartReady(avail)') &&
  blindsparkDashboard.includes('var controlsDisabled = svcRestartPending || svcConfigBusy;') &&
  blindsparkDashboard.includes('if (svcRestartPending || svcConfigBusy) return;') &&
  blindsparkDashboard.includes('if (svcDraftDirty){') &&
  blindsparkDashboard.includes('toast(\'Save selection before restart\');') &&
  blindsparkDashboard.includes('Saving service selection...') &&
  blindsparkDashboard.includes('Unsaved changes - save selection before restarting.') &&
  blindsparkDashboard.includes('Date.now() - svcRestartStartedAt < 2500') &&
  blindsparkDashboard.includes('var managedActive = active.filter') &&
  blindsparkDashboard.includes('if (!expected.length) return managedActive.length === 0;') &&
  blindsparkDashboard.includes('if (expected.indexOf(managedActive[j]) === -1) return false;') &&
  blindsparkDashboard.includes("$('svcStatus').textContent = svcConfigBusy ? 'Saving'") &&
  blindsparkDashboard.includes('restart.disabled = controlsDisabled;') &&
  blindsparkDashboard.includes('save.disabled = controlsDisabled;') &&
  blindsparkDashboard.includes('cb.disabled = controlsDisabled;') &&
  blindsparkDashboard.includes('Services are running') &&
  blindsparkDashboard.includes('Restart still pending') &&
  umbrelUiControlsTest.includes('umbrel service save disables duplicate in-flight config writes') &&
  umbrelUiControlsTest.includes('umbrel service restart refuses unsaved service drafts')
) {
  pass('Umbrel service restart controls show pending state and poll until selected providers are running')
} else {
  fail('Umbrel service restart controls can still look like a toast-only no-op')
}

if (
  literalButtonsHaveTypeButton(blindsparkDashboard) &&
  literalButtonsHaveTypeButton(wizardDashboard) &&
  blindsparkDashboard.includes("$('walletSave').addEventListener('click', function(){ saveWallet(false); });") &&
  blindsparkDashboard.includes('function handleWalletInputKey(event)') &&
  blindsparkDashboard.includes("$('walletInput').addEventListener('keydown', handleWalletInputKey);") &&
  blindsparkDashboard.includes('id="walletHelp"') &&
  blindsparkDashboard.includes('aria-describedby="walletHelp walletError"') &&
  blindsparkDashboard.includes('id="walletError" role="status" aria-live="polite" aria-atomic="true"') &&
  blindsparkDashboard.includes("$('walletSave').textContent = busy ? 'Saving...' : 'Save';") &&
  blindsparkDashboard.includes("$('walletDialog').setAttribute('aria-busy', busy ? 'true' : 'false');") &&
  blindsparkDashboard.includes("event.key !== 'Enter' || event.isComposing") &&
  blindsparkDashboard.includes("if ($('walletSave').disabled) return;") &&
  wizardDashboard.includes("await api('/api/wizard/payout', { method: 'POST', body: { address } })") &&
  wizardDashboard.includes('const REQUEST_TIMEOUT_MS = 10000') &&
  wizardDashboard.includes('async function fetchWithTimeout (path, opts = {})') &&
  wizardDashboard.includes("typeof AbortController === 'function'") &&
  wizardDashboard.includes('timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)') &&
  wizardDashboard.includes('const res = await fetchWithTimeout(path, {') &&
  wizardDashboard.includes('data-wizard-action="goto" data-step-target="relay_name"') &&
  wizardDashboard.includes('data-wizard-action="payout"') &&
  wizardDashboard.includes('data-wizard-action="accept-mode"') &&
  wizardDashboard.includes('href="dashboard" data-wizard-action="dashboard"') &&
  wizardDashboard.includes('document.querySelectorAll(\'[data-wizard-action="dashboard"][href]\').forEach(el => {') &&
  wizardDashboard.includes("el.setAttribute('href', appPath('/dashboard'))") &&
  wizardDashboard.includes('<h1 class="center-text">You\'re online.</h1>') &&
  wizardDashboard.includes('<p class="complete-note center-text">') &&
  wizardDashboard.includes('<div class="actions complete-actions">') &&
  wizardDashboard.includes("const el = event.target.closest('[data-wizard-action]')") &&
  wizardDashboard.includes('id="wizard-status" role="status" aria-live="polite"') &&
  wizardDashboard.includes('let wizardActionBusy = false') &&
  wizardDashboard.includes('function setWizardStatus (message, kind)') &&
  wizardDashboard.includes('function setWizardActionBusy (busy, action)') &&
  wizardDashboard.includes("if (wizardActionBusy && action !== 'select-mode') return") &&
  wizardDashboard.includes('setWizardActionBusy(true, action)') &&
  wizardDashboard.includes('.finally(() => { setWizardActionBusy(false, action) })') &&
  wizardDashboard.includes('function renderLoadError') &&
  wizardDashboard.includes('function setBusy (btnId, busy)') &&
  wizardDashboard.includes("spinner.className = 'loading'") &&
  wizardDashboard.includes("btn.replaceChildren(spinner, document.createTextNode('Working...'))") &&
  wizardDashboard.includes('card.replaceChildren(title, body, help)') &&
  !wizardDashboard.includes('onclick=') &&
  !wizardDashboard.includes('href="/dashboard"') &&
  !wizardDashboard.includes(' style=') &&
  !wizardDashboard.includes('innerHTML') &&
  dashboardWizardUiTest.includes('wizard controls use delegated actions instead of inline handlers') &&
  dashboardWizardUiTest.includes('wizard delegated action router preserves setup behavior') &&
  dashboardWizardUiTest.includes('wizard delegated action router blocks duplicate pending setup writes') &&
  dashboardWizardUiTest.includes('wizard busy state renders spinner without assigning HTML') &&
  dashboardWizardUiTest.includes('wizard API helper bounds setup requests and clears timeout handles') &&
  dashboardWizardUiTest.includes('wizard load errors render untrusted messages as text') &&
  umbrelUiControlsTest.includes('umbrel wallet destination saves on Enter without form navigation') &&
  umbrelUiControlsTest.includes("walletDialog.attributes['aria-busy']")
) {
  pass('Umbrel setup and wallet controls avoid submit-default refresh regressions, duplicate wizard writes, unbounded wizard requests, inline handlers, and wizard HTML assignment')
} else {
  fail('Umbrel setup or wallet controls can still regress to submit-default refresh/no-op behavior, duplicate wizard writes, unbounded wizard requests, or inline wizard handlers')
}

if (
  relayApi.includes("import { runWizardAction } from './api-wizard-actions.js'") &&
  relayApi.includes('const result = await runWizardAction({') &&
  relayApi.includes('applyConfig: this.node._applyWizardConfig ? cfg => this.node._applyWizardConfig(cfg) : null') &&
  relayApi.includes('if (result.kind === \'apply-config\')') &&
  relayApi.includes("if (result.kind === 'config-persist') return this._configPersistErrorResponse(res)") &&
  relayApi.includes("if (result.kind === 'wizard-persist') return this._wizardPersistErrorResponse(res, result.error)") &&
  relayApiWizardActions.includes('export async function runWizardAction') &&
  relayApiWizardActions.includes('case \'complete\'') &&
  relayApiWizardActions.includes('restoreRuntime()') &&
  relayApiWizardActions.includes('await persistConfigRollback({ persistConfig, emit })') &&
  relayApiWizardActions.includes("return { ok: false, kind: 'apply-config', error: err }") &&
  relayApiWizardActions.includes("return { ok: false, kind: 'config-persist', error: err }") &&
  relayApiWizardActions.includes("return { ok: false, kind: 'wizard-persist', error: err }") &&
  apiWizardActionsTest.includes('api wizard actions: step actions mutate and save wizard state') &&
  apiWizardActionsTest.includes('api wizard actions: apply-config failure restores wizard and config') &&
  apiWizardActionsTest.includes('api wizard actions: config persistence failure restores wizard and config') &&
  apiWizardActionsTest.includes('api wizard actions: wizard save failure after config persist rolls back config') &&
  dashboardWizardUiTest.includes('wizard delegated action router preserves setup behavior') &&
  umbrelUiControlsTest.includes('umbrel wizard setup actions post to the server instead of refreshing')
) {
  pass('Umbrel setup wizard action flow is extracted with config and wizard rollback coverage')
} else {
  fail('Umbrel setup wizard action flow can drift from route/UI behavior or rollback coverage')
}

if (
  relayApi.includes('} from \'./api-subsidy.js\'') &&
  relayApi.includes('buildSubsidyStatusPayload({') &&
  relayApi.includes('buildSubsidyClaimPayload({ subsidyAccrual: this.node.subsidyAccrual })') &&
  relayApi.includes('const result = await updateSubsidyDestination({') &&
  relayApi.includes('persistConfig: () => this._persistConfig()') &&
  relayApiSubsidy.includes('export function buildSubsidyStatusPayload') &&
  relayApiSubsidy.includes('export function buildSubsidyClaimPayload') &&
  relayApiSubsidy.includes("formatErr('UNSUPPORTED', 'subsidy claim export unavailable')") &&
  relayApiSubsidy.includes('export function parseSubsidyDestinationUpdate') &&
  relayApiSubsidy.includes('export async function updateSubsidyDestination') &&
  relayApiSubsidy.includes('destination (string or null) required') &&
  relayApiSubsidy.includes('await saveWizardRollback(wizard, wizardSaved, emit)') &&
  relayApiSubsidy.includes("emitRollbackError(emit, 'config-rollback-error', rollbackErr)") &&
  apiSubsidyTest.includes('api subsidy: status payload is shaped for disabled and enabled accrual') &&
  apiSubsidyTest.includes('api subsidy: claim payload reports disabled and unavailable exporters without throwing') &&
  apiSubsidyTest.includes('api subsidy: destination parser requires string or null and normalizes rails') &&
  apiSubsidyTest.includes('api subsidy: config persist failures restore runtime state and wizard file') &&
  apiSubsidyTest.includes('api subsidy: live accrual failures restore persisted config and emit rollback drift') &&
  apiAuthTest.includes('api-auth: wizard and wallet auth failures are counted like management routes') &&
  apiAuthTest.includes('api-auth: subsidy status and claim routes are auth-gated and shaped') &&
  umbrelUiControlsTest.includes('umbrel wallet save posts through app proxy without navigation')
) {
  pass('Umbrel wallet payout reads and updates are extracted with validation, rollback, and UI route coverage')
} else {
  fail('Umbrel wallet payout read/update flow can drift from route/UI behavior or rollback coverage')
}

if (
  relayApi.includes('} from \'./api-lease.js\'') &&
  relayApi.includes('buildLeaseStatusPayload({') &&
  relayApi.includes('const result = await runLeaseConfigAction({') &&
  relayApiLease.includes('export function buildLeaseStatusPayload') &&
  relayApiLease.includes('export function parseLeaseRateUpdate') &&
  relayApiLease.includes('export async function runLeaseConfigAction') &&
  relayApiLease.includes('sanitizeLeaseSummary') &&
  relayApiLease.includes("formatErr('PERSIST_FAILED', PERSIST_FAILED)") &&
  relayApiLease.includes("const RATE_MAX_PREFIX = 'satsPerGiBDay exceeds maximum'") &&
  relayApiLease.includes("if (!message || hasControlChars(message)) return 'invalid lease config'") &&
  relayApiLease.includes('message.startsWith(RATE_MAX_PREFIX)') &&
  leaseManager.includes('async setRateDurable') &&
  leaseManager.includes('this.satsPerGiBDay = previous') &&
  leaseManager.includes("wrapped.code = 'LEASE_RATE_PERSIST_FAILED'") &&
  leaseManager.includes("this._persist().catch((err) => { this.emit('persist-error', err) })") &&
  apiLeaseTest.includes('api lease: status payload shapes summary and counts active paid leases') &&
  apiLeaseTest.includes('api lease: config update uses durable setter before returning success') &&
  apiLeaseTest.includes('api lease: config update reports persistence failure without pretending success') &&
  apiLeaseTest.includes('api lease: disabled and malformed runtime states stay stable') &&
  apiLeaseTest.includes('/data/hiverelay/lease.json: permission denied') &&
  apiLeaseTest.includes('bad-request: invalid lease config') &&
  auditRoadmap.includes('Lease management API durability boundary')
) {
  pass('paid lease management API is extracted with sanitized status payloads and durable rate-update coverage')
} else {
  fail('paid lease management API can drift from sanitized status or durable persistence behavior')
}

if (
  [blindsparkDashboard, fullDashboard, wizardDashboard].every(html =>
    html.includes('new URL(raw, window.location.href)') &&
    html.includes('u.origin === window.location.origin') &&
    html.includes("h.set('Authorization', 'Bearer ' + t)")
  )
) {
  pass('dashboard UI auth shim only attaches bearer tokens to same-origin fetches')
} else {
  fail('dashboard UI auth shim can still leak bearer tokens to off-origin fetches')
}

if (
  relayApi.includes("import { buildDashboardHtmlResponse, setDashboardSecurityHeaders } from './api-dashboard-html.js'") &&
  relayApi.includes("import { resolveDashboardGetRoute } from './api-dashboard-routes.js'") &&
  relayApi.includes('const dashboardRoute = await this._resolveDashboardGetRoute(req, path)') &&
  relayApi.includes('if (dashboardRoute) return this._sendDashboardGetRoute(res, dashboardRoute)') &&
  relayApi.includes('const body = buildDashboardHtmlResponse(this[cacheKey], {') &&
  relayApi.includes('exposeToken: this._uiExposeToken') &&
  relayApi.includes('apiKey: this._apiKey') &&
  relayApi.includes('if (body.noStore) res.setHeader') &&
  relayApi.includes('res.end(body.html)') &&
  relayApi.includes('async _resolveDashboardGetRoute') &&
  relayApi.includes('_sendDashboardGetRoute') &&
  relayApi.includes('_setDashboardSecurityHeaders') &&
  relayApi.includes('return setDashboardSecurityHeaders(res)') &&
  relayApiDashboardHtml.includes('export function escapeHtmlAttr') &&
  relayApiDashboardHtml.includes('export function injectUiTokenMeta') &&
  relayApiDashboardHtml.includes('export function buildDashboardHtmlResponse') &&
  relayApiDashboardHtml.includes('export function setDashboardSecurityHeaders') &&
  relayApiDashboardHtml.includes('name="hiverelay-ui-token"') &&
  relayApiDashboardHtml.includes("Content-Type', 'text/html; charset=utf-8'") &&
  relayApiDashboardHtml.includes("X-Content-Type-Options', 'nosniff'") &&
  relayApiDashboardHtml.includes("Referrer-Policy', 'no-referrer'") &&
  relayApiDashboardHtml.includes('Permissions-Policy') &&
  relayApiDashboardHtml.includes('Content-Security-Policy') &&
  relayApiDashboardHtml.includes("default-src 'self'") &&
  relayApiDashboardHtml.includes("object-src 'none'") &&
  relayApiDashboardHtml.includes("base-uri 'none'") &&
  relayApiDashboardHtml.includes("connect-src 'self' ws: wss:") &&
  relayApiDashboardRoutes.includes('export function resolveDashboardGetRoute') &&
  relayApiDashboardRoutes.includes("['/network', { cacheKey: '_networkHtml', filename: 'network.html' }]") &&
  relayApiDashboardRoutes.includes("return redirect('/dashboard')") &&
  relayApiDashboardRoutes.includes('Wizard is localhost-only') &&
  relayApiDashboardRoutes.includes("return redirect(wizardComplete ? '/dashboard' : '/wizard')") &&
  apiDashboardHtmlTest.includes('token meta is attribute-escaped and injected into head') &&
  apiDashboardHtmlTest.includes('response builder injects only when exposeToken has a key') &&
  apiDashboardHtmlTest.includes('security headers set browser hardening policy') &&
  apiDashboardRoutesTest.includes('simple mode redirects full operator tabs') &&
  apiDashboardRoutesTest.includes('wizard remains local unless token exposure is enabled') &&
  apiDashboardRoutesTest.includes('root redirects by wizard completion state') &&
  apiUiTokenTest.includes('dashboard HTML is explicitly typed') &&
  apiUiTokenTest.includes('dashboard responses disable content sniffing') &&
  apiUiTokenTest.includes('dashboard responses do not leak referrers') &&
  apiUiTokenTest.includes('dashboard disables browser device permissions') &&
  apiUiTokenTest.includes('dashboard sets a same-origin CSP') &&
  apiUiTokenTest.includes('token response is not cacheable')
) {
  pass('dashboard HTML token injection, browser hardening headers, and dashboard route decisions are extracted and directly covered')
} else {
  fail('dashboard HTML token injection, browser hardening headers, or dashboard route decisions can drift without direct coverage')
}

if (
  relayApi.includes("} from './api-overview.js'") &&
  relayApi.includes('const stats = this.node.getStats({ includeSecrets: authed })') &&
  relayApi.includes('return this._json(res, buildOverviewPayload({') &&
  relayApi.includes('reputation: reputationOverview(this.node.reputation)') &&
  relayApi.includes('bandwidth: bandwidthOverview(this.node._bandwidthReceipt)') &&
  relayApi.includes('registry: registryOverview(this.node.seedingRegistry, config)') &&
  relayApiOverview.includes("import { buildReputationLeaderboardPayload } from './api-reputation-read.js'") &&
  relayApiOverview.includes('export function buildOverviewPayload') &&
  relayApiOverview.includes('export function overviewStorage') &&
  relayApiOverview.includes('export function overviewServed') &&
  relayApiOverview.includes('export function overviewRelay') &&
  relayApiOverview.includes('export function overviewSeeder') &&
  relayApiOverview.includes('export function overviewTorInfo') &&
  relayApiOverview.includes('function safeOverviewCounter') &&
  relayApiOverview.includes('buildReputationLeaderboardPayload({ reputation, maxEntries: 1 })') &&
  relayApiOverview.includes('relay: overviewRelay(stats)') &&
  relayApiOverview.includes('tor: overviewTorInfo(tor)') &&
  !relayApiOverview.includes('...stats.seeder') &&
  !relayApiOverview.includes('relay: stats.relay ||') &&
  relayApiOverview.includes('DEFAULT_MAX_STORAGE_BYTES') &&
  apiOverviewTest.includes('api overview: measured storage and served counters beat legacy seeder fallbacks') &&
  apiOverviewTest.includes('api overview: legacy storage and served fallbacks remain stable') &&
  apiOverviewTest.includes('api overview: relay, seeder, and tor summaries are known-field only') &&
  apiOverviewTest.includes('api overview: build payload preserves dashboard contract') &&
  apiAuthTest.includes('public overview requests use redacted stats and authenticated requests may include transport secrets') &&
  apiAuthTest.includes('overview tor details are shaped before response') &&
  statusSecretsRedactionTest.includes('getStats() redacts transport secrets when includeSecrets is false') &&
  readme.includes('`GET /api/overview`') &&
  readme.includes('public bounded relay/seeder/storage/reputation summary') &&
  auditRoadmap.includes('4.80') &&
  auditRoadmap.includes('HTTP overview payload shaping')
) {
  pass('operator overview payload builder is extracted and emits bounded HTTP summaries')
} else {
  fail('operator overview payload or public redaction path can drift without bounded-summary coverage')
}

if (
  relayApi.includes("import { buildStatusPayload } from './api-status-read.js'") &&
  relayApi.includes("if (path === '/status')") &&
  relayApi.includes('const result = buildStatusPayload({ node: this.node })') &&
  !relayApi.includes('this.node.getStats({ includeSecrets: this._checkAuth(req) })') &&
  relayApiStatusRead.includes('export function buildStatusPayload') &&
  relayApiStatusRead.includes('node.getStats({ includeSecrets: false })') &&
  relayApiStatusRead.includes('export function sanitizeTransportSummary') &&
  relayApiStatusRead.includes('export function sanitizeDiskInfo') &&
  relayApiStatusRead.includes('export function buildStatusServicesSummary') &&
  relayApiStatusRead.includes('sanitizeServiceCatalogEntries') &&
  apiStatusReadTest.includes('api status: build payload shapes public counters and omits raw secret fields') &&
  apiStatusReadTest.includes('api status: malformed public fields become stable null or zero values') &&
  apiAuthTest.includes('GET /status always returns bounded public status') &&
  statusSecretsRedactionTest.includes('buildStatusPayload() shapes public status without secret fields') &&
  readme.includes('/status` exposes shaped liveness') &&
  readme.includes('aggregate counters instead of raw node stats') &&
  developerDocs.includes('Public bounded status summary') &&
  auditRoadmap.includes('4.47') &&
  auditRoadmap.includes('Public status read boundary')
) {
  pass('public /status is bounded through a dedicated helper and cannot auth-expand into raw node stats')
} else {
  fail('public /status can drift back to raw node stats or undocumented secret-bearing fields')
}

if (
  wsFeed.includes('timingSafeEqual') &&
  wsFeed.includes('MAX_AUTH_MESSAGE_BYTES') &&
  wsFeed.includes("url.searchParams.has('token')") &&
  wsFeed.includes("url.searchParams.has('api_key')") &&
  wsFeed.includes('_awaitClientAuth') &&
  wsFeed.includes('parseAuthToken') &&
  wsFeed.includes("msg.type !== 'auth'") &&
  wsFeed.includes('safeTokenEqual(token, this._apiKey)') &&
  wsFeed.includes('ws._hiverelayReady === true') &&
  [fullDashboard, networkDashboard, paymentsDashboard, leaderboardDashboard].every(html =>
    html.includes("document.querySelector('meta[name=\"hiverelay-ui-token\"]')") &&
    html.includes("sock.send(JSON.stringify({ type: 'auth', token: t }))") &&
    html.includes('sendWsAuth(ws);') &&
    !html.includes('/ws?token=')
  ) &&
  dashboardIndexUiTest.includes('operator WebSocket clients authenticate with an in-band token frame') &&
  wsFeedPayloadTest.includes('query-string tokens do not authenticate dashboard sockets') &&
  wsFeedPayloadTest.includes('authenticated clients must send in-band auth before snapshots')
) {
  pass('dashboard WebSocket feed rejects URL tokens and waits for timing-safe in-band auth before live updates')
} else {
  fail('dashboard WebSocket feed can leak URL tokens or send live updates before authentication')
}

if (
  wsFeed.includes("import { buildOperatorAutoHealPayload } from './api-operator-telemetry.js'") &&
  wsFeed.includes('MAX_DASHBOARD_AUTO_HEAL_DRIVES = 50') &&
  wsFeed.includes('const snap = buildOperatorAutoHealPayload(node.autoHeal.snapshot())') &&
  wsFeed.includes('snap.drives.slice(0, MAX_DASHBOARD_AUTO_HEAL_DRIVES)') &&
  apiOperatorTelemetryTest.includes('api operator telemetry: auto-heal payload distinguishes disabled and sanitizes running state') &&
  wsFeedPayloadTest.includes('ws-feed: payload includes autoHeal snapshot when present') &&
  wsFeedPayloadTest.includes('raw AutoHeal fields are removed from live feed') &&
  wsFeedPayloadTest.includes('ws-feed: payload sanitizes and caps autoHeal.drives at 50 to bound payload size') &&
  wsFeedPayloadTest.includes('invalid rows do not consume the cap') &&
  auditRoadmap.includes('Dashboard WebSocket AutoHeal sanitization')
) {
  pass('dashboard WebSocket AutoHeal updates reuse the bounded operator sanitizer before frame capping')
} else {
  fail('dashboard WebSocket AutoHeal updates can regress to raw scheduler snapshots or invalid-row frame caps')
}

if (
  wsFeed.includes('DASHBOARD_CUSTODY_COUNTERS = [') &&
  wsFeed.includes('payload.custody = sanitizeDashboardCustodySnapshot(registry.custodySnapshot())') &&
  wsFeed.includes('function sanitizeDashboardCustodySnapshot') &&
  wsFeed.includes('function safeDashboardCounter') &&
  wsFeed.includes('function safeDashboardRatio') &&
  wsFeed.includes('commitRate = safeDashboardRatio(source.commitRate)') &&
  wsFeedPayloadTest.includes('ws-feed: payload includes custody snapshot when registry has one') &&
  wsFeedPayloadTest.includes('raw custody fields are removed from live feed') &&
  wsFeedPayloadTest.includes('ws-feed: payload normalizes malformed custody snapshot counters') &&
  wsFeedPayloadTest.includes('malformed custody snapshot raw fields are removed') &&
  auditRoadmap.includes('Dashboard WebSocket custody aggregate sanitization')
) {
  pass('dashboard WebSocket custody updates expose only bounded aggregate counters')
} else {
  fail('dashboard WebSocket custody updates can regress to raw registry snapshots or malformed aggregate counters')
}

if (
  wsFeed.includes('const stats = node.getStats({ includeSecrets: false })') &&
  wsFeed.includes('tor: sanitizeDashboardTransportInfo(stats.tor)') &&
  wsFeed.includes('holesail: sanitizeDashboardTransportInfo(stats.holesail)') &&
  wsFeed.includes('function sanitizeDashboardTransportInfo') &&
  wsFeedPayloadTest.includes('ws-feed: overview requests redacted stats and removes transport secrets') &&
  wsFeedPayloadTest.includes('feed asks RelayNode for redacted stats') &&
  wsFeedPayloadTest.includes('holesail connection key omitted') &&
  auditRoadmap.includes('Dashboard WebSocket transport redaction')
) {
  pass('dashboard WebSocket overview uses redacted node stats and shaped transport status')
} else {
  fail('dashboard WebSocket overview can regress to secret-bearing node stats or raw transport payloads')
}

if (
  wsFeed.includes('relay: sanitizeDashboardRelayStats(stats.relay)') &&
  wsFeed.includes('seeder: sanitizeDashboardSeederStats(stats.seeder, measuredServed)') &&
  wsFeed.includes('function sanitizeDashboardRelayStats') &&
  wsFeed.includes('function sanitizeDashboardSeederStats') &&
  wsFeedPayloadTest.includes('ws-feed: overview shapes relay and seeder counters') &&
  wsFeedPayloadTest.includes('raw relay/seeder fields are removed') &&
  auditRoadmap.includes('Dashboard WebSocket relay/seeder counter shaping')
) {
  pass('dashboard WebSocket overview emits bounded relay and seeder counters')
} else {
  fail('dashboard WebSocket overview can regress to raw relay/seeder stats objects')
}

if (
  wsFeed.includes("import { buildReputationLeaderboardPayload } from './api-reputation-read.js'") &&
  wsFeed.includes('MAX_DASHBOARD_PAYMENT_ACCOUNTS = 25') &&
  wsFeed.includes('reputation: sanitizeDashboardReputationOverview(node.reputation)') &&
  wsFeed.includes('bandwidth: sanitizeDashboardBandwidthOverview(node._bandwidthReceipt)') &&
  wsFeed.includes('credits: sanitizeDashboardCreditStats(readDashboardStats(node.creditManager))') &&
  wsFeed.includes('payment: sanitizeDashboardPaymentOverview(node.paymentManager, stats.payment)') &&
  wsFeed.includes('function sanitizeDashboardPaymentAccount') &&
  wsFeed.includes('function safeDashboardLabel') &&
  wsFeedPayloadTest.includes('ws-feed: overview shapes payment and service accounting telemetry') &&
  wsFeedPayloadTest.includes('payment accounts are capped') &&
  wsFeedPayloadTest.includes('raw payment/service manager fields are removed') &&
  wsFeedPayloadTest.includes('ws-feed: overview sanitizes reputation and bandwidth telemetry') &&
  wsFeedPayloadTest.includes('raw reputation/bandwidth fields are removed') &&
  auditRoadmap.includes('Dashboard WebSocket payment/reputation telemetry shaping')
) {
  pass('dashboard WebSocket overview emits bounded payment, accounting, bandwidth, and reputation telemetry')
} else {
  fail('dashboard WebSocket overview can regress to raw payment/accounting/reputation manager payloads')
}

if (
  websocketTransport.includes("import { createHash, randomBytes } from 'crypto'") &&
  websocketTransport.includes('this._ipHashSalt = randomBytes(32)') &&
  websocketTransport.includes('_hashIp (ip)') &&
  websocketTransport.includes('_safeInfo (ip, remotePort)') &&
  websocketTransport.includes('remoteAddressHash: this._hashIp(ip)') &&
  websocketTransport.includes('const info = this._safeInfo(req.socket.remoteAddress, req.socket.remotePort)') &&
  !websocketTransport.includes('remoteAddress: req.socket.remoteAddress') &&
  websocketTransportTest.includes('privacy-safe connection event') &&
  websocketTransportTest.includes('raw remote address is not emitted') &&
  websocketTransportTest.includes('salt rotates across transport instances')
) {
  pass('Hypercore-over-WebSocket transport emits salted client IP hashes instead of raw remote addresses')
} else {
  fail('Hypercore-over-WebSocket transport can expose raw client IPs in emitted connection info')
}

if (
  pokerWsAdapter.includes('timingSafeEqual') &&
  pokerWsAdapter.includes('MAX_AUTH_MESSAGE_BYTES') &&
  pokerWsAdapter.includes("url.searchParams.has('token')") &&
  pokerWsAdapter.includes("url.searchParams.has('api_key')") &&
  pokerWsAdapter.includes('_awaitClientAuth') &&
  pokerWsAdapter.includes('parseAuthToken') &&
  pokerWsAdapter.includes("msg.type !== 'auth'") &&
  pokerWsAdapter.includes('safeTokenEqual(token, this._apiKey)') &&
  pokerWsAdapter.includes('table-not-found') &&
  pokerWsAdapter.includes("_getStateSnapshot(tableKey, 'upgrade')") &&
  pokerWsAdapter.includes('_getStateSnapshot(tableKey, \'auth\')') &&
  pokerWsAdapter.includes("'ws-state-error'") &&
  pokerWsAdapter.includes("'ws-subscribe-error'") &&
  pokerWsAdapter.includes("error: 'subscribe-failed'") &&
  !pokerWsAdapter.includes("error: 'subscribe-failed:'") &&
  pokerWsAdapterTest.includes('rejects URL tokens and waits for in-band auth before state') &&
  pokerWsAdapterTest.includes('state frame is not sent before auth') &&
  pokerWsAdapterTest.includes('closes invalid auth frames without attaching clients') &&
  pokerWsAdapterTest.includes('redacts subscribe failures from clients') &&
  pokerWsAdapterTest.includes('redacts public state lookup failures during upgrade') &&
  pokerWsAdapterTest.includes('redacts authenticated state lookup failures after auth') &&
  pokerReadme.includes('optional in-band API-key auth frame') &&
  pokerReadme.includes('URL-token rejection')
) {
  pass('Poker WebSocket feed rejects URL tokens, waits for timing-safe in-band auth, and redacts provider failures')
} else {
  fail('Poker WebSocket feed can leak URL tokens, provider errors, or send table state before authentication')
}

if (
  relayApi.includes("} from './api-service-config.js'") &&
  relayApi.includes('return normalizeManageServicePlugins(plugins)') &&
  relayApi.includes('return serviceConfigPayload(this.node.config, this.node.serviceRegistry)') &&
  relayApiServiceConfig.includes('export const BUILTIN_SERVICE_PLUGINS') &&
  relayApiServiceConfig.includes('export const SERVICE_PLUGIN_BUNDLES') &&
  relayApiServiceConfig.includes("poker: Object.freeze(['poker', 'vrf', 'arbitration', 'zk'])") &&
  relayApiServiceConfig.includes('export function normalizeManageServicePlugins') &&
  relayApiServiceConfig.includes('export function serviceConfigPayload') &&
  relayApi.includes('_handlePokerHttpRoute') &&
  relayApiCors.includes('isPublicPokerCorsRoute') &&
  relayApiCors.includes("path.startsWith('/api/poker/')") &&
  relayApiCors.includes("path !== '/api/poker/usage'") &&
  relayApi.includes('/api/manage/services/available') &&
  relayApi.includes('/api/manage/services/config') &&
  relayApi.includes('/api/usage') &&
  relayApi.includes('/api/poker/usage') &&
  relayApi.includes("import('p2p-hiveservices/builtin/poker/http-adapter.js')") &&
  relayApi.includes("} from './api-usage-telemetry.js'") &&
  relayApi.includes('_getUsageTelemetryPayload') &&
  relayApi.includes('_getPokerUsageTelemetryPayload') &&
  relayApi.includes("if (path === '/api/usage' && req.method === 'GET')") &&
  relayApi.includes('if (this.node._bandwidthReceipt) return this._json(res, this._getUsageTelemetryPayload())') &&
  relayApi.includes("if (path === '/api/poker/usage' && req.method === 'GET')") &&
  relayApi.includes('const provider = pk.ok ? pk.provider : this._getPokerApp()') &&
  relayApi.includes('enabled: true') &&
  relayApi.includes('return usageTelemetryPayload(this.node._bandwidthReceipt, stats)') &&
  relayApi.includes('return pokerUsageTelemetryPayload(this._getPokerApp())') &&
  pokerHttpAdapter.includes("from 'p2p-hiverelay/core/relay-node/api-body.js'") &&
  pokerHttpAdapter.includes("from 'p2p-hiverelay/core/relay-node/api-request.js'") &&
  pokerHttpAdapter.includes("from 'p2p-hiverelay/core/relay-node/api-response.js'") &&
  pokerHttpAdapter.includes('getPostJsonContentTypeProblem(req)') &&
  pokerHttpAdapter.includes('await readJsonBody(req, maxBytes)') &&
  pokerHttpAdapter.includes('writeJson(res, body, status, headers)') &&
  pokerHttpAdapter.includes('function _createTableFailure') &&
  pokerHttpAdapter.includes("error: 'Poker table create failed'") &&
  pokerHttpAdapter.includes("error: 'Poker move failed'") &&
  pokerHttpAdapter.includes("error: 'Poker table list failed'") &&
  !pokerHttpAdapter.includes('res.end(JSON.stringify(body)') &&
  relayApiUsageTelemetry.includes('export function usageTelemetryPayload') &&
  relayApiUsageTelemetry.includes('export function pokerUsageTelemetryPayload') &&
  relayApiUsageTelemetry.includes('export function sumReceiptBytes') &&
  relayApiUsageTelemetry.includes('export function tableWriterCount') &&
  relayApiServiceConfig.includes('unknown service plugin') &&
  pluginLoader.includes("poker: { module: 'p2p-hiveservices/builtin/poker/index.js', className: 'PokerApp' }") &&
  pluginLoader.includes("poker: ['poker', 'vrf', 'arbitration', 'zk']") &&
  pluginLoader.includes('expandPluginConfigs') &&
  apiServiceConfigHelpersTest.includes('api service config helpers: normalize builtins and expand bundles') &&
  apiServiceConfigHelpersTest.includes('api service config helpers: payload reports configured builtins and active providers') &&
  apiUsageTelemetryTest.includes('api usage telemetry: builds dashboard payload from verified and measured counters') &&
  apiUsageTelemetryTest.includes('api usage telemetry: poker usage counts tables, appends, and seats defensively') &&
  apiAuthTest.includes('api-auth: operator usage telemetry requires auth and returns aggregate proof counters') &&
  apiServiceConfigTest.includes('poker service http api is delegated when poker provider is running') &&
  apiServiceConfigTest.includes('poker table api keeps app-facing CORS separate from management usage telemetry') &&
  pokerHttpAdapterTest.includes('poker http adapter uses hardened JSON response headers') &&
  pokerHttpAdapterTest.includes('poker http adapter rejects body-bearing non-json posts before parsing') &&
  pokerHttpAdapterTest.includes('poker http adapter redacts unexpected create table errors') &&
  pokerHttpAdapterTest.includes('poker http adapter normalizes invalid writer errors without reflecting input') &&
  pluginLoaderTest.includes('plugin loader resolves poker as a builtin service provider')
) {
  pass('management API exposes validated built-in service configuration, poker runtime wiring, hardened poker HTTP API, and usage telemetry endpoints')
} else {
  fail('management API is missing validated service configuration, poker runtime wiring, hardened poker HTTP API, or usage telemetry endpoints')
}

if (
  relayApi.includes('} from \'./api-ai-models.js\'') &&
  relayApi.includes('return buildManageAIModelRegistration(body)') &&
  relayApi.includes('return buildManageAIModelsPayload(models, status)') &&
  relayApi.includes('return manageAIModelStatus(model, qvacStatus)') &&
  relayApi.includes('publicManageAIModelError(err') &&
  relayApi.includes("this.emit('ai-model-error'") &&
  relayApiAiModels.includes('export function buildManageAIModelRegistration') &&
  relayApiAiModels.includes('export function buildManageAIModelsPayload') &&
  relayApiAiModels.includes('export function manageAIModelStatus') &&
  relayApiAiModels.includes('export function publicManageAIModelError') &&
  relayApiAiModels.includes('PUBLIC_AI_MODEL_ERROR_CODES') &&
  relayApiAiModels.includes('function objectRecord') &&
  relayApiAiModels.includes('function optionalObjectField') &&
  relayApiAiModels.includes('for (const field of [') &&
  relayApiAiModels.includes('modelSrc must be a string') &&
  relayApiAiModels.includes('delete params.handler') &&
  relayApiAiModels.includes('this endpoint only registers qvac-backed models') &&
  apiAiModelsTest.includes('api ai models: registration rejects malformed qvac option shapes') &&
  apiAiModelsTest.includes('modelConfig must be an object') &&
  apiAiModelsTest.includes('loadOptions must be an object') &&
  apiAiModelsTest.includes('api ai models: registration normalizes top-level qvac model sources') &&
  apiAiModelsTest.includes('api ai models: status decoration distinguishes qvac and handler backends') &&
  apiAiModelsTest.includes('api ai models: public errors preserve stable AI codes and redact internals') &&
  apiQvacModelsTest.includes('manage api qvac models: register, list, remove') &&
  apiQvacModelsTest.includes('manage api qvac models: rejects non-qvac registration') &&
  apiQvacModelsTest.includes('manage api qvac models: redacts unexpected provider errors') &&
  apiQvacModelsTest.includes('manage api qvac models: preserves known AI model errors') &&
  umbrelUiControlsTest.includes('umbrel AI model fields add on Enter without form navigation')
) {
  pass('management API QVAC model registration, status decoration, and provider-error redaction are extracted with route/UI coverage')
} else {
  fail('management API QVAC model registration or provider-error redaction can drift from route or UI coverage')
}

if (
  relayApi.includes("import { runServiceManagementAction } from './api-service-management.js'") &&
  relayApi.includes('const result = await runServiceManagementAction({') &&
  relayApi.includes('persistConfig: () => this._persistConfig()') &&
  relayApi.includes('serviceConfigPayload: () => this._getServiceConfigPayload()') &&
  relayApi.includes("if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)") &&
  relayApiServiceManagement.includes('export async function runServiceManagementAction') &&
  relayApiServiceManagement.includes('const configuredPlugins = configuredServicePlugins(config)') &&
  relayApiServiceManagement.includes('const bundleParents = bundleParentsForService(service, configuredPlugins)') &&
  relayApiServiceConfig.includes('export function configuredServicePlugins') &&
  relayApiServiceConfig.includes('export function bundleParentsForService') &&
  relayApiServiceManagement.includes("hint: 'Use /api/manage/services/config to change the selected service bundle.'") &&
  relayApiServiceManagement.includes('config.plugins = nextPlugins') &&
  relayApiServiceManagement.includes('if (nextPlugins.length === 0) config.enableServices = false') &&
  relayApiServiceManagement.indexOf('await persistConfig()') !== -1 &&
  relayApiServiceManagement.indexOf('await persistConfig()') < relayApiServiceManagement.indexOf('await registry.unregister(service)') &&
  relayApiServiceManagement.includes('registry.restart(service, ctx)') &&
  apiServiceManagementTest.includes('api service management: disable persists configured plugin removal before unregistering') &&
  apiServiceManagementTest.includes('api service management: disable rolls back config when persistence fails') &&
  apiServiceManagementTest.includes('api service management: disable rejects bundle dependencies before persistence') &&
  apiServiceManagementTest.includes('api service management: restart delegates to registry restart with node context') &&
  apiServiceConfigTest.includes('service management api: disable persists configured plugins before unregistering') &&
  apiServiceConfigTest.includes('service management api: disable rolls back configured plugins when persistence fails') &&
  apiServiceConfigTest.includes('service management api: disable rejects services required by configured bundles') &&
  apiServiceConfigHelpersTest.includes('api service config helpers: bundle parents identify configured bundle dependencies') &&
  cliManage.includes('Saved to service config') &&
  cliManage.includes('Runtime-only service stop') &&
  developerDocs.includes('configured disables persist before unregistering') &&
  auditRoadmap.includes('Durable live service disable') &&
  auditDoc.includes('Hardened live service disable semantics')
) {
  pass('service management disable persists configured plugin removal before unregistering live providers')
} else {
  fail('service management disable can still look successful without durable plugin removal')
}

if (
  relayApi.includes("import { buildServiceCatalogPayload } from './api-service-read.js'") &&
  relayApi.includes('const result = buildServiceCatalogPayload({ registry: this.node.serviceRegistry })') &&
  !relayApi.includes('services: this.node.serviceRegistry.catalog()') &&
  !relayApi.includes('count: this.node.serviceRegistry.services.size') &&
  relayApiServiceRead.includes('export function buildServiceCatalogPayload') &&
  relayApiServiceRead.includes('sanitizeServiceCatalogEntries(raw)') &&
  relayApiServiceRead.includes("'Cache-Control': 'public, max-age=10'") &&
  serviceCatalogCore.includes('export const MAX_SERVICE_CATALOG_ENTRIES = 128') &&
  serviceCatalogCore.includes('export const MAX_SERVICE_CAPABILITIES = 64') &&
  serviceCatalogCore.includes('export function sanitizeServiceCatalogEntry') &&
  serviceCatalogCore.includes('export function sanitizeServiceCatalogEntries') &&
  !serviceCatalogCore.includes('...entry') &&
  serviceRegistryCore.includes("import { sanitizeServiceCatalogEntries } from './service-catalog.js'") &&
  serviceRegistryCore.includes('const sanitized = sanitizeServiceCatalogEntries(services)') &&
  serviceRegistryCore.includes('services: sanitized') &&
  serviceProtocol.includes("import { sanitizeServiceCatalogEntries } from './service-catalog.js'") &&
  serviceProtocol.includes('const services = sanitizeServiceCatalogEntries(msg.services)') &&
  serviceProtocol.includes("this.emit('catalog-received', { remotePubkey, services })") &&
  serviceCatalogSanitizerTest.includes('service catalog sanitizer shapes public entries') &&
  serviceCatalogSanitizerTest.includes('api service read helper returns bounded public payload') &&
  servicesTest.includes('ServiceRegistry - sanitizes remote service catalogs before storing') &&
  protocolSecurityTest.includes('peer service catalogs are sanitized before registry and events') &&
  apiAuthTest.includes('GET /api/v1/services returns sanitized public service catalog') &&
  auditRoadmap.includes('Service catalog discovery boundary')
) {
  pass('service catalog discovery is bounded and sanitized across HTTP and P2P ingestion')
} else {
  fail('service catalog discovery can regress to raw unbounded provider or peer-advertised fields')
}

if (
  relayApi.includes("import { buildRouterInfoPayload } from './api-router-read.js'") &&
  relayApi.includes('const result = buildRouterInfoPayload({ router: this.node.router })') &&
  !relayApi.includes('topics: this.node.router.pubsub.topics?.() || []') &&
  !relayApi.includes('routes: this.node.router.routes().length') &&
  relayApiRouterRead.includes('export const MAX_ROUTER_TOPICS = 256') &&
  relayApiRouterRead.includes('export const MAX_ROUTER_TOPIC_BYTES = 256') &&
  relayApiRouterRead.includes('export function buildRouterInfoPayload') &&
  relayApiRouterRead.includes('router.getStats()') &&
  relayApiRouterRead.includes('pubsub.topicCount()') &&
  relayApiRouterRead.includes('safeSubscriberCount(pubsub)') &&
  relayApiRouterRead.includes("'Cache-Control': 'public, max-age=10'") &&
  apiRouterReadTest.includes('uses router stats for route count without materializing routes') &&
  apiRouterReadTest.includes('bounds and sanitizes public pubsub topics') &&
  apiRouterReadTest.includes('tolerates throwing router and pubsub helpers') &&
  apiAuthTest.includes('GET /api/v1/router returns bounded public router info') &&
  auditRoadmap.includes('Router discovery read boundary')
) {
  pass('router discovery reads are extracted with bounded sanitized public pubsub metadata')
} else {
  fail('router discovery reads can regress to raw routes() or unbounded pubsub topic exposure')
}

if (
  routerCore.includes('const DEFAULT_MAX_RATE_LIMIT_BUCKETS = 50_000') &&
  routerCore.includes('this._maxRateLimitBuckets = positiveInteger(opts.maxRateLimitBuckets, DEFAULT_MAX_RATE_LIMIT_BUCKETS)') &&
  routerCore.includes('this._rateLimitBucketTtlMs = positiveInteger(opts.rateLimitBucketTtlMs, DEFAULT_RATE_LIMIT_BUCKET_TTL_MS)') &&
  routerCore.includes('this._pruneRateLimitBuckets(now)') &&
  routerCore.includes('if (this._rateLimiters.size >= this._maxRateLimitBuckets) return false') &&
  routerCore.includes('rateLimitBuckets: this._rateLimiters.size') &&
  routerCore.includes('maxRateLimitBuckets: this._maxRateLimitBuckets') &&
  routerTest.includes('Router - rate limit bucket map rejects new peers at cap') &&
  routerTest.includes('Router - rate limit bucket cap prunes stale buckets before rejecting new peers') &&
  auditRoadmap.includes('Router rate-limit bucket cap')
) {
  pass('router service RPC rate-limit buckets are capped and stale-pruned')
} else {
  fail('router service RPC rate-limit buckets can regress to unbounded per-peer memory growth')
}

if (
  relayApi.includes("} from './api-mode-transport.js'") &&
  relayApi.includes('const result = await runModeSwitchAction({') &&
  relayApi.includes('const result = await runTransportToggleAction({') &&
  relayApiModeTransport.includes('export const AVAILABLE_MODES') &&
  relayApiModeTransport.includes('export async function runModeSwitchAction') &&
  relayApiModeTransport.includes('export async function runTransportToggleAction') &&
  relayApiModeTransport.includes('validatePositiveInt(body.maxConnections, 0, 100000, \'maxConnections\')') &&
  relayApiModeTransport.includes('validatePositiveNumber(body.maxRelayBandwidthMbps, 0, 100000, \'maxRelayBandwidthMbps\')') &&
  relayApiModeTransport.includes('function objectRecord') &&
  relayApiModeTransport.includes('function validateBooleanField') &&
  relayApiModeTransport.includes('field} must be an object') &&
  relayApiModeTransport.includes("validateBooleanField(body.registryAutoAccept, 'registryAutoAccept')") &&
  relayApiModeTransport.includes("validateBooleanField(enabled, 'enabled')") &&
  relayApiModeTransport.includes('node.config = previousConfig') &&
  relayApiModeTransport.includes('node._operatingMode = previousOperatingMode') &&
  relayApiModeTransport.includes("emit('config-rollback-error'") &&
  relayApiModeTransport.includes("RESERVED_TRANSPORT_NAMES = new Set(['__proto__', 'constructor', 'prototype'])") &&
  relayApiModeTransport.includes('delete config.transports') &&
  apiModeTransportTest.includes('api mode transport: validates mode action before applying') &&
  apiModeTransportTest.includes('field} must be an object') &&
  apiModeTransportTest.includes('registryAutoAccept must be a boolean') &&
  apiModeTransportTest.includes('enabled must be a boolean') &&
  apiModeTransportTest.includes('api mode transport: rolls back mode when persistence fails') &&
  apiModeTransportTest.includes('api mode transport: validates transport names before mutation') &&
  apiModeTransportTest.includes('api mode transport: persists transport toggles and rolls back failures') &&
  apiServiceConfigTest.includes('mode management api: persistence failure rolls back applied mode') &&
  apiServiceConfigTest.includes('transport management api: persists before success and rolls back on failure') &&
  auditRoadmap.includes('mode/transport helper owns mode override validation') &&
  auditRoadmap.includes('and transport toggle rollback') &&
  auditDoc.includes('Extracted mode and transport management orchestration')
) {
  pass('mode and transport management actions are extracted with validation and rollback coverage')
} else {
  fail('mode or transport management can drift from validation, persistence, or rollback coverage')
}

if (
  relayApi.includes("import { appendVaryHeader, writeJson, writeText } from './api-response.js'") &&
  relayApi.includes("import { buildCorsDecision, getAllowedOrigin } from './api-cors.js'") &&
  relayApiResponse.includes('export function appendVaryHeader (res, value)') &&
  relayApiResponse.includes("getResponseHeader(res, 'Vary')") &&
  relayApiResponse.includes("res.setHeader('Vary', text + ', ' + value)") &&
  relayApiCors.includes('export function isPublicPokerCorsRoute') &&
  relayApiCors.includes("path.startsWith('/api/poker/')") &&
  relayApiCors.includes("path !== '/api/poker/usage'") &&
  relayApiCors.includes('export function getAllowedOrigin') &&
  relayApiCors.includes("if (corsOrigins === '*') return '*'") &&
  relayApiCors.includes('export function buildCorsDecision') &&
  relayApiCors.includes("allowedOrigin: publicPokerRoute ? '*' : allowedOrigin") &&
  relayApiCors.includes("varyOrigin: Boolean(requestOrigin && !publicPokerRoute && corsOrigins !== '*')") &&
  relayApiCors.includes('preflightDenied: Boolean(requestOrigin && !allowedOrigin && !publicPokerRoute)') &&
  relayApi.includes('const cors = buildCorsDecision(this.corsOrigins, requestOrigin, requestPath)') &&
  relayApi.includes('if (cors.varyOrigin)') &&
  relayApi.includes("appendVaryHeader(res, 'Origin')") &&
  relayApi.includes("res.setHeader('Access-Control-Allow-Origin', cors.allowedOrigin)") &&
  relayApi.includes('if (cors.preflightDenied)') &&
  relayApi.includes('return getAllowedOrigin(this.corsOrigins, requestOrigin)') &&
  apiResponseTest.includes('appendVaryHeader preserves wildcard and avoids duplicates') &&
  apiCorsTest.includes('origin allowlist supports deny-by-default, strings, arrays, and wildcard') &&
  apiCorsTest.includes('dynamic allowlists vary by Origin while wildcard config does not') &&
  apiCorsTest.includes('public poker routes stay wildcard but usage telemetry stays managed') &&
  apiAuthTest.includes('configured CORS origins vary cached responses by Origin') &&
  apiAuthTest.includes('allowed dynamic CORS response varies by Origin') &&
  apiAuthTest.includes('denied preflight also varies by Origin')
) {
  pass('management API CORS decisions are extracted and dynamic responses vary by Origin for cache safety')
} else {
  fail('management API CORS decisions can drift from Vary: Origin or public Poker route boundaries')
}

if (
  relayApi.includes('import {\n  constantTimeStringEqual,') &&
  relayApi.includes("constantTimeStringEqual(auth, 'Bearer ' + this._apiKey)") &&
  relayApiAuthHelpers.includes("import { timingSafeEqual } from 'crypto'") &&
  relayApiAuthHelpers.includes('export function constantTimeStringEqual') &&
  relayApiAuthHelpers.includes('return timingSafeEqual(actualBuf, expectedBuf)') &&
  apiAuthHelpersTest.includes('constant-time string check requires exact string and length') &&
  apiAuthTest.includes('bearer token requires an exact match')
) {
  pass('management API compares bearer credentials with timing-safe equality')
} else {
  fail('management API bearer credential comparison is not timing-safe')
}

if (
  relayApi.includes('import {\n  constantTimeStringEqual,') &&
  relayApi.includes('return isLoopbackLocalRequest(req, this.trustProxy)') &&
  relayApi.includes('_hasLoopbackHostHeader (req)') &&
  relayApi.includes('_hasLoopbackOrigin (req)') &&
  relayApi.includes('return hasLoopbackHostHeader(req)') &&
  relayApi.includes('return hasLoopbackOrigin(req)') &&
  relayApiAuthHelpers.includes('export function normalizeHostLike (value)') &&
  relayApiAuthHelpers.includes('export function isLoopbackLocalRequest (req, trustProxy = false)') &&
  relayApiAuthHelpers.includes('if (trustProxy) return false') &&
  relayApiAuthHelpers.includes('hasLoopbackHostHeader(req)') &&
  relayApiAuthHelpers.includes('hasLoopbackOrigin(req)') &&
  apiAuthHelpersTest.includes('local fallback requires loopback socket, host, origin, and no trustProxy') &&
  apiAuthHelpersTest.includes('Host and Origin loopback checks reject rebinding inputs') &&
  apiAuthTest.includes('localhost fallback rejects non-loopback Host and Origin headers') &&
  apiAuthTest.includes('DNS-rebound Host is rejected') &&
  reverseProxyDocs.includes('socket,') &&
  reverseProxyDocs.includes('`Host`, and browser `Origin` are loopback values') &&
  reverseProxyDocs.includes('DNS-rebinding guard')
) {
  pass('management API localhost fallback rejects DNS-rebound Host and cross-site Origin headers')
} else {
  fail('management API localhost fallback can trust loopback sockets without loopback Host/Origin proof')
}

const dispatchRouteBlock = relayApi.slice(
  relayApi.indexOf("req.method === 'POST' && path === '/api/v1/dispatch'"),
  relayApi.indexOf('// POST routes')
)
if (
  relayApi.includes("import { runDispatchAction } from './api-dispatch.js'") &&
  dispatchRouteBlock.includes('return this._handleDispatch(res, body, this._isLocalRequest(req))') &&
  relayApi.includes('const result = await runDispatchAction({') &&
  relayApiDispatch.includes('export const LOCAL_ONLY_DISPATCH_ROUTES') &&
  relayApiDispatch.includes("'identity.sign'") &&
  relayApiDispatch.includes("'identity.verify'") &&
  relayApiDispatch.includes('LOCAL_ONLY_DISPATCH_ROUTES.has(body.route) && !isLocalRequest') &&
  relayApiDispatch.includes("payload: errorPayload('params must be an object')") &&
  relayApiDispatch.includes("transport: 'http'") &&
  relayApiDispatch.includes("caller: 'remote'") &&
  relayApiDispatch.includes("routeAccess === 'relay-admin' ? 'relay-admin' : 'authenticated-user'") &&
  relayApiDispatch.includes('role: dispatchRole({ router, route: body.route, isLocalRequest })') &&
  apiDispatchTest.includes('api dispatch: remote callers cannot use local-only identity routes') &&
  apiDispatchTest.includes('local-only denial happens before dispatch') &&
  apiDispatchTest.includes('api dispatch: rejects non-object params before dispatch') &&
  apiDispatchTest.includes('malformed params do not reach router') &&
  apiDispatchTest.includes('api dispatch: role mapping preserves HTTP remote caller contract') &&
  apiDispatchTest.includes("caller: 'remote'") &&
  apiAuthTest.includes('POST /api/v1/dispatch local-only route allowed from localhost with auth') &&
  capabilityEndpointsTest.includes('POST Content-Type requires exact application/json media type') &&
  auditRoadmap.includes('api-dispatch.js') &&
  auditDoc.includes('Extracted HTTP dispatch route policy')
) {
  pass('HTTP dispatch route policy is extracted with local-only route, params-shape, and caller-role coverage')
} else {
  fail('HTTP dispatch can regress local-only route denial, params-shape validation, caller role mapping, or route delegation')
}

const authorManifestGetBlock = relayApi.slice(
  relayApi.indexOf('const authorMatch = path.match'),
  relayApi.indexOf("if (path === '/api/forks/proofs')")
)
const forkProofGetStart = relayApi.indexOf("if (path === '/api/forks/proofs')")
const forkProofGetBlock = relayApi.slice(
  forkProofGetStart,
  relayApi.indexOf('// First-run setup wizard', forkProofGetStart)
)
const authorManifestPostBlock = relayApi.slice(
  relayApi.indexOf("if (path === '/api/authors/seeding.json')"),
  relayApi.indexOf('// Fork-proof gossip — receive a fork proof')
)
const forkProofPostBlock = relayApi.slice(
  relayApi.indexOf("if (path === '/api/forks/proof')"),
  relayApi.indexOf('// ─── Setup wizard mutations')
)
if (
  relayApi.includes('runAuthorManifestFetchAction,\n  runAuthorManifestPublishAction,\n  runForkProofPublishAction') &&
  authorManifestGetBlock.includes('runAuthorManifestFetchAction({') &&
  authorManifestGetBlock.includes('manifestStore: this.node.manifestStore') &&
  authorManifestGetBlock.includes('pubkey: authorMatch[1]') &&
  authorManifestPostBlock.includes('runAuthorManifestPublishAction({') &&
  authorManifestPostBlock.includes('manifestStore: this.node.manifestStore') &&
  authorManifestPostBlock.includes("result.kind === 'manifest-persist'") &&
  forkProofPostBlock.includes('runForkProofPublishAction({') &&
  forkProofPostBlock.includes('forkDetector: this.node.forkDetector') &&
  forkProofPostBlock.includes("result.kind === 'fork-persist'") &&
  !relayApi.includes('verifySeedingManifest') &&
  !relayApi.includes('verifyForkProof') &&
  relayApiSignedIngress.includes("import { verifySeedingManifest } from '../seeding-manifest.js'") &&
  relayApiSignedIngress.includes("import { verifyForkProof } from '../fork-proof-signing.js'") &&
  relayApiSignedIngress.includes('export function runAuthorManifestFetchAction') &&
  relayApiSignedIngress.includes('export async function runAuthorManifestPublishAction') &&
  relayApiSignedIngress.includes('export async function runForkProofPublishAction') &&
  relayApiSignedIngress.includes('const check = verifySeedingManifest(body)') &&
  relayApiSignedIngress.includes('const verify = verifyForkProof(body)') &&
  relayApiSignedIngress.includes('manifestStore.put(body)') &&
  relayApiSignedIngress.includes('await manifestStore.save()') &&
  relayApiSignedIngress.includes('manifestStore.restoreSnapshot(snapshot)') &&
  relayApiSignedIngress.includes('const status = /stale/.test(result.reason) ? 409 : 400') &&
  relayApiSignedIngress.includes('forkDetector.report({') &&
  relayApiSignedIngress.includes('await forkDetector.save()') &&
  relayApiSignedIngress.includes('forkDetector.restoreSnapshot(snapshot)') &&
  apiSignedIngressTest.includes('api signed ingress: author manifest publish verifies before store mutation') &&
  apiSignedIngressTest.includes('invalid signature path never reaches put') &&
  apiSignedIngressTest.includes('api signed ingress: author manifest save failure rolls back live store') &&
  apiSignedIngressTest.includes('api signed ingress: fork proof publish requires signed envelopes before report') &&
  apiSignedIngressTest.includes('api signed ingress: fork proof save failure rolls back report') &&
  manifestStoreTest.includes('snapshot + restore rolls back replacements and cap evictions') &&
  forkDetectorTest.includes('snapshot + restore rolls back fork evidence and bypass log changes') &&
  auditRoadmap.includes('api-signed-ingress.js') &&
  auditDoc.includes('Extracted public signed-ingress policy')
) {
  pass('public signed manifest and fork-proof ingress is extracted with signature-before-mutation and rollback coverage')
} else {
  fail('public signed manifest or fork-proof ingress can drift from signature gating, stale conflict, or persistence rollback coverage')
}

if (
  relayApi.includes("import { buildForkProofsPayload } from './api-fork-proofs.js'") &&
  forkProofGetBlock.includes('const result = buildForkProofsPayload({ forkDetector: this.node.forkDetector })') &&
  !forkProofGetBlock.includes('forkDetector.list().slice') &&
  relayApiForkProofs.includes('export const MAX_FORK_PROOF_RECORDS = 200') &&
  relayApiForkProofs.includes('export const MAX_FORK_PROOF_EVIDENCE_PER_RECORD = 16') &&
  relayApiForkProofs.includes('export const MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES = 8192') &&
  relayApiForkProofs.includes('source.slice(0, recordLimit)') &&
  relayApiForkProofs.includes('evidenceTruncated = true') &&
  relayApiForkProofs.includes('resolutionNote') === false &&
  apiForkProofsTest.includes('sanitizes public records without raw store fields') &&
  apiForkProofsTest.includes('caps records and per-record evidence') &&
  apiAuthTest.includes('GET /api/forks/proofs returns bounded sanitized public proofs') &&
  auditRoadmap.includes('Fork-proof read boundary')
) {
  pass('public fork-proof reads are extracted with bounded records/evidence and sanitized public payloads')
} else {
  fail('public fork-proof reads can regress to raw ForkDetector records or unbounded evidence exposure')
}

if (
  relayApi.includes('import {\n  checkApiRateLimit,') &&
  relayApi.includes('return checkApiRateLimit(this._rateLimits, ip)') &&
  relayApi.includes('return checkEndpointRateLimit(this._endpointRateLimits, ip, path)') &&
  relayApi.includes('return clientIpFromRequest(req, this.trustProxy)') &&
  relayApi.includes('sweepRateLimitMap(this._rateLimits, now)') &&
  relayApi.includes('sweepRateLimitMap(this._endpointRateLimits, now)') &&
  relayApiRateLimit.includes('export const API_RATE_LIMIT_MAX = 60') &&
  relayApiRateLimit.includes('export const API_ENDPOINT_RATE_LIMITS = Object.freeze') &&
  relayApiRateLimit.includes("'/api/wizard/reset': 5") &&
  relayApiRateLimit.includes("'/api/v1/seed': 30") &&
  relayApiRateLimit.includes('export function clientIpFromRequest') &&
  relayApiRateLimit.includes('export function checkFixedWindowRateLimit') &&
  relayApiRateLimit.includes('export function checkEndpointRateLimit') &&
  relayApiRateLimit.includes('export function sweepRateLimitMap') &&
  apiRateLimitTest.includes('client IP honors trusted proxy headers only when enabled') &&
  apiRateLimitTest.includes('fixed window rejects over cap and resets after expiry') &&
  apiRateLimitTest.includes('endpoint caps are separate from the general per-IP cap') &&
  apiRateLimitTest.includes('cleanup removes expired windows only')
) {
  pass('management API rate-limit and trusted-proxy IP helpers are extracted with direct cap/reset coverage')
} else {
  fail('management API rate-limit logic lacks extracted helper coverage for caps, reset windows, or trusted-proxy IP parsing')
}

if (
  relayApi.includes("const auth = req.headers.authorization || ''") &&
  !relayApi.includes("searchParams.get('api_key'") &&
  apiAuthTest.includes('query-string api keys are not accepted') &&
  reverseProxyDocs.includes('Authorization: Bearer <key>') &&
  reverseProxyDocs.includes('Query-string API keys are intentionally not') &&
  !reverseProxyDocs.includes('?api_key=<key>')
) {
  pass('management API and operator docs reject query-string API keys')
} else {
  fail('management API docs or tests still allow query-string API keys')
}

if (
  relayApi.includes("this._requireAuth(req, res, 'Unauthorized — wizard requires API key or localhost')") &&
  relayApi.includes("this._requireAuth(req, res, 'Unauthorized — subsidy destination requires API key or localhost')") &&
  relayApi.includes("this._requireAuth(req, res, 'Unauthorized — storage top requires API key or localhost')") &&
  relayApi.includes("this._requireAuth(req, res, 'Unauthorized — subsidy claim requires API key or localhost')") &&
    relayApi.includes("this._requireAuth(req, res, 'Unauthorized — API key required for /api/alerts')") &&
    relayApi.includes("this._requireAuth(req, res, 'Unauthorized — API key required for /api/health-detail')") &&
    relayApi.includes("this._requireAuth(req, res, 'Unauthorized — API key required for /api/auto-heal')") &&
    relayApi.includes("if (path === '/api/usage' && req.method === 'GET')") &&
    relayApi.includes("if (path === '/api/poker/usage' && req.method === 'GET')") &&
    relayApi.includes('if (!this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return') &&
    relayApi.includes("this._requireAuth(req, res, 'Unauthorized — API key required for /api/history')")
) {
  pass('wizard, wallet, alerts, diagnostics, usage, history, and operator telemetry auth failures use central auth metrics')
} else {
  fail('wizard, wallet, alerts, diagnostics, usage, history, or operator telemetry auth failures can bypass central auth metrics')
}

if (
  relayApi.includes("} from './api-operator-telemetry.js'") &&
  relayApi.includes('buildHealthDetailPayload({ node: this.node })') &&
  relayApi.includes('buildStorageTopPayload({ storageAccounting: this.node.storageAccounting, n })') &&
  relayApi.includes('buildAutoHealPayload({ autoHeal: this.node.autoHeal })') &&
  relayApi.includes('buildMetricsHistoryPayload({ metrics: this.node.metrics, minutes })') &&
  relayApiOperatorTelemetry.includes('export function buildHealthDetailPayload') &&
  relayApiOperatorTelemetry.includes('export function buildStorageTopPayload') &&
  relayApiOperatorTelemetry.includes('export function buildAutoHealPayload') &&
  relayApiOperatorTelemetry.includes('export function buildMetricsHistoryPayload') &&
  relayApiOperatorTelemetry.includes('MAX_OPERATOR_HEALTH_ACTIONS = 50') &&
  relayApiOperatorTelemetry.includes('MAX_OPERATOR_STORAGE_TOP_ENTRIES = 100') &&
  relayApiOperatorTelemetry.includes('MAX_OPERATOR_AUTO_HEAL_DRIVES = 256') &&
  relayApiOperatorTelemetry.includes('function buildOperatorHealthPayload') &&
  relayApiOperatorTelemetry.includes('function sanitizeStorageTopEntry') &&
  relayApiOperatorTelemetry.includes('function sanitizeAutoHealDrive') &&
  relayApiOperatorTelemetry.includes('MAX_METRICS_HISTORY_SNAPSHOTS = 1440') &&
  relayApiOperatorTelemetry.includes('function sanitizeMetricsSnapshot') &&
  relayApiOperatorTelemetry.includes('function sanitizeMetricGroup') &&
  relayApiOperatorTelemetry.includes('Number.isFinite(snapshot.timestamp)') &&
  apiOperatorTelemetryTest.includes('api operator telemetry: health detail caps and sanitizes health and self-heal actions') &&
  apiOperatorTelemetryTest.includes('api operator telemetry: storage top sanitizes summary and measured rows') &&
  apiOperatorTelemetryTest.includes('api operator telemetry: auto-heal payload distinguishes disabled and sanitizes running state') &&
  apiOperatorTelemetryTest.includes('api operator telemetry: metrics history is retention-bounded, capped, and sanitized') &&
  apiOperatorTelemetryTest.includes('MAX_OPERATOR_AUTO_HEAL_DRIVES') &&
  apiOperatorTelemetryTest.includes('MAX_OPERATOR_HEALTH_ACTIONS') &&
  apiOperatorTelemetryTest.includes('MAX_METRICS_HISTORY_SNAPSHOTS') &&
  apiAuthTest.includes('operator diagnostics require auth') &&
  apiAuthTest.includes('raw auto-heal details removed') &&
  apiAuthTest.includes('metrics history requires auth and returns shaped snapshots') &&
  auditRoadmap.includes('Metrics history snapshot sanitization') &&
  auditRoadmap.includes('Operator diagnostics snapshot sanitization')
) {
  pass('operator diagnostics payloads are extracted with direct coverage and telemetry snapshots are capped and shaped')
} else {
  fail('operator diagnostics payload shaping can regress to inline dispatcher logic or raw telemetry snapshots')
}

if (
  relayMetrics.includes('this.node.getStats({ includeSecrets: false }) || {}') &&
  relayMetrics.includes('this._buf[this._head] = this._snapshot()') &&
  relayMetrics.includes("if (typeof this.snapshotInterval.unref === 'function') this.snapshotInterval.unref()") &&
  relayMetrics.includes('function pushMetric') &&
  relayMetrics.includes('export function prometheusNumber') &&
  relayMetrics.includes('if (!Number.isFinite(number) || number < 0) return 0') &&
  relayMetrics.includes('Math.min(number, MAX_PROMETHEUS_VALUE)') &&
  relayApi.includes("import { appendVaryHeader, writeJson, writeText } from './api-response.js'") &&
  relayApi.includes('return writeText(res, this.node.metrics.toPrometheus() + this._authFailureMetricsLines())') &&
  relayApiResponse.includes('export function writeText') &&
  relayApiResponse.includes("Content-Type', 'text/plain; charset=utf-8'") &&
  metricsTest.includes('metrics: Prometheus exporter uses redacted stats and clamps sample values') &&
  metricsTest.includes('metrics: snapshots and summaries request public-redacted stats') &&
  metricsTest.includes('hiverelay_injected 1') &&
  apiResponseTest.includes('api response: writeText applies plain-text security defaults') &&
  apiAuthTest.includes('metrics endpoint disables content sniffing') &&
  apiAuthTest.includes('metrics endpoint is not cached by default') &&
  readme.includes('/metrics` exports redacted finite, no-sniff, no-store Prometheus samples') &&
  auditRoadmap.includes('Public Prometheus metrics redaction')
) {
  pass('public Prometheus metrics use redacted stats, finite samples, hardened text headers, and unref snapshot intervals')
} else {
  fail('public Prometheus metrics can regress to secret-bearing stats, malformed samples, weak text headers, or ref-held snapshot intervals')
}

if (
  relayApi.includes("} from './api-alert-management.js'") &&
  relayApi.includes('const result = buildAlertLogPayload({ alertManager: this.node.alertManager, url })') &&
  relayApi.includes('const result = runAlertTestAction({ body, alertManager: this.node.alertManager })') &&
  relayApiAlertManagement.includes("export const ALERT_SEVERITIES = ['info', 'warn', 'error', 'critical']") &&
  relayApiAlertManagement.includes('export const MAX_ALERT_TYPE_FILTER_BYTES = 80') &&
  relayApiAlertManagement.includes('export const MAX_ALERT_TEST_MESSAGE_BYTES = 512') &&
  relayApiAlertManagement.includes('export const MAX_ALERT_TEST_DETAILS_BYTES = 2048') &&
  relayApiAlertManagement.includes('type must be 1-80 bytes of letters, numbers, dot, underscore, colon, or dash') &&
  relayApiAlertManagement.includes('message must be 512 bytes or smaller') &&
  relayApiAlertManagement.includes('details must be 2048 bytes or smaller') &&
  apiAlertManagementTest.includes('api alert management: alert log validates filters and clamps pagination before lookup') &&
  apiAlertManagementTest.includes('api alert management: test alert validates body before dispatch') &&
  apiAuthTest.includes('alert test route validates body before dispatch') &&
  apiAuthTest.includes('invalid alert filters do not reach getLog') &&
  auditRoadmap.includes('Alert management route boundary')
) {
  pass('alert management routes are extracted with bounded filters and manual test payload validation')
} else {
  fail('alert management routes can regress to inline unbounded filters or oversized manual test dispatch')
}

if (
  relayApi.includes('import {\n  authFailureRoute,') &&
  relayApi.includes('_authFailureRoute (req)') &&
  relayApi.includes('return authFailureRoute(req)') &&
  relayApi.includes('_sanitizeAuthFailureRouteChars') &&
  relayApi.includes('return sanitizeAuthFailureRouteChars(value)') &&
  relayApi.includes('escapePrometheusLabelValue(route)') &&
  relayApiAuthFailures.includes('export const AUTH_FAILURE_ROUTE_SAFE_CHAR') &&
  relayApiAuthFailures.includes('export function sanitizeAuthFailureRouteChars') &&
  relayApiAuthFailures.includes('export function authFailureRoute') &&
  relayApiAuthFailures.includes("split('?')[0]") &&
  relayApiAuthFailures.includes('replace(/:\\//g, \'/\')') &&
  relayApiAuthFailures.includes('export function escapePrometheusLabelValue') &&
  relayApiAuthFailures.includes("replace(/\\n/g, '\\\\n')") &&
  apiAuthTest.includes('auth-failure route labels collapse hex ids (bounded cardinality)') &&
  apiAuthTest.includes('auth-failure route labels strip query secrets and sanitize log characters') &&
  apiAuthFailuresTest.includes('route labels strip query secrets and collapse long hex ids') &&
  apiAuthFailuresTest.includes('route labels sanitize unsafe characters and keep leading slash') &&
  apiAuthFailuresTest.includes('route labels are bounded after normalization') &&
  apiAuthFailuresTest.includes('Prometheus label values escape backslashes quotes and newlines')
) {
  pass('management API auth-failure route and Prometheus label sanitizers are extracted and directly covered')
} else {
  fail('management API auth-failure route or metric labels can leak query data or unsafe log/metric characters')
}

if (
  relayApi.includes("import { appendVaryHeader, writeJson, writeText } from './api-response.js'") &&
  relayApi.includes('return writeJson(res, data, status, headers)') &&
  bareHttpServer.includes("import { writeJson } from './api-response.js'") &&
  bareHttpServer.includes('return writeJson(res, body, status, {') &&
  bareHttpServer.includes("'Access-Control-Allow-Origin': '*'") &&
  bareHttpServer.includes("return this._json(res, doc, 200, { 'Cache-Control': 'public, max-age=60' })") &&
  bareHttpServer.includes("return this._json(res, { error: 'Not found', path }, 404)") &&
  relayApiResponse.includes('export function hasResponseHeader (res, name)') &&
  relayApiResponse.includes('export function writeJson (res, data, status = 200, headers = null)') &&
  relayApiResponse.includes('let explicitCacheControl = false') &&
  relayApiResponse.includes("if (name.toLowerCase() === 'cache-control') explicitCacheControl = true") &&
  relayApiResponse.includes("Content-Type', 'application/json; charset=utf-8'") &&
  relayApiResponse.includes("X-Content-Type-Options', 'nosniff'") &&
  relayApiResponse.includes("Cache-Control', 'no-store, max-age=0'") &&
  relayApiResponse.includes("!explicitCacheControl && !hasResponseHeader(res, 'Cache-Control')") &&
  relayApi.includes("return this._json(res, { error: 'Too many requests' }, 429, { 'Retry-After': '60' })") &&
  relayApi.includes("}, 429, { 'Retry-After': '60' })") &&
  relayApiHealth.includes("reason: 'disk-critical'") &&
  apiResponseTest.includes('writeJson applies JSON security defaults') &&
  apiResponseTest.includes('writeJson preserves explicit cache and extra headers') &&
  apiResponseTest.includes('writeJson preserves explicit cache on minimal response objects') &&
  capabilityEndpointsTest.includes('capability docs are typed as JSON') &&
  capabilityEndpointsTest.includes('JSON responses disable content sniffing') &&
  capabilityEndpointsTest.includes('error response is typed as JSON') &&
  capabilityEndpointsTest.includes('error response disables content sniffing') &&
  capabilityEndpointsTest.includes('error response is not cached by default') &&
  capabilityEndpointsTest.includes('rate-limit response is typed as JSON') &&
  capabilityEndpointsTest.includes('rate-limit response disables content sniffing') &&
  capabilityEndpointsTest.includes('rate-limit response is not cached by default') &&
  apiAuthTest.includes('disk-critical health gate returns hardened JSON 503') &&
  apiAuthTest.includes('disk-critical health is typed as JSON') &&
  apiAuthTest.includes('disk-critical health disables content sniffing') &&
  apiAuthTest.includes('disk-critical health is not cached by default') &&
  bareHttpServerTest.includes('public JSON responses use hardened headers') &&
  bareHttpServerTest.includes('capability docs preserve public cache while keeping JSON hardening') &&
  bareHttpServerTest.includes('function fakeBareRes') &&
  bareHttpServerTest.includes('404 responses use the same hardened JSON path')
) {
  pass('Node and Bare JSON responses set explicit type, nosniff, and safe cache headers')
} else {
  fail('Node or Bare JSON responses can be served without explicit type, nosniff, or safe cache headers')
}

if (
  relayApi.includes("import { buildHealthResponse } from './api-health.js'") &&
  relayApi.includes('const result = buildHealthResponse({') &&
  relayApi.includes('version: this._relayVersion()') &&
  relayApi.includes('return this._json(res, result.payload, result.status)') &&
  relayApiHealth.includes('export function diskHealthSummary') &&
  relayApiHealth.includes('MAX_HEALTH_DISK_ERROR_BYTES') &&
  relayApiHealth.includes('export function buildHealthResponse') &&
  relayApiHealth.includes('function safeDiskStatus') &&
  relayApiHealth.includes('usedPct: safeHealthNumber(disk.usedPct)') &&
  relayApiHealth.includes('status: safeDiskStatus(disk.status)') &&
  !relayApiHealth.includes('mountPath: disk.mountPath') &&
  relayApiHealth.includes('node.config?.diskHealthGate === true') &&
  relayApiHealth.includes("disk.status === 'critical'") &&
  relayApiHealth.includes("reason: 'disk-critical'") &&
  relayApiHealth.includes('disk: diskSummary') &&
  apiHealthTest.includes('api health: disk summary omits filesystem topology and caps unsafe errors') &&
  apiHealthTest.includes('api health: critical disk stays 200 unless diskHealthGate is enabled') &&
  apiHealthTest.includes('api health: diskHealthGate drains critical relays with stable fleet payload') &&
  apiHealthTest.includes('api health: missing metrics and disk monitor remain stable') &&
  apiAuthTest.includes('GET /health includes running package version') &&
  apiAuthTest.includes('disk-critical health gate returns hardened JSON 503') &&
  apiAuthTest.includes('public health does not expose disk mount path') &&
  fleetRolloutCheckTest.includes('fleet rollout check rejects updated repo with stale live health version') &&
  readme.includes('`/health` is a bounded runtime/disk-gate response without filesystem paths') &&
  auditRoadmap.includes('4.81') &&
  auditRoadmap.includes('Public health disk-path redaction') &&
  auditRoadmap.includes('api-health.js') &&
  auditDoc.includes('Extracted fleet health response policy')
) {
  pass('fleet health response policy is extracted with disk-gate, live-version, and disk-path redaction coverage')
} else {
  fail('fleet health response can drift from disk-gate, version, disk redaction, or /health rollout coverage')
}

if (
  relayApi.includes("import { runEvictionPurgeAction } from './api-eviction-purge.js'") &&
  relayApi.includes("this._requireAuth(req, res, 'Unauthorized — API key required for /api/eviction/purge')") &&
  relayApi.includes('const result = await runEvictionPurgeAction({') &&
  relayApi.includes('node: this.node') &&
  relayApiEvictionPurge.includes('export const MAX_PURGE_APP_KEYS = 50') &&
  relayApiEvictionPurge.includes("badRequest('appKeys (non-empty array) required')") &&
  relayApiEvictionPurge.includes("badRequest('max 50 appKeys per request')") &&
  relayApiEvictionPurge.includes('!isValidHexKey(appKey, 64)') &&
  relayApiEvictionPurge.includes("error: 'invalid appKey'") &&
  relayApiEvictionPurge.includes("throw new Error('manual purge unavailable')") &&
  relayApiEvictionPurge.includes('normalizeFreedBytes(out && out.bytes)') &&
  relayApiEvictionPurge.includes('freedBytes: purged.reduce((total, r) => total + normalizeFreedBytes(r.bytes), 0)') &&
  apiEvictionPurgeTest.includes('api eviction purge: validates request body before purging') &&
  apiEvictionPurgeTest.includes('api eviction purge: caps batch size before purging') &&
  apiEvictionPurgeTest.includes('api eviction purge: reports invalid keys per item and keeps valid purges moving') &&
  apiEvictionPurgeTest.includes('api eviction purge: isolates manual purge failures per key') &&
  apiEvictionPurgeTest.includes('api eviction purge: freed byte aggregation ignores malformed byte results') &&
  apiAuthTest.includes('POST /api/eviction/purge requires auth and reports mixed batch results') &&
  evictionTest.includes('assertPurgable: sacred entries refuse even operator-initiated purges') &&
  evictionTest.includes('purgeDriveCores: corrupt drive header falls back to meta-core purge') &&
  auditRoadmap.includes('api-eviction-purge.js') &&
  auditDoc.includes('Extracted operator eviction purge batch policy')
) {
  pass('operator eviction purge route is extracted with auth, batch cap, per-key error, and byte aggregation coverage')
} else {
  fail('operator eviction purge route can drift from auth, batch cap, per-key error, or byte aggregation coverage')
}

if (
  relayApi.includes("import { runLifecycleAction } from './api-lifecycle-actions.js'") &&
  relayApi.includes("action: 'restart'") &&
  relayApi.includes('emit: (...args) => this.emit(...args)') &&
  relayApi.includes("action: 'shutdown'") &&
  relayApiLifecycleActions.includes('export const LIFECYCLE_ACTION_DELAY_MS = 500') &&
  relayApiLifecycleActions.includes('export function runLifecycleAction') &&
  relayApiLifecycleActions.includes('schedule(async () => {') &&
  relayApiLifecycleActions.includes('await node.stop()') &&
  relayApiLifecycleActions.includes('await node.start()') &&
  relayApiLifecycleActions.includes("emit('error', { context: 'restart', error: err })") &&
  relayApiLifecycleActions.includes("node.emit('shutdown-complete', { clean: true })") &&
  relayApiLifecycleActions.includes("node.emit('shutdown-complete', { clean: false, error: err })") &&
  apiLifecycleActionsTest.includes('api lifecycle actions: restart schedules stop then start after response payload') &&
  apiLifecycleActionsTest.includes('api lifecycle actions: restart emits API error when stop or start fails') &&
  apiLifecycleActionsTest.includes('api lifecycle actions: shutdown schedules stop and emits clean completion') &&
  apiLifecycleActionsTest.includes('api lifecycle actions: shutdown emits unclean completion when stop fails') &&
  apiLifecycleActionsTest.includes('api lifecycle actions: unknown action is not scheduled') &&
  apiAuthTest.includes('POST /api/manage/shutdown without auth returns 401') &&
  apiAuthTest.includes('POST /api/manage/shutdown with valid Bearer token returns 200') &&
  auditRoadmap.includes('api-lifecycle-actions.js') &&
  auditDoc.includes('Extracted operator lifecycle action policy')
) {
  pass('operator lifecycle restart/shutdown actions are extracted with deferred scheduling and event coverage')
} else {
  fail('operator lifecycle restart/shutdown actions can drift from deferred scheduling or event/error semantics')
}

if (
  relayApi.includes("from './api-management-snapshots.js'") &&
  relayApi.includes('buildServiceRegistrySnapshot(this.node.serviceRegistry)') &&
  relayApi.includes('buildTransportStatusPayload(this.node)') &&
  relayApi.includes('buildDeviceStatusPayload(this.node)') &&
  relayApi.includes('buildPairingStatusPayload(this.node)') &&
  relayApi.includes("buildModeCatalogPayload(this.node._operatingMode || 'relay-core')") &&
  relayApiManagementSnapshots.includes("import { AVAILABLE_MODES } from './api-mode-transport.js'") &&
  relayApiManagementSnapshots.includes("import { sanitizeDeviceList } from './api-device-pairing.js'") &&
  relayApiManagementSnapshots.includes('export function buildServiceRegistrySnapshot') &&
  relayApiManagementSnapshots.includes('try { providerStats = provider.stats() } catch (_) {}') &&
  relayApiManagementSnapshots.includes('MAX_MANAGEMENT_SERVICE_SNAPSHOT_SERVICES = 128') &&
  relayApiManagementSnapshots.includes('MAX_MANAGEMENT_SERVICE_STATS_NODES = 256') &&
  relayApiManagementSnapshots.includes('SENSITIVE_STATS_KEY') &&
  relayApiManagementSnapshots.includes('function sanitizeStatsValue') &&
  relayApiManagementSnapshots.includes('Number.isFinite(value) ? value : undefined') &&
  relayApiManagementSnapshots.includes('export function buildTransportStatusPayload') &&
  relayApiManagementSnapshots.includes('export function buildDeviceStatusPayload') &&
  relayApiManagementSnapshots.includes('const devices = sanitizeDeviceList(source)') &&
  relayApiManagementSnapshots.includes('truncated: Array.isArray(source) && source.length > devices.length') &&
  relayApiManagementSnapshots.includes('export function buildPairingStatusPayload') &&
  relayApiManagementSnapshots.includes('expiresAt: state.expiresAt') &&
  !relayApiManagementSnapshots.includes('token: state.token') &&
  relayApiManagementSnapshots.includes('export function buildModeCatalogPayload') &&
  relayApiManagementSnapshots.includes('AVAILABLE_MODES.map') &&
  apiManagementSnapshotsTest.includes('api management snapshots: service entries prefer capabilities and isolate stats failures') &&
  apiManagementSnapshotsTest.includes('api management snapshots: service entries sanitize provider stats and noisy metadata') &&
  apiManagementSnapshotsTest.includes('MAX_MANAGEMENT_SERVICE_STATS_STRING_BYTES') &&
  apiManagementSnapshotsTest.includes('do-not-leak') &&
  apiManagementSnapshotsTest.includes('api management snapshots: transport payload reports optional runtime transports') &&
  apiManagementSnapshotsTest.includes('api management snapshots: device and pairing status avoid private state leakage') &&
  apiManagementSnapshotsTest.includes('do-not-leak-device-token') &&
  apiManagementSnapshotsTest.includes('api management snapshots: mode catalog stays aligned with switchable modes') &&
  auditRoadmap.includes('Service-management snapshot sanitization') &&
  auditRoadmap.includes('Device-management snapshot sanitization') &&
  auditRoadmap.includes('api-management-snapshots.js') &&
  auditDoc.includes('Extracted management read snapshot payloads')
) {
  pass('management read snapshot payloads are extracted with service, transport, device, pairing, mode, service-stats, and device-list sanitization coverage')
} else {
  fail('management read snapshot payloads can drift, leak private pairing/device-list state, or expose unsanitized service stats')
}

if (
  relayApi.includes("import { buildPeerListPayload } from './api-peer-state.js'") &&
  relayApi.includes('return this._json(res, buildPeerListPayload({') &&
  relayApi.includes("if (path === '/peers')") &&
  relayApi.includes('redact: this._redactPeers()') &&
  bareHttpServer.includes("import { buildPeerListPayload } from './api-peer-state.js'") &&
  bareHttpServer.includes('publicKeyAlias: true') &&
  bareHttpServer.includes('includeLastActivity: true') &&
  relayApiPeerState.includes("import { redactPubkeyHex } from '../privacy.js'") &&
  relayApiPeerState.includes('export const MAX_PEER_LIST_ENTRIES = 1000') &&
  relayApiPeerState.includes('export function buildPeerListPayload') &&
  relayApiPeerState.includes('maxPeers = MAX_PEER_LIST_ENTRIES') &&
  relayApiPeerState.includes('redact = true') &&
  relayApiPeerState.includes('const realPubkey = publicKeyHex(conn && conn.remotePublicKey)') &&
  relayApiPeerState.includes('const shownPubkey = redact ? redactPubkeyHex(realPubkey) : realPubkey') &&
  relayApiPeerState.includes('reputation.getRecord(realPubkey)') &&
  relayApiPeerState.includes('if (peers.length >= limit) continue') &&
  relayApiPeerState.includes('truncated: total > peers.length') &&
  relayApiPeerState.includes('redacted: !!redact') &&
  relayApiPeerState.includes('value.length !== 32') &&
  relayApiPeerState.includes('Buffer.from(value).toString(\'hex\')') &&
  relayApiPeerState.includes('Math.max(0, Math.floor(now - lastActivity))') &&
  relayApiPeerState.includes('Math.min(Math.floor(value), Math.floor(now))') &&
  relayApiPeerState.includes('!/^[a-z0-9_-]+$/i.test(type)') &&
  apiPeerStateTest.includes('builds stable public peer list payload') &&
  apiPeerStateTest.includes('redacts malformed peer metadata into JSON-safe fields') &&
  apiPeerStateTest.includes('tolerates absent swarm and connection maps') &&
  apiPeerStateTest.includes('redacts peer pubkeys by default (metadata minimization)') &&
  apiPeerStateTest.includes('reputation still keyed on the REAL pubkey') &&
  apiPeerStateTest.includes('supports Bare compatibility aliases without raw future timestamps') &&
  apiPeerStateTest.includes('caps public peer arrays while preserving total count') &&
  apiAuthTest.includes('legacy /peers uses capped sanitized public peer payload') &&
  auditRoadmap.includes('Public peer list bounds')
) {
  pass('public Node/Bare peer-state payload is extracted, bounded, redacted by default, and sanitizes malformed peer metadata')
} else {
  fail('public peer payloads can drift, grow unbounded, or expose malformed peer metadata across runtimes')
}

if (
  relayApi.includes("from './api-safe-config.js'") &&
  relayApi.includes('return buildSafeConfigPayload(this.node)') &&
  relayApi.includes('return snapshotWizardConfig(this.node.config)') &&
  relayApi.includes('return restoreWizardConfig(this.node.config, snapshot)') &&
  relayApiSafeConfig.includes('export function buildSafeConfigPayload') &&
  relayApiSafeConfig.includes('acceptAllowlist: Array.isArray(c.acceptAllowlist) ? c.acceptAllowlist : []') &&
  relayApiSafeConfig.includes('plugins: Array.isArray(c.plugins) ? c.plugins : []') &&
  relayApiSafeConfig.includes('discovery: c.discovery || { dht: true, announce: true, mdns: false }') &&
  relayApiSafeConfig.includes('subsidy: c.subsidy || { enabled: false, payoutDestination: null }') &&
  relayApiSafeConfig.includes("mode: node && node._operatingMode ? node._operatingMode : 'standard'") &&
  relayApiSafeConfig.includes('export function snapshotWizardConfig') &&
  relayApiSafeConfig.includes('hasRegistryAutoAccept: Object.prototype.hasOwnProperty.call(config, \'registryAutoAccept\')') &&
  relayApiSafeConfig.includes('export function restoreWizardConfig') &&
  !relayApiSafeConfig.includes('apiKey') &&
  !relayApiSafeConfig.includes('connectionKey') &&
  !relayApiSafeConfig.includes('onionAddress') &&
  !relayApiSafeConfig.includes('pairingToken') &&
  !relayApiSafeConfig.includes('privateKey') &&
  apiSafeConfigTest.includes('api safe config: emits only operator-safe persisted config fields') &&
  apiSafeConfigTest.includes('api safe config: normalizes missing arrays and nested defaults') &&
  apiSafeConfigTest.includes('api safe config: wizard snapshot and restore preserves missing fields') &&
  apiSafeConfigTest.includes('api safe config: wizard restore removes fields absent from snapshot') &&
  auditRoadmap.includes('api-safe-config.js') &&
  auditDoc.includes('Extracted operator-safe config payload')
) {
  pass('operator safe-config payload and wizard rollback snapshots are extracted with secret-omission coverage')
} else {
  fail('operator safe-config payload can drift, leak secrets, or lose wizard rollback semantics')
}

if (
  relayNode.includes('function identityTempPath (keyPath)') &&
  relayNode.includes('sodium.randombytes_buf(suffix)') &&
  relayNode.includes('const tmpPath = identityTempPath(keyPath)') &&
  relayNode.includes('await writeFile(tmpPath, JSON.stringify({') &&
  relayNode.includes('}, null, 2), { mode: 0o600 })') &&
  relayNode.includes('await chmod(tmpPath, 0o600)') &&
  relayNode.includes('await rename(tmpPath, keyPath)') &&
  relayNode.includes('try { await unlink(tmpPath) } catch (_) {}') &&
  bareRelay.includes('function identityTempPath (keyPath)') &&
  bareRelay.includes('sodium.randombytes_buf(suffix)') &&
  bareRelay.includes('const tmpPath = identityTempPath(keyPath)') &&
  !bareRelay.includes('process.pid') &&
  bareRelay.includes('await writeFile(tmpPath, b4a.toString(seed, \'hex\'), { mode: 0o600 })') &&
  bareRelay.includes('await chmod(tmpPath, 0o600)') &&
  bareRelay.includes('await rename(tmpPath, keyPath)') &&
  bareRelay.includes('try { await unlink(tmpPath) } catch (_) {}') &&
  relayNodeTest.includes('identity file is created owner-only and reloads') &&
  relayNodeTest.includes('relay identity is owner-read/write only') &&
  bareRelaySurfaceTest.includes('identity seed file is created owner-only and reloads') &&
  bareRelaySurfaceTest.includes('Bare identity seed is owner-read/write only') &&
  bareRelaySurfaceTest.includes('identity temp path avoids Node-only process globals')
) {
  pass('RelayNode and BareRelay create identity secret files atomically with owner-only permissions')
} else {
  fail('relay identity secret files can still be created with broad permissions or non-atomic writes')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['test:bare'] &&
  monorepoPkg.scripts['test:bare'].includes('node_modules/bare/bin') &&
  monorepoPkg.scripts['test:bare'].includes('brittle-bare test/bare/index.js') &&
  bareRuntimeTest.includes('BareRelay imports via the bare condition of the imports map') &&
  bareRuntimeTest.includes('which-runtime reports isBare === true') &&
  !federationCore.includes("import https from 'https'") &&
  federationCore.includes('typeof globalThis.fetch ===')
) {
  pass('Bare runtime smoke test is runnable locally and federation avoids Node-only https imports')
} else {
  fail('Bare runtime smoke test or federation imports can regress to Node-only behavior')
}

if (
  relayApi.includes('_queryInt (url, name, defaultValue, min, max)') &&
  relayApi.includes('return queryInt(url, name, defaultValue, min, max)') &&
  relayApiValidation.includes('export function queryInt') &&
  relayApiValidation.includes('Number.isSafeInteger(parsed)') &&
  relayApiCatalogRead.includes("queryInt(parsed, 'page', 1, 1, 1_000_000)") &&
  relayApiCatalogRead.includes("queryInt(parsed, 'pageSize', 50, 1, maxPageSize)") &&
  relayApiCatalogRead.includes('RELAY_CATALOG_PAGE_SIZE_MAX = 500') &&
  relayApiAlertManagement.includes("queryInt(parsed, 'offset', 0, 0, 10_000)") &&
  relayApiAlertManagement.includes("queryInt(parsed, 'limit', 50, 1, 500)") &&
  relayApi.includes("this._queryInt(url, 'n', 30, 1, 100)") &&
  relayApi.includes("this._queryInt(url, 'minutes', 60, 1, 24 * 60)") &&
  apiAuthTest.includes('alert pagination query values are clamped before log lookup') &&
  apiAuthTest.includes('metrics history minutes query is clamped to metrics retention') &&
  apiValidationTest.includes('queryInt clamps safe integers and defaults malformed values') &&
  apiValidationTest.includes('queryInt clamps unsafe negative integers to min')
) {
  pass('management API clamps malformed and oversized integer query parameters for operator endpoints')
} else {
  fail('management API integer query parameters can still be malformed, negative, or unbounded')
}

if (
  relayApi.includes("import { runConfigUpdateAction } from './api-config-update.js'") &&
  relayApi.includes('const result = await runConfigUpdateAction({') &&
  relayApiValidation.includes('export function validatePositiveInt') &&
  relayApiValidation.includes('export function validatePositiveNumber') &&
  relayApiValidation.includes('if (!/^\\d+$/.test(text))') &&
  relayApiValidation.includes('if (!/^-?(?:\\d+(?:\\.\\d+)?|\\.\\d+)$/.test(text))') &&
  relayApiValidation.includes('!Number.isSafeInteger(parsed)') &&
  relayApiConfigUpdate.includes('export async function runConfigUpdateAction') &&
  relayApiConfigUpdate.includes('function rollbackApplied') &&
  relayApiConfigUpdate.includes('function validateRegions') &&
  relayApiConfigUpdate.includes('function objectRecord') &&
  relayApiConfigUpdate.includes('function validateBooleanField') &&
  relayApiConfigUpdate.includes('regions must be an array of strings') &&
  relayApiConfigUpdate.includes('field} must be an object') &&
  relayApiConfigUpdate.includes('must be a boolean') &&
  relayApiConfigUpdate.includes('rollback()') &&
  relayApiConfigUpdate.includes('const result = validatePositiveInt(body[field], bounds.min, bounds.max, field)') &&
  relayApiConfigUpdate.includes("const result = validatePositiveNumber(body.maxRelayBandwidthMbps, 0.1, 100000, 'maxRelayBandwidthMbps')") &&
  relayApiModeTransport.includes("const result = validatePositiveInt(body.maxConnections, 0, 100000, 'maxConnections')") &&
  relayApiModeTransport.includes("const result = validatePositiveNumber(body.maxRelayBandwidthMbps, 0, 100000, 'maxRelayBandwidthMbps')") &&
  relayApiModeTransport.includes("const result = validatePositiveInt(body.maxStorageBytes, 0, 10e12, 'maxStorageBytes')") &&
  relayApi.includes('runDeviceManagementAction') &&
  relayApi.includes('runPairingManagementAction') &&
  relayApi.includes("from './api-device-pairing.js'") &&
  relayApiDevicePairing.includes("const result = validatePositiveInt(body.timeoutMs, 10_000, 30 * 60 * 1000, 'timeoutMs')") &&
  apiConfigUpdateTest.includes('api config update: rejects malformed integers and rolls back earlier fields') &&
  apiConfigUpdateTest.includes('api config update: rejects malformed decimals and rolls back earlier fields') &&
  apiConfigUpdateTest.includes('api config update: rejects malformed regions and nested object fields without mutation') &&
  apiConfigUpdateTest.includes('registryAutoAccept must be a boolean') &&
  apiConfigUpdateTest.includes('requireSignedCatalog must be a boolean') &&
  apiConfigUpdateTest.includes('api config update: persistence failure rolls back all applied fields') &&
  apiDevicePairingTest.includes('api device pairing: validates pairing actions before state changes') &&
  apiServiceConfigTest.includes('config management api: rejects malformed integer strings and rolls back earlier fields') &&
  apiServiceConfigTest.includes('config management api: rejects malformed decimal strings and rolls back earlier fields') &&
  apiServiceConfigTest.includes('config management api: rejects malformed boolean fields before mutation') &&
  apiServiceConfigTest.includes('mode management api: rejects malformed integer overrides before applying mode') &&
  apiServiceConfigTest.includes('mode management api: rejects malformed bandwidth override before applying mode') &&
  apiServiceConfigTest.includes('pairing management api: rejects malformed timeout before enabling pairing') &&
  apiValidationTest.includes('validatePositiveInt accepts plain decimal integers only') &&
  apiValidationTest.includes('validatePositiveNumber accepts plain decimals and rejects exponent/unsafe values')
) {
  pass('management API rejects malformed numeric, boolean, array, and object write fields without partial in-memory config drift')
} else {
  fail('management API writes can accept malformed numeric/boolean/array/object values or partially mutate config before rejection')
}

if (
  gatewayServer.includes('opts.gatewayPort ?? DEFAULT_GATEWAY_PORT') &&
  gatewayServer.includes('_activeSockets = new Set()') &&
  gatewayServer.includes("this.server.on('connection'") &&
  gatewayServer.includes("import { buildGatewayCatalogPayload } from './api-catalog-read.js'") &&
  gatewayServer.includes("import { writeJson } from './api-response.js'") &&
  gatewayServer.includes('const result = buildGatewayCatalogPayload({ node: this.node, url })') &&
  gatewayServer.includes("writeJson(res, { error: 'Too many requests' }, 429, { 'Retry-After': '60' })") &&
  gatewayServer.includes("writeJson(res, { error: 'Invalid URL' }, 400)") &&
  gatewayServer.includes("writeJson(res, { ok: true, service: 'gateway' })") &&
  gatewayServer.includes("writeJson(res, { error: 'Not found' }, 404)") &&
  gatewayServer.includes("writeJson(res, { error: 'Internal error' }, 500)") &&
  gatewayServer.includes("writeJson(res, result.payload, 200, { 'Cache-Control': 'public, max-age=30' })") &&
  !gatewayServer.includes('res.end(JSON.stringify') &&
  bareHttpServer.includes("import { buildRelayCatalogPayload } from './api-catalog-read.js'") &&
  bareHttpServer.includes("if (path === '/catalog.json')") &&
  bareHttpServer.includes('const result = this._catalog(url)') &&
  bareHttpServer.includes('return buildRelayCatalogPayload({') &&
  bareHttpServer.includes('relayKey') &&
  !bareHttpServer.includes('const buckets = { apps: [], drives: [], resources: [], datasets: [], media: [] }') &&
  relayApiCatalogRead.includes("import { buildFederationSnapshotPayload } from './api-federation-management.js'") &&
  relayApiCatalogRead.includes('export const GATEWAY_CATALOG_PAGE_SIZE_MAX = 200') &&
  relayApiCatalogRead.includes('CATALOG_TYPE_ERROR') &&
  relayApiCatalogRead.includes("const CATALOG_ACCEPT_MODES = ['open', 'review', 'allowlist', 'closed']") &&
  relayApiCatalogRead.includes('const MAX_CATALOG_LABEL_BYTES = 128') &&
  relayApiCatalogRead.includes("queryInt(parsed, 'page', 1, 1, 1_000_000)") &&
  relayApiCatalogRead.includes("queryInt(parsed, 'pageSize', 50, 1, maxPageSize)") &&
  relayApiCatalogRead.includes('relayKey: safeCatalogHexKey(relayKey)') &&
  relayApiCatalogRead.includes('region: safeCatalogLabel(node?.config?.regions?.[0])') &&
  relayApiCatalogRead.includes('operator: safeCatalogLabel(node?.config?.operator)') &&
  relayApiCatalogRead.includes('acceptMode: safeCatalogAcceptMode') &&
  relayApiCatalogRead.includes('function safeCatalogHexKey') &&
  relayApiCatalogRead.includes('function safeCatalogLabel') &&
  relayApiCatalogRead.includes('function safeCatalogAcceptMode') &&
  relayApiCatalogRead.includes('export function catalogEntriesByType ({ node, type, url, maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX } = {})') &&
  relayApiCatalogRead.includes("const pageSize = queryInt(parsed, 'pageSize', maxPageSize, 1, maxPageSize)") &&
  relayApiCatalogRead.includes('federation: federationCatalogSnapshot(node)') &&
  relayApiCatalogRead.includes('function federationCatalogSnapshot') &&
  relayApiCatalogRead.includes('buildFederationSnapshotPayload({ federation: node.federation })') &&
  !relayApiCatalogRead.includes('federation: node?.federation ? node.federation.snapshot() : null') &&
  relayApiCatalogRead.includes('pageCatalogEntries') &&
  relayApiCatalogRead.includes('catalogBeeKey') &&
  relayApi.includes("catalogEntriesByType({ node: this.node, type: 'app', url })") &&
  relayApi.includes("catalogEntriesByType({ node: this.node, type: 'drive', url })") &&
  relayApiValidation.includes('export function queryInt') &&
  relayApiValidation.includes('!Number.isSafeInteger(parsed)') &&
  gatewayServer.includes('closeAllConnections') &&
  gatewayServer.includes('socket.destroy()') &&
  gatewayServer.includes('const RATE_LIMIT_MAX_BUCKETS = 50_000') &&
  gatewayServer.includes('this._maxRateLimitBuckets = positiveInteger(opts.maxRateLimitBuckets, RATE_LIMIT_MAX_BUCKETS)') &&
  gatewayServer.includes('if (!entry && this._rateLimits.size >= this._maxRateLimitBuckets)') &&
  gatewayServer.includes('this._sweepRateLimits(now)') &&
  gatewayServer.includes('if (this._rateLimits.size >= this._maxRateLimitBuckets) return false') &&
  gatewayServer.includes('!Number.isFinite(entry.count)') &&
  gatewayServer.includes('!Number.isFinite(entry.resetAt)') &&
  gatewayServer.includes('function positiveInteger') &&
  apiCatalogReadTest.includes('relay catalog filters, counts, and paginates in one bounded helper') &&
  apiCatalogReadTest.includes('relay catalog sanitizes top-level public metadata') &&
  apiCatalogReadTest.includes('invalid types are rejected instead of widening public catalog reads') &&
  apiCatalogReadTest.includes('relay catalog sanitizes federation snapshot before public response') &&
  apiCatalogReadTest.includes('user:pass') &&
  apiCatalogReadTest.includes('rawCatalog') &&
  apiCatalogReadTest.includes('gateway catalog keeps its legacy shape and valid catalogBeeKey advertisement') &&
  apiCatalogReadTest.includes('legacy type arrays are bounded and paginated') &&
  apiAuthTest.includes('legacy catalog type routes are bounded and paginated') &&
  gatewayServerTest.includes('catalog pagination uses strict bounded integer parsing') &&
  gatewayServerTest.includes('invalid catalog type filter returns 400 instead of broadening response') &&
  gatewayServerTest.includes('JSON responses use hardened headers and explicit catalog cache') &&
  gatewayServerTest.includes('rate limit buckets reject new IPs at cap') &&
  gatewayServerTest.includes('rate limit bucket cap prunes stale buckets before rejecting new IPs') &&
  gatewayServerTest.includes('malformed rate limit buckets reset instead of poisoning an IP') &&
  gatewayServerTest.includes('stop force-closes held client sockets') &&
  bareHttpServerTest.includes('bare http server: catalog route reuses bounded relay catalog helper') &&
  bareHttpServerTest.includes('bare http server: catalog route rejects invalid type filters') &&
  readme.includes('public bounded catalog on Node, Bare, and data-plane gateway surfaces with sanitized top-level metadata and federation snapshot') &&
  readme.includes('legacy typed arrays are capped and paginated') &&
  auditRoadmap.includes('Bare catalog pagination parity') &&
  auditRoadmap.includes('Legacy catalog type-route bounds') &&
  auditRoadmap.includes('Public catalog federation snapshot sanitization') &&
  auditRoadmap.includes('Public catalog metadata sanitization') &&
  auditRoadmap.includes('Data-plane gateway JSON response hygiene') &&
  auditRoadmap.includes('Data-plane gateway rate-limit bucket cap')
) {
  pass('public catalog reads share bounded Node/Bare/legacy pagination, fail-closed type filters, hardened data-plane JSON, capped rate-limit buckets, and gateway force-close shutdown')
} else {
  fail('public catalog reads can drift to duplicated permissive parsing, unbounded pagination, weak data-plane JSON headers, unbounded gateway rate-limit buckets, or hanging gateway shutdown')
}

const gatewayStatsRouteStart = relayApi.indexOf("path === '/api/gateway'")
const gatewayStatsRouteBlock = relayApi.slice(
  gatewayStatsRouteStart,
  relayApi.indexOf('// Catalog endpoint', gatewayStatsRouteStart)
)
if (
  relayApi.includes("import {\n  buildGatewayStatsPayload,\n  sanitizeGatewayStats\n} from './api-gateway-stats.js'") &&
  gatewayStatsRouteBlock.includes('const result = buildGatewayStatsPayload({ gateway: this._gateway })') &&
  !gatewayStatsRouteBlock.includes('this._gateway.getStats()') &&
  relayApi.includes('gateway: this._gateway ? sanitizeGatewayStats(this._gateway.getStats()) : null') &&
  relayApiGatewayStats.includes('export function sanitizeGatewayStats') &&
  relayApiGatewayStats.includes('cachedDrives: safeCounter(stats && stats.cachedDrives)') &&
  relayApiGatewayStats.includes('totalRequests: safeCounter(stats && stats.totalRequests)') &&
  relayApiGatewayStats.includes('totalBytesServed: safeCounter(stats && stats.totalBytesServed)') &&
  relayApiGatewayStats.includes('...stats') === false &&
  standaloneGatewayServer.includes("import { sanitizeGatewayStats } from '../core/relay-node/api-gateway-stats.js'") &&
  standaloneGatewayServer.includes('...sanitizeGatewayStats(gateway.getStats())') &&
  apiGatewayStatsTest.includes('sanitizes public counters without raw fields') &&
  apiAuthTest.includes('GET /api/gateway returns sanitized public gateway stats') &&
  apiAuthTest.includes('overview gateway stats are sanitized') &&
  auditRoadmap.includes('Gateway stats read boundary')
) {
  pass('public gateway stats are extracted and sanitized across embedded and standalone gateway surfaces')
} else {
  fail('public gateway stats can regress to raw gateway.getStats() spreading or private-field exposure')
}

if (
  standaloneGatewayServer.includes("import { RELAY_DISCOVERY_TOPIC } from '../core/constants.js'") &&
  standaloneGatewayServer.includes("import { readJsonBody } from '../core/relay-node/api-body.js'") &&
  standaloneGatewayServer.includes("import { getPostJsonContentTypeProblem } from '../core/relay-node/api-request.js'") &&
  standaloneGatewayServer.includes("import { writeJson } from '../core/relay-node/api-response.js'") &&
  standaloneGatewayServer.includes('MAX_GATEWAY_SEED_BODY_BYTES = 4096') &&
  standaloneGatewayServer.includes('export function validateGatewaySeedKey') &&
  standaloneGatewayServer.includes('/^[0-9a-f]{64}$/i.test(key)') &&
  standaloneGatewayServer.includes('export function buildGatewaySeedErrorResponse') &&
  standaloneGatewayServer.includes('export async function readGatewaySeedBody') &&
  standaloneGatewayServer.includes('readJsonBody(req, MAX_GATEWAY_SEED_BODY_BYTES)') &&
  standaloneGatewayServer.includes("payload: { error: 'Gateway seed failed' }") &&
  standaloneGatewayServer.includes("err.message === 'Request body too large' ? 413 : 400") &&
  standaloneGatewayServer.includes('const { key } = await readGatewaySeedBody(req)') &&
  standaloneGatewayServer.includes('writeJson(res, { ok: true, seeding: key })') &&
  !standaloneGatewayServer.includes('res.end(JSON.stringify') &&
  standaloneGatewayServer.includes('const seedKeys = args.filter(a => /^[a-f0-9]{64}$/i.test(a))') &&
  standaloneGatewayServerTest.includes('standalone gateway seed body validates 64-hex keys') &&
  standaloneGatewayServerTest.includes('standalone gateway seed body rejects non-json media types before parsing') &&
  standaloneGatewayServerTest.includes('standalone gateway seed body rejects oversized and non-object JSON bodies') &&
  standaloneGatewayServerTest.includes('standalone gateway seed errors redact unexpected internals')
) {
  pass('standalone gateway seed endpoint uses bounded parsing, strict media type, exact keys, hardened JSON, and redacted internal errors')
} else {
  fail('standalone gateway seed endpoint can drift to broken imports, unbounded parsing, permissive keys, weak JSON headers, or raw internal errors')
}

if (
  hyperGateway.includes("if (req.method !== 'GET' && req.method !== 'HEAD')") &&
  hyperGateway.includes("res.setHeader('Allow', 'GET, HEAD')") &&
  hyperGateway.includes('function parseBytePosition') &&
  hyperGateway.includes('function parseByteCount') &&
  hyperGateway.includes('Number.isSafeInteger(n)') &&
  hyperGateway.includes('function decodePathComponent') &&
  hyperGateway.includes("error: 'Malformed path encoding'") &&
  hyperGateway.includes('clearTimeout(timer)') &&
  hyperGateway.includes('if (timer.unref) timer.unref()') &&
  hyperGateway.includes('function writeGatewayJson') &&
  hyperGateway.includes("res.setHeader('Content-Type', 'application/json; charset=utf-8')") &&
  hyperGateway.includes("res.setHeader('X-Content-Type-Options', 'nosniff')") &&
  hyperGateway.includes("res.setHeader('Cache-Control', 'no-store, max-age=0')") &&
  hyperGateway.includes("error: 'Gateway read failed'") &&
  hyperGateway.includes("error: 'Gateway stream failed'") &&
  !hyperGateway.includes('JSON.stringify({ error: err.message })') &&
  !hyperGateway.includes('const suffix = Number(endStr)') &&
  !hyperGateway.includes('start = Number(startStr)') &&
  hyperGatewayHardeningTest.includes('rejects unsupported methods before serving content') &&
  hyperGatewayHardeningTest.includes('public drive failures are redacted and use hardened JSON errors') &&
  hyperGatewayHardeningTest.includes('successful drive timeouts clear their timer handles') &&
  hyperGatewayHardeningTest.includes('malformed path encoding returns 400 instead of surfacing a 500') &&
  hyperGatewayHardeningTest.includes('double-encoded traversal remains forbidden') &&
  hyperGatewayHardeningTest.includes('byte ranges reject permissive JavaScript number syntax') &&
  hyperGatewayHardeningTest.includes('unsupported range units and multi-ranges are ignored as full responses')
) {
  pass('Hyperdrive HTTP gateway rejects malformed paths, redacts internal errors, hardens JSON responses, and bounds range/timeouts')
} else {
  fail('Hyperdrive HTTP gateway can accept unsafe methods, leak raw errors, emit weak JSON errors, accept permissive ranges, or leave stale timeout handles')
}

const persistGuardUses = (relayApi.match(/_persistConfigOrRespond\(res/g) || []).length
if (
  errorPrefixes.includes("PERSIST_FAILED: 'persist-failed: '") &&
  errorPrefixes.includes("NOT_ENABLED: 'not-enabled: '") &&
  errorPrefixesTest.includes("formatErr('NOT_ENABLED', 'service disabled')") &&
  errorPrefixesTest.includes("classifyErr('not-enabled: service disabled')") &&
  relayApi.includes("formatErr('PERSIST_FAILED'") &&
  relayApi.includes("formatErr('NOT_ENABLED', 'poker service is not enabled on this relay')") &&
  relayApiSubsidy.includes("formatErr('NOT_ENABLED', 'subsidy is not enabled on this relay')") &&
  relayApi.includes("errorCode: 'persist-failed'") &&
  relayApi.includes("this.emit('config-persist-error'") &&
  relayApi.includes("this.emit('config-rollback-error'") &&
  relayApi.includes('WIZARD_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes('SUBSIDY_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes("this.emit('wizard-persist-error'") &&
  relayApi.includes("this.emit('subsidy-persist-error'") &&
  relayApi.includes('return saveConfig(this._getSafeConfig())') &&
  relayApi.includes('throw err') &&
  relayApi.includes('_snapshotWizardConfig') &&
  relayApi.includes('_restoreWizardConfig') &&
  relayApiWizardActions.includes('await persistConfig()') &&
  relayApiWizardActions.includes('await persistConfigRollback({ persistConfig, emit })') &&
  apiWizardActionsTest.includes('api wizard actions: config persistence failure restores wizard and config') &&
  apiWizardActionsTest.includes('api wizard actions: wizard save failure after config persist rolls back config') &&
  relayApiConfigUpdate.includes('await persistConfig()') &&
  relayApiConfigUpdate.includes("return { ok: false, kind: 'config-persist', error: err }") &&
  relayApiConfigUpdate.includes('rollbackApplied({ applied, config, previousConfig })') &&
  apiConfigUpdateTest.includes('api config update: persistence failure rolls back all applied fields') &&
  relayApiServiceManagement.includes('await persistConfig()') &&
  relayApiServiceManagement.includes("return { ok: false, kind: 'config-persist', error: err }") &&
  relayApiServiceManagement.includes('config.plugins = previousPlugins') &&
  relayApiServiceManagement.includes('config.enableServices = previousEnableServices') &&
  relayApi.includes("if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)") &&
  apiServiceManagementTest.includes('api service management: disable rolls back config when persistence fails') &&
  apiServiceConfigTest.includes('service management api: disable rolls back configured plugins when persistence fails') &&
  relayApiModeTransport.includes('await persistConfig()') &&
  relayApiModeTransport.includes("return { ok: false, kind: 'config-persist', error: err }") &&
  relayApiModeTransport.includes('node.config = previousConfig') &&
  relayApiModeTransport.includes('delete config.transports') &&
  apiModeTransportTest.includes('api mode transport: rolls back mode when persistence fails') &&
  apiModeTransportTest.includes('api mode transport: persists transport toggles and rolls back failures') &&
  relayApiSubsidy.includes('const wizardSnapshot = snapshotWizardState(wizard)') &&
  relayApiSubsidy.includes('restoreWizardState(wizard, wizardSnapshot)') &&
  relayApiSubsidy.includes('await saveWizardRollback(wizard, wizardSaved, emit)') &&
  apiSubsidyTest.includes('api subsidy: wizard save failures restore config and wizard state') &&
  apiSubsidyTest.includes('api subsidy: config persist failures restore runtime state and wizard file') &&
  apiSubsidyTest.includes('api subsidy: live accrual failures restore persisted config and emit rollback drift') &&
  relayApi.includes('buildPendingCatalogPayload,') &&
  relayApi.includes('runCatalogAllowlistAction,') &&
  relayApi.includes('return this._json(res, buildPendingCatalogPayload({') &&
  relayApi.includes('return this._handleCatalogMode(res, body)') &&
  relayApi.includes('return this._handleCatalogAllowlist(res, body)') &&
  relayApi.includes("return this._handleCatalogAppAction(res, 'remove', body)") &&
  relayApiCatalogManagement.includes('export function buildPendingCatalogPayload') &&
  relayApiCatalogManagement.includes('function buildPendingCatalogRequest') &&
  relayApiCatalogManagement.includes('export async function runCatalogModeAction') &&
  relayApiCatalogManagement.includes('export async function runLegacyAutoAcceptAction') &&
  relayApiCatalogManagement.includes('export async function runCatalogAllowlistAction') &&
  relayApiCatalogManagement.includes('export async function runCatalogAppAction') &&
  relayApiCatalogManagement.includes('export async function runRegistryCancelAction') &&
  relayApiCatalogManagement.includes('function validateBooleanField') &&
  relayApiCatalogManagement.includes("validateBooleanField(body.enabled, 'enabled')") &&
  relayApiCatalogManagement.includes('delete config.registryAutoAccept // disambiguate') &&
  relayApiCatalogManagement.includes('restoreAcceptModeConfig(config, snapshot, emit)') &&
  relayApiSafeConfig.includes('acceptAllowlist: Array.isArray(c.acceptAllowlist) ? c.acceptAllowlist : []') &&
  relayApiCatalogManagement.includes('config.acceptAllowlist = body.allowlist') &&
  relayApiCatalogManagement.includes('restoreAllowlistConfig(config, snapshot, emit)') &&
  relayApiCatalogManagement.includes('await persistConfig()') &&
  relayApiCatalogManagement.includes("return { ok: false, kind: 'config-persist', error: err }") &&
  apiCatalogManagementTest.includes('api catalog management: mode persists accept mode and rolls back failures') &&
  apiCatalogManagementTest.includes('api catalog management: legacy auto-accept persists alias and rolls back failures') &&
  apiCatalogManagementTest.includes('enabled must be a boolean') &&
  apiCatalogManagementTest.includes('api catalog management: allowlist normalizes, de-duplicates, and rolls back failures') &&
  apiCatalogManagementTest.includes('api catalog management: app actions validate keys and call node operations') &&
  apiCatalogManagementTest.includes('api catalog management: registry cancel keeps readiness and pubkey behavior') &&
  apiCatalogManagementTest.includes('api catalog management: pending payload uses a stable public schema') &&
  apiCatalogManagementTest.includes('map key remains canonical') &&
  apiAuthTest.includes('api-auth: GET /api/registry/pending returns sanitized pending queue') &&
  relayApiModeTransport.includes('const previousConfig = node.config') &&
  relayApiModeTransport.includes('node.config = previousConfig') &&
  relayApiModeTransport.includes("if (node.running && typeof node._syncAccessControl === 'function')") &&
  relayApiModeTransport.includes("RESERVED_TRANSPORT_NAMES = new Set(['__proto__', 'constructor', 'prototype'])") &&
  relayApiModeTransport.includes('const previousTransports = config.transports && typeof config.transports === \'object\'') &&
  apiServiceConfigTest.includes('registryAutoAccept must be a boolean') &&
  apiServiceConfigTest.includes('enabled must be a boolean') &&
  apiServiceConfigTest.includes('wallet destination api: wizard persistence failure rolls back config before success') &&
  apiServiceConfigTest.includes('wallet destination api: config persistence failure restores saved wizard state') &&
  apiServiceConfigTest.includes('wallet destination api: live subsidy persistence failure rolls back config and wizard files') &&
  subsidyCore.includes('_persist ({ throwOnError = false } = {})') &&
  subsidyCore.includes('return throwOnError ? write : this._persisting') &&
  subsidyCore.includes('this.payoutDestination = previous') &&
  subsidyCore.includes("this.emit('persist-error'") &&
  subsidyTest.includes('setPayoutDestination: persistence failure rejects and keeps previous value') &&
  !relayApi.includes('_persistConfig().catch') &&
  relayNode.includes('delete this.config.registryAutoAccept') &&
  persistGuardUses >= 1
) {
  pass('management API reports config, wizard, and subsidy persistence failures before UI save success, rolls back failed service/wallet/wizard/mode saves, and sanitizes pending catalog reads')
} else {
  fail('management API can still hide config persistence failures from UI save flows or expose raw pending catalog entries')
}

const registryStatusRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/api/registry'"),
  relayApi.indexOf("path === '/api/reputation'")
)
if (
  relayApi.includes("import { buildRegistryStatusPayload } from './api-registry-status.js'") &&
  registryStatusRouteBlock.includes('const result = await buildRegistryStatusPayload({ registry: this.node.seedingRegistry })') &&
  !registryStatusRouteBlock.includes('...req') &&
  !registryStatusRouteBlock.includes('for (const req of requests)') &&
  relayApiRegistryStatus.includes('export const MAX_REGISTRY_STATUS_REQUESTS = 500') &&
  relayApiRegistryStatus.includes('export const MAX_REGISTRY_STATUS_RELAYS_PER_REQUEST = 100') &&
  relayApiRegistryStatus.includes('source.slice(0, requestLimit)') &&
  relayApiRegistryStatus.includes('relays.slice(0, relayLimit).map(sanitizeRelay)') &&
  relayApiRegistryStatus.includes('relaysTruncated: relays.length > relayItems.length') &&
  relayApiRegistryStatus.includes('publisherSignature') === false &&
  apiRegistryStatusTest.includes('sanitizes request fields and relay metadata') &&
  apiRegistryStatusTest.includes('caps request enrichment and per-request relays') &&
  apiAuthTest.includes('GET /api/registry requires auth and returns bounded sanitized status') &&
  auditRoadmap.includes('Registry status read boundary')
) {
  pass('registry status reads are extracted with bounded enrichment and sanitized operator payloads')
} else {
  fail('registry status reads can regress to raw request spreading or unbounded relay enrichment')
}

const reputationReadRouteStart = relayApi.indexOf("path === '/api/reputation'")
const reputationReadRouteBlock = relayApi.slice(
  reputationReadRouteStart,
  relayApi.indexOf('// ─── Services & Router', reputationReadRouteStart)
)
if (
  relayApi.includes('buildReputationLeaderboardPayload,\n  buildReputationRecordPayload') &&
  reputationReadRouteBlock.includes('const result = buildReputationLeaderboardPayload({ reputation: this.node.reputation })') &&
  reputationReadRouteBlock.includes('const result = buildReputationRecordPayload({') &&
  !reputationReadRouteBlock.includes('getLeaderboard(100)') &&
  !reputationReadRouteBlock.includes('getRecord(pubkey)') &&
  relayApiReputationRead.includes('export const MAX_REPUTATION_LEADERBOARD_ENTRIES = 100') &&
  relayApiReputationRead.includes('source.slice(0, limit)') &&
  relayApiReputationRead.includes('export function sanitizeReputationRecord') &&
  relayApiReputationRead.includes('secretToken') === false &&
  relayApiReputationRead.includes('...record') === false &&
  relayApiPeerState.includes("import { sanitizeReputationRecord } from './api-reputation-read.js'") &&
  relayApiPeerState.includes('peer.reputation = sanitizeReputationRecord(reputation.getRecord(realPubkey))') &&
  apiReputationReadTest.includes('sanitizes direct records without raw store fields') &&
  apiReputationReadTest.includes('caps and sanitizes leaderboard rows') &&
  apiPeerStateTest.includes('raw reputation fields are omitted') &&
  apiPeerStateTest.includes('reputation still keyed on the REAL pubkey') &&
  apiAuthTest.includes('GET /api/reputation returns bounded sanitized public leaderboard') &&
  apiAuthTest.includes('GET /api/reputation/:pubkey returns sanitized public record') &&
  auditRoadmap.includes('Reputation read boundary')
) {
  pass('public reputation reads and peer decorations are extracted with capped sanitized payloads and real-key lookups behind redacted public IDs')
} else {
  fail('public reputation reads can regress to raw records or unbounded leaderboard output')
}

const federationPersistFalseUses = (relayApiFederationManagement.match(/persist: false/g) || []).length
if (
  federationCore.includes('async save ({ throwOnError = false } = {})') &&
  federationCore.includes('restoreSnapshot (snapshot = {})') &&
  federationCore.includes('_syncPollTimer ()') &&
  federationCore.includes('this.node._addPendingRequest(appKey, pendingEntry)') &&
  federationCore.includes('_addPendingRequestFallback (appKey, entry)') &&
  federationCore.includes("this.emit('federation-queued', { appKey, source: entry.url })") &&
  federationCore.includes('MAX_FEDERATION_JSON_BYTES') &&
  federationCore.includes('_fetchJsonTarget (target)') &&
  federationCore.includes('_fetchJsonTargetWithFetch (parsed)') &&
  federationCore.includes('_fetchJsonTargetWithHttp (parsed)') &&
  federationCore.includes('function utf8ByteLength (text)') &&
  federationCore.includes('typeof globalThis.fetch ===') &&
  !federationCore.includes("import https from 'https'") &&
  federationCore.includes('contentLength > MAX_FEDERATION_JSON_BYTES') &&
  relayApi.includes('FEDERATION_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes('buildFederationSnapshotPayload,\n  runFederationManagementAction') &&
  relayApi.includes('const result = buildFederationSnapshotPayload({ federation: this.node.federation })') &&
  relayApi.includes('const result = await runFederationManagementAction({') &&
  relayApi.includes("this.emit('federation-persist-error'") &&
  relayApi.includes('_federationPersistErrorResponse(res, result.error)') &&
  relayApiFederationManagement.includes('export function buildFederationSnapshotPayload') &&
  relayApiFederationManagement.includes('MAX_FEDERATION_SNAPSHOT_RELAYS = 128') &&
  relayApiFederationManagement.includes('MAX_FEDERATION_SNAPSHOT_PEER_APPS = 128') &&
  relayApiFederationManagement.includes('function sanitizePeerCatalogEntry') &&
  relayApiFederationManagement.includes('function sanitizePeerCatalogApp') &&
  relayApiFederationManagement.includes('if (parsed.username || parsed.password) return null') &&
  relayApiFederationManagement.includes('export async function runFederationManagementAction') &&
  relayApiFederationManagement.includes('await federation.save({ throwOnError: true })') &&
  relayApiFederationManagement.includes('federation.restoreSnapshot(snapshot)') &&
  relayApiFederationManagement.includes("emit('federation-rollback-error'") &&
  relayApiFederationManagement.includes("message.startsWith('Federation:')") &&
  relayApiFederationManagement.includes('MAX_FEDERATION_NOTE_LENGTH') &&
  relayApiFederationManagement.includes('sourcePubkey must be 64 hex characters') &&
  relayApiFederationManagement.includes('channel must be a string') &&
  federationPersistFalseUses >= 5 &&
  apiFederationManagementTest.includes('api federation management: validates action bodies before federation access') &&
  apiFederationManagementTest.includes('api federation management: canonicalizes optional trusted metadata before persistence') &&
  apiFederationManagementTest.includes('api federation management: persists every mutation before success') &&
  apiFederationManagementTest.includes('api federation management: persistence failure restores snapshot') &&
  apiFederationManagementTest.includes('api federation management: federation validation failures roll back without save') &&
  apiFederationManagementTest.includes('api federation management: rollback errors are emitted without hiding persistence failure') &&
  apiFederationManagementTest.includes('api federation management: snapshot payload sanitizes remote federation state') &&
  apiAuthTest.includes('GET /api/manage/federation returns bounded sanitized management snapshot') &&
  federationPollManyTest.includes('federation poll: review queue uses RelayNode bounded pending helper') &&
  federationPollManyTest.includes('pending queue respects RelayNode cap') &&
  federationPollManyTest.includes('old entries evicted through bounded helper') &&
  federationHardeningTest.includes('Federation JSON fetch rejects oversized peer catalogs before parsing') &&
  federationHardeningTest.includes('Federation JSON fetch rejects oversized content-length on generic pulls') &&
  auditRoadmap.includes('Federation-management snapshot sanitization')
) {
  pass('federation management mutations persist before API success, roll back failed in-memory state, sanitize management snapshots, and catalog polling honors bounded queue and JSON body limits')
} else {
  fail('federation management API can still report success before durable persistence, expose raw federation snapshots, or bypass queue/body bounds')
}

if (
  relayApi.includes('MANIFEST_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes('FORK_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes("this.emit('manifest-persist-error'") &&
  relayApi.includes("this.emit('fork-persist-error'") &&
  relayApiSignedIngress.includes('manifestStore.snapshot()') &&
  relayApiSignedIngress.includes('manifestStore.restoreSnapshot(snapshot)') &&
  relayApiSignedIngress.includes('forkDetector.snapshot()') &&
  relayApiSignedIngress.includes('forkDetector.restoreSnapshot(snapshot)') &&
  relayApiSignedIngress.includes("kind: 'manifest-persist'") &&
  relayApiSignedIngress.includes("kind: 'fork-persist'") &&
  manifestStoreCore.includes('snapshot ()') &&
  manifestStoreCore.includes('restoreSnapshot (snapshot = {})') &&
  forkDetectorCore.includes('snapshot ()') &&
  forkDetectorCore.includes('restoreSnapshot (snapshot = {})') &&
  capabilityEndpointsTest.includes('POST /api/authors/seeding.json rolls back memory when manifest save fails') &&
  capabilityEndpointsTest.includes('POST /api/forks/proof rolls back memory when fork save fails') &&
  apiSignedIngressTest.includes('api signed ingress: author manifest save failure rolls back live store') &&
  apiSignedIngressTest.includes('api signed ingress: fork proof save failure rolls back report') &&
  manifestStoreTest.includes('snapshot + restore rolls back replacements and cap evictions') &&
  forkDetectorTest.includes('snapshot + restore rolls back fork evidence and bypass log changes')
) {
  pass('signed manifest and fork-proof ingestion roll back runtime state when persistence fails')
} else {
  fail('signed manifest or fork-proof ingestion can leave unsaved runtime state after persistence failure')
}

if (
  appRegistryCore.includes('snapshot ()') &&
  appRegistryCore.includes('restoreSnapshot (snapshot = {})') &&
  appRegistryCore.includes('async persistEntry (appKey, opts = {})') &&
  appRegistryCore.includes('async persistDelete (appKey, opts = {})') &&
  appRegistryCore.includes('const throwOnError = opts.throwOnError === true') &&
  appRegistryCore.includes('this._beeWriteTail = op.catch(() => {})') &&
  appRegistryCore.includes('throw err') &&
  appLifecycleCore.includes('node.appRegistry.set(appKeyHex, {') &&
  appLifecycleCore.includes('}, { persist: false })') &&
  appLifecycleCore.includes('await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })') &&
  appLifecycleCore.includes('node.appRegistry.restoreSnapshot(registrySnapshot)') &&
  appLifecycleCore.includes('node.appRegistry.delete(appKeyHex, { persist: false })') &&
  appLifecycleCore.includes('await node.appRegistry.persistDelete(appKeyHex, { throwOnError: true })') &&
  appLifecycleCore.indexOf('await node.appRegistry.persistDelete(appKeyHex, { throwOnError: true })') <
    appLifecycleCore.indexOf('Destroy persistent download ranges before tearing down the drive') &&
  appLifecycleCore.indexOf('await node.appRegistry.persistEntry(appKeyHex, { throwOnError: true })') <
    appLifecycleCore.indexOf('node.swarm.join(discoveryKey, { server: true, client: true })') &&
  appRegistryTest.includes('snapshot restore preserves map identity and indexes') &&
  appRegistryTest.includes('explicit JSON persistence rejects write failures') &&
  appLifecyclePersistenceTest.includes('failed unseed registry delete keeps live resources intact') &&
  appLifecyclePersistenceTest.includes('seedApp rolls back registry when explicit registry persist fails')
) {
  pass('app seed/unseed lifecycle persists registry changes before API-visible success and rolls back failed durable writes')
} else {
  fail('app seed/unseed lifecycle can still report success before durable app-registry persistence')
}

if (
  accessControl.includes('const hadPrevious = this.allowedDevices.has(pubkeyHex)') &&
  accessControl.includes('if (hadPrevious) this.allowedDevices.set(pubkeyHex, previous)') &&
  accessControl.includes('else this.allowedDevices.delete(pubkeyHex)') &&
  accessControl.includes('this.allowedDevices.set(pubkeyHex, previous)') &&
  accessControl.includes('const previousDevices = this._cloneAllowedDevices()') &&
  accessControl.includes('this.allowedDevices = previousDevices') &&
  accessControl.includes('timingSafeEqual') &&
  accessControl.includes('safePairingTokenEqual') &&
  !accessControl.includes('token !== this._pairingState.token') &&
  relayApi.includes('DEVICE_PERSIST_FAILED_MESSAGE') &&
  relayApi.includes('const result = await runDeviceManagementAction({') &&
  relayApi.includes('const result = runPairingManagementAction({') &&
  relayApi.includes("this.emit('device-persist-error'") &&
  relayApi.includes('_devicePersistErrorResponse') &&
  relayApiDevicePairing.includes('export const DEVICE_NAME_MAX_LENGTH = 80') &&
  relayApiDevicePairing.includes('export const MAX_DEVICE_LIST_ENTRIES = 128') &&
  relayApiDevicePairing.includes('export function normalizeDeviceName') &&
  relayApiDevicePairing.includes("error: 'name must not contain control characters'") &&
  relayApiDevicePairing.includes('export function sanitizeDeviceList') &&
  relayApiDevicePairing.includes('export function sanitizeDeviceEntry') &&
  relayApiDevicePairing.includes('const devices = sanitizeDeviceList(source)') &&
  relayApiDevicePairing.includes('const pubkey = body.pubkey.toLowerCase()') &&
  relayApiDevicePairing.includes('function isKnownDeviceOperatorError') &&
  relayApiDevicePairing.includes("message === 'Device not in allowlist'") &&
  relayApiDevicePairing.includes("message.startsWith('Maximum devices reached')") &&
  relayApiDevicePairing.includes("const result = validatePositiveInt(body.timeoutMs, 10_000, 30 * 60 * 1000, 'timeoutMs')") &&
  privateModeTest.includes('AccessControl - addDevice rolls back when save fails') &&
  privateModeTest.includes('AccessControl - removeDevice rolls back when save fails') &&
  privateModeTest.includes('AccessControl - pairing save failure keeps pairing active and device unpaired') &&
  privateModeTest.includes('AccessControl - pairing tokens use timing-safe comparison') &&
  privateModeTest.includes('AccessControl - restoreBackup rolls back when save fails') &&
  apiDevicePairingTest.includes('api device pairing: normalizes device names and canonicalizes pubkeys') &&
  apiDevicePairingTest.includes('api device pairing: list action sanitizes persisted device rows') &&
  apiDevicePairingTest.includes('MAX_DEVICE_LIST_ENTRIES') &&
  apiDevicePairingTest.includes('api device pairing: separates validation, operator, and persistence errors') &&
  apiDevicePairingTest.includes('api device pairing: validates pairing actions before state changes') &&
  apiServiceConfigTest.includes('device management api: add/list/remove canonicalizes keys and bounds names') &&
  apiServiceConfigTest.includes('device management api: persistence failures return persist-failed response') &&
  auditRoadmap.includes('Device-management snapshot sanitization')
) {
  pass('private-mode device pairing, API management, backup restore, and device-list snapshots sanitize persisted rows without unsaved allowlist drift')
} else {
  fail('private-mode device or pairing persistence can still leave unsaved allowlist changes, generic API failures, or unsanitized device lists')
}

if (
  relayApi.includes("} from './api-delegation-management.js'") &&
  relayApi.includes('buildDelegationRevocationsPayload({') &&
  relayApi.includes('const result = runDelegationRevokeAction({ body, node: this.node })') &&
  relayApiDelegationManagement.includes('export const MAX_DELEGATION_REVOCATION_LIST_ENTRIES = 1000') &&
  relayApiDelegationManagement.includes("errorPayload('certExpiresAt must be a positive safe integer')") &&
  relayApiDelegationManagement.includes("errorPayload('revocation required (signed message from primary identity)')") &&
  relayApiDelegationManagement.includes('node.submitRevocation(body.revocation, expiry.opts)') &&
  relayApiDelegationManagement.includes('function sanitizeRevocationEntry') &&
  relayApiDelegationManagement.includes("Buffer.byteLength(entry.reason, 'utf8') <= 256") &&
  apiDelegationManagementTest.includes('api delegation management: revoke validates body and cert expiry before mutation') &&
  apiDelegationManagementTest.includes('api delegation management: revocation list is capped and sanitized') &&
  apiAuthTest.includes('delegation revocation routes require auth and validate before mutation') &&
  auditRoadmap.includes('Delegation revocation management boundary')
) {
  pass('delegation revocation management is extracted with expiry validation and sanitized bounded list responses')
} else {
  fail('delegation revocation routes can regress to inline mutation, malformed expiry acceptance, or unsanitized list output')
}

const readBodyBlock = relayApi.slice(
  relayApi.indexOf('_readBody (req'),
  relayApi.indexOf('// ─── Management Handlers')
)
if (
  relayApi.includes("import { readJsonBody } from './api-body.js'") &&
  readBodyBlock.includes('return readJsonBody(req, maxBytes)') &&
  relayApiBody.includes('export function readJsonBody') &&
  relayApiBody.includes('tooLarge = true') &&
  relayApiBody.includes('req.resume()') &&
  relayApiBody.includes("new Error('JSON body must be an object')") &&
  !relayApiBody.includes('req.destroy()') &&
  relayApi.includes("this._json(res, { error: 'JSON body must be an object' }, 400)") &&
  relayApi.includes("this._json(res, { error: 'Request body too large' }, 413, { Connection: 'close' })") &&
  apiBodyTest.includes('rejects oversized bodies while draining the stream') &&
  apiBodyTest.includes('rejects malformed JSON with stable error message') &&
  apiBodyTest.includes('rejects top-level arrays and primitives with stable error message') &&
  apiServiceConfigTest.includes('rejects top-level non-object JSON bodies before mutation') &&
  apiServiceConfigTest.includes('oversized JSON body returns 413 without resetting the client')
) {
  pass('management API drains oversized JSON bodies, rejects non-object JSON bodies, and returns stable body errors')
} else {
  fail('management API JSON body handling can accept ambiguous shapes, reset clients, or keep unsafe connections reusable')
}

if (
  relayApi.includes("import { getPostJsonContentTypeProblem } from './api-request.js'") &&
  relayApi.includes('const contentTypeProblem = getPostJsonContentTypeProblem(req)') &&
  relayApi.includes('if (contentTypeProblem.close) res.shouldKeepAlive = false') &&
  relayApi.includes("contentTypeProblem.close ? { Connection: 'close' } : null") &&
  relayApiRequest.includes('export function getPostJsonContentTypeProblem (req)') &&
  relayApiRequest.includes("const contentMediaType = contentType.split(';', 1)[0].trim().toLowerCase()") &&
  relayApiRequest.includes("contentMediaType !== 'application/json'") &&
  !relayApiRequest.includes("contentType.includes('application/json')") &&
  relayApiRequest.includes("const transferEncoding = headers['transfer-encoding']") &&
  relayApiRequest.includes("const hasBody = (contentLength !== undefined && contentLength !== '0') || !!transferEncoding") &&
  relayApiRequest.includes('if (!contentType && hasBody)') &&
  apiRequestTest.includes('JSON-looking media types are rejected without substring matching') &&
  apiRequestTest.includes('chunked body without Content-Type is rejected and should close') &&
  capabilityEndpointsTest.includes('POST Content-Type requires exact application/json media type') &&
  capabilityEndpointsTest.includes('POST with chunked body and no Content-Type is rejected with 400')
) {
  pass('POST Content-Type gate requires exact application/json media type and closes early body rejections')
} else {
  fail('POST Content-Type gate can accept malformed JSON-looking media types or miss chunked bodies')
}

if (
  relayApi.includes("import { buildCustodyStatusPayload, redactCustodyStatus } from './api-custody-status.js'") &&
  relayApi.includes('return this._json(res, buildCustodyStatusPayload(status, { detailed: true }))') &&
  relayApi.includes('return this._json(res, buildCustodyStatusPayload(status))') &&
  relayApi.includes('return redactCustodyStatus(status)') &&
  !relayApi.includes('return this._json(res, status)') &&
  relayApiCustodyStatus.includes('export function buildCustodyStatusPayload') &&
  relayApiCustodyStatus.includes('export function detailedCustodyStatus') &&
  relayApiCustodyStatus.includes('export function redactCustodyStatus') &&
  relayApiCustodyStatus.includes('export function detailedCustodyReceipt') &&
  relayApiCustodyStatus.includes('export function redactCustodyReceipt') &&
  relayApiCustodyStatus.includes('receipts.map(redactCustodyReceipt)') &&
  relayApiCustodyStatus.includes('relayPubkey: receipt.relayPubkey || null') &&
  relayApiCustodyStatus.includes('shareIndex: Number.isInteger(receipt.shareIndex) ? receipt.shareIndex : null') &&
  relayApiCustodyStatus.includes('shareVerified: receipt.shareVerified === true') &&
  relayApiCustodyStatus.includes('anchored: receipt.anchored === true') &&
  relayApiCustodyStatus.includes('sanitizePvssSummary') &&
  relayApiCustodyStatus.includes('commitPendingReason: safeCustodyString(status.commitPendingReason)') &&
  relayApiCustodyStatus.includes('sourceRetirementPendingReason: safeCustodyString(status.sourceRetirementPendingReason)') &&
  !relayApiCustodyStatus.includes('addressKey') &&
  !relayApiCustodyStatus.includes('ciphertextRoot') &&
  !relayApiCustodyStatus.includes('signature') &&
  !relayApiCustodyStatus.includes('shareBundleKey') &&
  !relayApiCustodyStatus.includes('publisherSignature') &&
  apiCustodyStatusTest.includes('api custody status: redacted receipts expose only public attestation fields') &&
  apiCustodyStatusTest.includes('api custody status: redacted status omits detailed intent proof and witness bodies') &&
  apiCustodyStatusTest.includes('api custody status: detailed status preserves diagnostics without raw proof bodies') &&
  apiCustodyStatusTest.includes('api custody status: missing or malformed fields normalize to stable defaults') &&
  custodyStatusRedactionTest.includes('custody-redaction: public status exposes minimal per-receipt attestation') &&
  custodyStatusRedactionTest.includes('custody-redaction: ?detailed=1 without auth is 401') &&
  custodyStatusRedactionTest.includes('custody-redaction: ?detailed=1 with Bearer returns shaped diagnostics') &&
  apiAuthTest.includes('detailed custody status requires auth and returns shaped diagnostics') &&
  auditRoadmap.includes('Detailed custody status sanitization') &&
  auditRoadmap.includes('api-custody-status.js') &&
  auditDoc.includes('Extracted public custody status redaction')
) {
  pass('public and detailed custody status redaction is extracted with receipt-field and shaped-diagnostics coverage')
} else {
  fail('custody status can drift, lose public receipt attestations, leak raw detailed custody fields, or expose proof bodies')
}

if (
  relayApi.includes("} from './api-anchor-status.js'") &&
  relayApi.includes('buildAnchorProofPayload({') &&
  relayApi.includes("appKey: path.slice('/api/anchors/'.length, -'/proof'.length)") &&
  relayApi.includes("const detailed = isDetailedAnchorStatusQuery(url.searchParams.get('detailed'))") &&
  relayApi.includes("if (detailed && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed anchor status')) return") &&
  relayApi.includes('const result = buildAnchorStatusPayload({') &&
  relayApi.includes('return this._json(res, result.payload, result.status || 200)') &&
  bareHttpServer.includes("import { buildAnchorStatusPayload } from './api-anchor-status.js'") &&
  bareHttpServer.includes("if (path === '/api/anchors')") &&
  bareHttpServer.includes('const result = buildAnchorStatusPayload({') &&
  bareHttpServer.includes('appRegistry: this.relay.appRegistry') &&
  !bareHttpServer.includes('...this.relay.appRegistry.anchorStats()') &&
  relayApiAnchorStatus.includes('export function isDetailedAnchorStatusQuery') &&
  relayApiAnchorStatus.includes('export async function buildAnchorProofPayload') &&
  relayApiAnchorStatus.includes('!isValidHexKey(appKey)') &&
  relayApiAnchorStatus.includes("typeof node.createAnchorProof !== 'function'") &&
  relayApiAnchorStatus.includes('payload: await node.createAnchorProof(appKey)') &&
  relayApiAnchorStatus.includes("payload: { error: 'proof generation failed' }") &&
  relayApiAnchorStatus.includes('export function buildAnchorStatusPayload') &&
  relayApiAnchorStatus.includes('total: count(stats && stats.total)') &&
  relayApiAnchorStatus.includes('anchored: count(stats && stats.anchored)') &&
  relayApiAnchorStatus.includes('unanchored: count(stats && stats.unanchored)') &&
  relayApiAnchorStatus.includes('neverChecked: count(stats && stats.neverChecked)') &&
  relayApiAnchorStatus.includes('lastCheckedAt: timestampOrNull(lastCheckedAt)') &&
  !relayApiAnchorStatus.includes('...stats') &&
  relayApiAnchorStatus.includes('export function anchorStatusEntry') &&
  relayApiAnchorStatus.includes('entries = detailed') &&
  relayApiAnchorStatus.includes('custodyIntentId: entry.custodyIntentId || null') &&
  relayApiAnchorStatus.includes('blind: entry.blind === true') &&
  relayApiAnchorStatus.includes('storageClass: entry.storageClass || null') &&
  relayApiAnchorStatus.includes('availabilityClass: entry.availabilityClass || null') &&
  !relayApiAnchorStatus.includes('publisherPubkey') &&
  !relayApiAnchorStatus.includes('retainUntil') &&
  !relayApiAnchorStatus.includes('ciphertextRoot') &&
  !relayApiAnchorStatus.includes('shareBundleKey') &&
  apiAnchorStatusTest.includes('api anchor proof: valid appKey delegates to proof signer') &&
  apiAnchorStatusTest.includes('api anchor proof: malformed appKey is rejected before proof generation') &&
  apiAnchorStatusTest.includes('api anchor proof: unavailable or throwing signer returns stable payloads') &&
  apiAnchorStatusTest.includes('api anchor status: public payload keeps aggregate stats without entry details') &&
  apiAnchorStatusTest.includes('api anchor status: malformed aggregate stats become bounded public counters') &&
  apiAnchorStatusTest.includes('api anchor status: detailed entries expose only custody diagnostics') &&
  bareHttpServerTest.includes('bare http server: anchors route reuses bounded public anchor payload') &&
  apiAuthTest.includes('api-auth: detailed anchor diagnostics require auth') &&
  apiAuthTest.includes('public anchor proof remains readable') &&
  apiAuthTest.includes('malformed proof key rejected before signer') &&
  cliIndex.includes('await runManage(host, port, { apiKey: getApiKey(args) })') &&
  cliManage.includes('export class RelayClient') &&
  cliManage.includes("Authorization: 'Bearer ' + this.apiKey") &&
  manageCliClientTest.includes('manage CLI client attaches bearer auth to GET and POST requests') &&
  auditRoadmap.includes('api-anchor-status.js') &&
  auditRoadmap.includes('Anchor proof read extraction') &&
  auditRoadmap.includes('Node/Bare anchor aggregate shaping') &&
  readme.includes('public bounded aggregate/proof on Node and Bare') &&
  auditDoc.includes('Anchor proof reads now delegate through `api-anchor-status.js`') &&
  auditDoc.includes('proof-generation') &&
  auditDoc.includes('payloads with direct helper plus HTTP route coverage')
) {
  pass('anchor status and proof reads are extracted with bounded Node/Bare aggregate coverage')
} else {
  fail('anchor status/proof reads can drift, leak raw aggregate diagnostics publicly, or miss direct proof-route coverage')
}

if (
  relayApi.includes("} from './api-network-state.js'") &&
  relayApi.includes("const detailed = isDetailedNetworkStateQuery(url.searchParams.get('detailed'))") &&
  relayApi.includes("if (detailed && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed network state')) return") &&
  relayApi.includes('const result = buildNetworkStatePayload({') &&
  relayApiNetworkState.includes('export function publicNetworkState') &&
  relayApiNetworkState.includes('export function publicNetworkRelay') &&
  relayApiNetworkState.includes('export function detailedNetworkState') &&
  relayApiNetworkState.includes('MAX_NETWORK_RELAYS = 1000') &&
  relayApiNetworkState.includes('payload: detailed ? detailedNetworkState(state) : publicNetworkState(state)') &&
  relayApiNetworkState.includes('relays: relays.slice(0, MAX_NETWORK_RELAYS).map(sanitizeDetailedNetworkRelay)') &&
  relayApiNetworkState.includes('apiReachable: source.apiPort !== null && source.apiPort !== undefined') &&
  relayApiNetworkState.includes('torAvailable: source.tor && source.tor.running === true') &&
  relayApiNetworkState.includes('holesailAvailable: !!source.holesailKey || source.holesailConnected === true') &&
  !relayApiNetworkState.includes('host: relay.host') &&
  !relayApiNetworkState.includes('apiPort: relay.apiPort') &&
  !relayApiNetworkState.includes('memory: relay.memory') &&
  !relayApiNetworkState.includes('tor: relay.tor') &&
  !relayApiNetworkState.includes('holesailKey: relay.holesailKey') &&
  wsFeed.includes("import { detailedNetworkState, publicNetworkState } from './api-network-state.js'") &&
  wsFeed.includes('payload.network = this._apiKey ? detailedNetworkState(state) : publicNetworkState(state)') &&
  networkDashboard.includes("fetchWithTimeout('/api/network?detailed=1'") &&
  networkDashboard.includes("detailedHeaders.Authorization = 'Bearer ' + token") &&
  networkDashboard.includes("fetchWithTimeout('/api/network'") &&
  !networkDashboard.includes('AbortSignal.timeout') &&
  networkDashboard.includes('r.apiPort != null || r.apiReachable === true') &&
  networkDiscoveryCore.includes('MAX_API_OVERVIEW_BYTES = 256 * 1024') &&
  networkDiscoveryCore.includes('MAX_META_BYTES = 2048') &&
  networkDiscoveryCore.includes('HOLESAIL_Z32_KEY') &&
  networkDiscoveryCore.includes('normalizeHolesailKey (key)') &&
  networkDiscoveryCore.includes('_handleMetadataFrame (pubkey, buf)') &&
  networkDiscoveryCore.includes('buf.byteLength > MAX_META_BYTES') &&
  networkDiscoveryCore.includes('contentLength > MAX_API_OVERVIEW_BYTES') &&
  networkDiscoveryCore.includes("Buffer.byteLength(chunk, 'utf8')") &&
  networkDiscoveryCore.includes("finish(reject, new Error('Response too large'))") &&
  networkDiscoveryCore.includes("finish(reject, new Error('Unexpected status: ' + res.statusCode))") &&
  networkDiscoveryCore.includes("throw new Error('Invalid holesail key')") &&
  apiNetworkStateTest.includes('api network state: public relay redacts connection metadata') &&
  networkDiscoveryTest.includes('network discovery fetches bounded API overview JSON') &&
  networkDiscoveryTest.includes('network discovery rejects oversized API overview content-length') &&
  networkDiscoveryTest.includes('network discovery rejects oversized streamed API overview bodies') &&
  networkDiscoveryTest.includes('network discovery rejects non-object API overview JSON') &&
  networkDiscoveryTest.includes('network discovery accepts bounded z32 holesail metadata frames') &&
  networkDiscoveryTest.includes('network discovery ignores oversized holesail metadata frames') &&
  networkDiscoveryTest.includes('network discovery rejects malformed holesail metadata frames') &&
  networkDiscoveryTest.includes('network discovery rejects invalid holesail tunnel keys before connecting') &&
  apiNetworkStateTest.includes('api network state: detailed payload is bounded and drops raw relay internals') &&
  apiAuthTest.includes('api-auth: public network state redacts connection details and detailed state requires auth') &&
  wsFeedPayloadTest.includes('ws-feed: unauthenticated feed redacts network connection metadata') &&
  wsFeedPayloadTest.includes('authenticated network frames are detailed but shaped') &&
  dashboardNetworkUiTest.includes('network dashboard requests detailed state with token and falls back to public state') &&
  auditRoadmap.includes('api-network-state.js') &&
  auditRoadmap.includes('Network discovery detailed-state shaping') &&
  auditDoc.includes('detailed network state')
) {
  pass('network discovery state is public-redacted with detailed auth, dashboard fallback, bounded relay overview fetches, and bounded Holesail metadata frames')
} else {
  fail('network discovery state can leak host/API/Tor/Holesail details, lose dashboard fallback coverage, parse unbounded relay overview responses, or accept unbounded/invalid Holesail metadata')
}

const custodyWitnessRouteBlock = relayApi.slice(
  relayApi.indexOf("path.startsWith('/api/custody/') && path.endsWith('/witness')"),
  relayApi.indexOf("path.startsWith('/api/custody/') && path.endsWith('/non-serving-proof')")
)
if (
  relayApi.includes('import {\n  runOperatorCustodyAction') &&
  relayApi.includes('runPublisherCustodyAction') &&
  custodyWitnessRouteBlock.includes("return this._handleOperatorCustodyAction(res, 'witness', body, intentId)") &&
  !custodyWitnessRouteBlock.includes('await this._readBody(req)') &&
  relayApiCustodyManagement.includes('export async function runOperatorCustodyAction') &&
  relayApiCustodyManagement.includes('export async function runPublisherCustodyAction') &&
  relayApiCustodyManagement.includes("action === 'witness'") &&
  relayApiCustodyManagement.includes('{ ...body, intentId }') &&
  relayApiCustodyManagement.includes("registryNotRunning('registry not running')") &&
  relayApiCustodyManagement.includes('wrapOk: false') &&
  relayApiCustodyManagement.includes('node.seedingRegistry.publishCustodyIntent(body, null)') &&
  relayApiCustodyManagement.includes('node.seedingRegistry.publishCustodyCommit({ ...body, intentId }, null)') &&
  relayApiCustodyManagement.includes('node.seedingRegistry.publishSourceRetired({ ...body, intentId }, null)') &&
  relayApiCustodyManagement.includes("return { ok: false, kind: 'custody-error', error: err }") &&
  relayApi.includes("if (!result.ok && result.kind === 'custody-error') return this._custodyErrorResponse(res, result.error)") &&
  apiCustodyManagementTest.includes('api custody management: operator routes preserve readiness and validation order') &&
  apiCustodyManagementTest.includes('witness rejects malformed route ids before registry access') &&
  apiCustodyManagementTest.includes('api custody management: publisher routes require signatures and pass null signer') &&
  apiCustodyManagementTest.includes('api custody management: publisher registry errors stay delegated to custody error response') &&
  apiServiceConfigTest.includes('custody witness api uses parsed body once and validates intent ids at the route boundary') &&
  apiServiceConfigTest.includes('invalid route id does not reach registry') &&
  apiServiceConfigTest.includes('registry called exactly once') &&
  apiPublisherSignedTest.includes('/api/v1/custody/intent: accepts publisher-signed entry without operator key') &&
  apiTransientErrorsTest.includes('/api/v1/custody/intent: "The corestore is closed"') &&
  auditRoadmap.includes('Custody witness route body handling') &&
  auditDoc.includes('Hardened the management custody witness route')
) {
  pass('custody management routes are extracted, preserve witness body handling, and keep publisher-signed custody on null-signer plus transient-error paths')
} else {
  fail('custody management routes can regress witness parsing, publisher-signed custody auth, or transient-error mapping')
}

const operatorSeedRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/seed'"),
  relayApi.indexOf("path === '/registry/publish'")
)
const registryPublishRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/registry/publish'"),
  relayApi.indexOf("path === '/api/custody/intent'")
)
const publisherSeedRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/api/v1/seed'"),
  relayApi.indexOf("path === '/api/v1/custody/intent'")
)
if (
  relayApi.includes("from './api-seed-publish.js'") &&
  operatorSeedRouteBlock.includes('return this._handleOperatorSeed(res, body)') &&
  registryPublishRouteBlock.includes('return this._handleRegistryPublish(res, body)') &&
  publisherSeedRouteBlock.includes('return this._handlePublisherSeed(res, body)') &&
  relayApi.includes('const result = await runOperatorSeedAction({') &&
  relayApi.includes('const result = await runRegistryPublishAction({') &&
  relayApi.includes('const result = await runPublisherSeedAction({') &&
  relayApi.includes("if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)") &&
  relayApiSeedPublish.includes('export async function runOperatorSeedAction') &&
  relayApiSeedPublish.includes('export async function runRegistryPublishAction') &&
  relayApiSeedPublish.includes('export async function runPublisherSeedAction') &&
  relayApiSeedPublish.includes('function cloneSeedOpts') &&
  relayApiSeedPublish.includes("badRequest('opts must be an object')") &&
  relayApiSeedPublish.includes('return { ok: true, seedOpts: { ...opts } }') &&
  relayApiSeedPublish.includes('parentKey and mountPath are only supported when type is "drive"') &&
  relayApiSeedPublish.includes('shardIds must contain non-negative integers') &&
  relayApiSeedPublish.includes('discoveryKeys must be an array of at most') &&
  relayApiSeedPublish.includes('function normalizeRegistryGeoPreference') &&
  relayApiSeedPublish.includes('MAX_REGISTRY_TTL_DAYS') &&
  relayApiSeedPublish.includes('MAX_REGISTRY_BOUNTY_RATE') &&
  relayApiSeedPublish.includes("Buffer.from(body.appKey, 'hex')") &&
  relayApiSeedPublish.includes('node.seedingRegistry.publishRequest(built.request)') &&
  relayApiSeedPublish.includes('publisherPubkey: node.swarm ? node.swarm.keyPair.publicKey : Buffer.alloc(32)') &&
  relayApiSeedPublish.includes('buildPublisherSignedSeedOpts(body, {') &&
  relayApiSeedPublish.includes("return { ok: false, kind: 'seed-error', error: err }") &&
  apiSeedPublishTest.includes('api seed publish: operator seed normalizes metadata without mutating opts') &&
  apiSeedPublishTest.includes('api seed publish: operator seed rejects malformed input before seeding') &&
  apiSeedPublishTest.includes('opts must be an object') &&
  apiSeedPublishTest.includes('api seed publish: registry publish builds the signed catalog request') &&
  apiSeedPublishTest.includes('api seed publish: registry publish preserves readiness and validation errors') &&
  apiSeedPublishTest.includes('replicas must be between 1 and 255') &&
  apiSeedPublishTest.includes('geo must be a string or array of strings') &&
  apiSeedPublishTest.includes('bountyRate must be between 0 and 4294967295') &&
  apiSeedPublishTest.includes('api seed publish: publisher seed checks seedApp readiness before request validation') &&
  apiSeedPublishTest.includes('api seed publish: publisher seed forwards signed opts and validation errors') &&
  apiSeedPublishTest.includes('api seed publish: publisher seed preserves custody publisher mismatch and seed error delegation') &&
  auditRoadmap.includes('api-seed-publish.js') &&
  auditDoc.includes('Extracted operator seed, publisher-signed seed, and registry publish orchestration')
) {
  pass('operator seed, publisher-signed seed, and registry publish routes are extracted with direct validation/request-builder coverage')
} else {
  fail('seed or registry publish routes can regress validation, request construction, transient-error mapping, or route delegation')
}

const operatorUnseedRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/unseed'"),
  relayApi.indexOf("path === '/api/v1/unseed'")
)
const publisherUnseedRouteBlock = relayApi.slice(
  relayApi.indexOf("path === '/api/v1/unseed'"),
  relayApi.indexOf("path === '/api/v1/seed'")
)
if (
  relayApi.includes("from './api-unseed-actions.js'") &&
  operatorUnseedRouteBlock.includes('const result = await runOperatorUnseedAction({ body, node: this.node })') &&
  publisherUnseedRouteBlock.includes('const result = await runPublisherUnseedAction({ body, node: this.node })') &&
  !operatorUnseedRouteBlock.includes('await this.node.unseedApp(body.appKey)') &&
  !publisherUnseedRouteBlock.includes('await this.node.unseedApp(body.appKey)') &&
  relayApiUnseedActions.includes('export async function runOperatorUnseedAction') &&
  relayApiUnseedActions.includes('export async function runPublisherUnseedAction') &&
  relayApiUnseedActions.includes("badRequest('timestamp must be a positive safe integer')") &&
  relayApiUnseedActions.includes('!Number.isSafeInteger(body.timestamp) || body.timestamp <= 0') &&
  relayApiUnseedActions.includes('node.verifyUnseedRequest(body.appKey, body.publisherPubkey, body.signature, body.timestamp)') &&
  relayApiUnseedActions.includes('await node.unseedApp(body.appKey)') &&
  relayApiUnseedActions.includes('node.broadcastUnseed(body.appKey, body.publisherPubkey, body.signature, body.timestamp)') &&
  apiUnseedActionsTest.includes('publisher-signed unseed validates body before verifier and mutation') &&
  apiUnseedActionsTest.includes('malformed signed unseed does not verify, mutate, or broadcast') &&
  apiAuthTest.includes('publisher-signed unseed validates before verifier, mutation, and broadcast') &&
  apiAuthTest.includes('operator unseed validates appKey before mutation') &&
  auditRoadmap.includes('Unseed route boundary')
) {
  pass('operator and publisher-signed unseed routes are extracted with pre-verifier validation and broadcast-order coverage')
} else {
  fail('unseed routes can regress to inline mutation, malformed timestamp verifier calls, or broadcast-before-unseed behavior')
}

if (
  relayApi.includes('closeIdleConnections') &&
  relayApi.includes('closeAllConnections') &&
  relayApi.includes('Active HTTP') &&
  relayApi.includes('setImmediate') &&
  relayApi.includes('await this._dashboardFeed.stop()') &&
  wsFeed.includes('async stop ()') &&
  wsFeed.includes('ws.terminate()') &&
  wsFeed.includes('wss.close(resolve)')
) {
  pass('API shutdown force-closes active HTTP connections and awaits dashboard WebSocket teardown')
} else {
  fail('API shutdown can hang on active HTTP or dashboard WebSocket connections')
}

if (
  relayNode.includes('dhtFlushTimeoutMs: 1000') &&
  relayNode.includes('async _flushDhtForStartup ()') &&
  relayNode.includes("this.emit('dht-flush-timeout'") &&
  relayNode.includes('startups.push(this._flushDhtForStartup())')
) {
  pass('RelayNode startup bounds initial DHT flush so local health/UI startup is not blocked by slow bootstrap')
} else {
  fail('RelayNode startup can still block local health/UI startup on an unbounded DHT flush')
}

if (
  servedAccounting.includes('this._listeners = new Set()') &&
  servedAccounting.includes("entry.core.removeListener('upload', entry.onUpload)") &&
  servedAccounting.includes('this._coreCount = 0')
) {
  pass('served accounting removes per-core upload listeners on stop/restart')
} else {
  fail('served accounting can leak per-core upload listeners across stop/restart')
}

if (
  constantsCore.includes("const SEED_PROTOCOL_NAME = 'hiverelay-seed'") &&
  constantsCore.includes("const CIRCUIT_PROTOCOL_NAME = 'hiverelay-circuit'") &&
  constantsCore.includes("const FORWARD_PROTOCOL_NAME = 'hiverelay-forward'") &&
  constantsCore.includes("const SERVICES_PROTOCOL_NAME = 'hiverelay-services'") &&
  constantsCore.includes('function isValidHexKey') &&
  constantsCore.includes('function compareVersions') &&
  constantsCore.includes('function uint64ToBuffer') &&
  clientSdk.includes('SEED_PROTOCOL_NAME') &&
  clientSdk.includes('CIRCUIT_PROTOCOL_NAME') &&
  clientSdk.includes('FORWARD_PROTOCOL_NAME') &&
  clientSdk.includes('SERVICES_PROTOCOL_NAME') &&
  clientSdk.includes('protocol: SEED_PROTOCOL_NAME') &&
  clientSdk.includes('protocol: CIRCUIT_PROTOCOL_NAME') &&
  clientSdk.includes('protocol: FORWARD_PROTOCOL_NAME') &&
  clientSdk.includes('protocol: SERVICES_PROTOCOL_NAME') &&
  !clientSdk.includes("const SEED_PROTOCOL = 'hiverelay-seed'") &&
  seedRequestProtocol.includes("import { SEED_PROTOCOL_NAME } from '../constants.js'") &&
  seedRequestProtocol.includes('protocol: SEED_PROTOCOL_NAME') &&
  relayCircuitProtocol.includes("import { CIRCUIT_PROTOCOL_NAME } from '../constants.js'") &&
  relayCircuitProtocol.includes('protocol: CIRCUIT_PROTOCOL_NAME') &&
  forwardRelayProtocol.includes("import { FORWARD_PROTOCOL_NAME } from '../constants.js'") &&
  forwardRelayProtocol.includes('protocol: FORWARD_PROTOCOL_NAME') &&
  serviceProtocol.includes("import { SERVICES_PROTOCOL_NAME } from '../constants.js'") &&
  serviceProtocol.includes('protocol: SERVICES_PROTOCOL_NAME') &&
  !serviceProtocol.includes("protocol: 'hiverelay-services'") &&
  cliIndex.includes("import { isValidHexKey } from '../core/constants.js'") &&
  !cliIndex.includes('function isValidHexKey') &&
  cliCatalog.includes("import { isValidHexKey as isSharedValidHexKey } from '../core/constants.js'") &&
  cliCatalog.includes('return isSharedValidHexKey(value, length)') &&
  !cliCatalog.includes('new RegExp(`^[0-9a-fA-F]') &&
  discoveryTopicsTest.includes('protocol constants — stable Protomux channel names') &&
  auditRoadmap.includes('Shared constants module') &&
  auditDoc.includes('Completed the shared Core3 constants cleanup')
) {
  pass('Core3 constants centralize protocol names and hex-key validation across client, server, and CLI')
} else {
  fail('Core3 constants can regress to duplicated protocol names or hex-key validation helpers')
}

if (
  jsonMessageEncoding.includes('export function createLengthPrefixedJsonEncoding') &&
  jsonMessageEncoding.includes('function encodeJson') &&
  jsonMessageEncoding.includes('if (byteLength > maxBytes) throw new Error(tooLargeError)') &&
  jsonMessageEncoding.includes('const buffer = state && state.buffer') &&
  jsonMessageEncoding.includes('!Number.isSafeInteger(start) || start < 0 || start > bufferLength') &&
  jsonMessageEncoding.includes('!Number.isSafeInteger(limit) || limit < start || limit > bufferLength') &&
  jsonMessageEncoding.includes('start + 4 > limit') &&
  jsonMessageEncoding.includes('len > maxBytes') &&
  jsonMessageEncoding.includes('return { type: -1, error: tooLargeError }') &&
  jsonMessageEncoding.includes('if (end > limit)') &&
  serviceProtocol.includes('export const MAX_SERVICE_MESSAGE_BYTES = 1024 * 1024') &&
  serviceProtocol.includes("import { createLengthPrefixedJsonEncoding } from '../protocol/json-message-encoding.js'") &&
  serviceProtocol.includes('export const serviceMessageEncoding = createLengthPrefixedJsonEncoding') &&
  serviceProtocol.includes("malformedError: 'malformed JSON'") &&
  serviceProtocol.includes('encoding: serviceMessageEncoding') &&
  anchorChannel.includes("import { createLengthPrefixedJsonEncoding } from './json-message-encoding.js'") &&
  anchorChannel.includes('export const anchorMessageEncoding = createLengthPrefixedJsonEncoding') &&
  anchorChannel.includes('encoding: anchorMessageEncoding') &&
  custodyChannel.includes("import { createLengthPrefixedJsonEncoding } from './json-message-encoding.js'") &&
  custodyChannel.includes('export const custodyMessageEncoding = createLengthPrefixedJsonEncoding') &&
  custodyChannel.includes('encoding: custodyMessageEncoding') &&
  publishChannel.includes("import { createLengthPrefixedJsonEncoding } from './json-message-encoding.js'") &&
  publishChannel.includes('export const publishMessageEncoding = createLengthPrefixedJsonEncoding') &&
  publishChannel.includes('encoding: publishMessageEncoding') &&
  seedingRegistry.includes("import { createLengthPrefixedJsonEncoding } from '../protocol/json-message-encoding.js'") &&
  seedingRegistry.includes('export const MAX_REGISTRY_META_MESSAGE_BYTES = 64 * 1024') &&
  seedingRegistry.includes('export const registryMetaMessageEncoding = createLengthPrefixedJsonEncoding') &&
  seedingRegistry.includes('encoding: registryMetaMessageEncoding') &&
  !serviceProtocol.includes('readUInt32BE(state.start)') &&
  !anchorChannel.includes('readUInt32BE(state.start)') &&
  !custodyChannel.includes('readUInt32BE(state.start)') &&
  !publishChannel.includes('readUInt32BE(state.start)') &&
  !seedingRegistry.includes('readUInt32BE(state.start)') &&
  clientSdk.includes("import { serviceMessageEncoding } from 'p2p-hiverelay/core/services/protocol.js'") &&
  clientSdk.includes('encoding: serviceMessageEncoding') &&
  !clientSdk.includes('readUInt32BE(state.start)') &&
  protocolSecurityTest.includes('serviceMessageEncoding.decode') &&
  protocolSecurityTest.includes('MAX_SERVICE_MESSAGE_BYTES + 1') &&
  protocolSecurityTest.includes('truncated service message returns error type') &&
  protocolSecurityTest.includes('short service message header returns error type (no throw)') &&
  protocolSecurityTest.includes('invalid service decode state returns error type (no throw)') &&
  protocolSecurityTest.includes('Number.MAX_SAFE_INTEGER + 1') &&
  protocolJsonEncodingTest.includes('protocol-json-encoding: all channel encodings reject oversized declared frames') &&
  protocolJsonEncodingTest.includes('protocol-json-encoding: all channel encodings reject oversized outbound messages before allocation growth') &&
  protocolJsonEncodingTest.includes('protocol-json-encoding: all channel encodings reject malformed and truncated frames without throwing') &&
  protocolJsonEncodingTest.includes('protocol-json-encoding: all channel encodings reject invalid decode state without throwing') &&
  protocolJsonEncodingTest.includes('anchorMessageEncoding') &&
  protocolJsonEncodingTest.includes('custodyMessageEncoding') &&
  protocolJsonEncodingTest.includes('publishMessageEncoding') &&
  protocolJsonEncodingTest.includes('registryMetaMessageEncoding') &&
  auditRoadmap.includes('Shared JSON Protomux framing') &&
  auditRoadmap.includes('shared bounded JSON encoder') &&
  auditRoadmap.includes('registry meta') &&
  auditDoc.includes('Shared the service-protocol message framing') &&
  auditDoc.includes('Anchor, custody, and publisher-submit channels now use the same bounded JSON') &&
  auditDoc.includes('registry metadata channel now uses that same bounded encoder') &&
  auditDoc.includes('proof, custody') &&
  auditDoc.includes('publisher-submit fast paths')
) {
  pass('JSON Protomux message framing is shared across service, anchor, custody, publish, and registry-meta channels with capped outbound, malformed-frame, and invalid-state handling')
} else {
  fail('JSON Protomux message framing can drift across service, anchor, custody, publish, or registry-meta channels')
}

if (
  clientPairing.includes('export const pairMessageEncoding') &&
  clientPairing.includes('function encodePairJson') &&
  clientPairing.includes('b4a.byteLength(json) > MAX_FRAME_BYTES') &&
  clientPairing.includes('const lenState = { buffer, start: state.start, end: state.end }') &&
  clientPairing.includes('len > MAX_FRAME_BYTES') &&
  clientPairing.includes("return { type: -1, error: 'frame too large' }") &&
  clientPairing.includes("return { type: -1, error: 'malformed JSON' }") &&
  clientPairing.includes('encoding: pairMessageEncoding') &&
  pairingProtocolTest.includes('pairing protocol encoding: rejects oversized outbound messages before allocation growth') &&
  pairingProtocolTest.includes('pairing protocol encoding: rejects oversized declared inbound frame before string decode') &&
  pairingProtocolTest.includes('pairing protocol encoding: rejects malformed and truncated frames without throwing') &&
  pairingProtocolTest.includes('pairing protocol encoding: rejects invalid decode state without throwing') &&
  auditRoadmap.includes('Client pairing compact-string JSON framing') &&
  auditDoc.includes('Hardened client pairing protocol JSON framing') &&
  auditDoc.includes('pairMessageEncoding')
) {
  pass('client pairing protocol bounds compact-string JSON frames before outbound allocation and inbound decode')
} else {
  fail('client pairing protocol JSON framing can still allocate or throw on malformed compact-string frames')
}

if (
  forwardRelayProtocol.includes('export const MAX_FORWARD_DATA_MSG_BYTES = 64 * 1024') &&
  forwardRelayProtocol.includes('export const MAX_FORWARD_STATUS_MESSAGE_BYTES = 1024') &&
  forwardRelayProtocol.includes('export const forwardOpenEncoding') &&
  forwardRelayProtocol.includes('export const forwardDataEncoding') &&
  forwardRelayProtocol.includes('export const forwardStatusEncoding') &&
  forwardRelayProtocol.includes('export const forwardCloseEncoding') &&
  forwardRelayProtocol.includes('function encodeUintValue') &&
  forwardRelayProtocol.includes('this.maxDataMsgBytes = Math.min(opts.maxDataMsgBytes || MAX_FORWARD_DATA_MSG_BYTES, MAX_FORWARD_DATA_MSG_BYTES)') &&
  forwardRelayProtocol.includes('encoding: forwardStatusEncoding') &&
  forwardRelayProtocol.includes('encoding: forwardDataEncoding') &&
  forwardRelayProtocol.includes('encoding: forwardCloseEncoding') &&
  forwardRelayProtocol.includes('encoding: forwardOpenEncoding') &&
  clientSdk.includes("} from 'p2p-hiverelay/core/protocol/forward-relay.js'") &&
  clientSdk.includes('const FORWARD_MAX_FRAME = MAX_FORWARD_DATA_MSG_BYTES') &&
  clientSdk.includes('encoding: forwardStatusEncoding') &&
  clientSdk.includes('encoding: forwardDataEncoding') &&
  clientSdk.includes('encoding: forwardCloseEncoding') &&
  clientSdk.includes('encoding: forwardOpenEncoding') &&
  !clientSdk.includes('c.string.decode(s) } } },\n        onmessage: (msg) => this.emit(\'_forward-status-') &&
  forwardRelayEncodingTest.includes('forward-relay encodings: reject oversized outbound frames before allocation growth') &&
  forwardRelayEncodingTest.includes('status preencode rejects invalid code') &&
  forwardRelayEncodingTest.includes('close preencode rejects invalid reason') &&
  forwardRelayEncodingTest.includes('forward-relay encodings: reject oversized declared inbound frames before decode materializes them') &&
  forwardRelayEncodingTest.includes('forward-relay encodings: reject malformed and truncated frames without throwing') &&
  forwardRelayEncodingTest.includes('forward-relay encodings: reject invalid decode state without throwing') &&
  auditRoadmap.includes('Forward relay shared compact encodings') &&
  auditDoc.includes('Hardened forward-relay compact encodings')
) {
  pass('forward-relay client/server encodings are shared, capped, and no-throw on malformed compact frames')
} else {
  fail('forward-relay encodings can drift between client/server or throw on malformed compact frames')
}

if (
  relayCircuitProtocol.includes('export const CIRCUIT_ID_BYTES = 16') &&
  relayCircuitProtocol.includes('export const MAX_CIRCUIT_DATA_MSG_BYTES = 64 * 1024') &&
  relayCircuitProtocol.includes('export const MAX_CIRCUIT_STATUS_MESSAGE_BYTES = 1024') &&
  relayCircuitProtocol.includes('export const circuitConnectEncoding') &&
  relayCircuitProtocol.includes('export const circuitDataEncoding') &&
  relayCircuitProtocol.includes('export const circuitStatusEncoding') &&
  relayCircuitProtocol.includes('export const circuitReadyEncoding') &&
  relayCircuitProtocol.includes('export const circuitCloseEncoding') &&
  relayCircuitProtocol.includes('function encodeUintValue') &&
  relayCircuitProtocol.includes('this.maxDataMsgBytes = Math.min(opts.maxDataMsgBytes || MAX_CIRCUIT_DATA_MSG_BYTES, MAX_CIRCUIT_DATA_MSG_BYTES)') &&
  relayCircuitProtocol.includes('encoding: circuitConnectEncoding') &&
  relayCircuitProtocol.includes('encoding: circuitStatusEncoding') &&
  relayCircuitProtocol.includes('encoding: circuitDataEncoding') &&
  relayCircuitProtocol.includes('encoding: circuitReadyEncoding') &&
  relayCircuitProtocol.includes('encoding: circuitCloseEncoding') &&
  clientSdk.includes("} from 'p2p-hiverelay/core/protocol/relay-circuit.js'") &&
  clientSdk.includes('encoding: circuitConnectEncoding') &&
  clientSdk.includes('encoding: circuitStatusEncoding') &&
  clientSdk.includes('encoding: circuitDataEncoding') &&
  clientSdk.includes('encoding: circuitReadyEncoding') &&
  clientSdk.includes('encoding: circuitCloseEncoding') &&
  !clientSdk.includes('c.fixed(16).decode(state)') &&
  !clientSdk.includes('c.fixed32.decode(state)') &&
  circuitRelayEncodingTest.includes('circuit-relay encodings: reject bad outbound messages before allocation growth') &&
  circuitRelayEncodingTest.includes('circuit-relay encodings: reject oversized declared inbound frames before decode materializes them') &&
  circuitRelayEncodingTest.includes('circuit-relay encodings: reject malformed and truncated frames without throwing') &&
  circuitRelayEncodingTest.includes('circuit-relay encodings: reject invalid decode state without throwing') &&
  auditRoadmap.includes('Circuit relay shared compact encodings') &&
  auditDoc.includes('Hardened circuit-relay compact encodings')
) {
  pass('circuit-relay client/server encodings are shared, capped, and no-throw on malformed compact frames')
} else {
  fail('circuit-relay encodings can drift between client/server or throw on malformed compact frames')
}

if (
  protocolMessages.includes('export const MAX_SEED_DISCOVERY_KEYS = 64') &&
  protocolMessages.includes('export const MAX_SEED_GEO_PREFERENCE_BYTES = 2048') &&
  protocolMessages.includes('export const MAX_SEED_REGION_BYTES = 64') &&
  protocolMessages.includes('export const MAX_SEED_DENY_REASON_BYTES = 128') &&
  protocolMessages.includes('export const MAX_SEED_DENY_DETAIL_BYTES = 512') &&
  protocolMessages.includes('function normalizeSeedRequest') &&
  protocolMessages.includes('function seedRequestError') &&
  protocolMessages.includes('function decodeJsonString') &&
  protocolMessages.includes('function decodeOptionalUint') &&
  protocolMessages.includes('too many discovery keys') &&
  protocolMessages.includes('geoPreference too large') &&
  protocolMessages.includes('region too large') &&
  protocolMessages.includes('reasonCode too large') &&
  protocolMessages.includes('detail too large') &&
  seedRequestProtocol.includes('MAX_PROTOCOL_HANDSHAKE_BYTES = 256') &&
  seedRequestProtocol.includes('function parseProtocolHandshake') &&
  seedRequestProtocol.includes("this.emit('invalid-handshake'") &&
  seedRequestProtocol.includes('channel.close()') &&
  seedRequestProtocol.includes('if (!msg || msg.error)') &&
  seedRequestProtocol.includes("this.emit('invalid-request'") &&
  seedRequestProtocol.includes("this.emit('invalid-accept'") &&
  seedRequestProtocol.includes("this.emit('invalid-unseed'") &&
  seedRequestProtocol.includes("this.emit('invalid-deny'") &&
  clientSdk.includes("this.emit('invalid-accept', { appKey: appKeyHex, reason: msg && msg.error ? msg.error : 'malformed seed accept' })") &&
  clientSdk.includes("this.emit('invalid-deny', { appKey: appKeyHex, reason: msg && msg.error ? msg.error : 'malformed seed deny' })") &&
  seedProtocolEncodingTest.includes('seed protocol encodings: reject bad outbound frames before allocation growth') &&
  seedProtocolEncodingTest.includes('seed protocol encodings: reject oversized declared inbound frames before materializing them') &&
  seedProtocolEncodingTest.includes('seed protocol encodings: reject malformed and truncated frames without throwing') &&
  seedProtocolEncodingTest.includes('seed protocol encodings: reject invalid decode state without throwing') &&
  seedProtocolEncodingTest.includes('SeedProtocol handlers ignore decoded seed protocol errors without throwing') &&
  seedProtocolEncodingTest.includes('SeedProtocol handshake accepts current version before pending replay') &&
  seedProtocolEncodingTest.includes('SeedProtocol handshake rejects malformed and oversized frames before pending replay') &&
  seedProtocolEncodingTest.includes('SeedProtocol handshake rejects mismatched major versions before pending replay') &&
  seedProtocolEncodingTest.includes('HiveRelayClient seed handlers ignore decoded seed protocol errors without throwing') &&
  auditRoadmap.includes('Seed request compact encodings') &&
  auditDoc.includes('Hardened seed-request compact encodings')
) {
  pass('seed protocol encodings and handshakes are capped and no-throw on malformed peer input across relay and client handlers')
} else {
  fail('seed protocol encodings, handshake parsing, or handlers can still allocate/throw or replay pending requests on malformed peer input')
}

if (
  serviceProtocol.includes('GLOB_METACHARS') &&
  serviceProtocol.includes('MAX_REMOTE_SUBSCRIBE_TOPICS_PER_MESSAGE') &&
  serviceProtocol.includes('MAX_REMOTE_SUBSCRIPTIONS_PER_PEER') &&
  serviceProtocol.includes("this.emit('subscription-error'") &&
  serviceProtocol.includes('this._cleanupPeer(remotePubkey, { emitClose: false })') &&
  serviceProtocol.includes('this._cleanupPeer(remotePubkey, { emitClose: true })') &&
  serviceProtocol.includes('this._peerSubscriptions.clear()') &&
  serviceProtocol.includes('this._peerRateState.clear()') &&
  serviceProtocol.includes('this._peerRoles.clear()') &&
  protocolSecurityTest.includes('protocol-security: detach cleans peer state and pending requests immediately') &&
  protocolSecurityTest.includes('protocol-security: destroy clears orphan peer limiter and subscription state')
) {
  pass('service protocol bounds remote pubsub subscriptions, rejects wildcard firehose requests, and clears peer lifecycle state')
} else {
  fail('service protocol is missing remote pubsub subscription abuse guards or peer lifecycle cleanup')
}

if (
  serviceProtocol.includes('PUBLIC_SERVICE_ERROR_CODES') &&
  serviceProtocol.includes('function publicServiceError') &&
  serviceProtocol.includes("this.emit('request-error'") &&
  serviceProtocol.includes("return 'SERVICE_ERROR'") &&
  protocolSecurityTest.includes('protocol-security: service RPC redacts unexpected provider errors on the wire') &&
  protocolSecurityTest.includes('protocol-security: service RPC preserves fixed public control-plane errors')
) {
  pass('service protocol redacts unexpected provider RPC errors while preserving fixed control-plane error codes')
} else {
  fail('service protocol can expose raw provider exceptions over peer-visible RPC error frames')
}

if (
  serviceProtocol.includes('const MSG_APP_CATALOG_DELTA = 8') &&
  serviceProtocol.includes('buildCatalogDelta') &&
  serviceProtocol.includes('applyCatalogDelta') &&
  serviceProtocol.includes('this._lastAppCatalogByPeer = new Map()') &&
  serviceProtocol.includes("this._buildCatalogMessage({ mode: 'delta', previousApps, envelope: fullMsg })") &&
  serviceProtocol.includes("this.emit('app-catalog-delta'") &&
  serviceProtocol.includes('Relay-to-relay auto-seeding only acts on additions') &&
  relayNode.includes('this.serviceProtocol._getCatalogEnvelope = (opts = {})') &&
  relayNode.includes('Array.isArray(opts.apps)') &&
  clientSdk.includes('_applyAppCatalogDelta') &&
  clientSdk.includes('msg.type === 8') &&
  protocolSecurityTest.includes('app catalog broadcasts use deltas after initial full sync') &&
  protocolSecurityTest.includes('incoming app catalog delta emits signed additions for relay sync') &&
  clientServiceTest.includes('applies app catalog deltas to relay cache') &&
  auditRoadmap.includes('Delta app-catalog sync') &&
  auditDoc.includes('Optimized P2P app-catalog fan-out') &&
  readme.includes('Delta app-catalog sync')
) {
  pass('service protocol sends full app catalogs on connect and signed app-catalog deltas for live churn')
} else {
  fail('service protocol can still re-broadcast full app catalogs for every live app change')
}

if (
  proofOfRelay.includes('const DEFAULT_MAX_PENDING_CHALLENGES = 2048') &&
  proofOfRelay.includes('const DEFAULT_MAX_BATCH_SIZE = 64') &&
  protocolMessages.includes('export const MAX_PROOF_BLOCK_BYTES = 1024 * 1024') &&
  protocolMessages.includes('export const MAX_PROOF_MERKLE_PROOF_BYTES = 64 * 1024') &&
  protocolMessages.includes('function normalizeProofResponse') &&
  protocolMessages.includes("decodeBytes(state, MAX_PROOF_BLOCK_BYTES, 'blockData too large', 'malformed proof response')") &&
  protocolMessages.includes("decodeBytes(state, MAX_PROOF_MERKLE_PROOF_BYTES, 'merkleProof too large', 'malformed proof response')") &&
  proofOfRelay.includes("this.emit('invalid-challenge'") &&
  proofOfRelay.includes("this.emit('invalid-response'") &&
  proofOfRelay.includes('this._maxPendingChallenges = opts.maxPendingChallenges') &&
  proofOfRelay.includes('this._maxBatchSize = opts.maxBatchSize') &&
  proofOfRelay.includes('this._reservePendingCapacity(requiredSlots)') &&
  proofOfRelay.includes("this.emit('batch-challenge-rejected'") &&
  proofOfRelay.includes("this.emit('challenge-rejected'") &&
  defaultConfig.includes('proofMaxPendingChallenges: 2048') &&
  defaultConfig.includes('proofMaxBatchSize: 64') &&
  relayNode.includes('maxPendingChallenges: this.config.proofMaxPendingChallenges') &&
  relayNode.includes('maxBatchSize: this.config.proofMaxBatchSize') &&
  proofOfRelayTest.includes('pending challenge cap rejects new single challenges') &&
  proofOfRelayTest.includes('oversized batch is rejected before allocating pending entries') &&
  proofOfRelayTest.includes('batch reserves one batch slot plus per-index slots') &&
  proofOfRelayTest.includes('proof encodings: reject bad outbound frames before allocation growth') &&
  proofOfRelayTest.includes('proof encodings: reject oversized declared inbound frames before materializing them') &&
  proofOfRelayTest.includes('proof encodings: reject malformed and truncated frames without throwing') &&
  proofOfRelayTest.includes('ProofOfRelay handlers ignore decoded proof protocol errors without throwing') &&
  protocolSpecDocs.includes('Legacy/reserved field; current verification relies on Hypercore transport integrity') &&
  protocolSpecDocs.includes('proofMaxPendingChallenges') &&
  protocolSpecDocs.includes('does not run a custom Merkle') &&
  developerDocs.includes('maxPendingChallenges: 2048') &&
  developerDocs.includes('Hypercore replication owns flat-tree integrity') &&
  auditRoadmap.includes('custom Merkle verification was removed') &&
  auditDoc.includes('Hardened proof-of-relay challenge accounting')
) {
  pass('proof-of-relay removes custom Merkle verification, bounds pending challenge state, and caps proof response frames')
} else {
  fail('proof-of-relay pending state, proof response buffers, or flat-tree integrity docs can regress')
}

if (
  signedDirectory.includes('export const MAX_SIGNED_DIRECTORY_WIRE_ENTRY_BYTES = 64 * 1024') &&
  signedDirectory.includes('export const MAX_SIGNED_DIRECTORY_LIST_RESPONSE_ENTRIES = 512') &&
  signedDirectory.includes('export const MAX_SIGNED_DIRECTORY_STATUS_MESSAGE_BYTES = 512') &&
  signedDirectory.includes('function normalizeEntry') &&
  signedDirectory.includes('function decodeBytes') &&
  signedDirectory.includes("decodeBytes(state, MAX_SIGNED_DIRECTORY_WIRE_ENTRY_BYTES, 'payload too large', 'malformed entry')") &&
  signedDirectory.includes("return { entries: [], error: 'too many entries' }") &&
  signedDirectory.includes('this.maxEntryBytes = positiveIntegerOption(opts.maxEntryBytes, DEFAULT_MAX_ENTRY_BYTES, MAX_SIGNED_DIRECTORY_WIRE_ENTRY_BYTES)') &&
  signedDirectory.includes('this.maxListResponseEntries = positiveIntegerOption(opts.maxListResponseEntries, MAX_SIGNED_DIRECTORY_LIST_RESPONSE_ENTRIES, MAX_SIGNED_DIRECTORY_LIST_RESPONSE_ENTRIES)') &&
  signedDirectory.includes('const decodedError = decodedEntryStatus(entry)') &&
  signedDirectory.includes('entries.slice(0, this.maxListResponseEntries)') &&
  signedDirectoryTest.includes('signed-directory encodings: reject bad outbound frames before allocation growth') &&
  signedDirectoryTest.includes('signed-directory encodings: reject oversized declared inbound frames before materializing them') &&
  signedDirectoryTest.includes('signed-directory encodings: reject malformed and truncated frames without throwing') &&
  signedDirectoryTest.includes('signed-directory handlers reject decoded protocol errors without storing') &&
  signedDirectoryTest.includes('signed-directory list responses are sliced to the wire response cap') &&
  auditRoadmap.includes('Signed directory wire bounds')
) {
  pass('signed-directory wire records, statuses, and list responses are capped and no-throw on malformed peer input')
} else {
  fail('signed-directory can accept unbounded record payloads, status strings, list responses, or decoded protocol errors')
}

if (
  autoHealCore.includes('const storage = this._storageCapacity()') &&
  autoHealCore.includes("reason: 'storage-capacity-unavailable'") &&
  autoHealCore.includes('!seeder || !Number.isFinite(cap) || cap <= 0') &&
  autoHealCore.includes('used >= cap * margin') &&
  autoHealCore.includes('usedBytes: storage.usedBytes') &&
  autoHealCore.includes('maxStorageBytes: storage.maxStorageBytes') &&
  autoHealTest.includes('AutoHeal: refuses to recruit when storage capacity state is unavailable') &&
  autoHealTest.includes('AutoHeal: refuses to recruit when maxStorageBytes is missing or invalid') &&
  autoHealTest.includes('seeder: null') &&
  autoHealTest.includes('maxStorageBytes: 0') &&
  auditRoadmap.includes('AutoHeal capacity fail-closed') &&
  auditDoc.includes('Hardened AutoHeal archive recruitment capacity gating')
) {
  pass('AutoHeal archive recruitment fails closed when storage capacity accounting is unavailable')
} else {
  fail('AutoHeal can still recruit archive replicas without reliable storage capacity accounting')
}

if (
  appLifecycleCore.includes('!Number.isSafeInteger(timestamp) || timestamp < 0') &&
  appLifecycleCore.includes("return { ok: false, error: 'MALFORMED_REQUEST' }") &&
  unseedVerifyTest.includes('valid unseed with matching publisher key and fresh timestamp') &&
  unseedVerifyTest.includes('wrong publisher key returns PUBLISHER_MISMATCH') &&
  unseedVerifyTest.includes('stale timestamp (> 5 min old) returns STALE_TIMESTAMP') &&
  unseedVerifyTest.includes('future timestamp (> 60s ahead) returns STALE_TIMESTAMP') &&
  unseedVerifyTest.includes('no publisher key on record returns NO_PUBLISHER_KEY') &&
  unseedVerifyTest.includes('invalid signature returns INVALID_SIGNATURE') &&
  unseedVerifyTest.includes('malformed timestamp returns MALFORMED_REQUEST (no throw)') &&
  unseedVerifyTest.includes('Date.now() + 0.5') &&
  unseedVerifyTest.includes('-1') &&
  auditRoadmap.includes('Unseed verification coverage') &&
  auditDoc.includes('Hardened authenticated unseed verification')
) {
  pass('authenticated unseed verification rejects malformed timestamps and has adversarial coverage')
} else {
  fail('authenticated unseed verification can regress on malformed timestamps or adversarial coverage')
}

if (
  quorumSelector.includes('const DEFAULT_MIN_OPERATORS = 3') &&
  quorumSelector.includes('adds the most missing dimensions') &&
  quorumSelector.includes('gain = (seenRegions.has(region) ? 0 : 1) + (seenOperators.has(op) ? 0 : 1)') &&
  quorumSelector.includes('function normalizedScore') &&
  quorumSelector.includes('Number.isFinite(score) && score >= 0 && score <= 1') &&
  quorumSelector.includes('function normalizedLatency') &&
  quorumSelector.includes('Number.isFinite(latencyMs) && latencyMs >= 0') &&
  quorumSelector.includes('insufficient-operator-diversity') &&
  quorumSelector.includes('observedOperators') &&
  quorumSelector.includes('requiredOperators') &&
  quorumSelectorTest.includes('prefers a new operator over a same-operator region-only pick') &&
  quorumSelectorTest.includes('warns when operator diversity is below the floor') &&
  quorumSelectorTest.includes('ignores malformed or unnormalized score claims') &&
  quorumSelectorTest.includes('ignores malformed latency claims when scores tie') &&
  threatModelDoc.includes('client `selectQuorum` now diversity-ranks by region and operator')
) {
  pass('client quorum selection prioritizes operator/region diversity and ignores malformed ranking signals')
} else {
  fail('client quorum selection can still over-prefer same-operator relays or malformed score/latency claims')
}

if (
  reputationCore.includes('const FORBIDDEN_RECORD_KEYS') &&
  reputationCore.includes('.sort(byLeaderboardRank)') &&
  reputationCore.includes('byCompositeRank') &&
  reputationCore.includes('Object.create(null)') &&
  reputationCore.includes('normalizeRecord') &&
  reputationCore.includes('FORBIDDEN_RECORD_KEYS.has(key)') &&
  reputationTest.includes('leaderboard ties are deterministic') &&
  reputationTest.includes('selectRelays ties are deterministic') &&
  reputationTest.includes('export order is deterministic and skips forbidden keys') &&
  reputationTest.includes('import sanitizes malformed persisted records') &&
  threatModelDoc.includes('deterministic local ranking/import/export shipped') &&
  auditDoc.includes('Hardened local reputation aggregation')
) {
  pass('reputation ranking and persistence import/export are deterministic and sanitized')
} else {
  fail('reputation ranking can still depend on insertion order or unsafe persisted records')
}

if (
  corePkg.dependencies['@grpc/grpc-js'] &&
  corePkg.dependencies['@grpc/proto-loader'] &&
  lightningProvider.includes("await import('@grpc/grpc-js')") &&
  lightningProvider.includes("await import('@grpc/proto-loader')") &&
  auditRoadmap.includes('optional LND `LightningProvider`') &&
  auditRoadmap.includes('preserving lazy startup') &&
  !auditRoadmap.includes('Remove `@grpc/grpc-js` + `@grpc/proto-loader` (unused') &&
  auditDoc.includes('Re-audited the dependency cleanup roadmap item') &&
  auditDoc.includes('intentional Lightning payment dependencies')
) {
  pass('Lightning gRPC dependencies are intentionally retained for the optional LND provider and stay lazy-loaded')
} else {
  fail('Lightning gRPC dependency cleanup notes or package/import alignment are stale')
}

if (
  cliIndex.includes("await import('./setup.js')") &&
  cliIndex.includes("await import('./manage.js')") &&
  !cliSetup.includes("from '@inquirer/prompts'") &&
  !cliManage.includes("from '@inquirer/prompts'") &&
  cliSetup.includes("await import('@inquirer/prompts')") &&
  cliManage.includes("await import('@inquirer/prompts')") &&
  cliSetup.includes('await loadPrompts()') &&
  cliManage.includes('await loadPrompts()') &&
  auditRoadmap.includes('Lazy-load `@inquirer/prompts` for interactive setup/manage TUI modules') &&
  auditDoc.includes('Lazy-loaded the interactive `@inquirer/prompts` dependency')
) {
  pass('interactive prompt dependency is lazy-loaded for setup/manage and kept off non-interactive CLI imports')
} else {
  fail('interactive prompt dependency can still load on non-interactive CLI imports or docs are stale')
}

if (
  cliIndex.includes("import { HiveRelayClient } from 'p2p-hiverelay-client'") &&
  !cliIndex.includes('p2p-hiverelay/client') &&
  developerDocs.includes("export { Router } from './router/index.js'") &&
  developerDocs.includes("export { PubSub } from './router/pubsub.js'") &&
  developerDocs.includes("export { WorkerPool } from './router/worker-pool.js'") &&
  !developerDocs.includes("export { HiveRelayClient } from '../client/index.js'") &&
  packageEntryPointsTest.includes("const installedCore = await import('p2p-hiverelay')") &&
  packageEntryPointsTest.includes("const installedClient = await import('p2p-hiverelay-client')") &&
  packageEntryPointsTest.includes("await import('p2p-hiverelay/client')") &&
  packageEntryPointsTest.includes('legacy bundled client subpath is not part of the 0.20 package contract')
) {
  pass('package entrypoint docs and CLI examples preserve the split client/core contract')
} else {
  fail('package entrypoint docs, CLI examples, or tests can drift back to the legacy bundled client path')
}

if (
  corePkg.dependencies['@noble/curves'] &&
  corePkg.dependencies['@noble/secp256k1'] &&
  corePkg.dependencies['@noble/hashes'] &&
  servicesPkg.dependencies['@noble/curves'] &&
  servicesPkg.dependencies['@noble/secp256k1'] &&
  servicesPkg.dependencies['@noble/hashes'] &&
  pvssCore.includes("import * as secp from '@noble/secp256k1'") &&
  pvssCore.includes("import { sha256 } from '@noble/hashes/sha2.js'") &&
  blindMintCore.includes("import { secp256k1 } from '@noble/curves/secp256k1.js'") &&
  blindMintCore.includes('Cashu NUT-00 BDHKE blind-signature mint') &&
  cashuCore.includes('cashuA') &&
  clientSecretSharing.includes("import * as secp from '@noble/secp256k1'") &&
  servicesIdentityCrypto.includes("import * as secp from '@noble/secp256k1'") &&
  servicesVrfEcv.includes("import { ed25519 } from '@noble/curves/ed25519.js'") &&
  pokerChaumPedersen.includes("import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519.js'") &&
  blindMintTest.includes('Official Cashu NUT-00 test vectors') &&
  blindMintTest.includes('BDHKE: full blind') &&
  cashuTest.includes('cashuA token: encode') &&
  auditRoadmap.includes('retain `@noble/curves` in core for Cashu NUT-00 BDHKE') &&
  auditDoc.includes('`@noble/curves` for Cashu NUT-00 BDHKE blind-mint field/point arithmetic') &&
  auditDoc.includes('`p2p-hiveservices` for VRF and poker logic')
) {
  pass('Noble crypto dependencies are scoped to core PVSS/Cashu and service-owned curve usage')
} else {
  fail('Noble crypto dependency scope or audit notes are stale')
}

const desktopPkg = readJson(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'package.json')
const desktopLock = readJson(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'package-lock.json')
const desktopLayoutGuard = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'scripts', 'check-hiverelay-layout.mjs')
const desktopCi = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', '.github', 'workflows', 'desktop-ci.yml')
const desktopReadme = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'README.md')
const desktopRelayClient = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'backend', 'relay-client.js')
const desktopReleasePackagingTest = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'test', 'release-packaging.test.js')
const desktopRelayClientHttpTest = readText(workspaceRoot, '01-browser', 'pearbrowser-desktop', 'test', 'relay-client-http.test.js')
const mobilePkg = readJson(workspaceRoot, '01-browser', 'PearBrowser', 'package.json')
const mobileLock = readJson(workspaceRoot, '01-browser', 'PearBrowser', 'package-lock.json')
const mobileRelayClient = readText(workspaceRoot, '01-browser', 'PearBrowser', 'backend', 'relay-client.js')
const mobileRelayClientTest = readText(workspaceRoot, '01-browser', 'PearBrowser', 'test', 'relay-client.test.js')
const pearBrowserComIndex = readText(workspaceRoot, '03-sites', 'pearbrowser-com', 'index.html')
const pearBrowserComManifest = readJson(workspaceRoot, '03-sites', 'pearbrowser-com', 'site-manifest.json')
const pearBrowserIntegrationDoc = readText(hiverelayRoot, 'docs', 'PEARBROWSER-INTEGRATION.md')
const pearIntegrationDoc = readText(hiverelayRoot, 'docs', 'PEAR-INTEGRATION.md')
const ecosystemUpgradeDoc = readText(hiverelayRoot, 'docs', 'ECOSYSTEM-UPGRADE-0.20.2.md')
const desktopDeps = desktopPkg.dependencies || {}
const expectedDesktopDeps = {
  'p2p-hiverelay': 'file:../../00-core/hiverelay/packages/core',
  'p2p-hiverelay-client': 'file:../../00-core/hiverelay/packages/client',
  'p2p-hiverelay-verifier': 'file:../../00-core/hiverelay/packages/verifier'
}
for (const [dep, expected] of Object.entries(expectedDesktopDeps)) {
  const actual = desktopDeps[dep]
  if (actual === expected) pass(`pearbrowser-desktop pins ${dep} to the local HiveRelay anchor`)
  else fail(`pearbrowser-desktop ${dep} is ${JSON.stringify(actual)}; expected ${JSON.stringify(expected)}`)
}

const desktopHiveRelayLockEntries = {
  'p2p-hiverelay': '../../00-core/hiverelay/packages/core',
  'p2p-hiverelay-client': '../../00-core/hiverelay/packages/client',
  'p2p-hiverelay-verifier': '../../00-core/hiverelay/packages/verifier'
}
const desktopHiveRelayDrift = []
for (const [dep, lockPath] of Object.entries(desktopHiveRelayLockEntries)) {
  const entry = desktopLock.packages?.[lockPath]
  if (entry?.name === dep && entry?.version === expectedVersion) {
    pass(`pearbrowser-desktop lockfile records ${dep}@${expectedVersion}`)
  } else {
    desktopHiveRelayDrift.push(`package-lock ${lockPath} records ${entry?.name || dep}@${entry?.version || '(missing)'} instead of ${dep}@${expectedVersion}`)
  }
}

const desktopClientLockEntry = desktopLock.packages?.['../../00-core/hiverelay/packages/client']
const expectedCoreRange = `^${expectedVersion}`
if (desktopClientLockEntry?.dependencies?.['p2p-hiverelay'] === expectedCoreRange) {
  pass(`pearbrowser-desktop client lockfile depends on p2p-hiverelay ${expectedCoreRange}`)
} else {
  desktopHiveRelayDrift.push(`package-lock client dependency p2p-hiverelay is ${JSON.stringify(desktopClientLockEntry?.dependencies?.['p2p-hiverelay'])}; expected ${expectedCoreRange}`)
}

const expectedDesktopLayoutGuardTerms = [
  `['p2p-hiverelay', '${expectedVersion}', '../../00-core/hiverelay/packages/core/package.json']`,
  `['p2p-hiverelay-client', '${expectedVersion}', '../../00-core/hiverelay/packages/client/package.json']`,
  `['p2p-hiverelay-verifier', '${expectedVersion}', '../../00-core/hiverelay/packages/verifier/package.json']`,
  `HiveRelay ${expectedVersion} packages`
]
const missingDesktopLayoutGuardTerms = missingTerms(desktopLayoutGuard, expectedDesktopLayoutGuardTerms)
if (missingDesktopLayoutGuardTerms.length === 0) {
  pass(`pearbrowser-desktop install guard expects HiveRelay ${expectedVersion}`)
} else {
  desktopHiveRelayDrift.push(`scripts/check-hiverelay-layout.mjs missing ${missingDesktopLayoutGuardTerms.map(term => JSON.stringify(term)).join(', ')}`)
}

const expectedDesktopCiTerms = [
  `ref: v${expectedVersion}`,
  `Guard HiveRelay ${expectedVersion} workspace layout`,
  `['p2p-hiverelay', '${expectedVersion}', 'pear-ecosystem/00-core/hiverelay/packages/core/package.json']`,
  `['p2p-hiverelay-client', '${expectedVersion}', 'pear-ecosystem/00-core/hiverelay/packages/client/package.json']`,
  `['p2p-hiverelay-verifier', '${expectedVersion}', 'pear-ecosystem/00-core/hiverelay/packages/verifier/package.json']`
]
const missingDesktopCiTerms = missingTerms(desktopCi, expectedDesktopCiTerms)
if (missingDesktopCiTerms.length === 0) {
  pass(`pearbrowser-desktop CI checks out and guards HiveRelay ${expectedVersion}`)
} else {
  desktopHiveRelayDrift.push(`desktop-ci.yml missing ${missingDesktopCiTerms.map(term => JSON.stringify(term)).join(', ')}`)
}

const expectedDesktopReadmeTerms = [
  `packages at \`${expectedVersion}\``,
  `Those \`${expectedVersion}\` packages are not published to npm yet`,
  `local \`${expectedVersion}\` workspace packages`
]
const missingDesktopReadmeTerms = missingTerms(desktopReadme, expectedDesktopReadmeTerms)
if (missingDesktopReadmeTerms.length === 0) {
  pass(`pearbrowser-desktop README names the bundled HiveRelay ${expectedVersion} packages`)
} else {
  desktopHiveRelayDrift.push(`README.md missing ${missingDesktopReadmeTerms.map(term => JSON.stringify(term)).join(', ')}`)
}

if (desktopHiveRelayDrift.length === 0) {
  pass(`pearbrowser-desktop bundle metadata is aligned with HiveRelay ${expectedVersion}`)
} else {
  warn(`pearbrowser-desktop is not yet aligned with HiveRelay ${expectedVersion}: ${desktopHiveRelayDrift.join('; ')}`)
}

const expectedBrowserHttpsDep = '^2.1.3'
const desktopRootLock = desktopLock.packages?.['']
const mobileRootLock = mobileLock.packages?.['']
if (
  desktopPkg.dependencies?.['bare-https'] === expectedBrowserHttpsDep &&
  desktopRootLock?.dependencies?.['bare-https'] === expectedBrowserHttpsDep &&
  mobilePkg.dependencies?.['bare-https'] === expectedBrowserHttpsDep &&
  mobileRootLock?.dependencies?.['bare-https'] === expectedBrowserHttpsDep
) {
  pass('PearBrowser desktop and mobile declare bare-https for public HTTPS relay gateways')
} else {
  fail('PearBrowser desktop/mobile package metadata is missing the direct bare-https relay transport dependency')
}

if (
  desktopRelayClient.includes("const https = require('bare-https')") &&
  desktopRelayClient.includes('function relayTransportForUrl') &&
  desktopRelayClient.includes("parsed.protocol === 'https:'") &&
  desktopRelayClient.includes('transport.get(relayRequestOptions(parsed)') &&
  desktopRelayClient.includes('transport.request({') &&
  desktopRelayClient.includes("parsed.protocol === 'https:' ? 443 : 80") &&
  desktopRelayClient.includes('DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024') &&
  desktopRelayClient.includes('DEFAULT_MAX_CONTROL_RESPONSE_BYTES = 1024 * 1024') &&
  desktopRelayClient.includes('positiveIntegerOption') &&
  desktopRelayClient.includes('relay response exceeded ' + '$' + '{maxBytes}' + ' bytes') &&
  desktopRelayClient.includes('req?.destroy?.()') &&
  desktopRelayClient.includes('module.exports = { RelayClient, relayRequestOptions }') &&
  desktopReleasePackagingTest.includes('RelayClient uses scheme-aware transport for public HTTPS gateways') &&
  desktopReleasePackagingTest.includes('DEFAULT_MAX_RESPONSE_BYTES') &&
  desktopRelayClientHttpTest.includes('RelayClient GET rejects oversized relay bodies and destroys the request') &&
  desktopRelayClientHttpTest.includes('RelayClient POST rejects oversized control responses and destroys the request') &&
  desktopRelayClientHttpTest.includes('RelayClient timeout actively destroys hanging relay requests')
) {
  pass('pearbrowser-desktop relay client uses tested scheme-aware HTTP/HTTPS transport with bounded relay responses')
} else {
  fail('pearbrowser-desktop relay client can regress to untested plain HTTP transport, wrong HTTPS defaults, or unbounded relay responses')
}

if (
  mobileRelayClient.includes("const https = require('bare-https')") &&
  mobileRelayClient.includes('function relayTransportForUrl') &&
  mobileRelayClient.includes("parsed.protocol === 'https:'") &&
  mobileRelayClient.includes('transport.get(relayRequestOptions(parsed)') &&
  mobileRelayClient.includes('transport.request({') &&
  mobileRelayClient.includes("parsed.protocol === 'https:' ? 443 : 80") &&
  mobileRelayClient.includes('module.exports = { RelayClient, relayRequestOptions }') &&
  mobileRelayClientTest.includes('relayRequestOptions uses scheme-aware default ports')
) {
  pass('PearBrowser mobile relay client uses tested scheme-aware HTTP/HTTPS transport for gateway fetches')
} else {
  fail('PearBrowser mobile relay client is missing tested HTTPS relay transport/default-port handling')
}

const desktopRelease = desktopReadme.match(/\*\*Current release:\*\*\s*`(v[^`]+)` · production length `(\d+)`/)
if (!desktopRelease) {
  fail('pearbrowser-desktop README is missing current release metadata for ecosystem sync checks')
} else {
  const [, desktopVersion, desktopLength] = desktopRelease
  const expectedHero = `Desktop ${desktopVersion} · production length ${desktopLength} · installer artifacts pending · macOS · Windows · Linux`
  const expectedSpec = `${desktopVersion} · production length ${desktopLength} · pinned on the HiveRelay backbone`
  if (
    pearBrowserComIndex.includes(expectedHero) &&
    pearBrowserComIndex.includes(expectedSpec) &&
    pearBrowserComManifest.desktopRelease?.version === desktopVersion &&
    pearBrowserComManifest.desktopRelease?.productionLength === Number(desktopLength)
  ) {
    pass('pearbrowser.com release metadata is synced to the bundled PearBrowser desktop README')
  } else {
    fail('pearbrowser.com release metadata is stale relative to the bundled PearBrowser desktop README')
  }
}

if (
  pearBrowserIntegrationDoc.includes(`## Current ${expectedVersion} ecosystem alignment`) &&
  pearBrowserIntegrationDoc.includes('Pear Browser desktop') &&
  pearBrowserIntegrationDoc.includes('main bundled consumer') &&
  pearBrowserIntegrationDoc.includes(`bigdestiny2/P2P-Hiverelay@v${expectedVersion}`) &&
  pearBrowserIntegrationDoc.includes('HTTPS relay transport') &&
  pearBrowserIntegrationDoc.includes('signed capability-doc verification') &&
  pearBrowserIntegrationDoc.includes('DHT relay-record bootstrap') &&
  pearBrowserIntegrationDoc.includes('indexRoom') &&
  pearBrowserIntegrationDoc.includes('npm run audit:ecosystem-consumers') &&
  pearBrowserIntegrationDoc.includes('ECOSYSTEM-UPGRADE-0.20.2.md') &&
  pearBrowserIntegrationDoc.includes('live customer-facing relay consumers') &&
  pearBrowserIntegrationDoc.includes('workspace package manifests and lockfiles') &&
  pearBrowserIntegrationDoc.includes('stale lockfile') &&
  pearBrowserIntegrationDoc.includes('metadata such as old monorepo-root') &&
  pearIntegrationDoc.includes(`current Hiverelay workspace packages are:\n\n- \`p2p-hiverelay\` \`${expectedVersion}\``) &&
  pearIntegrationDoc.includes('Mobile is currently an HTTP/catalog consumer rather than a direct') &&
  pearIntegrationDoc.includes('non-bundled direct consumers') &&
  pearIntegrationDoc.includes('signed DHT relay records, and `indexRoom`') &&
  pearIntegrationDoc.includes('npm run audit:ecosystem-consumers') &&
  pearIntegrationDoc.includes('ECOSYSTEM-UPGRADE-0.20.2.md') &&
  pearIntegrationDoc.includes('live customer-facing relay')
) {
  pass(`HiveRelay docs track Pear Browser ${expectedVersion} bundle, API, and mobile parity updates`)
} else {
  fail('HiveRelay Pear Browser integration docs are missing the current bundle, API, or mobile parity update notes')
}

if (
  monorepoPkg.scripts['audit:ecosystem-consumers'] === 'node scripts/audit-ecosystem-consumers.mjs --check' &&
  monorepoPkg.scripts['ecosystem:sync'] === 'node scripts/sync-ecosystem-consumers.mjs' &&
  ecosystemConsumersAudit.includes('EXPECTED_CURRENT_CONSUMERS') &&
  ecosystemConsumersAudit.includes('EXPECTED_STALE_CONSUMERS') &&
  ecosystemConsumersAudit.includes('CURRENT_HIVERELAY_VERSION') &&
  ecosystemConsumersAudit.includes('termTemplate') &&
  ecosystemConsumersAudit.includes('01-browser/pearbrowser-desktop/package.json') &&
  ecosystemConsumersAudit.includes('02-apps/pearpaste/package.json') &&
  ecosystemConsumersAudit.includes('customer encrypted-availability app') &&
  ecosystemConsumersAudit.includes('02-apps/pear-pos/package.json') &&
  ecosystemConsumersAudit.includes('02-apps/pear-tickets/package.json') &&
  ecosystemConsumersAudit.includes('03-sites/pearbrowser-publishers/src/p2pbuilders/package.json') &&
  ecosystemConsumersAudit.includes('publisher-site consumer') &&
  ecosystemConsumersAudit.includes('file:../../../../00-core/hiverelay/packages/client') &&
  ecosystemConsumersAudit.includes('04-experiments/Opengit/packages/opengit-relay/package.json') &&
  ecosystemConsumersAudit.includes('optional Opengit blind-relay bridge') &&
  ecosystemConsumersAudit.includes('Opengit integration note names current workspace defaults') &&
  ecosystemConsumersAudit.includes('04-experiments/anongpt-native/package.json') &&
  ecosystemConsumersAudit.includes('customer relay/onion AI app') &&
  ecosystemConsumersAudit.includes('04-experiments/hiverelay-test/package.json') &&
  ecosystemConsumersAudit.includes('PearBrowser catalog advertises the current Hiverelay app release') &&
  ecosystemConsumersAudit.includes('PearBrowser backbone handover names the current Hiverelay workspace line') &&
  ecosystemConsumersAudit.includes('POS CJS bridge comment names the current split-client package line') &&
  ecosystemConsumersAudit.includes('00-core/hr-fleet/') &&
  ecosystemConsumersAudit.includes('scanCurrentConsumerLockChecks') &&
  ecosystemConsumersAudit.includes('Lockfile migration checks') &&
  ecosystemConsumersAudit.includes('stale monorepo-root Hiverelay lock entry') &&
  ecosystemConsumersAudit.includes('sourceChecks') &&
  ecosystemConsumersAudit.includes('scanConsumerSourceChecks') &&
  ecosystemConsumersAudit.includes('scanStaleConsumerSourceChecks') &&
  ecosystemConsumersAudit.includes('rejectTerms') &&
  ecosystemConsumersAudit.includes('Disallowed source-level migration marker found') &&
  ecosystemConsumersAudit.includes('Source-level migration checks') &&
  ecosystemConsumersAudit.includes('row.action') &&
  ecosystemConsumersSync.includes('syncEcosystemConsumers') &&
  ecosystemConsumersSync.includes('EXPECTED_CURRENT_CONSUMERS') &&
  ecosystemConsumersSync.includes('setDependency') &&
  ecosystemConsumersSync.includes('syncConsumerSourceMarkers') &&
  ecosystemConsumersSync.includes('termTemplateRegex') &&
  ecosystemConsumersSync.includes('scanCurrentConsumerLockChecks') &&
  ecosystemConsumersSync.includes('linked package metadata') &&
  ecosystemConsumersSync.includes('--check') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit classifies current, stale, and ignored consumers') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit fails on unclassified Hiverelay pins') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit fails when the known stale inventory changes') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit reports source-level migration markers') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit guards PearPaste current Hiverelay docs') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit guards PearBrowser and POS current Hiverelay source defaults') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit fails when source-level migration markers move') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit verifies lockfile local package metadata') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit rejects stale lockfile Hiverelay entries') &&
  ecosystemConsumersAuditTest.includes('ecosystem consumer audit finds monorepo package lockfiles') &&
  ecosystemConsumersAuditTest.includes('ecosystem sync updates app defaults and linked package lock metadata') &&
  ecosystemConsumersAuditTest.includes('ecosystem sync updates versioned app source markers') &&
  readme.includes('ECOSYSTEM-UPGRADE-0.20.2.md') &&
  readme.includes('npm run ecosystem:sync -- --check') &&
  ecosystemUpgradeDoc.includes('p2p-hiverelay/client') &&
  ecosystemUpgradeDoc.includes('p2p-hiverelay-client') &&
  ecosystemUpgradeDoc.includes('01-browser/pearbrowser-desktop') &&
  ecosystemUpgradeDoc.includes('02-apps/pearpaste') &&
  ecosystemUpgradeDoc.includes('02-apps/pear-pos') &&
  ecosystemUpgradeDoc.includes('02-apps/pear-tickets') &&
  ecosystemUpgradeDoc.includes('03-sites/pearbrowser-publishers/src/p2pbuilders') &&
  ecosystemUpgradeDoc.includes('test/m12-hiverelay-client-migration.js') &&
  ecosystemUpgradeDoc.includes('Opengit') &&
  ecosystemUpgradeDoc.includes('dynamically imports the split client') &&
  ecosystemUpgradeDoc.includes('04-experiments/anongpt-native') &&
  ecosystemUpgradeDoc.includes('test/hiverelay-upgrade.test.cjs') &&
  ecosystemUpgradeDoc.includes('04-experiments/hiverelay-test') &&
  ecosystemUpgradeDoc.includes('Lockfiles do not retain stale monorepo-root HiveRelay records') &&
  ecosystemUpgradeDoc.includes('Security tests still prove that app plaintext is not exported to relays') &&
  ecosystemUpgradeDoc.includes('every direct app consumer to point at the current local') &&
  ecosystemUpgradeDoc.includes('PearBrowser catalog') &&
  ecosystemUpgradeDoc.includes('PearPaste customer docs/probes') &&
  ecosystemUpgradeDoc.includes('Pear POS bridge docs/comments') &&
  ecosystemUpgradeDoc.includes('cannot quietly drift back') &&
  ecosystemUpgradeDoc.includes('to old client guidance') &&
  ecosystemUpgradeDoc.includes('versioned source markers') &&
  ecosystemUpgradeDoc.includes('npm run ecosystem:sync') &&
  pearBrowserIntegrationDoc.includes('npm run ecosystem:sync') &&
  pearIntegrationDoc.includes('npm run ecosystem:sync')
) {
  pass('ecosystem consumer sync/audit commands guard PearBrowser bundle pins, known stale consumers, snapshot exclusions, and app-level migration notes')
} else {
  fail('ecosystem consumer sync/audit commands, docs, or tests are missing current/stale consumer drift or app-level migration coverage')
}

const mobileReadme = readText(workspaceRoot, '01-browser', 'PearBrowser', 'README.md')
if (mobileReadme.includes('/catalog.json') && mobileReadme.includes('/.well-known/hiverelay.json')) {
  pass('PearBrowser README documents the HTTP catalog and capability-doc relay contracts')
} else {
  fail('PearBrowser README is missing the catalog or capability-doc relay contract')
}

if (
  pearBrowserDemoManifest.id === 'pearbrowser-marketplace-demo' &&
  pearBrowserDemoManifest.entry === '/index.html' &&
  pearBrowserDemoManifest.contentType === 'app' &&
  Array.isArray(pearBrowserDemoManifest.categories) &&
  pearBrowserDemoManifest.categories.length > 0
) {
  pass('PearBrowser marketplace demo manifest exposes the minimum browser-consumable metadata')
} else {
  fail('PearBrowser marketplace demo manifest is missing required browser metadata')
}

if (
  pearBrowserDemoReadme.includes('npm run demo:pearbrowser') &&
  pearBrowserDemoReadme.includes('/catalog.json') &&
  pearBrowserDemoReadme.includes('/.well-known/hiverelay.json')
) {
  pass('PearBrowser marketplace demo README documents the local browser-relay smoke flow')
} else {
  fail('PearBrowser marketplace demo README is missing the demo runbook or relay contract notes')
}

if (pearBrowserDemoHtml.includes('<h1>HiveRelay Marketplace Demo</h1>') && pearBrowserDemoHtml.includes('./app.js')) {
  pass('PearBrowser marketplace demo fixture includes a visible landing page and client bootstrap')
} else {
  fail('PearBrowser marketplace demo fixture is missing its landing page heading or client bootstrap')
}

const rootReadme = readText(hiverelayRoot, 'README.md')
const statusMatch = rootReadme.match(/Status:\s*v(\d+\.\d+\.\d+)/)
if (!statusMatch) warn('README status line is missing a parseable version badge')
else if (statusMatch[1] !== expectedVersion) warn(`README status badge is ${statusMatch[1]} while monorepo version is ${expectedVersion}`)
else pass(`README status badge matches monorepo version (${expectedVersion})`)

const rootReadmeRequiredTerms = [
  'Core3 blind relay infrastructure',
  '**Blindspark** is the appliance packaging',
  'structured for GitHub `main`',
  '### Current Publication Status',
  'npm run release:prepare',
  '## Architecture',
  '## Schemas And Contracts',
  '## HTTP And P2P API Surface',
  '## Client SDK And Verification',
  '## Use Cases',
  '## Blindspark On Umbrel And StartOS',
  '## Live Fleet And Release Automation',
  '### Live Vs Review-Gated Distribution',
  '### Dashboard State',
  '### Relay System Graph',
  '```mermaid',
  'Clients and Operators',
  'Network and Ingress',
  'HiveRelay Core3 Kernel',
  'P2P Protocol Channels',
  'Public Schemas and Evidence Contracts',
  'Release, Fleet, and Store Distribution',
  'Security and Runtime Guardrails',
  'GHCR image<br/>OCI multi-arch digest',
  'release-surfaces.yml<br/>tests, lint, audit, smoke',
  'HiveRelay is four connected layers',
  'The same source tree supports three deployment shapes',
  'Current-main v0.17-v0.20 surfaces',
  'HIVERELAY_MAX_STORAGE=10GB',
  'operator config wins',
  '`verifySeeded(driveKey, { relay })`',
  '`proveSeeded(driveKey, { relay, samples })`',
  '`StorageProofService`',
  '`subscribeService(service, event, onEvent, opts?)`',
  '`storage-proof`',
  '`storage-proof.prove`',
  'DHT-over-WS',
  'Hypercore-over-WS',
  '`hiverelay-circuit`',
  '`hiverelay-signed-directory`',
  '`Range`',
  '`Accept-Ranges`',
  '`/api/peers` is capped at 1000',
  '`GET /api/peers`, legacy `GET /peers`',
  'malformed peer metadata redacted',
  '`/api/registry` enriches at most',
  '500 active requests with 100',
  'relays per request',
  'returning shaped fields',
  '`GET /api/registry`, `/api/manage/catalog/*`, `/api/registry/*`',
  'registry status is bounded and sanitized before relay enrichment',
  'Operator diagnostics',
  '`/api/health-detail`, `/api/storage/top`, `/api/auto-heal`, `/api/history`',
  'metrics history filters malformed timestamps',
  'metrics history snapshots are capped and shaped',
  'health actions, storage rows, AutoHeal drives, and metrics history snapshots are capped and shaped',
  'bounded metrics history payloads',
  '`catalogBeeKey`',
  '`indexRoom`',
  'DHT relay records',
  'Paid pin leases are off by default',
  '`POST /seed-core`',
  '/api/lease',
  '/api/dedup/reclaim',
  '/api/manage/index-room',
  '`POST /api/usage/receipt`',
  'StorageAccounting',
  'ServedAccounting',
  'release-evidence.json',
  'release-image-manifest-evidence.json',
  'release image manifest platform proof',
  '`linux/amd64` and `linux/arm64`',
  'smoke sidecars must not predate the multi-arch image-manifest proof',
  'Smoke sidecars are accepted only after the pinned multi-arch image',
  'fleet inventory digest',
  'A release is live on the selected fleet only when',
  'bounded probe timing',
  '`timeoutMs`, `intervalMs`, `sshTimeoutMs`',
  'Release and handoff verifiers reject missing, malformed, too',
  'release-image-smoke-evidence.json',
  'umbrel-package-smoke-evidence.json',
  'dashboard WebSocket auth',
  'official-umbrel-pr-evidence.json',
  'runtimeReview.status: pending-real-device-review',
  'umbrel-runtime-review-evidence.json',
  'optional real Umbrel runtime-review sidecar',
  'startos-registry-evidence.json',
  'StartOS registry evidence SHA-256',
  'release:verify-handoff-evidence',
  'fleet rollout sidecar/link',
  'What moves on a full release',
  'Official Umbrel App Store | A draft `getumbrel/umbrel-apps` PR can be opened or refreshed',
  'Umbrel review plus real-device runtime evidence before review-ready handoff',
  'Official Start9 marketplace | Marketplace/community inclusion remains review-controlled',
  'Verify Umbrel PR, fleet rollout, StartOS registry, and optional real Umbrel runtime-review handoff sidecars',
  'Official Umbrel App Store publication still requires the upstream',
  '`getumbrel/umbrel-apps` PR/review flow',
  'Official App Store inclusion still needs the upstream',
  'Official Start9 marketplace/community registry inclusion still requires Start9',
  'review. Full releases can publish to a configured StartOS registry',
  'Full releases can publish to a configured StartOS registry',
  'Stable releases are distribution-complete by default',
  'Prereleases stay isolated with `channel=none`',
  'inventory is [fleet/relays.json]',
  'fleet/channels.json',
  '/api/manage/services/config',
  'POST /api/manage/services',
  'live disable/restart',
  'GET /api/usage',
  'GET /api/poker/usage',
  'WSS `/ws/replicate`, WSS `/ws/dht`',
  '`npm run release:check-image-manifest`',
  'Reader replicas',
  'Identity and devices',
  'Wallet destination | `GET /api/subsidy`, `POST /api/subsidy/destination` | management auth',
  '/.well-known/hiverelay.json'
]
const rootReadmeSdkMethods = [
  'publish',
  'open',
  'seed',
  'unseed',
  'getDurableStatus',
  'waitForDurable',
  'splitForCustody',
  'reconstructFromCustody',
  'fetchCapabilities',
  'queryQuorumWithComparison',
  'callService',
  'mirror',
  'unmirror',
  'registerCommunityReplicas',
  'enableCommunityReplicas',
  'disableCommunityReplicas',
  'exportIdentity',
  'importIdentity',
  'createDeviceAttestation',
  'verifyDeviceAttestation',
  'createCertRevocation',
  'createPairingCode',
  'claimPairingCode'
]
const missingReadmeTerms = missingTerms(rootReadme, rootReadmeRequiredTerms)
const missingReadmeSdkMethods = rootReadmeSdkMethods.filter(name => !rootReadme.includes('`' + name + '`') || !clientSdk.includes(name + ' ('))

if (missingReadmeTerms.length === 0 && missingReadmeSdkMethods.length === 0) {
  pass('README documents current Core3 architecture, v0.20 surfaces, schemas, APIs, SDK surfaces, packages, and live fleet release model')
} else {
  const missing = [
    ...missingReadmeTerms.map(term => `term ${JSON.stringify(term)}`),
    ...missingReadmeSdkMethods.map(name => `SDK method ${name}`)
  ]
  fail(`README is missing current Core3 architecture/schema/API/SDK/package/fleet coverage: ${missing.join(', ')}`)
}

const architectureGraphRequiredTerms = [
  '# HiveRelay Core3 Architecture Graph',
  '## System Graph',
  '## Relay Conversation Graph',
  '## Release And Live Fleet Graph',
  '## Standards And Primitives',
  '## API And Contract Map',
  '## Security Boundaries',
  '## Primary Use Cases',
  'flowchart LR',
  'sequenceDiagram',
  'flowchart TB',
  'Live Ecosystem Consumers',
  'PearBrowser desktop/mobile',
  'PearPaste',
  'anonGPT native',
  'Core3 Relay Kernel',
  'HyperDHT / Hyperswarm',
  'HTTP gateway',
  'WebSocket gateway',
  'hiverelay-seed',
  'hiverelay-publish',
  'hiverelay-custody',
  'hiverelay-proof',
  'hiverelay-anchor',
  'hiverelay-circuit',
  'hiverelay-forward',
  'hiverelay-services',
  'storage-proof',
  'Poker / SignedLog',
  'catalogBeeKey',
  'release-image-manifest-evidence.json',
  'fleet-rollout-evidence.json',
  'umbrel-package-smoke-evidence.json',
  'startos-registry-evidence.json',
  'app-proxy writes + setup links',
  'bounded lease polling + static markup',
  'Ecosystem consumer audit',
  'Privacy policy guard',
  'Dashboard WebSocket',
  'Operator controls',
  'App-proxy UI writes',
  'PearBrowser bundle delivery',
  'PearPaste private availability',
  'anonGPT relay/onion AI',
  'Full release defaults to both canary and stable'
]
const architectureGraphMissingTerms = missingTerms(architectureGraphDoc, architectureGraphRequiredTerms)
const architectureGraphSvgRequiredTerms = [
  '<title id="title">HiveRelay Core3 architecture graph</title>',
  'PearBrowser',
  'PearPaste',
  'anonGPT',
  'Consumer audit keeps PearBrowser desktop',
  'Core3 Relay Kernel',
  'HyperDHT / Hyperswarm',
  'HTTP gateway',
  'WebSocket ingress',
  'hiverelay-seed',
  'hiverelay-publish / custody',
  'hiverelay-proof / anchor',
  'hiverelay-circuit / forward',
  'hiverelay-services',
  'SERVICES AND CONTRACTS',
  'SECURITY BOUNDARIES',
  'LIVE RELEASE DISTRIBUTION',
  'GitHub Release',
  'GHCR digest',
  'fleet/channels',
  'release evidence',
  'Umbrel package',
  'app_proxy proof',
  'Official PR',
  'StartOS .s9pk',
  'registry proof',
  'PearBrowser bundle',
  'PearPaste availability',
  'anonGPT / AI services'
]
const architectureGraphSvgMissingTerms = missingTerms(architectureGraphSvg, architectureGraphSvgRequiredTerms)
const architectureGraphMermaidBlocks = (architectureGraphDoc.match(/^```mermaid$/gm) || []).length
if (
  rootReadme.includes('[docs/HIVERELAY-ARCHITECTURE-GRAPH.md](docs/HIVERELAY-ARCHITECTURE-GRAPH.md)') &&
  rootReadme.includes('[docs/assets/hiverelay-core3-architecture.svg](docs/assets/hiverelay-core3-architecture.svg)') &&
  architectureGraphDoc.includes('![HiveRelay Core3 architecture static SVG](assets/hiverelay-core3-architecture.svg)') &&
  architectureGraphMissingTerms.length === 0 &&
  architectureGraphSvgMissingTerms.length === 0 &&
  architectureGraphMermaidBlocks >= 3
) {
  pass('architecture graph doc and SVG are linked from README and cover relay, protocol, API, security, use-case, and release/fleet surfaces')
} else {
  const missing = [
    ...architectureGraphMissingTerms.map(term => `term ${JSON.stringify(term)}`),
    ...architectureGraphSvgMissingTerms.map(term => `SVG term ${JSON.stringify(term)}`),
    architectureGraphMermaidBlocks >= 3 ? null : `at least 3 mermaid blocks (found ${architectureGraphMermaidBlocks})`,
    rootReadme.includes('[docs/HIVERELAY-ARCHITECTURE-GRAPH.md](docs/HIVERELAY-ARCHITECTURE-GRAPH.md)') ? null : 'README graph doc link',
    rootReadme.includes('[docs/assets/hiverelay-core3-architecture.svg](docs/assets/hiverelay-core3-architecture.svg)') ? null : 'README graph SVG link',
    architectureGraphDoc.includes('![HiveRelay Core3 architecture static SVG](assets/hiverelay-core3-architecture.svg)') ? null : 'architecture graph doc SVG embed'
  ].filter(Boolean)
  fail(`architecture graph doc or SVG is missing release-ready coverage: ${missing.join(', ')}`)
}

const currentTestMatrixRequiredTerms = [
  'Hiverelay Test Command Matrix - 2026-06-27',
  '`npm test`',
  '`npm run lint`',
  '`npm run audit:workspace`',
  '`npm run ecosystem:sync -- --check`',
  '`npm run audit:ecosystem-consumers`',
  '`npm run audit:public-artifacts`',
  '`node --test test/unit/ecosystem-consumers.test.js`',
  '`git diff --check`',
  '13/13',
  '64/64',
  'PearPaste recovery/spec doc regressions',
  'public-artifact-secret-scan.test.js',
  'release-secret-template.test.js',
  '312/312',
  'public-artifact secret-pattern scanning',
  'exact post-apply setup/preflight command output',
  'fleet-rollout-check.test.js',
  'PearBrowser desktop',
  'PearPaste',
  'anonGPT native',
  'Full releases with no explicit channel resolve to `both`.',
  'Standalone `fleet:check-rollout` also defaults to `both`',
  'Prereleases with no explicit channel resolve to `none`.',
  'npm run release:write-secret-template',
  'release-distribution-preflight.yml',
  'fleet-rollout-evidence.json',
  'Official Umbrel PR evidence',
  'startos-registry-evidence.json',
  '28293455583',
  'versioned source markers',
  '`channel=both` and `prerelease=false`'
]
const currentTestMatrixMissingTerms = missingTerms(testCommandMatrix20260627, currentTestMatrixRequiredTerms)
if (
  rootReadme.includes('[docs/TEST-COMMAND-MATRIX-2026-06-27.md](docs/TEST-COMMAND-MATRIX-2026-06-27.md)') &&
  rootReadme.includes('npm run audit:ecosystem-consumers') &&
  rootReadme.includes('npm test') &&
  currentTestMatrixMissingTerms.length === 0
) {
  pass('README links the current 2026-06-27 command matrix with ecosystem-consumer, release-secret-template, full-suite, and external-gate evidence')
} else {
  const missing = [
    ...currentTestMatrixMissingTerms.map(term => `term ${JSON.stringify(term)}`),
    rootReadme.includes('[docs/TEST-COMMAND-MATRIX-2026-06-27.md](docs/TEST-COMMAND-MATRIX-2026-06-27.md)') ? null : 'README current command-matrix link',
    rootReadme.includes('npm run audit:ecosystem-consumers') ? null : 'README ecosystem audit command',
    rootReadme.includes('npm test') ? null : 'README full test command'
  ].filter(Boolean)
  fail(`current 2026-06-27 command matrix is missing ship-readiness coverage: ${missing.join(', ')}`)
}

const readmeMainUpdateRequiredTerms = [
  'Published GitHub `main` package version: `0.20.0`',
  'Remote `origin/main` commit rechecked on 2026-06-24',
  '34f8415a1e4cbfd228ced5a2eb008b28992b5ef7',
  'chore(startos): guard the s9pk image-digest pin',
  'published `README.md` blob is',
  'replace GitHub `main` as-is',
  'Do not publish the local `0.16.3` status line',
  'public `v0.20.0` status/version surface',
  '`0.17.0` through `0.20.0` features',
  '`verifySeeded(driveKey, { relay })`',
  '`proveSeeded(driveKey, { relay, samples })`',
  '`umbrel-runtime-review-evidence.json`',
  '`StorageProofService`',
  '`subscribeService(service, event, onEvent, opts?)`',
  "`client.subscribeService('poker', tableKey, ...)`",
  '`storage-proof` service',
  '`catalogBeeKey`',
  '`indexRoom`',
  'DHT-resolvable signed relay records',
  'Paid pin-lease primitives',
  'Durable bare-core pinning through `POST /seed-core`',
  'DHT-over-WS',
  'Hypercore-over-WS',
  '`hiverelay-circuit` NAT fallback',
  '`hiverelay-signed-directory`',
  '`exportIdentity`',
  '`createPairingCode`',
  'device attestation verification/revocation',
  '`mirror`',
  '`enableCommunityReplicas`',
  '/api/lease',
  '/api/peers',
  '/api/registry',
  '/api/health-detail',
  '/api/storage/top',
  '/api/auto-heal',
  '/api/history',
  '/api/dedup/reclaim',
  '/api/manage/index-room',
  '`/api/manage/services` live disable/restart',
  'durable service disable persistence before unregister',
  'release-image-manifest-evidence.json',
  'runtime-review evidence',
  '`linux/amd64` and',
  '`linux/arm64` manifests',
  'official Umbrel App Store or StartOS marketplace',
  'official store inclusion remains review-controlled',
  '**Live Vs Review-Gated Distribution**',
  '**Current Publication Status**',
  'external proof files still needed',
  'image-manifest-before-smoke chronology',
  '`getumbrel/umbrel-apps` PR/review process',
  'Start9 review',
  'README drift guard'
]
const missingReadmeAuditTerms = missingTerms(readmeMainUpdateAudit, readmeMainUpdateRequiredTerms)
if (missingReadmeAuditTerms.length === 0) {
  pass('README main update audit preserves v0.20 surfaces and marketplace-review caveats')
} else {
  fail(`README main update audit is missing v0.20 surface or store-review coverage: ${missingReadmeAuditTerms.map(term => JSON.stringify(term)).join(', ')}`)
}

const roadmapRequiredTerms = [
  'Living audit roadmap',
  'Current External Proof Gaps',
  'Current Remaining Engineering Gaps',
  'external review-controlled',
  'test/unit/api-service-config.test.js',
  'test/unit/protocol-json-encoding.test.js',
  'test/unit/umbrel-ui-controls.test.js',
  'test/unit/release-evidence.test.js',
  'fleet-rollout-evidence.json',
  'release-image-manifest-evidence.json',
  'docs/SHIP-HANDOFF-2026-06-26.md',
  'Validated GitHub secret rotation helper',
  'GitHub secret apply failure redaction',
  'Hermetic release env-file validation'
]
const roadmapForbiddenTerms = [
  'Doc may be partially out of date',
  'REFACTOR-NOTES.md',
  '0 tests for 25+ routes',
  'all untested',
  'No tests for malformed messages'
]
const missingRoadmapTerms = missingTerms(auditRoadmap, roadmapRequiredTerms)
const staleRoadmapTerms = roadmapForbiddenTerms.filter(term => auditRoadmap.includes(term))
if (missingRoadmapTerms.length === 0 && staleRoadmapTerms.length === 0) {
  pass('audit roadmap names current external proof gaps and no longer advertises stale zero-coverage claims')
} else {
  fail(`audit roadmap drifted: missing ${missingRoadmapTerms.map(term => JSON.stringify(term)).join(', ') || 'none'}; stale ${staleRoadmapTerms.map(term => JSON.stringify(term)).join(', ') || 'none'}`)
}

const currentShipHandoffRequiredTerms = [
  'Generated by `npm run docs:update-ship-handoff`',
  'HEAD inspected: `94580c6`',
  'Commit subject: `release: sync ecosystem consumer defaults`',
  'Worktree: clean snapshot (`main@94580c6`)',
  'Inspected commit CI finished green',
  'Post-merge main Test run: `28293344980`',
  'Post-merge Docker snapshot publish: `28293344978`',
  'Release distribution preflight run: `28293455583` (issue #120)',
  'Run URL: https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/28293455583',
  'Latest checked preflight: state `completed/failure`, head `main@94580c6`, created `2026-06-27T15:27:01Z`',
  'Earlier passing preflight `28238930607` at `1ffffe6` is superseded by this newer failure',
  'UMBREL_STORE_TOKEN must be a GitHub token without whitespace or control characters',
  'UMBREL_OFFICIAL_PR_TOKEN must be a GitHub token without whitespace or control characters',
  'UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug with a normal owner name and must not be getumbrel/umbrel-apps',
  'STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames',
  'Release default probes were regenerated from',
  'Full releases with no explicit channel resolve to `both`',
  'Prereleases with no explicit channel resolve to `none`',
  'node --test test/unit/ecosystem-consumers.test.js',
  'direct-consumer default-pinning',
  'before any image is published',
  'lockfile metadata plus versioned source markers',
  'npm run release:check-distribution-env',
  '--env-file /private/tmp/hiverelay-release-secrets.env',
  '--channel both',
  '--prerelease false',
  'npm run release:apply-github-secrets',
  'Docker runtime hardening',
  'docs/assets/hiverelay-core3-architecture.svg'
]
const missingShipHandoffTerms = missingTerms(shipHandoff20260626, currentShipHandoffRequiredTerms)
const shipHandoffUpdaterOk =
  monorepoPkg.scripts['docs:update-ship-handoff'] === 'node scripts/update-ship-handoff.mjs' &&
  shipHandoffUpdate.includes("git(['rev-parse', opts.ref])") &&
  shipHandoffUpdate.includes('preflightDetailLines') &&
  shipHandoffUpdate.includes('--preflight-head') &&
  shipHandoffUpdate.includes('--superseded-preflight-success') &&
  shipHandoffUpdate.includes('check-release-distribution-env.mjs') &&
  shipHandoffUpdate.includes('node --test test/unit/ecosystem-consumers.test.js') &&
  shipHandoffUpdate.includes('direct-consumer default-pinning') &&
  shipHandoffUpdate.includes('versioned source markers') &&
  shipHandoffUpdate.includes('release:check-distribution-env') &&
  shipHandoffUpdate.includes('parseReleaseBlockers') &&
  shipHandoffUpdate.includes('--blocker-log') &&
  shipHandoffIssue120Log.includes('Release distribution preflight failed:') &&
  shipHandoffIssue120Log.includes('UMBREL_STORE_TOKEN must be a GitHub token without whitespace or control characters') &&
  shipHandoffIssue120Log.includes('UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug') &&
  shipHandoffIssue120Log.includes('STARTOS_REGISTRY_URL must be a public https URL') &&
  !shipHandoffIssue120Log.includes('-----BEGIN') &&
  !shipHandoffIssue120Log.includes('ghp_')
if (missingShipHandoffTerms.length === 0 && shipHandoffUpdaterOk) {
  pass('current ship handoff is generated from git metadata, release defaults, architecture graph, and issue #120 blocker inputs')
} else {
  fail(`current ship handoff drifted from release state: missing ${missingShipHandoffTerms.map(term => JSON.stringify(term)).join(', ') || 'none'}; updater ok ${shipHandoffUpdaterOk}`)
}

if (
  /^manifestVersion:\s*1\.1\s*$/m.test(umbrelManifest) &&
  /^id:\s*blindspark\s*$/m.test(umbrelManifest) &&
  new RegExp(`^version:\\s*"${escapeRegExp(expectedVersion)}"\\s*$`, 'm').test(umbrelManifest) &&
  /^gallery:\s*\[\]\s*$/m.test(umbrelManifest) &&
  /^releaseNotes:\s*""\s*$/m.test(umbrelManifest) &&
  !/^icon:/m.test(umbrelManifest) &&
  umbrelAppValidateWorkflow.includes('Official first submissions keep gallery empty') &&
  umbrelAppValidateWorkflow.includes('submission must be a getumbrel/umbrel-apps pull request URL or the PENDING placeholder') &&
  umbrelAppValidateWorkflow.includes('releaseNotes must stay empty while submission is PENDING for a first official submission') &&
  umbrelAppValidateWorkflow.includes("if data['gallery'] and len(data['gallery']) < 3:") &&
  umbrelAppValidateWorkflow.includes('node scripts/check-umbrel-gallery.mjs') &&
  umbrelAppValidateWorkflow.includes('Verify gallery image names and dimensions when listed') &&
  !umbrelAppValidateWorkflow.includes("not isinstance(data['gallery'], list) or len(data['gallery']) < 3") &&
  fs.existsSync(path.join(hiverelayRoot, 'umbrel-app', 'data', '.gitkeep')) &&
  monorepoPkg.scripts &&
  monorepoPkg.scripts['umbrel:check-gallery'] === 'node scripts/check-umbrel-gallery.mjs' &&
  monorepoPkg.scripts['umbrel:export-official'] === 'node scripts/export-official-umbrel-app.mjs' &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'check-umbrel-gallery.mjs')) &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'export-official-umbrel-app.mjs')) &&
  officialUmbrelGalleryCheck.includes('umbrel-app.yml gallery is empty for the first official submission') &&
  officialUmbrelGalleryCheck.includes('gallery image name must be a numbered PNG/JPEG filename') &&
  officialUmbrelGalleryCheck.includes('Gallery image listed but missing') &&
  officialUmbrelGalleryCheck.includes('MAX_GALLERY_IMAGE_BYTES') &&
  officialUmbrelGalleryCheck.includes('validateGalleryDir') &&
  officialUmbrelGalleryCheck.includes('gallery directory must not be a symlink') &&
  officialUmbrelGalleryCheck.includes('gallery image must stay inside gallery directory') &&
  officialUmbrelGalleryCheck.includes('stat.isSymbolicLink()') &&
  officialUmbrelGalleryCheck.includes('gallery image must be a regular file') &&
  officialUmbrelGalleryCheck.includes('gallery image must be 1440x900 px') &&
  officialUmbrelGalleryCheck.includes('function jpegSize') &&
  officialUmbrelGalleryCheckTest.includes('allows the empty first-submission gallery') &&
  officialUmbrelGalleryCheckTest.includes('validates populated 1440x900 image lists') &&
  officialUmbrelGalleryCheckTest.includes('rejects symlinked listed images before read') &&
  officialUmbrelGalleryCheckTest.includes('rejects symlinked gallery directories before read') &&
  officialUmbrelGalleryCheckTest.includes('rejects oversized listed images before read') &&
  officialUmbrelGalleryCheckTest.includes('rejects path-like gallery names') &&
  officialUmbrelGalleryCheckTest.includes('rejects wrong dimensions') &&
  officialUmbrelExport.includes('assertSafeTargetRoot') &&
  officialUmbrelExport.includes('assertSafeTargetPaths') &&
  officialUmbrelExport.includes('symlinked official Umbrel path') &&
  officialUmbrelExport.includes('no existing parent directory was found') &&
  officialUmbrelExportTest.includes('rejects symlinked expected files') &&
  officialUmbrelExportTest.includes('rejects symlinked missing target parents')
) {
  pass('Umbrel official package manifest, validator, and exporter are first-submission ready apart from the real PR URL')
} else {
  fail('Umbrel official package manifest/validator/exporter is not aligned with first-submission rules')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['umbrel:write-runtime-review'] === 'node scripts/write-umbrel-runtime-review-evidence.mjs' &&
  monorepoPkg.scripts['umbrel:verify-runtime-review'] === 'node scripts/verify-umbrel-runtime-review-evidence.mjs' &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'write-umbrel-runtime-review-evidence.mjs')) &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'verify-umbrel-runtime-review-evidence.mjs')) &&
  umbrelRuntimeReviewEvidence.includes('umbrel-runtime-review') &&
  umbrelRuntimeReviewEvidence.includes('installedThroughUmbrel') &&
  umbrelRuntimeReviewEvidence.includes('dashboardProxyLoads') &&
  umbrelRuntimeReviewEvidence.includes('liveFeedInBandAuth') &&
  umbrelRuntimeReviewEvidence.includes('noWebSocketUrlTokens') &&
  umbrelRuntimeReviewEvidence.includes('wizardCompletes') &&
  umbrelRuntimeReviewEvidence.includes('setupActionLockObserved') &&
  umbrelRuntimeReviewEvidence.includes('addWalletPersists') &&
  umbrelRuntimeReviewEvidence.includes('walletBusyStateObserved') &&
  umbrelRuntimeReviewEvidence.includes('managementActionsPersist') &&
  umbrelRuntimeReviewEvidence.includes('serviceActionStateObserved') &&
  umbrelRuntimeReviewEvidence.includes('serviceRestartPendingObserved') &&
  umbrelRuntimeReviewEvidence.includes('aiModelAddStateObserved') &&
  umbrelRuntimeReviewEvidence.includes('reviewModeDefault') &&
  umbrelRuntimeReviewEvidence.includes('dataWritableUid999') &&
  umbrelRuntimeReviewEvidence.includes('reinstallPreservesPublicKey') &&
  umbrelRuntimeReviewEvidence.includes('publicKeySha256') &&
  umbrelRuntimeReviewEvidence.includes('publicKeyBeforeSha256') &&
  umbrelRuntimeReviewEvidence.includes('publicKeyAfterSha256') &&
  umbrelRuntimeReviewEvidence.includes('relay public key hash after reinstall') &&
  umbrelRuntimeReviewEvidence.includes('officialUmbrelPr:') &&
  umbrelRuntimeReviewEvidence.includes('requirePattern(\'official Umbrel PR URL\', body.officialUmbrelPr?.url') &&
  umbrelRuntimeReviewEvidence.includes("requireOnlyKeys('Umbrel runtime review officialUmbrelPr', body.officialUmbrelPr") &&
  umbrelRuntimeReviewEvidence.includes('Umbrel runtime review evidence generatedAt') &&
  umbrelRuntimeReviewEvidence.includes('assertRuntimeReviewEvidenceSchema') &&
  umbrelRuntimeReviewEvidence.includes("requireOnlyKeys('Umbrel runtime review evidence'") &&
  umbrelRuntimeReviewEvidence.includes('has unsupported fields') &&
  umbrelRuntimeReviewEvidence.includes('ISO_TIMESTAMP_PATTERN') &&
  umbrelRuntimeReviewEvidence.includes('LOCAL_ADDRESS_PATTERN') &&
  umbrelRuntimeReviewEvidence.includes('function isPublicHostname') &&
  umbrelRuntimeReviewEvidence.includes("'.example.com'") &&
  umbrelRuntimeReviewEvidence.includes('APP_SEED') &&
  umbrelRuntimeReviewEvidence.includes('must not include local hostnames or LAN addresses') &&
  umbrelRuntimeReviewEvidenceVerify.includes('umbrel-runtime-review') &&
  umbrelRuntimeReviewEvidenceVerify.includes('verifyIdentityHashes') &&
  umbrelRuntimeReviewEvidenceVerify.includes('publicKeyAfterSha256') &&
  umbrelRuntimeReviewEvidenceVerify.includes('verifyChecks') &&
  umbrelRuntimeReviewEvidenceVerify.includes('setupActionLockObserved') &&
  umbrelRuntimeReviewEvidenceVerify.includes('walletBusyStateObserved') &&
  umbrelRuntimeReviewEvidenceVerify.includes('serviceActionStateObserved') &&
  umbrelRuntimeReviewEvidenceVerify.includes('serviceRestartPendingObserved') &&
  umbrelRuntimeReviewEvidenceVerify.includes('aiModelAddStateObserved') &&
  umbrelRuntimeReviewEvidenceVerify.includes('Duplicate Umbrel runtime check') &&
  umbrelRuntimeReviewEvidenceVerify.includes('assertNoRawIdentityFields') &&
  umbrelRuntimeReviewEvidenceVerify.includes('assertRuntimeReviewSchema') &&
  umbrelRuntimeReviewEvidenceVerify.includes('function requireOnlyKeys') &&
  umbrelRuntimeReviewEvidenceVerify.includes('has unsupported fields') &&
  umbrelRuntimeReviewEvidenceVerify.includes('must not expose raw public key fields') &&
  umbrelRuntimeReviewEvidenceVerify.includes('OFFICIAL_UMBREL_PR_URL_PATTERN') &&
  umbrelRuntimeReviewEvidenceVerify.includes('requirePattern(\'official Umbrel PR URL\', body.officialUmbrelPr?.url') &&
  umbrelRuntimeReviewEvidenceVerify.includes("requireOnlyKeys('officialUmbrelPr', body.officialUmbrelPr") &&
  umbrelRuntimeReviewEvidenceVerify.includes('MAX_EVIDENCE_JSON_BYTES') &&
  umbrelRuntimeReviewEvidenceVerify.includes('MAX_GENERATED_AT_FUTURE_SKEW_MS') &&
  umbrelRuntimeReviewEvidenceVerify.includes('generatedAt must not be in the future') &&
  umbrelRuntimeReviewEvidenceVerify.includes('file must not be a symlink') &&
  umbrelRuntimeReviewEvidenceVerify.includes('file must be a regular file') &&
  umbrelRuntimeReviewEvidenceVerify.includes('function isPublicHostname') &&
  umbrelRuntimeReviewEvidenceVerify.includes("'.example.com'") &&
  umbrelRuntimeReviewEvidenceTest.includes('records public-safe manual checks') &&
  umbrelRuntimeReviewEvidenceTest.includes('keeps a closed public schema') &&
  umbrelRuntimeReviewEvidenceTest.includes('Umbrel runtime review evidence generatedAt is an ISO timestamp') &&
  umbrelRuntimeReviewEvidenceTest.includes('rejects missing manual checks') &&
  umbrelRuntimeReviewEvidenceTest.includes('setupActionLockObserved') &&
  umbrelRuntimeReviewEvidenceTest.includes('rejects reinstall public-key drift') &&
  umbrelRuntimeReviewEvidenceTest.includes('rejects local details and secrets') &&
  umbrelRuntimeReviewEvidenceTest.includes('rejects placeholder and credentialed public URLs') &&
  umbrelRuntimeReviewEvidenceTest.includes('requires upstream PR binding') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('accepts writer-produced evidence') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects missing, duplicate, and failed checks') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('walletBusyStateObserved') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects release and PR drift') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects future evidence timestamps') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects reinstall public-key hash drift') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects local details, secrets, and raw public-key fields') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects placeholder and credentialed public URLs') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects unsupported schema fields') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('rejects unsafe evidence files before parsing') &&
  umbrelRuntimeReviewEvidenceVerifyTest.includes('requires upstream PR binding') &&
  umbrelSubmissionChecklist.includes('umbrel-runtime-review-evidence.json') &&
  umbrelSubmissionChecklist.includes('umbrel:verify-runtime-review') &&
  umbrelSubmissionChecklist.includes('setupActionLockObserved') &&
  umbrelSubmissionChecklist.includes('walletBusyStateObserved') &&
  umbrelSubmissionChecklist.includes('serviceActionStateObserved') &&
  umbrelSubmissionChecklist.includes('serviceRestartPendingObserved') &&
  umbrelSubmissionChecklist.includes('aiModelAddStateObserved') &&
  releaseAutomationDocs.includes('umbrel-runtime-review-evidence.json') &&
  releaseAutomationDocs.includes('must be bound') &&
  releaseAutomationDocs.includes('setupActionLockObserved') &&
  releaseAutomationDocs.includes('walletBusyStateObserved') &&
  releaseAutomationDocs.includes('serviceActionStateObserved') &&
  releaseAutomationDocs.includes('serviceRestartPendingObserved') &&
  releaseAutomationDocs.includes('aiModelAddStateObserved') &&
  releaseHandoffEvidenceVerify.includes('requirePattern(\'Umbrel runtime review PR URL\', body.officialUmbrelPr?.url') &&
  releaseHandoffEvidenceVerify.includes("requireOnlyKeys('Umbrel runtime review officialUmbrelPr', body.officialUmbrelPr") &&
  releaseHandoffEvidenceVerifyTest.includes('requires Umbrel runtime review upstream PR binding')
) {
  pass('Umbrel real-device runtime review has public-safe writer and verifier coverage for the manual store checklist')
} else {
  fail('Umbrel real-device runtime review evidence writer/verifier is missing or not documented')
}

if (umbrelManifest.includes('https://github.com/getumbrel/umbrel-apps/pull/PENDING')) {
  warn('Umbrel official package still needs its real getumbrel/umbrel-apps PR URL in submission:')
}

if (
  prepareRelease.includes('pull/PENDING') &&
  prepareRelease.includes('workspace Umbrel releaseNotes left empty while official submission URL is pending') &&
  prepareRelease.includes('replaceYamlScalarOrBlock') &&
  prepareRelease.includes('yamlValueRegex') &&
  prepareRelease.includes('assertPublicReleaseNotes') &&
  prepareRelease.includes('FORBIDDEN_PUBLIC_RELEASE_NOTES_PATTERNS') &&
  prepareReleaseTest.includes('rejects secret-looking release notes before metadata sync') &&
  prepareReleaseTest.includes('rejects unsafe release-note control characters before metadata sync')
) {
  pass('release prep preserves empty official Umbrel first-submission release notes and rejects unsafe public release-note text')
} else {
  fail('release prep can overwrite/fail on official Umbrel first-submission releaseNotes or publish unsafe release-note text')
}

const umbrelAppDataDirExpression = '$' + '{APP_DATA_DIR}'
const umbrelAppSeedExpression = '$' + '{APP_SEED}'
if (
  new RegExp(`image:\\s*ghcr\\.io/bigdestiny2/p2p-hiverelay:${escapeRegExp(expectedVersion)}@sha256:[a-f0-9]{64}`).test(umbrelCompose) &&
  umbrelCompose.includes('APP_HOST: blindspark_web_1') &&
  umbrelCompose.includes('APP_PORT: 9100') &&
  umbrelCompose.includes(umbrelAppDataDirExpression + '/data:/data') &&
  umbrelCompose.includes('HIVERELAY_UI_EXPOSE_TOKEN: "true"') &&
  umbrelCompose.includes('HIVERELAY_ACCEPT_MODE: review') &&
  umbrelCompose.includes('HIVERELAY_MAX_STORAGE: 10GB') &&
  umbrelCompose.includes('APP_SEED: ' + umbrelAppSeedExpression) &&
  cliIndex.includes('HIVERELAY_ACCEPT_MODE') &&
  cliIndex.includes('cliOverrides.acceptMode = mode') &&
  cliIndex.includes('HIVERELAY_STORAGE') &&
  cliIndex.includes('else if (process.env.HIVERELAY_STORAGE) cliOverrides.storage = process.env.HIVERELAY_STORAGE') &&
  cliIndex.includes('HIVERELAY_MAX_STORAGE') &&
  cliIndex.includes("parseBytesOrExit(process.env.HIVERELAY_MAX_STORAGE, 'HIVERELAY_MAX_STORAGE')") &&
  cliIndex.includes('!hasPersistedConfig()') &&
  cliIndex.includes('function hasPersistedConfig') &&
  cliIndex.includes('Invalid $' + '{label}: expected a positive size') &&
  configLoaderTest.includes('cli start rejects invalid HIVERELAY_MAX_STORAGE before boot') &&
  configLoaderTest.includes('cli start uses HIVERELAY_MAX_STORAGE only before saved operator config exists') &&
  configLoaderTest.includes('cli start uses HIVERELAY_STORAGE when --storage is absent') &&
  configLoaderTest.includes('cli start --storage overrides HIVERELAY_STORAGE') &&
  configLoaderTest.includes('Max Store:  50.0 GB') &&
  umbrelReadme.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  umbrelReadme.includes('saved operator config') &&
  umbrelSubmissionChecklist.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  umbrelSubmissionChecklist.includes('Saved operator config wins') &&
  releaseAutomationDocs.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  releaseAutomationDocs.includes('first-boot home-server') &&
  auditDoc.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  auditDoc.includes('first-boot-only Umbrel storage-cap behavior') &&
  !/^\s+ports:\s*$/m.test(umbrelCompose) &&
  !/^\s+privileged:\s*true\s*$/m.test(umbrelCompose) &&
  !/^\s+network_mode:\s*host\s*$/m.test(umbrelCompose) &&
  !umbrelCompose.includes('/var/run/docker.sock')
) {
  pass('Umbrel official package compose uses app_proxy, digest-pinned image, persisted data, review-mode default, and no broad host access')
} else {
  fail('Umbrel official package compose is missing app_proxy/digest/persistence/review-mode safeguards')
}

if (
  /^concurrency:\n\s+group:\s+release-surfaces\n\s+cancel-in-progress:\s+false/m.test(releaseWorkflow)
) {
  pass('release workflow serializes release-surface runs')
} else {
  fail('release workflow is missing the release-surfaces concurrency guard')
}

if (
  releaseWorkflow.includes('RELEASE_EVENT_NAME: $' + '{{ github.event_name }}') &&
  releaseWorkflow.includes('RELEASE_TAG_NAME: $' + '{{ github.event.release.tag_name }}') &&
  releaseWorkflow.includes('RELEASE_IS_PRERELEASE: $' + '{{ github.event.release.prerelease }}') &&
  releaseWorkflow.includes('PUSH_REF_NAME: $' + '{{ github.ref_name }}') &&
  releaseWorkflow.includes('DISPATCH_VERSION: $' + '{{ inputs.version }}') &&
  releaseWorkflow.includes('DISPATCH_CHANNEL: $' + '{{ inputs.channel }}') &&
  releaseWorkflow.includes('if [ "$RELEASE_EVENT_NAME" = "release" ]; then') &&
  releaseWorkflow.includes('version="$RELEASE_TAG_NAME"') &&
  releaseWorkflow.includes('release_prerelease="$RELEASE_IS_PRERELEASE"') &&
  releaseWorkflow.includes('elif [ "$RELEASE_EVENT_NAME" = "push" ]; then') &&
  releaseWorkflow.includes('version="$PUSH_REF_NAME"') &&
  releaseWorkflow.includes('version="$DISPATCH_VERSION"') &&
  releaseWorkflow.includes('requested_channel="$DISPATCH_CHANNEL"') &&
  !releaseWorkflow.includes('version="$' + '{{ github.event.release.tag_name }}"') &&
  !releaseWorkflow.includes('version="$' + '{{ github.ref_name }}"') &&
  !releaseWorkflow.includes('version="$' + '{{ inputs.version }}"') &&
  !releaseWorkflow.includes('requested_channel="$' + '{{ inputs.channel }}"') &&
  !releaseWorkflow.includes('[ "$' + '{{ github.event_name }}" = "release" ]')
) {
  pass('release workflow treats raw release, tag-push, and dispatch inputs as environment data before shell validation')
} else {
  fail('release workflow interpolates raw release, tag-push, or dispatch inputs directly into shell before validation')
}

if (
  releaseWorkflow.includes("on:\n  push:\n    branches:\n      - ship/core3-release-readiness-2026-06-24\n    tags:\n      - 'v*'\n  release:") &&
  releasePreflightWorkflow.includes('on:\n  push:\n    branches:\n      - ship/core3-release-readiness-2026-06-24\n  workflow_dispatch:') &&
  releaseWorkflow.includes('Ensure GitHub Release exists') &&
  releaseWorkflow.includes('if: $' + '{{ github.event_name != \'release\' && steps.rel.outputs.is_branch_candidate != \'true\' }}') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_CANDIDATE=') &&
  releaseWorkflow.includes('Stamp branch candidate package version') &&
  releaseWorkflow.includes('gh release view "$version"') &&
  releaseWorkflow.includes('args=(release create "$version" --verify-tag --title "$version" --notes "$notes")') &&
  releaseWorkflow.includes('args+=(--prerelease)') &&
  releaseWorkflow.includes('gh "$' + '{args[@]}"') &&
  releaseWorkflow.indexOf('Ensure GitHub Release exists') > releaseWorkflow.indexOf('Verify release ref') &&
  releaseWorkflow.indexOf('Ensure GitHub Release exists') > releaseWorkflow.indexOf('Verify stable release distribution credentials') &&
  releaseAutomationDocs.includes('Published releases, pushed') &&
  releaseAutomationDocs.includes('`v*` tags, and manual promotions') &&
  releaseAutomationDocs.includes('Creates or reuses the public GitHub Release object only after the') &&
  releaseAutomationDocs.includes('distribution preflight passes')
) {
  pass('release workflow runs the full release-surface path for pushed v* tags, while branch candidates produce artifact evidence without release publication')
} else {
  fail('release workflow is missing pushed v* tag/candidate release-surface triggering or preflight-gated GitHub Release asset-target creation')
}

if (
  releaseWorkflow.includes('is_prerelease=true') &&
  releaseWorkflow.includes('channel=both') &&
  /^ {6}channel:\n(?: {8}.+\n)* {8}default: both$/m.test(releaseWorkflow) &&
  !/^ {8}default: canary$/m.test(releaseWorkflow) &&
  prepareRelease.includes('default: both; prereleases: none') &&
  prepareRelease.includes('defaultChannelForVersion(version)') &&
  releaseDistributionEnvCheck.includes("prerelease ? 'none' : 'both'") &&
  releaseDistributionEnvCheck.includes('--channel defaults to both for full releases and none for prereleases') &&
  releaseDistributionEnvCheck.includes('pre-release channel must be none') &&
  fleetRolloutCheck.includes('Relay channel to check (default: both)') &&
  fleetRolloutCheck.includes("process.env.HIVERELAY_FLEET_CHANNEL || 'both'") &&
  fleetRolloutCheckTest.includes('defaults to both fleet channels') &&
  readme.includes('npm run fleet:check-rollout -- --target v<version> --channel both') &&
  prepareRelease.includes('!args.noUmbrelStore && !isPrerelease') &&
  prepareRelease.includes('!args.noEcosystemConsumers && !isPrerelease') &&
  prepareRelease.includes('syncEcosystemConsumerDefaults()') &&
  prepareRelease.includes('syncEcosystemConsumers({') &&
  prepareRelease.includes('snapshotChecks: false') &&
  prepareRelease.includes('ecosystem consumer defaults skipped for pre-release') &&
  prepareReleaseTest.includes('prepare-release syncs sibling ecosystem consumer defaults') &&
  prepareRelease.includes("semver.includes('-') ? 'none' : 'both'") &&
  prepareReleaseTest.includes('defaults full release channel to both') &&
  prepareRelease.includes('cannot promote fleet/app-store channel') &&
  prepareRelease.includes('cannot sync the community Umbrel store') &&
  releaseEvidence.includes('successful prerelease channel') &&
  releaseWorkflow.includes('echo "is_prerelease=$is_prerelease" >> "$GITHUB_OUTPUT"') &&
  releaseWorkflow.includes('Pre-release $version cannot promote fleet/app-store channel') &&
  releaseWorkflow.includes('if [ "$' + '{{ steps.rel.outputs.is_prerelease }}" != "true" ]; then') &&
  releaseWorkflow.includes('tags+=(--tag "$IMAGE_NAME:latest")') &&
  releaseWorkflow.includes("steps.rel.outputs.is_prerelease != 'true'") &&
  releaseWorkflow.includes('args+=(--no-umbrel-store)')
) {
  pass('release workflow, release prep, and distribution preflight isolate pre-releases and default full releases to whole-fleet promotion')
} else {
  fail('release workflow, release prep, or distribution preflight is missing pre-release guardrails or the full-release whole-fleet default')
}

const releaseEcosystemGateCommand = 'node --test test/unit/ecosystem-consumers.test.js'
const publicArtifactAuditCommand = 'npm run audit:public-artifacts'
if (
  releaseWorkflow.includes('npm run audit:workspace') &&
  releaseWorkflow.includes(publicArtifactAuditCommand) &&
  releaseWorkflow.includes(releaseEcosystemGateCommand) &&
  releaseWorkflow.includes('npm run test:unit') &&
  releaseWorkflow.indexOf(publicArtifactAuditCommand) > releaseWorkflow.indexOf('npm run audit:workspace') &&
  releaseWorkflow.indexOf(publicArtifactAuditCommand) < releaseWorkflow.indexOf(releaseEcosystemGateCommand) &&
  releaseWorkflow.indexOf(releaseEcosystemGateCommand) > releaseWorkflow.indexOf('npm run audit:workspace') &&
  releaseWorkflow.indexOf(releaseEcosystemGateCommand) < releaseWorkflow.indexOf('Build and push multi-arch image') &&
  releaseAutomationDocs.includes(publicArtifactAuditCommand) &&
  releaseAutomationDocs.includes('scanner-sensitive secret examples') &&
  releaseAutomationDocs.includes(releaseEcosystemGateCommand) &&
  releaseAutomationDocs.includes('ecosystem inventory guard') &&
  releaseAutomationDocs.includes('consumer default-pinning contract')
) {
  pass('release workflow explicitly gates release images on public-artifact and ecosystem consumer inventory coverage')
} else {
  fail('release workflow is missing the explicit public-artifact or ecosystem consumer inventory gate before image publish')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['release:check-distribution-env'] === 'node scripts/check-release-distribution-env.mjs' &&
  releaseWorkflow.includes('Verify stable release distribution credentials') &&
  releaseWorkflow.includes('npm run release:check-distribution-env --') &&
  releaseWorkflow.includes('--github-env "$GITHUB_ENV"') &&
  releaseWorkflow.indexOf('Verify stable release distribution credentials') > releaseWorkflow.indexOf('Verify release ref') &&
  releaseWorkflow.indexOf('Verify stable release distribution credentials') < releaseWorkflow.indexOf('Ensure GitHub Release exists') &&
  releaseWorkflow.indexOf('Verify stable release distribution credentials') < releaseWorkflow.indexOf('Checkout Umbrel community store') &&
  releaseWorkflow.includes('Keep this before any public GitHub Release lookup/create or asset upload') &&
  releaseDistributionEnvCheck.includes("HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS: 'failed'") &&
  releaseDistributionEnvCheck.includes("HIVERELAY_RELEASE_SURFACES_STATUS: 'blocked'") &&
  releaseDistributionEnvCheck.includes("requirePrivateKey('FLEET_SSH_PRIVATE_KEY'") &&
  releaseDistributionEnvCheck.includes('FLEET_ROLLOUT_TIMEOUT_MIN_MS') &&
  releaseDistributionEnvCheck.includes('FLEET_ROLLOUT_TIMEOUT_MAX_MS') &&
  releaseDistributionEnvCheck.includes('requireOptionalFleetTimeout') &&
  releaseDistributionEnvCheck.includes("HIVERELAY_FLEET_ROLLOUT_STATUS = 'invalid-timeout'") &&
  releaseDistributionEnvCheck.includes("requireGitHubToken('UMBREL_STORE_TOKEN'") &&
  releaseDistributionEnvCheck.includes("requireGitHubToken('UMBREL_OFFICIAL_PR_TOKEN'") &&
  releaseDistributionEnvCheck.includes("requireSecret('UMBREL_OFFICIAL_FORK'") &&
  releaseDistributionEnvCheck.includes("requireSecret('NPM_TOKEN'") &&
  releaseDistributionEnvCheck.includes("requirePrivateKey('STARTOS_DEVELOPER_KEY_PEM'") &&
  releaseDistributionEnvCheck.includes("requireSecret('STARTOS_REGISTRY_URL'") &&
  releaseDistributionEnvCheck.includes("const value = String(env[name] || '')") &&
  releaseDistributionEnvCheck.includes('if (!value.trim())') &&
  releaseDistributionEnvCheck.includes('function isGitHubToken') &&
  releaseDistributionEnvCheck.includes('function isNpmToken') &&
  releaseDistributionEnvCheck.includes('function isPrivateKeyBlock') &&
  releaseDistributionEnvCheck.includes('--env-file') &&
  releaseDistributionEnvCheck.includes('const sourceEnv = args.envFile ? safeReadEnvFile(args.envFile) : process.env') &&
  releaseDistributionEnvCheck.includes('does not fall back to ambient shell secrets') &&
  releaseDistributionEnvCheck.includes("import { readEnvFile } from './lib/release-env-file.mjs'") &&
  releaseEnvFileLib.includes('export function readEnvFile') &&
  releaseEnvFileLib.includes('export function parseEnvFile') &&
  releaseEnvFileLib.includes('Refusing to read symlinked env file') &&
  releaseDistributionEnvCheck.includes('must be a GitHub token without whitespace or control characters') &&
  releaseDistributionEnvCheck.includes('must be an npm automation token without whitespace or control characters') &&
  releaseDistributionEnvCheck.includes('must be a private key block') &&
  releaseDistributionEnvCheck.includes('without whitespace or control characters') &&
  releaseDistributionEnvCheck.includes('function formatRepairPath') &&
  releaseDistributionEnvCheck.includes('Repair path:') &&
  releaseDistributionEnvCheck.includes('release:apply-github-secrets') &&
  releaseDistributionEnvCheck.includes('release-distribution-preflight.yml') &&
  releaseDistributionEnvCheckTest.includes('validates local candidate env files before setting GitHub secrets') &&
  releaseDistributionEnvCheckTest.includes('does not satisfy env-file candidates from ambient secrets') &&
  releaseDistributionEnvCheckTest.includes('rejects malformed local candidate env files without echoing values') &&
  releaseAutomationDocs.includes('--env-file /private/tmp/hiverelay-release-secrets.env') &&
  releaseAutomationDocs.includes('ambient shell') &&
  releaseAutomationDocs.includes('secrets do not satisfy missing file entries') &&
  releaseAutomationDocs.includes('prints a safe repair path') &&
  releaseAutomationDocs.includes('The repair block never includes') &&
  releaseAutomationDocs.includes('NAME<<DELIM') &&
  releaseAutomationDocs.includes('public docs stay friendly to secret') &&
  !releaseAutomationDocs.includes('ghp_') &&
  !releaseAutomationDocs.includes('github_pat_') &&
  !releaseAutomationDocs.includes('-----BEGIN OPENSSH PRIVATE KEY-----') &&
  !releaseAutomationDocs.includes('-----BEGIN PRIVATE KEY-----') &&
  monorepoPkg.scripts['audit:public-artifacts'] === 'node scripts/check-public-artifact-secrets.mjs' &&
  publicArtifactSecretsAudit.includes('export function scanPublicArtifacts') &&
  publicArtifactSecretsAudit.includes("'README.md'") &&
  publicArtifactSecretsAudit.includes("'docs'") &&
  publicArtifactSecretsAudit.includes("'.github'") &&
  publicArtifactSecretsAudit.includes('GitHub token prefix example') &&
  publicArtifactSecretsAudit.includes('private key delimiter example') &&
  publicArtifactSecretsAudit.includes('Bearer authorization example') &&
  publicArtifactSecretsAudit.includes("'.svg'") &&
  publicArtifactSecretsAuditTest.includes('public artifact secret scan passes scanner-safe docs and workflows') &&
  publicArtifactSecretsAuditTest.includes('public artifact secret scan reports token, bearer, and key examples') &&
  releaseDistributionEnvCheckTest.includes('accepts sane explicit fleet rollout timeout') &&
  releaseDistributionEnvCheckTest.includes('rejects unsafe fleet rollout timeout before SSH') &&
  releaseDistributionEnvCheckTest.includes('rejects placeholder GitHub tokens before checkout or gh calls') &&
  releaseDistributionEnvCheckTest.includes('rejects malformed npm tokens before package publish') &&
  releaseDistributionEnvCheckTest.includes('rejects whitespace-padded GitHub tokens before checkout or gh calls') &&
  releaseDistributionEnvCheckTest.includes('Repair path:') &&
  releaseDistributionEnvCheckTest.includes('release:apply-github-secrets') &&
  releaseDistributionEnvCheckTest.includes('rejects placeholder private-key secrets before SSH or StartOS publish') &&
  releaseDistributionEnvCheckTest.includes('rejects whitespace-padded private-key secrets before SSH or StartOS publish') &&
  releaseDistributionEnvCheck.includes('UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug with a normal owner name and must not be getumbrel/umbrel-apps') &&
  releaseDistributionEnvCheck.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS = \'invalid-fork\'') &&
  releaseDistributionEnvCheck.includes('function isOfficialUmbrelForkSlug') &&
  releaseDistributionEnvCheck.includes('function isGitHubOwnerName') &&
  releaseDistributionEnvCheck.includes("owner.toLowerCase() !== 'getumbrel'") &&
  releaseDistributionEnvCheck.includes("repo === 'umbrel-apps'") &&
  releaseDistributionEnvCheckTest.includes('rejects renamed or option-like official Umbrel forks before checkout') &&
  releaseDistributionEnvCheckTest.includes('getumbrel/umbrel-apps') &&
  releaseAutomationDocs.includes('not the upstream') &&
  releaseDistributionEnvCheck.includes('STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames') &&
  releaseDistributionEnvCheck.includes('HIVERELAY_STARTOS_REGISTRY_STATUS = \'invalid-registry-url\'') &&
  releaseDistributionEnvCheck.includes('function isPublicHttpsUrl') &&
  releaseDistributionEnvCheck.includes('function isPublicHostname') &&
  releaseDistributionEnvCheck.includes('function hasControlChars') &&
  releaseDistributionEnvCheck.includes('formatGithubEnvLine') &&
  releaseDistributionEnvCheck.includes('Refusing to write multi-line or control-character value') &&
  releaseDistributionEnvCheck.includes('!url.username') &&
  releaseDistributionEnvCheck.includes('!url.password') &&
  releaseDistributionEnvCheck.includes('!url.search') &&
  releaseDistributionEnvCheck.includes('!url.hash') &&
  releaseDistributionEnvCheck.includes("'.example.com'") &&
  releaseDistributionEnvCheckTest.includes('rejects placeholder StartOS registry hosts before publish')
) {
  pass('release workflow blocks stable releases before silently skipping npm, fleet, Umbrel, or StartOS distribution credentials')
} else {
  fail('release workflow can still silently skip required stable-release distribution credentials')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['release:check-github-setup'] === 'node scripts/check-github-release-setup.mjs' &&
  monorepoPkg.scripts['release:write-secret-template'] === 'node scripts/write-release-secrets-template.mjs' &&
  monorepoPkg.scripts['release:apply-github-secrets'] === 'node scripts/apply-github-release-secrets.mjs' &&
  githubReleaseSetupCheck.includes('REQUIRED_SECRETS') &&
  githubReleaseSetupCheck.includes("'FLEET_SSH_PRIVATE_KEY'") &&
  githubReleaseSetupCheck.includes("'UMBREL_STORE_TOKEN'") &&
  githubReleaseSetupCheck.includes("'UMBREL_OFFICIAL_PR_TOKEN'") &&
  githubReleaseSetupCheck.includes("'UMBREL_OFFICIAL_FORK'") &&
  githubReleaseSetupCheck.includes("'NPM_TOKEN'") &&
  githubReleaseSetupCheck.includes("'STARTOS_DEVELOPER_KEY_PEM'") &&
  githubReleaseSetupCheck.includes("'STARTOS_REGISTRY_URL'") &&
  githubReleaseSetupCheck.includes("['secret', 'list', '--repo', repo, '--json', 'name']") &&
  githubReleaseSetupCheck.includes("['variable', 'list', '--repo', repo, '--json', 'name,value']") &&
  githubReleaseSetupCheck.includes('Secret values are not readable through gh') &&
  githubReleaseSetupCheck.includes('Release distribution preflight') &&
  githubReleaseSetupCheck.includes('is configured as a repository variable; move it to GitHub Secrets') &&
  githubReleaseSetupCheck.includes('Repository variable FLEET_ROLLOUT_TIMEOUT_MS must be an integer') &&
  githubReleaseSetupCheck.includes('sanitizeGhError') &&
  githubReleaseSetupCheck.includes('isRepoFullName') &&
  releasePreflightWorkflow.includes('name: Release distribution preflight') &&
  releasePreflightWorkflow.includes('workflow_dispatch') &&
  releasePreflightWorkflow.includes('node scripts/check-release-distribution-env.mjs') &&
  releasePreflightWorkflow.includes('secrets.UMBREL_STORE_TOKEN') &&
  releasePreflightWorkflow.includes('secrets.UMBREL_OFFICIAL_PR_TOKEN') &&
  releasePreflightWorkflow.includes('secrets.NPM_TOKEN') &&
  releasePreflightWorkflow.includes('secrets.STARTOS_REGISTRY_URL') &&
  releasePreflightWorkflow.includes('vars.FLEET_ROLLOUT_TIMEOUT_MS') &&
  releasePreflightWorkflow.includes('#### Repair path') &&
  releasePreflightWorkflow.includes('repair_channel="' + '$' + '{HIVERELAY_RELEASE_EFFECTIVE_CHANNEL:-' + '$' + '{{ steps.rel.outputs.channel }}}"') &&
  releasePreflightWorkflow.includes('*) repair_channel=both ;;') &&
  releasePreflightWorkflow.includes('release:write-secret-template') &&
  releasePreflightWorkflow.includes('--env-file /private/tmp/hiverelay-release-secrets.env --channel ' + '$' + '{repair_channel} --prerelease false') &&
  releasePreflightWorkflow.includes('release:apply-github-secrets') &&
  releasePreflightWorkflow.includes('docs/RELEASE_AUTOMATION.md#repository-secret-setup') &&
  releaseDistributionEnvCheck.includes("import { readEnvFile } from './lib/release-env-file.mjs'") &&
  releaseEnvFileLib.includes('export function readEnvFile') &&
  releaseEnvFileLib.includes('export function parseEnvFile') &&
  releaseSecretsTemplate.includes('REPLACE_WITH_GITHUB_TOKEN_FOR_COMMUNITY_STORE') &&
  releaseSecretsTemplate.includes('REPLACE_WITH_NPM_AUTOMATION_TOKEN') &&
  releaseSecretsTemplate.includes('REPLACE_WITH_PUBLIC_HTTPS_REGISTRY_URL') &&
  releaseSecretsTemplate.includes('Refusing to write release secret template inside the repository') &&
  releaseSecretsTemplate.includes('mode: 0o600') &&
  releaseSecretsTemplate.includes('Refusing to overwrite symlinked output file') &&
  releaseDistributionEnvCheck.includes('release:write-secret-template') &&
  githubReleaseSecretsApply.includes('validateCandidateFile') &&
  githubReleaseSecretsApply.includes("['secret', 'set', name, '--repo', repo]") &&
  githubReleaseSecretsApply.includes("['variable', 'set', name, '--repo', repo, '--body', values[name]]") &&
  githubReleaseSecretsApply.includes('input') &&
  githubReleaseSecretsApply.includes('--dry-run') &&
  githubReleaseSecretsApply.includes('only validates full-release secret values') &&
  githubReleaseSecretsApply.includes('function printNextSteps') &&
  githubReleaseSecretsApply.includes('npm run release:check-github-setup -- --repo') &&
  githubReleaseSecretsApply.includes('gh workflow run release-distribution-preflight.yml --repo') &&
  githubReleaseSecretsApply.includes('redactSecretLikeValues') &&
  githubReleaseSecretsApply.includes('[redacted-github-token]') &&
  githubReleaseSecretsApply.includes('[redacted-npm-token]') &&
  githubReleaseSecretsApply.includes('PATH: process.env.PATH') &&
  githubReleaseSetupCheckTest.includes('passes with all required secrets') &&
  githubReleaseSetupCheckTest.includes('reports missing release secrets') &&
  githubReleaseSetupCheckTest.includes('rejects required secrets configured as variables') &&
  githubReleaseSetupCheckTest.includes('rejects invalid optional fleet timeout variable') &&
  githubReleaseSetupCheckTest.includes('reports gh JSON failures') &&
  githubReleaseSetupCheckTest.includes('rejects malformed repo names before gh calls') &&
  githubReleaseSecretsApplyTest.includes('sends validated values to gh secret set via stdin') &&
  githubReleaseSecretsApplyTest.includes('gh workflow run release-distribution-preflight.yml --repo bigdestiny2/P2P-Hiverelay -f channel=both -f prerelease=false') &&
  githubReleaseSecretsApplyTest.includes('rejects malformed candidate without calling gh or echoing values') &&
  githubReleaseSecretsApplyTest.includes('rejects prerelease validation mode before gh calls') &&
  githubReleaseSecretsApplyTest.includes('redacts gh failure output before printing') &&
  releaseSecretsTemplateTest.includes('creates private placeholder candidate outside repo') &&
  releaseSecretsTemplateTest.includes('refuses repo output paths') &&
  releaseSecretsTemplateTest.includes('refuses accidental overwrite unless forced') &&
  releaseSecretsTemplateTest.includes('refuses symlink output even with force') &&
  releaseAutomationDocs.includes('npm run release:check-github-setup') &&
  releaseAutomationDocs.includes('npm run release:write-secret-template') &&
  releaseAutomationDocs.includes('owner-only permissions') &&
  releaseAutomationDocs.includes('npm run release:apply-github-secrets') &&
  releaseAutomationDocs.includes('--dry-run') &&
  releaseAutomationDocs.includes('not print secret values') &&
  releaseAutomationDocs.includes('release-distribution-preflight.yml') &&
  releaseAutomationDocs.includes('side-effect-free masked-value') &&
  readme.includes('npm run release:check-github-setup') &&
  readme.includes('npm run release:apply-github-secrets')
) {
  pass('release readiness includes validated GitHub secret setup, apply, and repair-path audits')
} else {
  fail('release readiness can still rely on manual GitHub secret and variable inspection')
}

const releasePackageManifests = [
  'packages/core/package.json',
  'packages/services/package.json',
  'packages/client/package.json',
  'packages/verifier/package.json'
]

if (
  releaseWorkflow.includes('Publish npm packages') &&
  releaseWorkflow.includes('NODE_AUTH_TOKEN: $' + '{{ secrets.NPM_TOKEN }}') &&
  releaseWorkflow.includes('registry-url: https://registry.npmjs.org') &&
  releaseWorkflow.includes('for pkg in packages/core packages/client packages/verifier packages/services') &&
  releaseWorkflow.includes('npm publish "$pkg" --access public --tag latest') &&
  releaseWorkflow.includes('npm dist-tag add "$name@$version" latest') &&
  releaseWorkflow.includes('npm view "$name" dist-tags.latest') &&
  releaseWorkflow.includes('HIVERELAY_NPM_PUBLISH_STATUS=published') &&
  releaseWorkflow.includes('HIVERELAY_NPM_PUBLISH_STATUS=current') &&
  releaseWorkflow.indexOf('Publish npm packages') > releaseWorkflow.indexOf('Sync release metadata') &&
  releaseWorkflow.indexOf('Publish npm packages') > releaseWorkflow.indexOf('Smoke Umbrel package') &&
  releaseWorkflow.indexOf('Publish npm packages') > releaseWorkflow.indexOf('Build and verify StartOS package') &&
  releaseWorkflow.indexOf('Publish npm packages') < releaseWorkflow.indexOf('Upload StartOS package to GitHub Release') &&
  releaseWorkflow.indexOf('Publish npm packages') < releaseWorkflow.indexOf('Commit HiveRelay release surfaces') &&
  releaseAutomationDocs.includes('Publishes `p2p-hiverelay`, `p2p-hiverelay-client`') &&
  releaseAutomationDocs.includes('verifies every `latest`') &&
  releaseAutomationDocs.includes('app consumers safely move from local workspace')
) {
  pass('release workflow publishes npm packages and verifies latest dist-tags before downstream app-store packaging')
} else {
  fail('release workflow is missing npm package publication or latest dist-tag verification before downstream app consumers update')
}

const releaseSurfaceCommitStep = releaseWorkflow.slice(
  releaseWorkflow.indexOf('Commit HiveRelay release surfaces'),
  releaseWorkflow.indexOf('Configure fleet rollout SSH key')
)

if (
  releasePackageManifests.every(file => prepareRelease.includes(`'${file}'`)) &&
  releasePackageManifests.every(file => releaseSurfaceCommitStep.includes(file)) &&
  releasePackageManifests.every(file =>
    releaseSurfaceCommitStep.indexOf(file) > releaseSurfaceCommitStep.indexOf('git add package.json package-lock.json README.md')
  ) &&
  releaseWorkflow.includes('HiveRelay release surfaces commit SHA is malformed.')
) {
  pass('release workflow commits every package version surface updated by release prep')
} else {
  fail('release workflow can leave package version changes unstaged after release prep')
}

const dockerPublishesReleaseTags =
  /^ {4}tags:\s*\[?['"]?v\*/m.test(dockerPublishWorkflow) ||
  dockerPublishWorkflow.includes('type=semver')

if (
  !dockerPublishesReleaseTags &&
  dockerPublishWorkflow.includes('Release tags are intentionally handled by release-surfaces.yml') &&
  releaseWorkflow.includes('docker buildx build') &&
  releaseWorkflow.includes('--metadata-file /tmp/hiverelay-image.json')
) {
  pass('release workflow is the sole release image publisher; docker-publish is snapshot-only')
} else {
  fail('docker-publish workflow can still publish release tags outside release-surfaces gates')
}

if (
  dockerignore.includes('**/node_modules') &&
  dockerignore.includes('startos/image') &&
  dockerignore.includes('startos/*.s9pk') &&
  dockerignore.includes('startos/*.tar') &&
  !dockerignore.includes('docker-entrypoint.sh')
) {
  pass('Docker build context excludes nested dependencies and generated StartOS package artifacts')
} else {
  fail('Docker build context can still include nested dependencies or generated StartOS package artifacts')
}

if (
  dockerfile.includes('COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh') &&
  dockerfile.includes('RUN chmod +x /usr/local/bin/docker-entrypoint.sh') &&
  dockerfile.includes('HIVERELAY_STORAGE=/data') &&
  dockerfile.includes('ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh", "node", "/app/packages/core/cli/index.js"]') &&
  dockerEntrypoint.startsWith('#!/bin/sh\nset -e\n') &&
  dockerEntrypoint.includes('exec gosu hiverelay "$@"') &&
  dockerEntrypoint.includes('exec "$@"') &&
  gitattributes.includes('docker-entrypoint.sh text eol=lf') &&
  configLoaderTest.includes('cli start uses HIVERELAY_STORAGE when --storage is absent') &&
  configLoaderTest.includes('cli start --storage overrides HIVERELAY_STORAGE')
) {
  pass('Docker runtime copies LF-pinned entrypoint and routes default container storage to /data')
} else {
  fail('Docker runtime can lose its entrypoint or ignore the /data storage volume')
}

if (new RegExp(`^version:\\s*${escapeRegExp(expectedVersion)}\\s*$`, 'm').test(startOsManifest)) {
  pass(`StartOS manifest version matches monorepo (${expectedVersion})`)
} else {
  fail(`StartOS manifest version does not match monorepo ${expectedVersion}`)
}

if (
  /^VERSION\s*\?=\s*\$\(shell\s+sed -n/m.test(startOsMakefile) &&
  startOsMakefile.includes('../package.json') &&
  !prepareRelease.includes('StartOS Makefile VERSION') &&
  !prepareRelease.includes("path.join(repoRoot, 'startos', 'Makefile'),\n    /^VERSION") &&
  releaseAutomationDocs.includes('`startos/Makefile` derives its default `VERSION` from the root') &&
  auditRoadmap.includes('Read StartOS package build version from root `package.json`') &&
  auditDoc.includes('Removed the hardcoded StartOS build `VERSION`')
) {
  pass('StartOS Makefile derives VERSION from root package.json by default')
} else {
  fail('StartOS Makefile can still drift from the root package.json version')
}

if (
  startOsMakefile.includes('IMAGE_DIGEST ?=') &&
  startOsMakefile.includes('ALLOW_TAG_ONLY_IMAGE ?=') &&
  startOsMakefile.includes('IMAGE_REF := $(IMAGE)$(if $(IMAGE_DIGEST),@$(IMAGE_DIGEST),)') &&
  startOsMakefile.includes('validate-image-ref:') &&
  startOsMakefile.includes('IMAGE_DIGEST=sha256:<multi-arch-digest> is required for StartOS packaging') &&
  startOsMakefile.includes('Use ALLOW_TAG_ONLY_IMAGE=1 only for local mechanics checks.') &&
  startOsMakefile.includes("grep -Eq '^sha256:[a-f0-9]{64}$$'") &&
  startOsMakefile.includes("printf 'FROM $(IMAGE_REF)\\n' > Dockerfile.retag") &&
  /^\.PHONY:.*\bimage\b.*\bvalidate-image-ref\b.*\bDockerfile\.retag\b/m.test(startOsMakefile) &&
  /^image:\s+validate-image-ref\s+check-digest\s+Dockerfile\.retag/m.test(startOsMakefile) &&
  startOsMakefile.includes('rm -rf image') &&
  monorepoPkg.scripts?.['startos:verify'] === 'cd startos && make verify IMAGE_DIGEST="$HIVERELAY_IMAGE_DIGEST"' &&
  monorepoPkg.scripts?.['startos:verify:local'] === 'cd startos && make verify ALLOW_TAG_ONLY_IMAGE=1' &&
  startosPackageGuardTest.includes('StartOS packaging requires an image digest unless local tag-only mode is explicit')
) {
  pass('StartOS Makefile rebuilds fresh per-arch tarballs from a digest-qualified GHCR image and rejects accidental tag-only release packaging')
} else {
  fail('StartOS Makefile can reuse stale image tarballs, allow accidental tag-only release packaging, or is missing digest-qualified image support')
}

if (startOsReadme.includes(`v${expectedVersion}, one-page dashboard`)) {
  pass('StartOS README status version matches monorepo')
} else {
  fail('StartOS README status version does not match monorepo')
}

if (
  startOsEntrypoint.includes('export HIVERELAY_UI_SIMPLE=1') &&
  startOsEntrypoint.includes('export HIVERELAY_ACCEPT_MODE=review') &&
  startOsEntrypoint.includes('export HIVERELAY_MAX_STORAGE=10GB') &&
  startOsReadme.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  startOsReadme.includes('first-boot-only 10 GB storage cap') &&
  startOsManifest.includes('conservative 10 GB storage cap') &&
  releaseAutomationDocs.includes('StartOS entrypoint mirrors') &&
  releaseAutomationDocs.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  auditDoc.includes('Mirrored the conservative home-server cap in the StartOS entrypoint')
) {
  pass('StartOS package uses review-mode/simple-dashboard defaults plus a first-boot-only home-server storage cap')
} else {
  fail('StartOS package is missing review-mode/simple-dashboard defaults or the first-boot storage cap documentation')
}

if (
  releaseWorkflow.includes('Build and verify StartOS package') &&
  releaseWorkflow.includes('Upload StartOS package to GitHub Release') &&
  releaseWorkflow.includes('startos/blindspark.s9pk --clobber') &&
  releaseWorkflow.includes('make verify IMAGE_DIGEST="$HIVERELAY_IMAGE_DIGEST"') &&
  releaseWorkflow.includes('StartOS package SHA-256 is malformed.') &&
  releaseWorkflow.includes('^[a-f0-9]{64}$') &&
  releaseWorkflow.includes('StartOS package id from startos/manifest.yaml is malformed.') &&
  releaseWorkflow.includes('^[a-z0-9][a-z0-9-]{1,63}$') &&
  releaseWorkflow.includes('STARTOS_DEVELOPER_KEY_PEM:') &&
  releaseWorkflow.includes('start-sdk init')
) {
  pass('release workflow signs, builds, verifies, and uploads the StartOS .s9pk artifact from the release digest')
} else {
  fail('release workflow is missing the StartOS signing/build/verify/upload steps')
}

const githubSemverExpression = '$' + '{{ steps.rel.outputs.semver }}'
const githubChannelExpression = '$' + '{{ steps.rel.outputs.channel }}'
const githubVersionExpression = '$' + '{{ steps.rel.outputs.version }}'
const shellEvidenceArrayExpression = '$' + '{evidence[@]}'
const shellReleaseBaseUrlExpression = '$' + '{release_base_url}'

if (
  releaseWorkflow.includes('STARTOS_REGISTRY_URL:') &&
  releaseWorkflow.includes('Publish StartOS registry package') &&
  releaseWorkflow.includes("env.STARTOS_REGISTRY_URL != ''") &&
  releaseWorkflow.includes("env.STARTOS_DEVELOPER_KEY_PEM != ''") &&
  releaseWorkflow.includes('start-sdk publish "$STARTOS_REGISTRY_URL" startos/blindspark.s9pk') &&
  releaseWorkflow.includes('registry_package_url="' + '$' + '{STARTOS_REGISTRY_URL%/}/' + '$' + '{HIVERELAY_STARTOS_PACKAGE_ID}"') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_STATUS=published') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_URL="$STARTOS_REGISTRY_URL"') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL="$registry_package_url"') &&
  releaseWorkflow.includes('npm run release:write-startos-registry-evidence -- --out startos-registry-evidence.json') &&
  releaseWorkflow.includes('sha256sum startos-registry-evidence.json') &&
  releaseWorkflow.includes('StartOS registry evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_URL "$STARTOS_REGISTRY_URL"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL "$registry_package_url"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_EVIDENCE startos-registry-evidence.json') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256 "$startos_registry_evidence_sha"') &&
  releaseWorkflow.includes('args+=(--startos-registry startos-registry-evidence.json)') &&
  releaseWorkflow.includes('Upload StartOS registry evidence') &&
  releaseWorkflow.includes('gh release upload "' + githubVersionExpression + '" startos-registry-evidence.json --clobber') &&
  releaseWorkflow.includes("--pattern 'startos-registry-evidence.json'") &&
  releaseWorkflow.includes('cmp startos-registry-evidence.json "$startos_registry_dir/startos-registry-evidence.json"') &&
  releaseWorkflow.indexOf('Upload StartOS registry evidence') > releaseWorkflow.indexOf('Verify published release evidence assets') &&
  startosRegistryEvidence.includes("kind: 'startos-registry-publication'") &&
  startosRegistryEvidence.includes('StartOS registry evidence generatedAt') &&
  startosRegistryEvidence.includes('ISO_TIMESTAMP_PATTERN') &&
  startosRegistryEvidence.includes('blindspark.s9pk') &&
  startosRegistryEvidence.includes('registryPackage') &&
  startosRegistryEvidence.includes('function isRegistryPackageUrl') &&
  startosRegistryEvidence.includes('StartOS registry package URL') &&
  startosRegistryEvidence.includes('release-evidence.json') &&
  startosRegistryEvidence.includes('release-image-manifest-evidence.json') &&
  startosRegistryEvidence.includes('release-image-smoke-evidence.json') &&
  startosRegistryEvidence.includes("EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'") &&
  startosRegistryEvidence.includes('body.workflow.repository, EXPECTED_RELEASE_REPOSITORY') &&
  startosRegistryEvidence.includes('POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/') &&
  startosRegistryEvidence.includes('GITHUB_ACTIONS_RUN_URL_PATTERN') &&
  startosRegistryEvidence.includes('workflow URL matches repository and run id') &&
  startosRegistryEvidence.includes("return String(process.env[name] ?? '')") &&
  !startosRegistryEvidence.includes("return String(process.env[name] || '').trim()") &&
  startosRegistryEvidence.includes('assertStartosRegistryEvidenceSchema') &&
  startosRegistryEvidence.includes("requireOnlyKeys('StartOS registry evidence'") &&
  startosRegistryEvidence.includes('has unsupported fields') &&
  startosRegistryEvidence.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  startosRegistryEvidence.includes('APP_SEED') &&
  startosRegistryEvidence.includes('HIVERELAY_API_KEY') &&
  startosRegistryEvidence.includes('assertPublicSafeValues') &&
  startosRegistryEvidence.includes('hasControlChars') &&
  startosRegistryEvidence.includes('must not contain control characters') &&
  startosRegistryEvidence.includes('MAX_EVIDENCE_JSON_BYTES') &&
  startosRegistryEvidence.includes('workflow run attempt') &&
  startosRegistryEvidence.includes('must not expose URL credentials') &&
  startosRegistryEvidence.includes('reserved/local hostnames') &&
  startosRegistryEvidence.includes('function isPublicHostname') &&
  startosRegistryEvidence.includes('!url.search') &&
  startosRegistryEvidence.includes('!url.hash') &&
  startosRegistryEvidence.includes('verifyPresentStartosPackage') &&
  startosRegistryEvidence.includes('await verifyPresentStartosPackage(body)') &&
  startosRegistryEvidence.includes('verifyLinkedReleaseImageEvidence') &&
  startosRegistryEvidence.includes('await verifyLinkedReleaseImageEvidence()') &&
  startosRegistryEvidence.includes('verifyLinkedEvidenceFile') &&
  startosRegistryEvidence.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE') &&
  startosRegistryEvidence.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256') &&
  startosRegistryEvidence.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE') &&
  startosRegistryEvidence.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256') &&
  startosRegistryEvidence.includes('readLinkedEvidenceJson') &&
  startosRegistryEvidence.includes('file must contain valid JSON') &&
  startosRegistryEvidence.includes('SHA-256 does not match') &&
  startosRegistryEvidence.includes('file is required before writing registry evidence') &&
  startosRegistryEvidence.includes('file must be ' + '$' + '{MAX_EVIDENCE_JSON_BYTES} bytes or smaller') &&
  startosRegistryEvidence.includes('function sha256File') &&
  startosRegistryEvidence.includes('fs.createReadStream(file)') &&
  !startosRegistryEvidence.includes("fs.readFileSync(file, 'base64')") &&
  startosRegistryEvidence.includes("requireRegularFile('StartOS package'") &&
  startosRegistryEvidence.includes('file must not be a symlink') &&
  startosRegistryEvidence.includes('file must be a regular file') &&
  startosRegistryEvidence.includes('StartOS package SHA-256 does not match') &&
  startosRegistryEvidenceTest.includes('rejects placeholder registry hosts') &&
  startosRegistryEvidenceTest.includes('keeps a closed public schema') &&
  startosRegistryEvidenceTest.includes('StartOS registry evidence generatedAt is an ISO timestamp') &&
  startosRegistryEvidenceTest.includes('verifies present package artifacts before writing evidence') &&
  startosRegistryEvidenceTest.includes('hashes present package artifacts as a stream') &&
  startosRegistryEvidenceTest.includes('requires the local package artifact before writing evidence') &&
  startosRegistryEvidenceTest.includes('requires linked release image evidence before writing registry evidence') &&
  startosRegistryEvidenceTest.includes('rejects linked release image evidence hash drift') &&
  startosRegistryEvidenceTest.includes('rejects miswired release image evidence env before writing registry evidence') &&
  startosRegistryEvidenceTest.includes('rejects unsafe linked release image evidence before write') &&
  startosRegistryEvidenceTest.includes('rejects symlinked present package artifacts') &&
  startosRegistryEvidenceTest.includes('rejects non-regular present package artifacts') &&
  startosRegistryEvidenceTest.includes('rejects present package artifact hash drift') &&
  startosRegistryEvidenceTest.includes('derives package URL from registry and package id') &&
  startosRegistryEvidenceTest.includes('rejects mismatched package URLs') &&
  startosRegistryEvidenceTest.includes('zero-run-id.json') &&
  startosRegistryEvidenceTest.includes('bad-workflow-server.json') &&
  startosRegistryEvidenceTest.includes('rejects whitespace-normalized metadata before write') &&
  startosRegistryEvidenceTest.includes('releaseImageManifest') &&
  startosRegistryEvidenceTest.includes('releaseImageSmoke') &&
  githubEnvWriter.includes('Refusing to write multi-line or control-character value') &&
  githubEnvWriter.includes('/^[A-Z_][A-Z0-9_]*$/') &&
  releaseAutomationDocs.includes('startos-registry-evidence.json') &&
  releaseAutomationDocs.includes('image-proof links') &&
  releaseAutomationDocs.includes('validates raw workflow, registry, package, hash, and linked evidence') &&
  releaseAutomationDocs.includes('without trimming whitespace before writing public registry evidence') &&
  auditRoadmap.includes('StartOS registry raw metadata proof') &&
  releaseWorkflow.includes('Verify stable release distribution credentials') &&
  releaseWorkflow.indexOf('Publish StartOS registry package') > releaseWorkflow.indexOf('Commit HiveRelay release surfaces')
) {
  pass('release workflow publishes and evidence-links the verified StartOS package to the configured registry after metadata commit')
} else {
  fail('release workflow is missing required stable-release StartOS registry publication/evidence after metadata commit')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['release:check-image-manifest'] === 'node scripts/check-release-image-manifest.mjs' &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'check-release-image-manifest.mjs')) &&
  releaseImageManifestCheck.includes('REQUIRED_PLATFORMS') &&
  releaseImageManifestCheck.includes("'linux/amd64', 'linux/arm64'") &&
  releaseImageManifestCheck.includes('docker') &&
  releaseImageManifestCheck.includes('buildx') &&
  releaseImageManifestCheck.includes('imagetools') &&
  releaseImageManifestCheck.includes('inspect') &&
  releaseImageManifestCheck.includes('MAX_RAW_MANIFEST_BYTES') &&
  releaseImageManifestCheck.includes('stat.isSymbolicLink()') &&
  releaseImageManifestCheck.includes('raw manifest file must be a regular file') &&
  releaseImageManifestCheck.includes("kind: 'release-image-manifest'") &&
  releaseImageManifestCheck.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  releaseImageManifestCheck.includes('APP_SEED') &&
  releaseImageManifestCheck.includes('HIVERELAY_API_KEY') &&
  releaseImageManifestCheck.includes('assertPublicSafeValues') &&
  releaseImageManifestCheck.includes('assertEvidenceSchema') &&
  releaseImageManifestCheck.includes('has unsupported fields') &&
  releaseImageManifestCheck.includes('release image manifest has duplicate platform') &&
  releaseImageManifestCheck.includes('release image manifest evidence has duplicate platform') &&
  releaseImageManifestCheckTest.includes('writes platform evidence for multi-arch indexes') &&
  releaseImageManifestCheckTest.includes('rejects missing required platforms') &&
  releaseImageManifestCheckTest.includes('rejects duplicate platform entries') &&
  releaseImageManifestCheckTest.includes('rejects mutable or wrong-repository image refs') &&
  releaseImageManifestCheckTest.includes('rejects symlinked raw fixtures and unsafe raw values') &&
  releaseWorkflow.includes('Verify release image manifest platforms') &&
  releaseWorkflow.includes('npm run release:check-image-manifest --') &&
  releaseWorkflow.includes('--image "$IMAGE_NAME:' + githubSemverExpression + '@$HIVERELAY_IMAGE_DIGEST"') &&
  releaseWorkflow.includes('--out release-image-manifest-evidence.json') &&
  releaseWorkflow.includes('sha256sum release-image-manifest-evidence.json') &&
  releaseWorkflow.includes('Release image manifest evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_STATUS=passed') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE=release-image-manifest-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256=$image_manifest_sha') &&
  releaseWorkflow.includes('args+=(--release-image-manifest release-image-manifest-evidence.json)') &&
  releaseWorkflow.includes('hiverelay/release-image-manifest-evidence.json') &&
  releaseWorkflow.includes('evidence+=(release-image-manifest-evidence.json)') &&
  releaseWorkflow.includes("--pattern 'release-image-manifest-evidence.json'") &&
  releaseWorkflow.indexOf('Verify release image manifest platforms') > releaseWorkflow.indexOf('Build and push multi-arch image') &&
  releaseWorkflow.indexOf('Verify release image manifest platforms') < releaseWorkflow.indexOf('Smoke pushed release image') &&
  releaseEvidence.includes('imageManifest') &&
  releaseEvidence.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE_SHA256') &&
  releaseEvidence.includes('successful release image manifest evidence path') &&
  releaseEvidenceVerify.includes('--release-image-manifest <path>') &&
  releaseEvidenceVerify.includes('REQUIRED_IMAGE_PLATFORMS') &&
  releaseEvidenceVerify.includes('release-image-manifest-evidence.json') &&
  releaseEvidenceVerify.includes('verifyImageManifestSidecar') &&
  releaseEvidenceVerify.includes('release image manifest generatedAt must not be after release generatedAt') &&
  releaseEvidenceVerify.includes('assertImageManifestSidecarSchema') &&
  releaseEvidenceVerify.includes('release image manifest required platforms') &&
  releaseEvidenceVerify.includes('release image manifest evidence has duplicate platform') &&
  releaseHandoffEvidenceVerify.includes('--release-image-manifest <path>') &&
  releaseHandoffEvidenceVerify.includes('REQUIRED_IMAGE_PLATFORMS') &&
  releaseHandoffEvidenceVerify.includes('release-image-manifest-evidence.json') &&
  releaseHandoffEvidenceVerify.includes('verifyImageManifestSidecar') &&
  releaseHandoffEvidenceVerify.includes('release image manifest generatedAt must not be after release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('assertImageManifestSidecarSchema') &&
  releaseHandoffEvidenceVerify.includes('release image manifest evidence has duplicate platform') &&
  releaseEvidenceTest.includes('HIVERELAY_RELEASE_IMAGE_MANIFEST_STATUS') &&
  releaseEvidenceVerifyTest.includes('release-image-manifest-evidence.json') &&
  releaseEvidenceVerifyTest.includes('rejects future image-manifest sidecar timestamps') &&
  releaseEvidenceVerifyTest.includes('rejects duplicate image-manifest platform entries') &&
  releaseEvidenceVerifyTest.includes('rejects unsupported image-manifest sidecar fields') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-manifest-evidence.json') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects future image-manifest sidecar timestamps') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects duplicate image-manifest platform entries') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported image-manifest sidecar fields') &&
  readme.includes('release-image-manifest-evidence.json') &&
  releaseAutomationDocs.includes('release-image-manifest-evidence.json') &&
  umbrelSubmissionChecklist.includes('npm run release:check-image-manifest') &&
  auditRoadmap.includes('Release image manifest platform proof') &&
  auditDoc.includes('Hardened release image platform proof')
) {
  pass('release workflow proves multi-arch release image manifests before smoke, package, and handoff evidence')
} else {
  fail('release workflow is missing release-image manifest platform proof, evidence, verifier, docs, or tests')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['release:smoke-image'] === 'node scripts/smoke-release-image.mjs' &&
  releaseWorkflow.includes('Smoke pushed release image') &&
  releaseWorkflow.includes('npm run release:smoke-image --') &&
  releaseWorkflow.includes('"$IMAGE_NAME:' + githubSemverExpression + '@$HIVERELAY_IMAGE_DIGEST"') &&
  releaseWorkflow.includes('--evidence release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('sha256sum release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE=release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256=$image_smoke_sha') &&
  releaseWorkflow.indexOf('Smoke pushed release image') > releaseWorkflow.indexOf('Build and push multi-arch image') &&
  releaseWorkflow.indexOf('Smoke pushed release image') < releaseWorkflow.indexOf('Return to main for metadata sync') &&
  releaseImageSmoke.includes('--evidence <path>') &&
  releaseImageSmoke.includes('parseTimeoutMs') &&
  releaseImageSmoke.includes('MAX_SMOKE_TIMEOUT_MS = 30 * 60 * 1000') &&
  releaseImageSmoke.includes('MAX_EVIDENCE_JSON_BYTES') &&
  releaseImageSmoke.includes('Number.isSafeInteger(parsed)') &&
  releaseImageSmoke.includes('redactSensitiveOutput') &&
  releaseImageSmoke.includes('writeRedactedOutput') &&
  releaseImageSmoke.includes('formatCommand(cmd, argv)') &&
  releaseImageSmoke.includes('DIGEST_PINNED_IMAGE_REF_PATTERN') &&
  releaseImageSmoke.includes("REQUIRED_IMAGE_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])") &&
  releaseImageSmoke.includes('parseDigestPinnedImageRef') &&
  releaseImageSmoke.includes('imageName') &&
  releaseImageSmoke.includes('imageTag') &&
  releaseImageSmoke.includes('imageDigest') &&
  releaseImageSmoke.includes('isDigestPinnedImageRef') &&
  releaseImageSmoke.includes('requires a GHCR semver tag plus sha256 digest image ref') &&
  releaseImageSmoke.includes('requireImageManifestEvidence') &&
  releaseImageSmoke.includes('release image manifest evidence file is required before writing smoke evidence') &&
  releaseImageSmoke.includes('release image manifest evidence file must not be a symlink') &&
  releaseImageSmoke.includes('release image manifest evidence file must be a regular file') &&
  releaseImageSmoke.includes('release image manifest evidence file must be') &&
  releaseImageSmoke.includes('readImageManifestEvidence') &&
  releaseImageSmoke.includes('release image manifest image ref must match smoke image ref') &&
  releaseImageSmoke.includes('release image manifest image digest must match smoke image digest') &&
  releaseImageSmoke.includes('assertManifestPlatforms') &&
  releaseImageSmoke.includes('release image manifest evidence is missing required platform') &&
  releaseImageSmoke.includes('writeSmokeEvidence') &&
  releaseImageSmoke.includes("kind: 'release-image-smoke'") &&
  releaseImageSmoke.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  releaseImageSmoke.includes('APP_SEED') &&
  releaseImageSmoke.includes('HIVERELAY_API_KEY') &&
  releaseImageSmoke.includes('FORBIDDEN_PUBLIC_SMOKE_KEYS') &&
  releaseImageSmoke.includes('assertPublicSafeSmoke') &&
  releaseImageSmoke.includes('hasControlChars') &&
  releaseImageSmoke.includes('must not contain control characters') &&
  releaseImageSmoke.includes('must not expose URL credentials') &&
  releaseImageSmoke.includes('/api/usage') &&
  releaseImageSmoke.includes('/api/poker/usage') &&
  releaseImageSmoke.includes('assertDashboardWebSocket') &&
  releaseImageSmoke.includes('queryTokenRejected') &&
  releaseImageSmoke.includes('assertDashboardUiHardening') &&
  releaseImageSmoke.includes('assertSetupWizardUiHardening') &&
  releaseImageSmoke.includes('walletBusyState') &&
  releaseImageSmoke.includes('serviceActionState') &&
  releaseImageSmoke.includes('aiModelAddState') &&
  releaseImageSmoke.includes('appProxyWrites') &&
  releaseImageSmoke.includes('leasePollingBounded') &&
  releaseImageSmoke.includes('staticMarkupSafe') &&
  releaseImageSmoke.includes('statusRegion') &&
  releaseImageSmoke.includes('actionLock') &&
  releaseImageSmoke.includes('dashboardLinkAppPath') &&
  releaseImageSmoke.includes("recordCheck('dashboardWebSocket'") &&
  releaseImageSmoke.includes("recordCheck('usageTelemetry'") &&
  releaseImageSmoke.includes('HIVERELAY_ACCEPT_MODE=review') &&
  releaseImageSmoke.includes("recordCheck('acceptModeDefault'") &&
  releaseImageSmoke.includes('/api/subsidy/destination') &&
  releaseImageSmoke.includes('/api/manage/services/config') &&
  releaseImageSmoke.includes("plugins: ['poker', 'ai']") &&
  releaseImageSmoke.includes("EXPECTED_POKER_AI_PLUGINS = Object.freeze(['poker', 'vrf', 'arbitration', 'zk', 'ai'])") &&
  releaseImageSmoke.includes('assertPluginList(out?.config?.plugins, EXPECTED_POKER_AI_PLUGINS') &&
  releaseSmokeEvidenceWriterTest.includes('reject malformed timeout values before side effects') &&
  releaseSmokeEvidenceWriterTest.includes('require digest-pinned image refs before writing public evidence') &&
  releaseSmokeEvidenceWriterTest.includes('require release image manifest evidence before writing public evidence') &&
  releaseSmokeEvidenceWriterTest.includes('rejects stale manifest image provenance') &&
  releaseSmokeEvidenceWriterTest.includes('rejects incomplete manifest platforms') &&
  releaseSmokeEvidenceWriterTest.includes('redact failed docker logs and command output') &&
  releaseSmokeEvidenceWriterTest.includes('verifies packaged dashboard UI-hardening contracts') &&
  releaseSmokeEvidenceWriterTest.includes('verifies packaged setup wizard UI-hardening contracts') &&
  releaseEvidenceVerify.includes('release generatedAt') &&
  releaseEvidenceVerify.includes('`$' + '{kind} generatedAt`') &&
  releaseEvidenceVerify.includes('generatedAt must not be after release generatedAt') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageName`') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageTag`') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageDigest`') &&
  releaseEvidenceVerify.includes('walletBusyState') &&
  releaseEvidenceVerify.includes('serviceActionState') &&
  releaseEvidenceVerify.includes('aiModelAddState') &&
  releaseEvidenceVerify.includes('appProxyWrites') &&
  releaseEvidenceVerify.includes('leasePollingBounded') &&
  releaseEvidenceVerify.includes('staticMarkupSafe') &&
  releaseEvidenceVerify.includes('statusRegion') &&
  releaseEvidenceVerify.includes('actionLock') &&
  releaseEvidenceVerify.includes('dashboardLinkAppPath') &&
  releaseHandoffEvidenceVerify.includes('release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} generatedAt`') &&
  releaseHandoffEvidenceVerify.includes('generatedAt must not be after release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageName`') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageTag`') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageDigest`') &&
  releaseHandoffEvidenceVerify.includes('walletBusyState') &&
  releaseHandoffEvidenceVerify.includes('serviceActionState') &&
  releaseHandoffEvidenceVerify.includes('aiModelAddState') &&
  releaseHandoffEvidenceVerify.includes('appProxyWrites') &&
  releaseHandoffEvidenceVerify.includes('leasePollingBounded') &&
  releaseHandoffEvidenceVerify.includes('staticMarkupSafe') &&
  releaseHandoffEvidenceVerify.includes('statusRegion') &&
  releaseHandoffEvidenceVerify.includes('actionLock') &&
  releaseHandoffEvidenceVerify.includes('dashboardLinkAppPath') &&
  releaseEvidenceVerifyTest.includes('rejects smoke image provenance drift') &&
  releaseEvidenceVerifyTest.includes('rejects stale smoke evidence timestamps') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke dashboard walletBusyState') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke dashboard appProxyWrites') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke setupWizard actionLock') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke setupWizard dashboardLinkAppPath') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke dashboard walletBusyState') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke dashboard appProxyWrites') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke setupWizard actionLock') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke setupWizard dashboardLinkAppPath') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale smoke evidence timestamps')
) {
  pass('release workflow boots the pushed image digest and checks authenticated wallet/services writes before metadata promotion')
} else {
  fail('release workflow is missing authenticated pushed-image smoke checks before metadata promotion')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['release:write-evidence'] === 'node scripts/write-release-evidence.mjs' &&
  monorepoPkg.scripts['release:write-official-umbrel-pr-evidence'] === 'node scripts/write-official-umbrel-pr-evidence.mjs' &&
  monorepoPkg.scripts['release:write-startos-registry-evidence'] === 'node scripts/write-startos-registry-evidence.mjs' &&
  monorepoPkg.scripts['release:verify-evidence'] === 'node scripts/verify-release-evidence.mjs' &&
  monorepoPkg.scripts['release:verify-handoff-evidence'] === 'node scripts/verify-release-handoff-evidence.mjs' &&
  monorepoPkg.scripts['release:verify-review-ready-handoff'] === 'node scripts/verify-release-handoff-evidence.mjs --require-umbrel-runtime-review' &&
  releaseEvidence.includes('schemaVersion: 1') &&
  releaseEvidence.includes('release evidence generatedAt') &&
  releaseEvidence.includes('ISO_TIMESTAMP_PATTERN') &&
  releaseEvidence.includes("return String(process.env[name] ?? '')") &&
  !releaseEvidence.includes("return String(process.env[name] || '').trim()") &&
  releaseEvidence.includes('distributionPreflight') &&
  releaseEvidence.includes('pushedImageSmokeEvidence') &&
  releaseEvidence.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256') &&
  releaseEvidence.includes('umbrelPackageSmokeEvidence') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256') &&
  releaseEvidence.includes('startosPackage') &&
  releaseEvidence.includes('HIVERELAY_STARTOS_PACKAGE_SHA256') &&
  releaseEvidence.includes('fleetRollout') &&
  releaseEvidence.includes('fleetRolloutChannel') &&
  releaseEvidence.includes('fleetRolloutEvidence') &&
  releaseEvidence.includes('HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256') &&
  releaseEvidence.includes('npmPackages') &&
  releaseEvidence.includes('HIVERELAY_NPM_PUBLISH_STATUS') &&
  releaseEvidence.includes('successful prerelease npm packages') &&
  releaseEvidence.includes('successful full release npm packages') &&
  releaseEvidence.includes('startosRegistry') &&
  releaseEvidence.includes('startosRegistryUrl') &&
  releaseEvidence.includes('startosRegistryPackageUrl') &&
  releaseEvidence.includes('startosPackageId') &&
  releaseEvidence.includes('umbrelOfficial') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATE') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_BASE') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID') &&
  releaseEvidence.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT') &&
  releaseEvidence.includes('validateSuccessfulRun') &&
  releaseEvidence.includes("EXPECTED_RELEASE_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'") &&
  releaseEvidence.includes("EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'") &&
  releaseEvidence.includes('release semver matches version') &&
  releaseEvidence.includes('successful release workflow repository') &&
  releaseEvidence.includes('body.release.workflow.repository, EXPECTED_RELEASE_REPOSITORY') &&
  releaseEvidence.includes('successful release workflow run id') &&
  releaseEvidence.includes('successful release workflow run attempt') &&
  releaseEvidence.includes('POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/') &&
  releaseEvidence.includes('GITHUB_ACTIONS_RUN_URL_PATTERN') &&
  releaseEvidence.includes('OFFICIAL_UMBREL_PR_URL_PATTERN') &&
  releaseEvidence.includes('successful release workflow URL') &&
  releaseEvidence.includes('successful release metadata SHA') &&
  releaseEvidence.includes('successful release image name') &&
  releaseEvidence.includes('body.image.name, EXPECTED_RELEASE_IMAGE_NAME') &&
  releaseEvidence.includes('successful release image ref') &&
  releaseEvidence.includes('successful release StartOS package path') &&
  releaseEvidence.includes('successful release StartOS package SHA-256') &&
  releaseEvidence.includes('successful release image smoke evidence SHA-256') &&
  releaseEvidence.includes('successful release Umbrel package smoke evidence SHA-256') &&
  releaseEvidence.includes('successful full release fleet rollout') &&
  releaseEvidence.includes('successful full release fleet rollout channel') &&
  releaseEvidence.includes('successful full release fleet rollout evidence SHA-256') &&
  releaseEvidence.includes('successful full release official Umbrel PR') &&
  releaseEvidence.includes('successful full release official Umbrel PR head SHA') &&
  releaseEvidence.includes('successful full release official Umbrel PR state') &&
  releaseEvidence.includes('successful full release official Umbrel PR draft') &&
  releaseEvidence.includes('successful full release official Umbrel PR base') &&
  releaseEvidence.includes('function isGitHubOwnerName') &&
  releaseEvidence.includes('function isGitHubHeadRefName') &&
  releaseEvidence.includes('normal GitHub owner name') &&
  releaseEvidence.includes('must not be getumbrel') &&
  releaseEvidence.includes("value.toLowerCase() !== 'getumbrel'") &&
  releaseEvidence.includes('normal GitHub branch name') &&
  releaseEvidence.includes('successful full release official Umbrel PR head owner matches head owner') &&
  releaseEvidence.includes('successful full release official Umbrel PR head ref matches head branch') &&
  releaseEvidence.includes('successful full release official Umbrel PR head OID matches head SHA') &&
  releaseEvidence.includes('successful full release Umbrel community-store commit URL') &&
  releaseEvidence.includes('successful full release StartOS registry publish') &&
  releaseEvidence.includes('successful full release StartOS registry URL') &&
  releaseEvidence.includes('successful full release StartOS registry package URL') &&
  releaseEvidence.includes('startosRegistryEvidence') &&
  releaseEvidence.includes('HIVERELAY_STARTOS_REGISTRY_EVIDENCE_SHA256') &&
  releaseEvidence.includes('successful prerelease StartOS registry evidence path') &&
  releaseEvidence.includes('successful prerelease StartOS registry evidence hash') &&
  releaseEvidence.includes('successful full release StartOS registry evidence path') &&
  releaseEvidence.includes('successful full release StartOS registry evidence SHA-256') &&
  releaseEvidence.includes('HIVERELAY_STARTOS_REGISTRY_URL must be a public https URL without embedded credentials, query strings, fragments, or reserved/local hostnames') &&
  releaseEvidence.includes('HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL must be the public registry URL plus the StartOS package id') &&
  releaseEvidence.includes('requirePublicHttpsUrl') &&
  releaseEvidence.includes('function isRegistryPackageUrl') &&
  releaseEvidence.includes('function isPublicHostname') &&
  releaseEvidence.includes('!url.search') &&
  releaseEvidence.includes('!url.hash') &&
  releaseEvidence.includes("'.example.com'") &&
  releaseEvidence.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  releaseEvidence.includes('APP_SEED') &&
  releaseEvidence.includes('HIVERELAY_API_KEY') &&
  releaseEvidence.includes('assertPublicSafeValues') &&
  releaseEvidence.includes('hasControlChars') &&
  releaseEvidence.includes('must not contain control characters') &&
  releaseEvidence.includes('must not expose URL credentials') &&
  releaseEvidence.includes('MAX_EVIDENCE_JSON_BYTES') &&
  releaseEvidence.includes('verifyPresentEvidenceFiles') &&
  releaseEvidence.includes('await verifyPresentEvidenceFiles(body, false)') &&
  releaseEvidence.includes('await verifyPresentEvidenceFiles(body, true)') &&
  releaseEvidence.includes('file is required before writing successful release evidence') &&
  releaseEvidence.includes('file must not be a symlink') &&
  releaseEvidence.includes('file must be a regular file') &&
  releaseEvidence.includes('bytes or smaller') &&
  releaseEvidence.includes('readPublicEvidenceJson') &&
  releaseEvidence.includes('file must contain valid JSON') &&
  releaseEvidence.includes('file must contain a JSON object') &&
  releaseEvidence.includes('assertPublicSafeValues(readPublicEvidenceJson(label, file), label)') &&
  releaseEvidence.includes('SHA-256 does not match') &&
  releaseEvidence.includes('verifyPresentStartosPackage') &&
  releaseEvidence.includes('await verifyPresentStartosPackage(body)') &&
  releaseEvidence.includes("verifyPresentArtifactFile('StartOS package'") &&
  releaseEvidence.includes('function sha256File') &&
  releaseEvidence.includes('const actualSha256 = await sha256File(file)') &&
  releaseEvidence.includes('fs.createReadStream(file)') &&
  releaseEvidence.includes('`$' + '{label} file must not be a symlink') &&
  releaseEvidence.includes('`$' + '{label} file must be a regular file') &&
  releaseEvidence.includes('`$' + '{label} SHA-256 does not match') &&
  releaseEvidence.includes('fleet channel config path must be fleet/channels.json') &&
  releaseEvidence.includes('fleet channel config file must not be a symlink') &&
  releaseEvidenceTest.includes('rejects env-style secret public values before writing evidence') &&
  releaseEvidenceTest.includes('release evidence generatedAt is an ISO timestamp') &&
  releaseEvidenceTest.includes('successful release workflow repository must be') &&
  releaseEvidenceTest.includes('zero-run-id.json') &&
  releaseEvidenceTest.includes('zero-run-attempt.json') &&
  releaseEvidenceTest.includes('rejects whitespace-normalized metadata before write') &&
  releaseEvidenceTest.includes('zero-official-pr.json') &&
  releaseEvidenceTest.includes('ghcr.io/attacker/p2p-hiverelay') &&
  releaseEvidenceTest.includes('rejects successful full releases with stale official Umbrel PR state') &&
  releaseEvidenceTest.includes('rejects malformed official Umbrel PR GitHub owner names') &&
  releaseEvidenceTest.includes('GetUmbrel') &&
  releaseEvidenceTest.includes('rejects malformed official Umbrel PR GitHub head refs') &&
  releaseEvidenceTest.includes('rejects placeholder StartOS registry hosts') &&
  releaseEvidenceTest.includes('successful full release StartOS registry evidence path') &&
  releaseEvidenceTest.includes('successful full release StartOS registry evidence SHA-256') &&
  releaseEvidenceTest.includes('rejects symlinked present sidecars before writing evidence') &&
  releaseEvidenceTest.includes('rejects oversized present sidecars before hashing') &&
  releaseEvidenceTest.includes('rejects present sidecar hash drift') &&
  releaseEvidenceTest.includes('rejects unsafe or malformed present sidecars before writing evidence') &&
  releaseEvidenceTest.includes('hashes public sidecars as streams') &&
  releaseEvidenceTest.includes('requires successful release sidecars and package before writing evidence') &&
  releaseEvidenceTest.includes('verifies present StartOS package artifacts before writing evidence') &&
  releaseEvidenceTest.includes('hashes present StartOS package artifacts as a stream') &&
  releaseEvidenceTest.includes('rejects symlinked present StartOS package artifacts') &&
  releaseEvidenceTest.includes('rejects non-regular present StartOS package artifacts') &&
  releaseEvidenceTest.includes('rejects present StartOS package artifact hash drift') &&
  releaseEvidenceTest.includes('hashes canonical fleet channel config fallbacks from the release workspace') &&
  releaseEvidenceTest.includes('rejects non-canonical fleet channel config hash fallback paths') &&
  releaseEvidenceTest.includes('rejects symlinked fleet channel config hash fallbacks') &&
  releaseEvidenceTest.includes('rejects oversized fleet channel config hash fallbacks') &&
  releaseAutomationDocs.includes('release certificate writer validates raw') &&
  releaseAutomationDocs.includes('workflow, release, image, surface, and sidecar metadata') &&
  releaseAutomationDocs.includes('without trimming') &&
  releaseAutomationDocs.includes('whitespace before writing public release evidence') &&
  auditRoadmap.includes('Release certificate raw metadata proof') &&
  releaseEvidence.includes('successful full release StartOS package id') &&
  releaseEvidenceVerify.includes('--startos-registry <path>') &&
  releaseEvidenceVerify.includes('startosRegistryFile: inputs.startosRegistryFile') &&
  releaseEvidenceVerify.includes('--bundle-dir <path>') &&
  releaseEvidenceVerify.includes('--allow-failed-diagnostic') &&
  releaseEvidenceVerify.includes('resolveInputs') &&
  releaseEvidenceVerify.includes('release workflow status must be "success"') &&
  releaseEvidenceVerify.includes('Diagnostic release evidence verified') &&
  releaseEvidenceVerify.includes('release-image-smoke-evidence.json') &&
  releaseEvidenceVerify.includes('umbrel-package-smoke-evidence.json') &&
  releaseEvidenceVerify.includes('verifySuccessfulWorkflowIdentity') &&
  releaseEvidenceVerify.includes("EXPECTED_RELEASE_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'") &&
  releaseEvidenceVerify.includes("EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'") &&
  releaseEvidenceVerify.includes('successful release workflow repository') &&
  releaseEvidenceVerify.includes('workflow.repository, EXPECTED_RELEASE_REPOSITORY') &&
  releaseEvidenceVerify.includes('successful release workflow run id') &&
  releaseEvidenceVerify.includes('successful release workflow run attempt') &&
  releaseEvidenceVerify.includes('POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/') &&
  releaseEvidenceVerify.includes('OFFICIAL_UMBREL_PR_URL_PATTERN') &&
  releaseEvidenceVerify.includes('successful release workflow URL') &&
  releaseEvidenceVerify.includes('release.metadataSha') &&
  releaseEvidenceVerify.includes('StartOS package path') &&
  releaseEvidenceVerify.includes('verifySmokeSidecar') &&
  releaseEvidenceVerify.includes("EXPECTED_SMOKE_SERVICE_PLUGINS = Object.freeze(['poker', 'vrf', 'arbitration', 'zk', 'ai'])") &&
  releaseEvidenceVerify.includes('verifySmokeServiceChecks') &&
  releaseEvidenceVerify.includes('servicesSave plugins') &&
  releaseEvidenceVerify.includes('servicesPersistence active') &&
  releaseEvidenceVerify.includes('RELEASE_IMAGE_SMOKE_CHECKS') &&
  releaseEvidenceVerify.includes('UMBREL_PACKAGE_SMOKE_CHECKS') &&
  releaseEvidenceVerify.includes("'dashboardWebSocket'") &&
  releaseEvidenceVerify.includes('image.ref matches image name, release semver, and digest') &&
  releaseEvidenceVerify.includes('body.image?.name, EXPECTED_RELEASE_IMAGE_NAME') &&
  releaseEvidenceVerify.includes("'usageTelemetry'") &&
  releaseEvidenceVerify.includes("'acceptModeDefault'") &&
  releaseEvidenceVerify.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  releaseEvidenceVerify.includes('APP_SEED') &&
  releaseEvidenceVerify.includes('HIVERELAY_API_KEY') &&
  releaseEvidenceVerify.includes('sk-[A-Za-z0-9_-]') &&
  releaseEvidenceVerify.includes('assertPublicSafeValues') &&
  releaseEvidenceVerify.includes('hasControlChars') &&
  releaseEvidenceVerify.includes('must not contain control characters') &&
  releaseEvidenceVerify.includes('must not expose URL credentials') &&
  releaseEvidenceVerify.includes('MAX_EVIDENCE_JSON_BYTES') &&
  releaseEvidenceVerify.includes('readRegularFile') &&
  releaseEvidenceVerify.includes('file must not be a symlink') &&
  releaseEvidenceVerify.includes('file must be a regular file') &&
  releaseEvidenceVerify.includes('bytes or smaller') &&
  releaseEvidenceVerify.includes('without embedded credentials') &&
  releaseEvidenceVerify.includes('reserved/local hostnames') &&
  releaseEvidenceVerify.includes('function isPublicHostname') &&
  releaseEvidenceVerify.includes('!url.search') &&
  releaseEvidenceVerify.includes('!url.hash') &&
  releaseEvidenceVerify.includes('assertPublicSafeSmoke') &&
  releaseEvidenceVerify.includes('verifyOptionalFleetRollout') &&
  releaseEvidenceVerify.includes('verifyFleetRolloutSidecar') &&
  releaseEvidenceVerify.includes('ISO_TIMESTAMP_PATTERN') &&
  releaseEvidenceVerify.includes('requireIsoTimestamp') &&
  releaseEvidenceVerify.includes('fleet rollout generatedAt') &&
  releaseEvidenceVerify.includes('observedAt must not be after fleet rollout generatedAt') &&
  releaseEvidenceVerify.includes('sha256File') &&
  releaseEvidenceVerify.includes('fleet rollout target sha') &&
  releaseEvidenceVerify.includes('relay.packageVersion, release.release.version') &&
  releaseEvidenceVerify.includes('duplicate relay name') &&
  releaseEvidenceVerify.includes('channel both must include canary and stable relays') &&
  releaseEvidenceVerify.includes('StartOS registry URL') &&
  releaseEvidenceVerify.includes('npm packages') &&
  releaseEvidenceVerify.includes('StartOS registry package URL') &&
  releaseEvidenceVerify.includes('StartOS registry evidence path') &&
  releaseEvidenceVerify.includes('StartOS registry evidence SHA-256') &&
  releaseEvidenceVerify.includes('verifyStartosRegistrySidecar') &&
  releaseEvidenceVerify.includes('StartOS registry evidence hash') &&
  releaseEvidenceVerify.includes('StartOS registry evidence generatedAt') &&
  releaseEvidenceVerify.includes('StartOS registry evidence generatedAt must not be after release generatedAt') &&
  releaseEvidenceVerify.includes('StartOS registry evidence package URL') &&
  releaseEvidenceVerify.includes('StartOS registry evidence release evidence link') &&
  releaseEvidenceVerify.includes('StartOS registry evidence image manifest link') &&
  releaseEvidenceVerify.includes('StartOS registry evidence image smoke link') &&
  releaseEvidenceVerify.includes('StartOS package id') &&
  releaseEvidenceVerify.includes('function isRegistryPackageUrl') &&
  releaseEvidenceVerify.includes('official Umbrel PR head SHA') &&
  releaseEvidenceVerify.includes('official Umbrel PR draft') &&
  releaseEvidenceVerify.includes("requireBoolean('release.prerelease'") &&
  releaseEvidenceVerify.includes('prerelease npm packages') &&
  releaseEvidenceVerify.includes('prerelease StartOS registry URL') &&
  releaseEvidenceVerify.includes('prerelease StartOS package id') &&
  releaseEvidenceVerify.includes('prerelease official Umbrel PR URL') &&
  releaseEvidenceVerify.includes('prerelease official Umbrel PR draft') &&
  releaseEvidenceVerify.includes('prerelease Umbrel community commit') &&
  releaseEvidenceVerify.includes('function isGitHubOwnerName') &&
  releaseEvidenceVerify.includes('function isGitHubHeadRefName') &&
  releaseEvidenceVerify.includes('normal GitHub owner name') &&
  releaseEvidenceVerify.includes('must not be getumbrel') &&
  releaseEvidenceVerify.includes("value.toLowerCase() !== 'getumbrel'") &&
  releaseEvidenceVerify.includes('normal GitHub branch name') &&
  releaseEvidenceVerify.includes('official Umbrel PR head owner matches head owner') &&
  releaseEvidenceVerify.includes('official Umbrel PR head ref matches head branch') &&
  releaseEvidenceVerify.includes('official Umbrel PR head OID matches head SHA') &&
  releaseEvidenceVerify.includes('Umbrel community-store commit URL') &&
  releaseEvidenceVerify.includes('must not expose host') &&
  releaseEvidenceVerify.includes('must not expose sshKey') &&
  releaseEvidenceVerifyTest.includes('rejects stale fleet package versions') &&
  releaseEvidenceVerifyTest.includes('rejects stale fleet relay observation timestamps') &&
  releaseEvidenceVerifyTest.includes('rejects symlinked evidence sidecars') &&
  releaseEvidenceVerifyTest.includes('rejects oversized evidence sidecars before hashing') &&
  releaseEvidenceVerifyTest.includes('rejects placeholder registry hosts') &&
  releaseEvidenceVerifyTest.includes('rejects mismatched registry package URLs') &&
  releaseEvidenceVerifyTest.includes('rejects StartOS registry sidecar hash drift') &&
  releaseEvidenceVerifyTest.includes('honors explicit StartOS registry sidecar paths') &&
  releaseEvidenceVerify.includes('assertReleaseEvidenceSchema') &&
  releaseEvidenceVerifyTest.includes('rejects unsupported release certificate fields') &&
  releaseEvidenceVerify.includes('assertStartosRegistrySidecarSchema') &&
  releaseEvidenceVerify.includes('function requireOnlyKeys') &&
  releaseEvidenceVerify.includes('has unsupported fields') &&
  releaseEvidenceVerifyTest.includes('rejects unsupported StartOS registry sidecar fields') &&
  releaseEvidenceVerifyTest.includes('rejects StartOS registry sidecar package drift') &&
  releaseEvidenceVerifyTest.includes('rejects StartOS registry sidecar image evidence link drift') &&
  releaseEvidenceVerifyTest.includes('rejects future StartOS registry sidecar timestamps') &&
  releaseEvidenceVerifyTest.includes('rejects malformed prerelease boundary facts') &&
  releaseEvidenceVerifyTest.includes('rejects malformed successful workflow identity') &&
  releaseEvidenceVerifyTest.includes('successful release workflow repository must be') &&
  releaseEvidenceVerifyTest.includes('image.name must be') &&
  releaseEvidenceVerifyTest.includes('rejects successful evidence without metadata SHA') &&
  releaseEvidenceVerifyTest.includes('rejects stale official Umbrel PR state facts') &&
  releaseEvidenceVerifyTest.includes('rejects official Umbrel PR head owner and OID drift') &&
  releaseEvidenceVerifyTest.includes('rejects malformed official Umbrel PR GitHub owner names') &&
  releaseEvidenceVerifyTest.includes('GetUmbrel') &&
  releaseEvidenceVerifyTest.includes('rejects malformed official Umbrel PR GitHub head refs') &&
  releaseEvidenceVerifyTest.includes('rejects stale service smoke plugin lists') &&
  releaseEvidenceVerifyTest.includes('rejects stale Umbrel restart service proof') &&
  releaseEvidenceVerify.includes('evidence has duplicate check') &&
  releaseEvidenceVerify.includes('assertSmokeSidecarSchema') &&
  releaseEvidenceVerify.includes('function smokeCheckKeys') &&
  releaseEvidenceVerifyTest.includes('rejects duplicate smoke evidence checks') &&
  releaseEvidenceVerifyTest.includes('rejects unsupported smoke evidence fields') &&
  releaseHandoffEvidenceVerify.includes('evidence has duplicate check') &&
  releaseHandoffEvidenceVerify.includes('assertSmokeSidecarSchema') &&
  releaseHandoffEvidenceVerify.includes('function smokeCheckKeys') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects duplicate smoke evidence checks') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported smoke evidence fields') &&
  releaseHandoffEvidenceVerify.includes('assertUmbrelRuntimeReviewHandoffSchema') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported optional Umbrel runtime review evidence fields') &&
  releaseHandoffEvidenceVerify.includes('assertReleaseEvidenceSchema') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported release certificate fields') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry evidence hash') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects StartOS registry sidecar hash drift') &&
  releaseEvidenceVerify.includes("requireSmokeBoolean(kind, byName, 'dashboardWebSocket', 'inBandAuth')") &&
  releaseEvidenceVerify.includes("requireSmokeValue(kind, byName, 'firstBoot', 'acceptMode', 'review')") &&
  releaseEvidenceVerify.includes("requireSmokeValue(kind, byName, 'firstBoot', 'healthVersion', expectedVersion)") &&
  releaseEvidenceVerify.includes("requireSmokeBoolean(kind, byName, 'walletPersistence', 'destinationPersisted')") &&
  releaseEvidenceVerify.includes("requireSmokeValue(kind, byName, 'health', 'version', expectedVersion)") &&
  releaseEvidenceVerify.includes('function verifySmokeUsageTelemetry') &&
  releaseEvidenceVerify.includes('usageTelemetry bandwidth bandwidthBytes') &&
  releaseEvidenceVerify.includes('usageTelemetry poker enabled') &&
  releaseEvidenceVerify.includes('const imageManifestGeneratedAtMs = verifyImageManifestSidecar') &&
  releaseEvidenceVerify.includes('generatedAt must not be before release image manifest generatedAt') &&
  releaseEvidenceVerifyTest.includes('rejects stale critical smoke proof details') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke health version') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot healthVersion') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke usageTelemetry bandwidth bandwidthBytes') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke usageTelemetry poker enabled') &&
  releaseEvidenceVerifyTest.includes('release-image-smoke generatedAt must not be before release image manifest generatedAt') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke generatedAt must not be before release image manifest generatedAt') &&
  releaseEvidenceVerify.includes("await sha256LargeFile(opts.startosPackageFile, 'StartOS package')") &&
  releaseEvidenceVerify.includes('function sha256FileStream') &&
  releaseEvidenceVerify.includes('fs.createReadStream(file)') &&
  releaseEvidenceVerifyTest.includes('release evidence verifier hashes StartOS package artifacts as a stream') &&
  releaseHandoffEvidenceVerify.includes("requireSmokeBoolean(kind, byName, 'dashboardWebSocket', 'inBandAuth')") &&
  releaseHandoffEvidenceVerify.includes("requireSmokeValue(kind, byName, 'firstBoot', 'acceptMode', 'review')") &&
  releaseHandoffEvidenceVerify.includes("requireSmokeValue(kind, byName, 'firstBoot', 'healthVersion', expectedVersion)") &&
  releaseHandoffEvidenceVerify.includes("requireSmokeBoolean(kind, byName, 'walletPersistence', 'destinationPersisted')") &&
  releaseHandoffEvidenceVerify.includes("requireSmokeValue(kind, byName, 'health', 'version', expectedVersion)") &&
  releaseHandoffEvidenceVerify.includes('function verifySmokeUsageTelemetry') &&
  releaseHandoffEvidenceVerify.includes('usageTelemetry bandwidth bandwidthBytes') &&
  releaseHandoffEvidenceVerify.includes('usageTelemetry poker enabled') &&
  releaseHandoffEvidenceVerify.includes('const imageManifestGeneratedAtMs = verifyImageManifestSidecar') &&
  releaseHandoffEvidenceVerify.includes('generatedAt must not be before release image manifest generatedAt') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale critical smoke proof details') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke health version') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot healthVersion') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke usageTelemetry bandwidth bandwidthBytes') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke usageTelemetry poker enabled') &&
  releaseHandoffEvidenceVerifyTest.includes('release-image-smoke generatedAt must not be before release image manifest generatedAt') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke generatedAt must not be before release image manifest generatedAt') &&
  releaseHandoffEvidenceVerify.includes("await sha256LargeFile(packageFile, 'StartOS package')") &&
  releaseHandoffEvidenceVerify.includes('function sha256FileStream') &&
  releaseHandoffEvidenceVerify.includes('fs.createReadStream(file)') &&
  releaseHandoffEvidenceVerifyTest.includes('release handoff verifier hashes StartOS package artifacts as a stream') &&
  releaseEvidenceVerifyTest.includes('rejects StartOS package path drift') &&
  releaseEvidenceVerifyTest.includes('rejects failed workflow evidence by default') &&
  releaseEvidenceVerifyTest.includes('accepts failed workflow evidence only as an explicit diagnostic') &&
  releaseEvidenceVerifyTest.includes('rejects unsafe diagnostic fleet evidence sidecars') &&
  releaseEvidenceVerifyTest.includes('rejects incomplete fleet evidence for the authoritative inventory') &&
  releaseEvidenceVerifyTest.includes('rejects fleet inventory proof drift') &&
  releaseEvidenceVerifyTest.includes('rejects duplicate fleet relay names') &&
  releaseEvidenceVerifyTest.includes('rejects hyphenated API-key smoke evidence values') &&
  releaseEvidenceVerifyTest.includes('rejects env-style secret smoke evidence values') &&
  releaseEvidenceVerifyTest.includes('rejects env-style secret fleet evidence values') &&
  releaseHandoffEvidenceVerify.includes('official-umbrel-pr-evidence.json') &&
  releaseHandoffEvidenceVerify.includes('startos-registry-evidence.json') &&
  releaseHandoffEvidenceVerify.includes('MAX_EVIDENCE_JSON_BYTES') &&
  releaseHandoffEvidenceVerify.includes('readRegularFile') &&
  releaseHandoffEvidenceVerify.includes('file must not be a symlink') &&
  releaseHandoffEvidenceVerify.includes('file must be a regular file') &&
  releaseHandoffEvidenceVerify.includes('bytes or smaller') &&
  releaseHandoffEvidenceVerify.includes('--release-image-smoke <path>') &&
  releaseHandoffEvidenceVerify.includes('--umbrel-package-smoke <path>') &&
  releaseHandoffEvidenceVerify.includes('--fleet-rollout <path>') &&
  releaseHandoffEvidenceVerify.includes('verifySmokeSidecar') &&
  releaseHandoffEvidenceVerify.includes('verifyFleetRolloutSidecar') &&
  releaseHandoffEvidenceVerify.includes('EXPECTED_SMOKE_SERVICE_PLUGINS') &&
  releaseHandoffEvidenceVerify.includes("EXPECTED_RELEASE_IMAGE_NAME = 'ghcr.io/bigdestiny2/p2p-hiverelay'") &&
  releaseHandoffEvidenceVerify.includes("EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'") &&
  releaseHandoffEvidenceVerify.includes('body.release.workflow.repository, EXPECTED_RELEASE_REPOSITORY') &&
  releaseHandoffEvidenceVerify.includes('body.image.name, EXPECTED_RELEASE_IMAGE_NAME') &&
  releaseHandoffEvidenceVerify.includes('image.ref matches image name, release semver, and digest') &&
  releaseHandoffEvidenceVerify.includes('servicesPersistence active') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout evidence hash') &&
  releaseHandoffEvidenceVerify.includes('ISO_TIMESTAMP_PATTERN') &&
  releaseHandoffEvidenceVerify.includes('requireIsoTimestamp') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout generatedAt') &&
  releaseHandoffEvidenceVerify.includes('observedAt must not be after fleet rollout generatedAt') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout target sha') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout evidence for channel both must include canary and stable relays') &&
  releaseHandoffEvidenceVerify.includes('StartOS handoff package hash') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR image manifest link') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR fleet rollout link') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR StartOS package link') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR StartOS registry package link') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR StartOS registry link') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR number') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR head SHA') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR state') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR draft') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR base') &&
  releaseHandoffEvidenceVerify.includes('verifyOfficialUmbrelPrSidecarShape') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR handoff number matches URL') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR handoff head owner matches head owner') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR handoff head ref matches head branch') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR handoff generatedAt must not be before release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('function isGitHubOwnerName') &&
  releaseHandoffEvidenceVerify.includes('function isGitHubHeadRefName') &&
  releaseHandoffEvidenceVerify.includes('normal GitHub owner name') &&
  releaseHandoffEvidenceVerify.includes('must not be getumbrel') &&
  releaseHandoffEvidenceVerify.includes("value.toLowerCase() !== 'getumbrel'") &&
  releaseHandoffEvidenceVerify.includes('normal GitHub branch name') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR head owner matches head owner') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR head ref matches head branch') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR head OID matches head SHA') &&
  releaseHandoffEvidenceVerify.includes('release.metadataSha') &&
  releaseHandoffEvidenceVerify.includes('release workflow run attempt') &&
  releaseHandoffEvidenceVerify.includes('POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/') &&
  releaseHandoffEvidenceVerify.includes('GITHUB_ACTIONS_RUN_URL_PATTERN') &&
  releaseHandoffEvidenceVerify.includes('OFFICIAL_UMBREL_PR_URL_PATTERN') &&
  releaseHandoffEvidenceVerify.includes('release workflow canonical URL') &&
  releaseHandoffEvidenceVerify.includes('npm packages') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR workflow run attempt') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry workflow run attempt') &&
  releaseHandoffEvidenceVerify.includes('verifyStartosRegistrySidecarShape') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff generatedAt must not be after release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff package SHA-256') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff URL') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff package URL') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff workflow URL') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff image manifest link') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff image smoke link') &&
  releaseHandoffEvidenceVerify.includes('StartOS registry handoff package link') &&
  releaseHandoffEvidenceVerify.includes('StartOS handoff package URL') &&
  releaseHandoffEvidenceVerify.includes('function isRegistryPackageUrl') &&
  releaseHandoffEvidenceVerify.includes('prNumberFromUrl(release.surfaces.umbrelOfficial.prUrl)') &&
  releaseHandoffEvidenceVerify.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  releaseHandoffEvidenceVerify.includes('APP_SEED') &&
  releaseHandoffEvidenceVerify.includes('HIVERELAY_API_KEY') &&
  releaseHandoffEvidenceVerify.includes('sk-[A-Za-z0-9_-]') &&
  releaseHandoffEvidenceVerify.includes("assertPublicSafe(body, 'release evidence')") &&
  releaseHandoffEvidenceVerify.includes('hasControlChars') &&
  releaseHandoffEvidenceVerify.includes('must not contain control characters') &&
  releaseHandoffEvidenceVerify.includes('without embedded credentials') &&
  releaseHandoffEvidenceVerify.includes('reserved/local hostnames') &&
  releaseHandoffEvidenceVerify.includes('function isPublicHostname') &&
  releaseHandoffEvidenceVerify.includes('!url.search') &&
  releaseHandoffEvidenceVerify.includes('!url.hash') &&
  releaseHandoffEvidenceVerify.includes('must not expose URL credentials') &&
  releaseHandoffEvidenceVerify.includes('verifyPrereleaseSkips') &&
  releaseHandoffEvidenceVerify.includes("forbidPresent('fleet rollout handoff evidence'") &&
  releaseHandoffEvidenceVerify.includes('prerelease release channel') &&
  releaseHandoffEvidenceVerify.includes("requireBoolean('release.prerelease'") &&
  releaseHandoffEvidenceVerify.includes('prerelease npm packages') &&
  releaseHandoffEvidenceVerify.includes('prerelease StartOS registry URL') &&
  releaseHandoffEvidenceVerify.includes('prerelease StartOS package id') &&
  releaseHandoffEvidenceVerify.includes('prerelease StartOS registry evidence path') &&
  releaseHandoffEvidenceVerify.includes('prerelease official Umbrel PR URL') &&
  releaseHandoffEvidenceVerify.includes('prerelease official Umbrel PR draft') &&
  releaseHandoffEvidenceVerify.includes('prerelease Umbrel community commit') &&
  releaseHandoffEvidenceVerify.includes('Prerelease bundle must not include') &&
  releaseAutomationDocs.includes('npm run release:verify-evidence --') &&
  releaseAutomationDocs.includes('npm run release:verify-handoff-evidence --') &&
  releaseAutomationDocs.includes('the first\n`release:verify-evidence` pass checks the sidecar hash') &&
  releaseAutomationDocs.includes('the prerelease flag to be a real boolean') &&
  releaseAutomationDocs.includes('reject prerelease certificates that') &&
  releaseAutomationDocs.includes('official Umbrel PR, community-store, StartOS registry') &&
  releaseAutomationDocs.includes('not `getumbrel`') &&
  releaseAutomationDocs.includes('--bundle-dir .') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel workflow attempt drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects symlinked evidence sidecars') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects oversized evidence sidecars before parsing') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel PR handoff URL number mismatch') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel PR state drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale official Umbrel PR handoff timestamps') &&
  releaseHandoffEvidenceVerify.includes('assertOfficialUmbrelPrSidecarSchema') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported official Umbrel PR handoff fields') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel image manifest link drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel release evidence head-ref drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel PR head owner and OID drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed official Umbrel PR GitHub owner names') &&
  releaseHandoffEvidenceVerifyTest.includes('GetUmbrel') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed official Umbrel PR GitHub head refs') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed official Umbrel PR handoff owner names') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed official Umbrel PR handoff head refs') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale Umbrel smoke restart proof') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed release workflow attempt even when sidecars agree') &&
  releaseHandoffEvidenceVerifyTest.includes('release workflow repository must be') &&
  releaseHandoffEvidenceVerifyTest.includes('image.name must be') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects missing fleet rollout evidence') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale fleet rollout evidence') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale fleet relay observation timestamps') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects non-canonical release workflow URL even when sidecars agree') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects release evidence without metadata SHA') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects promoted prerelease bundles') &&
  releaseEvidenceVerifyTest.includes('prerelease npm packages') &&
  releaseHandoffEvidenceVerifyTest.includes('prerelease npm packages') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed prerelease boundary facts') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects StartOS registry workflow attempt drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects future StartOS registry handoff timestamps') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects malformed StartOS registry handoff package facts') &&
  releaseHandoffEvidenceVerify.includes('assertStartosRegistrySidecarSchema') &&
  releaseHandoffEvidenceVerify.includes('function requireOnlyKeys') &&
  releaseHandoffEvidenceVerify.includes('has unsupported fields') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported StartOS registry handoff fields') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects mismatched StartOS registry package URLs') &&
  releaseHandoffEvidenceVerifyTest.includes('image manifest link') &&
  releaseHandoffEvidenceVerifyTest.includes('image smoke link') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel registry package link drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsafe StartOS registry handoff URLs') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects inconsistent StartOS registry handoff links') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects placeholder registry hosts') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects hyphenated API-key handoff evidence values') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects env-style secret smoke sidecar values') &&
  releaseWorkflow.includes('Initialize release evidence') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_GATE_STATUS=passed') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_STATUS=passed') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE=release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE_SHA256=$image_smoke_sha') &&
  releaseWorkflow.includes('Release image smoke evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_SMOKE_STATUS=passed') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_SMOKE_EVIDENCE=umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_SMOKE_EVIDENCE_SHA256=$umbrel_smoke_sha') &&
  releaseWorkflow.includes('Umbrel package smoke evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('HIVERELAY_STARTOS_PACKAGE_SHA256=') &&
  releaseWorkflow.includes('HIVERELAY_STARTOS_PACKAGE_ID=') &&
  releaseWorkflow.includes('HIVERELAY_NPM_PUBLISH_STATUS=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATE=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_BASE=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF=') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID=') &&
  releaseWorkflow.includes("sed -n 's/^id:[[:space:]]*//p' manifest.yaml") &&
  releaseWorkflow.includes('sha256sum blindspark.s9pk') &&
  releaseWorkflow.includes('HIVERELAY_STARTOS_VERIFY_STATUS=passed') &&
  releaseWorkflow.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=verified') &&
  releaseWorkflow.includes('HIVERELAY_FLEET_ROLLOUT_CHANNEL=' + githubChannelExpression) &&
  releaseWorkflow.includes('HIVERELAY_FLEET_ROLLOUT_EVIDENCE_SHA256=') &&
  releaseWorkflow.includes('--evidence fleet-rollout-evidence.json') &&
  releaseWorkflow.includes('sha256sum fleet-rollout-evidence.json') &&
  releaseWorkflow.includes('Fleet rollout evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_STATUS=published') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_URL="$STARTOS_REGISTRY_URL"') &&
  releaseWorkflow.includes('export HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL="$registry_package_url"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_STATUS published') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_URL "$STARTOS_REGISTRY_URL"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL "$registry_package_url"') &&
  releaseWorkflow.includes('pr_state="$(gh pr view "$pr_url" --json state --jq \'.state\')"') &&
  releaseWorkflow.includes('pr_is_draft="$(gh pr view "$pr_url" --json isDraft --jq \'.isDraft\')"') &&
  releaseWorkflow.includes('pr_base="$(gh pr view "$pr_url" --json baseRefName --jq \'.baseRefName\')"') &&
  releaseWorkflow.includes('pr_head_owner="$(gh pr view "$pr_url" --json headRepositoryOwner --jq \'.headRepositoryOwner.login\')"') &&
  releaseWorkflow.includes('pr_head_ref="$(gh pr view "$pr_url" --json headRefName --jq \'.headRefName\')"') &&
  releaseWorkflow.includes('pr_head_oid="$(gh pr view "$pr_url" --json headRefOid --jq \'.headRefOid\')"') &&
  releaseWorkflow.includes('Official Umbrel PR head owner must be $fork_owner') &&
  releaseWorkflow.includes('Official Umbrel PR head OID must match pushed branch SHA') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_URL "$pr_url"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD "$fork_owner:$branch"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA "$official_head_sha"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_STATE "$pr_state"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT "$pr_is_draft"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_BASE "$pr_base"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER "$pr_head_owner"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF "$pr_head_ref"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID "$pr_head_oid"') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT=$community_sha') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_COMMIT_URL=https://github.com/bigdestiny2/blindspark-umbrel-store/commit/$community_sha') &&
  releaseWorkflow.includes('Umbrel community-store commit SHA is malformed.') &&
  releaseWorkflow.includes('Write release evidence') &&
  releaseWorkflow.includes('Verify release evidence') &&
  releaseWorkflow.includes('npm run release:verify-evidence --') &&
  releaseWorkflow.includes('--startos-package startos/blindspark.s9pk') &&
  releaseWorkflow.includes('--release-image-smoke release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('--umbrel-package-smoke umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.includes('--fleet-rollout fleet-rollout-evidence.json') &&
  releaseWorkflow.includes('--startos-registry startos-registry-evidence.json') &&
  releaseWorkflow.indexOf('Verify release evidence') > releaseWorkflow.indexOf('Write release evidence') &&
  releaseWorkflow.indexOf('Verify release evidence') < releaseWorkflow.indexOf('Upload release evidence artifact') &&
  releaseWorkflow.includes("always() && !cancelled() && hashFiles('hiverelay/scripts/write-release-evidence.mjs') != ''") &&
  releaseWorkflow.includes("always() && !cancelled() && hashFiles('hiverelay/release-evidence.json') != ''") &&
  releaseWorkflow.includes('actions/upload-artifact@v7') &&
  releaseWorkflow.includes('release-evidence.json') &&
  releaseWorkflow.includes('release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.includes('fleet-rollout-evidence.json') &&
  releaseWorkflow.includes('startos-registry-evidence.json') &&
  releaseWorkflow.includes('evidence=(release-evidence.json)') &&
  releaseWorkflow.includes('evidence+=(release-image-smoke-evidence.json)') &&
  releaseWorkflow.includes('evidence+=(umbrel-package-smoke-evidence.json)') &&
  releaseWorkflow.includes('if [ -f fleet-rollout-evidence.json ]; then') &&
  releaseWorkflow.includes('if [ -f startos-registry-evidence.json ]; then') &&
  releaseWorkflow.includes('evidence+=(startos-registry-evidence.json)') &&
  releaseWorkflow.includes('gh release upload "' + githubVersionExpression + '" "' + shellEvidenceArrayExpression + '" --clobber') &&
  releaseWorkflow.includes('Verify published release evidence assets') &&
  releaseWorkflow.includes('bundle_dir="$(mktemp -d)"') &&
  releaseWorkflow.includes('gh release download "' + githubVersionExpression + '"') &&
  releaseWorkflow.includes("--pattern 'release-evidence.json'") &&
  releaseWorkflow.includes("--pattern 'release-image-smoke-evidence.json'") &&
  releaseWorkflow.includes("--pattern 'umbrel-package-smoke-evidence.json'") &&
  releaseWorkflow.includes("--pattern 'blindspark.s9pk'") &&
  releaseWorkflow.includes("--pattern 'fleet-rollout-evidence.json'") &&
  releaseWorkflow.includes("--pattern 'startos-registry-evidence.json'") &&
  releaseWorkflow.includes('npm run release:verify-evidence -- --bundle-dir "$bundle_dir"') &&
  releaseWorkflow.indexOf('Verify published release evidence assets') > releaseWorkflow.indexOf('Upload release evidence to GitHub Release') &&
  releaseWorkflow.includes('Verify published handoff evidence assets') &&
  releaseWorkflow.includes('handoff_dir="$(mktemp -d)"') &&
  releaseWorkflow.indexOf("--pattern 'release-image-smoke-evidence.json'", releaseWorkflow.indexOf('handoff_dir="$(mktemp -d)"')) !== -1 &&
  releaseWorkflow.indexOf("--pattern 'umbrel-package-smoke-evidence.json'", releaseWorkflow.indexOf('handoff_dir="$(mktemp -d)"')) !== -1 &&
  releaseWorkflow.indexOf("--pattern 'fleet-rollout-evidence.json'", releaseWorkflow.indexOf('handoff_dir="$(mktemp -d)"')) !== -1 &&
  releaseWorkflow.includes("--pattern 'official-umbrel-pr-evidence.json'") &&
  releaseWorkflow.includes("--pattern 'startos-registry-evidence.json'") &&
  releaseWorkflow.includes('npm run release:verify-handoff-evidence -- --bundle-dir "$handoff_dir"') &&
  releaseWorkflow.indexOf('Verify published handoff evidence assets') > releaseWorkflow.indexOf('Upload official Umbrel PR evidence')
) {
  pass('release workflow emits and validates durable release evidence for image, npm, fleet, Umbrel, and StartOS surfaces')
} else {
  fail('release workflow is missing validated durable release evidence output')
}

const deprecatedNode20ActionRefs = [
  'actions/checkout@v4',
  'actions/setup-node@v4',
  'actions/upload-artifact@v4',
  'actions/upload-artifact@v5',
  'docker/setup-qemu-action@v3',
  'docker/setup-buildx-action@v3',
  'docker/login-action@v3',
  'docker/metadata-action@v5',
  'docker/build-push-action@v5'
]

if (
  deprecatedNode20ActionRefs.every(ref => !workflowTexts.includes(ref)) &&
  workflowTexts.includes('actions/checkout@v7') &&
  workflowTexts.includes('actions/setup-node@v6') &&
  workflowTexts.includes('actions/upload-artifact@v7') &&
  dockerPublishWorkflow.includes('docker/setup-qemu-action@v4') &&
  workflowTexts.includes('docker/setup-buildx-action@v4') &&
  workflowTexts.includes('docker/login-action@v4') &&
  dockerPublishWorkflow.includes('docker/metadata-action@v6') &&
  dockerPublishWorkflow.includes('docker/build-push-action@v7')
) {
  pass('GitHub workflows use Node 24-compatible action wrappers')
} else {
  fail('GitHub workflows still reference deprecated Node 20 action wrappers')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['umbrel:smoke-package'] === 'node scripts/smoke-umbrel-package.mjs' &&
  fs.existsSync(path.join(hiverelayRoot, 'scripts', 'smoke-umbrel-package.mjs')) &&
  releaseWorkflow.includes('Smoke Umbrel package') &&
  releaseWorkflow.includes('npm run umbrel:smoke-package --') &&
  releaseWorkflow.includes('--image-ref "$IMAGE_NAME:' + githubSemverExpression + '@$HIVERELAY_IMAGE_DIGEST"') &&
  releaseWorkflow.includes('--evidence umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.includes('sha256sum umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.indexOf('Smoke Umbrel package') > releaseWorkflow.indexOf('Sync release metadata') &&
  releaseWorkflow.indexOf('Smoke Umbrel package') < releaseWorkflow.indexOf('Install StartOS packaging tools') &&
  umbrelSmokePackage.includes('--evidence <path>') &&
  umbrelSmokePackage.includes('parseTimeoutMs') &&
  umbrelSmokePackage.includes('MAX_SMOKE_TIMEOUT_MS = 30 * 60 * 1000') &&
  umbrelSmokePackage.includes('MAX_EVIDENCE_JSON_BYTES') &&
  umbrelSmokePackage.includes('Number.isSafeInteger(parsed)') &&
  umbrelSmokePackage.includes('redactSensitiveOutput') &&
  umbrelSmokePackage.includes('writeRedactedOutput') &&
  umbrelSmokePackage.includes('formatCommand(cmd, argv)') &&
  umbrelSmokePackage.includes('DIGEST_PINNED_IMAGE_REF_PATTERN') &&
  umbrelSmokePackage.includes("REQUIRED_IMAGE_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])") &&
  umbrelSmokePackage.includes('parseDigestPinnedImageRef') &&
  umbrelSmokePackage.includes('imageName') &&
  umbrelSmokePackage.includes('imageTag') &&
  umbrelSmokePackage.includes('imageDigest') &&
  umbrelSmokePackage.includes('isDigestPinnedImageRef') &&
  umbrelSmokePackage.includes('requires a GHCR semver tag plus sha256 digest image ref') &&
  umbrelSmokePackage.includes('requireImageManifestEvidence') &&
  umbrelSmokePackage.includes('release image manifest evidence file is required before writing smoke evidence') &&
  umbrelSmokePackage.includes('release image manifest evidence file must not be a symlink') &&
  umbrelSmokePackage.includes('release image manifest evidence file must be a regular file') &&
  umbrelSmokePackage.includes('release image manifest evidence file must be') &&
  umbrelSmokePackage.includes('readImageManifestEvidence') &&
  umbrelSmokePackage.includes('release image manifest image ref must match smoke image ref') &&
  umbrelSmokePackage.includes('release image manifest image digest must match smoke image digest') &&
  umbrelSmokePackage.includes('assertManifestPlatforms') &&
  umbrelSmokePackage.includes('release image manifest evidence is missing required platform') &&
  umbrelSmokePackage.includes('writeSmokeEvidence') &&
  umbrelSmokePackage.includes("kind: 'umbrel-package-smoke'") &&
  umbrelSmokePackage.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  umbrelSmokePackage.includes('APP_SEED') &&
  umbrelSmokePackage.includes('HIVERELAY_API_KEY') &&
  umbrelSmokePackage.includes('FORBIDDEN_PUBLIC_SMOKE_KEYS') &&
  umbrelSmokePackage.includes('assertPublicSafeSmoke') &&
  umbrelSmokePackage.includes('hasControlChars') &&
  umbrelSmokePackage.includes('must not contain control characters') &&
  umbrelSmokePackage.includes('must not expose URL credentials') &&
  umbrelSmokePackage.includes('/api/usage') &&
  umbrelSmokePackage.includes('/api/poker/usage') &&
  umbrelSmokePackage.includes('assertDashboardWebSocket') &&
  umbrelSmokePackage.includes('queryTokenRejected') &&
  umbrelSmokePackage.includes('assertDashboardUiHardening') &&
  umbrelSmokePackage.includes('assertSetupWizardUiHardening') &&
  umbrelSmokePackage.includes('dashboardUiHardening') &&
  umbrelSmokePackage.includes('setupUiHardening') &&
  umbrelSmokePackage.includes('appProxyWrites') &&
  umbrelSmokePackage.includes('leasePollingBounded') &&
  umbrelSmokePackage.includes('dashboardStaticMarkupSafe') &&
  umbrelSmokePackage.includes('dashboardLinkAppPath') &&
  umbrelSmokePackage.includes('setupStaticMarkupSafe') &&
  umbrelSmokePackage.includes("recordCheck('dashboardWebSocket'") &&
  umbrelSmokePackage.includes("recordCheck('usageTelemetry'") &&
  umbrelSmokePackage.includes('HIVERELAY_ACCEPT_MODE=review') &&
  umbrelSmokePackage.includes('HIVERELAY_MAX_STORAGE=10GB') &&
  umbrelSmokePackage.includes('home-server storage cap env') &&
  umbrelSmokePackage.includes("recordCheck('acceptModeDefault'") &&
  umbrelSmokePackage.includes('assertAcceptModeDefault') &&
  umbrelSmokePackage.includes('/api/subsidy/destination') &&
  umbrelSmokePackage.includes('/api/manage/services/config') &&
  umbrelSmokePackage.includes("plugins: ['poker', 'ai']") &&
  umbrelSmokePackage.includes("EXPECTED_POKER_AI_PLUGINS = Object.freeze(['poker', 'vrf', 'arbitration', 'zk', 'ai'])") &&
  umbrelSmokePackage.includes('assertPluginList(out?.plugins, EXPECTED_POKER_AI_PLUGINS') &&
  umbrelSmokePackage.includes('recordCheck(\'servicesPersistence\', { selectedServicesActive: true, ...servicePersistence })') &&
  umbrelSmokePackage.includes('assertServices(second.baseUrl, second.token)') &&
  releaseEvidenceVerify.includes('release generatedAt') &&
  releaseEvidenceVerify.includes('`$' + '{kind} generatedAt`') &&
  releaseEvidenceVerify.includes('generatedAt must not be after release generatedAt') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageName`') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageTag`') &&
  releaseEvidenceVerify.includes('`$' + '{kind} imageDigest`') &&
  releaseEvidenceVerify.includes('dashboardUiHardening') &&
  releaseEvidenceVerify.includes('setupUiHardening') &&
  releaseEvidenceVerify.includes('dashboardStaticMarkupSafe') &&
  releaseEvidenceVerify.includes('setupStaticMarkupSafe') &&
  releaseHandoffEvidenceVerify.includes('release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} generatedAt`') &&
  releaseHandoffEvidenceVerify.includes('generatedAt must not be after release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageName`') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageTag`') &&
  releaseHandoffEvidenceVerify.includes('`$' + '{kind} imageDigest`') &&
  releaseHandoffEvidenceVerify.includes('dashboardUiHardening') &&
  releaseHandoffEvidenceVerify.includes('setupUiHardening') &&
  releaseHandoffEvidenceVerify.includes('dashboardStaticMarkupSafe') &&
  releaseHandoffEvidenceVerify.includes('setupStaticMarkupSafe') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects smoke image provenance drift') &&
  releaseEvidenceVerifyTest.includes('rejects stale smoke evidence timestamps') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke firstBoot dashboardUiHardening') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke firstBoot appProxyWrites') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot setupUiHardening') &&
  releaseEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot setupStaticMarkupSafe') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke firstBoot dashboardUiHardening') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke firstBoot appProxyWrites') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot setupUiHardening') &&
  releaseHandoffEvidenceVerifyTest.includes('umbrel-package-smoke secondBoot setupStaticMarkupSafe') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects stale smoke evidence timestamps')
) {
  pass('release workflow boots the synchronized Umbrel package and checks setup/wallet/services persistence before StartOS packaging')
} else {
  fail('release workflow is missing the Umbrel package lifecycle smoke gate after metadata sync')
}

if (
  monorepoPkg.scripts &&
  monorepoPkg.scripts['fleet:check-rollout'] === 'node scripts/check-fleet-rollout.mjs' &&
  fleetRolloutCheck.includes('Fleet rollout verified') &&
  fleetRolloutCheck.includes('sshCommand') &&
  fleetRolloutCheck.includes('HIVERELAY_FLEET_SSH_COMMAND') &&
  fleetRolloutCheck.includes('git') &&
  fleetRolloutCheck.includes('/health') &&
  fleetRolloutCheck.includes('--evidence <path>') &&
  fleetRolloutCheck.includes('writeRolloutEvidence') &&
  fleetRolloutCheck.includes('schemaVersion: 1') &&
  fleetRolloutCheck.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  fleetRolloutCheck.includes('APP_SEED') &&
  fleetRolloutCheck.includes('HIVERELAY_API_KEY') &&
  fleetRolloutCheck.includes('assertPublicSafeValues') &&
  fleetRolloutCheck.includes('redactSensitiveOutput') &&
  fleetRolloutCheck.includes('[redacted APP_SEED]') &&
  fleetRolloutCheck.includes('[redacted HIVERELAY_API_KEY]') &&
  fleetRolloutCheckTest.includes('redacts secret-looking probe errors') &&
  fleetRolloutCheck.includes('hasControlChars') &&
  fleetRolloutCheck.includes('fleet rollout API URL') &&
  fleetRolloutCheck.includes('must not contain control characters') &&
  fleetRolloutCheck.includes('must not expose URL credentials') &&
  fleetRolloutCheck.includes('without query strings or fragments') &&
  fleetRolloutCheck.includes('normalizeApiBase') &&
  fleetRolloutCheck.includes('validateSshHost') &&
  fleetRolloutCheck.includes('validateSshUser') &&
  fleetRolloutCheck.includes('shellQuote') &&
  fleetRolloutCheck.includes('cd -- "$repo"') &&
  fleetRolloutCheck.includes('sshArgs.push(') &&
  fleetRolloutCheck.includes("'bash', '-s')") &&
  !fleetRolloutCheck.includes('remoteRepoDir, service, api)') &&
  fleetRolloutCheck.includes('summary') &&
  fleetRolloutCheck.includes('inventorySha256') &&
  fleetRolloutCheck.includes('pathForEvidence') &&
  fleetRolloutCheck.includes('channelsEvidencePath') &&
  fleetRolloutCheck.includes('relayNames: relays.map((relay) => relay.name)') &&
  fleetRolloutCheck.includes('Duplicate relay name') &&
  fleetRolloutCheck.includes('Relay names must be unique before rollout evidence is written') &&
  fleetRolloutCheck.includes('--channels <path>') &&
  fleetRolloutCheck.includes('readChannels') &&
  fleetRolloutCheck.includes('readFleetMetadataFile') &&
  fleetRolloutCheck.includes('MAX_FLEET_METADATA_BYTES') &&
  fleetRolloutCheck.includes('file must not be a symlink') &&
  fleetRolloutCheck.includes('file must be a regular file') &&
  fleetRolloutCheck.includes('bytes or smaller') &&
  fleetRolloutCheck.includes('validateChannelTargets') &&
  fleetRolloutCheck.includes('channelConfig') &&
  fleetRolloutCheck.includes('fleet/channels.json') &&
  fleetRolloutCheck.includes('targetSha') &&
  fleetRolloutCheck.includes('targetVersion') &&
  fleetRolloutCheck.includes('observedAt') &&
  fleetRolloutCheck.includes('assertFleetRolloutEvidenceSchema') &&
  fleetRolloutCheck.includes('assertVerifiedProbeTiming(status)') &&
  fleetRolloutCheck.includes('verified fleet rollout timeoutMs') &&
  fleetRolloutCheck.includes('if (!/^[1-9][0-9]*$/.test(raw))') &&
  fleetRolloutCheck.includes('Expected a positive integer without whitespace or control characters') &&
  !fleetRolloutCheck.includes('Math.floor(n)') &&
  fleetRolloutCheck.includes("requireOnlyKeys('fleet rollout evidence'") &&
  fleetRolloutCheck.includes('has unsupported fields') &&
  fleetRolloutCheck.includes('health_version=') &&
  fleetRolloutCheck.includes('packageVersionMatches') &&
  fleetRolloutCheck.includes('waiting-package-version') &&
  fleetRolloutCheck.includes('runtimeVersionMatches') &&
  fleetRolloutCheckTest.includes('relay observation time is recorded') &&
  fleetRolloutCheckTest.includes('rejects stale channel targets before probing') &&
  fleetRolloutCheckTest.includes('rejects duplicate selected relay names before writing evidence') &&
  fleetRolloutCheckTest.includes('rejects unsafe fleet metadata files before writing evidence') &&
  fleetRolloutCheckTest.includes('evidence.channelConfig.sha256') &&
  fleetRolloutCheckTest.includes('rejects updated repo with stale package version') &&
  fleetRolloutCheckTest.includes('evidence.inventory.sha256') &&
  fleetRolloutCheckTest.includes('rejects query-string API bases before writing evidence') &&
  fleetRolloutCheckTest.includes('rejects non-http API URLs before writing evidence') &&
  fleetRolloutCheckTest.includes('rejects SSH option-like relay hosts before probing') &&
  fleetRolloutCheckTest.includes('keeps probe config out of SSH command argv') &&
  fleetRolloutCheckTest.includes('fleet rollout evidence writer keeps a closed public schema') &&
  fleetRolloutCheckTest.includes('rejects unsafe verified proof timing before writing evidence') &&
  fleetRolloutCheckTest.includes('rejects malformed timing integers before probing') &&
  fleetRolloutCheckTest.includes('HIVERELAY_ATTACKER_VALUE=owned') &&
  relayApi.includes('version: this._relayVersion()') &&
  releaseWorkflow.includes('FLEET_SSH_PRIVATE_KEY:') &&
  releaseWorkflow.includes('Configure fleet rollout SSH key') &&
  releaseWorkflow.includes('Verify raw fleet rollout') &&
  releaseWorkflow.includes('Verify stable release distribution credentials') &&
  releaseWorkflow.includes('npm run fleet:check-rollout --') &&
  releaseWorkflow.includes('--channel "' + githubChannelExpression + '"') &&
  releaseWorkflow.indexOf('Verify raw fleet rollout') > releaseWorkflow.indexOf('Commit HiveRelay release surfaces') &&
  releaseEvidenceVerify.includes('expectedFleetRollout') &&
  releaseEvidenceVerify.includes('fleet rollout inventory SHA-256') &&
  releaseEvidenceVerify.includes('fleet rollout relay names') &&
  releaseEvidenceVerify.includes('fleet channel config path') &&
  releaseEvidenceVerify.includes('fleet rollout channel config SHA-256') &&
  releaseEvidenceVerify.includes('verifyFleetChannelTargets') &&
  releaseEvidenceVerify.includes('verifyFleetRolloutProbeConfig') &&
  releaseEvidenceVerify.includes('assertFleetRolloutSidecarSchema') &&
  releaseEvidenceVerify.includes('fleet rollout timeoutMs') &&
  releaseEvidenceVerify.includes('FLEET_ROLLOUT_TIMEOUT_MIN_MS') &&
  releaseEvidenceVerify.includes('fleet rollout summary packageVersionMatches') &&
  releaseEvidenceVerify.includes('packageVersionMatches`, relay.packageVersionMatches') &&
  releaseHandoffEvidenceVerify.includes('expectedFleetRollout') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout inventory relay names') &&
  releaseHandoffEvidenceVerify.includes('fleet channel config path') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout channel config SHA-256') &&
  releaseHandoffEvidenceVerify.includes('verifyFleetChannelTargets') &&
  releaseHandoffEvidenceVerify.includes('verifyFleetRolloutProbeConfig') &&
  releaseHandoffEvidenceVerify.includes('assertFleetRolloutSidecarSchema') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout timeoutMs') &&
  releaseHandoffEvidenceVerify.includes('FLEET_ROLLOUT_TIMEOUT_MIN_MS') &&
  releaseHandoffEvidenceVerify.includes('fleet rollout summary packageVersionMatches') &&
  releaseHandoffEvidenceVerify.includes('packageVersionMatches`, relay.packageVersionMatches') &&
  releaseEvidenceVerifyTest.includes('rejects fleet inventory proof drift') &&
  releaseEvidenceVerifyTest.includes('rejects fleet channel config proof drift') &&
  releaseEvidenceVerifyTest.includes('rejects incomplete fleet package-version convergence proof') &&
  releaseEvidenceVerifyTest.includes('rejects unsafe fleet rollout probe timing') &&
  releaseEvidenceVerifyTest.includes('rejects unsupported fleet rollout sidecar fields') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects fleet inventory proof drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects fleet channel config proof drift') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects incomplete fleet package-version convergence proof') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsafe fleet rollout probe timing') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects unsupported fleet rollout sidecar fields') &&
  releaseAutomationDocs.includes('fleet/relays.json` inventory digest') &&
  releaseAutomationDocs.includes('channelConfig') &&
  releaseAutomationDocs.includes('stale channel pointer') &&
  releaseAutomationDocs.includes('per-relay package-version/runtime convergence') &&
  releaseAutomationDocs.includes('refuses to mint a `verified` sidecar') &&
  releaseAutomationDocs.includes('plain positive decimal integers') &&
  auditDoc.includes('Hardened live-fleet rollout evidence') &&
  auditDoc.includes('Hardened raw fleet rollout convergence proof') &&
  auditDoc.includes('Hardened fleet rollout probe timing proof') &&
  auditDoc.includes('Hardened raw fleet channel-target proof') &&
  auditRoadmap.includes('Fleet rollout writer timing proof') &&
  auditRoadmap.includes('Fleet rollout exact timing parser')
) {
  pass('release workflow verifies raw fleet rollout after stable-release channel promotion with authoritative fleet inventory, channel-config, and package-version proof')
} else {
  fail('release workflow is missing required stable-release raw fleet rollout verification or authoritative inventory/channel-config/package-version proof after channel promotion')
}

if (
  releaseWorkflow.includes('Validate Umbrel community store') &&
  releaseWorkflow.includes('working-directory: blindspark-umbrel-store') &&
  releaseWorkflow.includes('npm run validate')
) {
  pass('release workflow validates the Umbrel community store before push')
} else {
  fail('release workflow is missing the Umbrel community-store validation step')
}

if (
  fleetStatusScript.includes('CHANNEL="$channel" python3 -c') &&
  fleetStatusScript.includes('os.environ["CHANNEL"]') &&
  !fleetStatusScript.includes(".get('$channel'")
) {
  pass('fleet status tooling treats channel names as JSON data, not Python source')
} else {
  fail('fleet status tooling can interpolate channel names into Python source')
}

const updaterExpectedVersionArg = 'expected_version="' + '$' + '{1:-}"'
const updaterTargetHealthGate = 'if healthy "' + '$' + '{TARGET#v}"; then'
const updaterRollbackHealthGate = 'if healthy "' + '$' + '{CUR_VER#v}"; then'
if (
  fleetUpdaterScript.includes('rollback_to_previous') &&
  fleetUpdaterScript.includes('deps_if_changed "$CUR_SHA" "$TARGET_SHA" || rollback_to_previous') &&
  fleetUpdaterScript.includes('if ! git checkout --quiet "$CUR_SHA"; then') &&
  fleetUpdaterScript.includes('if ! deps_if_changed "$TARGET_SHA" "$CUR_SHA"; then') &&
  fleetUpdaterScript.includes(updaterExpectedVersionArg) &&
  fleetUpdaterScript.includes(updaterTargetHealthGate) &&
  fleetUpdaterScript.includes(updaterRollbackHealthGate) &&
  fleetShellSafetyTest.includes('fleet updater health-gates target and rollback runtime versions')
) {
  pass('fleet updater rolls back dependency-install failures, stops on failed rollback checkout, and verifies runtime versions')
} else {
  fail('fleet updater can exit before rollback, continue after failed rollback checkout, or accept a stale runtime version')
}

if (
  cliIndex.includes('const interactiveStatus = process.stdout.isTTY === true') &&
  cliIndex.includes('const statusIntervalMs = interactiveStatus ? 5000 : 60000') &&
  cliIndex.includes("log.info(status, 'relay status')") &&
  cliIndex.includes('function statusSnapshot (node)') &&
  fleetShellSafetyTest.includes('relay CLI keeps high-frequency status output off service logs')
) {
  pass('relay CLI TTY-gates the high-frequency status bar and emits low-rate structured service logs')
} else {
  fail('relay CLI can write the 5s carriage-return status bar into service logs')
}

if (
  deployVpsScript.includes('validate_api_key "$EFFECTIVE_KEY"') &&
  deployVpsScript.includes("API_KEY_B64='" + '$' + "{API_KEY_B64}'") &&
  deployVpsScript.includes('base64 -d') &&
  deployVpsScript.includes('EnvironmentFile=/etc/hiverelay/hiverelay.env') &&
  deployVpsScript.includes('chmod 0600 /etc/hiverelay/hiverelay.env') &&
  !deployVpsScript.includes('Environment=HIVERELAY_API_KEY=API_KEY_PLACEHOLDER') &&
  !deployVpsScript.includes('sed -i "s/API_KEY_PLACEHOLDER') &&
  deployVpsScript.includes('MEMORY_HIGH="$(memory_high_limit "$MAX_MEM")"') &&
  deployVpsScript.includes('NUM * 1024 * 80 / 100') &&
  !deployVpsScript.includes('MEM_HIGH=$(( MEM_NUM * 80 / 100 ))')
) {
  pass('legacy VPS deploy script keeps API keys out of world-readable units and computes gigabyte MemoryHigh correctly')
} else {
  fail('legacy VPS deploy script can leak API keys through systemd units or miscompute gigabyte MemoryHigh')
}

if (
  [fleetUpdaterScript, fleetStatusScript, fleetRolloutCheck, relayJanitorScript].every(source =>
    source.includes('/etc/hiverelay/hiverelay.env') &&
    source.includes('awk -F=') &&
    !source.includes("grep -o 'HIVERELAY_API_KEY=[^ ]*'") &&
    !source.includes("grep -oE 'HIVERELAY_API_KEY=[A-Za-z0-9._-]+'")
  ) &&
  fleetUpdaterScript.includes('ENV_FILE=') &&
  fleetStatusScript.includes('read_api_key()') &&
  fleetRolloutCheck.includes('env_file=') &&
  relayJanitorScript.includes('root-only env file first')
) {
  pass('fleet health tooling discovers API keys from root-only env files as well as legacy units')
} else {
  fail('fleet health tooling can miss API keys moved into root-only env files')
}

if (
  relayJanitorScript.includes('remoteHasApiKey') &&
  relayJanitorScript.includes('remoteUnseed') &&
  relayJanitorScript.includes("spawn('ssh', [...sshBase, 'bash', '-s', '--', ...args]") &&
  relayJanitorScript.includes('Never print or return it') &&
  relayJanitorScript.includes('-H "@$header_file"') &&
  !relayJanitorScript.includes('const key = await readApiKey') &&
  !relayJanitorScript.includes('authorization: Bearer ' + '$' + '{key}') &&
  !relayJanitorScript.includes('printf \'%s\\n\' "$key"') &&
  fleetShellSafetyTest.includes('relay janitor keeps remote API keys out of local ssh argv')
) {
  pass('relay janitor keeps relay API keys on the remote host and out of local SSH argv')
} else {
  fail('relay janitor can expose relay API keys through local process args or shell interpolation')
}

if (
  [fleetUpdaterScript, fleetStatusScript, fleetRolloutCheck].every(source =>
    source.includes('curl_with_optional_key()') &&
    source.includes('header_file="$(mktemp)"') &&
    source.includes('chmod 600 "$header_file"') &&
    source.includes('curl -H "@$header_file" "$@"') &&
    !source.includes('-H "Authorization: Bearer $key"') &&
    !source.includes('-H "Authorization: Bearer $K"')
  ) &&
  relayJanitorScript.includes('header_file="$(mktemp)"') &&
  relayJanitorScript.includes('chmod 600 "$header_file"') &&
  relayJanitorScript.includes('printf \'authorization: Bearer %s\\n\' "$key"') &&
  relayJanitorScript.includes('-H "@$header_file"') &&
  !relayJanitorScript.includes('-H "authorization: Bearer $key"') &&
  fleetShellSafetyTest.includes('fleet health probes keep relay API keys out of curl argv')
) {
  pass('fleet health and janitor probes keep relay API keys out of curl argv')
} else {
  fail('fleet health or janitor probes can expose relay API keys through curl process arguments')
}

if (
  fleetStatusScript.includes('clean_field()') &&
  fleetStatusScript.includes("tr -c '[:print:]' '?'") &&
  fleetStatusScript.includes("tr '|' '?'") &&
  fleetStatusScript.includes('valid_host()') &&
  fleetStatusScript.includes('valid_channel()') &&
  fleetStatusScript.includes('valid_key_path()') &&
  fleetStatusScript.includes('BADHOST') &&
  fleetStatusScript.includes('BADCHAN') &&
  fleetStatusScript.includes('BADKEY') &&
  fleetStatusScript.includes('safe_name="$(clean_field "$name")"') &&
  fleetStatusScript.includes('safe_target="$(clean_field "$target")"') &&
  fleetStatusScript.includes('out="$(printf \'%s\\n\' "$out" | tail -n 1)"') &&
  !fleetStatusScript.includes('"$name" UNREACH') &&
  !fleetStatusScript.includes(
    '"$' + '{ver:-?}" "$' + '{run:-?}" "$' + '{apps:-?}" "$' + '{conns:-?}" "$' + '{disk:-?}" "$target"'
  ) &&
  fleetShellSafetyTest.includes('fleet status sanitizes terminal output and validates inventory before ssh')
) {
  pass('fleet status sanitizes terminal output and validates inventory before SSH')
} else {
  fail('fleet status can print untrusted relay metadata or probe output without sanitizing')
}

if (
  releaseWorkflow.includes('UMBREL_OFFICIAL_PR_TOKEN:') &&
  releaseWorkflow.includes('UMBREL_OFFICIAL_FORK:') &&
  releaseWorkflow.includes('Verify stable release distribution credentials') &&
  releaseWorkflow.includes('Checkout official Umbrel fork') &&
  releaseWorkflow.includes('Open or update official Umbrel draft PR') &&
  releaseWorkflow.includes('npm run umbrel:export-official --') &&
  releaseWorkflow.includes('gh pr create') &&
  releaseWorkflow.includes('--draft') &&
  releaseWorkflow.includes('Official Umbrel PR URL from gh must point to getumbrel/umbrel-apps/pull/<number>.') &&
  releaseWorkflow.includes('^https://github\\.com/getumbrel/umbrel-apps/pull/[1-9][0-9]*$') &&
  releaseWorkflow.includes('Official Umbrel PR head SHA is malformed.') &&
  releaseWorkflow.includes('^[a-f0-9]{40}$') &&
  releaseWorkflow.includes('Official Umbrel PR must remain a draft before reviewer handoff') &&
  releaseWorkflow.includes('Official Umbrel PR head owner drifted before reviewer handoff') &&
  releaseWorkflow.includes('Official Umbrel PR head ref drifted before reviewer handoff') &&
  releaseWorkflow.includes('Official Umbrel PR head OID drifted before reviewer handoff') &&
  releaseWorkflow.includes('release_base_url="' + '$' + '{GITHUB_SERVER_URL:-https://github.com}/' + '$' + '{GITHUB_REPOSITORY}/releases/download/' + githubVersionExpression + '"') &&
  releaseWorkflow.includes('Release evidence: ' + shellReleaseBaseUrlExpression + '/release-evidence.json') &&
  releaseWorkflow.includes('Release image manifest: ' + shellReleaseBaseUrlExpression + '/release-image-manifest-evidence.json') &&
  releaseWorkflow.includes('Release image smoke: ' + shellReleaseBaseUrlExpression + '/release-image-smoke-evidence.json') &&
  releaseWorkflow.includes('Umbrel package smoke: ' + shellReleaseBaseUrlExpression + '/umbrel-package-smoke-evidence.json') &&
  releaseWorkflow.includes('Fleet rollout evidence: ' + shellReleaseBaseUrlExpression + '/fleet-rollout-evidence.json') &&
  releaseWorkflow.includes('StartOS package: ' + shellReleaseBaseUrlExpression + '/blindspark.s9pk') &&
  releaseWorkflow.includes('StartOS registry package: ' + '$' + '{HIVERELAY_STARTOS_REGISTRY_PACKAGE_URL}') &&
  releaseWorkflow.includes('StartOS registry evidence: ' + shellReleaseBaseUrlExpression + '/startos-registry-evidence.json') &&
  releaseWorkflow.includes('dashboard WebSocket URL-token rejection') &&
  releaseWorkflow.includes('dashboard WebSocket in-band auth') &&
  releaseWorkflow.includes('pinned multi-arch image manifests') &&
  releaseWorkflow.includes('Manual Umbrel runtime review status: pending real-device review') &&
  releaseWorkflow.includes('npm run umbrel:write-runtime-review') &&
  releaseWorkflow.includes('npm run umbrel:verify-runtime-review') &&
  releaseWorkflow.includes('Refresh official Umbrel PR evidence links') &&
  releaseWorkflow.includes('gh pr edit "$HIVERELAY_UMBREL_OFFICIAL_PR_URL" --body-file "$pr_body"') &&
  releaseWorkflow.indexOf('Refresh official Umbrel PR evidence links') > releaseWorkflow.indexOf('Verify published release evidence assets') &&
  releaseWorkflow.includes('npm run release:write-official-umbrel-pr-evidence -- --out official-umbrel-pr-evidence.json') &&
  releaseWorkflow.includes('sha256sum official-umbrel-pr-evidence.json') &&
  releaseWorkflow.includes('Official Umbrel PR evidence SHA-256 is malformed.') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_URL "$pr_url"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD "$fork_owner:$branch"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_STATE "$pr_state"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT "$pr_is_draft"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_BASE "$pr_base"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER "$pr_head_owner"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF "$pr_head_ref"') &&
  releaseWorkflow.includes('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID "$pr_head_oid"') &&
  releaseWorkflow.includes('export HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER="$pr_head_owner"') &&
  releaseWorkflow.includes('export HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID="$pr_head_oid"') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_BODY_EVIDENCE=official-umbrel-pr-evidence.json') &&
  releaseWorkflow.includes('HIVERELAY_UMBREL_OFFICIAL_PR_BODY_EVIDENCE_SHA256=$official_pr_evidence_sha') &&
  releaseWorkflow.includes('Upload official Umbrel PR evidence') &&
  releaseWorkflow.includes('gh release upload "' + githubVersionExpression + '" official-umbrel-pr-evidence.json --clobber') &&
  releaseWorkflow.includes("--pattern 'official-umbrel-pr-evidence.json'") &&
  releaseWorkflow.includes('cmp official-umbrel-pr-evidence.json "$official_pr_dir/official-umbrel-pr-evidence.json"') &&
  officialUmbrelPrEvidence.includes("kind: 'official-umbrel-pr'") &&
  officialUmbrelPrEvidence.includes('official Umbrel PR evidence generatedAt') &&
  officialUmbrelPrEvidence.includes('ISO_TIMESTAMP_PATTERN') &&
  officialUmbrelPrEvidence.includes('release-image-manifest-evidence.json') &&
  officialUmbrelPrEvidence.includes('release-image-smoke-evidence.json') &&
  officialUmbrelPrEvidence.includes('umbrel-package-smoke-evidence.json') &&
  officialUmbrelPrEvidence.includes('fleet-rollout-evidence.json') &&
  officialUmbrelPrEvidence.includes('blindspark.s9pk') &&
  officialUmbrelPrEvidence.includes('startosRegistryPackage') &&
  officialUmbrelPrEvidence.includes('startos-registry-evidence.json') &&
  officialUmbrelPrEvidence.includes('pending-real-device-review') &&
  officialUmbrelPrEvidence.includes('umbrel-runtime-review-evidence.json') &&
  officialUmbrelPrEvidence.includes('npm run umbrel:verify-runtime-review') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR runtime review status') &&
  releaseHandoffEvidenceVerify.includes('official Umbrel PR runtime review verifier') &&
  releaseHandoffEvidenceVerify.includes('--umbrel-runtime-review') &&
  releaseHandoffEvidenceVerify.includes('--require-umbrel-runtime-review') &&
  releaseHandoffEvidenceVerify.includes('requireUmbrelRuntimeReview') &&
  releaseHandoffEvidenceVerify.includes('Umbrel runtime review handoff evidence is required when --require-umbrel-runtime-review is set') &&
  releaseHandoffEvidenceVerify.includes('verifyOptionalUmbrelRuntimeReviewHandoff') &&
  releaseHandoffEvidenceVerify.includes('Umbrel runtime review generatedAt must not be before release generatedAt') &&
  releaseHandoffEvidenceVerify.includes('Umbrel runtime review generatedAt must not be before official Umbrel PR handoff generatedAt') &&
  releaseHandoffEvidenceVerify.includes('MAX_GENERATED_AT_FUTURE_SKEW_MS') &&
  releaseHandoffEvidenceVerify.includes('Umbrel runtime review generatedAt must not be in the future') &&
  releaseHandoffEvidenceVerify.includes('Umbrel runtime review PR URL') &&
  releaseHandoffEvidenceVerify.includes('verifyUmbrelRuntimeReviewIdentityHashes') &&
  releaseHandoffEvidenceVerify.includes('publicKeyAfterSha256') &&
  releaseHandoffEvidenceVerify.includes('assertNoRawPublicKeyFields') &&
  releaseHandoffEvidenceVerify.includes('UMBREL_RUNTIME_REVIEW_CHECKS') &&
  releaseHandoffEvidenceVerify.includes('setupActionLockObserved') &&
  releaseHandoffEvidenceVerify.includes('walletBusyStateObserved') &&
  releaseHandoffEvidenceVerify.includes('serviceActionStateObserved') &&
  releaseHandoffEvidenceVerify.includes('serviceRestartPendingObserved') &&
  releaseHandoffEvidenceVerify.includes('aiModelAddStateObserved') &&
  officialUmbrelPrEvidence.includes('number: prNumberFromUrl(prUrl)') &&
  officialUmbrelPrEvidence.includes("EXPECTED_RELEASE_REPOSITORY = 'bigdestiny2/P2P-Hiverelay'") &&
  officialUmbrelPrEvidence.includes('body.workflow.repository, EXPECTED_RELEASE_REPOSITORY') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_SHA') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATE') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_DRAFT') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_BASE') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OWNER') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_REF') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_UMBREL_OFFICIAL_PR_HEAD_OID') &&
  officialUmbrelPrEvidence.includes('official Umbrel PR head SHA') &&
  officialUmbrelPrEvidence.includes('function isGitHubOwnerName') &&
  officialUmbrelPrEvidence.includes('function isGitHubHeadRefName') &&
  officialUmbrelPrEvidence.includes('normal GitHub owner name') &&
  officialUmbrelPrEvidence.includes('must not be getumbrel') &&
  officialUmbrelPrEvidence.includes("value.toLowerCase() !== 'getumbrel'") &&
  officialUmbrelPrEvidence.includes('normal GitHub branch name') &&
  officialUmbrelPrEvidence.includes('official Umbrel PR head owner matches head owner') &&
  officialUmbrelPrEvidence.includes('official Umbrel PR head ref matches head branch') &&
  officialUmbrelPrEvidence.includes('official Umbrel PR head OID matches head SHA') &&
  officialUmbrelPrEvidence.includes('assertOfficialUmbrelPrEvidenceSchema') &&
  officialUmbrelPrEvidence.includes("requireOnlyKeys('official Umbrel PR evidence'") &&
  officialUmbrelPrEvidence.includes('has unsupported fields') &&
  officialUmbrelPrEvidence.includes("return String(process.env[name] ?? '')") &&
  !officialUmbrelPrEvidence.includes("return String(process.env[name] || '').trim()") &&
  officialUmbrelPrEvidence.includes('await validate(body)') &&
  officialUmbrelPrEvidence.includes('verifyLinkedEvidenceArtifacts') &&
  officialUmbrelPrEvidence.includes('await verifyLinkedEvidenceArtifacts(body)') &&
  officialUmbrelPrEvidence.includes('readLinkedReleaseEvidence') &&
  officialUmbrelPrEvidence.includes('verifyReleaseEvidenceAlignment') &&
  officialUmbrelPrEvidence.includes('release evidence workflow status') &&
  officialUmbrelPrEvidence.includes('release evidence official Umbrel PR head OID') &&
  officialUmbrelPrEvidence.includes('release evidence StartOS registry package URL') &&
  officialUmbrelPrEvidence.includes('linked ' + '$' + '{label} SHA-256 does not match ' + '$' + '{expectedFile}') &&
  officialUmbrelPrEvidence.includes("verifyLinkedArtifactHash('StartOS package'") &&
  officialUmbrelPrEvidence.includes('function sha256File') &&
  officialUmbrelPrEvidence.includes('fs.createReadStream(file)') &&
  officialUmbrelPrEvidence.includes('MAX_EVIDENCE_JSON_BYTES') &&
  officialUmbrelPrEvidence.includes("requireRegularFile('linked evidence artifact'") &&
  officialUmbrelPrEvidence.includes('requireRegularFile(label, expectedFile)') &&
  officialUmbrelPrEvidence.includes('is required before writing official Umbrel PR evidence') &&
  officialUmbrelPrEvidence.includes('must not be a symlink') &&
  officialUmbrelPrEvidence.includes('FORBIDDEN_PUBLIC_VALUE_PATTERNS') &&
  officialUmbrelPrEvidence.includes('APP_SEED') &&
  officialUmbrelPrEvidence.includes('HIVERELAY_API_KEY') &&
  officialUmbrelPrEvidence.includes('assertPublicSafeValues') &&
  officialUmbrelPrEvidence.includes('POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/') &&
  officialUmbrelPrEvidence.includes('GITHUB_ACTIONS_RUN_URL_PATTERN') &&
  officialUmbrelPrEvidence.includes('OFFICIAL_UMBREL_PR_URL_PATTERN') &&
  officialUmbrelPrEvidence.includes('workflow URL matches repository and run id') &&
  officialUmbrelPrEvidence.includes('hasControlChars') &&
  officialUmbrelPrEvidence.includes('must not contain control characters') &&
  officialUmbrelPrEvidence.includes('StartOS registry package link') &&
  officialUmbrelPrEvidence.includes('workflow run attempt') &&
  officialUmbrelPrEvidence.includes('must not expose URL credentials') &&
  officialUmbrelPrEvidenceTest.includes('releaseImageManifest') &&
  officialUmbrelPrEvidenceTest.includes('keeps a closed public schema') &&
  officialUmbrelPrEvidenceTest.includes('requires linked release artifacts before write') &&
  officialUmbrelPrEvidenceTest.includes('rejects linked artifact hash drift before write') &&
  officialUmbrelPrEvidenceTest.includes('rejects release evidence drift before write') &&
  officialUmbrelPrEvidenceTest.includes('releaseEvidenceBytes') &&
  officialUmbrelPrEvidenceTest.includes('official Umbrel PR evidence generatedAt is an ISO timestamp') &&
  officialUmbrelPrEvidenceTest.includes('workflow repository must be') &&
  officialUmbrelPrEvidenceTest.includes('rejects whitespace-normalized metadata before write') &&
  officialUmbrelPrEvidenceTest.includes('rejects malformed GitHub owner names') &&
  officialUmbrelPrEvidenceTest.includes('GetUmbrel') &&
  officialUmbrelPrEvidenceTest.includes('rejects malformed GitHub head refs') &&
  officialUmbrelPrEvidenceTest.includes('zero-run-id.json') &&
  officialUmbrelPrEvidenceTest.includes('zero-official-pr.json') &&
  officialUmbrelPrEvidenceTest.includes('bad-workflow-server.json') &&
  officialUmbrelPrEvidenceTest.includes('rejects unsafe StartOS registry package URLs') &&
  officialUmbrelPrEvidenceTest.includes('pending-real-device-review') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects official Umbrel runtime review drift') &&
  releaseHandoffEvidenceVerifyTest.includes('validates optional real Umbrel runtime review evidence') &&
  releaseHandoffEvidenceVerifyTest.includes('requires real Umbrel runtime review evidence when requested') &&
  releaseHandoffEvidenceVerifyTest.includes('rejects optional Umbrel runtime review evidence drift') &&
  releaseHandoffEvidenceVerifyTest.includes('Umbrel runtime review generatedAt must not be before release generatedAt') &&
  releaseHandoffEvidenceVerifyTest.includes('Umbrel runtime review generatedAt must not be before official Umbrel PR handoff generatedAt') &&
  releaseHandoffEvidenceVerifyTest.includes('Umbrel runtime review generatedAt must not be in the future') &&
  releaseHandoffEvidenceVerifyTest.includes('Umbrel runtime review public key hash after reinstall') &&
  releaseHandoffEvidenceVerifyTest.includes('Missing Umbrel runtime review checks: aiModelAddStateObserved') &&
  releaseAutomationDocs.includes('umbrel-runtime-review-evidence.json') &&
  releaseAutomationDocs.includes('release:verify-handoff-evidence') &&
  releaseAutomationDocs.includes('release:verify-review-ready-handoff') &&
  releaseAutomationDocs.includes('--require-umbrel-runtime-review') &&
  releaseHandoffEvidenceVerifyTest.includes('release:verify-review-ready-handoff') &&
  readme.includes('release:verify-review-ready-handoff') &&
  readme.includes('--require-umbrel-runtime-review') &&
  startosRegistryEvidenceTest.includes('workflow repository must be') &&
  !officialUmbrelPrEvidence.includes('HIVERELAY_RELEASE_BASE_URL') &&
  releaseWorkflow.includes('--submission-url "$pr_url"') &&
  releaseWorkflow.includes('--check') &&
  releaseWorkflow.lastIndexOf('--check') > releaseWorkflow.indexOf('--submission-url "$pr_url"') &&
  releaseWorkflow.lastIndexOf('--check') < releaseWorkflow.lastIndexOf('node scripts/write-github-env.mjs HIVERELAY_UMBREL_OFFICIAL_PR_STATUS draft-pr-ready') &&
  releaseAutomationDocs.includes('workflow refreshes the draft') &&
  releaseAutomationDocs.includes('PR body with deterministic links') &&
  releaseAutomationDocs.includes('validates those raw metadata values without trimming') &&
  releaseAutomationDocs.includes('whitespace before writing public evidence') &&
  releaseAutomationDocs.includes('release-image-manifest-evidence.json') &&
  releaseAutomationDocs.includes('release-image-smoke-evidence.json') &&
  releaseAutomationDocs.includes('umbrel-package-smoke-evidence.json') &&
  releaseAutomationDocs.includes('fleet-rollout-evidence.json') &&
  releaseAutomationDocs.includes('startos-registry-evidence.json') &&
  auditRoadmap.includes('Official Umbrel raw metadata proof')
) {
  pass('release workflow opens, evidence-links, and verifies a draft official Umbrel App Store PR for stable releases')
} else {
  fail('release workflow is missing required stable-release official Umbrel App Store PR automation, evidence links, or final export verification')
}

for (const warning of warnings) {
  console.log(`WARN  ${warning}`)
}
for (const check of checks) {
  const prefix = check.level === 'pass' ? 'PASS ' : 'FAIL '
  console.log(prefix + check.message)
}

if (checks.some((check) => check.level === 'fail')) process.exit(1)

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
