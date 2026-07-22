// Public, bounded projection of an AppRelease v2 record. HiveRelay records
// availability facts only; signature and install-policy verification belongs to
// the canonical contract consumer (for example PearBrowser's privileged host).
const APP_KINDS = new Set(['site', 'desktop-app', 'binary', 'worker'])
const GENERATIONS = new Set(['hyperdrive', 'pear-v3', 'legacy-v2'])

export function summarizeV3Release (record) {
  const spec = record && record.kind === 'AppRelease' && record.apiVersion === 'pear.deploy/v1alpha1' ? record.spec : null
  if (!spec || !spec.identity || !spec.release || !spec.kind || !spec.distribution) return null
  const appKind = spec.kind.appKind
  const distributionGeneration = spec.kind.distributionGeneration
  if (!APP_KINDS.has(appKind) || !GENERATIONS.has(distributionGeneration)) return null
  const artifacts = Array.isArray(spec.distribution.artifacts) ? spec.distribution.artifacts : []
  const targets = artifacts.filter(item => item && typeof item.host === 'string' && item.artifact && typeof item.artifact.basename === 'string').slice(0, 16).map(item => ({ host: item.host, basename: item.artifact.basename, byteSize: item.artifact.byteSize, treeDigest: item.artifact.treeDigest }))
  return { id: typeof record.metadata?.id === 'string' ? record.metadata.id : null, appId: typeof spec.identity.appId === 'string' ? spec.identity.appId : null, productName: typeof spec.identity.productName === 'string' ? spec.identity.productName : null, publisherKey: typeof spec.identity.publisherKey === 'string' ? spec.identity.publisherKey : null, channel: typeof spec.identity.channel === 'string' ? spec.identity.channel : null, version: typeof spec.release.version === 'string' ? spec.release.version : null, sequence: Number.isSafeInteger(spec.release.sequence) ? spec.release.sequence : null, appKind, distributionGeneration, targets, trust: 'unverified-by-relay' }
}
