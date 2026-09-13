/** Normative FUTURE engine/coordinator interfaces, not implemented exports.
 * These declarations cannot mint runtime authority. Constructors and brands must
 * remain module-private WeakMap/WeakSet identities in the implementing lanes.
 */
declare const owner: unique symbol
declare const barrier: unique symbol
declare const authority: unique symbol
declare const capture: unique symbol
declare const shadow: unique symbol
declare const coverage: unique symbol
declare const suffix: unique symbol
declare const installation: unique symbol
declare const hc11: unique symbol
export type Role = 'CELL' | 'INBOX' | 'CORE'
export type Bytes32 = Uint8Array
export interface RootIdentity<R extends Role = Role> {
  readonly role: R
  readonly installationId: Bytes32
  readonly rootId: Bytes32
  readonly relayPublicKey: Bytes32
  readonly storeId: Bytes32
  readonly durabilityContinuityHash: Bytes32
}
export interface WalTuple { readonly sequence: bigint; readonly hash: Bytes32 }
export interface OwnerLease<R extends Role> { readonly [owner]: R }
export interface WalBarrier<R extends Role> { readonly [barrier]: R }
export interface VerifiedFormat { readonly [authority]: 'private-2.0' }
export interface VerifiedInstallation { readonly [installation]: true }
export interface CapturedRole<R extends Role> { readonly [capture]: R }
export interface DetachedShadow<R extends Role> { readonly [shadow]: R }
export interface PublishedCoverage<R extends Role> { readonly [coverage]: R }
export interface VerifiedSuffix<R extends Role> { readonly [suffix]: R }
export interface VerifiedHc11Activation { readonly [hc11]: true }

/** Real engine-owned operations. No caller-provided state or semantic callback. */
export interface EngineCheckpointPort<R extends Role> {
  readonly identity: RootIdentity<R>
  drainAndCapture(lease: OwnerLease<R>, barrier: WalBarrier<R>, format: VerifiedFormat, history: VerifiedInstallation): Promise<CapturedRole<R>>
  hydrateDetached(snapshot: CapturedRole<R>, lease: OwnerLease<R>, history: VerifiedInstallation): Promise<DetachedShadow<R>>
  applyVerifiedSuffix(shadow: DetachedShadow<R>, suffix: VerifiedSuffix<R>, lease: OwnerLease<R>): Promise<DetachedShadow<R>>
  revalidateBodiesAccountingFloors(shadow: DetachedShadow<R>, lease: OwnerLease<R>, history: VerifiedInstallation): Promise<void>
  adoptVerifiedShadow(shadow: DetachedShadow<R>, lease: OwnerLease<R>, history: VerifiedInstallation): Promise<void>
}
/** Only authenticated decoding plus the engine's private validator may restore a
 * persisted capture handle. Raw decoded Snapshot bytes never satisfy this port.
 */
export interface RoleCheckpointCoordinator<R extends Role> {
  publish(capture: CapturedRole<R>, lease: OwnerLease<R>): Promise<PublishedCoverage<R>>
  pruneCoveredSealedPrefix(coverage: PublishedCoverage<R>, lease: OwnerLease<R>): Promise<void>
  closeAndDrain(): Promise<void>
}
export type BlindParticipant =
  | { readonly kind: 'blind'; readonly role: 'CELL'; readonly coverage: PublishedCoverage<'CELL'> }
  | { readonly kind: 'blind'; readonly role: 'INBOX'; readonly coverage: PublishedCoverage<'INBOX'> }
  | { readonly kind: 'blind'; readonly role: 'CORE'; readonly coverage: PublishedCoverage<'CORE'> }
export interface Hc11Participant { readonly kind: 'hc11'; readonly activation: VerifiedHc11Activation }
export type GenerationParticipant = BlindParticipant | Hc11Participant
export interface SharedHistoryPort {
  /** Preserve first-trigger record bytes and immutable ancestry; reread after
   * uncertain publication. A terminal error quarantines every writer and cache.
   */
  acknowledge(participant: GenerationParticipant, prior: VerifiedInstallation): Promise<VerifiedInstallation>
  closeAndDrain(): Promise<void>
}
export interface HealthObservation {
  readonly verifiedReaderIntegrity: 'verified' | 'unverified' | 'failed'
  readonly writeAvailability: 'available' | 'quarantined' | 'closed'
}
