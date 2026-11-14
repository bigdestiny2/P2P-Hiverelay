# Private paid-proof routing correction 1

The runtime validates all supplied non-null `coreProofBytes`, `canonicalResultBytes` and `predictedResultBodyBytes` against storage-owned retained metadata before replacing any size field or reading a retired corpus. An inconsistent reservation fails with `INTERNAL`. Missing or null fields retain the documented direct-hook behavior; this does not replace admission and capacity reservation through the public coordinator. The request, prepared admission and sizing snapshot remain captured before any await.

After awaiting inherited proof execution, the runtime checks the captured caller signal before returning the original branded result object. A follower cancelled while waiting for shared execution fails with `CORE_ABORTED`. Its cancellation does not cancel the leader or other live followers.

These changes correct the two private-hook issues in the independent review of `2313f8d1879bb83625787b31f023df360a45d103`. Normal cheap-state metadata was already consistent, and the unchanged public coordinator already checked cancellation before public success delivery. No externally controlled authenticated-state or public delivery bypass is claimed.

The original README is retained byte-for-byte because the original sealed evidence directly binds that file. This document records the corrected behavior without changing that historical artifact. The package API, eleven accepted predecessor source/lock bindings, wire/WAL formats, storage authority, original result branding and production selectors are unchanged. Original source and evidence remain available for review.

Seven added tests cover each independent size disagreement, exact/missing size controls, owned metadata across a held lookup and a cancelled follower with a live leader and another live follower. The latter performs one real proof materialization and preserves the other callers' branded result without new WAL pins or charges. These tests supplement the original coordinator/offline-restart and real Hypercore matrix and the unchanged independent-review regressions.

This remains an unused private prerequisite. The deployment and resource limitations in the original README still apply, and the exact corrected commit requires independent acceptance.
