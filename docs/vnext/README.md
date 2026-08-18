# HiveRelay vNext programme control

`program-state.json` is the machine-readable release-profile, decision, gate,
and track board for the vNext integration train. Recommendations are not owner
decisions. A pending decision stays visibly pending, and a gate cannot be
marked passed without at least one immutable evidence reference.

Each D-1 through D-7 entry names its owner role, affected profiles, blocked
boundary, recommendation rationale, and the assumption it would supersede.
`deadline: null` means the owner has not scheduled the decision yet; it is not
an implicit approval. A resolved decision requires a canonical deadline,
owner rationale, selected option, and immutable evidence for the signed record.

Validate it with:

```bash
npm run vnext:check-program
```

`protocol-remediation.json` keeps the preserved Blind protocol candidate in a
draft-only state while the audited CR-1 through CR-8 controls, D-6, D-7, and
PG-2 remain open. Its validator also rejects the appearance of final authority
artifacts before all of those controls are supported by immutable evidence:

```bash
npm run vnext:check-protocol
```

The current integration base is post-release `main` at `999b0afd…`; the exact
`v0.24.3` artifact baseline remains `d0190577…`. The train is
`v0.26.0-rc.N` (current RC: `v0.26.0-rc.1`, GA target `v0.26.0`); the earlier
`0.25.0-rc.1`…`rc.9` candidates are superseded and folded into it. No profile
promotion, channel movement, or public claim is authorized by this file.
