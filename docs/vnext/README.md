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

The current integration base is post-release `main` at `999b0afd…`; the exact
`v0.24.3` artifact baseline remains `d0190577…`. The tentative train is
`v0.25.0-rc.N`. No concrete RC number, profile promotion, channel movement, or
public claim is authorized by this file.
