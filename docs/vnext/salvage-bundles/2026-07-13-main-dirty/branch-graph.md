# HiveRelay branch graph — 2026-07-13

Baseline: `999b0afd` (ops: promote stable → v0.24.3)

- **hiverelay**: `main` @ `999b0afd ops(fleet): promote stable → v0.24.3` — dirty=36, commits after baseline=0
- **hr-https-gateway**: `feat/public-https-hive-gateway` @ `0ff54842 test(gateway): assert retirement admission boundary` — dirty=0, commits after baseline=10
- **hr-vnext-integration**: `feat/vnext-integration` @ `2ef12971 fix(test): preserve complete suite results` — dirty=1, commits after baseline=42
- **hr-main-salvage**: `fix/vnext-inherited-baseline` @ `e437d924 fix(storage): prove lifecycle ownership and hard quota admission` — dirty=0, commits after baseline=3
- **hr-blind-protocol-remediation**: `fix/blind-protocol-remediation` @ `065e1a8 fix(blind): reject executable schema metadata drift` — dirty=0, commits after baseline=5
- **hr-blind-v3-staged-put**: `fix/blind-v3-staged-put` @ `70e85f9 test(blind): enforce staged PUT admission gate` — dirty=0, commits after baseline=6
- **hr-blind-cr5-route-scope**: `fix/blind-cr5-route-scope` @ `edf62a3 feat(blind): add draft forward route scope` — dirty=0, commits after baseline=7
- **hr-blind-review**: `review/blind-preservation` @ `211b20d8 fix(blind): refresh browser artifact authority` — dirty=0, commits after baseline=4

## Divergence

| Pair | Relationship |
| --- | --- |
| gateway ∩ vnext (path names) | 4 overlapping paths of 190 gateway / 882 vnext |
| gateway tip in vnext? | no (separate +10 commits) |
| storage redesign on gateway/salvage? | yes (`resolveStorageCap` + provenance) |
| storage redesign on vnext? | no |
| credits auth-gate on vnext? | yes (`ee4b1a6b`) |
| credits auth-gate on main dirty? | no (P1 open in working tree) |
