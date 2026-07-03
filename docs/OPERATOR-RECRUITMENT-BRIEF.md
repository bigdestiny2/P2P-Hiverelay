# Become a Blindspark Operator — Candidate Brief

> **Who this is for:** someone deciding whether to run a HiveRelay / Blindspark box as a
> **genuinely independent** operator. It's the outward-facing companion to the maintainer's
> onboarding checklist (`fleet/`, `docs/OPERATOR_ECONOMICS.md`) and the liability design
> (`docs/OPERATOR-INCENTIVES-Y1.md`; peerit's `OPERATOR-LIABILITY.md`).
>
> **Not legal advice.** Everything below describes a *design and positioning posture*, not a
> legal opinion, contract, or guarantee. Running infrastructure carries real,
> jurisdiction-specific exposure — talk to your own lawyer before you operate, especially if
> you ever take payment.

---

## The ask, in one line

Run an always-on box that stores **opaque, content-addressed fragments** for a peer-to-peer
network **you don't control** — and that you cannot read, index, or reconstruct on your own.

## Why *you* matter (the honest version)

HiveRelay's headline property is *"no single operator can read or reconstruct the content."*
The cryptography behind that is real and proven end-to-end in the code: content is
**k-of-n secret-shared** before it reaches any relay, each relay holds **fewer than the
threshold**, and a reader reassembles only at the edge (see `packages/client/blind-shards.js`
+ the k-of-n dispersal proof). A single relay — or any minority of them — **cannot** put the
pieces back together.

But that guarantee is **vacuous while one entity runs every relay.** If the same person owns
all the boxes, they can co-locate enough shares to reconstruct everything, and one subpoena or
seizure reaches the whole "fleet." The threshold protects nothing against a colluding pool.

So the security model doesn't become *real* until at least one operator is **arms-length from
the maintainer**. That's you. Going from **1 → 2 independent entities** is the single biggest
step this network can take; full dispersal wants roughly **6**. **No amount of code substitutes
for this** — it is the one lever that can only be pulled by a person who isn't us.

## What you're actually running

- **A blind relay.** It stores bytes addressed only by their hash (`shard:<hash>`). It holds
  **no plaintext in the ordinary course of storage**, **no decryption keys**, and **cannot
  enumerate or index** what it holds — there is no "list everything about topic X" it can answer.
- **Below-threshold by construction.** Because content is dispersed k-of-n, your box holds an
  individually meaningless fragment. You can **serve, withhold, or drop** it; you **cannot
  forge, tamper with, read, or reconstruct** it. Every record's authenticity is re-checked in
  the *reader's* browser, never by you.
- **The same binary everyone runs.** Independence comes from *who runs it and how*, not from a
  special build. You hold no key that could impersonate a user or sign on anyone's behalf.

## The honest liability posture (read carefully)

The architecture is deliberately shaped to keep an operator in the position of a **neutral
intermediary / transitory conduit**, not a content host. Secondary-liability and safe-harbor
doctrines turn on three prongs, and the design works to remove each:

| Prong | How the design addresses it |
|---|---|
| **Knowledge** | Blindness — in the ordinary course you perceive only opaque bytes; you'd have to take deliberate, non-ordinary steps to read anything. |
| **Attributable benefit** | Content-neutral pricing — you're paid (if ever) for bytes and uptime, never for *what* the bytes are or how popular they are. |
| **Right & ability to control** | No ability to read or select, plus **drop-by-opaque-id** takedown — you can remove a specific `shard`/`blindContentId` on a valid notice **without reading it**. |

**What this is NOT — stated plainly, not softened:**

- **NOT immunity and NOT a guarantee.** It is a *risk-reduction posture.* Courts and
  jurisdictions vary; nothing here promises you can't be named, served, or sued.
- **NOT legal advice.** Get your own counsel before operating, and before ever accepting payment.
- **NOT self-executing.** The posture only holds while *you* keep it: stay blind (never
  configure the box to read/index/select), stay content-neutral, honor drop-by-id notices, and
  **never** market the relay as "host anything" or "uncensorable hosting." **Inducement destroys
  the entire argument regardless of blindness.**

## What it costs — and earns — you (honest, current state)

- **Today: unpaid volunteer.** The network is in its reputation-only phase — **no money flows
  yet.** Do not do this expecting income right now.
- **Roadmap (designed, not live):** Lightning per-call sats on **demand-blind** pricing (bytes
  stored · bytes served · uptime — never content-derived), plus a **founder cash subsidy** for
  the cold-start period that is explicitly built to *sunset* as real paid demand grows. See
  `docs/OPERATOR-INCENTIVES-Y1.md` and `docs/OPERATOR_ECONOMICS.md`.
- **Hardware:** a spare always-on machine or a small VPS. It's **storage-bound** — you set a cap
  (in the dashboard or `HIVERELAY_MAX_STORAGE`) and the box sheds surplus fragments to fit, so
  it never fills your disk. Modest CPU/RAM.
- **Your bill, your account.** You pay your own infrastructure from your own funds — that isn't
  incidental, it's part of what makes you independent (a shared invoice re-collapses the "one
  legal person" problem).

## What you commit to (the operator posture)

Short and plain. As an operator you agree to:

1. **Run it untrusted.** The relay never signs for users and is an availability provider only —
   it can serve, replicate, or refuse data, never forge or impersonate.
2. **Stay content-neutral.** You don't select, rank, or curate. If/when payment exists, it's
   metered on bytes and uptime only — never per-work, per-view, or popularity-weighted.
3. **Honor blind takedown.** On a valid notice you drop the specific `shard`/`blindContentId`
   **by identifier, without reading it.**
4. **No inducement.** You frame it as *"I provide storage and bandwidth to a blind fragment
   network"* — never "host anything" or "get paid to carry what nobody else will."
5. **Keep the box blind.** Don't configure it to read, index, or select content, and don't
   co-locate enough shares of one item to reconstruct it.
6. **Attest independence.** You are a separate entity with independent control of the infra,
   domain, keys, and funding — and you'll disclose if that ever changes.

## The bar you must clear (independence gate)

A new relay only helps if it's a genuinely separate seizure-and-trust surface. Every box must be true:

- [ ] **A different legal person/entity** — not the maintainer, not a shell or alias they control. *(load-bearing; the rest is defense in depth)*
- [ ] **A different hosting provider / account** than the existing relays.
- [ ] **Different funding trail** — you pay your own bill.
- [ ] **Independent control** of the domain, TLS, and server keys — the maintainer cannot log in.
- [ ] **A different jurisdiction**, ideally — raises the cost of one legal process covering everyone.

If the first, fourth, or the independence attestation fail, the box is *another hat on the same
head*: it adds attack surface without adding the independence that is the entire point.

## How to start (concrete)

1. **Install Blindspark.** One-click from the Umbrel community store, sideload the `.s9pk` on
   StartOS, or run bare on a VPS (systemd unit + the pull-updater in `fleet/`; the box
   self-updates on a health-gated, auto-rollback timer).
2. **Harden.** Run `fleet/harden-box.sh`; set a storage cap; put your own domain + TLS in front;
   set a per-box API key (`openssl rand -hex 32`).
3. **Enable the shard store** so the box can hold custody fragments (Services tab, or add
   `shard-store` to `plugins`).
4. **Join the signed roster.** Send the maintainer your relay URL + pubkey; they re-sign the
   roster to include you (no client rebuild needed — clients pick up the new relay
   automatically). A misbehaving or non-serving relay is simply dropped at the next re-sign —
   membership is revocable, not a permanent grant.
5. **Sign the independence attestation.** This is the on-record proof that "no right-and-ability
   to control" is genuinely true.

## FAQ

**Can I read what I'm storing?** No. You hold opaque, content-addressed fragments below the
reconstruction threshold, with no decryption keys. Reading would require deliberate,
non-ordinary steps you agree not to take.

**Am I liable for what's in the fragments?** The design is built to place you as a neutral
conduit, not a host — but that's a *posture, not immunity, and not legal advice*. Your exposure
depends on your jurisdiction and conduct. Get counsel, keep the posture, honor takedowns.

**What happens when I get a takedown notice?** You drop the named `shard`/`blindContentId` by
identifier, without reading it. Blind storage and prompt takedown aren't in tension when the
target is an id, not content.

**What does it cost me?** Your infra bill (a spare box or small VPS) — and today, that's it;
there's no income yet. The paid model (sats + a cold-start subsidy) is designed but not live.

**Why can't the maintainer just run more boxes instead of recruiting me?** Because same-owner
boxes are *one legal person wearing many hats* — one subpoena reaches all of them, and a single
entity can co-locate shares to reconstruct everything. Independent operators are the *only*
thing that makes the collusion threshold and seizure-resistance real.

**Do I have to trust the code?** It's open and audited, you run the same binary as everyone
else, and the relay holds no key that can impersonate a user or forge a record — readers verify
everything themselves. Trust is in the math you can check, not in the operator.

**What if I want out?** Stop the box, or ask to be removed from the roster; it's dropped at the
next re-sign. No lock-in, no obligation to keep serving.

---

**The bottom line:** the cryptography is done and proven; the missing piece is *you* — one
independent operator turns "no single party can read or reconstruct this" from a design claim
into a fact on the ground. It starts a road that runs to a handful of arms-length operators, at
which point the network's censorship- and seizure-resistance stop being theoretical.
