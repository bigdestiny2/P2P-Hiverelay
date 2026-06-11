# Blindspark

Blindspark keeps decentralized Pear/Holepunch apps alive by seeding
**end-to-end-encrypted** data the relay itself cannot read. Your node
stores ciphertext and proofs — never plaintext, never who-reads-what.

## First run

1. Open the **Blindspark Dashboard** from the service's UI button.
2. Walk through the short setup wizard (a couple of minutes): name your
   node and choose how to accept seed requests.
3. That's it. The dashboard shows live connections, the apps your node
   keeps alive, and exactly how much disk is used — measured for real.

## Accepting content

By default Blindspark runs in **review mode**: every request to store
data on your node waits in the dashboard's Seeding Registry for your
approval. Switch to auto-accept from the registry toggle whenever you're
comfortable.

## Storage

The dashboard's System panel shows true on-disk usage. If you enable
**eviction** (off by default), the node automatically sheds copies the
network holds in surplus when your disk runs hot — never pinned content,
never paid-durability content, and never the last copies of anything.

## Privacy

- Content is end-to-end encrypted between publisher and consumer
  (Hypercore Noise transport). The relay holds ciphertext blocks.
- The dashboard binds to localhost inside the container; StartOS fronts
  it over Tor/LAN with your device's normal access controls, and the
  page authenticates itself with a token derived from a seed that never
  leaves your data volume.
- No telemetry. There are no project servers to send anything to.

## Identity & reinstalls

Your relay identity (and dashboard token) derive from a seed stored on
the service's data volume. Reinstalling the service keeps your identity
as long as you keep the data; a backup restore brings the node back as
itself.
