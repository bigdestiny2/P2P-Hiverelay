# Blindspark

Blindspark keeps decentralized Pear/Holepunch apps alive by seeding
**end-to-end-encrypted** data the relay itself cannot read. Your node
stores ciphertext and proofs — never plaintext, never who-reads-what.

## First run

1. Open the **Blindspark Dashboard** from the service's UI button.
2. Walk through the short setup wizard (a couple of minutes): name your
   node and choose how to accept seed requests.
3. That's it. The dashboard is a single page showing your relay's name
   and public key, live status, connected peers, how many apps it keeps
   alive, and real on-disk storage usage.

## Accepting content

By default Blindspark runs in **review mode**: every request to store
data on your node waits for your approval before the relay seeds it. The
dashboard shows the current mode; you can change it from the setup
wizard whenever you're comfortable.

## Storage

The **Storage used** stat shows true on-disk usage, measured for real
(not an estimate). It's a percentage of the storage cap configured for
the service, so you can see headroom at a glance.

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
