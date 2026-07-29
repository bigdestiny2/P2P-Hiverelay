# Blindspark

Blindspark is an always-on blind relay for Pear and Holepunch peer-to-peer
applications. It stores and serves encrypted Hyperdrive data that it can
verify but cannot read, helping applications remain reachable while their
publishers and users are offline.

The Runtipi package persists the relay identity, configuration, Hypercores,
and seeded content. A unique management key is generated during installation,
and incoming seed requests default to operator review.

Keep the dashboard on a trusted network. If you expose it to the internet,
place it behind an authenticating reverse proxy.
