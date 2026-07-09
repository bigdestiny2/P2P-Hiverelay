export const short = {
  en_US: 'Keep P2P apps alive — a blind relay for the Pear ecosystem',
}

export const long = {
  en_US:
    'Blindspark is a blind relay for the Pear/Holepunch decentralized app ' +
    'ecosystem. It seeds end-to-end-encrypted Hyperdrives — content the relay ' +
    'cannot read but can verify and serve — so P2P apps stay available while ' +
    'their users are offline.\n\n' +
    'The relay is genuinely "blind": it holds ciphertext blocks and Merkle ' +
    'proofs, never plaintext, and never sees who reads what. By default every ' +
    'incoming seed request waits for your approval ("review" mode); you can ' +
    'switch to auto-accept from the dashboard.\n\n' +
    'The Blindspark dashboard is a single, simple page: your relay\'s name and ' +
    'public key, live online status, connected peers, how many apps it keeps ' +
    'alive, and real measured on-disk usage. Fresh installs start with ' +
    'review-mode seed acceptance and a conservative 10 GB storage cap; saved ' +
    'operator config wins on later restarts. No account, no telemetry, no ' +
    'payment.',
}
