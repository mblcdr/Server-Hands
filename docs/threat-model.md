# Threat model (draft)

Assets: LUKS passphrases (phone vault, in flight, server RAM during unlock); server identity key; paired-device list.

| # | Threat | Mitigation |
|---|---|---|
| T1 | Attacker on LAN impersonates server (ARP/DNS spoof, rogue AP, replayed old replies) | QR out-of-band trust root; pinned TLS SPKI + pinned Ed25519 identity; fresh client nonce in every signed reply; no TOFU after pairing; no address from mDNS/intents/push |
| T2 | Fake server asks for other drives' passphrases | Vault releases only UUIDs recorded for that server; HPKE info binds server key, req, nonce, device |
| T3 | Network eavesdropper | TLS plus independent HPKE to a per-request ephemeral key (forward secret) |
| T4 | Stolen/unlocked phone | Per-use `BiometricPrompt` + `CryptoObject`, BIOMETRIC_STRONG only, key invalidated on new enrollment; revoke device + kill phone keyslot |
| T5 | Malware on phone | Keystore/StrongBox non-exportable keys; passphrases in memory only briefly as zeroed ByteArray; `FLAG_SECURE`; no backups; overlay protection; no accessibility-visible passphrase text |
| T6 | Secrets leaking via logs/ps/core/swap on server | libcryptsetup (no argv), pipes not files, Secret newtypes, no body logging, `LimitCORE=0`, `PR_SET_DUMPABLE=0`, `MemorySwapMax=0`, `mlockall` (swap is unencrypted) |
| T7 | Replay of a recorded approve | Single-use nonce, request consumed on first decrypt, ephemeral key destroyed, 10-min expiry |
| T8 | Brute force on approve endpoint | Device-signed requests only, rate limit/backoff, constant-shape errors |
| T9 | Rogue pairing | One-time 5-min token, QR only via SSH console, SAS confirmed by operator |
| T10 | Server host compromise (root) | Out of scope: root can read the passphrase during unlock. Limit blast radius with a dedicated phone keyslot |
| T11 | Supply chain | Signed releases, `cargo-deny`, pinned Gradle dependency verification, SBOM, reproducible builds |
| T12 | Phone (or a stolen paired key) used to run arbitrary commands via post-unlock scripts | The phone only names a script from the server's config, never a path or arguments; scripts must be root-owned and not group/world-writable (checked before every run); run requests are device-signed with single-use nonces; scripts only start once all drives are unlocked |
