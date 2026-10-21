# Server Hands: implementation plan

Phone-approved LUKS unlock for an OpenMediaVault 8 homelab.
At boot, a tiny host service publishes an unlock request. The user opens an Android app, authenticates with a biometric bound to the Android Keystore, and the app sends the drive passphrases end-to-end encrypted to the server, which unlocks and mounts the drives and starts dependent services.

Status (2026-10-21): Phases 1 to 4 done. Phase 4 was run on the real server: three drives unlock from the phone, the mergerfs pool refreshes, post-unlock scripts run, and the boot delay is cut from ~90 s to ~14 s. Release engineering is in place: signed apt repository and signed Android APK built by GitHub Actions, R8-minified release build, MIT license. Phase 5 (hardening) is partly started (release signing, R8, dependency verification). Toolchains: Rust stable, JDK 17, Gradle 9.8 wrapper, Kotlin 2.4.21. Current version: 0.2.0.

## Decisions (final)

| Topic | Decision |
|---|---|
| Server packaging | Native **systemd service in a signed `.deb`**. Docker was evaluated and rejected: unlock+mount needs `SYS_ADMIN`, block devices, mount propagation and a loosened AppArmor profile, which is root-equivalent with less isolation and extra udev hacks. |
| Server language | **Rust** (tokio current-thread, hyper, rustls/ring, libcryptsetup loaded via dlopen so the build needs no dev package; logging is plain stderr to journald, no tracing crate). Target <8 MB RSS idle (`MemoryMax` for the daemon ~24 MB). |
| Unlock | libcryptsetup directly, in a short-lived child started with `systemd-run --pipe` (own cgroup with `MemoryMax=1536M`, `mlockall`; passphrases go over its stdin as the normative plaintext, so the daemon itself keeps `MemoryMax=32M` and only `CAP_IPC_LOCK`). **Never** `omv-rpc` or the `cryptsetup` CLI with the passphrase (argv is visible in `ps`; `omv-rpc` has no stdin option, confirmed on the box). |
| Network | LAN only. No WireGuard/Tailscale/relay in v1. |
| App | Kotlin Multiplatform, Compose Multiplatform. **Android first (minSdk 31)**, macOS later as **Compose Desktop (JVM)**. Both clients are JVM, so crypto lives in a shared `jvmCommon` source set. |
| Root disk | Unencrypted (Docker data-root is on it too). |
| Drives | 3x LUKS2 (Disk-1, Disk-2, Disk-3), ext4 on LUKS, fstab entries `nofail`, no crypttab entries. mergerfs pool `Pool` on top. |

## Architecture

```
OMV boot
  └─ handsd.service (Rust; DefaultDependencies=no, after udev + network.target; socket-activated listener, FreeBind)
       ├─ enumerate LUKS containers (UUID, label, size); skip active ones or ones with a crypttab entry
       ├─ per request: ephemeral X25519 keypair held in RAM only
       └─ serve:  pairing, list requests, approve request (TLS, pinned key)

Phone (app opened)
  ├─ verify server (pinned Ed25519 identity + pinned TLS SPKI + fresh client nonce)
  ├─ show host fingerprint + drive names/labels
  ├─ BiometricPrompt(CryptoObject(Cipher)) -> decrypt ONE vault blob (all drive passphrases)
  └─ HPKE-seal passphrases to the request's ephemeral key, sign with StrongBox device key, POST

handsd on approve
  ├─ verify device signature and request freshness, HPKE-open, zeroize ephemeral key
  ├─ fork unlock child: crypt_activate_by_passphrase per drive (mapper name <kernel>-crypt, same as plugin)
  ├─ wait for /dev/disk/by-uuid/<fsuuid> -> start srv-dev-disk-by-uuid-*.mount (or accept if systemd did)
  ├─ start srv-mergerfs-Pool.mount
  ├─ restart the mergerfs pool mount (like the OMV plugin's "restart pool"); touch /run/server-hands/unlocked
  ├─ run `auto` post-unlock scripts (root, transient unit); `manual` ones are listed in the app and started from there
  └─ zeroize, report per-drive result to the app (no secrets in the response)
```

## Security properties

1. **No server impersonation.** Trust root is the QR shown on the server console over SSH, scanned in-app. After that the app talks only to the pinned identity: pinned TLS SPKI (no CA store), every reply signed by the pinned Ed25519 key and bound to a fresh client nonce. mDNS, push, intents and deep links never supply an address or key. A changed server key hard-fails until re-paired.
2. **A rogue server can't obtain a decryptable payload.** HPKE `info` binds server-key hash, request id, client nonce and device id. The vault releases a passphrase only for LUKS UUIDs recorded at pairing for that server.
3. **Forward secrecy.** Per-request ephemeral server key lives only in memory and is destroyed after use; stolen server disk or recorded traffic reveals nothing.
4. **Replay resistance.** Single-use request id + nonce, 10-minute expiry, signed approve message.
5. **Device authentication.** Server accepts approvals only from paired device keys (ECDSA P-256 in StrongBox when available). Revocable with `handsctl revoke`.
6. **Phone vault.** One AES-256-GCM Keystore key, StrongBox-preferred, `setUserAuthenticationRequired` with timeout 0 and `AUTH_BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`, attestation checked at creation. Each decrypt is a `BiometricPrompt` with a `CryptoObject`; no device-credential fallback. Passphrases are `ByteArray`s, zeroed after use, never `String`, never logged.
7. **No secret in logs.** Secret newtypes without `Debug`/`Display`; no request-body logging; core dumps off; `PR_SET_DUMPABLE=0`; `MemorySwapMax=0` and `mlockall` because the swap partition is unencrypted. CI canary test greps journal/logs/strace/core for a known passphrase.
8. **Revocable phone credential.** Each LUKS drive gets a dedicated random keyslot for the phone (`luksAddKey`). The human passphrase stays as recovery; the phone slot can be killed independently.

Residual risk (accepted): root on the live server can read the passphrase during unlock.

## Homelab changes

1. BIOS: restore power on AC loss, Wake-on-LAN; DHCP reservation for the server.
2. Install: `sudo apt install ./server-hands_X.Y.Z_amd64.deb`, then `sudo handsctl discover` (writes `/etc/server-hands/config.toml`), `sudo handsctl pair`.
3. Add phone keyslot to each drive (documented in `docs/homelab-setup.md`).
4. **Post-unlock scripts instead of gating.** Docker and other services are not gated. `[[script]]` entries in the config run as root (transient unit) after the pool is refreshed: `auto` ones right after the unlock, `manual` ones from the app's "After unlock" card. The phone can only name a configured script. The pool mount is restarted like the OMV mergerfs plugin's "restart pool" (`systemctl restart <mount unit>`).
5. `DefaultDeviceTimeoutSec=10s` drop-in for the ~90 s boot delay (documented in `docs/homelab-setup.md`).
6. Firewall: allow only the handsd port from the LAN.
7. Reboot test, and a documented recovery procedure (lost phone: unlock via OMV GUI with the human passphrase, `handsctl revoke`, `luksKillSlot`).

## Repository layout

```
PLAN.md
README.md, LICENSE (MIT)
.github/workflows/  deb.yml (server package + apt repo + Pages), app.yml (tests + signed APK)
docs/        phase0-findings.md, protocol.md, threat-model.md, homelab-setup.md, apt-repo.md, android-release.md, phase2-box-test.md, phase3-device-test.md
docs/site/   GitHub Pages landing page template
spike/       omv-probe.sh
server/      Cargo workspace: hands-proto (messages + crypto), handsd, handsctl, hands-client (test client)
  packaging/ systemd units, drop-ins, config template, example post-unlock script, debian maintainer scripts, build-deb.sh, check-security.sh
app/         Gradle KMP: core:crypto, core:protocol, core:data, feature:*, androidApp, desktopApp
```

## Phases

| # | Phase | Exit criteria |
|---|---|---|
| 0 | Spike (done: source review + probe) | findings doc; remaining: confirm boot delay cause; live-box proof that libcryptsetup activate -> systemd mount shows "unlocked" in OMV GUI |
| 1 | Protocol (**done**) | `docs/protocol.md` normative encodings; `protocol/vectors/v1.json` (+ `v1-kotlin.json`) pass in Rust and Kotlin, both seal directions; 20 negative vectors; server request state machine with 14 tests (replay, expiry, rogue server key, lockout, revoked device) |
| 2 | Server MVP (**done**) | `handsd`/`handsctl`/`hands-client`; real unlock of a LUKS container from the test client verified on the box; `systemd-analyze security` 1.9 (target <= 3.0); `.deb` built with `build-deb.sh` |
| 3 | Android MVP (**done**) | pairing, vault, biometric flow, requests list, approve; verified on a real phone: pair, save passphrase, biometric unlock of a test container; interop and Keystore signing also covered by automated tests. Not yet run on a phone: the instrumented Keystore property tests (`connectedDebugAndroidTest`) and a StrongBox check |
| 4 | Full homelab flow (**done**) | verified on the real server: 3 drives, mergerfs pool refresh, post-unlock scripts (auto and from the app), `DefaultDeviceTimeoutSec=10s` (boot ~14 s, first device timeouts at ~12.8 s), reboot test, recovery docs. Gating of Docker and services was dropped in favour of scripts |
| 5 | Hardening (**started**) | done: signed apt repo, signed APK in CI, R8 minify checked by instrumented tests on an emulator, Gradle dependency verification. Open: fuzzing, `cargo-deny`/`cargo-audit`, canary leak test, reproducible builds, SBOM |
| 6 | macOS | Compose Desktop; Keychain/Secure Enclave via `expect/actual`; Touch ID with a Secure Enclave key |

## Open items

- ~~Confirm cause of the ~90 s boot delay~~: confirmed, and fixed by `DefaultDeviceTimeoutSec=10s`.
- Something (probably OMV's monit filesystem checks) retries the locked drives' mount units every ~20 s to ~80 s after boot, each retry waiting 10 s and logging a timeout. Harmless and after boot is finished; unconfirmed cause (`journalctl -b -o short-monotonic | grep -iE "monit|Mounting /srv"`).
- Manual scripts have no confirmation or biometric on the phone: one tap runs them (the device key signs without a prompt). Consider a per-script `confirm = true` (dialog) and/or a biometric option, especially for a reboot script.
- Shutdown order: Docker and Samba have no ordering against the drives' mounts, so a reboot can unmount under running containers. The documented mitigation is a stop-first script (stop the drive-dependent compose projects with a long grace period, `sync`, then reboot); an `After=` drop-in is the alternative.
- Android release APK not yet run on a phone end to end (Compose UI, QR scan, biometric prompt, StrongBox are not covered by the emulator tests). The instrumented Keystore tests skip on the emulator (no biometric/StrongBox).
- Decide notification story for "a request is waiting" on a LAN-only setup: v1 is open-the-app; optional ntfy/UnifiedPush ping later (content-free).
- ~~HPKE provider~~: decided and shipped, BouncyCastle lightweight API, bundled.
- ~~Navigation~~: decided, no navigation library for the MVP (one screen plus dialogs, state in a ViewModel). Revisit if Phase 6 desktop needs more screens.
- Phase 3 deviations from the layout above: no `core:data`/`feature:*` modules (their code lives in `androidApp` and `core:protocol` for now), HTTP client is `HttpsURLConnection` with a pinning trust manager instead of Ktor (fewer dependencies, same pinning), QR scanning via `zxing-android-embedded`.
