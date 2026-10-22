# Server Hands

Phone-approved LUKS unlock for an OpenMediaVault 8 homelab.

The server boots with its encrypted drives locked. You open the Android app, confirm with a biometric, and the app sends the drive passphrases, end-to-end encrypted, to the server. The server unlocks and mounts the drives, refreshes the mergerfs pool and runs your post-unlock scripts (for example to start the Docker containers that need the data).

LAN only: no cloud, no relay, no account.

Status: version 0.4.0. Verified on a real OpenMediaVault 8 server with three LUKS drives, a mergerfs pool and a real phone. See [PLAN.md](PLAN.md) for decisions and open items.

## How it works

```
server boots ── handsd publishes an unlock request (drives stay locked)
phone        ── verifies the pinned server identity, shows the waiting drives
             ── biometric releases the passphrases from the Keystore vault
             ── HPKE-seals them to the request's one-time key, signs with the device key, sends
handsd       ── unlocks via libcryptsetup, mounts through fstab, restarts the mergerfs pool,
                runs `auto` scripts; `manual` scripts appear in the app and can be run from it at any time
```

Security properties in short: pinned TLS plus a pinned Ed25519 server identity (no CA, no trust on first use after pairing), per-request ephemeral keys held in RAM only, single-use nonces, per-use biometric on the phone, a dedicated revocable LUKS keyslot for the phone, no secrets in logs or argv. See [docs/threat-model.md](docs/threat-model.md) and [docs/protocol.md](docs/protocol.md).

## Repository layout

| Path | Contents |
|---|---|
| `server/` | Rust workspace: `handsd` (daemon), `handsctl` (pairing, discovery, keyslots, revoke), `hands-proto` (wire types and crypto), `hands-client` (test client). Packaging (systemd units, config template, `.deb` scripts) in `server/packaging/`. |
| `app/` | Kotlin Multiplatform Gradle build: `core:crypto`, `core:protocol`, `androidApp` (Compose UI, Keystore, QR pairing, minSdk 31). macOS client planned. |
| `protocol/vectors/` | Test vectors that both the Rust and Kotlin implementations must pass. |
| `docs/` | Setup guide, protocol, threat model, apt repository, Android release and signing, test notes. |
| `docs/site/` | The GitHub Pages landing page. |
| `.github/workflows/` | `deb.yml` (tests, `.deb`, signed apt repo, Pages) and `app.yml` (tests, signed APK). |
| `PLAN.md` | Decisions, architecture and phase status. |

## Install the server

Debian 13 / OpenMediaVault 8, amd64, from the signed apt repository (details and key check in [docs/apt-repo.md](docs/apt-repo.md)):

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://mblcdr.github.io/Server-Hands/server-hands.gpg | sudo tee /etc/apt/keyrings/server-hands.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/server-hands.gpg] https://mblcdr.github.io/Server-Hands/ ./" | sudo tee /etc/apt/sources.list.d/server-hands.list
sudo apt update && sudo apt install server-hands
```

Or download the `.deb` from a release and run `sudo apt install ./server-hands_X.Y.Z_amd64.deb`. The service is not enabled automatically.

## Install the app

Download `server-hands_X.Y.Z.apk` from the [GitHub Release](https://github.com/mblcdr/Server-Hands/releases) of the same version (check it against `SHA256SUMS`) and install it on the phone (Android 12+, minSdk 31). It is signed with the project's release key; see [docs/android-release.md](docs/android-release.md) for the signing setup and how to build it yourself. A phone with a strong biometric is required.

## Set it up

The full walkthrough is [docs/homelab-setup.md](docs/homelab-setup.md). The short version:

1. `sudo handsctl discover --write` finds your LUKS drives and writes `/etc/server-hands/config.toml`.
2. `sudo handsctl add-phone-key <luks-uuid>` adds a phone-only keyslot per drive.
3. List the mergerfs mount unit under `[post_unlock] mount_units`, and register scripts as `[[script]]` entries (`mode = "auto"` or `"manual"`).
4. `sudo systemctl enable --now handsd.socket handsd.service`, then `sudo handsctl pair` and scan the QR in the app.
5. Recommended: lower the device timeout so a locked boot does not stall for 90 s (step 8 of the setup guide). On the reference server boot dropped from ~90 s to ~14 s.

### Post-unlock scripts

```toml
[post_unlock]
mount_units = ["srv-mergerfs-Pool.mount"]   # restarted like the OMV mergerfs plugin's "restart pool"

[[script]]
name = "media"
label = "Media containers"
path = "/etc/server-hands/scripts/media.sh"
mode = "auto"          # runs right after the unlock; "manual" shows a Run button in the app
# requires_unlock = false   # manual only: allow running while the drives are still locked (default true)
# requires_confirmation = true   # the app asks "Run media?" first
# biometric_protection = true    # needs a fresh fingerprint/face, checked by the server (replaces the dialog)
```

Scripts run as root in a transient systemd unit (`journalctl -u server-hands-script-media`). They must be owned by root and not writable by others. The phone can only start scripts named in this file. An example is installed at `/usr/share/server-hands/post-unlock-example.sh`. A script can also do something other than start containers, for example a reboot (stop the drive-dependent containers first, then `systemctl --no-block reboot`); note that anyone holding the unlocked phone can start a listed script with one tap unless it sets `requires_confirmation` (a dialog) or `biometric_protection` (a biometric the server verifies; the first protected run registers the phone's approval key, and `sudo handsctl reset-approval-key <device-id>` lets a phone register a new one, for example after its biometrics changed).

## Build and test

Server (Rust stable):
```sh
cd server
cargo test --workspace
packaging/build-deb.sh   # needs Docker; builds the .deb in a Debian 13 container
```

App (JDK 17, Android SDK):
```sh
cd app
./gradlew :androidApp:assembleDebug
./gradlew :core:crypto:jvmTest :core:protocol:jvmTest :androidApp:testDebugUnitTest
```
`InteropTest` runs the Kotlin client against the real daemon with a fake host; build the fixture first with `cargo build -p handsd --example fake_server`. More in [app/README.md](app/README.md).

## Releasing

Pushing a tag `vX.Y.Z` builds the `.deb`, signs the apt repository and publishes it with the landing page to GitHub Pages ([docs/apt-repo.md](docs/apt-repo.md)). The same tag builds the signed Android APK and attaches it to the GitHub Release ([docs/android-release.md](docs/android-release.md), including the one-time signing key and secrets setup). The tag becomes the package version, so keep it in step with the workspace version in `server/Cargo.toml`.

## Recovery

Lost phone: unlock in the OMV GUI with the human passphrase, run `sudo handsctl revoke <device>`, and kill the phone keyslot with `cryptsetup luksKillSlot <dev> <slot>`.

## License

MIT, see [LICENSE](LICENSE).
