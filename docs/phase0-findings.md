# Phase 0 findings: openmediavault-luksencryption

Source reviewed: `OpenMediaVault-Plugin-Developers/openmediavault-luksencryption` (shallow clone, HEAD as of 2026-10-19).
Not yet verified on a live OMV 8 box: run `spike/omv-probe.sh`.

## How the plugin unlocks (what we must mirror)

| Step | Plugin behaviour | Source |
|---|---|---|
| Open | `cryptsetup open --type luks[ --allow-discards] <dev> <name>-crypt --key-file=-`, passphrase piped from PHP `echo -n` | `luks/container.inc` `open()` |
| Mapper name | `<kernel name>-crypt`, e.g. `sdb-crypt`. Derived from `/dev/sdX`, so **not stable across boots**. OMV does not rely on it: fstab uses the filesystem UUID of the decrypted device. | `generateDecryptedName()` |
| After open | `udevadm settle --timeout=30` | `open()` |
| LVM inside LUKS | `pvs` -> `vgchange -a y <vg>` -> settle -> `lvs` to find LVs | `openContainer` |
| Mount | If `OMV_LUKS_MOUNT_ON_UNLOCK` (default true) and the fs has an fstab entry (`FsTab getByFsName`): mount via OMV filesystem backend. **systemd may race and mount the fstab entry itself as soon as the device appears**; plugin tolerates this by settling, sleeping 1s and re-checking `isMounted()`. | `mountContainerFS()` |
| Btrfs multi-device | Skips mount until `btrfs filesystem show` reports all devices present | `mountContainerFS()` |
| State | No OMV DB state for "unlocked". Status is derived live (`isOpen()`). So unlocking outside OMV is safe as long as the mapping + mount end up the same. | `enumerateContainers` |

## Existing auto-unlock (relevant alternatives)

The plugin already supports boot auto-unlock via `/etc/crypttab`:
- **keyfile** at `/etc/luks-keys/<luks-uuid>` (0400 root) -> key sits on the unencrypted root disk, defeating encryption. Not what we want.
- **Clevis/Tang/TPM2** (crypttab entry with no keyfile, `clevis-luks-askpass.path`, `_netdev`, `remote-cryptsetup.target`).

Our service is a third path: **manual, phone-approved unlock**. Our drives must therefore have **no crypttab entry** (otherwise systemd tries to prompt at boot). `handsctl discover` should warn if one exists.

## Consequences for the design

1. **Never call `omv-rpc ... openContainer` with the passphrase in argv.** The RPC takes `passphrase` as a JSON parameter on the command line (`omv-rpc -u admin LuksMgmt openContainer '<json>'`), visible in `/proc/<pid>/cmdline` and `ps` to any local user. Even the plugin's own `cryptsetup` pipeline passes the secret through `escapeshellarg` in a shell command line (`echo -n <secret> | cryptsetup`), also exposed in argv. We must not copy that.
2. **Use libcryptsetup directly** (`crypt_init`, `crypt_load`, `crypt_activate_by_passphrase`) with the same mapper name scheme, same flags (`--allow-discards` if the user chose it; default off), so the result is indistinguishable from a GUI unlock.
3. **Then replicate the post-steps in Rust:**
   - wait for udev (`udevadm settle` via fork/exec with a fixed argv, no secrets, or poll for `/dev/disk/by-uuid/<fs-uuid>`),
   - LVM: `vgchange -a y` if the decrypted device is a PV,
   - mount: let systemd's fstab-generated unit do it (`systemctl start <escaped mount unit>`), fall back to `mount <mountpoint>` if absent. Handle the btrfs multi-device rule by waiting for all member containers first.
4. **Optional cleaner path to investigate on the box:** `omv-rpc` with `keyfile` param pointing at a root-only tmpfs path or `/proc/self/fd/N`. Avoids argv exposure while reusing all of OMV's logic (LVM, btrfs, notifications). Needs `format: devicefile`/path validation check and a secure unlink. Cost: spawns PHP (about 30-60 MB transient RSS), which conflicts with the "light" goal, though only for a few seconds per unlock. Decide after the probe. Default: libcryptsetup.
5. **Mapper name collision:** `<kernel-name>-crypt` already exists if the user unlocked from the GUI -> treat `EEXIST`/already-active as success (idempotent).
6. **Request creation at boot:** enumerate containers (`cryptsetup isLuks` over `lsblk`), skip those with crypttab entries or already active, create one request listing LUKS UUID + label + size (never the kernel name as identity).
7. **Ordering:** since fstab entries are `nofail` and systemd mounts on device appearance, dependent host services should use `RequiresMountsFor=` / `After=hands-unlocked.target` drop-ins; Docker bind mounts need `create_host_path: false`.
8. **Key hygiene suggestion:** `cryptsetup luksAddKey` a dedicated high-entropy phone keyslot per container so the phone credential is independently revocable (`luksKillSlot`). The plugin has `addContainerKey` / `killContainerKeySlot` in the GUI for this.

## Open items for the live-box probe

- Does `omv-rpc -h` allow params from stdin/file?
- Are fstab entries for the encrypted filesystems `nofail`? (expected: yes)
- Docker root dir location (must not be on a LUKS drive).
- cryptsetup/libcryptsetup versions on OMV 8 (Debian 13); LUKS2 argon2 memory cost matters: **argon2id uses up to ~1 GiB per unlock by default**, and this runs inside our service. `MemoryMax` must allow for that during unlock only (or run the activation in a short-lived child process with its own cgroup limit), otherwise the "light" daemon gets OOM-killed on unlock.
- Whether any drives are already in crypttab.

---

# Probe results (a live OMV 8 test server, 2026-10-19)

| Item | Result | Impact |
|---|---|---|
| OS / OMV | Debian 13, OMV 8.5.12, luksencryption 8.1.6, cryptsetup/libcryptsetup 2.7.5, systemd 257 | libcryptsetup12 FFI is fine; x86_64 glibc, so a normal `.deb` (no musl needed) |
| RAM | A typical homelab box; swap is an **unencrypted partition** | argon2id's ~1 GiB is not a concern. Swap is: set `MemorySwapMax=0`, `mlockall`, never swap secrets |
| LUKS drives | 3x LUKS2, each with 1 keyslot (labels `Disk-1` to `Disk-3`) | Request lists these by LUKS UUID + label |
| crypttab | Empty (comments only), no `/etc/luks-keys` | No conflicting auto-unlock |
| fstab | 3 OMV ext4 entries on `/dev/disk/by-uuid/...` with `nofail`, plus an unencrypted data disk | Matches plugin behaviour, ext4 directly on LUKS (no LVM/btrfs), so post-unlock logic stays simple |
| mergerfs | `srv-mergerfs-Pool.mount` exists and is **inactive** | After all branch mounts are up, handsd must explicitly start the pool mount |
| Docker | data-root on the unencrypted root disk; containers were running with the data drives locked | Good: Docker does not depend on LUKS. But containers are starting against empty mountpoints |
| `omv-rpc` | `[params]` argv only, no stdin/file option | Confirmed: do not use it for the passphrase. libcryptsetup directly |
| Boot | `network-online.target` at 1m30s; `local-fs.target` also at ~1m30s | Suspect 90 s default device timeout on the 3 missing `/dev/disk/by-uuid` fstab devices. See below |

## Decisions from the results

1. **Docker/services gating** (superseded in Phase 4: not gated; post-unlock `[[script]]` entries start the containers that need the drives, see `homelab-setup.md`). Add a drop-in so `docker.service` (and `docker.socket`) only start after unlock: `ConditionPathExists=/run/server-hands/unlocked`; handsd then runs `systemctl start` on a configurable `post_unlock_units` list (e.g. `docker`, `smbd`, `nfs-server`, the mergerfs `srv-mergerfs-Pool.mount`). This is simpler and more robust than blocking boot jobs. Trade-off: all containers (even ones that only use root-disk data) wait for the unlock. Per-container gating is a later option.
2. **Post-unlock order:** activate every approved container -> wait for each `/dev/disk/by-uuid/<fsuuid>` -> start matching `srv-dev-disk-by-uuid-*.mount` (or accept if systemd already mounted) -> start `srv-mergerfs-Pool.mount` -> start `post_unlock_units`. The mapping from container -> fs UUID is learned after activation, not configured.
3. **One biometric prompt for all drives.** Store all passphrases for a server in a single AEAD blob under one Keystore key, so one `BiometricPrompt` + one `Cipher.doFinal` yields all three. Per-drive AAD is still enforced inside the blob structure. Do not create one key/blob per drive (that would mean three prompts).
4. **Boot delay.** Verify with `systemd-analyze blame`. If it is the missing-device timeout, mitigate with `DefaultDeviceTimeoutSec=10s` in `/etc/systemd/system.conf.d/`. Do not edit OMV-managed fstab. Independently, give `handsd.service` `DefaultDependencies=no` + `After=systemd-udevd.service network.target` so the request exists as soon as the NIC is up, and bind via socket activation on all addresses (`FreeBind`) so DHCP timing does not matter.
5. **Dedicated phone keyslot:** each drive has exactly one keyslot today. Setup docs: `cryptsetup luksAddKey` a long random passphrase per drive (or one shared) to use as the phone credential. The existing human passphrase stays as recovery. Keep the Android vault holding only the phone credentials.
6. **Unencrypted swap:** also disable hibernation, and make the unlock path a separate short-lived child with `mlockall` and `MemorySwapMax=0`.

## Update: boot delay confirmed (2026-10-19)

The ~90 s boot delay is the default device timeout on the locked encrypted fstab devices. The same timeout cascades into the mergerfs mount failing during boot (its branches are not there yet). Consequences:
- `handsd.service` already uses `DefaultDependencies=no` and does not wait for `local-fs.target`, so the unlock request exists as soon as the network is up.
- Ship the optional `system.conf.d/10-server-hands.conf` (`DefaultDeviceTimeoutSec=10s`) to cut the delay.
- The mergerfs failure at boot is expected and harmless; handsd starts the pool mount after unlock. If systemd marks it `failed`, handsd must `systemctl reset-failed` before starting.

Phase 4 result (2026-10-21): with `DefaultDeviceTimeoutSec=10s` the first device timeouts land at ~12.8 s and boot finishes at ~14 s of userspace (was ~90 s). Later retries of the same mounts (every ~20 s to ~80 s) do not delay boot.
