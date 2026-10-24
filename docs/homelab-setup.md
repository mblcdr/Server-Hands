# Homelab setup (draft, finalised in Phase 4)

1. BIOS: Restore on AC power loss = Power On; enable Wake-on-LAN. DHCP reservation for the server.
2. Install the package, either from the apt repository (preferred, gives upgrades: see `apt-repo.md`) or from a downloaded file: `sudo apt install ./server-hands_X.Y.Z_amd64.deb`
3. `sudo handsctl discover --write`, then review labels and the `[post_unlock]` lists in `/etc/server-hands/config.toml`. Drives with an `/etc/crypttab` entry are skipped and reported.
4. Add a phone-only keyslot per drive (you will be prompted for the existing passphrase; the new one is generated and shown once for entry into the app):
   `sudo handsctl add-phone-key <luks-uuid>` (libcryptsetup directly; the existing passphrase is read from the tty, nothing goes through argv)
5. Post-unlock actions. Docker and the other services are **not** gated: they start at boot as usual. Containers that need the encrypted drives are started by scripts instead, so containers that only use the root disk are unaffected.
   - Stop the dependent containers from starting at boot, so they do not come up on empty mount points: set `restart: "no"` in their compose files (or `docker update --restart=no <container>`) so the script is the only thing that starts them.
   - Put the commands in a script, e.g. start from `/usr/share/server-hands/post-unlock-example.sh`:
     ```
     sudo install -d -m 0755 /etc/server-hands/scripts
     sudo install -m 0755 /usr/share/server-hands/post-unlock-example.sh /etc/server-hands/scripts/media.sh
     sudo nano /etc/server-hands/scripts/media.sh
     ```
     It must be owned by root and not writable by anyone else (its directory too), and must not be under `/home`. handsd refuses to run it otherwise.
   - Register it in `/etc/server-hands/config.toml`:
     ```
     [[script]]
     name = "media"
     label = "Media containers"
     path = "/etc/server-hands/scripts/media.sh"
     mode = "auto"      # runs right after the unlock; "manual" = only when you tap Run in the app
     ```
     Manual scripts do not have to be about the unlock: add `requires_unlock = false` to one (a status check, a service restart, a reboot) and the app can run it at any time, even while the drives are locked. Without it a manual script is refused until every drive is unlocked.

     For dangerous scripts (a reboot, say) add `requires_confirmation = true` (the app asks "Run X?") or `biometric_protection = true` (the phone must produce a fresh fingerprint/face, which the server checks with a challenge it issues; the biometric prompt then replaces the dialog). The first protected run registers the phone's approval key automatically. If the phone's biometrics change, the key is destroyed; run `sudo handsctl reset-approval-key <device-id>` (ids from `handsctl devices`) and the phone registers a new one on its next protected run.
     Scripts run as root in a transient unit, in the order listed, after the pool is refreshed. A non-zero exit or the `timeout_secs` limit (default 300) shows as "failed" in the app. Output: `journalctl -u server-hands-script-media`.
   - Test it without a reboot: `sudo systemctl restart handsd`, unlock (or, with the drives already open, handsd runs `auto` scripts at startup), then check the app's "Scripts" card.
   - The mergerfs pool: list its mount unit in `mount_units`. To get the value (run these with the drives unlocked and the pool mounted):
     ```
     findmnt -t fuse.mergerfs -o TARGET,SOURCE          # the pool's mount point, e.g. /srv/mergerfs/Pool
     systemd-escape --path --suffix=mount /srv/mergerfs/Pool    # its unit name: srv-mergerfs-Pool.mount
     systemctl list-units --type=mount | grep -i mergerfs        # confirm that unit exists
     ```
     If `findmnt` prints nothing, the pool is not mounted; the pool's name is on the OMV web UI's Storage > Union Filesystems page, and the mount point is `/srv/mergerfs/<name>` (check with `ls /srv/mergerfs`). Then put the unit name in the config:
     ```
     [post_unlock]
     mount_units = ["srv-mergerfs-Pool.mount"]
     ```
     The same list feeds the pool bar in the app, so a wrong name shows as "Not mounted" there. After the drives are mounted handsd runs `systemctl restart` on it, exactly as the OMV mergerfs plugin's "restart pool" action does. If something holds the pool open (a running container or Samba), the restart can fail with "target is busy"; keep those out of boot, or start them from a script.
   - `service_units` takes plain systemd unit names (`systemctl list-unit-files | grep -i smb` finds them, e.g. `smbd.service`); they are started without waiting after the unlock. Prefer a script for containers.
   - Optional hard gating of a systemd service (the old approach): `sudo install -D -m644 /usr/share/server-hands/gated-service.conf /etc/systemd/system/<unit>.d/server-hands.conf`, add the unit to `service_units`.
6. `sudo systemctl enable --now handsd.socket handsd.service`, then run `systemd-analyze security handsd.service` and expect an exposure of 3.0 or lower.
7. `sudo handsctl pair`, scan the QR in the app, confirm the 6-digit code on both sides.
8. Shorter boot delay (optional, recommended). The locked drives' fstab entries make systemd wait for their devices for the default 90 s before giving up, which stalls boot. Lower the default device timeout:
   ```
   sudo install -D -m644 /usr/share/server-hands/10-server-hands.conf /etc/systemd/system.conf.d/10-server-hands.conf
   sudo systemctl daemon-reexec     # or just reboot
   ```
   This sets `DefaultDeviceTimeoutSec=10s` in `[Manager]`. It is global (every device wait in fstab, also USB or network disks), so use a larger value if you have slow-appearing disks. OMV regenerates `/etc/fstab`, so per-entry `x-systemd.device-timeout=` options would be overwritten; the global setting survives. Check the effect after a reboot with `systemd-analyze blame | head` and `systemd-analyze critical-chain`. To undo: delete the file and `systemctl daemon-reexec`.
9. Reboot, open the app, approve. Check the OMV GUI shows the drives unlocked and mounted.

Recovery (lost phone): unlock in the OMV GUI with the human passphrase; `sudo handsctl revoke <device>`; `cryptsetup luksKillSlot <dev> <slot>`.

## Troubleshooting a failing script

The app only shows "failed"; the reason is in the server's journal. Replace `media` with the script's `name`:

```sh
# the script's own output and exit status
journalctl -u server-hands-script-media -n 100 --no-pager

# handsd's verdict ("script media ok/failed") and refusals
journalctl -u handsd -n 50 --no-pager | grep -i script
```

What "failed" can mean:

- **The script exited non-zero.** The cause is in `server-hands-script-<name>`. The unit is transient and removed after it finishes, so use the journal rather than `systemctl status`.
- **It hit `timeout_secs`** (default 300). The unit's journal shows it was stopped at the runtime limit; raise `timeout_secs` (up to 3600) or make the script faster.
- **handsd refused to run it.** The file must be executable, owned by root and not writable by group or others, and so must its directory. There is no script unit then; the reason is in the `handsd` journal as `handsd: script <name> refused: ...`.
- **`systemd-run` could not start the unit.** Only `script <name> failed` appears in the `handsd` journal and there is no unit log. Run the script by hand to see whether it starts at all.

Reproduce it by hand with the same variable handsd sets:

```sh
sudo SERVER_HANDS_TRIGGER=manual /etc/server-hands/scripts/media.sh
```

Your shell's environment is richer than the transient unit's, so a failure that only happens under handsd is usually a missing `PATH` entry or `HOME`. Put `set -x` at the top of the script to log every command to the journal.

A script that is refused with "needs the drives unlocked first" has `requires_unlock = true` (the default); see the script options above. A protected script that the app cannot approve is covered by `biometric_protection`: after a biometrics change run `sudo handsctl reset-approval-key <device-id>`.
