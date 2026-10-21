# Phase 2: what is verified, and the on-box checklist

## Verified off-box (macOS, `cargo test --workspace`)

- Protocol state machine (14 tests), vectors (Rust), config/LUKS-header/crypttab/fstab/ext4-superblock parsers.
- `handsd` end to end over real TLS 1.3 with pinned SPKI (5 tests, `crates/handsd/tests/e2e.rs`): pairing with matching SAS on both sides and operator reject, wrong token, list, approve, wrong passphrase gives a fresh request with a fresh ephemeral key, replay of a consumed request, unpaired device, wrong TLS pin, revocation, post-unlock hook runs once all drives are open.
- Unlock child protocol (stdin plaintext in, per-drive results out; unreported drives fail closed).
- `handsctl` pair/status/devices against a live `handsd`, with `hands-client` as the phone stand-in.
- `.deb` metadata and asset paths (`cargo deb --no-build`, throwaway package, not shipped).

## Not run yet (needs the OMV box or a Debian 13 VM / Docker daemon)

| Item | How |
|---|---|
| Linux build + tests | `server/packaging/build-deb.sh` (Debian 13 container; Docker daemon was not running here) |
| libcryptsetup unlock (dlopen path, `-EPERM` / `-EEXIST` mapping) | loop-device test below |
| `systemd-run --pipe` unlock child, and that the sandboxed daemon may call it with only `CAP_IPC_LOCK` | loop-device test; if it fails, widen `CapabilityBoundingSet` or set `unlock_wrapper = []` plus `CAP_SYS_ADMIN` |
| `systemd-analyze security` exposure <= 3.0 | `server/packaging/check-security.sh` |
| fstab mount via `systemctl start <mountpoint>`, mergerfs, gated services | Phase 4 on the real box |

## Loop-device test (safe, no real drives)

```sh
truncate -s 64M /root/t.img
cryptsetup luksFormat --type luks2 /root/t.img          # passphrase: test
L=$(losetup -f --show /root/t.img)
cryptsetup open $L t && mkfs.ext4 /dev/mapper/t && cryptsetup close t
udevadm settle; cryptsetup luksUUID $L                  # note the UUID, check /dev/disk/by-uuid/<uuid> exists
apt install ./server-hands_*.deb
handsctl discover --write                               # lists the loop container
systemctl enable --now handsd.socket handsd.service
handsctl pair                                           # scan nothing: copy the hands:// URL
hands-client pair 'hands://pair?...'                    # confirm the code in handsctl
hands-client list
printf 'test\n' | hands-client approve <uuid>           # expect: <uuid>  ok
ls /dev/mapper; journalctl -u handsd | grep -i test     # mapper exists; the passphrase appears nowhere
printf 'wrong\n' | hands-client approve <uuid>          # on a second locked container: bad_passphrase + new request
```
`hands-client` is not packaged; build it with `cargo build --release -p hands-client` and copy it over.
