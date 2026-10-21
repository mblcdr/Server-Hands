#!/bin/bash
# Phase 0 read-only probe for server-hands. Run as root on the OMV box:
#   sudo bash omv-probe.sh | tee omv-probe.txt
# Collects NO secrets: no passphrases, no key material, no config.xml.
# Review the output before sharing it.
set -u
sec() { printf '\n===== %s =====\n' "$1"; }

sec "OS / kernel / OMV"
cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID)='
uname -r
dpkg-query -W -f='${Package} ${Version}\n' openmediavault openmediavault-luksencryption cryptsetup \
  cryptsetup-bin libcryptsetup12 systemd udev clevis 2>&1 | grep -v 'no packages'

sec "Memory / arch"
uname -m; free -m | head -2

sec "Block devices (LUKS)"
lsblk -o NAME,KNAME,TYPE,FSTYPE,UUID,LABEL,SIZE,MOUNTPOINTS
echo; for d in $(lsblk -pnro NAME); do
  cryptsetup isLuks "$d" 2>/dev/null && echo "LUKS: $d uuid=$(cryptsetup luksUUID "$d") ver=$(cryptsetup luksDump "$d" | awk '/^Version:/{print $2}')"
done

sec "Active mappings (names only)"
dmsetup ls --target crypt 2>/dev/null
ls -l /dev/mapper

sec "/etc/crypttab (keyfile column only shows paths, not contents)"
cat /etc/crypttab 2>&1
ls -ld /etc/luks-keys 2>&1

sec "/etc/fstab"
cat /etc/fstab

sec "Mount units for OMV data mounts"
systemctl list-units --type=mount --all --no-legend 'srv-*' 2>&1

sec "OMV env overrides"
grep -rn "OMV_LUKS" /etc/default/openmediavault /etc/default/ 2>/dev/null

sec "Docker data-root and compose paths"
docker info --format '{{.DockerRootDir}}' 2>&1
findmnt -T "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)" -o TARGET,SOURCE,FSTYPE

sec "Services that may depend on data mounts"
systemctl list-unit-files --no-legend | grep -E '^(docker|containerd|smbd|nfs-server|nmbd|proftpd|rsync|minidlna|openmediavault-engined)' 

sec "omv-rpc availability / enumerate (read-only)"
omv-rpc -u admin LuksMgmt enumerateContainers '{}' 2>&1 | head -50

sec "Can omv-rpc read params from stdin? (help text only)"
omv-rpc -h 2>&1 | head -30

sec "Boot ordering: when does network come up relative to local-fs"
systemd-analyze critical-chain network-online.target 2>&1 | head -15

sec "systemd-cryptsetup udev behaviour (does udev create /dev/mapper nodes?)"
systemctl is-active systemd-udevd
echo "DONE"
