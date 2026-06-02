#!/usr/bin/env bash
# Zap scratch devices (Teuthology roleless-style), create Bluestore LVM OSDs via ceph-volume.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

OSD_COUNT="${OSD_COUNT:-2}"

FSID=$(ceph fsid)
CONFIG=/etc/ceph/ceph.conf
KEYRING=/etc/ceph/ceph.client.admin.keyring
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-bluestore-lvm"
mkdir -p "$TMPDIR"

sudo cephadm shell --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- \
    ceph auth get client.bootstrap-osd > "${TMPDIR}/keyring.bootstrap.osd"

export FSID CONFIG KEYRING TMPDIR
export BOOTSTRAP_KEYRING="${TMPDIR}/keyring.bootstrap.osd"

zap_all_scratch_devices
ceph orch device ls --refresh

mapfile -t SCRATCH_DEVICES < <(list_scratch_devices)
if [[ "${#SCRATCH_DEVICES[@]}" -lt "$OSD_COUNT" ]]; then
    echo "need at least ${OSD_COUNT} scratch device(s), found ${#SCRATCH_DEVICES[@]}" >&2
    printf '%s\n' "${SCRATCH_DEVICES[@]}" >&2 || true
    exit 1
fi

for ((i = 0; i < OSD_COUNT; i++)); do
    create_bluestore_lvm_osd "${SCRATCH_DEVICES[$i]}"
done

wait_for_osds_up "$OSD_COUNT"
ceph osd stat
ceph_volume lvm list
rm -rf "$TMPDIR"