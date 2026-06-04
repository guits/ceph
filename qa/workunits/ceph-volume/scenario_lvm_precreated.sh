#!/usr/bin/env bash
# Use existing scratch LVs, ceph-volume lvm prepare, then cephadm deploy.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

OSD_COUNT="${OSD_COUNT:-2}"

FSID=$(ceph fsid)
CONFIG=/etc/ceph/ceph.conf
KEYRING=/etc/ceph/ceph.client.admin.keyring
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-precreated"
mkdir -p "$TMPDIR"

sudo cephadm shell --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- \
    ceph auth get client.bootstrap-osd > "${TMPDIR}/keyring.bootstrap.osd"

export FSID CONFIG KEYRING TMPDIR
export BOOTSTRAP_KEYRING="${TMPDIR}/keyring.bootstrap.osd"

mapfile -t SCRATCH_DEVICES < <(list_scratch_devices)
if [[ "${#SCRATCH_DEVICES[@]}" -lt "$OSD_COUNT" ]]; then
    echo "need at least ${OSD_COUNT} scratch device(s), found ${#SCRATCH_DEVICES[@]}" >&2
    printf '%s\n' "${SCRATCH_DEVICES[@]}" >&2 || true
    exit 1
fi

for ((i = 0; i < OSD_COUNT; i++)); do
    create_bluestore_lvm_precreated_osd "${SCRATCH_DEVICES[$i]}"
done

wait_for_osds_up "$OSD_COUNT"
sudo ceph osd stat
ceph_volume lvm list
rm -rf "$TMPDIR"
