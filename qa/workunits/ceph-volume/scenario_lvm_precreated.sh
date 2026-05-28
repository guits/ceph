#!/usr/bin/env bash
# Bluestore on administrator-precreated LVs (ceph-volume lvm prepare), then cephadm deploy.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

FSID=$(ceph fsid)
CONFIG=/etc/ceph/ceph.conf
KEYRING=/etc/ceph/ceph.client.admin.keyring
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-precreated"
mkdir -p "$TMPDIR"

OSD_VG_NAME="ceph-volume-precreated"
OSD_LV_NAME="data"
OSD_IMAGE_SIZE=$((10 * 1024 * 1024 * 1024))
OSD_IMAGE="${TMPDIR}/osd.img"

dd if=/dev/zero of="$OSD_IMAGE" bs=1 count=0 seek="$OSD_IMAGE_SIZE"
loop_dev=$(sudo losetup -f)
sudo vgremove -f "$OSD_VG_NAME" 2>/dev/null || true
sudo losetup "$loop_dev" "$OSD_IMAGE"
sudo pvcreate -y "$loop_dev"
sudo vgcreate -y "$OSD_VG_NAME" "$loop_dev"
sudo lvcreate -l 100%VG -n "${OSD_LV_NAME}.0" "$OSD_VG_NAME"
device_name="/dev/${OSD_VG_NAME}/${OSD_LV_NAME}.0"

cephadm shell --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- \
    ceph auth get client.bootstrap-osd > "${TMPDIR}/keyring.bootstrap.osd"

CEPH_VOLUME="cephadm ceph-volume --fsid ${FSID} -c ${CONFIG} -k ${TMPDIR}/keyring.bootstrap.osd --"

$CEPH_VOLUME lvm prepare --bluestore --data "$device_name" --no-systemd
$CEPH_VOLUME lvm batch --no-auto "$device_name" --yes --no-systemd

$CEPH_VOLUME lvm list --format json "$device_name" > "${TMPDIR}/osd.map"
osd_id=$(jq -cr '.. | ."ceph.osd_id"? | select(.)' "${TMPDIR}/osd.map" | head -1)
osd_fsid=$(jq -cr '.. | ."ceph.osd_fsid"? | select(.)' "${TMPDIR}/osd.map" | head -1)

jq --null-input \
    --arg fsid "$FSID" \
    --arg name "osd.${osd_id}" \
    --arg keyring "${TMPDIR}/keyring.bootstrap.osd" \
    --arg config "$CONFIG" \
    --arg osd_fsid "$osd_fsid" \
    '{"fsid": $fsid, "name": $name, "params":{"keyring": $keyring, "config": $config, "osd_fsid": $osd_fsid}}' | \
    cephadm _orch deploy

wait_for_osds_up 1
ceph orch ps | grep "osd.${osd_id}" | grep -q running
ceph osd tree | grep -q "osd.${osd_id}"
