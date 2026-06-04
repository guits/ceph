#!/usr/bin/env bash
# Zap scratch devices, create Bluestore LVM OSDs, zap/redeploy, verify.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

OSD_STORE=lvm
export OSD_STORE
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-bluestore-lvm"

scenario_export_bootstrap
load_scratch_devices
zap_all_scratch_devices
ceph orch device ls --refresh

for ((i = 0; i < OSD_COUNT; i++)); do
    create_bluestore_lvm_osd "$i"
done

wait_for_osds_up "$OSD_COUNT"
zap_and_redeploy_osds
wait_for_osds_up "$OSD_COUNT"
sudo ceph osd stat
ceph_volume lvm list
rm -rf "$TMPDIR"
