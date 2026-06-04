#!/usr/bin/env bash
# Use existing scratch LVs (or blocks with SCRATCH_MODE=blocks), prepare, zap/redeploy.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

OSD_STORE=precreated
export OSD_STORE
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-precreated"

scenario_export_bootstrap
load_scratch_devices

for ((i = 0; i < OSD_COUNT; i++)); do
    create_bluestore_lvm_precreated_osd "$i"
done

wait_for_osds_up "$OSD_COUNT"
zap_and_redeploy_osds
wait_for_osds_up "$OSD_COUNT"
sudo ceph osd stat
ceph_volume lvm list
rm -rf "$TMPDIR"
