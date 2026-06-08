#!/usr/bin/env bash
# Clean scratch devices, create Bluestore LVM OSDs, zap/redeploy, verify.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

OSD_STORE=lvm
export OSD_STORE
TMPDIR="${TESTDIR:-/tmp}/ceph-volume-bluestore-lvm"

scenario_export_bootstrap
load_scratch_devices
clean_lvm_stack
ceph orch device ls --refresh

create_bluestore_lvm_osds

wait_for_osds_up "$OSD_COUNT"
zap_and_redeploy_osds
wait_for_osds_up "$OSD_COUNT"
sudo ceph osd stat
ceph_volume lvm list
rm -rf "$TMPDIR"
