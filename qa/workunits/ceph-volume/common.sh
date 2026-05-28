#!/usr/bin/env bash
# Shared helpers for ceph-volume teuthology workunits.
set -euo pipefail

wait_for_osds_up() {
    local min="${1:-1}"
    local tries="${2:-120}"
    local i
    for ((i = 0; i < tries; i++)); do
        local up
        up=$(ceph osd stat -f json | python3 -c "import json,sys; print(json.load(sys.stdin).get('num_up_osds', 0))")
        if [[ "$up" -ge "$min" ]]; then
            return 0
        fi
        sleep 5
    done
    echo "timed out waiting for at least ${min} OSD(s) to be up" >&2
    ceph osd stat || true
    return 1
}

ceph_volume() {
    # Run ceph-volume via cephadm in the bootstrapped cluster.
    cephadm shell -- ceph-volume "$@"
}

first_available_scratch_device() {
    # First unused device from orchestrator inventory (baremetal/OpenStack).
    ceph orch device ls -f json | python3 -c '
import json, sys
for d in json.load(sys.stdin):
    if d.get("available"):
        print(d["path"])
        break
else:
    sys.exit(1)
'
}

scratch_devices_available() {
    local n="${1:-1}"
    local count
    count=$(ceph orch device ls -f json | python3 -c '
import json, sys
print(sum(1 for d in json.load(sys.stdin) if d.get("available")))
')
    [[ "$count" -ge "$n" ]]
}
