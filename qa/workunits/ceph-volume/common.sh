#!/usr/bin/env bash
# Shared helpers for ceph-volume teuthology workunits.
set -euo pipefail

wait_for_osds_up() {
    local min="${1:-1}"
    local tries="${2:-120}"
    local i
    for ((i = 0; i < tries; i++)); do
        local up
        up=$(sudo ceph osd stat -f json | python3 -c "import json,sys; print(json.load(sys.stdin).get('num_up_osds', 0))")
        if [[ "$up" -ge "$min" ]]; then
            return 0
        fi
        sleep 5
    done
    echo "timed out waiting for at least ${min} OSD(s) to be up" >&2
    sudo ceph osd stat || true
    return 1
}

ceph_volume() {
    # Run ceph-volume via cephadm in the bootstrapped cluster.
    sudo cephadm shell -- ceph-volume "$@"
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

# Requires FSID, CONFIG, KEYRING (and optionally BOOTSTRAP_KEYRING, TMPDIR for OSD helpers).
ceph_volume_admin() {
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- "$@"
}

ceph_volume_bootstrap() {
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$BOOTSTRAP_KEYRING" -- "$@"
}

list_scratch_devices() {
    local dev
    if [[ -f /scratch_devs ]]; then
        while read -r dev; do
            [[ -n "$dev" ]] && echo "$dev"
        done < /scratch_devs
        return 0
    fi
    for dev in /dev/sd? /dev/vd?; do
        [[ -e "$dev" ]] || continue
        case "$dev" in
            *vda) continue ;;
        esac
        if sudo dd if="$dev" of=/dev/null bs=1 count=1 2>/dev/null \
            && ! mount | grep -qF "$dev"; then
            echo "$dev"
        fi
    done
}

zap_all_scratch_devices() {
    local dev
    while read -r dev; do
        [[ -z "$dev" ]] && continue
        echo "zapping scratch device ${dev}"
        ceph_volume_admin lvm zap "$dev" || true
        sudo wipefs --all "$dev" || true
        sudo dd if=/dev/zero of="$dev" bs=1M count=10 conv=fsync || true
    done < <(list_scratch_devices)
}

deploy_osd_daemon() {
    local osd_id="$1"
    local osd_fsid="$2"
    jq --null-input \
        --arg fsid "$FSID" \
        --arg name "osd.${osd_id}" \
        --arg keyring "$BOOTSTRAP_KEYRING" \
        --arg config "$CONFIG" \
        --arg osd_fsid "$osd_fsid" \
        '{"fsid": $fsid, "name": $name, "params":{"keyring": $keyring, "config": $config, "osd_fsid": $osd_fsid}}' | \
        sudo cephadm _orch deploy
}

create_bluestore_lvm_osd() {
    local dev="$1"
    local map_file="${TMPDIR}/osd.map.$(basename "$dev")"

    ceph_volume_bootstrap lvm batch --no-auto "$dev" --yes --no-systemd --objectstore bluestore
    ceph_volume_bootstrap lvm list --format json "$dev" > "$map_file"
    local osd_id osd_fsid
    osd_id=$(jq -cr '.. | ."ceph.osd_id"? | select(.)' "$map_file" | head -1)
    osd_fsid=$(jq -cr '.. | ."ceph.osd_fsid"? | select(.)' "$map_file" | head -1)
    deploy_osd_daemon "$osd_id" "$osd_fsid"
}
