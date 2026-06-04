#!/usr/bin/env bash
# Shared helpers for ceph-volume teuthology workunits.
set -euo pipefail

OSD_PROFILE="${OSD_PROFILE:-plain}"
OSD_COUNT="${OSD_COUNT:-2}"
ZAP_REDEPLOY="${ZAP_REDEPLOY:-1}"
SCRATCH_MODE="${SCRATCH_MODE:-lvs}"
SCRATCH_ARE_LVS="${SCRATCH_ARE_LVS:-0}"

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
    sudo cephadm shell -- ceph-volume "$@"
}

first_available_scratch_device() {
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

ceph_volume_admin() {
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- "$@"
}

ceph_volume_bootstrap() {
    if [[ "$OSD_PROFILE" == dmcrypt ]] && [[ "${OSD_STORE:-}" == raw ]]; then
        export CEPH_VOLUME_DMCRYPT_SECRET="${CEPH_VOLUME_DMCRYPT_SECRET:-ceph-volume-integration-dmcrypt}"
    fi
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$BOOTSTRAP_KEYRING" -- "$@"
}

device_is_system_disk() {
    lsblk -rn -o MOUNTPOINT "$1" 2>/dev/null | grep -qE '^/(|boot|boot/efi)$'
}

lv_block_device() {
    local lv="$1" dev
    dev=$(sudo lvs --noheadings -o devices "$lv" 2>/dev/null | awk '{print $1}' | sed 's/(.*//')
    [[ -z "$dev" ]] && return 1
    if [[ "$dev" == /dev/dm-* ]]; then
        dev=$(readlink -f "$dev")
    fi
    echo "$dev"
}

vg_nvme_in_use() {
    findmnt -rn -o SOURCE 2>/dev/null | grep -qE 'vg_nvme|/dev/mapper/vg_nvme'
}

scratch_devices_required() {
    if [[ "$OSD_PROFILE" == db-wal ]]; then
        echo $((OSD_COUNT * 3))
    else
        echo "$OSD_COUNT"
    fi
}

device_already_collected() {
    local candidate="$1" existing resolved
    shift
    resolved=$(readlink -f "$candidate" 2>/dev/null || echo "$candidate")
    for existing in "$@"; do
        [[ "$(readlink -f "$existing" 2>/dev/null || echo "$existing")" == "$resolved" ]] && return 0
    done
    return 1
}

collect_unique_scratch_lv() {
    local lv="$1" pv
    local -n _lvs=$2
    local -n _pvs=$3
    local need="$4"

    pv=$(lv_block_device "$lv") || return 1
    pv=$(readlink -f "$pv" 2>/dev/null || echo "$pv")
    device_is_system_disk "$pv" && return 1
    device_already_collected "$pv" "${_pvs[@]}" && return 1
    _lvs+=("$lv")
    _pvs+=("$pv")
    [[ ${#_lvs[@]} -ge "$need" ]]
}

collect_unique_block_device() {
    local dev="$1"
    local -n _devices=$2
    local need="$3"

    dev=$(readlink -f "$dev" 2>/dev/null || echo "$dev")
    device_is_system_disk "$dev" && return 1
    device_already_collected "$dev" "${_devices[@]}" && return 1
    _devices+=("$dev")
    [[ ${#_devices[@]} -ge "$need" ]]
}

teardown_vg_nvme() {
    if ! sudo vgs vg_nvme >/dev/null 2>&1; then
        return 0
    fi
    sudo lvchange -an vg_nvme 2>/dev/null || true
    sudo vgchange -an vg_nvme 2>/dev/null || true
    sudo vgremove -fy vg_nvme 2>/dev/null || true
    if command -v udevadm >/dev/null 2>&1; then
        sudo udevadm settle 2>/dev/null || true
    fi
}

zap_block_device() {
    local dev="$1" part lv
    dev=$(readlink -f "$dev")

    while IFS= read -r lv; do
        [[ -z "$lv" ]] && continue
        sudo lvchange -an "$lv" 2>/dev/null || true
    done < <(sudo lvs --noheadings -o lv_path --select "pv_name=${dev}" 2>/dev/null | awk 'NF { print $1 }')

    sudo pvremove -ffy "$dev" 2>/dev/null || true

    while IFS= read -r part; do
        [[ -z "$part" || "$part" == "$dev" ]] && continue
        sudo wipefs -af "$part" 2>/dev/null || true
    done < <(lsblk -pnro NAME "$dev" 2>/dev/null)

    sudo wipefs -af "$dev" 2>/dev/null || true
    sudo dd if=/dev/zero of="$dev" bs=1M count=10 conv=fsync 2>/dev/null || true
}

debug_scratch_layout() {
    echo '=== /scratch_devs ===' >&2
    cat /scratch_devs >&2
    echo '=== lsblk ===' >&2
    lsblk -o NAME,KNAME,TYPE,SIZE,MOUNTPOINT,FSTYPE >&2
}

zap_scratch_lv() {
    local lv="$1"
    ceph_volume_bootstrap lvm zap --destroy "$lv"
}

list_scratch_devices() {
    local dev lv pv need
    local -a devices=() pvs_seen=()

    if [[ ! -f /scratch_devs ]]; then
        echo "missing /scratch_devs" >&2
        exit 1
    fi

    if [[ "$SCRATCH_MODE" != blocks ]]; then
        cat /scratch_devs
        return
    fi

    need=$(scratch_devices_required)

    # nvme_loop rewrites /scratch_devs with bare /dev/nvme*n* paths.
    if ! grep -qE '^/dev/[^/]+/[^/]+' /scratch_devs; then
        while IFS= read -r dev; do
            [[ -z "$dev" ]] && continue
            collect_unique_block_device "$dev" devices "$need" && break
        done < <(grep -E '^/dev/' /scratch_devs)
        if [[ ${#devices[@]} -eq 0 ]]; then
            echo "no scratch block devices from /scratch_devs" >&2
            exit 1
        fi
        for dev in "${devices[@]}"; do
            echo "$dev"
        done
        return
    fi

    # Sepia baremetal: cephadm keeps a vg_nvme LV mounted (e.g. lv_5 on
    # /var/lib/ceph). Use scratch LVs from /scratch_devs; do not vgremove.
    if vg_nvme_in_use; then
        echo "vg_nvme in use (cluster mount); using scratch LVs from /scratch_devs" >&2
        while IFS= read -r lv; do
            [[ -z "$lv" ]] && continue
            collect_unique_scratch_lv "$lv" devices pvs_seen "$need" && break
        done < <(grep -E '^/dev/[^/]+/[^/]+' /scratch_devs)
        if [[ ${#devices[@]} -eq 0 ]]; then
            echo "no scratch LVs from /scratch_devs" >&2
            exit 1
        fi
        for lv in "${devices[@]}"; do
            echo "$lv"
        done
        return
    fi

    while IFS= read -r pv; do
        [[ -z "$pv" ]] && continue
        collect_unique_block_device "$pv" devices "$need" && break
    done < <(sudo pvs --noheadings -o pv_name -S vg_name=vg_nvme | awk 'NF { print $1 }')

    if [[ ${#devices[@]} -eq 0 ]]; then
        echo "no scratch block devices from /scratch_devs" >&2
        exit 1
    fi

    teardown_vg_nvme
    for dev in "${devices[@]}"; do
        echo "$dev"
    done
}

scratch_path_is_lv() {
    [[ "$1" == /dev/*/* ]]
}

load_scratch_devices() {
    local need
    if [[ "$SCRATCH_MODE" == blocks ]]; then
        debug_scratch_layout
    fi
    mapfile -t SCRATCH_DEVICES < <(list_scratch_devices)
    need=$(scratch_devices_required)
    if [[ "${#SCRATCH_DEVICES[@]}" -lt "$need" ]]; then
        echo "need at least ${need} unique scratch device(s) for profile ${OSD_PROFILE}, found ${#SCRATCH_DEVICES[@]}" >&2
        printf '%s\n' "${SCRATCH_DEVICES[@]}" >&2 || true
        exit 1
    fi
    if scratch_path_is_lv "${SCRATCH_DEVICES[0]}"; then
        SCRATCH_ARE_LVS=1
        export SCRATCH_ARE_LVS
        echo "scratch devices are teuthology LVs; using lvm prepare (not batch --no-auto)" >&2
    else
        SCRATCH_ARE_LVS=0
        export SCRATCH_ARE_LVS
    fi
}

scratch_device_for_osd() {
    local osd_idx="$1"
    local role="${2:-data}"
    if [[ "$OSD_PROFILE" != db-wal ]]; then
        echo "${SCRATCH_DEVICES[$osd_idx]}"
        return 0
    fi
    case "$role" in
        data) echo "${SCRATCH_DEVICES[$osd_idx]}" ;;
        db) echo "${SCRATCH_DEVICES[$((OSD_COUNT + osd_idx))]}" ;;
        wal) echo "${SCRATCH_DEVICES[$((OSD_COUNT * 2 + osd_idx))]}" ;;
        *) echo "unknown scratch role: ${role}" >&2; return 1 ;;
    esac
}

zap_all_scratch_devices() {
    local dev
    if [[ "${SCRATCH_ARE_LVS:-0}" == 1 ]]; then
        echo "skipping initial scratch zap (teuthology LVs in shared vg_nvme)" >&2
        return 0
    fi
    for dev in "${SCRATCH_DEVICES[@]}"; do
        [[ -z "$dev" || "$dev" != /dev/* ]] && continue
        if scratch_path_is_lv "$dev"; then
            echo "zapping scratch lv ${dev}"
            zap_scratch_lv "$dev"
        else
            echo "zapping scratch device ${dev}"
            zap_block_device "$dev"
        fi
    done
}

scenario_export_bootstrap() {
    FSID=$(ceph fsid)
    CONFIG=/etc/ceph/ceph.conf
    KEYRING=/etc/ceph/ceph.client.admin.keyring
    export FSID CONFIG KEYRING TMPDIR
    mkdir -p "$TMPDIR"
    sudo cephadm shell --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- \
        ceph auth get client.bootstrap-osd > "${TMPDIR}/keyring.bootstrap.osd"
    export BOOTSTRAP_KEYRING="${TMPDIR}/keyring.bootstrap.osd"
    : > "${TMPDIR}/osds.jsonl"
}

profile_batch_extra_args() {
    case "$OSD_PROFILE" in
        dmcrypt) echo --dmcrypt ;;
        dmcrypt-tpm2) echo --dmcrypt --with-tpm ;;
    esac
}

profile_prepare_extra_args() {
    case "$OSD_PROFILE" in
        dmcrypt) echo --dmcrypt ;;
        dmcrypt-tpm2) echo --dmcrypt --with-tpm ;;
    esac
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

record_osd_deployment() {
    local osd_id="$1"
    local osd_fsid="$2"
    local store="$3"
    local data="$4"
    local db="${5:-}"
    local wal="${6:-}"
    jq -cn \
        --arg osd_id "$osd_id" \
        --arg osd_fsid "$osd_fsid" \
        --arg store "$store" \
        --arg data "$data" \
        --arg db "$db" \
        --arg wal "$wal" \
        --arg profile "$OSD_PROFILE" \
        '{osd_id: $osd_id, osd_fsid: $osd_fsid, store: $store, data: $data, db: $db, wal: $wal, profile: $profile}' \
        >> "${TMPDIR}/osds.jsonl"
}

lvm_data_path() {
    local lv="$1"
    if [[ -z "$lv" ]]; then
        echo "empty LV path for lvm prepare" >&2
        return 1
    fi
    if [[ "$lv" == /dev/*/* ]]; then
        echo "${lv#/dev/}"
    else
        echo "$lv"
    fi
}

create_admin_lv_on_device() {
    local dev="$1"
    local base vg_name lv_path
    dev=$(readlink -f "$dev")
    base=$(basename "$dev")
    vg_name="ceph-prec-${base}"
    sudo vgremove -fy "$vg_name" 2>/dev/null || true
    sudo pvcreate -ffy "$dev" >/dev/null
    sudo vgcreate -y "$vg_name" "$dev" >/dev/null
    sudo lvcreate -y -l 100%VG -n data "$vg_name" >/dev/null
    sudo lvchange -ay "$vg_name" >/dev/null
    if command -v udevadm >/dev/null 2>&1; then
        sudo udevadm settle >/dev/null 2>&1 || true
    fi
    lv_path=$(sudo lvs --noheadings -o lv_path "$vg_name/data" | awk 'NF { print $1; exit }')
    if [[ -z "$lv_path" ]]; then
        echo "failed to create admin LV on ${dev}" >&2
        return 1
    fi
    echo "$lv_path"
}

ensure_precreated_lv() {
    local dev="$1"
    if sudo lvs --noheadings "$dev" >/dev/null 2>&1; then
        echo "$dev"
    else
        create_admin_lv_on_device "$dev"
    fi
}

ensure_scratch_lv() {
    local lv_path="$1"
    local vg_name lv_name ref_lv ref_size pv

    if sudo lvs "$lv_path" >/dev/null 2>&1; then
        echo "$lv_path"
        return 0
    fi

    vg_name=$(basename "$(dirname "$lv_path")")
    lv_name=$(basename "$lv_path")
    ref_lv=""
    while IFS= read -r candidate; do
        [[ -z "$candidate" || "$candidate" == "$lv_path" ]] && continue
        [[ "$(basename "$(dirname "$candidate")")" != "$vg_name" ]] && continue
        if sudo lvs "$candidate" >/dev/null 2>&1; then
            ref_lv="$candidate"
            break
        fi
    done < <(grep -E '^/dev/[^/]+/[^/]+' /scratch_devs 2>/dev/null || true)

    if [[ -z "$ref_lv" ]]; then
        echo "missing scratch LV ${lv_path} and no reference LV in ${vg_name}" >&2
        return 1
    fi

    pv=$(lv_block_device "$ref_lv") || return 1
    ref_size=$(sudo lvs --noheadings -o lv_size --units g --nosuffix "$ref_lv" | awk '{print int($1)}')
    if [[ -z "$ref_size" || "$ref_size" -le 0 ]]; then
        echo "failed to read size of reference LV ${ref_lv}" >&2
        return 1
    fi

    echo "recreating scratch LV ${lv_path} on ${pv} (${ref_size}G)" >&2
    sudo lvcreate -y -L "${ref_size}G" -n "$lv_name" "$vg_name" "$pv"
    if command -v udevadm >/dev/null 2>&1; then
        sudo udevadm settle 2>/dev/null || true
    fi
    echo "$lv_path"
}

_create_bluestore_lvm_batch_from_devices() {
    local -n _data_devices=$1
    local -n _db_devices=$2
    local -n _wal_devices=$3
    local -a batch_args profile_args
    local i data db wal map_file osd_id osd_fsid

    batch_args=(lvm batch --no-auto "${_data_devices[@]}" --yes --no-systemd --objectstore bluestore)
    # shellcheck disable=SC2206
    profile_args=($(profile_batch_extra_args))
    batch_args+=("${profile_args[@]}")
    if [[ ${#_db_devices[@]} -gt 0 ]]; then
        batch_args+=(--db-devices "${_db_devices[@]}")
    fi
    if [[ ${#_wal_devices[@]} -gt 0 ]]; then
        batch_args+=(--wal-devices "${_wal_devices[@]}")
    fi
    ceph_volume_bootstrap "${batch_args[@]}"

    for ((i = 0; i < ${#_data_devices[@]}; i++)); do
        data="${_data_devices[$i]}"
        db=""
        wal=""
        if [[ ${#_db_devices[@]} -gt 0 ]]; then
            db="${_db_devices[$i]}"
        fi
        if [[ ${#_wal_devices[@]} -gt 0 ]]; then
            wal="${_wal_devices[$i]}"
        fi
        map_file="${TMPDIR}/osd.map.$(basename "$data")"
        ceph_volume_bootstrap lvm list --format json "$data" > "$map_file"
        osd_id=$(jq -cr '.. | ."ceph.osd_id"? | select(.)' "$map_file" | head -1)
        osd_fsid=$(jq -cr '.. | ."ceph.osd_fsid"? | select(.)' "$map_file" | head -1)
        deploy_osd_daemon "$osd_id" "$osd_fsid"
        record_osd_deployment "$osd_id" "$osd_fsid" lvm "$data" "$db" "$wal"
    done
}

create_bluestore_lvm_osds_on_scratch_lvs() {
    local i data db wal

    for ((i = 0; i < OSD_COUNT; i++)); do
        data=$(ensure_scratch_lv "$(scratch_device_for_osd "$i" data)")
        db=""
        wal=""
        if [[ "$OSD_PROFILE" == db-wal ]]; then
            db=$(ensure_scratch_lv "$(scratch_device_for_osd "$i" db)")
            wal=$(ensure_scratch_lv "$(scratch_device_for_osd "$i" wal)")
        fi
        _create_bluestore_lvm_prepare_paths "$data" "$db" "$wal" lvm
    done
}

create_bluestore_lvm_osds() {
    if [[ "${SCRATCH_ARE_LVS:-0}" == 1 ]]; then
        create_bluestore_lvm_osds_on_scratch_lvs
        return 0
    fi

    local -a data_devices db_devices wal_devices
    local i

    data_devices=()
    db_devices=()
    wal_devices=()
    for ((i = 0; i < OSD_COUNT; i++)); do
        data_devices+=("$(scratch_device_for_osd "$i" data)")
        if [[ "$OSD_PROFILE" == db-wal ]]; then
            db_devices+=("$(scratch_device_for_osd "$i" db)")
            wal_devices+=("$(scratch_device_for_osd "$i" wal)")
        fi
    done
    _create_bluestore_lvm_batch_from_devices data_devices db_devices wal_devices
}

redeploy_lvm_osds_from_records() {
    local rec store data db wal saved_profile
    local -a data_devices db_devices wal_devices

    saved_profile="$OSD_PROFILE"
    data_devices=()
    db_devices=()
    wal_devices=()
    while read -r rec; do
        store=$(echo "$rec" | jq -cr '.store')
        [[ "$store" == lvm ]] || continue
        data=$(echo "$rec" | jq -cr '.data')
        db=$(json_field_or_empty "$(echo "$rec" | jq -cr '.db')")
        wal=$(json_field_or_empty "$(echo "$rec" | jq -cr '.wal')")
        OSD_PROFILE=$(echo "$rec" | jq -cr '.profile')
        data_devices+=("$data")
        [[ -n "$db" ]] && db_devices+=("$db")
        [[ -n "$wal" ]] && wal_devices+=("$wal")
    done < "${TMPDIR}/osds.jsonl.redeploy"

    if [[ ${#data_devices[@]} -eq 0 ]]; then
        OSD_PROFILE="$saved_profile"
        return 0
    fi

    if [[ "${SCRATCH_ARE_LVS:-0}" == 1 ]] || scratch_path_is_lv "${data_devices[0]}"; then
        mapfile -t SCRATCH_DEVICES < <(list_scratch_devices)
        create_bluestore_lvm_osds_on_scratch_lvs
    else
        _create_bluestore_lvm_batch_from_devices data_devices db_devices wal_devices
    fi
    OSD_PROFILE="$saved_profile"
}

_create_bluestore_lvm_prepare_paths() {
    local lv="$1"
    local db="${2:-}"
    local wal="${3:-}"
    local store="${4:-precreated}"
    local data_path map_file
    local -a prepare_args profile_args
    data_path=$(lvm_data_path "$lv")
    map_file="${TMPDIR}/osd.map.$(basename "$lv")"
    prepare_args=(lvm prepare --bluestore --data "$data_path" --no-systemd)
    # shellcheck disable=SC2206
    profile_args=($(profile_prepare_extra_args))
    prepare_args+=("${profile_args[@]}")
    if [[ -n "$db" ]]; then
        prepare_args+=(--block.db "$(lvm_data_path "$db")")
    fi
    if [[ -n "$wal" ]]; then
        prepare_args+=(--block.wal "$(lvm_data_path "$wal")")
    fi
    ceph_volume_bootstrap "${prepare_args[@]}"
    ceph_volume_bootstrap lvm list --format json "$data_path" > "$map_file"
    local osd_id osd_fsid
    osd_id=$(jq -cr '.. | ."ceph.osd_id"? | select(.)' "$map_file" | head -1)
    osd_fsid=$(jq -cr '.. | ."ceph.osd_fsid"? | select(.)' "$map_file" | head -1)
    deploy_osd_daemon "$osd_id" "$osd_fsid"
    record_osd_deployment "$osd_id" "$osd_fsid" "$store" "$lv" "$db" "$wal"
}

_create_bluestore_lvm_precreated_paths() {
    _create_bluestore_lvm_prepare_paths "$1" "$2" "$3" precreated
}

create_bluestore_lvm_precreated_osd() {
    local lv db wal
    lv=$(ensure_precreated_lv "$(scratch_device_for_osd "$1" data)")
    db=""
    wal=""
    if [[ "$OSD_PROFILE" == db-wal ]]; then
        db=$(ensure_precreated_lv "$(scratch_device_for_osd "$1" db)")
        wal=$(ensure_precreated_lv "$(scratch_device_for_osd "$1" wal)")
    fi
    _create_bluestore_lvm_precreated_paths "$lv" "$db" "$wal"
}

_create_bluestore_raw_osd_paths() {
    local data="$1"
    local db="${2:-}"
    local wal="${3:-}"
    local map_file
    local -a prepare_args profile_args
    map_file="${TMPDIR}/osd.map.$(basename "$data")"
    prepare_args=(raw prepare --bluestore --data "$data")
    # shellcheck disable=SC2206
    profile_args=($(profile_batch_extra_args))
    prepare_args+=("${profile_args[@]}")
    if [[ -n "$db" ]]; then
        prepare_args+=(--block.db "$db")
    fi
    if [[ -n "$wal" ]]; then
        prepare_args+=(--block.wal "$wal")
    fi
    ceph_volume_bootstrap "${prepare_args[@]}"
    ceph_volume_bootstrap raw list --format json "$data" > "$map_file"
    local osd_id osd_fsid
    osd_id=$(jq -cr 'to_entries[0].value.osd_id' "$map_file")
    osd_fsid=$(jq -cr 'to_entries[0].key' "$map_file")
    deploy_osd_daemon "$osd_id" "$osd_fsid"
    record_osd_deployment "$osd_id" "$osd_fsid" raw "$data" "$db" "$wal"
}

create_bluestore_raw_osd() {
    local data db wal
    data=$(scratch_device_for_osd "$1" data)
    db=""
    wal=""
    if [[ "$OSD_PROFILE" == db-wal ]]; then
        db=$(scratch_device_for_osd "$1" db)
        wal=$(scratch_device_for_osd "$1" wal)
    fi
    _create_bluestore_raw_osd_paths "$data" "$db" "$wal"
}

remove_osd_via_orch() {
    local osd_id="$1"
    local store="${2:-}"
    if [[ "$store" == precreated ]]; then
        ceph orch osd rm "$osd_id" --force
    else
        ceph orch osd rm "$osd_id" --force --zap
    fi
    while ceph orch osd rm status 2>/dev/null | grep -q "^${osd_id} "; do
        sleep 5
    done
}

zap_osd_leftover_metadata() {
    local osd_id="$1"
    local osd_fsid="$2"
    local store="$3"
    local destroy_flag=(--destroy)
    if [[ "$store" == precreated ]]; then
        destroy_flag=()
    fi
    case "$store" in
        lvm|precreated)
            ceph_volume lvm zap "${destroy_flag[@]}" --osd-id "$osd_id" || true
            ceph_volume lvm zap "${destroy_flag[@]}" --osd-fsid "$osd_fsid" || true
            ;;
        raw)
            ceph_volume lvm zap --destroy --osd-id "$osd_id" || true
            ceph_volume lvm zap --destroy --osd-fsid "$osd_fsid" || true
            ;;
    esac
}

json_field_or_empty() {
    local value="$1"
    if [[ "$value" == null || -z "$value" ]]; then
        echo ""
    else
        echo "$value"
    fi
}

redeploy_recorded_osd() {
    local rec="$1"
    local saved_profile="$OSD_PROFILE"
    local store data db wal
    store=$(echo "$rec" | jq -cr '.store')
    data=$(echo "$rec" | jq -cr '.data')
    db=$(json_field_or_empty "$(echo "$rec" | jq -cr '.db')")
    wal=$(json_field_or_empty "$(echo "$rec" | jq -cr '.wal')")
    OSD_PROFILE=$(echo "$rec" | jq -cr '.profile')
    case "$store" in
        lvm)
            echo "redeploy_recorded_osd does not support lvm store; use redeploy_lvm_osds_from_records" >&2
            OSD_PROFILE="$saved_profile"
            return 1
            ;;
        precreated) _create_bluestore_lvm_precreated_paths "$data" "$db" "$wal" ;;
        raw) _create_bluestore_raw_osd_paths "$data" "$db" "$wal" ;;
        *) echo "unknown store in record: ${store}" >&2; OSD_PROFILE="$saved_profile"; return 1 ;;
    esac
    OSD_PROFILE="$saved_profile"
}

zap_and_redeploy_osds() {
    local rec osd_id osd_fsid store
    if [[ "$ZAP_REDEPLOY" != 1 ]]; then
        return 0
    fi
    if [[ ! -s "${TMPDIR}/osds.jsonl" ]]; then
        echo "no OSD records to zap/redeploy" >&2
        return 1
    fi
    echo "zapping deployed OSDs before redeploy"
    while read -r rec; do
        osd_id=$(echo "$rec" | jq -cr '.osd_id')
        osd_fsid=$(echo "$rec" | jq -cr '.osd_fsid')
        store=$(echo "$rec" | jq -cr '.store')
        remove_osd_via_orch "$osd_id" "$store"
        zap_osd_leftover_metadata "$osd_id" "$osd_fsid" "$store"
    done < "${TMPDIR}/osds.jsonl"
    ceph orch device ls --refresh
    cp "${TMPDIR}/osds.jsonl" "${TMPDIR}/osds.jsonl.redeploy"
    : > "${TMPDIR}/osds.jsonl"
    echo "redeploying OSDs after zap"
    stores=$(jq -sr '[.[].store] | unique | join(",")' "${TMPDIR}/osds.jsonl.redeploy")
    if [[ "$stores" == lvm ]]; then
        redeploy_lvm_osds_from_records
    else
        while read -r rec; do
            redeploy_recorded_osd "$rec"
        done < "${TMPDIR}/osds.jsonl.redeploy"
    fi
}

assert_no_lvm_osd_metadata() {
    if ceph_volume lvm list; then
        echo "expected no LVM OSD metadata for raw deployment" >&2
        return 1
    fi
}
