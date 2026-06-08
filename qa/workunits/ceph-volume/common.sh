#!/usr/bin/env bash
# Shared helpers for ceph-volume teuthology workunits.
#
# /scratch_devs is the source of truth: one device path per line provisioned by
# the lab for this job. Workunits must not infer or rewrite scratch devices.
set -euo pipefail

OSD_PROFILE="${OSD_PROFILE:-plain}"
OSD_COUNT="${OSD_COUNT:-2}"
ZAP_REDEPLOY="${ZAP_REDEPLOY:-1}"

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

ceph_volume_admin() {
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$KEYRING" -- "$@"
}

ceph_volume_bootstrap() {
    if [[ "$OSD_PROFILE" == dmcrypt ]] && [[ "${OSD_STORE:-}" == raw ]]; then
        export CEPH_VOLUME_DMCRYPT_SECRET="${CEPH_VOLUME_DMCRYPT_SECRET:-ceph-volume-integration-dmcrypt}"
    fi
    sudo cephadm ceph-volume --fsid "$FSID" -c "$CONFIG" -k "$BOOTSTRAP_KEYRING" -- "$@"
}

read_scratch_devices() {
    local line
    if [[ ! -f /scratch_devs ]]; then
        echo "missing /scratch_devs" >&2
        exit 1
    fi
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        echo "$line"
    done < /scratch_devs
}

is_lv() {
    local path="$1"
    sudo lvs "$path" >/dev/null 2>&1
}

get_realdevice() {
    local path="$1" dev
    if ! is_lv "$path"; then
        readlink -f "$path"
        return 0
    fi
    dev=$(sudo lvs --noheadings -o devices "$path" 2>/dev/null | awk '{print $1}' | sed 's/(.*//')
    if [[ -z "$dev" ]]; then
        echo "failed to resolve backing device for LV ${path}" >&2
        return 1
    fi
    readlink -f "$dev"
}

_clean_block_device_stack() {
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

clean_lvm_stack() {
    local path
    while IFS= read -r path; do
        if is_lv "$path"; then
            echo "zapping LV ${path}" >&2
            ceph_volume_bootstrap lvm zap --no-systemd "$path"
        else
            echo "cleaning LVM stack on ${path}" >&2
            _clean_block_device_stack "$path"
        fi
    done < <(read_scratch_devices)
}

debug_scratch_layout() {
    echo '=== /scratch_devs ===' >&2
    cat /scratch_devs >&2
    echo '=== lsblk ===' >&2
    lsblk -o NAME,KNAME,TYPE,SIZE,MOUNTPOINT,FSTYPE >&2
    echo '=== pvs ===' >&2
    sudo pvs >&2
    echo '=== vgs ===' >&2
    sudo vgs >&2
    echo '=== lvs ===' >&2
    sudo lvs >&2
}

scratch_devices_required() {
    if [[ "$OSD_PROFILE" == db-wal ]]; then
        echo $((OSD_COUNT * 3))
    else
        echo "$OSD_COUNT"
    fi
}

load_scratch_devices() {
    local need
    debug_scratch_layout
    mapfile -t SCRATCH_DEVICES < <(read_scratch_devices)
    need=$(scratch_devices_required)
    if [[ "${#SCRATCH_DEVICES[@]}" -lt "$need" ]]; then
        echo "need at least ${need} scratch device(s) for profile ${OSD_PROFILE}, found ${#SCRATCH_DEVICES[@]}" >&2
        printf '%s\n' "${SCRATCH_DEVICES[@]}" >&2 || true
        exit 1
    fi
    export SCRATCH_DEVICES
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

json_field_or_empty() {
    local value="$1"
    if [[ "$value" == null || -z "$value" ]]; then
        echo ""
    else
        echo "$value"
    fi
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

_create_admin_lv_on_block() {
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

scratch_path_for_lvm_prepare() {
    local path="$1"
    if is_lv "$path"; then
        echo "$path"
    else
        _create_admin_lv_on_block "$path"
    fi
}

_create_bluestore_lvm_prepare_paths() {
    local lv="$1"
    local db="${2:-}"
    local wal="${3:-}"
    local store="${4:-lvm}"
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

create_bluestore_lvm_osds() {
    local i data db wal

    if is_lv "${SCRATCH_DEVICES[0]}"; then
        for ((i = 0; i < OSD_COUNT; i++)); do
            data=$(scratch_device_for_osd "$i" data)
            db=""
            wal=""
            if [[ "$OSD_PROFILE" == db-wal ]]; then
                db=$(scratch_device_for_osd "$i" db)
                wal=$(scratch_device_for_osd "$i" wal)
            fi
            _create_bluestore_lvm_prepare_paths "$data" "$db" "$wal" lvm
        done
        return 0
    fi

    local -a data_devices db_devices wal_devices
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

create_bluestore_lvm_precreated_osd() {
    local lv db wal
    lv=$(scratch_path_for_lvm_prepare "$(scratch_device_for_osd "$1" data)")
    db=""
    wal=""
    if [[ "$OSD_PROFILE" == db-wal ]]; then
        db=$(scratch_path_for_lvm_prepare "$(scratch_device_for_osd "$1" db)")
        wal=$(scratch_path_for_lvm_prepare "$(scratch_device_for_osd "$1" wal)")
    fi
    _create_bluestore_lvm_prepare_paths "$lv" "$db" "$wal" precreated
}

_create_bluestore_raw_osd_paths() {
    local data="$1"
    local db="${2:-}"
    local wal="${3:-}"
    local reuse_osd_id="${4:-}"
    local reuse_osd_fsid="${5:-}"
    local map_file
    local -a prepare_args profile_args
    map_file="${TMPDIR}/osd.map.$(basename "$data")"
    prepare_args=(raw prepare --bluestore --data "$data")
    # shellcheck disable=SC2206
    profile_args=($(profile_batch_extra_args))
    prepare_args+=("${profile_args[@]}")
    if [[ -n "$reuse_osd_id" ]]; then
        prepare_args+=(--osd-id "$reuse_osd_id")
    fi
    if [[ -n "$reuse_osd_fsid" ]]; then
        prepare_args+=(--osd-fsid "$reuse_osd_fsid")
    fi
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

wait_for_orch_osd_daemon_gone() {
    local osd_id="$1"
    local tries="${2:-60}"
    local i daemon_name="osd.${osd_id}"

    for ((i = 0; i < tries; i++)); do
        if ! ceph orch ps --daemon-type osd 2>/dev/null | awk '{print $1}' | grep -qx "$daemon_name"; then
            return 0
        fi
        sleep 5
    done

    echo "forcing removal of stale daemon ${daemon_name}" >&2
    ceph orch daemon rm "$daemon_name" --force || true
    for ((i = 0; i < tries; i++)); do
        if ! ceph orch ps --daemon-type osd 2>/dev/null | awk '{print $1}' | grep -qx "$daemon_name"; then
            return 0
        fi
        sleep 5
    done
    echo "timed out waiting for ${daemon_name} to disappear from ceph orch ps" >&2
    ceph orch ps --daemon-type osd >&2 || true
    return 1
}

remove_osd_via_orch() {
    local osd_id="$1"
    local store="${2:-}"
    local data="${3:-}"
    if [[ "$store" == precreated ]] || { [[ "$store" == raw ]] && is_lv "$data"; }; then
        ceph orch osd rm "$osd_id" --force
    else
        ceph orch osd rm "$osd_id" --force --zap
    fi
    while ceph orch osd rm status 2>/dev/null | grep -q "^${osd_id} "; do
        sleep 5
    done
    wait_for_orch_osd_daemon_gone "$osd_id"
}

_zap_device_path() {
    local path="$1"
    local destroy="${2:-0}"
    local -a zap_args=(lvm zap --no-systemd)
    if [[ "$destroy" == 1 ]]; then
        zap_args+=(--destroy)
    fi
    echo "zapping device ${path}" >&2
    ceph_volume_bootstrap "${zap_args[@]}" "$path"
}

zap_osd_device_paths() {
    local store="$1"
    local data="$2"
    local db="${3:-}"
    local wal="${4:-}"
    local destroy=0
    local dev

    if [[ "$store" != precreated ]] && ! is_lv "$data"; then
        destroy=1
    fi
    for dev in "$data" "$db" "$wal"; do
        [[ -z "$dev" ]] && continue
        _zap_device_path "$dev" "$destroy"
    done
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

    if is_lv "${data_devices[0]}"; then
        local i
        for ((i = 0; i < ${#data_devices[@]}; i++)); do
            data="${data_devices[$i]}"
            db=""
            wal=""
            if [[ ${#db_devices[@]} -gt 0 ]]; then
                db="${db_devices[$i]}"
            fi
            if [[ ${#wal_devices[@]} -gt 0 ]]; then
                wal="${wal_devices[$i]}"
            fi
            _create_bluestore_lvm_prepare_paths "$data" "$db" "$wal" lvm
        done
    else
        _create_bluestore_lvm_batch_from_devices data_devices db_devices wal_devices
    fi
    OSD_PROFILE="$saved_profile"
}

redeploy_recorded_osd() {
    local rec="$1"
    local saved_profile="$OSD_PROFILE"
    local store data db wal osd_id osd_fsid
    store=$(echo "$rec" | jq -cr '.store')
    data=$(echo "$rec" | jq -cr '.data')
    db=$(json_field_or_empty "$(echo "$rec" | jq -cr '.db')")
    wal=$(json_field_or_empty "$(echo "$rec" | jq -cr '.wal')")
    osd_id=$(echo "$rec" | jq -cr '.osd_id')
    osd_fsid=$(echo "$rec" | jq -cr '.osd_fsid')
    OSD_PROFILE=$(echo "$rec" | jq -cr '.profile')
    case "$store" in
        lvm)
            echo "redeploy_recorded_osd does not support lvm store; use redeploy_lvm_osds_from_records" >&2
            OSD_PROFILE="$saved_profile"
            return 1
            ;;
        precreated)
            if ! is_lv "$data"; then
                data=$(scratch_path_for_lvm_prepare "$data")
            fi
            if [[ -n "$db" ]] && ! is_lv "$db"; then
                db=$(scratch_path_for_lvm_prepare "$db")
            fi
            if [[ -n "$wal" ]] && ! is_lv "$wal"; then
                wal=$(scratch_path_for_lvm_prepare "$wal")
            fi
            _create_bluestore_lvm_prepare_paths "$data" "$db" "$wal" precreated
            ;;
        raw)
            _create_bluestore_raw_osd_paths "$data" "$db" "$wal" "$osd_id" "$osd_fsid"
            ;;
        *) echo "unknown store in record: ${store}" >&2; OSD_PROFILE="$saved_profile"; return 1 ;;
    esac
    OSD_PROFILE="$saved_profile"
}

zap_and_redeploy_osds() {
    local rec osd_id osd_fsid store data db wal
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
        data=$(echo "$rec" | jq -cr '.data')
        db=$(json_field_or_empty "$(echo "$rec" | jq -cr '.db')")
        wal=$(json_field_or_empty "$(echo "$rec" | jq -cr '.wal')")
        remove_osd_via_orch "$osd_id" "$store" "$data"
        zap_osd_device_paths "$store" "$data" "$db" "$wal"
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
