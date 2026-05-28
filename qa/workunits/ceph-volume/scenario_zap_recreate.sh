#!/usr/bin/env bash
# Zap an existing LVM OSD (by id / fsid) and recreate it on the same device.
set -ex

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

wait_for_osds_up 1

OSD_ID=0
OSD_FSID=$(ceph osd metadata "$OSD_ID" -f json | python3 -c 'import json,sys; print(json.load(sys.stdin)["osd_fsid"])')

DEVID=$(ceph device ls -f json | python3 -c "
import json, sys
for d in json.load(sys.stdin):
    if d.get('daemon_names') and 'osd.0' in d.get('daemon_names', []):
        print(d['devid'])
        break
else:
    sys.exit(1)
")
HOST=$(ceph orch device ls -f json | python3 -c "
import json, sys
devid = sys.argv[1]
for d in json.load(sys.stdin):
    if d.get('devid') == devid:
        print(d['hostname'])
        break
" "$DEVID")
DEV=$(ceph orch device ls -f json | python3 -c "
import json, sys
devid = sys.argv[1]
for d in json.load(sys.stdin):
    if d.get('devid') == devid:
        print(d['path'].replace('/dev/', ''))
        break
" "$DEVID")

ceph orch osd rm "$OSD_ID" --force --zap
while ceph orch osd rm status 2>/dev/null | grep -q "^${OSD_ID} "; do
    sleep 5
done

ceph_volume lvm zap --destroy --osd-id "$OSD_ID" || true
ceph_volume lvm zap --destroy --osd-fsid "$OSD_FSID" || true

ceph orch device ls --refresh
ceph orch daemon add osd "${HOST}:${DEV}"
wait_for_osds_up 1
ceph osd tree | grep -q "osd.${OSD_ID}"
