from __future__ import print_function
import json
import logging
import os
from textwrap import dedent
from ceph_volume.util import prepare as prepare_utils
from ceph_volume.util import encryption as encryption_utils
from ceph_volume.util import disk
from ceph_volume.util import system
from ceph_volume import decorators, terminal, objectstore
from ceph_volume.devices.lvm.common import rollback_osd
from .common import create_parser

logger = logging.getLogger(__name__)

def prepare_dmcrypt(key, device, device_type, fsid):
    """
    Helper for devices that are encrypted. The operations needed for
    block, db, wal, devices are all the same
    """
    if not device:
        return ''
    kname = disk.lsblk(device)['KNAME']
    mapping = 'ceph-{}-{}-{}-dmcrypt'.format(fsid, kname, device_type)
    # format data device
    encryption_utils.luks_format(
        key,
        device
    )
    encryption_utils.luks_open(
        key,
        device,
        mapping
    )

    return '/dev/mapper/{}'.format(mapping)


class Prepare(object):

    help = 'Format a raw device and associate it with a (BlueStore) OSD'

    def __init__(self, argv):
        self.argv = argv
        self.osd_id = None

    def main(self):
        sub_command_help = dedent("""
        Prepare an OSD by assigning an ID and FSID, registering them with the
        cluster with an ID and FSID, formatting the volume.

        Once the OSD is ready, an ad-hoc systemd unit will be enabled so that
        it can later get activated and the OSD daemon can get started.

            ceph-volume raw prepare --bluestore --data {device}

        DB and WAL devices are supported.

            ceph-volume raw prepare --bluestore --data {device} --block.db {device} --block.wal {device}

        """)
        parser = create_parser(
            prog='ceph-volume raw prepare',
            description=sub_command_help,
        )
        if not self.argv:
            print(sub_command_help)
            return
        self.args = parser.parse_args(self.argv)
        if not self.args.bluestore:
            terminal.error('must specify --bluestore (currently the only supported backend)')
            raise SystemExit(1)
        if self.args.dmcrypt and not os.getenv('CEPH_VOLUME_DMCRYPT_SECRET'):
            terminal.error('encryption was requested (--dmcrypt) but environment variable ' \
                           'CEPH_VOLUME_DMCRYPT_SECRET is not set, you must set ' \
                           'this variable to provide a dmcrypt secret.')
            raise SystemExit(1)

        self.objectstore = objectstore.mapping['RAW'][self.args.objectstore](args=self.args)
        self.objectstore.safe_prepare(self.args)
