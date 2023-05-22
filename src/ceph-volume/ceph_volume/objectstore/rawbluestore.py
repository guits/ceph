import logging
import json
from .bluestore import BlueStore
from ceph_volume import terminal, decorators
from ceph_volume.util import system
from ceph_volume.util import prepare as prepare_utils
from ceph_volume.devices.lvm.common import rollback_osd

logger = logging.getLogger(__name__)

class RawBlueStore(BlueStore):
    def __init__(self, args):
        super().__init__(args)
        self.block_device_path = self.args.data

    def safe_prepare(self, args=None):
        """
        An intermediate step between `main()` and `prepare()` so that we can
        capture the `self.osd_id` in case we need to rollback

        :param args: Injected args, usually from `raw create` which compounds
                     both `prepare` and `create`
        """
        if args is not None:
            self.args = args # This should be moved (to __init__ ?)
        try:
            self.prepare()
        except Exception:
            logger.exception('raw prepare was unable to complete')
            logger.info('will rollback OSD ID creation')
            rollback_osd(self.args, self.osd_id)
            raise
        dmcrypt_log = 'dmcrypt' if args.dmcrypt else 'clear'
        terminal.success("ceph-volume raw {} prepare successful for: {}".format(dmcrypt_log, self.args.data))

    @decorators.needs_root
    def prepare(self):
        if self.encrypted:
            self.secrets['dmcrypt_key'] = os.getenv('CEPH_VOLUME_DMCRYPT_SECRET')
        self.osd_fsid = system.generate_uuid()
        crush_device_class = self.args.crush_device_class
        if crush_device_class:
            self.secrets['crush_device_class'] = crush_device_class

        tmpfs = not self.args.no_tmpfs
        if self.args.block_wal:
            self.wal = self.args.block_wal
        if self.args.block_db:
            self.db = self.args.block_db

        # reuse a given ID if it exists, otherwise create a new ID
        self.osd_id = prepare_utils.create_id(
            self.osd_fsid, json.dumps(self.secrets))

        self.prepare_osd_req(tmpfs=tmpfs)

        # prepare the osd filesystem
        self.osd_mkfs()
