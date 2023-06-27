import logging
import os
import errno
import time
from ceph_volume import conf, terminal, process
from ceph_volume.api import lvm as api
from ceph_volume.util import prepare as prepare_utils
from ceph_volume.util import system, disk
from typing import Dict, Any, Tuple, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    from ceph_volume.api.lvm import Volume

# logger = logging.getLogger(__name__)
logger = logging.getLogger('terminal')


class BaseObjectStore:
    def __init__(self, args: "argparse.Namespace") -> None:
        self.args: "argparse.Namespace" = args
        # FIXME we don't allow re-using a keyring, we always generate one
        # for the OSD, this needs to be fixed. This could either be a file (!)
        # or a string (!!) or some flags that we would need to compound
        # into a dict so that we can convert to JSON (!!!)
        self.secrets = {'cephx_secret': prepare_utils.create_key()}
        self.cephx_secret = self.secrets.get('cephx_secret',
                                             prepare_utils.create_key())
        self.encrypted = 0
        self.tags: Dict[str, Any] = {}
        self.osd_id: str = ''
        self.osd_fsid = ''
        self.block_lv: Optional["Volume"] = None
        self.cephx_lockbox_secret = ''
        self.objectstore: str = ''
        self.osd_mkfs_cmd: List[str] = []
        self.block_device_path = ''
        if hasattr(self.args, 'dmcrypt'):
            if self.args.dmcrypt:
                self.encrypted = 1
                self.cephx_lockbox_secret = prepare_utils.create_key()
                self.secrets['cephx_lockbox_secret'] = \
                    self.cephx_lockbox_secret

    def get_ptuuid(self, argument: str) -> str:
        uuid = disk.get_partuuid(argument)
        if not uuid:
            terminal.error('blkid could not detect a PARTUUID for device: %s' %
                           argument)
            raise RuntimeError('unable to use device')
        return uuid

    def get_osdspec_affinity(self) -> str:
        return os.environ.get('CEPH_VOLUME_OSDSPEC_AFFINITY', '')

    def pre_prepare(self) -> None:
        raise NotImplementedError()

    def prepare_data_device(self,
                            device_type: str,
                            osd_uuid: str) -> Optional["Volume"]:
        raise NotImplementedError()

    def safe_prepare(self, args: "argparse.Namespace") -> None:
        raise NotImplementedError()

    def add_objectstore_opts(self) -> None:
        raise NotImplementedError()

    def prepare_osd_req(self, tmpfs: bool = True) -> None:
        # create the directory
        prepare_utils.create_osd_path(self.osd_id, tmpfs=tmpfs)
        # symlink the block
        prepare_utils.link_block(self.block_device_path, self.osd_id)
        # get the latest monmap
        prepare_utils.get_monmap(self.osd_id)
        # write the OSD keyring if it doesn't exist already
        prepare_utils.write_keyring(self.osd_id, self.cephx_secret)

    def prepare(self) -> None:
        raise NotImplementedError()

    def prepare_dmcrypt(self) -> None:
        raise NotImplementedError()

    def get_cluster_fsid(self) -> str:
        """
        Allows using --cluster-fsid as an argument, but can fallback to reading
        from ceph.conf if that is unset (the default behavior).
        """
        if self.args.cluster_fsid:
            return self.args.cluster_fsid
        else:
            return conf.ceph.get('global', 'fsid')

    def setup_device(self,
                     device_type: str,
                     device_name: str,
                     tags: Dict[str, Any],
                     size: int,
                     slots: int) -> Tuple[str, str, Dict[str, Any]]:
        """
        Check if ``device`` is an lv, if so, set the tags, making sure to
        update the tags with the lv_uuid and lv_path which the incoming tags
        will not have.

        If the device is not a logical volume, then retrieve the partition UUID
        by querying ``blkid``
        """
        if device_name is None:
            return '', '', tags
        tags['ceph.type'] = device_type
        tags['ceph.vdo'] = api.is_vdo(device_name)

        try:
            vg_name, lv_name = device_name.split('/')
            lv = api.get_single_lv(filters={'lv_name': lv_name,
                                            'vg_name': vg_name})
        except ValueError:
            lv = None

        if lv:
            lv_uuid = lv.lv_uuid
            path = lv.lv_path
            tags['ceph.%s_uuid' % device_type] = lv_uuid
            tags['ceph.%s_device' % device_type] = path
            lv.set_tags(tags)
        elif disk.is_device(device_name):
            # We got a disk, create an lv
            lv_type = "osd-{}".format(device_type)
            name_uuid = system.generate_uuid()
            kwargs = {
                'device': device_name,
                'tags': tags,
                'slots': slots
            }
            # TODO use get_block_db_size and co here to get configured size in
            # conf file
            if size != 0:
                kwargs['size'] = size
            lv = api.create_lv(
                lv_type,
                name_uuid,
                **kwargs)
            path = lv.lv_path
            tags['ceph.{}_device'.format(device_type)] = path
            tags['ceph.{}_uuid'.format(device_type)] = lv.lv_uuid
            lv_uuid = lv.lv_uuid
            lv.set_tags(tags)
        else:
            # otherwise assume this is a regular disk partition
            name_uuid = self.get_ptuuid(device_name)
            path = device_name
            tags['ceph.%s_uuid' % device_type] = name_uuid
            tags['ceph.%s_device' % device_type] = path
            lv_uuid = name_uuid
        return path, lv_uuid, tags

    def get_osd_path(self) -> str:
        return '/var/lib/ceph/osd/%s-%s/' % (conf.cluster, self.osd_id)

    def build_osd_mkfs_cmd(self) -> List[str]:
        self.supplementary_command = [
            '--osd-data', self.osd_path,
            '--osd-uuid', self.osd_fsid,
            '--setuser', 'ceph',
            '--setgroup', 'ceph'
        ]
        self.osd_mkfs_cmd = [
            'ceph-osd',
            '--cluster', conf.cluster,
            '--osd-objectstore', self.objectstore,
            '--mkfs',
            '-i', self.osd_id,
            '--monmap', self.monmap,
        ]
        # if keyring is not None:
        if self.cephx_secret is not None:
            self.osd_mkfs_cmd.extend(['--keyfile', '-'])
        try:
            self.add_objectstore_opts()
        except NotImplementedError:
            logger.info("No specific objectstore options to add.")

        self.osd_mkfs_cmd.extend(self.supplementary_command)
        return self.osd_mkfs_cmd

    def osd_mkfs(self) -> None:
        self.osd_path = self.get_osd_path()
        self.monmap = os.path.join(self.osd_path, 'activate.monmap')
        cmd = self.build_osd_mkfs_cmd()

        system.chown(self.osd_path)
        for retry in range(5):
            _, _, returncode = process.call(cmd,
                                            stdin=self.cephx_secret,
                                            terminal_verbose=True,
                                            show_command=True)
            if returncode == 0:
                break
            else:
                if returncode == errno.EWOULDBLOCK:
                    time.sleep(1)
                    logger.info('disk is held by another process, '
                                'trying to mkfs again... (%s/5 attempt)' %
                                retry)
                    continue
                else:
                    raise RuntimeError('Command failed with exit code %s: %s' %
                                       (returncode, ' '.join(cmd)))

    def activate(self) -> None:
        raise NotImplementedError()
