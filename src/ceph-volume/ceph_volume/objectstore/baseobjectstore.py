import logging
import os
import errno
import time
import tempfile
from ceph_volume import conf, terminal, process
from ceph_volume.util import prepare as prepare_utils
from ceph_volume.util import system, disk
from ceph_volume.util import encryption as encryption_utils
from typing import Dict, Any, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import argparse
    from ceph_volume.api.lvm import Volume


logger = logging.getLogger(__name__)


class BaseObjectStore:
    def __init__(self, args: "argparse.Namespace") -> None:
        self.args: "argparse.Namespace" = args
        self.secrets: Dict[str, str] = {}
        self.cephx_secret: str = ""
        self.encrypted: int = 0
        self.tags: Dict[str, Any] = {}
        self.osd_id: str = ''
        self.osd_fsid: str = ''
        self.cephx_lockbox_secret: str = ''
        self.objectstore: str = ''
        self.osd_mkfs_cmd: List[str] = []
        self.block_device_path: str = ''
        self.dmcrypt_key: str = encryption_utils.create_dmcrypt_key()
        self.with_tpm: int = int(getattr(self.args, 'with_tpm', False))
        self.method: str = ''

    @classmethod
    async def create(cls, args: "argparse.Namespace") -> "BaseObjectStore":
        self = cls(args)
        self.secrets['cephx_secret'] = await prepare_utils.create_key()
        self.cephx_secret = self.secrets['cephx_secret']

        if getattr(self.args, 'dmcrypt', False):
            self.encrypted = 1
            if not self.with_tpm:
                self.cephx_lockbox_secret = await prepare_utils.create_key()
                self.secrets['cephx_lockbox_secret'] = self.cephx_lockbox_secret

        return self

    async def get_ptuuid(self, argument: str) -> str:
        uuid = await disk.get_partuuid(argument)
        if not uuid:
            terminal.error('blkid could not detect a PARTUUID for device: %s' %
                           argument)
            raise RuntimeError('unable to use device')
        return uuid

    def get_osdspec_affinity(self) -> str:
        return os.environ.get('CEPH_VOLUME_OSDSPEC_AFFINITY', '')

    async def pre_prepare(self) -> None:
        raise NotImplementedError()

    async def prepare_data_device(self,
                            device_type: str,
                            osd_uuid: str) -> Optional["Volume"]:
        raise NotImplementedError()

    async def safe_prepare(self, args: Optional["argparse.Namespace"] = None) -> None:
        raise NotImplementedError()

    async def add_objectstore_opts(self) -> None:
        raise NotImplementedError()

    async def prepare_osd_req(self, tmpfs: bool = True) -> None:
        # create the directory
        await prepare_utils.create_osd_path(self.osd_id, tmpfs=tmpfs)
        # symlink the block
        await prepare_utils.link_block(self.block_device_path, self.osd_id)
        # get the latest monmap
        await prepare_utils.get_monmap(self.osd_id)
        # write the OSD keyring if it doesn't exist already
        await prepare_utils.write_keyring(self.osd_id, self.cephx_secret)

    async def prepare(self) -> None:
        raise NotImplementedError()

    async def prepare_dmcrypt(self) -> None:
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

    def get_osd_path(self) -> str:
        return '/var/lib/ceph/osd/%s-%s/' % (conf.cluster, self.osd_id)

    async def build_osd_mkfs_cmd(self) -> List[str]:
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
        if self.cephx_secret is not None:
            self.osd_mkfs_cmd.extend(['--keyfile', '-'])
        try:
            await self.add_objectstore_opts()
        except NotImplementedError:
            logger.info("No specific objectstore options to add.")

        self.osd_mkfs_cmd.extend(self.supplementary_command)
        return self.osd_mkfs_cmd

    async def osd_mkfs(self) -> None:
        self.osd_path = self.get_osd_path()
        self.monmap = os.path.join(self.osd_path, 'activate.monmap')
        cmd = await self.build_osd_mkfs_cmd()

        await system.chown(self.osd_path)
        """
        When running in containers the --mkfs on raw device sometimes fails
        to acquire a lock through flock() on the device because systemd-udevd holds one temporarily.
        See KernelDevice.cc and _lock() to understand how ceph-osd acquires the lock.
        Because this is really transient, we retry up to 5 times and wait for 1 sec in-between
        """
        for retry in range(5):
            _, _, returncode = await process.call(cmd,
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

    async def activate(self) -> None:
        raise NotImplementedError()

    async def activate_all(self) -> None:
        raise NotImplementedError()

    async def enroll_tpm2(self, device: str) -> None:
        """
        Enrolls a device with TPM2 (Trusted Platform Module 2.0) using systemd-cryptenroll.
        This method creates a temporary file to store the dmcrypt key and uses it to enroll the device.

        Args:
            device (str): The device path to be enrolled with TPM2.
        """

        if self.with_tpm:
            tmp_dir: str = '/rootfs/tmp' if os.environ.get('I_AM_IN_A_CONTAINER', False) else '/tmp'
            with tempfile.NamedTemporaryFile(mode='w', delete=True, dir=tmp_dir) as temp_file:
                temp_file.write(self.dmcrypt_key)
                temp_file.flush()
                temp_file_name: str = temp_file.name.replace('/rootfs', '', 1)
                cmd: List[str] = ['systemd-cryptenroll', '--tpm2-device=auto',
                                  device, '--unlock-key-file', temp_file_name,
                                  '--tpm2-pcrs', '9+12', '--wipe-slot', 'tpm2']
                await process.call(cmd, run_on_host=True, show_command=True)
