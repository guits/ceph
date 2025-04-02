"""
Utilities to control systemd units
"""
import logging

from ceph_volume import process
from typing import List

logger = logging.getLogger(__name__)

async def start(unit: str) -> None:
    await process.run(['systemctl', 'start', unit])


async def stop(unit: str) -> None:
    await process.run(['systemctl', 'stop', unit])


async def enable(unit: str, runtime: bool = False) -> None:
    if runtime:
        await process.run(['systemctl', 'enable', '--runtime', unit])
    else:
        await process.run(['systemctl', 'enable', unit])


async def disable(unit: str) -> None:
    await process.run(['systemctl', 'disable', unit])


async def mask(unit: str) -> None:
    await process.run(['systemctl', 'mask', unit])


async def is_active(unit: str) -> bool:
    _, _, rc = await process.call(
        ['systemctl', 'is-active', unit],
        verbose_on_failure=False
    )
    return rc == 0

async def get_running_osd_ids() -> List[str]:
    out, _, rc = await process.call([
        'systemctl',
        'show',
        '--no-pager',
        '--property=Id',
        '--state=running',
        'ceph-osd@*',
    ])
    osd_ids = []
    if rc == 0:
        for line in out:
            if line:
                # example line looks like: Id=ceph-osd@1.service
                try:
                    osd_id = line.split("@")[1].split(".service")[0]
                    osd_ids.append(osd_id)
                except (IndexError, TypeError):
                    logger.warning("Failed to parse output from systemctl: %s", line)
    return osd_ids

async def start_osd(id_: str) -> None:
    return await start(osd_unit % id_)


async def stop_osd(id_: str) -> None:
    return await stop(osd_unit % id_)


async def enable_osd(id_: str) -> None:
    return await enable(osd_unit % id_, runtime=True)


async def disable_osd(id_: str) -> None:
    return await disable(osd_unit % id_)


async def osd_is_active(id_: str) -> bool:
    return await is_active(osd_unit % id_)


async def enable_volume(id_: str, fsid: str, device_type: str = 'lvm') -> None:
    return await enable(volume_unit % (device_type, id_, fsid))


async def mask_ceph_disk() -> None:
    # systemctl allows using a glob like '*' for masking, but there was a bug
    # in that it wouldn't allow this for service templates. This means that
    # masking ceph-disk@* will not work, so we must link the service directly.
    # /etc/systemd takes precedence regardless of the location of the unit
    await process.run(
        ['ln', '-sf', '/dev/null', '/etc/systemd/system/ceph-disk@.service']
    )


#
# templates
#

osd_unit = "ceph-osd@%s"
ceph_disk_unit = "ceph-disk@%s"
volume_unit = "ceph-volume@%s-%s-%s"
