#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import cpfs_nfs_common


MOUNT_FMT_LINE = '{address}:/ {mountpoint} {fs_type} {options},addr={address} 0 0'
DEFAULT_OPTS = 'rw,port=12345'


def _create_mount_file(tmpdir, lines):
    mount_file = tmpdir.join('mounts')
    mount_file.write('\n'.join(lines))
    return str(mount_file)


def test_no_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [])

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert mounts == {}


def test_no_local_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='10.1.0.1', mountpoint='/mnt',
                                                                   fs_type='nfs4', options=DEFAULT_OPTS)])

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert mounts == {}


def test_no_local_nfs_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='127.0.0.1', mountpoint='/mnt',
                                                                   fs_type='ext4', options=DEFAULT_OPTS)])

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert mounts == {}


def test_local_nfs_mount_non_alinas(tmpdir):
    fstab = [
        MOUNT_FMT_LINE.format(address='127.0.0.1', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='127.0.1.1', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='127.0.2.1', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='127.0.0.2', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='127.0.1.2', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='127.0.2.2', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
    ]
    mount_file = _create_mount_file(tmpdir, fstab)

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert len(mounts) == 0


def test_local_nfs_mount(tmpdir):
    fstab = [
        MOUNT_FMT_LINE.format(address='cpfs-127.0.0.1.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='cpfs-127.0.1.1.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='cpfs-127.0.2.1.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs4', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='cpfs-127.0.0.2.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='cpfs-127.0.1.2.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
        MOUNT_FMT_LINE.format(address='cpfs-127.0.2.2.cpfs.aliyuncs.com', mountpoint='/mnt', fs_type='nfs', options=DEFAULT_OPTS),
    ]
    mount_file = _create_mount_file(tmpdir, fstab)

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert len(mounts) == 6
    assert 'cpfs-127.0.0.1.cpfs.aliyuncs.com' in mounts
    assert 'cpfs-127.0.1.1.cpfs.aliyuncs.com' in mounts
    assert 'cpfs-127.0.2.1.cpfs.aliyuncs.com' in mounts
    assert 'cpfs-127.0.0.2.cpfs.aliyuncs.com' in mounts
    assert 'cpfs-127.0.1.2.cpfs.aliyuncs.com' in mounts
    assert 'cpfs-127.0.2.2.cpfs.aliyuncs.com' in mounts


def test_local_nfs_mount_noresvport(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='cpfs-127.0.0.1.cpfs.aliyuncs.com', mountpoint='/mnt',
                                                                   fs_type='nfs4', options='rw,noresvport,addr=12345')])

    mounts = cpfs_nfs_common.get_current_local_nfs_mounts(mount_file)

    assert len(mounts) == 1
    assert 'cpfs-127.0.0.1.cpfs.aliyuncs.com' in mounts
