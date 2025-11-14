#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas

import pytest

from mock import MagicMock

DNS_NAME = '123456ab00-abc00.cn-beijing.nas.aliyuncs.com'
DEFAULT_OPTIONS = {'vers': 4.0,
                   'rsize': 1048576, 'wsize': 1048576,
                   'hard': None,
                   'timeo': 600, 'retrans': 2}

# indices of different arguments to the NFS call
NFS_BIN_ARG_IDX = 0
NFS_MOUNT_PATH_IDX = 1
NFS_MOUNT_POINT_IDX = 2
NFS_OPTION_FLAG_IDX = 3
NFS_OPTIONS_IDX = 4


def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr'.encode(), )
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_mount_default(mocker):
    mock = _mock_popen(mocker)

    options = {}
    mount_alinas.mount_nfs_directly(DNS_NAME, '/', '/mnt', options)

    args, _ = mock.call_args
    args = args[0]

    assert '/sbin/mount.nfs' == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[NFS_MOUNT_PATH_IDX]
    assert '/mnt' == args[NFS_MOUNT_POINT_IDX]



def test_mount_nfs_v3(mocker):
    mock = _mock_popen(mocker)

    options = dict(DEFAULT_OPTIONS)
    options['vers'] = 3
    mount_alinas.mount_nfs_directly(DNS_NAME, '/', '/mnt', options)

    args, _ = mock.call_args
    args = args[0]

    assert '/sbin/mount.nfs' == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[NFS_MOUNT_PATH_IDX]
    assert '/mnt' == args[NFS_MOUNT_POINT_IDX]


def test_mount_nfs_v4(mocker):
    mock = _mock_popen(mocker)

    options = dict(DEFAULT_OPTIONS)
    options['vers'] = 4.0
    mount_alinas.mount_nfs_directly(DNS_NAME, '/', '/mnt', options)

    args, _ = mock.call_args
    args = args[0]

    assert '/sbin/mount.nfs4' == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[NFS_MOUNT_PATH_IDX]
    assert '/mnt' == args[NFS_MOUNT_POINT_IDX]


def test_mount_nfs_failure(mocker):
    _mock_popen(mocker, returncode=1)

    with pytest.raises(SystemExit) as ex:
        mount_alinas.mount_nfs_directly(DNS_NAME, '/', '/mnt', DEFAULT_OPTIONS)

    assert 0 != ex.value.code
