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

import pytest

from mock import MagicMock

PID = 1234


def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.pid = PID
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_start_proxy(mocker):
    _mock_popen(mocker)
    mocker.patch('cpfs_nfs_common.is_pid_running', return_value=True)

    procs = []
    pid = watchdog.start_proxy(procs, 'fs-deadbeef', 'stunnel')

    assert PID == pid
    assert 1 == len(procs)


def test_start_proxy_fails(mocker):
    _mock_popen(mocker)
    mocker.patch('cpfs_nfs_common.is_pid_running', return_value=False)

    procs = []

    with pytest.raises(RuntimeError):
        watchdog.start_proxy(procs, 'fs-deadbeef', 'stunnel')
