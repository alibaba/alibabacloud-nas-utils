#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import subprocess
import signal
import time

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
    mocker.patch('watchdog.is_pid_running', return_value=True)

    procs = []
    pid = watchdog.start_proxy(procs, 'fs-deadbeef', 'stunnel')

    assert PID == pid
    assert 1 == len(procs)


def test_start_proxy_fails(mocker):
    _mock_popen(mocker)
    mocker.patch('watchdog.is_pid_running', return_value=False)

    procs = []

    with pytest.raises(RuntimeError):
        watchdog.start_proxy(procs, 'fs-deadbeef', 'stunnel')

def empty_fn():
    pass


def signal_del_fn():
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def test_subprocess_and_signal():
    # case 1
    # empty lambda not influence child
    signal.signal(signal.SIGTERM, lambda *args: None)
    p = subprocess.Popen('sleep 5', shell=True, preexec_fn=empty_fn)
    p.terminate()
    # sleep a little moment to wait process handle signal
    time.sleep(0.1)
    res = p.poll()
    assert res is not None
    assert res == -15

    # case 2
    # SIG_IGN influence child
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    p = subprocess.Popen('sleep 5', shell=True, preexec_fn=empty_fn)
    p.terminate()
    res = p.poll()
    assert res is None

    # sleep to wait process quit normally
    time.sleep(6)
    res = p.poll()
    assert res is not None
    assert res == 0

    # case 3
    # SIG_IGN can be deleted
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    p = subprocess.Popen('sleep 5', shell=True, preexec_fn=signal_del_fn)
    p.terminate()
    # sleep a little moment to wait process handle signal
    time.sleep(0.1)
    res = p.poll()
    assert res is not None
    assert res == -15

    # case 4
    # empty lambda not influence child, del signal is ok
    signal.signal(signal.SIGTERM, lambda *args: None)
    p = subprocess.Popen('sleep 5', shell=True, preexec_fn=signal_del_fn)
    p.terminate()
    # sleep a little moment to wait process handle signal
    time.sleep(0.1)
    res = p.poll()
    assert res is not None
    assert res == -15

