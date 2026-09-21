#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs

EXPECTED_CMD = (
    'ss -ntapH src 127.0.1.1:30000 or dst 127.0.1.1:30000'
    '| grep -w 127.0.1.1:30000'
)


def _patch_devnull(mocker):
    # open() is used as a context manager; mock_open makes the value bound by
    # `with open(...) as devnull` be the mock's return_value.
    open_mock = mocker.patch('builtins.open', mocker.mock_open())
    return open_mock.return_value


def test_port_is_used_true(mocker):
    devnull = _patch_devnull(mocker)
    call_mock = mocker.patch('subprocess.call', return_value=0)

    assert mount_cpfs.cpfs_port_is_used('127.0.1.1', 30000) is True

    call_mock.assert_called_once_with(
        EXPECTED_CMD,
        shell=True,
        stdout=devnull,
        stderr=devnull,
    )


def test_port_is_used_false(mocker):
    devnull = _patch_devnull(mocker)
    call_mock = mocker.patch('subprocess.call', return_value=1)

    assert mount_cpfs.cpfs_port_is_used('127.0.1.1', 30000) is False

    call_mock.assert_called_once_with(
        EXPECTED_CMD,
        shell=True,
        stdout=devnull,
        stderr=devnull,
    )


def test_port_is_used_grep_no_match(mocker):
    # grep returns 1 when no line matches, so the port is reported as free.
    _patch_devnull(mocker)
    mocker.patch('subprocess.call', return_value=1)

    assert mount_cpfs.cpfs_port_is_used('127.0.1.1', 30000) is False
