#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import subprocess

import pytest

import cpfs_nfs_tool.switch_server as switch_server


def test_get_haproxy_pid_uses_pgrep(mocker):
    check_output_mock = mocker.patch('subprocess.check_output', return_value=b'12345\n')

    result = switch_server.get_haproxy_pid('foo.cpfs.aliyuncs.com')

    assert result == b'12345\n'
    check_output_mock.assert_called_once_with(
        ['pgrep', '-f', r'haproxy.*foo\.cpfs\.aliyuncs\.com']
    )


def test_get_haproxy_pid_failure_calls_fatal_error(mocker):
    mocker.patch('subprocess.check_output', side_effect=subprocess.CalledProcessError(1, ['pgrep']))
    fatal_error_mock = mocker.patch('cpfs_nfs_tool.switch_server.fatal_error')

    switch_server.get_haproxy_pid('foo.cpfs.aliyuncs.com')

    fatal_error_mock.assert_called_once_with('Failed to get proxy pid: foo.cpfs.aliyuncs.com')
