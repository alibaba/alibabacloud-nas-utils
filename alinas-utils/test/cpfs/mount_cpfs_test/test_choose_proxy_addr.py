#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import cpfs_nfs_common
import socket
from configparser import ConfigParser

import pytest

from mock import MagicMock


def _get_config():
    config = ConfigParser()
    config.add_section(mount_cpfs.CONFIG_SECTION)
    config.set(mount_cpfs.CONFIG_SECTION, 'proxy_port', str(8888))
    return cpfs_nfs_common.SafeConfig(config, None, None)


def test_choose_proxy_addr_first_try(mocker):
    mocker.patch('socket.socket', return_value=MagicMock())

    ip, port = mount_cpfs.choose_proxy_addr(_get_config())

    assert ip == '127.0.1.1'
    assert port == 8888


def test_choose_proxy_addr_second_try(mocker):
    bad_sk = MagicMock()
    bad_sk.bind.side_effect = [socket.error, None]
    mocker.patch('socket.socket', return_value=bad_sk)

    ip, port = mount_cpfs.choose_proxy_addr(_get_config())

    assert ip == '127.0.1.2'
    assert port == 8888
    assert bad_sk.bind.call_count == 2


def mocked_bind(addr):
    ip, port = addr
    if ip == '127.0.1.1':
        raise socket.error()
    else:
        return True


def test_choose_proxy_addr_third_try(mocker):
    bad_sk = MagicMock()
    bad_sk.bind.side_effect = mocked_bind
    mocker.patch('socket.socket', return_value=bad_sk)

    ip, port = mount_cpfs.choose_proxy_addr(_get_config())

    assert ip == '127.0.1.2'
    assert port == 8888
    assert bad_sk.bind.call_count == 2


def test_choose_proxy_addr_never_succeeds(mocker, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()

    mocker.patch('socket.socket', return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_cpfs.choose_proxy_addr(_get_config())

    assert ex.value.code != 0

    out, err = capsys.readouterr()
    assert 'Failed to find a loopback ip' in err


def test_choose_proxy_addr_conflict(mocker, tmpdir):
    mocker.patch('socket.socket', return_value=MagicMock())

    ip, port = mount_cpfs.choose_proxy_addr(_get_config(), str(tmpdir))

    assert ip == '127.0.1.1'
    assert port == 8888

    tmpdir.join('xxx.127.0.1.1').write('xxx')
    ip, port = mount_cpfs.choose_proxy_addr(_get_config(), str(tmpdir))

    assert ip == '127.0.1.2'
    assert port == 8888

    tmpdir.join('xxx.127.0.1.2').write('xxx')
    tmpdir.join('xxx.127.0.1.3').write('xxx')

    ip, port = mount_cpfs.choose_proxy_addr(_get_config(), str(tmpdir))

    assert ip == '127.0.1.4'
    assert port == 8888
