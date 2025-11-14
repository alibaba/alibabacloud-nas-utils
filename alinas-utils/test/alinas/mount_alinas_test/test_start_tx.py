#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import os
import mount_alinas

import pytest
from mock import MagicMock


PROXY_IP = '127.0.1.1'
PROXY_PORT = 8888
FS_ID = '123456ab00'
DNS_NAME = '{}-abc00.cn-beijing.nas.aliyuncs.com'.format(FS_ID)
NAS_IP = '8.8.8.8'
UUID = 'testuuid'


def mock_start_watchdog(mocker):
    return mocker.patch('mount_alinas.start_watchdog')


def mock_choose_proxy_addr(mocker):
    return mocker.patch('mount_alinas.choose_proxy_addr', return_value=(PROXY_IP, PROXY_PORT))


def mock_local_dns(mocker):
    return mocker.patch('mount_alinas.setup_local_dns')


def mock_popen(mocker):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = 0

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_start_tx_tls(mocker, tmpdir):
    mocker.patch('socket.socket', return_value=MagicMock())
    watchdog_mock = mock_start_watchdog(mocker)
    choose_addr_mock = mock_choose_proxy_addr(mocker)
    popen_mock = mock_popen(mocker)
    dns_mock = mock_local_dns(mocker)
    options = {'vers': 4.0, 'tls': None}
    proxy_proc_mock = MagicMock()
    proxy_proc_mock.pid = 1000
    mocker.patch('mount_alinas.resolve_dns', return_value=NAS_IP)
    mocker.patch('mount_alinas.gen_tls_local_dns_with_uuid',
		    return_value=('{}.tls.{}-{}'.format(FS_ID, PROXY_IP, UUID), UUID))

    ctx = mount_alinas.MountContext('config', 'init', DNS_NAME, FS_ID, 'home', '/mnt', None, options)
    with mount_alinas.start_tx('tx', ctx, str(tmpdir)) as tx:
        assert options['proxy'] == PROXY_IP
        assert options['proxy_port'] == PROXY_PORT
        assert options['clientaddr'] == mount_alinas.get_clientaddr(DNS_NAME, NAS_IP)
        assert '{}.tls.{}-{}'.format(FS_ID, PROXY_IP, UUID) == tx.local_dns
        tx.commit('configfile', proxy_proc_mock, ['a', 'b', 'c'])

    watchdog_mock.assert_called_once()
    watchdog_mock.assert_called_with('init')
    dns_mock.assert_called_once()
    dns_mock.assert_called_with(mount_alinas.compose_local_dns_with_uuid(FS_ID, PROXY_IP, is_tls=True)[0], PROXY_IP, options)
    choose_addr_mock.assert_called_once()
    choose_addr_mock.assert_called_with('config', str(tmpdir))
    popen_mock.assert_called_once()

    state_file, _ = mount_alinas.compose_local_dns_with_uuid(FS_ID,
                                                   PROXY_IP,
                                                   is_tls=True)
    with open(os.path.join(str(tmpdir), state_file)) as f:
        import json

        state = json.load(f)
        assert state['pid'] == proxy_proc_mock.pid
        assert state['cmd'] == ['a', 'b', 'c']
        assert state['files'] == ['configfile']
        assert state['local_ip'] == PROXY_IP
        assert state['local_dns'] == state_file
        assert state['nas_dns'] == DNS_NAME
        assert state['nas_ip'] == NAS_IP
        assert state['uuid'] == UUID 
