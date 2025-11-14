#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas
from contextlib import contextmanager
from mock import MagicMock, patch
from configparser import ConfigParser
from multiprocessing import Process, Manager
import os
import json

local_dns = 'alinas-abcde.127.0.0.1'
local_ip = '127.0.0.1'
tx = mount_alinas.Tx(local_dns)

@contextmanager
def dummy_context(*args, **kwargs):
    yield tx

def test_mount_proxy(mocker):
    start_tx_mock = mocker.patch('mount_alinas.start_tx', side_effect=dummy_context)
    bootstrap_mock = mocker.patch('mount_alinas.bootstrap_tls', return_value=('a', 'b', 'c', None))

    ctx = mount_alinas.MountContext('config', 'init', 'dns', 'alinas-abcde', 'path', 'mp', 'credentials', 'options')
    mount_alinas.mount_tls(ctx)

    bootstrap_mock.assert_called_once()
    bootstrap_mock.assert_called_with('config', 'alinas-abcde', 'mp', local_dns, 'dns', 'credentials', 'options')
    start_tx_mock.assert_called_once()
    start_tx_mock.assert_called_with('Stunnel', ctx)

    assert tx.config_file == 'a'
    assert tx.process == 'b'
    assert tx.cmd == 'c'

def _mock_mount_process(mocker, tmpdir):
    mocker.patch('mount_alinas.choose_proxy_addr', return_value=(local_ip, '8888'))
    mocker.patch('mount_alinas.start_watchdog')
    mocker.patch('mount_alinas.subprocess_call')
    mocker.patch('mount_alinas.poll_proxy_process')
    mocker.patch('mount_alinas.setup_local_dns')
    mocker.patch('mount_alinas.wait_for_proxy_ready')
    mocker.patch('mount_alinas.get_version_specific_stunnel_options', return_value=(True, True))

    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = 0 
    popen_mock.pid = 'pid'
    mocker.patch('subprocess.Popen', return_value=popen_mock)

    def create_tmp_state_dir_wrapper(original_function, tmpdir):
        def wrapper(*args, **kwargs):
            kwargs['state_file_dir'] = tmpdir
            return original_function(*args, **kwargs)
        return wrapper

    start_tx_wrapper = create_tmp_state_dir_wrapper(mount_alinas.start_tx, tmpdir)
    bootstrap_tls_wrapper = create_tmp_state_dir_wrapper(mount_alinas.bootstrap_tls, tmpdir)

    mocker.patch('mount_alinas.start_tx', new=start_tx_wrapper)
    mocker.patch('mount_alinas.bootstrap_tls', new=bootstrap_tls_wrapper)

def test_uuid(mocker, tmpdir):
    _mock_mount_process(mocker, tmpdir)

    uuid = 'TeST1234'
    mocker.patch('mount_alinas.gen_short_uuid', return_value=uuid)

    config = mount_alinas.SafeConfig(ConfigParser(), None, None)
    ctx = mount_alinas.MountContext(config, 'init', 'dns', 'alinas-abcde', 'path', 'mp', None, {'tls':None})
    mount_alinas.mount_tls(ctx)

    state_file = mount_alinas.tls_local_dns('alinas-abcde', local_ip, uuid)
    abs_state_file = os.path.join(tmpdir, state_file)
    with open(abs_state_file) as f:
        state = json.load(f)
    assert uuid == state.get('uuid')
    state_dir = state.get('mountStateDir')
    stunnel_config = state.get('config_file')
    certificate = state.get('certificate')
    assert uuid in state_file
    assert uuid in state_dir
    assert uuid in stunnel_config
    assert uuid in certificate

    abs_state_dir = os.path.join(tmpdir, state_dir)
    abs_stunnel_config = os.path.join(tmpdir, stunnel_config)
    assert os.path.exists(abs_state_dir)
    assert os.path.exists(abs_stunnel_config)

def test_uuid_for_concurrent_mounts(mocker, tmpdir):
    _mock_mount_process(mocker, tmpdir)

    config = mount_alinas.SafeConfig(ConfigParser(), None, None)
    ctx = mount_alinas.MountContext(config, 'init', 'dns', 'alinas-abcde', 'path', 'mp', None, {'tls':None})

    pnum = 20
    procs = []
    uuids = Manager().list()
    for _ in range(pnum):
        p = Process(target=mount_alinas.mount_tls, args=(ctx,))
        procs.append(p)

    for p in procs:
        p.start()
    
    for p in procs:
        p.join()
        assert p.exitcode == 0

    state_files = []
    for f in os.listdir(tmpdir):
        if f.startswith('alinas-') and os.path.isfile(os.path.join(tmpdir, f)):
            state_files.append(f)
    assert len(state_files) == pnum

    uuids = []
    state_dirs = []
    stunnel_configs = []
    certificates = []
    for state_file in state_files:
        abs_state_file = os.path.join(tmpdir, state_file)
        with open(abs_state_file) as f:
            state = json.load(f)
            uuid = state.get('uuid')
            state_dir = state.get('mountStateDir')
            stunnel_config = state.get('config_file')
            certificate = state.get('certificate')

            assert os.path.exists(os.path.join(tmpdir, state_dir))
            assert os.path.exists(os.path.join(tmpdir, stunnel_config))

            uuids.append(uuid)
            state_dirs.append(state_dir)
            stunnel_configs.append(stunnel_config)
            certificates.append(certificate)

    assert len(set(uuids)) == pnum
    assert len(set(state_dirs)) == pnum
    assert len(set(stunnel_configs)) == pnum
    assert len(set(certificates)) == pnum

def test_setup_local_dns(mocker, tmpdir):
    dns = 'www.abc.com'
    ip = '1.1.1.1'
    options = {}
    hostfile = os.path.join(tmpdir, 'testhosts')
    open(hostfile, 'w')
    mount_alinas.setup_local_dns(dns, ip, options, hostfile=hostfile)
    assert open(hostfile, 'r').read().find(dns) >= 0
    assert open(hostfile, 'r').read().find(ip) >= 0

    original_func = mount_alinas.atomic_write_hostfile
    with patch('mount_alinas.atomic_write_hostfile') as atomic_rename_mock:
        def mock_atomic_write_hostfile(*args, **kwargs):
            print(kwargs)
            if 'tmpdir' in kwargs and kwargs['tmpdir'] == '/tmp':
                raise OSError("mock error")
            else:
                original_func(*args)
        atomic_rename_mock.side_effect = mock_atomic_write_hostfile  
        dns = 'www.efc.com'
        ip = '2.2.2.2'
        mount_alinas.setup_local_dns(dns, ip, options, hostfile=hostfile)
        assert atomic_rename_mock.call_count == 2
        assert open(hostfile, 'r').read().find(dns) >= 0
        assert open(hostfile, 'r').read().find(ip) >= 0

