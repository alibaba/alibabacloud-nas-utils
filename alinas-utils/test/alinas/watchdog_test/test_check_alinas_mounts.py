#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json
import tempfile

from mock import MagicMock


TIME = 1514764800
GRACE_PERIOD = 30
PID = 1234
UUID = 'test-uuid-123'
STATE = {
    'pid': PID,
    'uuid': UUID
}


def setup_mocks(mocker, mounts, state_files, is_pid_running=True, ps_info=''):
    state = dict(STATE)
    state['unmount_time'] = TIME - GRACE_PERIOD

    mocker.patch('watchdog.get_current_local_nfs_mounts', return_value=mounts)
    mocker.patch('watchdog.get_current_unas_mounts', return_value=mounts)
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    mocker.patch('watchdog.is_pid_running', return_value=is_pid_running)
    mocker.patch('watchdog.mark_as_unmounted', return_value=state)
    mocker.patch('os.popen', return_value=MagicMock(read=MagicMock(return_value=ps_info)))
    mocker.patch('time.time', return_value=TIME + GRACE_PERIOD + 1)

    clean_up_mock = mocker.patch('watchdog.clean_up_mount_state')
    restart_proxy = mocker.patch('watchdog.restart_proxy')

    return clean_up_mock, restart_proxy


def _setup_watchdog_mock(mocker):
    wd = MagicMock()
    fm = watchdog.StateFileManager()
    wd.load_state_file.side_effect = fm.load_state_file
    return wd


def create_state_file(tmpdir, state=STATE):
    if type(state) is not str:
        state[watchdog.STATE_SIGN] = watchdog.sign_state(state)
        state = json.dumps(state)

    state_file = tmpdir.join(tempfile.mktemp())
    state_file.write(state, ensure=True)

    return state_file.dirname, state_file.basename


def test_no_state_files(mocker):
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                               state_files={})
    wd = _setup_watchdog_mock(mocker)

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_malformed_state_file(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir, 'not-json')

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_no_mount_for_state_file(mocker, tmpdir):
    state = dict(STATE)

    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_no_mount_for_state_file_out_of_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state['unmount_time'] = TIME - GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker, 
                                               mounts={}, 
                                               state_files={'mnt': state_file},
                                               ps_info='')

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_called_once()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_no_mount_for_state_file_in_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state['unmount_time'] = TIME + GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_tls_not_running(mocker, tmpdir):
    state = dict(STATE)
    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                               state_files={'mnt': state_file}, 
                                               is_pid_running=False,
                                               ps_info='') 

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_called_once()
    #wd.handle_events.assert_called_once()

def test_tls_not_running_when_pid_exist(mocker, tmpdir):
    state = dict(STATE)
    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                               state_files={'mnt': state_file}, 
                                               is_pid_running=True,
                                               ps_info='')

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_called_once()

def test_tls_not_running_with_old_version_state(mocker, tmpdir):
    state = dict(STATE)
    del state['uuid'] # old version not have uuid
    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                               state_files={'mnt': state_file}, 
                                               is_pid_running=True,
                                               ps_info='')

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()

def test_extra_mount(mocker, tmpdir):
    state = dict(STATE)
    state_file_dir, state_file = create_state_file(tmpdir, state)

    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts={
                                                   'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0'),
                                                   'mnt2': watchdog.Mount('192.168.1.1', '/mnt2', 'nfs4', '', '0', '0'),
                                               },
                                               state_files={'mnt3': state_file})

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_proxy.assert_not_called()
    #wd.handle_events.assert_called_once()


def test_mixed_scenarios_normal_restart_cleanup(mocker, tmpdir):
    # State 1: Normal running
    state1 = dict(STATE)
    state1_file_dir, state1_file = create_state_file(tmpdir, state1)
    
    # State 2: Need restart (proxy not running)
    state2 = dict(STATE)
    state2['pid'] = 5678
    state2['uuid'] = 'test-uuid-456'
    state2_file_dir, state2_file = create_state_file(tmpdir, state2)
    
    # State 3: Need cleanup (grace period expired)
    state3 = dict(STATE)
    state3['pid'] = 9012
    state3['uuid'] = 'test-uuid-789'
    state3['unmount_time'] = TIME - GRACE_PERIOD - 1  # Expired
    state3_file_dir, state3_file = create_state_file(tmpdir, state3)
    
    state_files = {
        'mnt1': state1_file,
        'mnt2': state2_file,
        'mnt3': state3_file
    }
    
    mounts = {
        'mnt1': watchdog.Mount('127.0.0.1', '/mnt1', 'nfs4', '', '0', '0'),
        'mnt2': watchdog.Mount('127.0.0.2', '/mnt2', 'nfs4', '', '0', '0'),
        'mnt3': watchdog.Mount('127.0.0.3', '/mnt3', 'nfs4', '', '0', '0'),
    }
    
    # ps info: only state1 and state3 processes are running
    ps_info = '1234 stunnel-test-uuid-123\n9012 stunnel-test-uuid-789'
    
    wd = _setup_watchdog_mock(mocker)
    clean_up_mock, restart_proxy = setup_mocks(mocker,
                                               mounts=mounts,
                                               state_files=state_files,
                                               ps_info='stunnel-test-uuid-123\n9012 stunnel-test-uuid-789')

    watchdog.check_nfs_mounts(wd, GRACE_PERIOD, state1_file_dir)

    # Verify:
    # 1. state3 triggers cleanup (grace period expired)
    # 2. state2 triggers restart (proxy not running)
    # 3. state1 triggers no operation (normal)
    clean_up_mock.assert_called_once_with(
        state3_file_dir, 
        state3_file,
        state3['pid'],
        True,
        None
    )    

    state2.pop(watchdog.STATE_SIGN, '')
    restart_proxy.assert_called_once_with(
        wd.child_procs,
        state2,
        state2_file_dir,
        state2_file
    )

