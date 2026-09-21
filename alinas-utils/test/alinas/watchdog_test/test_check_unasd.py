#
# Copyright 2020-2022 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import sys
import os
import time
import json
import shutil
import fcntl
import tempfile
import socket
from contextlib import contextmanager
from multiprocessing import Process, Event
from mock import MagicMock, patch
from mock_open import MockOpen
import pytest
import watchdog
import efc_process
from watchdog import _cleanup_unmounted_logs_by_size, TOTAL_UNMOUNTED_LOG_MAX_SIZE

FILE_PREFIX = 'eac-'
BUILTIN_OPEN_FUNC = "builtins.open"
if sys.version_info < (3, 0):
    BUILTIN_OPEN_FUNC = "__builtin__.open"

def _mock_os_popen(mocker, return_str):
    fd = os.popen("echo {}".format(return_str))
    return mocker.patch("os.popen", return_value=fd)

def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = returncode
    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def _efc_probe(state, pid=123, proc_state='S'):
    return efc_process.EfcProbeResult(
        state=state,
        owner_pid=pid,
        proc_state=proc_state,
        proc_starttime=456 if pid else 0,
        proc_comm='aliyun-alinas-e' if pid else '',
        lock_path='/var/run/efc/mount_uuid_test.efc.lock',
        lock_dev=1 if pid else 0,
        lock_inode=2 if pid else 0,
        pidfile_pid=pid,
        pidfile_match=bool(pid),
        reason='test',
    )


def setup_mocks(mocker):
    fm = watchdog.StateFileManager()
    #mocker.patch('watchdog.write_unas_state_file')
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_RUNNING),
    )
    clean_up = mocker.patch('watchdog.schedule_clean_up_mount_files')
    restart_unas = mocker.patch('watchdog.restart_unas_process')
    mocker.patch('watchdog.check_unas_sessmgr')
    mocker.patch('watchdog.schedule_discover_dadi')
    return restart_unas, clean_up


def _setup_watchdog_mock(mocker):
    wd = MagicMock()
    fm = watchdog.StateFileManager()
    wd.load_state_file.side_effect = fm.load_state_file
    return wd


# copied from test_lock_alinas.py
def do_lock(lock_file, ready_event, exit_event):
    fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        ready_event.set()

    exit_event.wait()

@contextmanager
def lock_unas(state_dir, expected_success):
    lock_file = os.path.join(state_dir, watchdog.ALINAS_LOCK)

    ready_event = Event()
    exit_event = Event()
    p = Process(target=do_lock, args=(lock_file, ready_event, exit_event))
    p.start()
    ready_event.wait()

    try:
        yield
    finally:
        exit_event.set()
        p.join()

    if expected_success:
        assert p.exitcode == 0
    else:
        assert p.exitcode != 0

def create_state_file(tmpdir, state):
    if 'mountuuid' not in state:
        state['mountuuid'] = 'mount_uuid_test'
    if 'mountpoint' not in state:
        state['mountpoint'] = 'mount_point_test'
    if 'mountpath' not in state:
        state['mountpath'] = 'mount_path_test'
    if 'mountcmd' not in state:
        state['mountcmd'] = 'mount_cmd_test'
    if 'mountkey' not in state:
        state['mountkey'] = 'mount_key_test'

    state[watchdog.STATE_SIGN] = watchdog.sign_state(state)
    state = json.dumps(state)

    state_file = tmpdir.join(tempfile.mktemp())
    state_file.write(state, ensure=True)

    return state_file.dirname, state_file.basename


def test_check_unas_mem(mocker):
    unas_state = watchdog.UnasState('mount_uuid_test', '/mnt', 'mount_path_test', 'mount_cmd_test', 'mount_key_test', 'bind_tag_test', True)
    probe = _efc_probe(efc_process.EFC_RUNNING)
    # mem usage not exceed
    anno_rss = watchdog.CGROUP_BASE_MEMORY_LIMIT_SIZE - watchdog.PAGE_SIZE
    shm = watchdog.CGROUP_BASE_MEMORY_LIMIT_SIZE + watchdog.PAGE_SIZE * 1024
    total = anno_rss + shm
    mock_proc_statm = "27021 %d %d 11 0 80 0" % (total / watchdog.PAGE_SIZE, shm / watchdog.PAGE_SIZE)
    mp = MockOpen()
    mp["/proc/123/statm"].read_data = mock_proc_statm
    with patch(BUILTIN_OPEN_FUNC, mp) as mock_file:
        mock_kill = mocker.patch('watchdog.kill_process_uuid')
        watchdog.check_unas_process_mem(unas_state, probe)
        mock_kill.assert_not_called()

def test_check_unas_mem2(mocker):
    unas_state = watchdog.UnasState('mount_uuid_test', '/mnt', 'mount_path_test', 'mount_cmd_test', 'mount_key_test', 'bind_tag_test', False)
    probe = _efc_probe(efc_process.EFC_RUNNING)
    # mem usage exceed
    anno_rss = watchdog.CGROUP_BASE_MEMORY_LIMIT_SIZE + watchdog.PAGE_SIZE # exceed
    shm = watchdog.CGROUP_BASE_MEMORY_LIMIT_SIZE + watchdog.PAGE_SIZE * 1024
    total = anno_rss + shm
    mock_proc_statm = "27021 %d %d 11 0 80 0" % (total / watchdog.PAGE_SIZE, shm / watchdog.PAGE_SIZE)
    mp = MockOpen()
    mp["/proc/123/statm"].read_data = mock_proc_statm
    with patch(BUILTIN_OPEN_FUNC, mp) as mock_file:
        mock_kill = mocker.patch('watchdog.kill_process_uuid')
        watchdog.check_unas_process_mem(unas_state, probe)
        mock_kill.assert_called_once()

'''
def test_write_unas_state_file(mocker):
    state_file_dir = os.getcwd()
    mount_uuid = "mount_uuid_test"
    mount_point = "mount_point_test"
    mount_path = "mount_path_test"
    mount_cmd = "mount_cmd_test"
    sessmgr_required = True
    unas_state = watchdog.UnasState(mount_uuid, mount_point, mount_path, mount_cmd, sessmgr_required)
    new_file = watchdog.write_unas_state_file(mount_uuid, unas_state, state_file_dir)
    assert new_file == "%s%s"% (FILE_PREFIX, mount_uuid)

    with open(new_file, "r") as f:
        state = json.load(f)
        assert len(state) == 5
        assert state["mountuuid"] == mount_uuid
        assert state["mountpoint"] == mount_point
        assert state["mountpath"] == mount_path
        assert state["mountcmd"] == mount_cmd
        assert state["sessmgr_required"] == sessmgr_required
        saved_sign = state.pop(watchdog.STATE_SIGN, '')
        assert saved_sign == watchdog.sign_state(state)
'''

def test_restart_unas_process(mocker, tmpdir):
    dead = _efc_probe(efc_process.EFC_DEAD, pid=0)
    running = _efc_probe(efc_process.EFC_RUNNING)
    mocker.patch(
        'watchdog.efc_process.probe_efc', side_effect=[dead, running])
    mocker.patch('watchdog.add_cgroup_limit')
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[
        watchdog.Mount('mount_uuid_test:server:/', 'mount_point_test',
                       'fuse.aliyun-alinas-efc', '', '0', '0')])
    runner = mocker.Mock(return_value=(0, '', ''))

    mount_uuid = 'mount_uuid_test'
    mount_point = 'mount_point_test'
    mount_path = 'server:/'
    mount_cmd = 'mount_cmd_test'
    mount_key = 'mount_key_test'
    bind_tag = 'bind_tag_test'
    state_file_dir, state_file = create_state_file(tmpdir, {})
    assert os.path.exists(state_file_dir + '/' + state_file) == True
    unas_state = watchdog.UnasState(mount_uuid, mount_point, mount_path, mount_cmd, mount_key, bind_tag, True)
    assert watchdog.restart_unas_process(
        unas_state, str(tmpdir), expected_probe=dead, runner=runner) is True
    runner.assert_called_once_with(
        mount_cmd, watchdog.UNAS_RESTART_TIMEOUT)
    assert os.path.exists(state_file_dir + '/' + state_file) == True


def test_schedule_clean_up_mount_files(mocker, tmpdir):
    watchdog.UNAS_LOG_FILE_GC_IN_SEC = 2

    mount_log_dir1 = '%smount_dir1_uuid' % FILE_PREFIX
    mount_log_dir2 = '%smount_dir2_uuid' % FILE_PREFIX

    dir1 = tmpdir.mkdir(mount_log_dir1)
    dir11 = dir1.mkdir('eaclog')
    dir111 = dir11.mkdir('123')
    dir111.join('eac.LOG').write('')

    time.sleep(3)
    dir2 = tmpdir.mkdir(mount_log_dir2)
    dir22 = dir2.mkdir('eaclog')
    dir222 = dir22.mkdir('123')
    dir222.join('eac.LOG').write('')

    state_file_dir = 'mock_test_state_dir'
    tmpdir.mkdir(state_file_dir)

    # state file is deleted, remove useless logs
    watchdog.schedule_clean_up_mount_files(str(tmpdir), str(tmpdir.join(state_file_dir)))
    assert len(tmpdir.listdir()) == 2


def test_is_unas_mounted(mocker):
    state = {'mountuuid': 'uuid', 'mountpoint': '/mnt', 'mountpath':'', 'mountcmd':'' , 'mountkey':''}
    local_mount_dns = 'uuid:dns:/'
    unas_proc_mounts = [watchdog.Mount('uuid1:dns1:/', '/mnt', 'type', 'options', '', '')]
    assert watchdog.is_unas_mounted(state, local_mount_dns, unas_proc_mounts) == False

    unas_proc_mounts = [watchdog.Mount('uuid:dns:/', '/mnt', 'type', 'options', '', '')]
    assert watchdog.is_unas_mounted(state, local_mount_dns, unas_proc_mounts) == True


def mock_load_state_file(state_file_dir, state_file):
    return {'mountpoint':'/mnt'}


def test_clean_shm_files(mocker, tmpdir):
    wd = _setup_watchdog_mock(mocker)
    mocker.patch('watchdog.lock_state_file')

    '''
    tmpdir.join('volume_123').write('')
    tmpdir.join('journal_123').write('')
    tmpdir.join('page_123').write('')
    tmpdir.join('file_123').write('')
    '''
    '''
    os.mknod('volume_123')
    os.mknod('journal_123')
    os.mknod('page_123')
    os.mknod('file_123')
    '''

    '''
    shm_dir = os.getcwd()
    # somebody use it, donot drop it
    mocker.patch('watchdog.get_files_with_prefix', return_value={'st':'st'})
    wd.load_state_file = mock_load_state_file
    watchdog.clean_shm_files('/mnt', wd, shm_dir, tmpdir)
    assert os.path.exists('volume_123') == True

    # nobody use this shm, clear it
    mocker.patch('watchdog.get_files_with_prefix', return_value={})
    watchdog.clean_shm_files('/mnt', wd, shm_dir, tmpdir)
    assert os.path.exists('volume_123') == False
    '''

def test_drop_unas_mount(mocker, tmpdir):
    wd = _setup_watchdog_mock(mocker)
    unas_state = {'mountuuid':'mount_uuid_test', 'mountpoint':'/mnt', 'mountpath':'dns'}
    unas_mount_info = "echo nothing"
    fd = os.popen(unas_mount_info)

    pmock = _mock_popen(mocker, 0)
    mock0 = mocker.patch('watchdog.get_current_unas_mounts', return_value={})
    mock1 = mocker.patch('os.popen', return_value=fd)
    mock2 = mocker.patch('watchdog.is_unas_mounted', return_value=True)
    mock3 = mocker.patch('watchdog.clean_shm_files')
    mock4 = mocker.patch('watchdog.clean_up_unas_state')

    watchdog.drop_unas_mount(unas_state, wd, tmpdir, 'eac-mountuuid')
    pmock.assert_not_called()
    mock3.assert_not_called()


def test_drop_unas_mount1(mocker, tmpdir):
    wd = _setup_watchdog_mock(mocker)
    mount_uuid = 'mount_uuid_test'
    unas_state = {
        'mountuuid': mount_uuid,
        'mountpoint': '/mnt',
        'mountpath': 'dns',
        'mountcmd': '',
    }
    unas_mount_info = 'mount_uuid=%s' % mount_uuid
    fd = os.popen(unas_mount_info)

    tmpdir.join('test').write(unas_mount_info)
    fd = open(str(tmpdir) + '/test')
    pmock = _mock_popen(mocker, 0)
    mock0 = mocker.patch('watchdog.get_current_unas_mounts', return_value={})
    mock1 = mocker.patch('os.popen', return_value=fd)
    mock2 = mocker.patch('watchdog.is_unas_mounted', return_value=False)
    mock3 = mocker.patch('watchdog.is_unas_bindroot_mounted', return_value=False)
    mock4 = mocker.patch('watchdog.clean_shm_files')
    mock5 = mocker.patch('watchdog.clean_up_unas_state')
    mock6 = mocker.patch('watchdog.clean_up_cgroup_workspace')
    mock7 = mocker.patch('watchdog.kill_process_uuid')

    watchdog.drop_unas_mount(unas_state, wd, tmpdir, 'eac-mountuuid')

    assert mock3.call_count == 2
    mock7.assert_called_once()


def test_drop_unas_mount_cancels_kill_when_mount_reappears(mocker, tmpdir):
    wd = _setup_watchdog_mock(mocker)
    state = {
        'mountuuid': 'mount_uuid_test',
        'mountpoint': '/mnt',
        'mountpath': 'dns',
        'mountcmd': '',
        'fail_check_time': 1,
    }
    mount = watchdog.Mount(
        'mount_uuid_test:dns', '/mnt', 'eac', '', '0', '0')
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[mount])
    rewrite = mocker.patch('watchdog.rewrite_state_file')
    kill = mocker.patch('watchdog.kill_process_uuid')

    assert watchdog.drop_unas_mount(
        state, wd, str(tmpdir), 'eac-mountuuid') is False

    kill.assert_not_called()
    rewrite.assert_called_once()
    assert 'fail_check_time' not in state


def test_drop_unas_mount_rechecks_immediately_before_kill(mocker, tmpdir):
    wd = _setup_watchdog_mock(mocker)
    state = {
        'mountuuid': 'mount_uuid_test',
        'mountpoint': '/mnt',
        'mountpath': 'dns',
        'mountcmd': '',
        'fail_check_time': 1,
    }
    mount = watchdog.Mount(
        'mount_uuid_test:dns', '/mnt', 'eac', '', '0', '0')
    mocker.patch(
        'watchdog.get_current_unas_mounts', side_effect=[[], [mount]])
    kill = mocker.patch('watchdog.kill_process_uuid')
    mocker.patch('watchdog.rewrite_state_file')

    assert watchdog.drop_unas_mount(
        state, wd, str(tmpdir), 'eac-mountuuid') is False

    kill.assert_not_called()


def test_clean_bindroot_rechecks_mounts_after_umount(mocker):
    order = []

    def sync_umount(*args):
        order.append('umount')
        return True

    def current_mounts(*args):
        order.append('mounts')
        return []

    mocker.patch('watchdog.sync_umount_unas', side_effect=sync_umount)
    mocker.patch('watchdog.get_current_unas_mounts', side_effect=current_mounts)
    mocker.patch('watchdog.os.path.exists', return_value=False)

    assert watchdog.clean_bindroot(
        'bindroot-uuid', watchdog.BIND_ROOT_DIR + '/bindroot-uuid', {}) is True
    assert order == ['umount', 'mounts']


def test_check_unas_mounts_no_statefiles(mocker, tmpdir):
    restart_unas, clean_up = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state_files = {}
    mocker.patch('watchdog.get_current_unas_mounts', return_value={})
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    watchdog.check_unas_mounts(wd, str(tmpdir))
    restart_unas.assert_not_called()
    clean_up.assert_called_once()


def test_check_unas_mounts_valid(mocker, tmpdir):
    restart_unas, clean_up = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state = {}
    state_file_dir, state_file = create_state_file(tmpdir, state)
    state_files = {'/mnt':state_file}
    mocker.patch('watchdog.get_current_unas_mounts',
                return_value={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'eac', '', '0', '0')})
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    restart_unas.assert_not_called()
    clean_up.assert_called_once()


def test_check_unas_mounts_invalid(mocker, tmpdir):
    restart_unas, clean_up = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state = {}
    state_file_dir, state_file = create_state_file(tmpdir, state)
    state_files = {'/mnt':state_file}
    mocker.patch('watchdog.get_current_unas_mounts',
                return_value={'/mnt': watchdog.Mount('127.0.0.1', '/mnt', 'eac', '', '0', '0')})
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    # check unas failed
    mocker.patch('watchdog.is_unas_mounted', return_value=True)
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_DEAD, pid=0),
    )
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    restart_unas.assert_called_once()
    clean_up.assert_called_once()


@pytest.mark.parametrize(
    'probe_state,detach_result,should_restart',
    [
        (efc_process.EFC_ZOMBIE_LOCKED, efc_process.DETACH_WAIT, False),
        (efc_process.EFC_ZOMBIE_LOCKED, efc_process.DETACH_DETACHED, True),
        (efc_process.EFC_LOCK_CONFLICT, None, False),
        (efc_process.EFC_UNKNOWN, None, False),
    ],
)
def test_check_unas_mounts_state_action(
        mocker, tmpdir, probe_state, detach_result, should_restart):
    restart_unas, _ = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state_file_dir, state_file = create_state_file(tmpdir, {})
    mocker.patch(
        'watchdog.get_files_with_prefix',
        return_value={'/mnt': state_file},
    )
    mocker.patch(
        'watchdog.get_current_unas_mounts',
        return_value=[watchdog.Mount(
            'mount_uuid_test:mount_path_test', '/mnt', 'eac', '', '0', '0')],
    )
    mocker.patch('watchdog.is_unas_mounted', return_value=True)
    probe = _efc_probe(
        probe_state,
        proc_state='Z' if probe_state == efc_process.EFC_ZOMBIE_LOCKED else 'S',
    )
    mocker.patch('watchdog.efc_process.probe_efc', return_value=probe)
    detach = mocker.patch(
        'watchdog.try_remove_efc_lock_when_zombie',
        return_value=detach_result,
    )

    watchdog.check_unas_mounts(wd, str(state_file_dir))

    if probe_state == efc_process.EFC_ZOMBIE_LOCKED:
        detach.assert_called_once_with('mount_uuid_test', probe)
    else:
        detach.assert_not_called()
    assert restart_unas.called is should_restart


def mock_load_state_file_no_fail(state_file_dir, state_file):
    return {'mountpath':'path', 'mountuuid':'uuid', 'mountpoint':'mountpoint', 'mountcmd':'mountcmd', 'mountkey':'mountkey'}

def mock_load_state_file_fail(state_file_dir, state_file):
    return {'mountpath':'path', 'mountuuid':'uuid', 'mountpoint':'mountpoint', 'mountcmd':'mountcmd', 'mountkey':'mountkey', 'fail_check_time':(time.time()-1000)}

def test_check_unas_mounts_not_mounted(mocker, tmpdir):
    mocker.patch('watchdog.lock_state_file')
    restart_unas, clean_up = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state = {}
    state_file_dir, state_file = create_state_file(tmpdir, state)

    mocker.patch('watchdog.get_files_with_prefix', return_value={'st':'st'})
    wd.load_state_file = mock_load_state_file_no_fail
    mocker.patch('watchdog.is_unas_mounted', return_value=False)
    rmock = mocker.patch('watchdog.rewrite_state_file')
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    rmock.assert_called_once()

    wd.load_state_file = mock_load_state_file_fail
    dmock = mocker.patch('watchdog.drop_unas_mount')
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    dmock.assert_called_once()


def test_check_unas_mounts_reads_mounts_inside_uuid_lock(mocker, tmpdir):
    restart_unas, _ = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state_file_dir, state_file = create_state_file(tmpdir, {})
    mocker.patch(
        'watchdog.get_files_with_prefix', return_value={'st': state_file})
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_DEAD, pid=0))
    mocker.patch('watchdog.rewrite_state_file')

    lock_held = {'value': False}
    mount_reads = []

    @contextmanager
    def tracked_lock(*args, **kwargs):
        lock_held['value'] = True
        try:
            yield
        finally:
            lock_held['value'] = False

    def current_mounts(*args, **kwargs):
        mount_reads.append(lock_held['value'])
        if not lock_held['value']:
            return [watchdog.Mount(
                'mount_uuid_test:mount_path_test', '/mnt',
                'eac', '', '0', '0')]
        return []

    mocker.patch('watchdog.lock_state_file', side_effect=tracked_lock)
    mocker.patch('watchdog.get_current_unas_mounts', side_effect=current_mounts)

    watchdog.check_unas_mounts(wd, str(state_file_dir))

    assert mount_reads == [False, True]
    restart_unas.assert_not_called()


def test_check_unas_mounts_uses_state_reloaded_under_lock(mocker):
    initial = {
        'mountuuid': 'uuid',
        'mountpoint': '/old',
        'mountpath': 'server:/old',
        'mountcmd': 'old-command',
        'mountkey': 'uuid.lock',
    }
    current = dict(initial)
    current.update({
        'mountpoint': '/new',
        'mountpath': 'server:/new',
        'mountcmd': 'new-command',
    })
    wd = MagicMock()
    wd.load_state_file.side_effect = [initial, current]
    mocker.patch('watchdog.lock_state_file')
    mocker.patch(
        'watchdog.get_files_with_prefix', return_value={'st': 'efc-uuid'})
    mocker.patch(
        'watchdog.get_current_unas_mounts',
        return_value=[watchdog.Mount(
            'uuid:server:/new', '/new', 'eac', '', '0', '0')])
    dead = _efc_probe(efc_process.EFC_DEAD, pid=0)
    mocker.patch('watchdog.efc_process.probe_efc', return_value=dead)
    mocker.patch('watchdog.os.path.exists', return_value=False)
    restart = mocker.patch('watchdog.restart_unas_process')
    mocker.patch('watchdog.schedule_clean_up_mount_files')

    watchdog.check_unas_mounts(wd, '/state')

    restarted_state = restart.call_args[0][0]
    assert restarted_state.mountpoint == '/new'
    assert restarted_state.mountpath == 'server:/new'
    assert restarted_state.mountcmd == 'new-command'


def test_check_unas_mounts_skips_changed_state_identity(mocker):
    initial = {
        'mountuuid': 'uuid',
        'mountpoint': '/mnt',
        'mountpath': 'server:/',
        'mountcmd': 'command',
        'mountkey': 'uuid.lock',
    }
    changed = dict(initial)
    changed['mountuuid'] = 'other-uuid'
    wd = MagicMock()
    wd.load_state_file.side_effect = [initial, changed]
    mocker.patch('watchdog.lock_state_file')
    mocker.patch(
        'watchdog.get_files_with_prefix', return_value={'st': 'efc-uuid'})
    mounts = mocker.patch('watchdog.get_current_unas_mounts')
    probe = mocker.patch('watchdog.efc_process.probe_efc')
    restart = mocker.patch('watchdog.restart_unas_process')
    mocker.patch('watchdog.schedule_clean_up_mount_files')

    watchdog.check_unas_mounts(wd, '/state')

    mounts.assert_called_once_with(watchdog.MOUNT_TYPE_ALL)
    probe.assert_not_called()
    restart.assert_not_called()

def test_check_unas_bindmount(mocker, tmpdir):
    restart_unas, clean_up = setup_mocks(mocker)
    wd = _setup_watchdog_mock(mocker)
    state = {'mountuuid':'bindroot-xxoo', 'mountpath':'127.0.0.1:/', 'mountpoint':'/var/run/alinas/bindroot'}
    state_file_dir, state_file = create_state_file(tmpdir, state)
    state_files = {'/var/run/alinas/bindroot':state_file}
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_DEAD, pid=0),
    )
    mocker.patch('watchdog.get_current_unas_mounts',
                return_value=[watchdog.Mount('bindroot-xxoo:127.0.0.1:/', '/var/run/alinas/bindroot', 'aliyun-alinas-eac', '', '0', '0')])
    local_mount_dns = state['mountuuid'] + ':' + state['mountpath']
    mounted = watchdog.is_unas_bindroot_mounted(state, watchdog.get_current_unas_mounts())
    assert mounted == True
    mounted = watchdog.is_unas_mounted(state, local_mount_dns, watchdog.get_current_unas_mounts())
    assert mounted == False
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    restart_unas.assert_called_once()

    restart_unas.reset_mock()
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_RUNNING),
    )
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    restart_unas.assert_not_called()

    restart_unas.reset_mock()
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_RUNNING),
    )
    mocker.patch('watchdog.get_current_unas_mounts',
        return_value=[watchdog.Mount('bindroot-xxoo:127.0.0.1:/', '/var/run/alinas/bindroot', 'aliyun-alinas-eac', '', '0', '0'), watchdog.Mount('bindroot-xxoo:127.0.0.1:/', '/mnt', 'aliyun-alinas-eac', '', '0', '0')])
    mounted = watchdog.is_unas_bindroot_mounted(state, watchdog.get_current_unas_mounts())
    assert mounted == True
    mounted = watchdog.is_unas_mounted(state, local_mount_dns, watchdog.get_current_unas_mounts())
    assert mounted == True
    watchdog.check_unas_mounts(wd, str(state_file_dir))
    restart_unas.assert_not_called()

    # test drop bindroot mount
    state = {'mountuuid':'bindroot-xxoo', 'mountpath':'127.0.0.1:/', 'mountpoint':'/var/run/alinas/bindroot', 'fail_check_time':100}
    state_file_dir, state_file = create_state_file(tmpdir, state)
    state_files = {'/var/run/alinas/bindroot':state_file}
    mocker.patch('watchdog.get_files_with_prefix', return_value=state_files)
    mocker.patch('watchdog.get_current_unas_mounts', \
        return_value=[watchdog.Mount('bindroot-xxoo:127.0.0.1:/', '/var/run/alinas/bindroot', 'aliyun-alinas-eac', '', '0', '0')])
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        return_value=_efc_probe(efc_process.EFC_RUNNING),
    )
    try_umount_unas = mocker.patch('watchdog.try_umount_unas', watchdog.try_umount_unas)
    clean_shm_files = mocker.patch('watchdog.clean_shm_files', watchdog.clean_shm_files)
    clean_up_unas_state = mocker.patch('watchdog.clean_up_unas_state', watchdog.clean_up_unas_state)
    with mocker.patch('socket.socket') as mock_socket:
        mock_socket.return_value.recv.decode.return_value = "0"
        watchdog.check_unas_mounts(wd, str(state_file_dir))


class TestCleanupBySize:

    def _setup_environment(self, tmpdir, file_specs, active_mounts=[]):
        """
        :param tmpdir: pytest的临时目录
        :param file_specs: 一个列表 格式: [('mount_name', 'sub_dir', 'file_name', size, age_in_seconds), ...]
        :param active_mounts: 一个列表 处于活动的挂载列表
        """
        log_dir = tmpdir.mkdir("logs")
        state_dir = tmpdir.mkdir("state")
        
        now = time.time()
        
        for mount_name, sub_dir, file_name, size, age in file_specs:
            full_sub_dir_path = os.path.join(str(log_dir), mount_name, sub_dir)
            
            os.makedirs(full_sub_dir_path, exist_ok=True)
            
            file_path = os.path.join(full_sub_dir_path, file_name)
            
            with open(file_path, "wb") as f:
                f.write(b'\0' * size)
            
            mtime = now - age
            os.utime(file_path, (mtime, mtime))

        for mount_name in active_mounts:
            mount_path = os.path.join(str(log_dir), mount_name)
            os.makedirs(mount_path, exist_ok=True)
            
            state_file_name = mount_name.replace('efc', 'eac')
            state_dir.join(state_file_name).write("active")
            
        return str(log_dir), str(state_dir)

    def test_cleanup_when_size_exceeds_limit(self, tmpdir, mocker):
        one_mb = 1024 * 1024
        

        mocker.patch('watchdog.TOTAL_UNMOUNTED_LOG_MAX_SIZE', 2 * one_mb)
        file_specs = [
            # 已卸载的日志
            ('efc-unmounted-1', 'efclog/12345641', 'oldest.log', one_mb, 3600), # 最旧 (1小时前)
            ('efc-unmounted-1', 'efclog/78978979', 'older.log',  one_mb, 1800), # 次旧 (30分钟前)
            ('efc-unmounted-2', 'vsclog/54564655', 'newest.log', one_mb, 60),   # 最新 (1分钟前)
            # 活动挂载点的日志 (不应该被删除)
            ('efc-active-1', 'efclog/sessionX', 'active.log', one_mb, 7200),  # 非常旧，但是是活动的
        ]
        
        log_dir, state_dir = self._setup_environment(tmpdir, file_specs, active_mounts=['efc-active-1'])
        
        # 执行清理
        _cleanup_unmounted_logs_by_size(log_file_dir=log_dir, state_file_dir=state_dir)
        

        # 1. 最旧的文件被删除了
        path_oldest = os.path.join(log_dir, 'efc-unmounted-1', 'efclog/12345641', 'oldest.log')
        assert not os.path.exists(path_oldest)
        
        # 2. 两个较新的未挂载文件不被删除
        path_older = os.path.join(log_dir, 'efc-unmounted-1', 'efclog/78978979', 'older.log')
        path_newest = os.path.join(log_dir, 'efc-unmounted-2', 'vsclog/54564655', 'newest.log')
        assert os.path.exists(path_older)
        assert os.path.exists(path_newest)
        
        # 3. 活动挂载点的文件不被删除
        path_active = os.path.join(log_dir, 'efc-active-1', 'efclog/sessionX', 'active.log')
        assert os.path.exists(path_active)

        # 4. 因文件删除而产生的空目录应该被清理
        assert not os.path.exists(os.path.join(log_dir, 'efc-unmounted-1', 'efclog/12345641'))
        # 父目录 'efclog' 因为还有 'session2'，所以不应该被删除
        assert os.path.exists(os.path.join(log_dir, 'efc-unmounted-1', 'efclog'))


    def test_cleanup_when_size_within_limit(self, tmpdir, mocker):

        one_mb = 1024 * 1024
        
        mocker.patch('watchdog.TOTAL_UNMOUNTED_LOG_MAX_SIZE', 5 * one_mb)

        file_specs = [
            ('efc-unmounted-1', 'efclog', 'old.log', one_mb, 3600),
            ('efc-unmounted-2', 'vsclog', 'new.log', one_mb, 60),
        ]
        
        log_dir, state_dir = self._setup_environment(tmpdir, file_specs)
        
        # 执行清理
        _cleanup_unmounted_logs_by_size(log_file_dir=log_dir, state_file_dir=state_dir)
        

        # 所有文件还在
        path_old = os.path.join(log_dir, 'efc-unmounted-1', 'efclog', 'old.log')
        path_new = os.path.join(log_dir, 'efc-unmounted-2', 'vsclog', 'new.log')
        assert os.path.exists(path_old)
        assert os.path.exists(path_new)
