#
# Copyright 2020-2022 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from fileinput import filename
import pdb
import sys
import os
import json
from mock import MagicMock, patch, mock_open
import mount_alinas
import pytest

FILE_PREFIX = 'eac-'
ALIFUSE_MODULE_NAME = 'alifuse'
ALIFUSE_CTL_MOUNT_PATH = '/sys/fs/alifuse/connections'
SESSMGR_BIN_NAME = 'aliyun-alinas-eac-sessmgrd'
WATCHDOG_BIN_NAME = 'aliyun-alinas-mount-watchdog'
BUILTIN_OPEN_FUNC = "builtins.open"
if sys.version_info < (3, 0):
    BUILTIN_OPEN_FUNC = "__builtin__.open"

mount_alinas.UNAS_DEFAULT_ENABLE_BINDMOUNT = False

def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout'.encode(), 'stderr'.encode(), )
    popen_mock.returncode = returncode
    popen_mock.poll.return_value = None
    popen_mock.wait.return_value = returncode
    return mocker.patch('subprocess.Popen', return_value=popen_mock)

def _mock_fatal_error(mocker):
    return mocker.patch('mount_alinas.fatal_error')


def test_get_mount_flags(mocker, tmpdir):
    mp_url, fs_id, path, mountpoint, options = mount_alinas.parse_arguments(['mount.alinas', '-u', '/mnt1', 'eac'])
    assert mountpoint == '/mnt1'
    assert mount_alinas.UNAS_APP_NAME in options
    assert options['umount_flag'] == mount_alinas.NORMAL_UMOUNT
    mp_url, fs_id, path, mountpoint, options = mount_alinas.parse_arguments(['mount.alinas', '-u', '/mnt1', 'eac', '-f'])
    assert mountpoint == '/mnt1'
    assert mount_alinas.UNAS_APP_NAME in options
    assert options['umount_flag'] == mount_alinas.FORCE_UMOUNT

def test_get_current_unas_mounts(mocker):
    mock_local_mounts = "dns-uuid /mnt aliyun-alinas-eac dns freq passno\neac /mnt1 alinas-mounts dns freq passno"

    with patch(BUILTIN_OPEN_FUNC, mock_open(read_data=mock_local_mounts)) as mock_file:
        mounts = mount_alinas.get_current_unas_mounts()
        assert len(mounts) == 1
        assert mounts[0].server == 'dns-uuid'


def test_mount_alifuse(mocker, tmpdir):
    pmock = _mock_popen(mocker)

    # alifuse already mounted
    alifuse_mounted = "echo /fusemountpath %s" % ALIFUSE_MODULE_NAME
    tmpdir.join('test').write(alifuse_mounted)

    fd = open(str(tmpdir) + '/test')
    mock = mocker.patch("os.popen", return_value=fd)
    mount_alinas.mount_alifuse()
    #assert len(pmock.mock_calls) == 0
    pmock.assert_not_called

    # alifuse not mounted
    alifuse_not_mounted = "echo /ext4mountpath ext4"
    fd = os.popen(alifuse_not_mounted)
    mock = mocker.patch("os.popen", return_value=fd)
    mount_alinas.mount_alifuse()
    args, _ = pmock.call_args
    assert len(args) == 1
    assert args[0].startswith("/usr/sbin/insmod")
    fd.close()


def test_mount_alifuse_ctl(mocker):
    mock = _mock_popen(mocker)

    # alifuse ctl already mounted
    mock_ctl_mount = "seever %s type options freq passno" % ALIFUSE_CTL_MOUNT_PATH
    with patch(BUILTIN_OPEN_FUNC, mock_open(read_data=mock_ctl_mount)) as mock_file:
        mounts = mount_alinas.mount_alifuse_ctl()
        #assert len(mock.mock_calls) == 0
        mock.assert_not_called()

    # alifuse ctl not mounted
    mock_no_ctl_mount = "server /mnt type options freq passno"
    with patch(BUILTIN_OPEN_FUNC, mock_open(read_data=mock_no_ctl_mount)) as mock_file:
        mounts = mount_alinas.mount_alifuse_ctl()
        args, _ = mock.call_args
        assert len(args) == 1
        assert  args[0].startswith("mount -t alifusectl")


def test_create_unas_mount_dir(mocker, tmpdir):
    mount_uuid = 'mount_uuid_test'
    log_path_prefix = 'eac-' + mount_uuid
    global_dir_path = str(tmpdir)

    tmpdir.join('flag_conf_template').write('')
    log_conf_template = 'xxxxx:xxxx\nLogFilePath:path'
    tmpdir.join('log_conf_template').write(log_conf_template)
    mount_alinas.UNAS_FLAG_CONF_TEMPLATE_PATH = str(tmpdir) + '/flag_conf_template'
    mount_alinas.UNAS_LOG_CONF_TEMPLATE_PATH = str(tmpdir) + '/log_conf_template'


    dir_path, log_conf_path = mount_alinas.get_unas_mount_file_path(mount_uuid)
    mount_alinas.create_unas_mount_dir(mount_uuid, global_dir_path)
    # two template files & sessmgr log dir & unas log dir
    assert len(tmpdir.listdir()) == 4

    # find unas log dir
    dir_name = 'eac-%s' % mount_uuid
    for i in range(len(tmpdir.listdir())):
        if str(tmpdir.listdir()[i]).find(dir_name) != -1:
            log_dir = tmpdir.listdir()[i]
            break

    # check log conf content
    assert len(log_dir.listdir()) == 2
    log_conf_context = log_dir.join('log_conf.eac.json').read()
    assert log_conf_context.find(log_path_prefix) != -1


def test_check_sessmgr_alive(mocker):
    # sessmgr already alive
    alive_process = "echo %s" % SESSMGR_BIN_NAME
    fd = os.popen(alive_process)
    mock = mocker.patch("os.popen", return_value=fd)
    assert mount_alinas.check_sessmgr_alive() == True

    # sessmgr not alive
    alive_process = "echo eac"
    fd = os.popen(alive_process)
    mock = mocker.patch("os.popen", return_value=fd)
    assert mount_alinas.check_sessmgr_alive() == False

def test_check_watchdog_alive(mocker):
    # watchdog already alive
    alive_process = "echo %s" % WATCHDOG_BIN_NAME
    fd = os.popen(alive_process)
    mock = mocker.patch("os.popen", return_value=fd)
    assert mount_alinas.check_watchdog_alive() == True

    # watchdog not alive
    alive_process = "echo eac"
    fd = os.popen(alive_process)
    mock = mocker.patch("os.popen", return_value=fd)
    assert mount_alinas.check_watchdog_alive() == False

def test_start_sessmgr(mocker, tmpdir):
    pmock = _mock_popen(mocker)

    sessmgr_log_path = 'mock_sessmgr_log_path_test'
    alive_process = "echo eac"
    tmpdir.join('test').write(alive_process)
    fd = open(str(tmpdir) + '/test')

    unas_dir_path = "unas_dir_path_test"
    mock = mocker.patch("os.popen", return_value=fd)
    mount_alinas.start_sessmgr()
    args, _ = pmock.call_args
    assert len(args) == 1
    assert args[0].find(SESSMGR_BIN_NAME) != -1

    # popen failed
    mocker.patch('mount_alinas.check_sessmgr_alive', return_value=False)
    subdir = tmpdir.mkdir(unas_dir_path)
    pmock = _mock_popen(mocker, 1) # return code = 1
    fmock = _mock_fatal_error(mocker)
    #mount_alinas.start_sessmgr(sessmgr_log_path, str(tmpdir) + '/' + unas_dir_path)
    mount_alinas.start_sessmgr(str(tmpdir) + '/' + unas_dir_path)
    print(tmpdir.listdir()[0], tmpdir.listdir()[1])
    assert len(tmpdir.listdir()) == 2
    assert len(subdir.listdir()) == 1


def test_write_unas_state_file(mocker):
    state_file_dir = os.getcwd()
    mount_uuid = "mount_uuid_test"
    mount_point = "mount_point_test"
    mount_path = "mount_path_test"
    mount_cmd = "mount_cmd_test"
    mount_key = "mount_key_test"
    bind_tag = "bind_tag_test"
    sessmgr_required = True
    unas_state = mount_alinas.UnasState(mount_uuid, mount_point, mount_path, mount_cmd, mount_key, bind_tag, sessmgr_required)
    state_file = 'eac-' + mount_uuid
    new_file = mount_alinas.write_unas_state_file(unas_state._asdict(), state_file_dir, state_file)

    new_file = state_file
    with open(new_file, "r") as f:
        state = json.load(f)
        assert len(state) == 7
        assert state["mountuuid"] == mount_uuid
        assert state["mountpoint"] == mount_point
        assert state["mountpath"] == mount_path
        assert state["mountcmd"] == mount_cmd
        assert state["mountkey"] == mount_key
        assert state["bindtag"] == bind_tag
        assert state['sessmgr_required'] == sessmgr_required
        saved_sign = state.pop(mount_alinas.STATE_SIGN, '')
        assert saved_sign == mount_alinas.sign_state(state)


def test_gen_unas_mount_cmd(mocker):
    mount_uuid = 'mount_uuid_test'
    mount_point = 'mount_point_test'
    mount_path = 'mount_path_test'
    mount_options = {}
    log_path = 'log_path_test'
    mount_cmd = mount_alinas.gen_unas_mount_cmd(mount_uuid, mount_point, mount_path, mount_options, log_path)
    assert mount_cmd.find(mount_uuid) != -1
    assert mount_cmd.find(mount_point) != -1
    assert mount_cmd.find(mount_path) != -1
    assert mount_cmd.find(log_path) != -1


def test_wait_mount_completed(mocker):
    mount_uuid = "mount_uuid_test"
    mount_path = 'dns_test:/'
    gmock = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[])

    # mount info failed updated
    succ = mount_alinas.wait_mount_completed(mount_uuid, mount_path)
    assert succ == False

    # mount info updated
    local_proc_mounts = mount_alinas.Mount('mount_uuid_test:dns_test:/', '/mnt', 'type', '', '', '')
    gmock = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[local_proc_mounts])
    succ = mount_alinas.wait_mount_completed(mount_uuid, mount_path)
    assert succ == True

def test_check_unas_bindmount(mocker):
    gmock = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[])
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_test', 'fs_id', 'path', 'mountpoint', None, {})

    mount_point, uuid = mount_alinas.check_unas_bindmount(ctx)
    assert not mount_point
    assert uuid.startswith(mount_alinas.BIND_ROOT_PREFIX)

    mp = mount_alinas.BIND_ROOT_DIR + '/bindroot-xx'
    local_proc_mounts = mount_alinas.Mount('bindroot-xx:dns_test:/', mp, 'type', '', '', '')
    gmock = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[local_proc_mounts])

    gmock = mocker.patch('mount_alinas.check_unas_process', return_value=[True])
    gmock = mocker.patch('mount_alinas.check_unas_lock_available', return_value=[True])
    mount_point, uuid = mount_alinas.check_unas_bindmount(ctx)
    assert mount_point == mp
    assert uuid == "bindroot-xx"

def setup_mocks(mocker, tmpdir):
    mocker.patch('mount_alinas.start_watchdog')
    mount_cmd = 'mount_cmd_test'
    mocker.patch('mount_alinas.gen_unas_mount_cmd', return_value=mount_cmd)

    tmpdir.mkdir('logdir')
    mocker.patch('mount_alinas.prepare_mount_unas', return_value=[str(tmpdir) + '/logdir', 'b', 'c'])

    mount_uuid = 'mount_uuid_test'
    tmpdir.join('eac-' + mount_uuid).write('')
    mocker.patch('mount_alinas.write_unas_state_file', return_value=str(tmpdir) + '/eac-' + mount_uuid)

    mocker.patch('mount_alinas.lock_alinas')
    mount_alinas.STATE_FILE_DIR = str(tmpdir)

    mocker.patch('mount_alinas.wait_mount_completed', return_value=True)
    mocker.patch('mount_alinas.check_kernel_version_for_unas')

    return mocker, mount_cmd

def test_mount_unas(mocker, tmpdir):
    _, mount_cmd = setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker)
    mocker.patch('mount_alinas.check_unas_mount_exist', return_value='')
    mocker.patch('mount_alinas.add_cgroup_limit')

    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', 'path', 'mountpoint', None, {})

    mount_alinas.mount_unas(ctx)
    args, _ = pmock.call_args
    assert len(args) == 1
    assert args[0].startswith(mount_cmd)
    assert len(tmpdir.listdir()) == 3

    # process not started
    mocker.patch('mount_alinas.wait_mount_completed', return_value=False)
    _mock_fatal_error(mocker)
    mount_alinas.mount_unas(ctx)

    assert len(tmpdir.listdir()) == 4

def test_mount_umount_unas_with_monitor(mocker, tmpdir):
    _, mount_cmd = setup_mocks(mocker, tmpdir)
    state = {'monitor_metrics_paths' : {}}
    pmock = _mock_popen(mocker)
    mocker.patch('mount_alinas.check_unas_mount_exist', return_value='')
    mocker.patch('mount_alinas.add_cgroup_limit')
    mocker.patch('os.path.exists', return_value=False)
    mocker.patch('os.makedirs')
    mocker.patch('mount_alinas.run_mount_unas')
    mocker.patch('mount_alinas.load_unas_state_file', return_value=state)
    mocker.patch('mount_alinas.write_unas_state_file')
    mocker.patch('shutil.rmtree')
    mocker.patch('os.removedirs')
    mocker.patch('os.listdir')
    mocker.patch('mount_alinas.check_mountpoint_uuid', return_value='mount_uuid')
    mocker.patch('mount_alinas.lock_file', return_value=1)
    mocker.patch('mount_alinas.unlock_file')
    mocker.patch('mount_alinas.sync_umount_unas', return_value=True)

    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', 'path', '/var/run/eac/pods/pod_uid/volumes/kubernetes.io~csi/mountpoint1/abc', None, {'prometheus_mon' : None})
    mount_alinas.mount_unas(ctx)
    assert 'pod_uid/mountpoint1' in state['monitor_metrics_paths'] and state['monitor_metrics_paths']['pod_uid/mountpoint1'] == 1

    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '', '/var/run/eac/pods/pod_uid/volumes/kubernetes.io~csi/mountpoint1/abc', None, {'umount_flag':0})
    mount_alinas.umount_unas(ctx)
    assert 'pod_uid/mountpoint1' not in state['monitor_metrics_paths']

def test_mount_unas_fail(mocker, tmpdir):
    setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker, 1)
    _mock_fatal_error(mocker)
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', 'path', 'mountpoint', None, {})
    mount_alinas.mount_unas(ctx)
    assert len(tmpdir.listdir()) == 3

def test_check_unas_upgrade(mocker, tmpdir):
    setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker)
    tmpdir.mkdir('mnt')
    mocker.patch('mount_alinas.check_unas_mount_exist', mount_alinas.check_unas_mount_exist)
    local_proc_mounts = mount_alinas.Mount('bindroot-xx:dns_test:/', '/mnt22', 'type', '', '', '')
    gmock = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[local_proc_mounts])
    uuid = mount_alinas.check_unas_mount_exist('dns_test:/', '/mnt22')
    assert uuid == 'bindroot-xx'

def test_mount_unas_upgrade(mocker, tmpdir):
    setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker)
    tmpdir.mkdir('mnt')
    mocker.patch('mount_alinas.check_unas_mount_exist', return_value='')
    mocker.patch('mount_alinas.gen_unas_uuid', return_value='eac')
    ctx1 = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', 'path', str(tmpdir) + '/mnt', None, {})
    mount_alinas.mount_unas(ctx1)
    mount_alinas.mount_unas(ctx1)
    assert len(tmpdir.listdir()) == 4

    mocker.patch('mount_alinas.check_unas_mount_exist', return_value='eac')
    mocker.patch('mount_alinas.write_unas_state_file')
    ctx2 = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', 'path', str(tmpdir) + '/mnt', None, {'upgrade':None})
    mount_alinas.mount_unas(ctx2)
    assert len(tmpdir.listdir()) == 4


class MockRunMountUnas(object):
    def __init__(self, mocker):
        self.proc_mounts = []
        self.mocker = mocker

    def run_mount_unas(self, ctx, mount_uuid, mount_point, mount_path, is_upgrade):
        mount = mount_alinas.Mount(mount_uuid + ':' + mount_path, mount_point, 'aliyun-alinas-eac', '', '', '')
        self.proc_mounts.append(mount)

    def try_umount_unas(self, mount_uuid, mount_point, umount_flag, timeout=60):
        self.proc_mounts = [m for m in self.proc_mounts if m.mountpoint != mount_point]
    
    def do_bind_mount(self, ctx, bind_mountpoint, mount_point):
        mount_path = ctx.dns + ":" + ctx.path
        mount_uuid = mount_alinas.BIND_ROOT_PREFIX + 'xxoo'
        mount = mount_alinas.Mount(mount_uuid + ':' + mount_path, mount_point, 'aliyun-alinas-eac', '', '', '')
        self.proc_mounts.append(mount)

    def do_bind_umount(self, bind_mountpoint, mount_point, umount_flag):
        return self.try_umount_unas('uuid', mount_point, umount_flag)

    def load_unas_state_file(self, state_file_dir, state_file):
        state = {}
        # state_file like eac-uuid
        mount_uuid = state_file[state_file.find('-') + 1:]
        for m in self.proc_mounts:
            if mount_uuid in m.server:
                state["mountuuid"] = mount_uuid
                state["mountpoint"] = m.mountpoint
                state["mountpath"] = m.server
                state["mountcmd"] = 'mountcmd'
                state["mountkey"] = 'mountkey'
                return state
        return None

    def read_proc_mounts(self):
        return self.proc_mounts

def test_get_bindroot_mountpoint(mocker):
    mount = mount_alinas.Mount('uuid1:server1:path1', 'mount_point', 'aliyun-alinas-eac', '', '', '')
    mocker.patch('mount_alinas.compare_unas_mountpoint', return_value=True)
    mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[mount])
    assert mount_alinas.get_bindroot_mountpoint('uuid1') == mount_alinas.BIND_ROOT_DIR + '/' + 'uuid1'
    assert not mount_alinas.get_bindroot_mountpoint('uuid2')

def test_mount_umount_unas_bind(mocker, tmpdir):
    setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker)
    tmpdir.mkdir('mnt')
    mock_mount_unas = MockRunMountUnas(mocker)

    mocker.patch('mount_alinas.run_mount_unas', mock_mount_unas.run_mount_unas)
    mocker.patch('mount_alinas.try_umount_unas', mock_mount_unas.try_umount_unas)
    mocker.patch('mount_alinas.do_bind_mount', mock_mount_unas.do_bind_mount)
    mocker.patch('mount_alinas.do_bind_umount', mock_mount_unas.do_bind_umount)
    mocker.patch('mount_alinas.get_current_unas_mounts', mock_mount_unas.read_proc_mounts)
    mocker.patch('mount_alinas.load_unas_state_file', mock_mount_unas.load_unas_state_file)
    mocker.patch('mount_alinas.check_unas_process', return_value=[True])
    mocker.patch('mount_alinas.check_unas_lock_available', return_value=[True])

    mount_uuid = mount_alinas.BIND_ROOT_PREFIX + 'xxoo'
    mount_point = mount_alinas.BIND_ROOT_DIR + '/' + mount_uuid
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '/path', '/mnt1', None, {'trybind':'yes'})
    mocker.patch('mount_alinas.gen_unas_uuid', return_value=mount_uuid)
    mount_alinas.mount_unas(ctx)
    succ = mount_alinas.wait_mount_completed(mount_uuid, 'dns_name:/')
    assert succ == True
    succ = mount_alinas.wait_mount_completed(mount_uuid, 'dns_name:/path')
    assert succ == True
    assert len(mock_mount_unas.read_proc_mounts()) == 2

    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '/path/xx', '/mnt2', None, {'trybind':'yes'})
    mocker.patch('mount_alinas.gen_unas_uuid', return_value=mount_uuid)
    mount_alinas.mount_unas(ctx)
    succ = mount_alinas.wait_mount_completed(mount_uuid, 'dns_name:/path/xx')
    assert succ == True
    assert len(mock_mount_unas.read_proc_mounts()) == 3

    # umount
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '', '/mnt2', None, {'umount_flag':0})
    mount_alinas.umount_unas(ctx)
    assert len(mock_mount_unas.read_proc_mounts()) == 2
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '', '/mnt1', None, {'umount_flag':0})
    mount_alinas.umount_unas(ctx)
    # mnt1 and bindroot will be umounted
    assert len(mock_mount_unas.read_proc_mounts()) == 0

def test_check_kernel_version(mocker, tmpdir):
    original_kernel_check = mount_alinas.check_kernel_version_for_unas
    setup_mocks(mocker, tmpdir)
    pmock = _mock_popen(mocker)
    # unpatch check_kernel_version_for_unas
    mocker.patch('mount_alinas.check_kernel_version_for_unas', original_kernel_check)

    mocker.patch('os.path.exists', return_value=False)
    mocker.patch('os.makedirs')
    mocker.patch('shutil.rmtree')
    mocker.patch('os.removedirs')
    mocker.patch('os.listdir')
    mocker.patch('mount_alinas.lock_file', return_value=1)
    mocker.patch('mount_alinas.unlock_file')
    mocker.patch('mount_alinas.update_lock_available_state')
    mocker.patch('mount_alinas.write_umount_helper_info')
    mocker.patch('mount_alinas.check_start_sessmgr', return_value=True)

    mount_nfs_mock = mocker.patch('mount_alinas.mount_nfs_directly')
    mount_unas_mock = mocker.patch('mount_alinas.run_mount_unas')
    start_sessmgr_mock = mocker.patch('mount_alinas.start_sessmgr')

    # 1. test no fallback
    # system unsupported
    options = dict()
    ctx = mount_alinas.MountContext(None, 'init_system', 'dns_name', 'fs_id', '/path/xx', '/mnt', None, options)
    mocker.patch('mount_alinas.get_system_release_version', return_value = 'UNKNOWN_SYSTEM')
    with pytest.raises(SystemExit) as _:
        mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_not_called()
    mount_unas_mock.assert_not_called()

    # kernel version unsupported
    mocker.patch('mount_alinas.get_system_release_version', return_value = 'Alibaba Cloud Linux xxx')
    mocker.patch('platform.release', return_value = '5.10.133-13.al8.x86_64')
    with pytest.raises(SystemExit) as _:
        mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_not_called()
    mount_unas_mock.assert_not_called()

    # supported
    mocker.patch('platform.release', return_value = '5.10.134-13.al8.x86_64')
    mocker.patch('mount_alinas.fuse_kernel_has_recovery', return_value=False)
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_not_called()
    mount_unas_mock.assert_called_once()
    start_sessmgr_mock.assert_called_once()

    # 2. test fallback
    ctx.options.clear()
    ctx.options['auto_fallback_nfs'] = True
    mount_unas_mock.reset_mock()
    # fallback beacuse system unsupported
    mocker.patch('mount_alinas.get_system_release_version', return_value = 'UNKNOWN_SYSTEM')
    mocker.patch('platform.release', return_value = '4.19.91-22.al8.x86_64')
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_called_once()
    mount_unas_mock.assert_not_called()

    # fallback beacuse version unsupported
    mount_nfs_mock.reset_mock()
    mocker.patch('mount_alinas.get_system_release_version', return_value = 'Alibaba Cloud Linux xxx')
    mocker.patch('platform.release', return_value = '4.19.81-99.al8.x86_64')
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_called_once()
    mount_unas_mock.assert_not_called()

    # fallback beacuse parse kernel fail
    mount_nfs_mock.reset_mock()
    mocker.patch('platform.release', return_value = 'bad-release-version')
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_called_once()
    mount_unas_mock.assert_not_called()

    # fallback because of no recovery
    mount_nfs_mock.reset_mock()
    mocker.patch('platform.release', return_value = '4.19.91-22.al8.x86_64')
    mocker.patch('mount_alinas.fuse_kernel_has_recovery', return_value=False)
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_called_once()
    mount_unas_mock.assert_not_called()

    # kernel version supported, no need to fallback
    mount_nfs_mock.reset_mock()
    start_sessmgr_mock.reset_mock()
    mocker.patch('mount_alinas.fuse_kernel_has_recovery', return_value=True)
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_not_called()
    mount_unas_mock.assert_called_once()
    start_sessmgr_mock.assert_not_called()

    # 3. test no check kernel version
    # kernel version unsupported
    ctx.options.clear()
    ctx.options['kernel_version_check'] = 'none'
    mount_unas_mock.reset_mock()
    mount_nfs_mock.reset_mock()
    mocker.patch('mount_alinas.get_system_release_version', return_value = 'Alibaba Cloud Linux xxx')
    mocker.patch('platform.release', return_value = '5.10.133-13.al8.x86_64')
    mount_alinas.mount_unas(ctx)
    mount_nfs_mock.assert_not_called()
    mount_unas_mock.assert_called_once()