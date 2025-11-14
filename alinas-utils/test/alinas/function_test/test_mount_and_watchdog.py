#
# Copyright 2020-2022 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from collections import namedtuple
from contextlib import contextmanager
import errno
import json
from mock import MagicMock, patch
import multiprocessing as mp
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import os
import random
import uuid
import mount_alinas


MountContext = namedtuple('MountContext', ('uuid', 'mountpath', 'mountpoint'))

DEFAULT_EXITCODE = 1
CGROUP_BASE_MEMORY_LIMIT_SIZE_FLAG = 'CGROUP_BASE_MEMORY_LIMIT_SIZE'

EFC_VERSIONS = {
    '1.1-1': ('https://aliyun-alinas-eac.oss-cn-beijing.aliyuncs.com/alinas-eac-1.1-1.x86_64.rpm', '1.1-2~1.1-4'),
    '1.2-1': ('https://aliyun-alinas-eac.oss-cn-beijing.aliyuncs.com/alinas-eac-1.2-1.x86_64.rpm', '1.1-2~1.1-4'),
    '1.2-2': ('https://aliyun-alinas-eac.oss-cn-beijing.aliyuncs.com/alinas-efc-1.2-2.x86_64.rpm', '>=1.1-5'),
    '1.2-3': ('https://aliyun-alinas-eac.oss-cn-beijing.aliyuncs.com/alinas-efc-1.2-3.x86_64.rpm', '>=1.1-6'),
}
HOT_UPGRADE_RULES = [
    ('1.1-1', '1.2-1'),
    ('1.2-2', '1.2-3'),
]
ALINAS_UTILS_VERSIONS = {
    '1.1-2': 'https://aliyun-encryption.oss-cn-beijing.aliyuncs.com/aliyun-alinas-utils-1.1-2.al7.noarch.rpm',
    '1.1-3': 'https://aliyun-encryption.oss-cn-beijing.aliyuncs.com/aliyun-alinas-utils-1.1-3.al7.noarch.rpm',
    '1.1-4': 'https://aliyun-encryption.oss-cn-beijing.aliyuncs.com/aliyun-alinas-utils-1.1-4.al7.noarch.rpm',
    '1.1-5': 'https://aliyun-encryption.oss-cn-beijing.aliyuncs.com/aliyun-alinas-utils-1.1-5.al7.noarch.rpm',
    '1.1-6': 'https://aliyun-encryption.oss-cn-beijing.aliyuncs.com/aliyun-alinas-utils-1.1-6.al7.noarch.rpm',
}
TEMP_DIR = '/tmp/efc_ft'


def fatal_error(message):
    print('error:', message)
    traceback.print_stack()
    sys.exit(DEFAULT_EXITCODE)


# when use another process to run mount_alinas.main(), we may want to distinguish 
# between a crash in main() and a crash in test code, at this case, we can set 
# the default exit code of test code to any other value instead of -1
def update_exitcode(exitcode):
    global DEFAULT_EXITCODE
    DEFAULT_EXITCODE = exitcode


def parse_arguments():
    if len(sys.argv) != 3:
        fatal_error('format: <file> <mountpath> <mountpoint-parent>')

    _, server, tmpdir = sys.argv
    return server, tmpdir


def execute(cmd, shell, verbose=False, *, ignore_err=False):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
    out, err = proc.communicate()
    out, err = out.decode('utf-8'), err.decode('utf-8')
    if verbose or (proc.returncode != 0 and not ignore_err):
        print('run command {}'.format(cmd))
        print('output:', out, sep='\n')
        print('error:', err, sep='\n')
    return proc.returncode, out, err


def mountpoint_join(parent, name):
    true_name = name
    while true_name.startswith('/'):
        true_name = true_name[1:]
    return os.path.join(parent, true_name)


def check_alifuse_ctl():
    with open('/proc/mounts') as f:
        for line in f.readlines():
            if mount_alinas.ALIFUSE_CTL_MOUNT_PATH in line:
                return True
    return False


def get_proc_pid(proc_name):
    cmd = 'ps -ef | grep {} | grep -vw grep'.format(proc_name)
    _, out, err = execute(cmd, True, ignore_err=True)
    if err:
        fatal_error('get pid of {} failed'.format(proc_name))
    if out.strip():
        line = out.split('\n')[0]
        pid = line.split()[1]
        return int(pid)
    return None


def check_watchdog():
    return get_proc_pid(mount_alinas.WATCHDOG_BIN_NAME) is not None


def restart_watchdog():
    pid = get_proc_pid(mount_alinas.WATCHDOG_BIN_NAME)
    if pid is None:
        fatal_error('get watchdog process failed')
    os.kill(pid, signal.SIGKILL)
    while get_proc_pid(mount_alinas.WATCHDOG_BIN_NAME) is None:
        print('wait watchdog restarting')
        time.sleep(1)


def check_sessmgr():
    return get_proc_pid(mount_alinas.SESSMGR_BIN_PATH) is not None


def stop_sessmgr():
    pid = get_proc_pid(mount_alinas.SESSMGR_BIN_NAME)
    if pid is None:
        fatal_error('get sessmgr process failed')
    os.kill(pid, signal.SIGKILL)


def get_mount_uuid(mountpoint):
    uuids = []
    with open('/proc/mounts') as f:
        for line in f.readlines():
            if mountpoint in line.split():
                fsid, *_ = line.split()
                uuids.append(fsid.split(':')[0])
    if len(uuids) != 1:
        fatal_error('uuids is %s' % str(uuids))
    return uuids[0]


def get_efc_pid(mountpoint, wait_until_one):
    uuid = get_mount_uuid(mountpoint)
    while True:
        pids = []
        cmd = 'ps -ef | grep %s | grep -vw grep' % uuid
        for line in os.popen(cmd).readlines():
            pids.append(int(line.split()[1]))
        if len(pids) == 1:
            return pids[0]
        if wait_until_one:
            time.sleep(1)
            continue
        else:
            fatal_error('found efc processes %s' % str(pids))


def wait_until_efc_exited(ctx):
    cnt = 0
    while True:
        assert cnt < 60
        pids = []
        if ctx is not None:
            cmd = 'ps -ef | grep %s | grep -vw grep' % ctx.uuid
        else:
            cmd = 'ps -ef | grep aliyun-alinas-efc | grep -v sessmgrd | grep -vw grep'
        for line in os.popen(cmd).readlines():
            pids.append(int(line.split()[1]))
        if pids:
            print(pids)
            time.sleep(1)
            cnt += 1
            continue
        else:
            break


def get_memory_usage(mountpoint):
    # trigger memory usage
    os.listdir(mountpoint)
    uuid = get_mount_uuid(mountpoint)
    stat_path = os.path.join(mount_alinas.CGROUP_DIR, uuid, 'memory.stat')
    rss = None
    with open(stat_path, 'r') as f:
        for line in f.readlines():
            if 'total_rss' in line.split():
                rss = int(line.split()[-1])
    if rss is None:
        fatal_error('can not get memory used')
    return rss


def wait_efc_restart(mountpoint, opid):
    restarted = False
    while not restarted:
        try:
            # use statfs to wait until the new process running
            os.statvfs(mountpoint)
            restarted = get_efc_pid(mountpoint, True) != opid
        except OSError as e:
            assert e.errno == errno.EIO
            time.sleep(0.1)


def version_compare(lv, rv):
    lvt = re.split(r'\.|-', lv)
    rvt = re.split(r'\.|-', rv)
    if lvt < rvt:
        return -1
    elif lvt == rvt:
        return 0
    else:
        return 1


def get_alinas_utils_version():
    ret, out, _ = execute('yum list installed | grep aliyun-alinas-utils.noarch', True, ignore_err=True)
    if ret:
        return None
    vstr = out.split()[1]
    if vstr.endswith('.al7'):
        version = vstr[:-4]
    elif vstr.endswith('.alios7'):
        version = vstr[:-7]
    else:
        version = vstr
    if version not in ALINAS_UTILS_VERSIONS:
        fatal_error('unknown alinas utils version: %s' % version)
    return version


def get_alinas_utils_package_path(version):
    if not os.path.exists(TEMP_DIR):
        os.mkdir(TEMP_DIR)
    return os.path.join(TEMP_DIR, ALINAS_UTILS_VERSIONS.get(version).split('/')[-1])


def install_alinas_utils(version):
    package = get_alinas_utils_package_path(version)
    if not os.path.exists(package):
        ret, *_ = execute('wget {} -O {}'.format(ALINAS_UTILS_VERSIONS.get(version), package), True)
        if ret:
            fatal_error('download alinas utils package (%s) failed' % version)
    ret, *_ = execute('yum install -y {}'.format(package), shell=True)
    if ret:
        fatal_error('install alinas utils failed')


def uninstall_alinas_utils():
    ret, *_ = execute('yum remove -y aliyun-alinas-utils', True)
    if ret:
        fatal_error('uninstall alinas utils failed')


def select_alinas_utils_version(efc_version):
    _, require = EFC_VERSIONS.get(efc_version)
    minv, maxv = None, None
    if '~' in require:
        minv, maxv = require.split('~')
    elif require.startswith('>='):
        minv = require[2:]
        maxv = max(ALINAS_UTILS_VERSIONS.keys())
    else:
        fatal_error('unknown requirement format %s' % require)
    return minv, maxv


def get_efc_package_path(version):
    return os.path.join(TEMP_DIR, EFC_VERSIONS.get(version)[0].split('/')[-1])


def remove_kernel_mod(mod):
    ctl_fs = '/sys/fs/%s/connections' % mod
    exists = False
    with open('/proc/mounts') as f:
        for line in f.readlines():
            if ctl_fs in line:
                exists = True
    if exists:
        ret, *_ = execute('umount %s' % ctl_fs, True)
        if ret:
            fatal_error('umount %s failed' % ctl_fs)

    ret, *_ = execute('/usr/sbin/rmmod {}'.format(mod), True)
    # if ret:
    #     fatal_error('rmmod failed')


def remove_kernel_mods():
    _, out, err = execute("/usr/sbin/lsmod | grep fuse | awk '{ print $1 }' | tr '\n' ' '", True, ignore_err=True)
    if err:
        print('no (ali)fuse module')
    if out:
        for mod in out.split():
            remove_kernel_mod(mod)


def install_efc(version):
    old_alinas_utils = get_alinas_utils_version()
    min_version, max_version = select_alinas_utils_version(version)
    if old_alinas_utils is None or version_compare(old_alinas_utils, min_version) < 0 or version_compare(old_alinas_utils, max_version) > 0:
        if old_alinas_utils is not None:
            uninstall_alinas_utils()
        install_alinas_utils(max_version)
    package = get_efc_package_path(version)
    if not os.path.exists(package):
        ret, *_ = execute('wget {} -O {}'.format(EFC_VERSIONS.get(version)[0], package), True)
        if ret:
            fatal_error('download efc package {} failed'.format(version))
    ret, *_ = execute('yum install -y {}'.format(package), True)
    if ret:
        fatal_error('installed efc {} failed'.format(version))


def uninstall_efc(rmmod):
    ret, *_ = execute('yum remove -y alinas-e[af]c.x86_64', True)
    if ret:
        return False
    if rmmod:
        remove_kernel_mods()
    uninstall_alinas_utils()
    return True


@contextmanager
def mock_mount_env(remote_name, mount_name, *options):
    server, mountpoint_parent = parse_arguments()
    mountpath = '{}:{}'.format(server, remote_name)
    mountpoint = mountpoint_join(mountpoint_parent, mount_name)
    # create remote mount path
    if remote_name != '/':
        name = str(uuid.uuid4())
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=env') as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            os.makedirs(mountpoint_join(ctx.mountpoint, remote_name), exist_ok=True)
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)
    os.makedirs(mountpoint, exist_ok=True)
    options += ('netcheck=none',)
    margs = [sys.argv[0], mountpath, mountpoint, '-o', ','.join(options)]
    try:
        oargs = sys.argv
        sys.argv = margs
        ctx = MountContext(None, mountpath, mountpoint)
        yield ctx
    finally:
        sys.argv = oargs


@contextmanager
def mock_unmount_env(unmount_name, force, *options):
    server, mountpoint_parent = parse_arguments()
    mountpoint = mountpoint_join(mountpoint_parent, unmount_name)
    uargs = [sys.argv[0], server, mountpoint, '-u']
    if force:
        uargs.append('-f')
    uargs.append(','.join(options))
    try:
        oargs = sys.argv
        sys.argv = uargs
        ctx = MountContext(get_mount_uuid(mountpoint), None, mountpoint)
        yield ctx
    finally:
        sys.argv = oargs


def ensure_mount_ok(ctx):
    # trigger efc related files
    os.statvfs(ctx.mountpoint)
    uuid = get_mount_uuid(ctx.mountpoint)
    if not check_watchdog():
        fatal_error('watchdog is not running {}')
    if not check_sessmgr():
        fatal_error('sessmgr is not running')
    # log dir
    log_dir = os.path.join(mount_alinas.UNAS_LOG_DIR, 'efc-' + uuid)
    if not os.path.isdir(log_dir):
        fatal_error('check log dir {} failed'.format(log_dir))
    # state file
    state_file = os.path.join(mount_alinas.STATE_FILE_DIR, 'eac-' + uuid)
    if not os.path.isfile(state_file):
        fatal_error('check state file {} failed'.format(state_file))
    # bind root
    if uuid.startswith(mount_alinas.BIND_ROOT_PREFIX):
        def is_root(uuid, entry):
            root_mountpoint = os.path.join(mount_alinas.BIND_ROOT_DIR, uuid)
            if root_mountpoint in entry:
                return True
            # the mount entry is starts with '/run', not '/var/run'
            if root_mountpoint.startswith('/var/run'):
                return root_mountpoint[4:] in entry

        root_mountpoint = os.path.join(mount_alinas.BIND_ROOT_DIR, uuid)
        if not os.path.isdir(root_mountpoint):
            fatal_error('check mount root dir %s failed' % root_mountpoint)
        root_found, entry_found = False, False
        with open('/proc/mounts') as f:
            for line in f.readlines():
                if is_root(uuid, line):
                    root_found = True
                    server = line.split()[0]
                    mount_host = ctx.mountpath.split(':')[0]
                    if server != '{}:{}:/'.format(uuid, mount_host):
                        fatal_error('check bind root entry failed')
                if ctx.mountpoint in line.split():
                    entry_found = True
                    server = line.split()[0]
                    if server != '{}:{}'.format(uuid, ctx.mountpath):
                        fatal_error('check mount entry failed')
        if not root_found:
            fatal_error('bind root entry not found')
        if not entry_found:
            fatal_error('mount entry not found')
    else:
        # when current mount is not bind-root, check lock file. if current mount 
        # is bind-root, its lock file may be removed by watchdog
        lock_file = os.path.join(mount_alinas.STATE_FILE_DIR, mount_alinas.get_uuid_lock_name(uuid))
        if not os.path.isfile(lock_file):
            fatal_error('check lock file {} failed'.format(lock_file))


def ensure_unmount_ok(ctx, wait_exited=True):
    mount_root_entries_cnt = 0
    with open('/proc/mounts') as f:
        for line in f.readlines():
            if ctx.mountpoint in line.split():
                fatal_error('mount entry exists after unmount')
            if ctx.uuid in line:
                mount_root_entries_cnt += 1
    # if the last bind-root entry is unmounted, the root mount will be unmounted too
    if mount_root_entries_cnt == 1:
        fatal_error('bind root entry still exists after unmounted all entries')
    if wait_exited:
        print('wait exited')
        wait_until_efc_exited(ctx)


def mount_process(mount_path, name, *options):
    global DEFAULT_EXITCODE
    DEFAULT_EXITCODE = errno.ECHILD
    with mock_mount_env(mount_path, name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)


def unmount_process(name, force, *options):
    global DEFAULT_EXITCODE
    DEFAULT_EXITCODE = errno.ECHILD
    with mock_unmount_env(name, force, *options) as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_nobind_mount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'nobind'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_nobind_multi_mounts(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MOUNTS_CNT = 10
    mount_info = [('nobind-{}'.format(i), 'ft-nobind-{}'.format(i)) for i in range(MOUNTS_CNT)]
    for name, owner in mount_info:
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
    for name, _ in mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)


def test_bind_mount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = '/bind/local'
    with mock_mount_env('/bind/remote', name, 'trybind=yes', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_bind_multi_mounts(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MOUNTS_CNT = 10
    mount_info = [('bind-{}'.format(i), 'ft-{}'.format(i)) for i in range(MOUNTS_CNT)]
    for name, owner in mount_info:
        with mock_mount_env('/', name, 'trybind=yes', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
    for name, _ in mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx, wait_exited=False)
    wait_until_efc_exited(None)


def test_nobind_and_bind_mount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    NOBIND_MOUNTS_CNT = 10
    nobind_mount_info = [('nobind-{}'.format(i), 'ft-nobind-{}'.format(i)) for i in range(NOBIND_MOUNTS_CNT)]
    for name, owner in nobind_mount_info:
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
    BIND_MOUNTS_CNT = 10
    bind_mount_info = [('bind-{}'.format(i), 'ft-bind-{}'.format(i)) for i in range(BIND_MOUNTS_CNT)]
    for name, owner in bind_mount_info:
        with mock_mount_env('/', name, 'trybind=yes', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
    for name, _ in bind_mount_info + nobind_mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx, wait_exited=False)
    wait_until_efc_exited(None)


def test_manual_bind_mount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'manual_bind_mount'
    import tempfile
    tmpdir = tempfile.mkdtemp()
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    ret, _, _ = execute('mount --bind %s %s' % (ctx.mountpoint, tmpdir), shell=True)
    assert ret == 0
    ret, _, _ = execute('umount %s' % ctx.mountpoint, shell=True, ignore_err=True)
    assert ret != 0
    ret, _, _ = execute('umount %s' % tmpdir, shell=True)
    assert ret == 0
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_force_unmount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'force'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    with mock_unmount_env(name, True, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def io_process(filepath):
    fd = os.open(filepath, os.O_CREAT | os.O_RDWR)
    time.sleep(10)
    ret = os.write(fd, 'test'.encode('utf-8'))
    if ret >= 0:
        exit(0)
    else:
        exit(ret)


def test_unmount_when_io(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'unmount-when-io'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    io_proc = mp.Process(target=io_process, args=(os.path.join(mountpoint, 'io_test'),))
    umount_proc = mp.Process(target=unmount_process, args=(name, False, 'efc'))
    io_proc.start()
    time.sleep(1)
    umount_proc.start()
    umount_proc.join()
    io_proc.join()
    assert umount_proc.exitcode == errno.EBUSY
    assert io_proc.exitcode == 0
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_force_umount_when_io(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'force-unmount-when-io'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    io_proc = mp.Process(target=io_process, args=(os.path.join(mountpoint, 'io_test'),))
    umount_proc = mp.Process(target=unmount_process, args=(name, True, 'efc'))
    io_proc.start()
    time.sleep(1)
    umount_proc.start()
    umount_proc.join()
    io_proc.join()
    assert umount_proc.exitcode == errno.EBUSY
    assert io_proc.exitcode == 0
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_flush_when_umount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'flush-when-umount'
    for i in range(10):
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=flush') as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            mountpoint = ctx.mountpoint

        filepath = os.path.join(mountpoint, 'flush-file')
        data = chr(ord('a') + i % 26) * 1024 * 16
        fd = os.open(filepath, os.O_CREAT | os.O_RDWR)
        os.write(fd, data.encode('utf-8'))
        os.close(fd)

        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)

        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=flush') as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            mountpoint = ctx.mountpoint

        with open(filepath) as f:
            content = ''.join(f.readlines())
            assert content == data

        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)


def test_journal_when_umount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'flush-journal-when-umount'

    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=flush') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint

    for i in range(10):
        journal_file = os.path.join(mountpoint, 'journal-file-%d' % i)
        if os.path.exists(journal_file):
            os.remove(journal_file)

    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)

    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=flush') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint

    for i in range(10):
        journal_file = os.path.join(mountpoint, 'journal-file-%d' % i)
        assert not os.path.exists(journal_file)

    cmd = 'aliyun-alinas-efc-cli -r failpoint -m %s -f "fp_flush_dirty_delay=10*sleep(1000)"' % mountpoint
    rc, out, _ = execute(cmd, True)
    print(rc, out, _)
    if rc != 0:
        if "can't find" in out:
            print('fp_flush_dirty_delay is not supported')
            return False
        else:
            fatal_error('set failpoint failed')

    for i in range(10):
        journal_file = os.path.join(mountpoint, 'journal-file-%d' % i)
        os.mknod(journal_file)

    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)

    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=flush') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint

    for i in range(10):
        journal_file = os.path.join(mountpoint, 'journal-file-%d' % i)
        assert os.path.exists(journal_file)

    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_nobind_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'nobind-upgrade'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, True)
    with mock_mount_env('/', name, *options, 'upgrade') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        # use statfs to wait until the new process running
        os.statvfs(ctx.mountpoint)
        npid = get_efc_pid(ctx.mountpoint, True)
    assert opid != npid
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_nobind_multi_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MOUNTS_CNT = 10
    mount_info = [('nobind-upgrade-{}'.format(i), 'ft-{}'.format(i)) for i in range(MOUNTS_CNT)]
    opids, npids = [], []
    mountpoints = []
    options = ['trybind=no', 'efc']
    for name, owner in mount_info:
        with mock_mount_env('/', name, *options, 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            opids.append(get_efc_pid(ctx.mountpoint, True))
    for name, _ in mount_info:
        with mock_mount_env('/', name, *options, 'upgrade', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            mountpoints.append(ctx.mountpoint)
            npids.append(get_efc_pid(ctx.mountpoint, True))
    # use statfs to wait until the new process running
    for mountpoint in mountpoints:
        os.statvfs(mountpoint)
    for opid, npid in zip(opids, npids):
        assert opid != npid
    for name, _ in mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)


def test_bind_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    mountpath, mountpoint = '/bind/remote', '/bind/local'
    opid, npid = None, None
    options = ['trybind=yes', 'efc', 'client_owner=ft']
    with mock_mount_env(mountpath, mountpoint, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, True)
    with mock_mount_env(mountpath, mountpoint, *options, 'upgrade') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        # use statfs to wait until the new process running
        os.statvfs(ctx.mountpoint)
        npid = get_efc_pid(ctx.mountpoint, True)
    assert opid != npid
    with mock_unmount_env(mountpoint, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_bind_multi_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MOUNTS_CNT = 10
    mount_info = [
        ('/bind/remote/bind-{}'.format(i), '/bind/local/bind-{}'.format(i), 'ft-{}'.format(i))
        for i in range(MOUNTS_CNT)
    ]
    opid = None
    mountpoints = []
    options = ['trybind=yes', 'efc']
    for mountpath, name, owner in mount_info:
        with mock_mount_env(mountpath, name, *options, 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            opid = get_efc_pid(ctx.mountpoint, True)
    for mountpath, name, owner in mount_info:
        with mock_mount_env(mountpath, name, *options, 'upgrade', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            mountpoints.append(ctx.mountpoint)
            # use statfs to wait until the new process running
            os.statvfs(ctx.mountpoint)
            npid = get_efc_pid(ctx.mountpoint, True)
            assert opid != npid
            opid = npid
    for _, name, _ in mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx, wait_exited=False)
    wait_until_efc_exited(None)


def test_nobind_and_bind_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    NOBIND_MOUNTS_CNT = 10
    nobind_mount_info = [('nobind-{}'.format(i), 'ft-nobind-{}'.format(i)) for i in range(NOBIND_MOUNTS_CNT)]
    nobind_opids, nobind_npids, nobind_mountpoints = [], [], []
    for name, owner in nobind_mount_info:
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            nobind_opids.append(get_efc_pid(ctx.mountpoint, True))
    BIND_MOUNTS_CNT = 10
    bind_mount_info = [('bind-{}'.format(i), 'ft-bind-{}'.format(i)) for i in range(BIND_MOUNTS_CNT)]
    bind_opid = None
    for name, owner in bind_mount_info:
        with mock_mount_env('/', name, 'trybind=yes', 'efc', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            bind_opid = get_efc_pid(ctx.mountpoint, True)
    for name, owner in nobind_mount_info:
        with mock_mount_env('/', name, 'trybind=no', 'efc', 'upgrade', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            nobind_npids.append(get_efc_pid(ctx.mountpoint, True))
            nobind_mountpoints.append(ctx.mountpoint)
    for name, owner in bind_mount_info:
        with mock_mount_env('/', name, 'trybind=yes', 'efc', 'upgrade', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            # use statfs to wait until the new process running
            os.statvfs(ctx.mountpoint)
            bind_npid = get_efc_pid(ctx.mountpoint, True)
            assert bind_opid != bind_npid
            bind_opid = bind_npid
    # use statfs to wait until the new process running
    for mountpoint in nobind_mountpoints:
        os.statvfs(mountpoint)
    for opid, npid in zip(nobind_opids, nobind_npids):
        assert opid != npid
    for name, _ in bind_mount_info + nobind_mount_info:
        with mock_unmount_env(name, False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx, wait_exited=False)
    wait_until_efc_exited(None)


def concurrent_process(mountpath, name, trybind, owner):
    update_exitcode(errno.ECHILD)
    random.seed(time.time())
    time.sleep(random.random() * 5)
    trybind_option = 'trybind={}'.format('yes' if trybind else 'no')
    with mock_mount_env(mountpath, name, trybind_option, 'efc', 'client_owner={}'.format(owner)) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, True)
        print(name, ctx.mountpoint, get_mount_uuid(ctx.mountpoint))
    time.sleep(random.random() * 5)
    if random.random() > 0.5:
        with mock_mount_env(mountpath, name, trybind_option, 'efc', 'upgrade', 'client_owner={}'.format(owner)) as ctx:
            mount_alinas.main()
            ensure_mount_ok(ctx)
            # use statfs to wait until the new process running
            os.statvfs(ctx.mountpoint)
            npid = get_efc_pid(ctx.mountpoint, True)
            if opid == npid:
                fatal_error('upgrade failed')
            print('upgraded', ctx, opid, 'to', npid)
        time.sleep(random.random() * 5)
    with mock_unmount_env(name, random.random() > 0.5, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx, wait_exited=False)


def test_concurrent_mount_and_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MOUNTS_CNT = 30
    processes = []
    for i in range(MOUNTS_CNT):
        mountpath = '/concurrent/{}'.format(i)
        name = '/concurrent/{}'.format(i)
        trybind = bool(i % 2)
        owner = 'concurrent-{}'.format(i)
        proc = mp.Process(target=concurrent_process, args=(mountpath, name, trybind, owner))
        proc.start()
        processes.append(proc)
    for proc in processes:
        proc.join()
        print('concurrent exitcode', proc.exitcode)
        assert proc.exitcode != errno.ECHILD
    wait_until_efc_exited(None)


def test_watchdog_restart_efc(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'restart'
    with mock_mount_env('/', name, 'trybind=no', 'efc') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, False)
        os.kill(opid, signal.SIGKILL)
        wait_efc_restart(ctx.mountpoint, opid)
        npid = get_efc_pid(ctx.mountpoint, False)
        assert opid != npid
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_watchdog_restart_sessmgr(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    assert check_sessmgr()
    stop_sessmgr()
    while not check_sessmgr():
        print('wait sessmgr restarting')
        time.sleep(1)


def test_watchdog_restart(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    assert check_watchdog()
    restart_watchdog()


def test_memory_limit_exceeded_with_cgroup(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    MEM_LIMIT = 500 * 4096
    name = 'limit-exceeded-cgroup'
    with mock_mount_env('/', name, 'trybind=no', 'efc') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, False)
        uuid = get_mount_uuid(ctx.mountpoint)
        limit_path = os.path.join(mount_alinas.CGROUP_DIR, uuid, mount_alinas.CGROUP_LIMIT_FILE)
        with open(limit_path, 'w') as f:
            f.write(str(MEM_LIMIT))
        mem = get_memory_usage(ctx.mountpoint)
        if mem > MEM_LIMIT:
            restarted = False
            while not restarted:
                try:
                    if get_efc_pid(ctx.mountpoint, True) == opid:
                        print('wait efc restarting')
                        time.sleep(1)
                        continue
                    # use statfs to wait until the new process running
                    os.statvfs(ctx.mountpoint)
                    restarted = True
                except OSError as e:
                    assert e.errno == errno.EIO
                    time.sleep(0.1)
            npid = get_efc_pid(ctx.mountpoint, False)
            assert opid != npid
        else:
            print('set to a larger memory limit, skip test')
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def replace_watchdog_memory_limit_line(newline):
    old = None
    lines = []
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'r') as f:
        for line in f.readlines():
            if re.match(CGROUP_BASE_MEMORY_LIMIT_SIZE_FLAG + r'\s*=\s*\d', line):
                if old is not None:
                    fatal_error('more than 1 memory limit line are found')
                old = line
                if newline[-1] != '\n':
                    newline += '\n'
                lines.append(newline)
            else:
                lines.append(line)
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'w') as f:
        f.writelines(lines)
    if old is None:
        fatal_error('can not find memory limit line')
    print('replace watchdog script line:\n\t{} => {}'.format(old.strip(), newline.strip()))
    return old


def invalidate_adjust_memory():
    lines = []
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'r') as f:
        for line in f.readlines():
            if re.match(r'\s*adjust_memory_limit()', line):
                newline = '    # adjust_memory_limit()\n'
                lines.append(newline)
                print('replace watchdog script line:\n\t{} => {}'.format(line.strip(), newline.strip()))
            else:
                lines.append(line)
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'w') as f:
        f.writelines(lines)


def validate_adjust_memory():
    lines = []
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'r') as f:
        for line in f.readlines():
            if re.match(r'\s*# adjust_memory_limit()', line):
                newline = '    adjust_memory_limit()\n'
                lines.append(newline)
                print('replace watchdog script line:\n\t{} => {}'.format(line.strip(), newline.strip()))
            else:
                lines.append(line)
    with open(mount_alinas.WATCHDOG_BIN_PATH, 'w') as f:
        f.writelines(lines)


def test_memory_limit_exceeded_with_watchdog(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'limit-exceeded-watchdog'
    with mock_mount_env('/', name, 'trybind=no', 'efc') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        opid = get_efc_pid(ctx.mountpoint, False)
        mem = get_memory_usage(ctx.mountpoint)
        if mem:
            nlimit = '{} = {}'.format(CGROUP_BASE_MEMORY_LIMIT_SIZE_FLAG, mem // 2)
            olimit = replace_watchdog_memory_limit_line(nlimit)
            invalidate_adjust_memory()
            restart_watchdog()
            restarted = False
            while not restarted:
                try:
                    if get_efc_pid(ctx.mountpoint, True) == opid:
                        print('wait efc restarting')
                        time.sleep(1)
                        continue
                    # use statfs to wait until the new process running
                    os.statvfs(ctx.mountpoint)
                    restarted = True
                except OSError as e:
                    assert e.errno == errno.EIO
                    time.sleep(0.1)
            validate_adjust_memory()
            replace_watchdog_memory_limit_line(olimit)
            restart_watchdog()
            npid = get_efc_pid(ctx.mountpoint, True)
            assert opid != npid
        else:
            print('can not get memory used, skip test')
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def mock_prometheus_name(parent):
    while parent[-1] == '/':
        parent = parent[:-1]
    n = len(parent.split('/'))
    name = ''
    for i in range(4 - n):
        name += '/%d' % i
    name += '/pods/a/volumes/alicloud~nas/c'
    return name, 'a/c'


def test_watchdog_monitor(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    _, parent = parse_arguments()
    name, key = mock_prometheus_name(parent)
    mountpoint = ''
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    assert mount_alinas.valid_mountpoint_for_prometheus(mountpoint)
    config = mount_alinas.read_config()
    poll_interval_sec = config.getint('mount-watchdog', 'poll_interval_sec', default=3, minvalue=1, maxvalue=60)
    time.sleep(2 * poll_interval_sec)
    monitor_path = os.path.join(mount_alinas.EFC_WORKSPACE_DIR, key)
    old_mtimes = {}
    for file in os.listdir(monitor_path):
        old_mtimes[file] = os.stat(os.path.join(monitor_path, file)).st_mtime
    time.sleep(2 * poll_interval_sec)
    for file in os.listdir(monitor_path):
        assert file in old_mtimes
        assert old_mtimes[file] < os.stat(os.path.join(monitor_path, file)).st_mtime
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_watchdog_clear(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'clear'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        uuid = get_mount_uuid(ctx.mountpoint)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)

    residual = {'shm', 'cgroup', 'state'}
    shm = [os.path.join('/dev/shm', '{}_{}'.format(fmt, uuid)) for fmt in ('file', 'journal', 'page', 'volume')]
    cgroup = os.path.join(mount_alinas.CGROUP_DIR, uuid)
    state = [os.path.join(mount_alinas.STATE_FILE_DIR, file) for file in
                    ('eac-' + uuid, mount_alinas.UNAS_MOUNT_LOCK_PREFIX + uuid)]
    config = mount_alinas.read_config()
    poll_interval_sec = config.getint('mount-watchdog', 'poll_interval_sec', default=3, minvalue=1, maxvalue=60)
    while residual:
        print('wait for watchdog loop')
        time.sleep(poll_interval_sec)
        if 'shm' in residual:
            for shm_file in shm:
                if os.path.exists(shm_file):
                    break
            else:
                print('shm files are removed')
                residual.remove('shm')
        if 'cgroup' in residual:
            if not os.path.exists(cgroup):
                print('cgroup dir is removed')
                residual.remove('cgroup')
        if 'state' in residual:
            for state_file in state:
                if os.path.exists(state_file):
                    break
            else:
                print('state files are removed')
                residual.remove('state')


def test_nobind_mount_when_crash(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'nobind'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    pid = get_efc_pid(mountpoint, False)
    proc = mp.Process(target=mount_process, args=('/', name, *options))
    os.kill(pid, signal.SIGKILL)
    proc.start()
    proc.join()
    assert proc.exitcode == 1
    wait_efc_restart(mountpoint, pid)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_bind_mount_when_crash(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'bind'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    pid = get_efc_pid(ctx.mountpoint, False)
    proc = mp.Process(target=mount_process, args=('/', name, *options))
    os.kill(pid, signal.SIGKILL)
    proc.start()
    proc.join()
    assert proc.exitcode == 1
    wait_efc_restart(mountpoint, pid)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_upgrade_when_crash(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'upgrade'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        mountpoint = ctx.mountpoint
    pid = get_efc_pid(mountpoint, False)
    proc = mp.Process(target=mount_process, args=('/', name, *options, 'upgrade'))
    os.kill(pid, signal.SIGKILL)
    proc.start()
    proc.join()
    assert proc.exitcode == 0
    wait_efc_restart(mountpoint, pid)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_unmount_when_crash(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'unmount'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        pid = get_efc_pid(ctx.mountpoint, False)
        mountpoint = ctx.mountpoint
    proc = mp.Process(target=unmount_process, args=(name, False, 'efc'))
    os.kill(pid, signal.SIGKILL)
    proc.start()
    proc.join()
    wait_efc_restart(mountpoint, pid)
    assert proc.exitcode == 1
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def mount_error_process(error_type, mount_path, name, *options):
    true_popen = subprocess.Popen
    with patch('subprocess.Popen') as mock_popen:
        def popen_side_effect(cmd, *args, **kargs):
            if isinstance(cmd, str) and cmd.startswith(mount_alinas.UNAS_BIN_PATH):
                if error_type == 'error':
                    mocker = MagicMock()
                    mocker.communicate.return_value = ('stdout'.encode(), 'stderr'.encode(), )
                    mocker.returncode = 1
                    return mocker
                elif error_type == 'timeout':
                    return true_popen('sleep 1000', shell=True)
            else:
                return true_popen(cmd, *args, **kargs)
        mock_popen.side_effect = popen_side_effect
        with mock_mount_env(mount_path, name, *options) as _:
            mount_alinas.main()


def test_mount_error(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    proc = mp.Process(target=mount_error_process, args=('error', '/', 'mount-error', 'trybind=no', 'efc', 'client_owner=ft'))
    proc.start()
    proc.join()
    assert proc.exitcode == 1


def test_mount_timeout(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    proc = mp.Process(target=mount_error_process, args=('timeout', '/', 'mount-error', 'trybind=no', 'efc', 'client_owner=ft'))
    proc.start()
    proc.join()
    assert proc.exitcode == 1


def mock_socket_server(address):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(address)
    sock.listen(1)
    conn, _ = sock.accept()
    while True:
        conn.recv(1024)


def unmount_error_process(error_type, name, force, *options):
    update_exitcode(errno.ECHILD)
    true_socket = socket.socket
    with patch('socket.socket') as mock_socket:
        def socket_side_effect(*args, **kargs):
            mocker = MagicMock()
            mocker.true_socket = true_socket(*args, **kargs)
            def connect_side_effect(*args, **kargs):
                if isinstance(args[0], str) and args[0].endswith('.sock'):
                    if error_type == 'error':
                        mocker.true_socket.connect(*args, **kargs)
                        # do not send anything
                        mocker.send = MagicMock()
                        mocker.send.return_value = 0
                        mocker.recv = MagicMock()
                        mocker.recv.return_value = b''
                    else:
                        if not os.path.exists(error_type):
                            fatal_error('can not mock socket')
                        mocker.true_socket.connect(error_type)
            mocker.connect.side_effect = connect_side_effect
            mocker.bind = mocker.true_socket.bind
            mocker.getsockname = mocker.true_socket.getsockname
            mocker.settimeout = mocker.true_socket.settimeout
            mocker.send = mocker.true_socket.send
            mocker.recv = mocker.true_socket.recv
            mocker.close = mocker.true_socket.close
            return mocker
        mock_socket.side_effect = socket_side_effect
        with mock_unmount_env(name, force, *options) as ctx:
            mount_alinas.main()


def test_unmount_error(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'unmount-error'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    proc = mp.Process(target=unmount_error_process, args=('error', name, False, 'efc'))
    proc.start()
    proc.join()
    assert proc.exitcode == 1
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_unmount_timeout(mocker, server, testdir, tmpdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'unmount-timeout'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    mock_socket_addr = str(tmpdir.join('test.sock'))
    server_proc = mp.Process(target=mock_socket_server, args=(mock_socket_addr,))
    server_proc.start()
    proc = mp.Process(target=unmount_error_process, args=(mock_socket_addr, name, False, 'efc'))
    proc.start()
    proc.join()
    assert proc.exitcode == 1
    server_proc.terminate()
    if os.path.exists(mock_socket_addr):
        os.remove(mock_socket_addr)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_upgrade_error(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'upgrade-error'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        pid = get_efc_pid(ctx.mountpoint, False)
    proc = mp.Process(target=mount_error_process, args=('error', '/', name, *options, 'upgrade'))
    proc.start();
    proc.join()
    assert proc.exitcode == 1
    with mock_unmount_env(name, False, 'efc') as ctx:
        assert get_efc_pid(ctx.mountpoint, False) == pid
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_upgrade_timeout(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'upgrade-timeout'
    options = ['trybind=no', 'efc', 'client_owner=ft']
    with mock_mount_env('/', name, *options) as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        pid = get_efc_pid(ctx.mountpoint, False)
    proc = mp.Process(target=mount_error_process, args=('timeout', '/', name, *options, 'upgrade'))
    proc.start();
    proc.join()
    assert proc.exitcode == 1
    with mock_unmount_env(name, False, 'efc') as ctx:
        assert get_efc_pid(ctx.mountpoint, False) == pid
        mount_alinas.main()
        ensure_unmount_ok(ctx)


#  # may mount fail
# def test_sessmgrd_crash_when_mount():
#     true_popen = subprocess.Popen
#     with patch('subprocess.Popen') as mock_popen:
#         random.seed(time.time())
#         crash_point = random.randint(3, 6)
#         def popen_side_effect(*args, **kargs):
#             if mock_popen.call_count == crash_point:
#                 stop_sessmgr()
#             return true_popen(*args, **kargs)
#         mock_popen.side_effect = popen_side_effect
#         with mock_mount_env('/', 'mount-sessmgrd-crash', 'trybind=no', 'efc', 'client_owner=ft') as ctx:
#             mount_alinas.main()
#             ensure_mount_ok(ctx)
#     with mock_unmount_env('mount-sessmgrd-crash', False, 'efc') as ctx:
#         mount_alinas.main()
#         ensure_unmount_ok(ctx)


def test_sessmgrd_crash_when_unmount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    with mock_mount_env('/', 'unmount-sessmgrd-crash', 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    true_socket = socket.socket
    with patch('socket.socket') as mock_socket:
        def socket_side_effect(*args, **kargs):
            stop_sessmgr()
            return true_socket(*args, **kargs)
        mock_socket.side_effect = socket_side_effect
        with mock_unmount_env('unmount-sessmgrd-crash', False, 'efc') as ctx:
            mount_alinas.main()
            ensure_unmount_ok(ctx)


# # may fail
# def test_sessmgrd_crash_when_upgrade():
#     mountpoint = ''
#     with mock_mount_env('/', 'upgrade-sessmgrd-crash', 'trybind=no', 'efc', 'client_owner=ft') as ctx:
#         mount_alinas.main()
#         ensure_mount_ok(ctx)
#         mountpoint = ctx.mountpoint
#     true_popen = subprocess.Popen
#     with patch('subprocess.Popen') as mock_popen:
#         random.seed(time.time())
#         crash_point = random.randint(3, 6)
#         def popen_side_effect(*args, **kargs):
#             if mock_popen.call_count == crash_point:
#                 stop_sessmgr()
#             return true_popen(*args, **kargs)
#         mock_popen.side_effect = popen_side_effect
#         with mock_mount_env('/', 'upgrade-sessmgrd-crash', 'trybind=no', 'efc', 'client_owner=ft', 'upgrade') as ctx:
#             mount_alinas.main()
#     os.statvfs(mountpoint)
#     with mock_unmount_env('upgrade-sessmgrd-crash', False, 'efc') as ctx:
#         mount_alinas.main()
#         ensure_unmount_ok(ctx)


def test_mount_with_hang_mount(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    with mock_mount_env('/', 'hang', 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
        uuid = get_mount_uuid(ctx.mountpoint)
        statfile = os.path.join(mount_alinas.STATE_FILE_DIR, 'eac-{}'.format(uuid))
        with open(statfile, 'r+') as f:
            state = json.load(f)
            old_cmd = state['mountcmd']
            state['mountcmd'] = 'ls'
            f.truncate(0)
            f.seek(0)
            json.dump(state, f)
        pid = get_efc_pid(ctx.mountpoint, False)
        os.kill(pid, signal.SIGKILL)
    with mock_mount_env('/', 'other', 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    with mock_unmount_env('other', False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)
    with mock_unmount_env('hang', False, 'efc') as ctx:
        with open(statfile, 'r+') as f:
            state = json.load(f)
            state['mountcmd'] = old_cmd
            f.truncate(0)
            f.seek(0)
            json.dump(state, f)
        wait_efc_restart(ctx.mountpoint, pid)
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_uninstall_when_mounted(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    name = 'uninstall'
    with mock_mount_env('/', name, 'trybind=no', 'efc', 'client_owner=ft') as ctx:
        mount_alinas.main()
        ensure_mount_ok(ctx)
    assert not uninstall_efc(False)
    with mock_unmount_env(name, False, 'efc') as ctx:
        mount_alinas.main()
        ensure_unmount_ok(ctx)


def test_install_state(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])

    # filename and its minimum required version
    files = [
        ('aliyun-alinas-e[af]c', '1.1-1'),
        ('aliyun-alinas-e[af]c-sessmgrd', '1.1-1'),
        ('aliyun-alinas-e[af]c-cli', '1.1-1'),
        ('aliyun-alinas-e[af]c-cmd', '1.2-2'),
        ('aliyun-alinas-*dadi-kubediscover', '1.1-1'),
        ('*alifuse.ko', '1.1-1'),
        ('aliyun-alinas-e[af]c-rpm-*', '1.2-2'),
    ]

    for version in EFC_VERSIONS.keys():
        assert uninstall_efc(False)
        install_efc(version)
        for file, min_version in files:
            # ignore non-exist file at current version
            if version_compare(version, min_version) < 0:
                continue
            ret, *_ = execute('ls /usr/bin/{}'.format(file), True)
            assert ret == 0


def get_efc_option(version):
    # use 'eac' option when version is lower than 1.2-2
    if version_compare(version, '1.2-1') <= 0:
        return 'eac'
    else:
        return 'efc'


def test_hot_upgrade(mocker, server, testdir):
    mocker.patch('sys.argv', [__file__, server, testdir])
    mountpath = '{}:/'.format(sys.argv[1])
    mountpoint = mountpoint_join(sys.argv[2], 'hot-upgrade')
    os.makedirs(mountpoint, exist_ok=True)

    uninstall_efc(True)
    for d in ['/var/run/eac', '/var/run/efc']:
        try:
            shutil.rmtree(d)
        except FileNotFoundError:
            continue
        except Exception as e:
            fatal_error('remove %s failed for %s' % (d, str(e)))
    for version_i in EFC_VERSIONS.keys():
        for version_j in EFC_VERSIONS.keys():
            if version_compare(version_i, version_j) >= 0:
                continue
            for minv, maxv in HOT_UPGRADE_RULES:
                if version_compare(version_i, minv) >= 0 and version_compare(version_j, maxv) <= 0:
                    support = True
                    break
                else:
                    support = False
            uninstall_efc(True)
            print('hot upgrade from %s to %s' % (version_i, version_j))
            install_efc(version_i)
            i_option = get_efc_option(version_i)
            ret, *_ = execute('mount -t alinas -o {} {} {}'.format(i_option, mountpath, mountpoint), True)
            assert ret == 0
            opid = get_efc_pid(mountpoint, False)
            install_efc(version_j)
            j_option = get_efc_option(version_j)
            ret, *_ = execute('mount -t alinas -o {},upgrade {} {}'.format(j_option, mountpath, mountpoint), True)
            if support:
                assert ret == 0
                npid = get_efc_pid(mountpoint, True)
                os.statvfs(mountpoint)
                assert opid != npid
            else:
                assert ret != 0
                npid = get_efc_pid(mountpoint, True)
                os.statvfs(mountpoint)
                assert opid == npid
            ret, *_ = execute('umount {}'.format(mountpoint), True)
            # assert ret == 0
