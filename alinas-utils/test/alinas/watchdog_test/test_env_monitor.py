#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import hashlib
import json
import os
import pytest
import random
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from configparser import ConfigParser
from datetime import datetime
from mock import MagicMock, patch

import watchdog
from watchdog import SafeConfig, EnvMonitor, NAS_AGENT_CONFIG_SECTION


def mock_config():
    parser = ConfigParser()
    parser.add_section(NAS_AGENT_CONFIG_SECTION)
    parser.set(NAS_AGENT_CONFIG_SECTION, 'nas_agent_user', '1241392231042436')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'io_hang_timeout_us', '180000000')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'io_hang_timeout_req_count', '4')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'debug_max_req_count', '64')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'update_mount_entities_interval', '5')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'update_commands_interval', '5')
    parser.set(NAS_AGENT_CONFIG_SECTION, 'upload_mount_info_interval', '5')
    config = SafeConfig(parser, 'mock config', None)
    return config


LOWER_CASE = 1
UPPER_CASE = 2
DIGIT = 4

def random_string(length, type):
    def _random_char(type):
        chars = []
        if type & LOWER_CASE:
            chars.append(chr(random.randint(ord('a'), ord('z'))))
        if type & UPPER_CASE:
            chars.append(chr(random.randint(ord('A'), ord('Z'))))
        if type & DIGIT:
            chars.append(chr(random.randint(ord('0'), ord('9'))))
        return random.sample(chars, 1)[0]

    return ''.join(_random_char(type) for _ in range(length))


class Mount(object):
    def __init__(self, region, fstype, entries):
        self._region = region
        self._fstype = fstype
        self._fsid = random_string(10, LOWER_CASE | DIGIT)
        self._uniqueid = random_string(5, LOWER_CASE | DIGIT)

        self._type = 'alifuse.aliyun-alinas-efc'
        self._uuid = random_string(8, LOWER_CASE | UPPER_CASE | DIGIT)
        self._options = 'rw,nosuid,nodev,relatime,user_id=0,group_id=0,default_permissions,allow_other'
        self._connid = random.randint(50, 100)
        self._pid = random.randint(1000, 10000)
        self._entries = entries

    @property
    def fsid(self):
        return self._fsid

    @property
    def connid(self):
        return self._connid

    @property
    def pid(self):
        return self._pid

    @pid.setter
    def pid(self, value):
        self._pid = value

    @property
    def uuid(self):
        return self._uuid

    def server(self):
        if self._fstype == 'nas':
            return '%s-%s.%s.nas.aliyuncs.com' % (self._fsid, self._uniqueid, self._region)

    def mount_strings(self):
        strings = []
        for mountpath, mountpoint in self._entries:
            strings.append('%s:%s:%s %s alifuse.aliyun-alinas-efc %s 0 0' % (self._uuid, self.server(), mountpath, mountpoint, self._options))
        return strings


class LoggerMocker:
    def __init__(self):
        self._lock = threading.Lock()
        self._logs = [{}]

    def rollover(self):
        self._logs.append({})

    def submit(self, region, record):
        self._lock.acquire()
        if region not in self._logs[-1]:
            self._logs[-1][region] = []
        self._logs[-1][region].append(record)
        self._lock.release()


class TestMocker:
    def __init__(self, region):
        self._open = open
        self._open_mocker = patch('builtins.open', side_effect=self._open_side_effect)
        self._truncate = os.truncate
        self._truncate_mocker = patch('os.truncate', side_effect=self._truncate_side_effect)
        self._os_popen = os.popen
        self._os_popen_mocker = patch('os.popen', side_effect=self._os_popen_side_effect)
        self._proc_popen = subprocess.Popen
        self._proc_popen_mocker = patch('subprocess.Popen', side_effect=self._proc_popen_side_effect)
        self._mkdir = os.makedirs
        self._mkdir_mocker = patch('os.makedirs', side_effect=self._mkdir_side_effect)
        self._mknod = os.mknod
        self._mknod_mocker = patch('os.mknod', side_effect=self._monod_side_effect)

        self._region = region
        self._mounts = []
        self._commands = None
        self._repos = []
        self._old_logger = None
        self._logger = LoggerMocker()

    def _open_side_effect(self, filepath, *args, **kargs):
        fd, file = tempfile.mkstemp(text=True)
        if filepath == '/proc/mounts':
            lines = [
                'sysfs /sys sysfs rw,relatime 0 0',
                'proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0',
                'devtmpfs /dev devtmpfs rw,nosuid,size=7913012k,nr_inodes=1978253,mode=755 0 0',
                'tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0',
                'devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0',
                'tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0',
                '/dev/vda2 / ext4 rw,relatime 0 0',
                'tmpfs /run/user/1378578 tmpfs rw,nosuid,nodev,relatime,size=1585012k,mode=700,uid=1378578,gid=100 0 0',
                'fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0',
                'alifusectl /sys/fs/alifuse/connections alifusectl rw,relatime 0 0',
            ]
            for mount in self._mounts:
                lines.extend(mount.mount_strings())
            os.write(fd, '\n'.join(lines).encode())
            os.close(fd)
            return self._open(file)
        elif filepath == watchdog.NAS_AGENT_LOCAL_COMMANDS_PATH:
            os.write(fd, json.dumps({'commands': self._commands}).encode())
            os.close(fd)
            return self._open(file)
        elif filepath == watchdog.NAS_AGENT_ID_FILE_PATH:
            os.close(fd)
            return self._open(file, 'w')
        elif watchdog.NAS_AGENT_REMOTE_COMMANDS_DIR in filepath:
            filename = filepath.split('/')[-1]
            key = filename[:-5].split('-')[-1]
            for repo in self._repos:
                if repo.region != self._region:
                    continue
                content = repo.get_commands(key)
                os.write(fd, content.encode())
                os.close(fd)
                return self._open(file)
        elif filepath == watchdog.NAS_AGENT_CONF_PATH:
            conf = {
                'config_server_address': 'http://logtail.%s-intranet.log.aliyuncs.com' % self._region,
                'data_server_list': [{
                    'cluster': self._region,
                    'endpoint': '%s-intranet.log.aliyuncs.com' % self._region,
                }],
                "cpu_usage_limit": 0.4,
                "mem_usage_limit": 384,
                "max_bytes_per_sec": 20971520,
                "bytes_per_sec": 1048576,
                "buffer_file_num": 25,
                "buffer_file_size": 20971520,
                "buffer_map_num": 5,
                "streamlog_open": False,
                "streamlog_pool_size_in_mb": 50,
                "streamlog_rcv_size_each_call": 1024,
                "streamlog_formats": [],
                "streamlog_tcp_port": 11111,
            }
            content = json.dumps(conf)
            os.write(fd, content.encode())
            os.close(fd)
            return self._open(file)
        return self._open(filepath, *args, **kargs)

    def _truncate_side_effect(self, filepath, *args, **kargs):
        print('truncate', filepath)

    def _os_popen_side_effect(self, command, *args, **kargs):
        ret = None
        if 'mountinfo' in command:
            for mount in self._mounts:
                if mount.uuid in command:
                    ret = str(mount.connid)
                    break
        if ret is None:
            for mount in self._mounts:
                if mount.uuid in command:
                    ret = str(mount.pid)
        if ret is not None:
            mocker = MagicMock()
            mocker.read.return_value = ret
            return mocker
        print('os popen', command)
        return self._os_popen(command, *args, **kargs)

    def _proc_popen_side_effect(self, command, *args, **kargs):
        ret = None
        if 'curl' in command:
            ret = self._region
        if watchdog.NAS_AGENT_ID_GEN_BIN_NAME in command:
            fsid = command.split()[-1]
            ret = fsid + '-01234567'
        if 'wget' in command:
            for repo in self._repos:
                if repo.region != self._region:
                    continue
                url = command.split('"')[1]
                if repo.url not in url:
                    continue
                file = url.split('/')[-1]
                key = file[:-5].split('-')[-1]
                if repo.get_commands(key):
                    ret = ''
        if ret is not None:
            mocker = MagicMock()
            mocker.communicate.return_value = (ret.encode(), ''.encode())
            mocker.returncode = 0
            return mocker
        print('proc popen', command)
        return self._proc_popen(command, *args, **kargs)

    def _mkdir_side_effect(self, path, *args, **kargs):
        if path in [watchdog.NAS_AGENT_USER_DIR, watchdog.NAS_AGENT_REMOTE_COMMANDS_DIR]:
            return
        print('mkdir', path)

    def _monod_side_effect(self, path, *args, **kargs):
        if watchdog.NAS_AGENT_USER_DIR in path:
            return
        print('monod', path)

    @property
    def logs(self):
        return self._logger._logs

    def __enter__(self):
        self._old_logger = watchdog.NAS_AGENT_LOGGER
        watchdog.NAS_AGENT_LOGGER = self._logger
        self._open_mocker.start()
        self._truncate_mocker.start()
        self._os_popen_mocker.start()
        self._proc_popen_mocker.start()
        self._mkdir_mocker.start()
        self._mknod_mocker.start()
        return self

    def __exit__(self, type, value, trace):
        watchdog.NAS_AGENT_LOGGER = self._old_logger
        self._open_mocker.stop()
        self._truncate_mocker.stop()
        self._os_popen_mocker.stop()
        self._proc_popen_mocker.stop()
        self._mkdir_mocker.stop()
        self._mknod_mocker.stop()

    def add_mount(self, mount):
        self._mounts.append(mount)

    def add_mounts(self, mounts):
        self._mounts.extend(mounts)

    def set_commands(self, commands, repos=[]):
        self._commands = commands
        self._repos = repos


class RemoteRepo:
    def __init__(self, region):
        self.region = region
        self.url = watchdog.NAS_AGENT_REMOTE_REPO_PATTERN % (region, region)
        self.version_commands = None
        self.version = None
        self.host_commands = None
        self.host = None
        self.fs_commands = None
        self.fsid = None
        self._has_error = False

    def inject_error(self):
        self._has_error = True

    def get_commands(self, key):
        commands = None
        if self.version_commands and key == self.version:
            commands = self.version_commands
        if self.host_commands and key == hashlib.md5(self.host.encode()).hexdigest():
            commands = self.host_commands
        if self.fs_commands and key == hashlib.md5(self.fsid.encode()).hexdigest():
            commands = self.fs_commands
        if commands:
            content = json.dumps({'commands': commands})
            if self._has_error:
                content = content.replace('{', '[')
            return content
        return None


def periodic_command(task, interval, version='0.0.1'):
    return {
        'version': version,
        'task': task,
        'interval': interval,
    }


def conditional_command(task, event, version='0.0.1'):
    return {
        'version': version,
        'task': task,
        'event': event,
    }


def traverse_logs(logs, handler):
    for i, logdict in enumerate(logs):
        for region, logarr in logdict.items():
            for log in logarr:
                handler(i, region, log)


def fromisoformat(microtime):
    segments = re.split(' |-|:', microtime)
    year, month, day, hour, minute = [int(s) for s in segments[:-1]]
    seconds = float(segments[-1])
    second = int(seconds)
    microsecond = int((seconds - second) * 1000)
    return datetime(year, month, day, hour, minute, second, microsecond)


def test_execute_command():
    with TestMocker('cn-hangzhou') as mocker:
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test': periodic_command('echo test', 1)
        }
        mocker.set_commands(commands)
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(4)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'] == 'test':
                assert log['test'] == 'test' and region == 'cn-hangzhou'

        traverse_logs(mocker.logs, _check)


def test_periodic_command_pattern():
    with TestMocker('cn-hangzhou') as mocker:
        mounts = [
            Mount('cn-hangzhou', 'nas', [('/', '/mnt')]),
            Mount('cn-hangzhou', 'nas', [('/', '/mnt-2')]),
        ]
        mocker.add_mounts(mounts)
        commands = {
            'test': periodic_command('echo <pid> <uuid> <connid>', 1)
        }
        mocker.set_commands(commands)
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(4)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'] == 'test':
                for mount in mounts:
                    if mount.fsid == log['fsid']:
                        assert log['mountuuid'] == mount.uuid
                        assert log['test'] == '%d %s %d' % (mount.pid, mount.uuid, mount.connid)

        traverse_logs(mocker.logs, _check)


def test_execute_commands():
    with TestMocker('cn-hangzhou') as mocker:
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test-%d' % i: periodic_command('echo test %d' % i, i % 3 + 1) for i in range(500)
        }
        mocker.set_commands(commands)
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(10)
        monitor.stop()

        ''.startswith
        logs = {}
        def _group(idx, region, log):
            if not log['type'].startswith('test'):
                return
            cmd_id = int(log['type'].split('-')[-1])
            if cmd_id not in logs:
                logs[cmd_id] = []
            logs[cmd_id].append((log[log['type']], log['microtime']))

        traverse_logs(mocker.logs, _group)

        for cmd_id, cmdlogs in logs.items():
            last_time = None
            for output, microtime in cmdlogs:
                assert output == 'test %d' % cmd_id
                if last_time is None:
                    last_time = fromisoformat(microtime)
                    continue
                curr_time = fromisoformat(microtime)
                expect_interval = cmd_id % 3 + 1
                assert abs(expect_interval - (curr_time - last_time).total_seconds()) < 1
                last_time = curr_time


def test_pid_changed():
    with TestMocker('cn-hangzhou') as mocker:
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test': conditional_command('echo <opid> <pid> <uuid> <connid>', watchdog.Command.EVENT_PID_CHANGED)
        }
        mocker.set_commands(commands)
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(2)
        opid = mount.pid
        mount.pid = opid + 1
        time.sleep(5)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'] == 'test':
                assert log['fsid'] == mount.fsid
                assert log['mountuuid'] == mount.uuid
                assert log['test'] == '%d %d %s %d' % (opid, opid + 1, mount.uuid, mount.connid)

        traverse_logs(mocker.logs, _check)


def test_command_fail():
    with TestMocker('cn-hangzhou') as mocker:
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test-1': periodic_command('not-found test', 1),
            'test-2': periodic_command('echo 2', 1),
        }
        mocker.set_commands(commands)
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(3)
        monitor.stop()

        success = False
        def _check(idx, region, log):
            nonlocal success
            if log['type'] == 'test-2':
                success = True

        traverse_logs(mocker.logs, _check)
        assert success


def test_command_hang():
    def _timer_side_effect(*args, **kargs):
        ret = MagicMock()
        ret.cancel.return_value = None
        return ret
    with patch('threading.Timer', side_effect=_timer_side_effect) as timer_mocker:
        threading.Timer(1)
        with TestMocker('cn-hangzhou') as mocker:
            mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
            mocker.add_mount(mount)
            commands = {
                'hang': periodic_command('sleep 15', 1),
                'test-2': periodic_command('echo 2', 1),
                'test-3': periodic_command('echo 2', 1),
                'test-4': periodic_command('echo 2', 1),
                'test-5': periodic_command('echo 2', 1),
            }
            mocker.set_commands(commands)
            monitor = watchdog.EnvMonitor(mock_config())
            monitor.start()
            time.sleep(10)
            # ensure the hang task executed only once
            assert monitor._event_waiter.event_count() <= 7
            monitor.stop()

            exe_time = 0

            def _check(idx, region, log):
                nonlocal exe_time
                if log['type'].startswith('test'):
                    exe_time += 1

            traverse_logs(mocker.logs, _check)
            # ensure other task are execut normally
            assert exe_time > 4 * 8


def test_remote_version_commands():
    with TestMocker('cn-hangzhou') as mocker:
        os.makedirs('abcd', exist_ok=True)
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test-1': periodic_command('echo 1', 1),
            'test-2': periodic_command('echo 2', 1),
            'test-3': periodic_command('echo 3', 1),
        }
        repo = RemoteRepo('cn-hangzhou')
        repo.version = watchdog.VERSION
        repo.version_commands = {
            'test-1': periodic_command('echo newer 1', 1, version='0.0.2'),
            'test-2': periodic_command('echo newer 2', 1, version='0.0.1'),
            'test-3': periodic_command('echo newer 3', 1, version='0.0.0'),
        }
        mocker.set_commands(commands, [repo])
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(10)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'] == 'test-1':
                assert log['test-1'] == 'newer 1'
            if log['type'] == 'test-2':
                assert log['test-2'] == '2', log['test-2']
            if log['type'] == 'test-3':
                assert log['test-3'] == '3'

        traverse_logs(mocker.logs, _check)


def test_matched_remote_fs_commands():
    with TestMocker('cn-hangzhou') as mocker:
        mounts = [
            Mount('cn-hangzhou', 'nas', [('/', '/mnt')]),
            Mount('cn-hangzhou', 'nas', [('/', '/mnt-2')]),
        ]
        mocker.add_mounts(mounts)
        commands = {
            'test-1': periodic_command('echo <uuid>', 1),
        }
        repo = RemoteRepo('cn-hangzhou')
        repo.fsid = mounts[0].fsid
        repo.fs_commands = {
            'test-1': periodic_command('echo newer <uuid>', 1, version='0.0.2'),
        }
        mocker.set_commands(commands, [repo])
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(5)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'].startswith('test'):
                assert log[log['type']] == 'newer %s' % log['mountuuid']

        traverse_logs(mocker.logs, _check)


def test_mismatched_remote_fs_commands():
    with TestMocker('cn-hangzhou') as mocker:
        mounts = [
            Mount('cn-hangzhou', 'nas', [('/', '/mnt')]),
            Mount('cn-hangzhou', 'nas', [('/', '/mnt-2')]),
        ]
        mocker.add_mounts(mounts)
        commands = {
            'test-1': periodic_command('echo <uuid>', 1),
        }
        repo = RemoteRepo('cn-hangzhou')
        repo.fsid = mounts[0].fsid + 'a'
        repo.fs_commands = {
            'test-1': periodic_command('echo newer <uuid>', 1, version='0.0.2'),
        }
        mocker.set_commands(commands, [repo])
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(5)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'].startswith('test'):
                assert log[log['type']] == log['mountuuid']

        traverse_logs(mocker.logs, _check)


def test_remote_commands_format_error():
    with TestMocker('cn-hangzhou') as mocker:
        mount = Mount('cn-hangzhou', 'nas', [('/', '/mnt')])
        mocker.add_mount(mount)
        commands = {
            'test-1': periodic_command('echo 1', 1),
        }
        repo = RemoteRepo('cn-hangzhou')
        repo.version_commands = {
            'test-1': periodic_command('echo newer 1', 1, version='0.0.2'),
        }
        repo.inject_error()
        mocker.set_commands(commands, [repo])
        monitor = watchdog.EnvMonitor(mock_config())
        monitor.start()
        time.sleep(5)
        monitor.stop()

        def _check(idx, region, log):
            if log['type'] == 'test-1':
                assert log['test-1'] == '1', log['test-1']

        traverse_logs(mocker.logs, _check)
