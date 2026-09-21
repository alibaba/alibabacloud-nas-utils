import errno
import os
import signal
import shutil
import subprocess
import sys
import time

import pytest

import process_probe


def _write_stat(proc_root, pid, comm='worker', state='S', starttime=456):
    proc_dir = proc_root.mkdir(str(pid))
    tail = [state] + ['0'] * 18 + [str(starttime)]
    proc_dir.join('stat').write('%s (%s) %s\n' % (
        pid, comm, ' '.join(tail)))
    return proc_dir


def test_normalize_deleted_exe_path():
    assert process_probe.normalize_exe_path(
        '/usr/bin/aliyun-alinas-efc (deleted)') == \
        '/usr/bin/aliyun-alinas-efc'


def test_read_proc_stat_handles_parentheses_in_comm(tmpdir):
    _write_stat(tmpdir, 123, comm='worker (copy)', starttime=789)

    assert process_probe.read_proc_stat(123, str(tmpdir)) == (
        'worker (copy)', 'S', 789)


def test_read_process_identity_normalizes_deleted_exe(mocker, tmpdir):
    _write_stat(tmpdir, 123)
    mocker.patch(
        'process_probe.os.readlink',
        return_value='/usr/bin/worker (deleted)',
    )

    identity = process_probe.read_process_identity(123, str(tmpdir))

    assert identity.exe == '/usr/bin/worker'
    assert identity.starttime == 456


def test_read_process_identity_rejects_pid_reuse(mocker):
    mocker.patch(
        'process_probe.read_proc_stat',
        side_effect=[('worker', 'S', 100), ('worker', 'S', 200)],
    )
    mocker.patch('process_probe.read_process_exe', return_value='/usr/bin/worker')

    with pytest.raises(OSError) as error:
        process_probe.read_process_identity(123)

    assert error.value.errno == errno.ESRCH


def test_read_process_identity_allows_state_transition(mocker):
    mocker.patch(
        'process_probe.read_proc_stat',
        side_effect=[('worker', 'R', 100), ('worker', 'S', 100)],
    )
    mocker.patch('process_probe.read_process_exe', return_value='/usr/bin/worker')

    identity = process_probe.read_process_identity(123)

    assert identity.state == 'S'


def test_find_processes_matches_exact_exe_and_skips_zombie(mocker):
    identities = [
        process_probe.ProcessIdentity(10, 'S', 1, 'nas-agent',
                                      '/usr/local/nas-agent/nas-agent'),
        process_probe.ProcessIdentity(11, 'S', 2, 'nas-agent-helper',
                                      '/usr/local/nas-agent/nas-agent-helper'),
        process_probe.ProcessIdentity(12, 'Z', 3, 'nas-agent',
                                      '/usr/local/nas-agent/nas-agent'),
    ]
    mocker.patch('process_probe.iter_process_identities', return_value=identities)

    result = process_probe.find_processes_by_exe(
        ('/usr/local/nas-agent/nas-agent',))

    assert [identity.pid for identity in result] == [10]


def test_find_processes_by_script_matches_only_argv1(mocker):
    identities = [
        process_probe.ProcessIdentity(
            10, 'S', 1, 'python3', '/usr/bin/python3'),
        process_probe.ProcessIdentity(
            11, 'S', 2, 'python3', '/usr/bin/python3'),
    ]
    mocker.patch('process_probe.iter_process_identities', return_value=identities)
    mocker.patch(
        'process_probe._read_process_cmdline',
        side_effect=[
            ['python3', '/usr/bin/watchdog'],
            ['python3', '/opt/process_probe.py', 'kill-script',
             '/usr/bin/watchdog'],
        ],
    )

    result = process_probe.find_processes_by_script(('/usr/bin/watchdog',))

    assert [identity.pid for identity in result] == [10]


def test_exe_probe_and_signal_do_not_read_cmdline(mocker, tmpdir):
    _write_stat(tmpdir, 123)
    mocker.patch('process_probe.os.readlink', return_value='/usr/bin/worker')
    cmdline = mocker.patch(
        'process_probe._read_process_cmdline',
        side_effect=AssertionError('cmdline is unsafe for watchdog probes'),
    )
    kill = mocker.patch('process_probe.os.kill')

    matches = process_probe.find_processes_by_exe(
        ('/usr/bin/worker',), str(tmpdir))
    assert [identity.pid for identity in matches] == [123]
    assert process_probe.kill_processes_by_exe(
        ('/usr/bin/worker',), str(tmpdir)) == 1

    kill.assert_called_once_with(123, signal.SIGKILL)
    cmdline.assert_not_called()


def test_signal_process_revalidates_identity(mocker):
    expected = process_probe.ProcessIdentity(
        123, 'S', 100, 'worker', '/usr/bin/worker')
    changed = expected._replace(starttime=200)
    mocker.patch('process_probe.read_process_identity', return_value=changed)
    kill = mocker.patch('process_probe.os.kill')

    assert process_probe.signal_process_if_same(
        expected, signal.SIGKILL) is False
    kill.assert_not_called()


def test_signal_process_sends_signal_for_same_identity(mocker):
    expected = process_probe.ProcessIdentity(
        123, 'S', 100, 'worker', '/usr/bin/worker')
    mocker.patch('process_probe.read_process_identity', return_value=expected)
    kill = mocker.patch('process_probe.os.kill')

    assert process_probe.signal_process_if_same(
        expected, signal.SIGTERM) is True
    kill.assert_called_once_with(123, signal.SIGTERM)


def test_signal_script_process_revalidates_script(mocker):
    expected = process_probe.ProcessIdentity(
        123, 'S', 100, 'python3', '/usr/bin/python3')
    mocker.patch(
        'process_probe.read_process_identity', return_value=expected)
    mocker.patch(
        'process_probe._read_process_cmdline',
        return_value=['python3', '/usr/bin/other-script'],
    )
    kill = mocker.patch('process_probe.os.kill')

    assert process_probe.signal_script_process_if_same(
        expected, ('/usr/bin/watchdog',)) is False
    kill.assert_not_called()


def test_signal_script_process_sends_signal_for_same_process(mocker):
    expected = process_probe.ProcessIdentity(
        123, 'S', 100, 'python3', '/usr/bin/python3')
    mocker.patch(
        'process_probe.read_process_identity', return_value=expected)
    mocker.patch(
        'process_probe._read_process_cmdline',
        return_value=['python3', '/usr/bin/watchdog'],
    )
    kill = mocker.patch('process_probe.os.kill')

    assert process_probe.signal_script_process_if_same(
        expected, ('/usr/bin/watchdog',), signal.SIGTERM) is True
    kill.assert_called_once_with(123, signal.SIGTERM)


def test_kill_processes_by_exe_revalidates_all_matches(mocker):
    processes = [
        process_probe.ProcessIdentity(
            10, 'S', 100, 'nas-agent', '/usr/local/nas-agent/nas-agent'),
        process_probe.ProcessIdentity(
            11, 'S', 200, 'nas-agent', '/usr/local/nas-agent/nas-agent'),
    ]
    find = mocker.patch(
        'process_probe.find_processes_by_exe', return_value=processes)
    signal_if_same = mocker.patch(
        'process_probe.signal_process_if_same', side_effect=[True, False])

    assert process_probe.kill_processes_by_exe(
        ('/usr/local/nas-agent/nas-agent',), '/mock/proc') == 1
    find.assert_called_once_with(
        ('/usr/local/nas-agent/nas-agent',), '/mock/proc')
    assert signal_if_same.call_args_list == [
        mocker.call(processes[0], signal.SIGKILL, '/mock/proc'),
        mocker.call(processes[1], signal.SIGKILL, '/mock/proc'),
    ]


def test_main_kills_absolute_executable_paths(mocker):
    kill_by_exe = mocker.patch(
        'process_probe.kill_processes_by_exe', return_value=2)

    assert process_probe.main([
        'kill-exe',
        '/usr/local/nas-agent/nas-agent',
        '/usr/bin/another-agent',
    ]) == 0
    kill_by_exe.assert_called_once_with((
        '/usr/local/nas-agent/nas-agent',
        '/usr/bin/another-agent',
    ))


def test_main_kills_script_and_requires_a_match(mocker):
    kill_by_script = mocker.patch(
        'process_probe.kill_processes_by_script', side_effect=[1, 0])

    assert process_probe.main([
        'kill-script', '/usr/bin/aliyun-alinas-mount-watchdog']) == 0
    assert process_probe.main([
        'kill-script', '/usr/bin/aliyun-alinas-mount-watchdog']) == 1


@pytest.mark.parametrize('argv', [
    [],
    ['unknown', '/usr/local/nas-agent/nas-agent'],
    ['kill-exe'],
    ['kill-exe', 'relative/nas-agent'],
])
def test_main_rejects_invalid_arguments(mocker, argv):
    kill_by_exe = mocker.patch('process_probe.kill_processes_by_exe')
    kill_by_script = mocker.patch('process_probe.kill_processes_by_script')

    assert process_probe.main(argv) == 2
    kill_by_exe.assert_not_called()
    kill_by_script.assert_not_called()


def test_kill_processes_by_exe_only_kills_exact_binary(tmpdir):
    target_dir = tmpdir.mkdir('target')
    other_dir = tmpdir.mkdir('other')
    target = str(target_dir.join('nas-agent'))
    other = str(other_dir.join('nas-agent'))
    shutil.copy('/bin/sleep', target)
    shutil.copy('/bin/sleep', other)
    target_proc = subprocess.Popen([target, '60'])
    other_proc = subprocess.Popen([other, '60'])

    try:
        deadline = time.time() + 2
        while time.time() < deadline:
            if any(identity.pid == target_proc.pid for identity in
                   process_probe.find_processes_by_exe((target,))):
                break
            time.sleep(0.01)

        assert process_probe.kill_processes_by_exe((target,)) == 1
        assert target_proc.wait(timeout=2) == -signal.SIGKILL
        assert other_proc.poll() is None
    finally:
        for proc in (target_proc, other_proc):
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def test_kill_processes_by_script_only_kills_exact_argv1(tmpdir):
    target = str(tmpdir.join('watchdog.py'))
    tmpdir.join('watchdog.py').write('import time\ntime.sleep(60)\n')
    target_proc = subprocess.Popen([sys.executable, target])
    other_proc = subprocess.Popen([
        sys.executable,
        '-c',
        'import time; time.sleep(60)',
        target,
    ])

    try:
        deadline = time.time() + 2
        while time.time() < deadline:
            if any(identity.pid == target_proc.pid for identity in
                   process_probe.find_processes_by_script((target,))):
                break
            time.sleep(0.01)

        assert process_probe.kill_processes_by_script((target,)) == 1
        assert target_proc.wait(timeout=2) == -signal.SIGKILL
        assert other_proc.poll() is None
    finally:
        for proc in (target_proc, other_proc):
            if proc.poll() is None:
                proc.kill()
            proc.wait()


def test_process_alive_seconds_uses_starttime(mocker, tmpdir):
    tmpdir.join('uptime').write('100.0 50.0\n')
    mocker.patch('process_probe.os.sysconf', return_value=100)

    assert process_probe.process_alive_seconds(
        123, 5000, str(tmpdir)) == 50
