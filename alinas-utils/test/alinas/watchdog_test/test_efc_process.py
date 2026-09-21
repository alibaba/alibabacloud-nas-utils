import ctypes
import errno
import fcntl
import logging
import os
import shlex
import signal
import sys
import time
from multiprocessing import Event, Process

import pytest

import efc_process
import watchdog


def make_probe(state, pid=123, proc_state='S', starttime=456,
               lock_path='/tmp/uuid.efc.lock', dev=1, inode=2,
               pidfile_pid=None, comm='aliyun-alinas-e'):
    if pidfile_pid is None:
        pidfile_pid = pid
    return efc_process.EfcProbeResult(
        state=state,
        owner_pid=pid,
        proc_state=proc_state,
        proc_starttime=starttime,
        proc_comm=comm,
        lock_path=lock_path,
        lock_dev=dev,
        lock_inode=inode,
        pidfile_pid=pidfile_pid,
        pidfile_match=bool(pid and pid == pidfile_pid),
        reason='test',
    )


class FakeClock(object):
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def clear_watchdog_efc_state():
    watchdog.zombie_detection_times.clear()
    watchdog.restart_attempt_times.clear()
    watchdog._restart_log_contexts.clear()
    watchdog.restart_in_progress.clear()
    yield
    watchdog.zombie_detection_times.clear()
    watchdog.restart_attempt_times.clear()
    watchdog._restart_log_contexts.clear()
    watchdog.restart_in_progress.clear()


@pytest.fixture(autouse=True)
def efc_exe_mock(mocker):
    return mocker.patch(
        'efc_process.process_probe.read_process_exe',
        return_value='/usr/bin/aliyun-alinas-efc',
    )


def prepare_files(tmpdir, mount_uuid='uuid', pid=123):
    lock_path = str(tmpdir.join('%s.efc.lock' % mount_uuid))
    pid_path = str(tmpdir.join('%s.efc.pid' % mount_uuid))
    with open(lock_path, 'w'):
        pass
    with open(pid_path, 'w') as pid_file:
        pid_file.write(str(pid))
    return lock_path, pid_path


def test_probe_dead_when_lock_missing(tmpdir):
    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))
    assert result.state == efc_process.EFC_DEAD
    assert result.owner_pid == 0


def test_probe_invalid_uuid_is_unknown(tmpdir):
    result = efc_process.probe_efc('../uuid', str(tmpdir), str(tmpdir))
    assert result.state == efc_process.EFC_UNKNOWN
    assert 'invalid' in result.reason


def test_readiness_retries_dead_and_unknown_until_running(mocker):
    dead = make_probe(efc_process.EFC_DEAD, pid=0, starttime=0,
                      dev=0, inode=0, pidfile_pid=0, comm='')
    unknown = make_probe(efc_process.EFC_UNKNOWN)
    running = make_probe(efc_process.EFC_RUNNING)
    probe = mocker.Mock(side_effect=[dead, unknown, running])
    clock = FakeClock()

    result = efc_process.wait_efc_readiness(
        'uuid', timeout=3, probe_fn=probe,
        monotonic_fn=clock.monotonic, sleep_fn=clock.sleep)

    assert result is running
    assert probe.call_count == 3
    assert clock.sleeps == [0.1, 0.1]


def test_upgrade_readiness_requires_owner_transition(mocker):
    old_owner = make_probe(efc_process.EFC_RUNNING)
    new_owner = make_probe(
        efc_process.EFC_RUNNING, pid=124, starttime=457, inode=3)
    probe = mocker.Mock(side_effect=[old_owner, old_owner, new_owner])
    clock = FakeClock()

    result = efc_process.wait_efc_readiness(
        'uuid', timeout=3, previous_probe=old_owner, probe_fn=probe,
        monotonic_fn=clock.monotonic, sleep_fn=clock.sleep)

    assert result is new_owner
    assert probe.call_count == 3


def test_readiness_stops_on_lock_conflict(mocker):
    conflict = make_probe(efc_process.EFC_LOCK_CONFLICT)
    probe = mocker.Mock(return_value=conflict)
    clock = FakeClock()

    result = efc_process.wait_efc_readiness(
        'uuid', timeout=3, probe_fn=probe,
        monotonic_fn=clock.monotonic, sleep_fn=clock.sleep)

    assert result is conflict
    assert clock.sleeps == []


def test_readiness_returns_last_unknown_at_timeout(mocker):
    unknown = make_probe(efc_process.EFC_UNKNOWN)
    probe = mocker.Mock(return_value=unknown)
    clock = FakeClock()

    result = efc_process.wait_efc_readiness(
        'uuid', timeout=0.25, probe_fn=probe,
        monotonic_fn=clock.monotonic, sleep_fn=clock.sleep)

    assert result is unknown
    assert clock.now == pytest.approx(0.25)
    assert probe.call_count == 4


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='requires O_NOFOLLOW')
def test_pidfile_symlink_is_not_followed(tmpdir):
    target = tmpdir.join('target')
    target.write('123')
    pid_path = str(tmpdir.join('uuid.efc.pid'))
    os.symlink(str(target), pid_path)

    assert efc_process.read_pidfile(pid_path) == 0


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='requires O_NOFOLLOW')
def test_probe_lock_symlink_is_unknown(tmpdir):
    target = tmpdir.join('target')
    target.write('')
    os.symlink(str(target), str(tmpdir.join('uuid.efc.lock')))

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert 'open lock failed' in result.reason


def test_probe_dead_when_lock_is_unlocked(mocker, tmpdir):
    prepare_files(tmpdir)
    query = mocker.patch(
        'efc_process.query_lock_owner',
        return_value=(fcntl.F_UNLCK, 0),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_DEAD
    assert result.pidfile_pid == 123
    query.assert_called_once()


def test_probe_is_unknown_when_lock_query_fails(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=OSError(errno.EIO, 'query failed'),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert 'F_GETLK failed' in result.reason


def test_probe_running_with_matching_pidfile(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_RUNNING
    assert result.owner_pid == 123
    assert result.proc_starttime == 456
    assert result.pidfile_match is True


def test_probe_uses_legacy_eac_workspace_symlink(mocker, tmpdir):
    legacy_workspace = tmpdir.mkdir('eac')
    workspace = str(tmpdir.join('efc'))
    os.symlink(str(legacy_workspace), workspace)
    prepare_files(legacy_workspace)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )

    result = efc_process.probe_efc('uuid', workspace, str(tmpdir))

    assert result.state == efc_process.EFC_RUNNING
    assert result.owner_pid == 123
    assert result.pidfile_match is True


def test_probe_running_without_pidfile_for_efc_v1_9(mocker, tmpdir):
    # The validated EFC v1.9 package uses efc.lock but has no efc.pid.
    tmpdir.join('uuid.efc.lock').write('')
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_RUNNING
    assert result.owner_pid == 123
    assert result.pidfile_pid == 0
    assert result.pidfile_match is False
    assert 'missing or stale' in result.reason


def test_probe_running_with_stale_pidfile(mocker, tmpdir):
    prepare_files(tmpdir, pid=999)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_RUNNING
    assert result.pidfile_match is False
    assert 'stale' in result.reason


def test_probe_rejects_foreign_lock_owner(mocker, tmpdir, efc_exe_mock):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('temporary-tool', 'S', 456),
    )
    efc_exe_mock.return_value = '/usr/bin/temporary-tool'

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_LOCK_CONFLICT


def test_probe_accepts_legacy_eac_executable(
        mocker, tmpdir, efc_exe_mock):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )
    efc_exe_mock.return_value = '/usr/bin/aliyun-alinas-eac'

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_RUNNING


def test_probe_zombie_requires_pidfile_match(mocker, tmpdir):
    prepare_files(tmpdir, pid=999)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'Z', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert result.pidfile_match is False


def test_probe_zombie_without_pidfile_for_efc_v1_9(mocker, tmpdir):
    # Without a pidfile, legacy EFC zombies cannot be detached safely.
    tmpdir.join('uuid.efc.lock').write('')
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'Z', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert result.owner_pid == 123
    assert result.pidfile_pid == 0
    assert result.pidfile_match is False
    assert 'pidfile' in result.reason


def test_probe_reports_matching_zombie_owner(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 123)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'Z', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_ZOMBIE_LOCKED
    assert result.pidfile_match is True


def test_probe_is_unknown_when_owner_proc_disappears(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        return_value=(fcntl.F_WRLCK, 123),
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        side_effect=OSError(errno.ENOENT, 'gone'),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert 'stat failed' in result.reason


def test_probe_detects_inode_change(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        return_value=(fcntl.F_UNLCK, 0),
    )
    mocker.patch('efc_process._same_path_inode', return_value=False)

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert 'inode changed' in result.reason


def test_probe_detects_owner_change(mocker, tmpdir):
    prepare_files(tmpdir)
    mocker.patch(
        'efc_process.query_lock_owner',
        side_effect=[(fcntl.F_WRLCK, 123), (fcntl.F_WRLCK, 124)],
    )
    mocker.patch(
        'efc_process.read_proc_stat',
        return_value=('aliyun-alinas-e', 'S', 456),
    )

    result = efc_process.probe_efc('uuid', str(tmpdir), str(tmpdir))

    assert result.state == efc_process.EFC_UNKNOWN
    assert 'owner changed' in result.reason


def test_zombie_waits_then_detaches(mocker, caplog):
    probe = make_probe(efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z')
    detach = mocker.patch(
        'watchdog.efc_process.detach_zombie_lock',
        return_value=(efc_process.DETACH_DETACHED, probe, 'quarantine'),
    )

    assert watchdog.try_remove_efc_lock_when_zombie(
        'uuid', probe, now=100) == efc_process.DETACH_WAIT
    assert watchdog.try_remove_efc_lock_when_zombie(
        'uuid', probe, now=159) == efc_process.DETACH_WAIT
    assert watchdog.try_remove_efc_lock_when_zombie(
        'uuid', probe, now=160) == efc_process.DETACH_DETACHED
    detach.assert_called_once_with('uuid', probe, watchdog.EFC_WORKSPACE_DIR)
    assert not watchdog.zombie_detection_times
    assert [(r.levelno, r.getMessage()) for r in caplog.records[:3]] == [
        (logging.WARNING, 'uuid:uuid pid:123 zombie:True first zombie, inode:2'),
        (logging.WARNING, 'uuid:uuid pid:123 zombie time: 59.0s, inode:2'),
        (logging.WARNING, 'uuid:uuid pid:123 zombie time: 60.0s try remove lock, inode:2'),
    ]


def test_zombie_identity_change_restarts_timer(mocker):
    first = make_probe(efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z', inode=2)
    changed = make_probe(efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z', inode=3)
    detach = mocker.patch('watchdog.efc_process.detach_zombie_lock')

    assert watchdog.try_remove_efc_lock_when_zombie(
        'uuid', first, now=100) == efc_process.DETACH_WAIT
    assert watchdog.try_remove_efc_lock_when_zombie(
        'uuid', changed, now=200) == efc_process.DETACH_WAIT
    detach.assert_not_called()


def test_detach_zombie_lock_revalidates_owner(mocker, tmpdir):
    lock_path, _ = prepare_files(tmpdir)
    lock_stat = os.stat(lock_path)
    expected = make_probe(
        efc_process.EFC_ZOMBIE_LOCKED,
        proc_state='Z',
        lock_path=lock_path,
        dev=lock_stat.st_dev,
        inode=lock_stat.st_ino,
    )
    running = expected._replace(state=efc_process.EFC_RUNNING, proc_state='S')
    mocker.patch('efc_process.probe_efc', return_value=running)
    rename = mocker.patch('os.rename')

    result, _, _ = efc_process.detach_zombie_lock(
        'uuid', expected, str(tmpdir), str(tmpdir))

    assert result == efc_process.DETACH_ABORTED
    rename.assert_not_called()


def test_detach_reports_already_released_lock(mocker):
    expected = make_probe(efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z')
    dead = make_probe(
        efc_process.EFC_DEAD, pid=0, starttime=0, dev=0, inode=0,
        pidfile_pid=0, comm='')
    mocker.patch('efc_process.probe_efc', return_value=dead)

    result, _, _ = efc_process.detach_zombie_lock('uuid', expected)

    assert result == efc_process.DETACH_RELEASED


def test_detach_rejects_changed_zombie_identity(mocker):
    expected = make_probe(
        efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z', inode=2)
    changed = make_probe(
        efc_process.EFC_ZOMBIE_LOCKED, proc_state='Z', inode=3)
    mocker.patch('efc_process.probe_efc', return_value=changed)

    result, _, _ = efc_process.detach_zombie_lock('uuid', expected)

    assert result == efc_process.DETACH_ABORTED


def test_detach_zombie_lock_quarantines_verified_inode(mocker, tmpdir):
    lock_path, _ = prepare_files(tmpdir)
    lock_stat = os.stat(lock_path)
    expected = make_probe(
        efc_process.EFC_ZOMBIE_LOCKED,
        proc_state='Z',
        lock_path=lock_path,
        dev=lock_stat.st_dev,
        inode=lock_stat.st_ino,
    )
    mocker.patch('efc_process.probe_efc', return_value=expected)

    result, _, quarantine = efc_process.detach_zombie_lock(
        'uuid', expected, str(tmpdir), str(tmpdir))

    assert result == efc_process.DETACH_DETACHED
    assert not os.path.exists(lock_path)
    assert os.path.exists(quarantine)
    assert os.stat(quarantine).st_ino == lock_stat.st_ino


def test_detach_restores_path_if_renamed_inode_does_not_match(mocker, tmpdir):
    lock_path, _ = prepare_files(tmpdir)
    lock_stat = os.stat(lock_path)
    expected = make_probe(
        efc_process.EFC_ZOMBIE_LOCKED,
        proc_state='Z',
        lock_path=lock_path,
        dev=lock_stat.st_dev,
        inode=lock_stat.st_ino,
    )
    mocker.patch('efc_process.probe_efc', return_value=expected)
    real_lstat = os.lstat

    def mismatched_quarantine_stat(path):
        if '.zombie.' in path:
            try:
                real_lstat(lock_path)
            except OSError:
                return MagicStat(lock_stat.st_dev, lock_stat.st_ino + 1)
        return real_lstat(path)

    mocker.patch(
        'efc_process.os.lstat', side_effect=mismatched_quarantine_stat,
    )

    result, _, detail = efc_process.detach_zombie_lock(
        'uuid', expected, str(tmpdir), str(tmpdir))

    assert result == efc_process.DETACH_ERROR
    assert os.path.exists(lock_path)
    assert 'restored' in detail


def test_restart_rechecks_and_verifies_new_owner(mocker):
    dead = make_probe(
        efc_process.EFC_DEAD,
        pid=0,
        starttime=0,
        dev=0,
        inode=0,
        pidfile_pid=0,
        comm='',
    )
    running = make_probe(efc_process.EFC_RUNNING)
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        side_effect=[dead, running],
    )
    add_cgroup = mocker.patch('watchdog.add_cgroup_limit')
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[
        watchdog.Mount('uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')])
    runner = mocker.Mock(return_value=(0, '', ''))
    state = watchdog.UnasState(
        'uuid', '/mnt', 'server:/', 'mount-cmd', 'mount-key', '', True)

    assert watchdog.restart_unas_process(
        state, expected_probe=dead, runner=runner, now=100) is True
    runner.assert_called_once_with('mount-cmd', watchdog.UNAS_RESTART_TIMEOUT)
    add_cgroup.assert_called_once_with('mount-cmd', 'uuid', efc_pid=123)


def test_restart_is_cancelled_when_owner_appears(mocker):
    running = make_probe(efc_process.EFC_RUNNING)
    mocker.patch('watchdog.efc_process.probe_efc', return_value=running)
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[
        watchdog.Mount('uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')])
    runner = mocker.Mock()
    state = watchdog.UnasState(
        'uuid', '/mnt', 'server:/', 'mount-cmd', 'mount-key', '', True)

    assert watchdog.restart_unas_process(state, runner=runner, now=100) is False
    runner.assert_not_called()


@pytest.mark.parametrize('mount_server', [None, 'other-uuid:server:/', 'uuid:other-server:/'])
def test_restart_is_cancelled_when_mount_disappears(mocker, mount_server):
    probe = mocker.patch('watchdog.efc_process.probe_efc')
    mounts = [] if mount_server is None else [watchdog.Mount(
        mount_server, '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')]
    mocker.patch('watchdog.get_current_unas_mounts', return_value=mounts)
    runner = mocker.Mock()
    state = watchdog.UnasState(
        'uuid', '/mnt', 'server:/', 'mount-cmd', 'mount-key', '', True)

    assert watchdog.restart_unas_process(
        state, runner=runner, now=100) is False

    probe.assert_not_called()
    runner.assert_not_called()


def test_restart_requires_running_owner_after_command(mocker):
    dead = make_probe(
        efc_process.EFC_DEAD, pid=0, starttime=0, dev=0, inode=0,
        pidfile_pid=0, comm='')
    probe = mocker.patch(
        'watchdog.efc_process.probe_efc', return_value=dead)
    readiness = mocker.patch(
        'watchdog.efc_process.wait_efc_readiness', return_value=dead)
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[
        watchdog.Mount('uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')])
    runner = mocker.Mock(return_value=(0, '', ''))
    state = watchdog.UnasState(
        'uuid', '/mnt', 'server:/', 'mount-cmd', 'mount-key', '', True)

    assert watchdog.restart_unas_process(
        state, expected_probe=dead, runner=runner, now=100) is False
    assert watchdog.restart_unas_process(
        state, expected_probe=dead, runner=runner, now=102) is False
    runner.assert_called_once()
    assert probe.call_count == 2
    readiness.assert_not_called()


def test_restart_runner_has_hard_timeout(tmpdir):
    started = time.monotonic()
    return_code, _, error = watchdog._run_restart_command(
        'sleep 5', timeout=0.1, temp_dir=str(tmpdir))
    elapsed = time.monotonic() - started

    assert return_code == -errno.ETIMEDOUT
    assert elapsed < 2
    assert 'timed out' in error


def test_process_alive_seconds_uses_proc_starttime(mocker, tmpdir):
    tmpdir.join('uptime').write('100.0 50.0\n')
    probe = make_probe(
        efc_process.EFC_RUNNING, starttime=5000)
    mocker.patch('efc_process.process_probe.os.sysconf', return_value=100)

    assert efc_process.process_alive_seconds(probe, str(tmpdir)) == 50


def test_kill_process_revalidates_lock_owner(mocker, caplog):
    running = make_probe(efc_process.EFC_RUNNING)
    probe = mocker.patch(
        'watchdog.efc_process.probe_efc',
        side_effect=[running, running],
    )
    mocker.patch('watchdog.efc_process.process_alive_seconds', return_value=60)
    kill = mocker.patch('watchdog.os.kill')

    assert watchdog.kill_process_uuid('uuid', min_alive_sec=30) is True

    assert probe.call_count == 2
    kill.assert_called_once_with(running.owner_pid, signal.SIGKILL)
    assert [(r.levelno, r.getMessage()) for r in caplog.records
            if r.getMessage().startswith('eac process killed ')] == [(
                logging.ERROR, 'eac process killed uuid:uuid pid: 123')]


def test_kill_process_skips_changed_lock_owner(mocker):
    running = make_probe(efc_process.EFC_RUNNING)
    changed = running._replace(owner_pid=124, proc_starttime=789)
    mocker.patch(
        'watchdog.efc_process.probe_efc',
        side_effect=[running, changed],
    )
    mocker.patch('watchdog.efc_process.process_alive_seconds', return_value=60)
    kill = mocker.patch('watchdog.os.kill')

    assert watchdog.kill_process_uuid('uuid') is False

    kill.assert_not_called()


@pytest.mark.parametrize('returncode', [0, 7])
def test_real_launcher_with_crashed_lock_owner_emits_failure_log(mocker, tmpdir, caplog, returncode):
    """A launcher can return zero after its real child acquired a lock and died."""
    lock_path = str(tmpdir.join('uuid.efc.lock'))
    script = (
        'import fcntl, os, signal\n'
        'pid = os.fork()\n'
        'if pid == 0:\n'
        '    fd = os.open(%r, os.O_CREAT | os.O_RDWR, 0o600)\n'
        '    fcntl.lockf(fd, fcntl.LOCK_EX)\n'
        '    os.kill(os.getpid(), signal.SIGKILL)\n'
        'os.waitpid(pid, 0)\n'
        'raise SystemExit(%d)\n'
    ) % (lock_path, returncode)
    command = '%s -c %s' % (shlex.quote(sys.executable), shlex.quote(script))
    state = watchdog.UnasState('uuid', '/mnt', 'server:/', command, 'uuid.lock', '', True)
    mocker.patch('watchdog.EFC_WORKSPACE_DIR', str(tmpdir))
    mocker.patch('watchdog.get_current_unas_mounts', return_value=[watchdog.Mount(
        'uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')])
    cgroup = mocker.patch('watchdog.add_cgroup_limit')
    wait = mocker.patch('watchdog.efc_process.wait_efc_readiness')

    for attempt in range(1, 4):
        assert watchdog.restart_unas_process(state, now=100 + (attempt - 1) * 5) is False
        assert efc_process.probe_efc('uuid', str(tmpdir)).state == efc_process.EFC_DEAD
        errors = [r for r in caplog.records if r.getMessage().startswith('Failed to remount ')]
        assert len(errors) == (attempt if returncode else max(0, attempt - 2))
    assert errors[-1].levelno == logging.ERROR
    assert 'returncode=%d, stderr=""' % returncode in errors[-1].getMessage()
    wait.assert_not_called()
    cgroup.assert_not_called()


def _real_lock_holder(lock_path, pid_path, ready, stop):
    libc = ctypes.CDLL(None)
    libc.prctl(15, ctypes.c_char_p(b'aliyun-alinas-e'), 0, 0, 0)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with open(pid_path, 'w') as pid_file:
        pid_file.write(str(os.getpid()))
    ready.set()
    stop.wait(10)
    os.close(fd)


class MagicStat(object):
    def __init__(self, dev, inode):
        self.st_dev = dev
        self.st_ino = inode


def _write_fake_proc_stat(proc_root, pid, state, comm='aliyun-alinas-e',
                          starttime=456):
    pid_dir = proc_root.mkdir(str(pid))
    fields = [state] + ['0'] * 18 + [str(starttime)]
    pid_dir.join('stat').write(
        '%s (%s) %s\n' % (pid, comm, ' '.join(fields)))


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='requires Linux')
@pytest.mark.parametrize(
    'proc_state,expected_state',
    [
        ('D', efc_process.EFC_RUNNING),
        ('Z', efc_process.EFC_ZOMBIE_LOCKED),
    ],
)
def test_probe_real_lock_with_simulated_proc_state(
        tmpdir, proc_state, expected_state):
    lock_path = str(tmpdir.join('uuid.efc.lock'))
    pid_path = str(tmpdir.join('uuid.efc.pid'))
    ready = Event()
    stop = Event()
    process = Process(
        target=_real_lock_holder,
        args=(lock_path, pid_path, ready, stop),
    )
    process.start()
    try:
        assert ready.wait(5)
        proc_root = tmpdir.mkdir('proc')
        _write_fake_proc_stat(proc_root, process.pid, proc_state)
        result = efc_process.probe_efc(
            'uuid', str(tmpdir), str(proc_root))
        assert result.state == expected_state
        assert result.owner_pid == process.pid
    finally:
        stop.set()
        process.join(5)
        if process.is_alive():
            os.kill(process.pid, signal.SIGKILL)
            process.join(5)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='requires Linux')
def test_detach_simulated_zombie_real_lock_allows_new_owner(tmpdir):
    lock_path = str(tmpdir.join('uuid.efc.lock'))
    pid_path = str(tmpdir.join('uuid.efc.pid'))
    ready = Event()
    stop = Event()
    process = Process(
        target=_real_lock_holder,
        args=(lock_path, pid_path, ready, stop),
    )
    process.start()
    new_fd = -1
    try:
        assert ready.wait(5)
        proc_root = tmpdir.mkdir('proc')
        _write_fake_proc_stat(proc_root, process.pid, 'Z')
        expected = efc_process.probe_efc(
            'uuid', str(tmpdir), str(proc_root))
        assert expected.state == efc_process.EFC_ZOMBIE_LOCKED

        result, _, quarantine = efc_process.detach_zombie_lock(
            'uuid', expected, str(tmpdir), str(proc_root))
        assert result == efc_process.DETACH_DETACHED
        assert os.path.exists(quarantine)
        assert not os.path.exists(lock_path)

        new_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.lockf(new_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert os.stat(lock_path).st_ino != os.stat(quarantine).st_ino
    finally:
        if new_fd >= 0:
            os.close(new_fd)
        stop.set()
        process.join(5)
        if process.is_alive():
            os.kill(process.pid, signal.SIGKILL)
            process.join(5)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='requires Linux /proc')
def test_probe_with_real_posix_lock_owner(tmpdir):
    lock_path = str(tmpdir.join('uuid.efc.lock'))
    pid_path = str(tmpdir.join('uuid.efc.pid'))
    ready = Event()
    stop = Event()
    process = Process(
        target=_real_lock_holder,
        args=(lock_path, pid_path, ready, stop),
    )
    process.start()
    try:
        assert ready.wait(5)
        result = efc_process.probe_efc('uuid', str(tmpdir), '/proc')
        assert result.state == efc_process.EFC_RUNNING
        assert result.owner_pid == process.pid
        assert result.pidfile_match is True
    finally:
        stop.set()
        process.join(5)
        if process.is_alive():
            os.kill(process.pid, signal.SIGKILL)
            process.join(5)

    result = efc_process.probe_efc('uuid', str(tmpdir), '/proc')
    assert result.state == efc_process.EFC_DEAD
