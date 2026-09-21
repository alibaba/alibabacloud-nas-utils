"""Watchdog confirms delayed EFC starts across scans, without readiness sleeps."""

from types import SimpleNamespace
import logging

import pytest

import efc_process
import watchdog


def probe(state, pid=123):
    return efc_process.EfcProbeResult(
        state, pid, 'S', 456, 'aliyun-alinas-e',
        '%s/uuid.efc.lock' % watchdog.EFC_WORKSPACE_DIR,
        1, 2, pid, True, 'test')


@pytest.fixture
def recovery(mocker, tmpdir):
    host_sidecar_path = '%s/sidecar_exit' % watchdog.EFC_WORKSPACE_DIR
    workspace = tmpdir.mkdir('efc-workspace')
    # Never let a real host's sidecar_exit or lock files select a UT branch.
    mocker.patch('watchdog.EFC_WORKSPACE_DIR', str(workspace))
    watchdog.restart_attempt_times.clear()
    watchdog._restart_log_contexts.clear()
    watchdog.restart_in_progress.clear()
    watchdog.zombie_detection_times.clear()
    state = watchdog.UnasState(
        'uuid', '/mnt', 'server:/', 'mount-cmd', 'uuid.lock', '', True)
    mounts = [watchdog.Mount(
        'uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')]
    wd = mocker.Mock()
    wd.load_state_file.side_effect = lambda *a: dict(state._asdict())
    clock = SimpleNamespace(now=100.0)
    mocker.patch('watchdog.time.monotonic', side_effect=lambda: clock.now)
    sleep = mocker.patch('watchdog.time.sleep')
    wait = mocker.patch('watchdog.efc_process.wait_efc_readiness')
    current_mounts = mocker.patch(
        'watchdog.get_current_unas_mounts', return_value=mounts)
    mocker.patch('watchdog.get_files_with_prefix', side_effect=lambda d, p: (
        {'uuid': 'efc-uuid'} if p == 'efc-' else {}))
    mocker.patch('watchdog.lock_state_file')
    mocker.patch('watchdog.skip_check_unas_mounts', return_value=False)
    mocker.patch('watchdog.schedule_clean_up_mount_files')
    mocker.patch('watchdog.update_monitor_metrics')
    mocker.patch('watchdog.check_unas_process_mem')
    rewrite = mocker.patch('watchdog.rewrite_state_file')
    runner = mocker.patch('watchdog._run_restart_command', return_value=(0, '', ''))
    owner = mocker.patch('watchdog.efc_process.probe_efc', return_value=probe(efc_process.EFC_DEAD))
    cgroup = mocker.patch('watchdog.add_cgroup_limit')
    try:
        yield SimpleNamespace(
            state=state, wd=wd, clock=clock, sleep=sleep, wait=wait,
            mounts=current_mounts, runner=runner, probe=owner,
            cgroup=cgroup, rewrite=rewrite, workspace=workspace,
            host_sidecar_path=host_sidecar_path)
    finally:
        wait.assert_not_called()
        sleep.assert_not_called()
        watchdog.restart_attempt_times.clear()
        watchdog._restart_log_contexts.clear()
        watchdog.restart_in_progress.clear()
        watchdog.zombie_detection_times.clear()


@pytest.mark.parametrize('returncode', [0, 1])
@pytest.mark.parametrize('post_state', [
    efc_process.EFC_RUNNING, efc_process.EFC_DEAD, efc_process.EFC_UNKNOWN,
    efc_process.EFC_ZOMBIE_LOCKED, efc_process.EFC_LOCK_CONFLICT,
])
def test_restart_checks_once_regardless_of_command_result(recovery, returncode, post_state):
    r = recovery
    r.runner.return_value = (returncode, '', 'test')
    r.probe.side_effect = [probe(efc_process.EFC_DEAD), probe(post_state)]

    assert watchdog.restart_unas_process(r.state) is (post_state == efc_process.EFC_RUNNING)
    assert r.probe.call_count == 2  # final pre-start check and one post-start check
    assert r.runner.call_count == 1
    if post_state == efc_process.EFC_RUNNING:
        assert 'uuid' not in watchdog.restart_attempt_times
        r.cgroup.assert_called_once_with('mount-cmd', 'uuid', efc_pid=123)
    else:
        assert watchdog.restart_attempt_times['uuid'] == 100
        r.cgroup.assert_not_called()


@pytest.mark.parametrize('returncode', [0, 1])
def test_later_scan_completes_restart_once(recovery, returncode):
    r = recovery
    r.runner.return_value = (returncode, '', '')
    assert watchdog.restart_unas_process(r.state) is False
    r.probe.return_value = probe(efc_process.EFC_RUNNING, pid=456)
    r.clock.now = 101

    watchdog.check_unas_mounts(r.wd)
    watchdog.check_unas_mounts(r.wd)

    assert r.runner.call_count == 1
    r.cgroup.assert_called_once_with('mount-cmd', 'uuid', efc_pid=456)
    assert 'uuid' not in watchdog.restart_attempt_times
    assert 'uuid' not in watchdog._restart_log_contexts


def test_dead_scans_do_not_retry_until_interval_expires(recovery):
    r = recovery
    assert watchdog.restart_unas_process(r.state) is False
    for now in (101, 102, 103, 104.9):
        r.clock.now = now
        watchdog.check_unas_mounts(r.wd)
        assert r.runner.call_count == 1

    r.clock.now = 105
    watchdog.check_unas_mounts(r.wd)
    assert r.runner.call_count == 2
    assert watchdog.restart_attempt_times['uuid'] == 105


def test_retry_interval_starts_when_command_finishes(recovery):
    r = recovery

    def command(*args):
        r.clock.now = 120
        return 0, '', ''

    r.runner.side_effect = command
    assert watchdog.restart_unas_process(r.state) is False
    assert watchdog.restart_attempt_times['uuid'] == 120
    r.clock.now = 124
    watchdog.check_unas_mounts(r.wd)
    assert r.runner.call_count == 1


@pytest.mark.parametrize('state', [efc_process.EFC_UNKNOWN, efc_process.EFC_LOCK_CONFLICT])
def test_uncertain_scan_never_restarts_after_interval(recovery, state):
    r = recovery
    watchdog.restart_unas_process(r.state)
    r.clock.now = 200
    r.probe.return_value = probe(state)
    watchdog.check_unas_mounts(r.wd)
    assert r.runner.call_count == 1
    r.cgroup.assert_not_called()


@pytest.mark.parametrize('owner_state', [efc_process.EFC_RUNNING, efc_process.EFC_DEAD])
def test_unmounted_attempt_is_cleared_without_completion_or_restart(recovery, owner_state):
    r = recovery
    watchdog.restart_unas_process(r.state)
    r.mounts.return_value = []
    r.probe.return_value = probe(owner_state)
    r.clock.now = 200

    watchdog.check_unas_mounts(r.wd)

    assert 'uuid' not in watchdog.restart_attempt_times
    assert r.runner.call_count == 1
    r.cgroup.assert_not_called()
    r.rewrite.assert_called_once()  # existing unmount grace bookkeeping


@pytest.mark.parametrize('mount_uuid', ['uuid', 'bindroot-uuid'])
def test_restart_rechecks_real_mount_records(recovery, mount_uuid):
    r = recovery
    mountpoint = watchdog.BIND_ROOT_DIR + '/' + mount_uuid if mount_uuid.startswith('bindroot-') else '/mnt'
    state = r.state._replace(mountuuid=mount_uuid, mountpoint=mountpoint)
    r.mounts.return_value = [watchdog.Mount(
        mount_uuid + ':server:/', mountpoint, 'fuse.aliyun-alinas-efc', '', '0', '0')]
    assert watchdog.restart_unas_process(state) is False
    assert r.runner.call_count == 1

    r.clock.now = 105
    r.mounts.return_value = []
    assert watchdog.restart_unas_process(state) is False
    assert r.runner.call_count == 1
    assert mount_uuid not in watchdog.restart_attempt_times


def test_owner_appearing_before_retry_cancels_start(recovery):
    r = recovery
    watchdog.restart_unas_process(r.state)
    r.clock.now = 105
    r.probe.return_value = probe(efc_process.EFC_RUNNING)
    assert watchdog.restart_unas_process(r.state) is False
    assert r.runner.call_count == 1


@pytest.mark.parametrize('returncode', [0, 1])
def test_100_unready_restarts_do_not_accumulate_waits(recovery, returncode):
    r = recovery
    r.runner.return_value = (returncode, '', '')
    for index in range(100):
        mount_uuid = 'uuid-%d' % index
        state = r.state._replace(mountuuid=mount_uuid)
        r.mounts.return_value = [watchdog.Mount(
            mount_uuid + ':server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')]
        assert watchdog.restart_unas_process(state) is False

    assert r.runner.call_count == 100
    assert r.probe.call_count == 200
    assert len(watchdog.restart_attempt_times) == 100
    assert all(context['unconfirmed_attempts'] == 1
               for context in watchdog._restart_log_contexts.values())
    assert r.clock.now == 100


def messages(caplog, prefix):
    return [(record.levelno, record.getMessage()) for record in caplog.records
            if record.getMessage().startswith(prefix)]


@pytest.mark.parametrize('returncode', [0, 1])
@pytest.mark.parametrize('delayed', [False, True])
def test_success_log_preserves_legacy_case_fields_and_actual_command(
        recovery, mocker, caplog, returncode, delayed):
    r = recovery
    caplog.set_level(logging.INFO)
    r.runner.return_value = (returncode, '', '')
    r.probe.side_effect = [probe(efc_process.EFC_DEAD), probe(
        efc_process.EFC_DEAD if delayed else efc_process.EFC_RUNNING)]
    watchdog.restart_unas_process(r.state)
    if delayed:
        assert not messages(caplog, 'Remount ')
    r.probe.side_effect = None
    r.probe.return_value = probe(efc_process.EFC_RUNNING)
    watchdog.check_unas_mounts(r.wd)
    watchdog.check_unas_mounts(r.wd)

    assert messages(caplog, 'Remount ') == [(logging.INFO,
        'Remount server:/ at /mnt, uuid:uuid Successfully, mount-cmd')]
    assert not watchdog._restart_log_contexts
    if not delayed:
        # The owner is confirmed even if the launcher returned nonzero.
        assert not messages(caplog, 'Failed to remount ')


@pytest.mark.parametrize('post_state', [
    efc_process.EFC_DEAD, efc_process.EFC_UNKNOWN,
    efc_process.EFC_ZOMBIE_LOCKED, efc_process.EFC_LOCK_CONFLICT,
])
def test_command_failure_keeps_legacy_error_prefix_and_fields(recovery, caplog, post_state):
    r = recovery
    caplog.set_level(logging.INFO)
    r.runner.return_value = (7, '', 'launcher failed')
    r.probe.side_effect = [probe(efc_process.EFC_DEAD), probe(post_state)]
    assert watchdog.restart_unas_process(r.state) is False
    errors = messages(caplog, 'Failed to remount ')
    assert len(errors) == 1
    assert errors[0][0] == logging.ERROR
    assert errors[0][1].startswith(
        'Failed to remount server:/ at /mnt, uuid:uuid returncode=7, stderr="launcher failed"')
    assert 'post_state=' + post_state in errors[0][1]
    assert not messages(caplog, 'Remount ')


def test_repeated_unconfirmed_starts_escalate_without_waiting(recovery, caplog):
    r = recovery
    caplog.set_level(logging.INFO)
    for attempt in range(1, 5):
        r.clock.now = 100 + (attempt - 1) * watchdog.UNAS_RESTART_RETRY_INTERVAL
        watchdog.check_unas_mounts(r.wd)
        errors = messages(caplog, 'Failed to remount ')
        assert len(errors) == max(0, attempt - 2)
        if attempt >= 3:
            assert errors[-1][0] == logging.ERROR
            assert errors[-1][1].startswith(
                'Failed to remount server:/ at /mnt, uuid:uuid returncode=0, stderr=""')
            assert 'unconfirmed_attempts=%d' % attempt in errors[-1][1]
        assert len(messages(caplog, 'Check eac status failed,')) == attempt
    assert r.runner.call_count == 4
    assert len(messages(caplog, 'EFC restart not yet confirmed,')) == 2
    assert not messages(caplog, 'Remount ')


@pytest.mark.parametrize('cancel', ['interval', 'in_progress', 'owner_changed', 'unexpected_probe'])
def test_skipped_attempts_do_not_inflate_failure_count(recovery, caplog, cancel):
    r = recovery
    caplog.set_level(logging.INFO)
    watchdog.restart_unas_process(r.state)
    kwargs = {}
    if cancel != 'interval':
        r.clock.now = 105
    if cancel == 'in_progress':
        watchdog.restart_in_progress.add('uuid')
    elif cancel == 'owner_changed':
        r.probe.return_value = probe(efc_process.EFC_UNKNOWN)
    elif cancel == 'unexpected_probe':
        kwargs['expected_probe'] = probe(efc_process.EFC_UNKNOWN)
    for _ in range(4):
        assert watchdog.restart_unas_process(r.state, **kwargs) is False
    assert r.runner.call_count == 1
    assert watchdog._restart_log_contexts['uuid']['unconfirmed_attempts'] == 1
    assert not messages(caplog, 'Failed to remount ')


@pytest.mark.parametrize('reset', ['running', 'unmounted_scan', 'unmounted_restart'])
def test_unconfirmed_counter_resets_after_recovery_or_unmount(recovery, caplog, reset):
    r = recovery
    caplog.set_level(logging.INFO)
    for now in (100, 105):
        r.clock.now = now
        watchdog.restart_unas_process(r.state)
    saved_mounts = r.mounts.return_value
    r.clock.now = 110
    if reset == 'running':
        r.probe.return_value = probe(efc_process.EFC_RUNNING)
    else:
        r.mounts.return_value = []
    if reset == 'unmounted_restart':
        watchdog.restart_unas_process(r.state)
    else:
        watchdog.check_unas_mounts(r.wd)
    assert 'uuid' not in watchdog._restart_log_contexts
    caplog.clear()
    r.mounts.return_value = saved_mounts
    r.probe.return_value = probe(efc_process.EFC_DEAD)
    watchdog.restart_unas_process(r.state)
    assert watchdog._restart_log_contexts['uuid']['unconfirmed_attempts'] == 1
    assert not messages(caplog, 'Failed to remount ')


def test_restart_exception_also_has_legacy_failure_keyword(recovery, caplog):
    r = recovery
    r.runner.side_effect = RuntimeError('launcher unavailable')
    assert watchdog.restart_unas_process(r.state) is False
    assert messages(caplog, 'restart eac process failed:') == [(
        logging.ERROR, 'restart eac process failed: msg=launcher unavailable')]
    assert messages(caplog, 'Failed to remount ') == [(logging.ERROR,
        'Failed to remount server:/ at /mnt, uuid:uuid, exception msg:launcher unavailable')]


@pytest.mark.parametrize('sidecar', [False, True])
@pytest.mark.parametrize('lock_present', [False, True])
def test_dead_status_log_keeps_legacy_message(recovery, caplog, sidecar, lock_present):
    caplog.set_level(logging.INFO)
    if sidecar:
        recovery.workspace.join('sidecar_exit').write('')
    if lock_present:
        recovery.workspace.join('uuid.efc.lock').write('')
    watchdog.check_unas_mounts(recovery.wd)
    skip_restart = sidecar and not lock_present
    tail = 'no restart because efc lock not exist' if skip_restart else 'try restart'
    assert messages(caplog, 'Check eac status failed,') == [(
        logging.INFO, 'Check eac status failed, mount_uuid:uuid, ' + tail)]
    assert recovery.runner.call_count == (0 if skip_restart else 1)


@pytest.mark.parametrize('host_sidecar_present', [False, True])
def test_recovery_does_not_read_host_sidecar_marker(recovery, mocker, host_sidecar_present):
    real_exists = watchdog.os.path.exists
    exists = mocker.patch('watchdog.os.path.exists', side_effect=lambda path: (
        host_sidecar_present if path == recovery.host_sidecar_path else real_exists(path)))

    watchdog.check_unas_mounts(recovery.wd)

    recovery.runner.assert_called_once()
    assert not any(call[0][0] == recovery.host_sidecar_path
                   for call in exists.call_args_list)


def test_unknown_scan_does_not_emit_false_restart_result(recovery, caplog):
    caplog.set_level(logging.INFO)
    recovery.probe.return_value = probe(efc_process.EFC_UNKNOWN)
    for _ in range(4):
        watchdog.check_unas_mounts(recovery.wd)
    recovery.runner.assert_not_called()
    assert not messages(caplog, 'Check eac status failed,')
    assert not messages(caplog, 'Remount ')
    assert not messages(caplog, 'Failed to remount ')
    assert len(messages(caplog, 'Skip EFC restart,')) == 4
