"""UNKNOWN diagnostics must never change proxy recovery decisions."""

import logging
from types import SimpleNamespace

import pytest

import process_probe
import watchdog


def probe(state, reason='procfs read failed: EACCES'):
    identity = process_probe.ProcessIdentity(
        123, 'S', 456, 'stunnel', '/usr/bin/stunnel')
    return watchdog.StunnelProbeResult(
        state, identity if state == watchdog.STUNNEL_RUNNING else None, reason)


@pytest.fixture
def scan(mocker, tmpdir, caplog):
    watchdog._stunnel_unknown_reports.clear()
    caplog.set_level(logging.INFO)
    state = {'pid': 123, 'pid_starttime': 456,
             'cmd': ['stunnel', '/tmp/stunnel.conf'], 'certificate': 'cert'}
    wd = mocker.Mock(child_procs=[])
    wd.load_state_file.side_effect = lambda *args: dict(state)
    clock = mocker.patch('watchdog.time.monotonic', return_value=100.0)
    mocker.patch('watchdog.time.time', return_value=1000.0)
    mocker.patch('watchdog.time.sleep')
    files = mocker.patch('watchdog.get_files_with_prefix',
                         return_value={'dns': 'alinas-test'})
    mounts = mocker.patch('watchdog.get_current_local_nfs_mounts', return_value={
        'dns': watchdog.Mount('dns:/', '/mnt', 'nfs4', '', '0', '0')})
    owner = mocker.patch('watchdog.probe_stunnel_process',
                         return_value=probe(watchdog.STUNNEL_UNKNOWN))
    start = mocker.patch('watchdog.start_proxy', return_value=789)
    mocker.patch('watchdog.set_process_starttime')
    signal = mocker.patch('watchdog.signal_stunnel_process_group_if_same')
    certificate = mocker.patch('watchdog.check_certificate')
    rewrite = mocker.patch('watchdog.rewrite_state_file')
    cleanup = mocker.spy(watchdog, 'clean_up_mount_state')
    mark = mocker.patch('watchdog.mark_as_unmounted')
    try:
        yield SimpleNamespace(
            state=state, wd=wd, clock=clock, files=files, mounts=mounts,
            owner=owner, start=start, signal=signal, certificate=certificate,
            rewrite=rewrite, cleanup=cleanup, mark=mark,
            key=(str(tmpdir), 'alinas-test'),
            run=lambda: watchdog.check_nfs_mounts(None, wd, 30, str(tmpdir)))
    finally:
        watchdog._stunnel_unknown_reports.clear()


def unknown_logs(caplog):
    return [r for r in caplog.records if 'process state is UNKNOWN' in r.getMessage()]


@pytest.mark.parametrize('unmounted', [False, True])
def test_unknown_escalates_and_rate_limits_without_taking_action(scan, caplog, unmounted):
    s = scan
    if unmounted:
        s.state['unmount_time'] = 0  # already past the unmount grace period
        s.mounts.return_value = {}
    for now in (100, 101, 159.9, 160, 161, 220):
        s.clock.return_value = now
        s.owner.return_value = probe(watchdog.STUNNEL_UNKNOWN, 'error at %s' % now)
        s.run()

    logs = unknown_logs(caplog)
    assert [r.levelno for r in logs] == [logging.WARNING, logging.ERROR, logging.ERROR]
    assert 'duration_sec:60.0 count:4' in logs[1].getMessage()
    assert 'duration_sec:120.0 count:6 reason:error at 220' in logs[2].getMessage()
    assert 'pid:123 pid_starttime:456' in logs[2].getMessage()
    assert s.key[0] + '/' + s.key[1] in logs[2].getMessage()
    assert s.owner.call_count == 6  # logging is throttled, probing is not
    s.start.assert_not_called()
    s.signal.assert_not_called()
    s.cleanup.assert_not_called()
    s.mark.assert_not_called()
    s.certificate.assert_not_called()
    s.rewrite.assert_not_called()


@pytest.mark.parametrize('state', [watchdog.STUNNEL_RUNNING, watchdog.STUNNEL_DEAD])
def test_known_state_clears_report_and_resumes_actions(scan, caplog, state):
    s = scan
    s.run()
    s.clock.return_value = 110
    s.owner.return_value = probe(state)
    s.run()

    assert s.key not in watchdog._stunnel_unknown_reports
    s.certificate.assert_called_once()
    assert s.start.call_count == (1 if state == watchdog.STUNNEL_DEAD else 0)
    recovered = [r for r in caplog.records if 'recovered from UNKNOWN' in r.getMessage()]
    assert len(recovered) == 1
    assert 'duration_sec:10.0 count:1' in recovered[0].getMessage()
    s.owner.return_value = probe(watchdog.STUNNEL_RUNNING)
    s.run()
    assert len([r for r in caplog.records if 'recovered from UNKNOWN' in r.getMessage()]) == 1

    s.clock.return_value = 200
    s.owner.return_value = probe(watchdog.STUNNEL_UNKNOWN)
    s.run()
    assert unknown_logs(caplog)[-1].levelno == logging.WARNING
    assert watchdog._stunnel_unknown_reports[s.key]['count'] == 1


@pytest.mark.parametrize('field,value', [('pid', 124), ('pid_starttime', 457)])
def test_changed_process_identity_starts_new_report(scan, caplog, field, value):
    s = scan
    s.run()
    s.clock.return_value = 200
    s.state[field] = value
    s.run()

    report = watchdog._stunnel_unknown_reports[s.key]
    assert report['first_seen'] == 200
    assert report['count'] == 1
    assert [r.levelno for r in unknown_logs(caplog)] == [logging.WARNING, logging.WARNING]


@pytest.mark.parametrize('removed', [False, True])
def test_missing_or_invalid_state_discards_report(scan, removed):
    s = scan
    s.run()
    if removed:
        s.files.return_value = {}
    else:
        s.wd.load_state_file.side_effect = None
        s.wd.load_state_file.return_value = None
    s.run()
    assert s.key not in watchdog._stunnel_unknown_reports


def test_reports_are_independent_and_pruning_is_directory_scoped(scan):
    s = scan
    s.run()
    other_key = (s.key[0] + '/other', s.key[1])
    s.clock.return_value = 150
    watchdog._report_stunnel_unknown(other_key[0], other_key[1], s.state, 'EIO')
    assert watchdog._stunnel_unknown_reports[s.key]['first_seen'] == 100
    assert watchdog._stunnel_unknown_reports[other_key]['first_seen'] == 150
    s.files.return_value = {}
    s.run()
    assert s.key not in watchdog._stunnel_unknown_reports
    assert other_key in watchdog._stunnel_unknown_reports


@pytest.mark.parametrize('stage', ['identity', 'cleanup', 'cleanup_final', 'restart'])
def test_recheck_unknown_is_not_reset_by_initial_known_probe(scan, caplog, stage):
    s = scan
    dead = probe(watchdog.STUNNEL_DEAD)
    unknown = probe(watchdog.STUNNEL_UNKNOWN)
    if stage == 'identity':
        del s.state['pid_starttime']  # legacy state triggers identity recheck
        results = [probe(watchdog.STUNNEL_RUNNING), unknown]
    elif stage.startswith('cleanup'):
        s.state['unmount_time'] = 0
        s.mounts.return_value = {}
        results = [dead, unknown] if stage == 'cleanup' else [dead, dead, unknown]
    else:
        results = [dead, unknown]

    for now in (100, 159, 160):
        s.clock.return_value = now
        s.owner.side_effect = list(results)
        s.run()

    report = watchdog._stunnel_unknown_reports[s.key]
    assert report['first_seen'] == 100
    assert report['count'] == 3
    assert s.owner.call_count == 3 * len(results)
    assert [r.levelno for r in unknown_logs(caplog)] == [logging.WARNING, logging.ERROR]
    assert 'recheck' in unknown_logs(caplog)[-1].getMessage() or stage == 'cleanup'
    assert not any('recovered from UNKNOWN' in r.getMessage() for r in caplog.records)
    s.start.assert_not_called()
    s.signal.assert_not_called()
    s.rewrite.assert_not_called()


def test_failed_scan_does_not_report_false_recovery(scan, caplog):
    s = scan
    s.run()
    s.clock.return_value = 160
    s.wd.load_state_file.side_effect = OSError('state read failed')
    s.run()
    assert s.key in watchdog._stunnel_unknown_reports
    assert not any('recovered from UNKNOWN' in r.getMessage() for r in caplog.records)
