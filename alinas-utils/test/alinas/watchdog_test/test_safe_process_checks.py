import json
import os
import signal

import process_probe
import watchdog


def identity(pid=123, state='S', starttime=456,
             exe='/usr/local/nas-agent/nas-agent'):
    return process_probe.ProcessIdentity(pid, state, starttime, 'test', exe)


def test_get_nas_agent_pids_uses_exact_exe_probe(mocker):
    find = mocker.patch(
        'watchdog.process_probe.find_processes_by_exe',
        return_value=[identity(10), identity(11)],
    )

    assert watchdog.get_nas_agent_pids() == [10, 11]
    find.assert_called_once_with((watchdog.NAS_AGENT_BIN_PATH,))


def test_stop_nas_agent_revalidates_each_process(mocker):
    processes = [identity(10), identity(11)]
    signal_if_same = mocker.patch(
        'watchdog.process_probe.signal_process_if_same')

    watchdog.stop_nas_agent(processes)

    assert signal_if_same.call_args_list == [
        mocker.call(processes[0], signal.SIGKILL),
        mocker.call(processes[1], signal.SIGKILL),
    ]


def test_stop_nas_agent_scans_immediately_before_signalling(mocker):
    processes = [identity(10), identity(11)]
    scan = mocker.patch(
        'watchdog.get_nas_agent_processes', return_value=processes)
    signal_if_same = mocker.patch(
        'watchdog.process_probe.signal_process_if_same')

    watchdog.stop_nas_agent()

    scan.assert_called_once_with()
    assert signal_if_same.call_count == 2


def test_check_nas_agent_state_does_not_reuse_healthcheck_snapshot(mocker):
    mocker.patch('watchdog.os.path.exists', return_value=True)
    mocker.patch(
        'watchdog.get_nas_agent_processes', return_value=[identity(10)])
    logger = mocker.Mock()
    mocker.patch('watchdog.NAS_AGENT_LOGGER', logger)
    stop = mocker.patch('watchdog.stop_nas_agent')
    mocker.patch(
        'watchdog.execute_with_timeout', return_value=(None, 0, '', ''))

    watchdog.check_nas_agent_state()

    stop.assert_called_once_with()


def test_check_pexporter_alive_does_not_restart(mocker):
    mocker.patch(
        'watchdog.process_probe.find_processes_by_exe',
        return_value=[identity(exe=watchdog.PEXPORTER_BIN_PATH)],
    )
    popen = mocker.patch('subprocess.Popen')

    watchdog.check_pexporter_state()

    popen.assert_not_called()


def test_dadi_enabled_from_legacy_eac_state(tmpdir):
    tmpdir.join('eac-uuid').write(json.dumps({
        'mountcmd': '/usr/bin/aliyun-alinas-eac '
                    '--tier_EnableClusterCache=true',
    }))

    assert watchdog.is_dadi_enabled(str(tmpdir)) is True


def test_dadi_disabled_from_efc_state(tmpdir):
    tmpdir.join('efc-uuid').write(json.dumps({
        'mountcmd': '/usr/bin/aliyun-alinas-efc '
                    '--tier_EnableClusterCache=000',
    }))

    assert watchdog.is_dadi_enabled(str(tmpdir)) is False


def test_old_stunnel_state_is_accepted_by_pid_and_exe(mocker):
    current = identity(exe='/usr/bin/stunnel')
    mocker.patch(
        'watchdog.process_probe.read_process_identity',
        return_value=current,
    )
    mocker.patch('watchdog.shutil.which', return_value='/usr/bin/stunnel')

    result = watchdog.get_stunnel_process_identity({
        'pid': current.pid,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    })

    assert result == current


def test_stunnel_starttime_mismatch_is_not_running(mocker):
    current = identity(starttime=999, exe='/usr/bin/stunnel')
    mocker.patch(
        'watchdog.process_probe.read_process_identity',
        return_value=current,
    )
    mocker.patch('watchdog.shutil.which', return_value='/usr/bin/stunnel')

    result = watchdog.get_stunnel_process_identity({
        'pid': current.pid,
        'pid_starttime': 456,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    })

    assert result is None


def test_stunnel_starttime_accepts_old_binary_after_symlink_upgrade(mocker):
    current = identity(exe='/usr/bin/stunnel-old')
    mocker.patch(
        'watchdog.process_probe.read_process_identity',
        return_value=current,
    )
    mocker.patch('watchdog.shutil.which', return_value='/usr/bin/stunnel-new')

    result = watchdog.probe_stunnel_process({
        'pid': current.pid,
        'pid_starttime': current.starttime,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    })

    assert result.state == watchdog.STUNNEL_RUNNING
    assert result.identity == current


def test_non_stunnel_pid_is_not_accepted(mocker):
    current = identity(exe='/usr/bin/sleep')
    mocker.patch(
        'watchdog.process_probe.read_process_identity',
        return_value=current,
    )
    mocker.patch('watchdog.shutil.which', return_value='/usr/bin/stunnel')

    assert watchdog.get_stunnel_process_identity({
        'pid': current.pid,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    }) is None


def test_stunnel_probe_reports_unknown_on_procfs_error(mocker):
    mocker.patch(
        'watchdog.process_probe.read_process_identity',
        side_effect=OSError(5, 'input/output error'),
    )

    result = watchdog.probe_stunnel_process({
        'pid': 123,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    })

    assert result.state == watchdog.STUNNEL_UNKNOWN
    assert result.identity is None


def test_signal_stunnel_group_revalidates_identity(mocker):
    current = identity(exe='/usr/bin/stunnel')
    probe = mocker.patch(
        'watchdog.get_stunnel_process_identity',
        side_effect=[current, current],
    )
    mocker.patch('watchdog.os.getpgid', return_value=321)
    killpg = mocker.patch('watchdog.os.killpg')
    state = {
        'pid': current.pid,
        'pid_starttime': current.starttime,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    }

    assert watchdog.signal_stunnel_process_group_if_same(
        state, signal.SIGHUP, current) == 321

    assert probe.call_count == 2
    killpg.assert_called_once_with(321, signal.SIGHUP)


def test_signal_stunnel_group_skips_changed_identity(mocker):
    current = identity(exe='/usr/bin/stunnel')
    changed = identity(starttime=789, exe='/usr/bin/stunnel')
    mocker.patch(
        'watchdog.get_stunnel_process_identity',
        side_effect=[current, changed],
    )
    mocker.patch('watchdog.os.getpgid', return_value=321)
    killpg = mocker.patch('watchdog.os.killpg')

    assert watchdog.signal_stunnel_process_group_if_same(
        {'pid': current.pid, 'cmd': ['stunnel', '/tmp/stunnel.conf']},
        signal.SIGTERM,
        current,
    ) is None

    killpg.assert_not_called()


def test_refresh_and_pin_stunnel_identity_preserves_reloaded_state(mocker):
    current = identity(exe='/usr/bin/stunnel')
    reloaded = {
        'pid': current.pid,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
        'certificateCreationTime': 'new-value',
    }
    wd = mocker.Mock()
    wd.load_state_file.return_value = reloaded
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_RUNNING, current, 'test running'))
    rewrite = mocker.patch('watchdog.rewrite_state_file')

    state, result = watchdog.refresh_and_pin_stunnel_identity(
        wd, '/state', 'alinas-state', current)

    assert result.state == watchdog.STUNNEL_RUNNING
    assert result.identity == current
    assert state['certificateCreationTime'] == 'new-value'
    assert state[watchdog.PROCESS_STARTTIME] == current.starttime
    rewrite.assert_called_once_with(state, '/state', 'alinas-state')


def test_refresh_and_pin_stunnel_identity_skips_changed_process(mocker):
    expected = identity(exe='/usr/bin/stunnel')
    changed = identity(starttime=789, exe='/usr/bin/stunnel')
    reloaded = {
        'pid': changed.pid,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    }
    wd = mocker.Mock()
    wd.load_state_file.return_value = reloaded
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_RUNNING, changed, 'test changed'))
    rewrite = mocker.patch('watchdog.rewrite_state_file')

    state, result = watchdog.refresh_and_pin_stunnel_identity(
        wd, '/state', 'alinas-state', expected)

    assert state == reloaded
    assert result.state == watchdog.STUNNEL_RUNNING
    assert result.identity == changed
    rewrite.assert_not_called()
