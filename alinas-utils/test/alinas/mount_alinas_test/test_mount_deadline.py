"""The shared deadline stops waiting, not the final mount verification."""

from types import SimpleNamespace

import pytest

import efc_process
import mount_alinas


@pytest.fixture
def completion(mocker):
    clock = SimpleNamespace(now=100.0)
    mocker.patch('mount_alinas.time.monotonic', side_effect=lambda: clock.now)

    def advance(seconds):
        clock.now += seconds

    sleep = mocker.patch('mount_alinas.time.sleep', side_effect=advance)
    mounts = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=[])
    protocol = mocker.patch('mount_alinas.check_fuse_protocol', return_value=True)
    probe = mocker.patch(
        'mount_alinas.efc_process.probe_efc',
        return_value=SimpleNamespace(state=efc_process.EFC_RUNNING))
    mounted = mount_alinas.Mount(
        'uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')
    return SimpleNamespace(
        clock=clock, sleep=sleep, mounts=mounts, protocol=protocol,
        probe=probe, mounted=mounted,
        run=lambda timeout: mount_alinas.wait_mount_completed(
            'uuid', 'server:/', timeout))


@pytest.mark.parametrize('timeout', [0, -1])
@pytest.mark.parametrize('record', ['present', 'missing', 'other_uuid', 'bad_protocol'])
def test_expired_budget_checks_mount_once_without_waiting(completion, timeout, record):
    c = completion
    if record != 'missing':
        mounted = c.mounted
        if record == 'other_uuid':
            mounted = mounted._replace(server='other:server:/')
        c.mounts.return_value = [mounted]
    c.protocol.return_value = record != 'bad_protocol'

    assert c.run(timeout) is (record == 'present')
    c.mounts.assert_called_once_with(mount_alinas.MOUNT_TYPE_EFC)
    assert c.protocol.call_count == int(record in ('present', 'bad_protocol'))
    c.probe.assert_not_called()
    c.sleep.assert_not_called()


@pytest.mark.parametrize('appears', [True, False])
def test_last_sleep_is_followed_by_final_mount_check(completion, appears):
    c = completion
    c.mounts.side_effect = [[], [c.mounted] if appears else []]
    timeout = efc_process.EFC_READINESS_POLL_INTERVAL

    assert c.run(timeout) is appears
    assert c.mounts.call_count == 2
    c.probe.assert_called_once()
    c.sleep.assert_called_once()
    assert c.sleep.call_args[0][0] == pytest.approx(timeout)
    assert c.clock.now == pytest.approx(100 + timeout)


@pytest.mark.parametrize('state', [efc_process.EFC_DEAD, efc_process.EFC_UNKNOWN])
def test_final_check_does_not_extend_startup_grace(completion, state):
    c = completion
    c.probe.return_value = SimpleNamespace(state=state, reason='test')

    assert c.run(efc_process.EFC_READINESS_TIMEOUT) is False
    assert c.clock.now == pytest.approx(100 + efc_process.EFC_READINESS_TIMEOUT)
    assert c.mounts.call_count == c.probe.call_count + 1


@pytest.mark.parametrize('state', [efc_process.EFC_ZOMBIE_LOCKED, efc_process.EFC_LOCK_CONFLICT])
def test_terminal_process_state_still_fails_immediately(completion, state):
    c = completion
    c.probe.return_value = SimpleNamespace(state=state, owner_pid=123, reason='test')

    assert c.run(120) is False
    c.mounts.assert_called_once()
    c.probe.assert_called_once()
    c.sleep.assert_not_called()
