"""Only upgrade preflight retries UNKNOWN; mount/bind paths stay unchanged."""

from types import SimpleNamespace
import errno
import logging
import os

import pytest

import efc_process
import mount_alinas


def probe(state, pid=100, reason='test'):
    return efc_process.EfcProbeResult(
        state, pid, 'S', pid * 10, 'aliyun-alinas-e', '/tmp/uuid.efc.lock',
        1, 2, pid, True, reason)


@pytest.fixture
def upgrade(mocker, tmpdir):
    clock = SimpleNamespace(now=100.0)
    mocker.patch('mount_alinas.time.monotonic', side_effect=lambda: clock.now)

    def advance(seconds):
        clock.now += seconds

    sleep = mocker.patch('mount_alinas.time.sleep', side_effect=advance)
    mocker.patch('mount_alinas.load_unas_state_file', return_value={'mountcmd': 'mount-cmd'})
    mocker.patch('mount_alinas.get_unas_internal_info', return_value='info')
    mocker.patch('mount_alinas.create_unas_mount_dir')
    mocker.patch('mount_alinas.get_unas_mount_file_path', return_value=('dir', 'log', 'vsc-log'))
    mocker.patch('mount_alinas.gen_unas_mount_cmd', return_value='mount-cmd')
    mocker.patch('mount_alinas.write_unas_state_file')
    mocker.patch('mount_alinas.BIND_ROOT_DIR', str(tmpdir.join('bindroot')))
    mocker.patch('mount_alinas.get_remote_root_path', return_value='/')
    mocker.patch('mount_alinas.get_relative_path_to_bind_root', return_value='')
    owner = mocker.patch('mount_alinas.efc_process.probe_efc')
    execute = mocker.patch('mount_alinas.execute', return_value=0)
    new_owner = probe(efc_process.EFC_RUNNING, pid=101)
    readiness = mocker.patch('mount_alinas.efc_process.wait_efc_readiness', return_value=new_owner)
    real_wait = mount_alinas.wait_mount_completed
    mounted = mocker.patch('mount_alinas.wait_mount_completed', return_value=True)
    cgroup = mocker.patch('mount_alinas.add_cgroup_limit')
    ctx = mount_alinas.MountContext(
        None, 'systemd', 'server', 'fs-id', '/', '/mnt', None, {'upgrade': None})
    return SimpleNamespace(
        ctx=ctx, clock=clock, sleep=sleep, owner=owner, execute=execute,
        readiness=readiness, mounted=mounted, cgroup=cgroup, real_wait=real_wait,
        run=lambda: mount_alinas.run_mount_unas(ctx, 'uuid', '/mnt', 'server:/', True, True))


@pytest.mark.parametrize('state', [efc_process.EFC_RUNNING, efc_process.EFC_DEAD])
def test_known_upgrade_state_does_not_wait(upgrade, state):
    u = upgrade
    confirmed = probe(state)
    u.owner.return_value = confirmed
    u.run()

    u.owner.assert_called_once_with('uuid', mount_alinas.EFC_WORKSPACE_DIR)
    u.sleep.assert_not_called()
    u.execute.assert_called_once_with('mount-cmd', mount_alinas.UNAS_MOUNT_TIMEOUT)
    assert u.readiness.call_args[1]['previous_probe'] is confirmed


@pytest.mark.parametrize('state', [efc_process.EFC_RUNNING, efc_process.EFC_DEAD])
def test_unknown_retries_until_first_safe_upgrade_state(upgrade, state):
    u = upgrade
    confirmed = probe(state)
    u.owner.side_effect = [probe(efc_process.EFC_UNKNOWN), probe(efc_process.EFC_UNKNOWN), confirmed]
    u.run()

    assert u.owner.call_count == 3
    assert u.sleep.call_count == 2
    assert u.clock.now == pytest.approx(100.2)
    assert u.execute.call_count == 1
    assert u.execute.call_args[0][1] == pytest.approx(119.8)
    assert u.readiness.call_args[1]['previous_probe'] is confirmed
    u.cgroup.assert_called_once_with(u.ctx, 'uuid', efc_pid=101)


@pytest.mark.parametrize('initial_unknown', [False, True])
@pytest.mark.parametrize('state', [efc_process.EFC_ZOMBIE_LOCKED, efc_process.EFC_LOCK_CONFLICT])
def test_unsafe_upgrade_state_fails_immediately(upgrade, capsys, initial_unknown, state):
    u = upgrade
    results = [probe(state, reason='unsafe lock owner')]
    if initial_unknown:
        results.insert(0, probe(efc_process.EFC_UNKNOWN))
    u.owner.side_effect = results
    with pytest.raises(SystemExit):
        u.run()

    assert u.owner.call_count == len(results)
    assert u.sleep.call_count == int(initial_unknown)
    assert u.clock.now == pytest.approx(100.1 if initial_unknown else 100.0)
    error = capsys.readouterr().err
    assert state in error and 'unsafe lock owner' in error
    u.execute.assert_not_called()
    u.readiness.assert_not_called()
    u.mounted.assert_not_called()


@pytest.mark.parametrize('operation_timeout, expected_wait', [(120, 3.0), (0.25, 0.25)])
def test_unknown_timeout_respects_both_deadlines(upgrade, mocker, capsys, operation_timeout, expected_wait):
    u = upgrade
    mocker.patch('mount_alinas.UNAS_MOUNT_TIMEOUT', operation_timeout)
    u.owner.return_value = probe(efc_process.EFC_UNKNOWN, reason='procfs denied')
    with pytest.raises(SystemExit):
        u.run()

    assert u.clock.now == pytest.approx(100 + expected_wait)
    assert u.owner.call_count == u.sleep.call_count + 1
    assert all(0 < c[0][0] <= 0.1 for c in u.sleep.call_args_list)
    error = capsys.readouterr().err
    assert 'UNKNOWN' in error and 'procfs denied' in error
    u.execute.assert_not_called()
    u.readiness.assert_not_called()
    u.mounted.assert_not_called()


def test_initial_probe_time_counts_toward_retry_limit(upgrade):
    u = upgrade

    def slow_probe(*args):
        u.clock.now += 3
        return probe(efc_process.EFC_UNKNOWN)

    u.owner.side_effect = slow_probe
    with pytest.raises(SystemExit):
        u.run()
    assert u.owner.call_count == 1
    u.sleep.assert_not_called()
    u.execute.assert_not_called()


def test_retry_time_is_deducted_from_command_and_post_start_budgets(upgrade):
    u = upgrade
    confirmed = probe(efc_process.EFC_RUNNING)
    u.owner.side_effect = [probe(efc_process.EFC_UNKNOWN), confirmed]

    def execute(*args):
        u.clock.now += 7
        return 0

    def readiness(*args, **kwargs):
        u.clock.now += 2
        return probe(efc_process.EFC_RUNNING, pid=101)

    u.execute.side_effect = execute
    u.readiness.side_effect = readiness
    u.run()

    assert u.execute.call_args[0][1] == pytest.approx(119.9)
    assert u.readiness.call_args[1]['timeout'] == pytest.approx(112.9)
    assert u.mounted.call_args[0][2] == pytest.approx(110.9)


def test_unknown_retry_does_not_accept_unchanged_post_upgrade_owner(upgrade):
    u = upgrade
    confirmed = probe(efc_process.EFC_RUNNING)
    u.owner.side_effect = [probe(efc_process.EFC_UNKNOWN), confirmed]
    u.readiness.return_value = confirmed
    with pytest.raises(SystemExit):
        u.run()

    assert u.readiness.call_args[1]['previous_probe'] is confirmed
    u.execute.assert_called_once()
    u.mounted.assert_not_called()
    u.cgroup.assert_not_called()


@pytest.mark.parametrize('record', ['present', 'missing', 'bad_protocol'])
@pytest.mark.parametrize('owner_changed', [True, False])
def test_upgrade_budget_exhausted_still_validates_owner_and_mount(
        upgrade, mocker, record, owner_changed):
    u = upgrade
    u.owner.return_value = probe(efc_process.EFC_RUNNING)

    def readiness(*args, **kwargs):
        u.clock.now += kwargs['timeout']
        return probe(efc_process.EFC_RUNNING, pid=101 if owner_changed else 100)

    u.readiness.side_effect = readiness
    u.mounted.side_effect = u.real_wait
    mounts = mocker.patch('mount_alinas.get_current_unas_mounts', return_value=(
        [] if record == 'missing' else [mount_alinas.Mount(
            'uuid:server:/', '/mnt', 'fuse.aliyun-alinas-efc', '', '0', '0')]))
    mocker.patch('mount_alinas.check_fuse_protocol', return_value=record != 'bad_protocol')
    mocker.patch('mount_alinas.get_mount_err_log', return_value='test')

    if owner_changed and record == 'present':
        u.run()
        u.cgroup.assert_called_once_with(u.ctx, 'uuid', efc_pid=101)
    else:
        with pytest.raises(SystemExit):
            u.run()
        u.cgroup.assert_not_called()

    if owner_changed:
        u.mounted.assert_called_once_with('uuid', 'server:/', 0.0)
        mounts.assert_called_once_with(mount_alinas.MOUNT_TYPE_EFC)
    else:
        # An existing mount record never substitutes for a new upgrade owner.
        u.mounted.assert_not_called()
        mounts.assert_not_called()
    u.sleep.assert_not_called()
    assert u.clock.now == 100 + mount_alinas.UNAS_MOUNT_TIMEOUT


def test_preflight_retry_does_not_retry_failed_upgrade_command(upgrade):
    u = upgrade
    u.owner.side_effect = [probe(efc_process.EFC_UNKNOWN), probe(efc_process.EFC_DEAD)]
    u.execute.return_value = 1
    with pytest.raises(SystemExit):
        u.run()

    u.execute.assert_called_once()
    assert u.sleep.call_count == 1
    u.readiness.assert_not_called()


@pytest.mark.parametrize('mode', ['mount', 'bindroot', 'bind_existing'])
def test_normal_mount_and_bind_do_not_run_upgrade_preflight(upgrade, mode):
    u = upgrade
    ctx = u.ctx._replace(options={})

    def post_mount_probe(*args):
        # The existing post-mount cgroup probe is allowed, but no preflight.
        assert u.execute.call_count == 1
        return probe(efc_process.EFC_UNKNOWN)

    u.owner.side_effect = post_mount_probe
    if mode == 'mount':
        mount_alinas.run_mount_unas(ctx, 'uuid', '/mnt', 'server:/', False, True)
    elif mode == 'bindroot':
        mount_alinas.mount_bindroot(ctx, 'bindroot-uuid', False, True)
    else:
        mount_alinas.do_bind_mount(ctx, '/bindroot', '/mnt')

    assert u.owner.call_count == (0 if mode == 'bind_existing' else 1)
    u.execute.assert_called_once()
    u.sleep.assert_not_called()
    u.readiness.assert_not_called()


@pytest.mark.parametrize('failure', [
    'unknown', 'zombie', 'conflict', 'unchanged_owner', 'not_ready',
    'command', 'missing_mount', 'exception',
])
def test_upgrade_failure_preserves_mount_alarm_prefix(upgrade, mocker, caplog, capsys, failure):
    u = upgrade
    u.owner.return_value = probe(efc_process.EFC_RUNNING)
    if failure in ('unknown', 'zombie', 'conflict'):
        u.owner.return_value = probe({
            'unknown': efc_process.EFC_UNKNOWN,
            'zombie': efc_process.EFC_ZOMBIE_LOCKED,
            'conflict': efc_process.EFC_LOCK_CONFLICT,
        }[failure])
    elif failure == 'unchanged_owner':
        u.readiness.return_value = u.owner.return_value
    elif failure == 'not_ready':
        u.readiness.return_value = probe(efc_process.EFC_DEAD)
    elif failure == 'command':
        u.execute.return_value = 1
    elif failure == 'missing_mount':
        u.mounted.return_value = False
        mocker.patch('mount_alinas.get_mount_err_log', return_value='missing mount')
    else:
        u.execute.side_effect = RuntimeError('test exception')
    with pytest.raises(SystemExit):
        u.run()
    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert errors[0].levelno == logging.ERROR
    assert message.startswith('Fail to mount ' + mount_alinas.UNAS_APP_NAME)
    assert capsys.readouterr().err.strip() == message
    if failure != 'exception':
        assert message.startswith('Fail to mount %s:uuid:server:/' % mount_alinas.UNAS_APP_NAME)
    if failure in ('unknown', 'zombie', 'conflict', 'unchanged_owner', 'not_ready'):
        assert '[operation:upgrade,' in message
        assert 'state:' in message and 'reason:' in message


@pytest.mark.parametrize('is_upgrade', [False, True])
def test_mount_success_log_contract(upgrade, caplog, capsys, is_upgrade):
    u = upgrade
    caplog.set_level(logging.INFO)
    u.owner.return_value = probe(efc_process.EFC_RUNNING)
    mount_alinas.run_mount_unas(u.ctx, 'uuid', '/mnt', 'server:/', is_upgrade, True)
    operation = 'upgrade' if is_upgrade else 'mount'
    assert [(r.levelno, r.getMessage()) for r in caplog.records
            if r.getMessage().startswith('Successfully ')] == [(
                logging.INFO, 'Successfully %s server:/ at /mnt' % operation)]
    assert capsys.readouterr().out.strip() == '%s %s:server:/ successfully' % (
        operation, mount_alinas.UNAS_APP_NAME)


@pytest.mark.parametrize('failure', ['command', 'missing_mount', 'exception'])
def test_normal_mount_failure_log_contract(upgrade, mocker, caplog, failure):
    u = upgrade
    if failure == 'command':
        u.execute.return_value = 1
        expected = 'Fail to mount %s:uuid:server:/' % mount_alinas.UNAS_APP_NAME
    elif failure == 'missing_mount':
        u.mounted.return_value = False
        mocker.patch('mount_alinas.get_mount_err_log', return_value='missing mount')
        expected = 'Fail to mount %s:uuid:server:/ [missing mount]' % mount_alinas.UNAS_APP_NAME
    else:
        u.execute.side_effect = RuntimeError('test exception')
        expected = 'Fail to mount %s, exception msg:test exception' % mount_alinas.UNAS_APP_NAME
    with pytest.raises(SystemExit):
        mount_alinas.run_mount_unas(u.ctx, 'uuid', '/mnt', 'server:/', False, True)
    assert [(r.levelno, r.getMessage()) for r in caplog.records
            if r.levelno >= logging.ERROR] == [(logging.ERROR, expected)]


@pytest.mark.parametrize('umount', [False, True])
@pytest.mark.parametrize('returncode', [0, 1])
def test_bind_mount_and_umount_log_contract(upgrade, caplog, umount, returncode):
    caplog.set_level(logging.INFO)
    upgrade.execute.return_value = returncode
    if umount:
        run = lambda: mount_alinas.do_bind_umount('/bindroot', '/mnt', 0)
        message = ('Failed to umount bind /mnt at /bindroot: returncode=1'
                   if returncode else 'Successfully umount bind /mnt at /bindroot')
    else:
        run = lambda: mount_alinas.do_bind_mount(upgrade.ctx, '/bindroot', '/mnt')
        message = ('Failed to bind mount /bindroot at /mnt: returncode=1'
                   if returncode else 'Successfully bind mounted /bindroot at /mnt')
    if returncode:
        with pytest.raises(SystemExit):
            run()
    else:
        run()
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [(
        logging.ERROR if returncode else logging.INFO, message)]


@pytest.mark.parametrize('error', [0, errno.EIO])
def test_efc_umount_log_contract(mocker, caplog, error):
    caplog.set_level(logging.INFO)
    sock = mocker.patch('mount_alinas.socket.socket').return_value
    sock.recv.return_value = ('%d\0' % error).encode('ascii')
    mocker.patch('mount_alinas.get_unas_mount_type', return_value=mount_alinas.MOUNT_TYPE_EFC)
    connection = '%s/uuid.%s' % (mount_alinas.EFC_WORKSPACE_DIR, mount_alinas.EFC_SOCKET_SUFFIX)
    if error:
        with pytest.raises(SystemExit):
            mount_alinas.try_umount_unas('uuid', '/mnt', 0)
        expected = [
            (logging.ERROR, 'Unas umount return error %d, uuid:uuid mount_point:/mnt conn:%s' % (error, connection)),
            (logging.ERROR, 'Fail to umount %s:/mnt, error:%s' % (mount_alinas.UNAS_APP_NAME, os.strerror(error))),
        ]
    else:
        assert mount_alinas.try_umount_unas('uuid', '/mnt', 0) is True
        expected = [(logging.INFO, 'Unas umount return ok, uuid:uuid mount_point:/mnt conn:%s' % connection)]
    assert [(r.levelno, r.getMessage()) for r in caplog.records][1:] == expected
    sock.close.assert_called_once()
