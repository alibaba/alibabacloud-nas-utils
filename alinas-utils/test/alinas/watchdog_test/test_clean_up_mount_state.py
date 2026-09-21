#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json
import os
import tempfile
import logging

import pytest

PID = 99999999999999999


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def create_state_file(tmpdir, extra_files=list(), dns=None, ip=None, mount_state_dir=None):
    content = {
        'pid': PID,
        'files': extra_files
    }
    if dns:
        content['local_dns'] = dns
    if ip:
        content['local_ip'] = ip
    if mount_state_dir:
        content['mountStateDir'] = mount_state_dir

    state_file = create_temp_file(tmpdir, json.dumps(content))

    return state_file.dirname, state_file.basename, str(state_file)


def setup_mock(mocker, is_pid_running):
    mocker.patch('os.getpgid')
    mocker.patch('watchdog.is_pid_running', return_value=is_pid_running)

    killpg_mock = mocker.patch('os.killpg')
    return killpg_mock


def test_clean_up_on_first_try(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_file_dir, state_file, PID, is_running=True)

    killpg_mock.assert_called_once()
    assert not os.path.exists(abs_state_file)


def _test_clean_up_files(mocker, tmpdir, files_should_exist):
    killpg_mock = setup_mock(mocker, False)
    clean_up_local_dns_mock = mocker.patch('watchdog.clean_up_local_dns')

    extra_files = [
        str(create_temp_file(tmpdir)),
        str(create_temp_file(tmpdir)),
    ]

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir, extra_files)

    assert os.path.exists(abs_state_file)
    for f in extra_files:
        if not files_should_exist:
            os.remove(f)
        assert os.path.exists(f) or not files_should_exist

    watchdog.clean_up_mount_state(state_file_dir, state_file, PID, is_running=True)

    killpg_mock.assert_called_once()
    assert not os.path.exists(abs_state_file)
    for f in extra_files:
        assert not os.path.exists(f)

    clean_up_local_dns_mock.assert_called_once()
    clean_up_local_dns_mock.assert_called_with(None, None)


def test_clean_up_nonexistent_files(mocker, tmpdir):
    _test_clean_up_files(mocker, tmpdir, files_should_exist=False)


def test_clean_up_multiple_files(mocker, tmpdir):
    _test_clean_up_files(mocker, tmpdir, files_should_exist=True)


def test_clean_up_pid_still_lives(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, True)

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_file_dir, state_file, PID, is_running=True)

    killpg_mock.assert_called_once()
    assert os.path.exists(abs_state_file)


def test_pid_not_running(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_file_dir, state_file, PID, is_running=False)

    killpg_mock.assert_not_called()
    assert not os.path.exists(abs_state_file)


def test_clean_up_local_dns(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)
    clean_up_local_dns_mock = mocker.patch('watchdog.clean_up_local_dns')

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir, [], 'dns', 'ip')

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_file_dir, state_file, PID, is_running=True)

    killpg_mock.assert_called_once()
    clean_up_local_dns_mock.assert_called_once()
    clean_up_local_dns_mock.assert_called_with('dns', 'ip')

def test_clean_up_mount_state_dir_success(mocker, tmpdir):
    setup_mock(mocker, False)
    mocker.patch("os.path.isdir", return_value=True)
    rm_tree = mocker.patch("shutil.rmtree")

    state_file_dir, state_file, abs_state_file = create_state_file(
        tmpdir, mount_state_dir="/fake/path"
    )

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(
        state_file_dir, state_file, PID, is_running=False, mount_state_dir="/fake/path"
    )

    rm_tree.assert_called_once()
    assert not os.path.exists(abs_state_file)

def test_clean_up_mount_state_dir_fail(mocker, tmpdir):
    setup_mock(mocker, False)
    mocker.patch("os.path.isdir", return_value=False)
    rm_tree = mocker.patch("shutil.rmtree")
    mount_state_dir = "/fake/path"

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir, 
        mount_state_dir=mount_state_dir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(
        state_file_dir, state_file, PID, is_running=False, mount_state_dir="/fake/path"
    )

    rm_tree.assert_not_called()
    assert not os.path.exists(abs_state_file)


def test_clean_up_mount_state_dir_skip(mocker, tmpdir):
    setup_mock(mocker, False)
    rm_tree = mocker.patch("shutil.rmtree")
    # Skip removing a bug version with format {fsid.mountpoint.tlsport+}
    mount_state_dir = "/1a2b3c.mnt.12049+"

    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir,
        mount_state_dir=mount_state_dir)
    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(
        state_file_dir, state_file, PID, is_running=False, mount_state_dir=mount_state_dir
    )

    rm_tree.assert_not_called()
    assert not os.path.exists(abs_state_file)


def test_cleanup_cancels_when_state_changed(mocker, tmpdir):
    expected_state = {
        'pid': PID,
        'pid_starttime': 100,
        'cmd': ['stunnel', '/tmp/old.conf'],
    }
    current_state = dict(expected_state)
    current_state['pid_starttime'] = 200
    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir)
    state_loader = mocker.Mock(return_value=current_state)
    signal_proxy = mocker.patch(
        'watchdog.signal_stunnel_process_group_if_same')

    assert watchdog.clean_up_mount_state(
        state_file_dir, state_file, PID, True,
        state=expected_state,
        process_identity=mocker.Mock(),
        state_loader=state_loader,
    ) is False

    signal_proxy.assert_not_called()
    assert os.path.exists(abs_state_file)


def test_cleanup_defers_when_process_probe_is_unknown(mocker, tmpdir):
    state = {
        'pid': PID,
        'pid_starttime': 100,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    }
    state_file_dir, state_file, abs_state_file = create_state_file(tmpdir)
    state_loader = mocker.Mock(return_value=state)
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_UNKNOWN, None, 'procfs unavailable'))
    signal_proxy = mocker.patch(
        'watchdog.signal_stunnel_process_group_if_same')

    assert watchdog.clean_up_mount_state(
        state_file_dir, state_file, PID, False,
        state=state,
        state_loader=state_loader,
    ) is False

    signal_proxy.assert_not_called()
    assert os.path.exists(abs_state_file)


@pytest.mark.parametrize('group', [123, None])
def test_verified_proxy_termination_preserves_log(mocker, caplog, group):
    caplog.set_level(logging.INFO)
    state = {'pid': PID}
    mocker.patch('watchdog.signal_stunnel_process_group_if_same', return_value=group)
    mocker.patch('watchdog.probe_stunnel_process', return_value=watchdog.StunnelProbeResult(
        watchdog.STUNNEL_RUNNING, None, 'still running'))
    assert watchdog.clean_up_mount_state('/unused', 'state', PID, True, state=state) is False
    messages = [(r.levelno, r.getMessage()) for r in caplog.records
                if r.getMessage().startswith('Terminating running proxy - ')]
    assert messages == ([(logging.INFO,
        'Terminating running proxy - PID: %d, group ID: 123' % PID)] if group else [])
