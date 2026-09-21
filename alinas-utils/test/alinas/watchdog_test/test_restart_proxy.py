#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import process_probe
import json
import tempfile

PID = 1234


def test_restart_tls_tunnel(mocker, tmpdir):
    mocker.patch('watchdog.start_proxy', return_value=PID)
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_DEAD, None, 'test dead'))

    state = {
        'pid': 9999,
        'cmd': ''
    }

    state_file = tmpdir.join(tempfile.mktemp())
    state_file.write(json.dumps(state), ensure=True)

    watchdog.restart_proxy([], state, state_file.dirname, state_file.basename)

    assert PID == state['pid']

    with state_file.open() as f:
        new_state = json.load(f)

    assert PID == new_state['pid']


def test_restart_tls_tunnel_cancels_when_second_probe_finds_process(
        mocker, tmpdir):
    current = process_probe.ProcessIdentity(
        9999, 'S', 456, 'stunnel', '/usr/bin/stunnel')
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_RUNNING, current, 'test running'))
    start = mocker.patch('watchdog.start_proxy')
    state = {
        'pid': current.pid,
        'pid_starttime': current.starttime,
        'cmd': ['stunnel', '/tmp/stunnel.conf'],
    }

    assert watchdog.restart_proxy(
        [], state, str(tmpdir), 'state-file') is False

    start.assert_not_called()


def test_restart_tls_tunnel_cancels_when_probe_is_unknown(mocker):
    mocker.patch(
        'watchdog.probe_stunnel_process',
        return_value=watchdog.StunnelProbeResult(
            watchdog.STUNNEL_UNKNOWN, None, 'procfs unavailable'))
    start = mocker.patch('watchdog.start_proxy')

    assert watchdog.restart_proxy(
        [], {'pid': 9999, 'cmd': ['stunnel', '/tmp/stunnel.conf']},
        '/state', 'state-file') is False

    start.assert_not_called()
