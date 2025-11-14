#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import threading
import time

from mock import MagicMock
from mock import call

import watchdog

STATE_FILE = 'alinas-123456abc.127.0.0.1'


def _dump_state(tmpfile, state):
    state[watchdog.STATE_SIGN] = watchdog.sign_state(state)
    tmpfile.write(json.dumps(state))


def test_ping_nothing(mocker, tmpdir):
    statvfs_mock = mocker.patch('os.statvfs')
    _dump_state(tmpdir.join(STATE_FILE), {
        'timeo': 4,
        'mountpoint': '/mnt'
    })

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))

    try:
        detector.start()

        time.sleep(5)
        statvfs_mock.assert_not_called()
    finally:
        detector.stop()

        assert len(detector._volumes) == 0


def test_ping_default(mocker, tmpdir):
    statvfs_mock = mocker.patch('os.statvfs')
    _dump_state(tmpdir.join(STATE_FILE), {
        'timeo': 4,
        'mountpoint': '/mnt'
    })

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))

    try:
        detector.start()
        detector.refresh({STATE_FILE: None})

        time.sleep(6)
        assert statvfs_mock.call_count == 2

        statvfs_mock.assert_has_calls([call('/mnt'), call('/mnt')])
    finally:
        detector.stop()

        assert len(detector._volumes) == 1


def test_ping_multiple(mocker, tmpdir):
    state_file1 = 'state_file_1'
    state_file2 = 'state_file_2'

    statvfs_mock = mocker.patch('os.statvfs')
    _dump_state(tmpdir.join(state_file1), {'timeo': 4, 'mountpoint': '/a'})
    _dump_state(tmpdir.join(state_file2), {'timeo': 8, 'mountpoint': '/b'})

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))
    try:
        detector.start()
        detector.refresh({state_file1: None, state_file2: None})
        time.sleep(6)

        assert statvfs_mock.call_count == 3

        statvfs_mock.assert_has_calls([call('/a'), call('/b'), call('/a')])
    finally:
        detector.stop()

        assert len(detector._volumes) == 2


def test_ping_not_found(mocker, tmpdir):
    state_file = 'state_file_not_found'
    statvfs_mock = mocker.patch('os.statvfs')

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))
    try:
        detector.start()
        detector.refresh({state_file: None})
        time.sleep(5)

        statvfs_mock.assert_not_called()
    finally:
        detector.stop()

        assert len(detector._volumes) == 0


def _mock(mocker):
    return mocker.patch('time.time'), mocker.patch('os.statvfs')


def test_ping_refresh(mocker, tmpdir):
    _mock(mocker)

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))
    try:
        detector.start()

        detector._refresh()
        assert detector._pending_refresh is None
        assert len(detector._volumes) == 0
        assert detector._event_waiter.event_count() == 0
    finally:
        detector.stop()


def test_ping_refresh_add(mocker, tmpdir):
    time_mock, _ = _mock(mocker)
    load_mock = MagicMock(return_value={'timeo': 4, 'mountpoint': '/mnt'})

    time_mock.return_value = 10
    fm = watchdog.StateFileManager()
    fm.load_state_file = load_mock
    detector = watchdog.LiveDetector(MagicMock(), fm, str(tmpdir))
    try:
        detector.start()
        detector._pending_refresh = {'fs1': None, 'fs2': None}
        detector._refresh()

        assert load_mock.call_count == 2
        assert len(detector._volumes) == 2
        assert 'fs1' in detector._volumes
        assert 'fs2' in detector._volumes
        assert detector._event_waiter.event_count() == 2
    finally:
        detector.stop()


def test_ping_refresh_remove(mocker):
    _mock(mocker)

    fm = watchdog.StateFileManager()
    detector = watchdog.LiveDetector(MagicMock(), fm)
    try:
        detector.start()
        detector._volumes = {
            'fs1': None,
            'fs2': None
        }

        detector._refresh()
        assert len(detector._volumes) == 2

        detector._pending_refresh = {'fs1': 1}
        detector._refresh()
        assert len(detector._volumes) == 1
        assert detector._pending_refresh is None

        detector._pending_refresh = {}
        detector._refresh()
        assert len(detector._volumes) == 0
        assert detector._pending_refresh is None
    finally:
        detector.stop()
