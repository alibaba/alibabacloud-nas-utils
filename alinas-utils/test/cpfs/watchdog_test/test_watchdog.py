#
# Copyright 2017-2019 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

from mock import MagicMock


def test_watchdog_start(mocker, tmpdir):
    detector = MagicMock()
    refresher = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    mocker.patch('watchdog.DnsRefresher', return_value=refresher)

    wd = watchdog.MountWatchdog('config', str(tmpdir))
    wd.start()

    detector.start.assert_called_once()
    refresher.start.assert_called_once()


def test_watchdog_stop(mocker, tmpdir):
    detector = MagicMock()
    refresher = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    mocker.patch('watchdog.DnsRefresher', return_value=refresher)

    wd = watchdog.MountWatchdog('config', str(tmpdir))
    wd.stop()

    detector.stop.assert_called_once()
    refresher.stop.assert_called_once()


def test_watchdog_handle_event(mocker, tmpdir):
    detector = MagicMock()
    refresher = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    mocker.patch('watchdog.DnsRefresher', return_value=refresher)
    logging_mock = mocker.patch('logging.exception')

    wd = watchdog.MountWatchdog('config', str(tmpdir))

    cmd1 = MagicMock()
    cmd2 = MagicMock()
    cmd2.run.side_effect = RuntimeError
    wd._eventbus.append(cmd1)
    wd._eventbus.append(cmd2)
    wd.handle_events('nfsmount')

    detector.refresh.assert_called_once()
    detector.refresh.assert_called_with('nfsmount')

    assert len(wd._eventbus) == 0
    cmd1.run.assert_called_once()
    cmd1.run.assert_called_with('nfsmount', wd)
    cmd2.run.assert_called_once()
    cmd2.run.assert_called_with('nfsmount', wd)
    logging_mock.assert_called_once()
