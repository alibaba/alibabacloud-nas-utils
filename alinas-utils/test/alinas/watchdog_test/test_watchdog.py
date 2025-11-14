#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

from mock import MagicMock
from watchdog import SafeConfig


def test_watchdog_start(mocker, tmpdir):
    detector = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    config = SafeConfig({}, None, None)

    wd = watchdog.MountWatchdog(config, str(tmpdir))
    wd.start()

    detector.start.assert_called_once()


def test_watchdog_stop(mocker, tmpdir):
    detector = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    config = SafeConfig({}, None, None)

    wd = watchdog.MountWatchdog(config, str(tmpdir))
    wd.stop()

    detector.stop.assert_called_once()


def test_watchdog_handle_event(mocker, tmpdir):
    detector = MagicMock()
    mocker.patch('watchdog.LiveDetector', return_value=detector)
    config = SafeConfig({}, None, None)

    wd = watchdog.MountWatchdog(config, str(tmpdir))

    wd.handle_events('nfsmount')

    detector.refresh.assert_called_once()
    detector.refresh.assert_called_with('nfsmount')
