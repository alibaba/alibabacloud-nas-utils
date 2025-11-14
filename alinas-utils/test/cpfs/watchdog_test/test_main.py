#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
from configparser import ConfigParser

import watchdog
import cpfs_nfs_common

import pytest
import mock


def _test_main(mocker, root=True):
    if root:
        mocker.patch('os.geteuid', return_value=0)
    else:
        mocker.patch('os.geteuid', return_value=100)

    config = ConfigParser()
    config.add_section(watchdog.WATCHDOG_CONFIG_SECTION)
    config.set(watchdog.WATCHDOG_CONFIG_SECTION, 'poll_interval_sec', '10')
    config.set(watchdog.WATCHDOG_CONFIG_SECTION, 'unmount_grace_period_sec', '20')
    config = cpfs_nfs_common.SafeConfig(config, None, None)

    parse_argument_mock = mocker.patch('watchdog.parse_arguments')
    read_config_mock = mocker.patch('cpfs_nfs_common.read_config', return_value=config)
    bootstrap_logging_mock = mocker.patch('cpfs_nfs_common.bootstrap_logging')
    check_alinas_mounts_mock = mocker.patch('watchdog.check_alinas_mounts')
    check_child_procs_mock = mocker.patch('watchdog.check_child_procs')
    sleep_mocker = mocker.patch('time.sleep', side_effect=SystemExit())
    detector = mock.MagicMock()
    detector_mock = mocker.patch('watchdog.LiveDetector', return_value=detector)

    if root:
        with pytest.raises(SystemExit) as _:
            watchdog.main()

        detector.stop.assert_called_once()
        detector_mock.assert_called_once()
        parse_argument_mock.assert_called_once()
        read_config_mock.assert_called_once()
        bootstrap_logging_mock.assert_called_once()

        check_alinas_mounts_mock.assert_called_once()
        check_child_procs_mock.assert_called_once()
        sleep_mocker.assert_called_with(10)
    else:
        watchdog.main()


def test_main_default(mocker):
    _test_main(mocker)


def test_main_non_root(mocker, capsys):
    with pytest.raises(SystemExit) as ex:
        _test_main(mocker, root=False)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'only root' in err
