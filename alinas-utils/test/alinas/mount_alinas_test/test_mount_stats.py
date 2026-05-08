#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas
import pytest
from mock import MagicMock
import time


class TestMountStats(object):
    """Test cases for mount statistics functions."""

    def teardown_method(self, method):
        """Clean up after each test method."""
        mount_alinas.stat_timestamps.clear()

    def test_init_mount_stats(self, mocker):
        """Test init_mount_stats initializes the statistics dictionary."""
        # Setup: pre-populate stat_timestamps with some data
        mount_alinas.stat_timestamps['old_key'] = 12345.0
        
        # Execute
        mount_alinas.init_mount_stats()
        
        # Verify
        assert 'total_start_time' in mount_alinas.stat_timestamps
        assert 'old_key' not in mount_alinas.stat_timestamps
        assert isinstance(mount_alinas.stat_timestamps['total_start_time'], float)
        # The timestamp should be close to current time (within 1 second)
        current_time = time.time()
        assert abs(mount_alinas.stat_timestamps['total_start_time'] - current_time) < 1.0

    def test_record_mount_stat(self, mocker):
        """Test record_mount_stat records timestamp for a given key."""
        # Setup
        test_key = 'test_key'
        mock_time = mocker.patch('mount_alinas.time.time', return_value=12345.678)
        
        # Execute
        mount_alinas.record_mount_stat(test_key)
        
        # Verify
        assert test_key in mount_alinas.stat_timestamps
        assert mount_alinas.stat_timestamps[test_key] == 12345.678
        mock_time.assert_called_once()

    def test_record_mount_stat_multiple_keys(self, mocker):
        """Test record_mount_stat can record multiple keys."""
        # Setup
        mock_time = mocker.patch('mount_alinas.time.time')
        mock_time.side_effect = [100.0, 200.0, 300.0]
        
        # Execute
        mount_alinas.record_mount_stat('key1')
        mount_alinas.record_mount_stat('key2')
        mount_alinas.record_mount_stat('key3')
        
        # Verify
        assert mount_alinas.stat_timestamps['key1'] == 100.0
        assert mount_alinas.stat_timestamps['key2'] == 200.0
        assert mount_alinas.stat_timestamps['key3'] == 300.0
        assert mock_time.call_count == 3

    def test_complete_mount_stats_success(self, mocker, capsys):
        """Test complete_mount_stats calculates and logs all delays correctly."""
        # Set up timestamps with realistic values (in seconds)
        mount_alinas.stat_timestamps['total_start_time'] = 1000.0
        mount_alinas.stat_timestamps['stunnel_start_time'] = 1000.5  # 500ms later
        mount_alinas.stat_timestamps['proxy_ready_time'] = 1001.0    # 500ms later
        mount_alinas.stat_timestamps['nfs_mount_end_time'] = 1001.3  # 300ms later
        
        # Create mock context
        ctx = MagicMock()
        ctx.dns = 'test-fs.cn-beijing.nas.aliyuncs.com'
        ctx.mountpoint = '/mnt/test'
        
        mock_logging = mocker.patch('mount_alinas.logging.info')

        # Execute
        mount_alinas.complete_mount_stats(ctx)
        
        # Verify logging was called
        mock_logging.assert_called_once()
        call_args = mock_logging.call_args
        
        # Verify the log message format - call_args[0] contains positional args
        # The first arg is the format string, remaining args are the format values
        format_string = call_args[0][0]
        format_args = call_args[0][1:]
        
        # Verify format arguments
        # format_args should be: ('tls', ctx.dns, ctx.mountpoint, prep_delay, stunnel_delay, nfs_delay, total_delay)
        assert format_args[0] == 'test-fs.cn-beijing.nas.aliyuncs.com'
        assert format_args[1] == '/mnt/test'
        
        # Verify calculated delays (converted to milliseconds)
        # preparation: (1000.5 - 1000.0) * 1000 = 500.0
        # stunnel_startup: (1001.0 - 1000.5) * 1000 = 500.0
        # nfs_mount: (1001.3 - 1001.0) * 1000 = 300.0
        # total: (1001.3 - 1000.0) * 1000 = 1300.0
        assert abs(format_args[2] - 500.0) < 0.001  # preparation
        assert abs(format_args[3] - 500.0) < 0.001  # stunnel_startup
        assert abs(format_args[4] - 300.0) < 0.001  # nfs_mount
        assert abs(format_args[5] - 1300.0) < 0.001  # total

    def test_complete_mount_stats_missing_nfs_mount_end_time(self, mocker):
        """Test complete_mount_stats returns early if nfs_mount_end_time is missing."""
        # Setup
        mount_alinas.stat_timestamps['total_start_time'] = 1000.0
        mount_alinas.stat_timestamps['stunnel_start_time'] = 1000.5
        mount_alinas.stat_timestamps['proxy_ready_time'] = 1001.0
        # Note: nfs_mount_end_time is NOT set
        
        ctx = MagicMock()
        ctx.dns = 'test-fs.cn-beijing.nas.aliyuncs.com'
        ctx.mountpoint = '/mnt/test'
        
        mocker.patch('mount_alinas.logging.info')
        # Execute
        mount_alinas.complete_mount_stats(ctx)
        
        # Verify logging was NOT called
        mount_alinas.logging.info.assert_not_called()
