#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import os
import subprocess
import time

try:
    from unittest.mock import MagicMock, Mock, patch
except ImportError:
    from mock import MagicMock, Mock, patch

import watchdog
import cpfs_nfs_common

STATE_FILE = 'cpfs-123456abc.cn-hangzhou.cpfs.aliyuncs.com'
LOCAL_DNS = 'cpfs-123456abc.cn-hangzhou.cpfs.aliyuncs.com'


def _dump_state(tmpfile, state):
    state[watchdog.STATE_SIGN] = cpfs_nfs_common.sign_state(state)
    tmpfile.write(json.dumps(state))


def _make_config():
    """创建模拟配置"""
    config = Mock()
    config.getint = Mock(side_effect=lambda section, key, **kwargs: {
        'zombie_session_threshold_sec': 5,
        'zombie_session_restart_interval_sec': 70
    }.get(key, kwargs.get('default', 5)))
    return config


class TestDetectZombieSessions:
    """测试僵尸 session 检测逻辑"""

    def test_detect_zombie_sessions_with_zombies(self):
        """测试检测到僵尸 session（前端 EST + 后端 CLO + 无超时）- 单行格式"""
        # 模拟 show sess 输出：两个僵尸 session（单行格式）
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3 c_exp=
0x7f0a8c02ebe1: proto=tcpv4 src=127.0.0.1:36871 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,11100h,fd=42,rex=,wex=] scb=[10,22005h,fd=43,rex=,wex=] exp= rc=3 c_exp=
"""

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            config = _make_config()
            detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
            count = detector.detect_zombie_sessions('/var/run/cpfs/haproxy-test.sock')
            assert count == 2

    def test_detect_zombie_sessions_no_zombies(self):
        """测试没有僵尸 session（正常 session：前端 EST + 后端 EST）- 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0 age=20631d1h calls=4568 rate=0 cpu=0 lat=0 rq[f=848101h,i=0,an=00h,ax=] rp[f=80048101h,i=0,an=00h,ax=] scf=[8,0h,fd=42,rex=44s,wex=] scb=[8,1h,fd=43,rex=44s,wex=] exp=20s rc=0 c_exp=
"""

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            config = _make_config()
            detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
            count = detector.detect_zombie_sessions('/var/run/cpfs/haproxy-test.sock')
            assert count == 0  # 后端也是 EST，不是僵尸

    def test_detect_zombie_sessions_normal_closing(self):
        """测试正常关闭中的 session（前端 EST + 后端 CLO + 有超时）- 单行格式"""
        # 正常关闭中的 session 有超时，不应该被识别为僵尸
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp=30s rc=3 c_exp=
"""

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            config = _make_config()
            detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
            count = detector.detect_zombie_sessions('/var/run/cpfs/haproxy-test.sock')
            assert count == 0  # 有 exp 超时值，不是僵尸

    def test_detect_zombie_sessions_all_closed(self):
        """测试已关闭的 session（前端 CLO + 后端 CLO）- 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[10,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3 c_exp=
"""

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            config = _make_config()
            detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
            count = detector.detect_zombie_sessions('/var/run/cpfs/haproxy-test.sock')
            assert count == 0  # 前端也是 CLO，不是僵尸

    def test_detect_zombie_sessions_exception(self):
        """测试检测异常情况"""
        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          side_effect=Exception('socket not found')):
            config = _make_config()
            detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
            count = detector.detect_zombie_sessions('/var/run/cpfs/nonexistent.sock')
            assert count == 0  # 异常时返回 0


class TestParseSessionFields:
    """测试解析 session 字段（兼容单行和多行格式）"""

    def test_parse_single_line_format(self):
        """测试单行格式解析"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {}
        line = "0x7f0a8c02ebe0: proto=tcpv4 scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3"
        detector._parse_session_fields(line, session_info)

        assert session_info['scf_state'] == 8
        assert session_info['scb_state'] == 10
        assert session_info['exp_empty'] is True

    def test_parse_single_line_format_with_timeout(self):
        """测试单行格式带超时值"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {}
        line = "0x7f0a8c02ebe0: proto=tcpv4 scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp=30s rc=3"
        detector._parse_session_fields(line, session_info)

        assert session_info['scf_state'] == 8
        assert session_info['scb_state'] == 10
        assert session_info['exp_empty'] is False

    def test_parse_multi_line_format(self):
        """测试多行格式解析"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {}

        # 模拟多行格式的每一行
        detector._parse_session_fields('scf=[8,14200h,fd=40,rex=,wex=]', session_info)
        detector._parse_session_fields('scb=[10,34005h,fd=41,rex=,wex=]', session_info)
        detector._parse_session_fields('exp=', session_info)

        assert session_info['scf_state'] == 8
        assert session_info['scb_state'] == 10
        assert session_info['exp_empty'] is True


class TestParseScState:
    """测试解析 stconn state"""

    def test_parse_sc_state_est(self):
        """测试解析 EST state (8)"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        state = detector._parse_sc_state('scf=[8,14200h,fd=40,rex=,wex=]')
        assert state == 8

    def test_parse_sc_state_clo(self):
        """测试解析 CLO state (10)"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        state = detector._parse_sc_state('scb=[10,34005h,fd=41,rex=,wex=]')
        assert state == 10

    def test_parse_sc_state_invalid(self):
        """测试无效格式"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        state = detector._parse_sc_state('invalid line')
        assert state is None


class TestIsZombieSession:
    """测试判断僵尸 session"""

    def test_is_zombie_true(self):
        """测试真正的僵尸 session"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {
            'scf_state': 8,   # 前端 EST
            'scb_state': 10,  # 后端 CLO
            'exp_empty': True # 无超时
        }
        assert detector._is_zombie_session(session_info) is True

    def test_is_zombie_false_with_timeout(self):
        """测试有超时的 session（不是僵尸）"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {
            'scf_state': 8,
            'scb_state': 10,
            'exp_empty': False  # 有超时
        }
        assert detector._is_zombie_session(session_info) is False

    def test_is_zombie_false_backend_est(self):
        """测试后端 EST（不是僵尸）"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {
            'scf_state': 8,
            'scb_state': 8,   # 后端也是 EST
            'exp_empty': True
        }
        assert detector._is_zombie_session(session_info) is False

    def test_is_zombie_false_frontend_clo(self):
        """测试前端 CLO（不是僵尸）"""
        config = _make_config()
        detector = watchdog.ZombieSessionDetector(config, Mock(), Mock())
        session_info = {
            'scf_state': 10,  # 前端 CLO
            'scb_state': 10,
            'exp_empty': True
        }
        assert detector._is_zombie_session(session_info) is False


class TestCheckAllHaproxy:
    """测试检查所有 HAProxy 实例"""

    def test_no_zombies_no_restart(self, tmpdir):
        """测试没有僵尸 session 时不触发重启 - 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0 age=20631d1h calls=4568 rate=0 cpu=0 lat=0 rq[f=848101h,i=0,an=00h,ax=] rp[f=80048101h,i=0,an=00h,ax=] scf=[8,0h,fd=42,rex=44s,wex=] scb=[8,1h,fd=43,rex=44s,wex=] exp=20s rc=0 c_exp=
"""
        socket_path = str(tmpdir.join('haproxy-test.sock'))
        with open(socket_path, 'w') as f:
            f.write('')

        state = {
            'stats_socket': socket_path,
            'pid': 12345
        }
        _dump_state(tmpdir.join(STATE_FILE), state)

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            config = _make_config()
            eventbus = watchdog.EventBus()
            fm = cpfs_nfs_common.StateFileManager()
            wd = Mock()
            wd.load_state_file = fm.load_state_file

            detector = watchdog.ZombieSessionDetector(config, eventbus, wd, str(tmpdir))
            detector._check_all_haproxy()

            cmds = eventbus.fetch_and_remove()
            assert len(cmds) == 0

    def test_zombies_trigger_restart(self, tmpdir):
        """测试僵尸 session 超过阈值触发重启 - 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3 c_exp=
"""
        socket_path = str(tmpdir.join('haproxy-test.sock'))
        with open(socket_path, 'w') as f:
            f.write('')

        state = {
            'stats_socket': socket_path,
            'pid': 12345
        }
        _dump_state(tmpdir.join(STATE_FILE), state)

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            with patch('time.time', return_value=100):
                config = _make_config()
                eventbus = watchdog.EventBus()
                fm = cpfs_nfs_common.StateFileManager()
                wd = Mock()
                wd.load_state_file = fm.load_state_file

                detector = watchdog.ZombieSessionDetector(config, eventbus, wd, str(tmpdir))
                detector._zombie_detected_time[LOCAL_DNS] = 90  # 10秒前检测
                detector._check_all_haproxy()

                cmds = eventbus.fetch_and_remove()
                assert len(cmds) == 1
                assert isinstance(cmds[0], watchdog.RestartCommand)

    def test_restart_interval_not_elapsed(self, tmpdir):
        """测试重启间隔未过，不再次触发重启 - 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3 c_exp=
"""
        socket_path = str(tmpdir.join('haproxy-test.sock'))
        with open(socket_path, 'w') as f:
            f.write('')

        # 状态文件包含 last_zombie_restart_time（30秒前重启）
        state = {
            'stats_socket': socket_path,
            'pid': 12345,
            'last_zombie_restart_time': 70
        }
        _dump_state(tmpdir.join(STATE_FILE), state)

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            with patch('time.time', return_value=100):
                config = _make_config()
                eventbus = watchdog.EventBus()
                fm = cpfs_nfs_common.StateFileManager()
                wd = Mock()
                wd.load_state_file = fm.load_state_file

                detector = watchdog.ZombieSessionDetector(config, eventbus, wd, str(tmpdir))
                detector._zombie_detected_time[LOCAL_DNS] = 95
                detector._check_all_haproxy()

                cmds = eventbus.fetch_and_remove()
                assert len(cmds) == 0  # 重启间隔未过

    def test_restart_time_saved_to_state(self, tmpdir):
        """测试重启时间保存到状态文件 - 单行格式"""
        mock_output = """0x7f0a8c02ebe0: proto=tcpv4 src=127.0.0.1:36870 fe=cpfs2049 be=bk2049 srv=cpfs_primary ts=00 epoch=0x6 age=20631d1h calls=10 rate=0 cpu=0 lat=0 rq[f=808000h,i=0,an=00h,ax=] rp[f=80000000h,i=0,an=00h,ax=] scf=[8,14200h,fd=40,rex=,wex=] scb=[10,34005h,fd=41,rex=,wex=] exp= rc=3 c_exp=
"""
        socket_path = str(tmpdir.join('haproxy-test.sock'))
        with open(socket_path, 'w') as f:
            f.write('')

        state = {
            'stats_socket': socket_path,
            'pid': 12345
        }
        _dump_state(tmpdir.join(STATE_FILE), state)

        with patch.object(watchdog.ZombieSessionDetector, '_query_stats_socket',
                          return_value=mock_output):
            with patch('time.time', return_value=100):
                config = _make_config()
                eventbus = watchdog.EventBus()
                fm = cpfs_nfs_common.StateFileManager()
                wd = Mock()
                wd.load_state_file = fm.load_state_file

                detector = watchdog.ZombieSessionDetector(config, eventbus, wd, str(tmpdir))
                detector._zombie_detected_time[LOCAL_DNS] = 90
                detector._check_all_haproxy()

                saved_state = fm.load_state_file(str(tmpdir), STATE_FILE)
                assert 'last_zombie_restart_time' in saved_state
                assert saved_state['last_zombie_restart_time'] == 100