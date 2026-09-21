#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import os
import tempfile

import mount_cpfs


def _write_profile(content):
    fd, path = tempfile.mkstemp(suffix='.haproxy')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise
    return path


# ---------------------------------------------------------------------------
# get_apparmor_writable_dir
# ---------------------------------------------------------------------------

def test_writable_dir_detects_rw():
    profile = _write_profile('/var/lib/haproxy/* rw,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/var/lib/haproxy/*'


def test_writable_dir_detects_rwl():
    profile = _write_profile('/var/lib/haproxy/stats* rwl,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/var/lib/haproxy/stats*'


def test_writable_dir_detects_rwlk():
    profile = _write_profile('/var/lib/haproxy/haproxy-master.sock* rwlk,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/var/lib/haproxy/haproxy-master.sock*'


def test_writable_dir_detects_star_in_middle():
    profile = _write_profile('/var/lib/haproxy/stats.*.bak rwl,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/var/lib/haproxy/stats.*.bak'


def test_writable_dir_detects_alternation():
    profile = _write_profile('/{,usr/}local/haproxy/* rwlk,\n')
    # First expansion is /local/haproxy/*, which is not excluded.
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/local/haproxy/*'


def test_writable_dir_ignores_deny():
    profile = _write_profile('deny /var/lib/haproxy/* w,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_ignores_audit_deny():
    profile = _write_profile('audit deny /var/lib/haproxy/* rw,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_ignores_write_only():
    # 'w' alone is not enough; the socket must also be readable.
    profile = _write_profile('/var/lib/haproxy/* w,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_ignores_read_only():
    # 'r' alone is not enough; haproxy must be able to create the socket.
    profile = _write_profile('/var/lib/haproxy/* r,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_ignores_write_link_only():
    # 'wl' has write but no read, so it is not enough.
    profile = _write_profile('/var/lib/haproxy/* wl,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_ignores_read_link_only():
    # 'rl' has read but no write, so haproxy cannot create the socket.
    profile = _write_profile('/var/lib/haproxy/* rl,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None

def test_writable_dir_ignores_comments():
    profile = _write_profile('# /var/lib/haproxy/* rw,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) is None


def test_writable_dir_excludes_system_dirs():
    for path in ('/sys/firmware/*', '/proc/sys/fs/*', '/dev/shm/*',
                 '/run/systemd/*', '/tmp/haproxy/*', '/var/tmp/haproxy/*'):
        profile = _write_profile('%s rw,\n' % path)
        assert mount_cpfs.get_apparmor_writable_dir(profile) is None, path


def test_writable_dir_alternation_skips_excluded_and_keeps_valid():
    # /run/ is excluded, but /var/run/ is valid, so the latter should be selected.
    profile = _write_profile('/{,var/}run/haproxy.sock* rwlk,\n')
    assert mount_cpfs.get_apparmor_writable_dir(profile) == '/var/run/haproxy.sock*'


def test_writable_dir_missing_profile_returns_none():
    assert mount_cpfs.get_apparmor_writable_dir('/non/existent/profile') is None


# ---------------------------------------------------------------------------
# construct_path_from_pattern
# ---------------------------------------------------------------------------

HASH = 'a1b2c3d4'


def test_construct_path_simple_star():
    assert mount_cpfs.construct_path_from_pattern('/var/lib/haproxy/*', HASH) == \
        '/var/lib/haproxy/haproxy-a1b2c3d4.sock'


def test_construct_path_star_with_suffix():
    assert mount_cpfs.construct_path_from_pattern('/var/lib/haproxy/*.sock', HASH) == \
        '/var/lib/haproxy/haproxy-a1b2c3d4.sock'


def test_construct_path_star_in_middle_with_dot_prefix():
    assert mount_cpfs.construct_path_from_pattern('/var/lib/haproxy/stats.*.bak', HASH) == \
        '/var/lib/haproxy/stats.haproxy-a1b2c3d4.bak'


def test_construct_path_star_in_middle_without_dot_prefix():
    assert mount_cpfs.construct_path_from_pattern('/path/file*.txt', HASH) == \
        '/path/file-haproxy-a1b2c3d4.txt'


def test_construct_path_expands_alternation():
    result = mount_cpfs.construct_path_from_pattern('/{,var/}run/haproxy-master.sock*', HASH)
    assert '{,var/}' not in result
    assert result == '/run/haproxy-master.sock-haproxy-a1b2c3d4'


def test_construct_path_no_wildcard():
    assert mount_cpfs.construct_path_from_pattern('/var/lib/haproxy', HASH) == \
        '/var/lib/haproxy/haproxy-a1b2c3d4.sock'


def test_construct_path_multiple_wildcards():
    assert mount_cpfs.construct_path_from_pattern('/var/lib/haproxy/**', HASH) == \
        '/var/lib/haproxy/haproxy-a1b2c3d4.sock'


def test_construct_path_multiple_wildcards_with_exact_suffix():
    # /var/lib/*/*.sock should place the socket in /var/lib/, not /var/lib/*/
    assert mount_cpfs.construct_path_from_pattern('/var/lib/*/*.sock', HASH) == \
        '/var/lib/haproxy-a1b2c3d4.sock'


# ---------------------------------------------------------------------------
# get_haproxy_socket_name
# ---------------------------------------------------------------------------

def test_get_haproxy_socket_name_uses_apparmor_writable_dir(monkeypatch):
    import hashlib

    dns = 'cpfs-12345.cn-hangzhou.cpfs.aliyuncs.com'
    hash_str = hashlib.md5(dns.encode('utf-8')).hexdigest()[:8]

    tmp_dir = tempfile.mkdtemp()
    writable_pattern = os.path.join(tmp_dir, 'haproxy', '*')

    monkeypatch.setattr(mount_cpfs, 'get_apparmor_writable_dir',
                        lambda profile_path: writable_pattern)

    socket_path = mount_cpfs.get_haproxy_socket_name(
        dns,
        options={},
        state_file_dir='/var/run/cpfs',
        apparmor_profile_path='/fake/profile')

    expected = os.path.join(tmp_dir, 'haproxy', 'haproxy-%s.sock' % hash_str)
    assert socket_path == expected
    assert os.path.isdir(os.path.dirname(socket_path))


# ---------------------------------------------------------------------------
# load_ha_proxy_path
# ---------------------------------------------------------------------------

def test_load_ha_proxy_path_does_not_corrupt_conf_suffix():
    profile = _write_profile('/etc/haproxy/*.conf r,\n')
    result = mount_cpfs.load_ha_proxy_path({}, profile, '/var/run/cpfs')
    assert result == '/etc/haproxy/'
