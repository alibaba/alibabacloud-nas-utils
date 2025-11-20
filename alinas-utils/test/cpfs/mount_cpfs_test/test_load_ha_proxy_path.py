#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import tempfile
from pathlib import Path

def generate_apparmor_hp_profile(generateData) -> Path:
    temp_dir = tempfile.mkdtemp()
    apparmor_file = Path(temp_dir) / "usr.sbin.haproxy"
    if generateData:
        config = """#include <tunables/global>

    profile haproxy /usr/sbin/haproxy {
    #include <abstractions/base>
    #include <abstractions/openssl>
    #include <abstractions/ssl_certs>
    #include <abstractions/ssl_keys>
    #include <abstractions/nameservice>
    capability net_bind_service,
    capability setgid,
    capability setuid,
    capability kill,
    capability sys_resource,
    capability sys_chroot,
    capability net_admin,

    # those are needed for the stats socket creation
    capability chown,
    capability fowner,
    capability fsetid,

    network inet,
    network inet6,

    /etc/haproxy/* r, 

    /usr/sbin/haproxy rmix,

    /var/lib/haproxy/stats rwl,
    /var/lib/haproxy/stats.*.bak rwl,
    /var/lib/haproxy/stats.*.tmp rwl,
    /{,var/}run/haproxy.pid rw,
    /{,var/}run/haproxy-master.sock* rwlk,

    # Site-specific additions and overrides. See local/README for details.
    #include if exists <local/haproxy>
    #include if exists <local/usr.sbin.haproxy>
    }"""
        apparmor_file.write_text(config)
    return apparmor_file

def test_load_ha_proxy_path_from_input():
    input = '/etc/hp_config_dir_input'
    options = {'hp_config_dir': input }
    hp_config_dir = mount_cpfs.load_ha_proxy_path(options, str(generate_apparmor_hp_profile(True)), '/var/run/cpfs')
    assert hp_config_dir == input

def test_load_ha_proxy_path_from_ha_profile():
    options = {}
    hp_config_dir = mount_cpfs.load_ha_proxy_path(options, str(generate_apparmor_hp_profile(True)), '/var/run/cpfs')
    assert hp_config_dir == '/etc/haproxy/'

def test_load_ha_proxy_path_from_defaultvalue():
    options = {}
    hp_config_dir = mount_cpfs.load_ha_proxy_path(options, str(generate_apparmor_hp_profile(False)), '/var/run/cpfs')
    assert hp_config_dir == '/var/run/cpfs'