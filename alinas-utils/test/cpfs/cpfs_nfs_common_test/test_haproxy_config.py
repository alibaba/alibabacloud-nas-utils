#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import os
import tempfile

import cpfs_nfs_common


PRIMARY_2049 = '   server cpfs_primary 10.10.2.233:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'
BACKUP_2049 = '   server cpfs_backup  10.10.2.12:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 backup'
PRIMARY_60000 = '   server cpfs_primary 10.10.2.233:60000 maxconn 2048 check port 60000 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'
BACKUP_60000 = '   server cpfs_backup  10.10.2.12:60000 maxconn 2048 check port 60000 inter 2s fall 8 rise 30 backup'


def test_parse_haproxy_server_host():
    assert cpfs_nfs_common.parse_haproxy_server_host(PRIMARY_2049, 'cpfs_primary') == '10.10.2.233'
    assert cpfs_nfs_common.parse_haproxy_server_host(BACKUP_2049, 'cpfs_backup') == '10.10.2.12'
    assert cpfs_nfs_common.parse_haproxy_server_host(PRIMARY_60000, 'cpfs_primary') == '10.10.2.233'
    assert cpfs_nfs_common.parse_haproxy_server_host(BACKUP_60000, 'cpfs_backup') == '10.10.2.12'
    assert cpfs_nfs_common.parse_haproxy_server_host(PRIMARY_2049, 'cpfs_backup') is None
    assert cpfs_nfs_common.parse_haproxy_server_host('backend bk2049', 'cpfs_primary') is None


def test_get_mount_port_from_haproxy_config():
    tmpdir = tempfile.mkdtemp()
    config_path = os.path.join(tmpdir, 'haproxy-config.test-domain')
    try:
        with open(config_path, 'w') as f:
            f.write('backend bk2049\n')
            f.write(PRIMARY_60000 + '\n')
            f.write(BACKUP_60000 + '\n')
        assert cpfs_nfs_common.get_mount_port_from_haproxy_config(config_path) == 60000

        with open(config_path, 'w') as f:
            f.write('backend bk2049\n')
            f.write(PRIMARY_2049 + '\n')
            f.write(BACKUP_2049 + '\n')
        assert cpfs_nfs_common.get_mount_port_from_haproxy_config(config_path) == 2049
    finally:
        os.unlink(config_path)
        os.rmdir(tmpdir)
