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
import cpfs_nfs_tool.switch_server as switch_server


PRIMARY_2049 = '   server cpfs_primary 10.10.2.233:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'
BACKUP_2049 = '   server cpfs_backup  10.10.2.12:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 backup'
PRIMARY_60000 = '   server cpfs_primary 10.10.2.233:60000 maxconn 2048 check port 60000 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'
BACKUP_60000 = '   server cpfs_backup  10.10.2.12:60000 maxconn 2048 check port 60000 inter 2s fall 8 rise 30 backup'


def test_get_haproxy_server():
    tmpdir = tempfile.mkdtemp()
    config_path = os.path.join(tmpdir, 'haproxy-config.test-domain')
    try:
        with open(config_path, 'w') as f:
            f.write('backend bk2049\n')
            f.write(PRIMARY_60000 + '\n')
            f.write(BACKUP_60000 + '\n')

        orig = switch_server.cpfs_nfs_common.get_haproxy_config_file_path
        switch_server.cpfs_nfs_common.get_haproxy_config_file_path = lambda *args, **kwargs: config_path
        try:
            primary, backup = switch_server.get_haproxy_server('test-domain')
            assert primary == '10.10.2.233'
            assert backup == '10.10.2.12'
        finally:
            switch_server.cpfs_nfs_common.get_haproxy_config_file_path = orig
    finally:
        os.unlink(config_path)
        os.rmdir(tmpdir)


def test_check_arguments_uses_mount_port_from_config(mocker):
    tmpdir = tempfile.mkdtemp()
    config_path = os.path.join(tmpdir, 'haproxy-config.test-domain')
    try:
        with open(config_path, 'w') as f:
            f.write('backend bk2049\n')
            f.write(PRIMARY_60000 + '\n')
            f.write(BACKUP_60000 + '\n')

        orig = cpfs_nfs_common.get_haproxy_config_file_path
        cpfs_nfs_common.get_haproxy_config_file_path = lambda *args, **kwargs: config_path
        is_server_ready_mock = mocker.patch('cpfs_nfs_common.is_server_ready', return_value=True)
        try:
            class Args(object):
                domain = '105364000-123ab.cn-beijing.cpfs.aliyuncs.com'
                old_primary_server = '10.10.2.233'
                old_backup_server = '10.10.2.12'
                new_primary_server = '10.10.2.234'
                new_backup_server = '10.10.2.123'
            switch_server.check_arguments(Args())
            is_server_ready_mock.assert_any_call('10.10.2.234', 60000)
            is_server_ready_mock.assert_any_call('10.10.2.123', 60000)
        finally:
            cpfs_nfs_common.get_haproxy_config_file_path = orig
    finally:
        os.unlink(config_path)
        os.rmdir(tmpdir)
