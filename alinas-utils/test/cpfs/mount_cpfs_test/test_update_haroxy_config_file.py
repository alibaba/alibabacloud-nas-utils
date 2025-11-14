#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import cpfs_nfs_common

FS_ID = '105364000'
DNS_NAME = '105364000-123ab.cn-beijing.nas.aliyuncs.com'
MOUNT_POINT = '/mnt/test'
PROXY = "127.0.0.1"
PORT = 8888
VERIFY_LEVEL = 2
LOCAL_DNS = '{}.{}'.format(FS_ID, PROXY)

PRIMARY = '       server cpfs_primary {}:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'
BACKUP = '       server cpfs_backup  {}:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 backup'


def test_try_update_haproxy_config_line(mocker):
    old_primary_line = PRIMARY.format('10.10.2.233')
    new_primary_line = PRIMARY.format('10.10.2.234')
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_primary_line, cpfs_nfs_common.CPFS_PRIMARY, '10.10.2.23', '10.10.2.234')
    assert line == new_primary_line
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_primary_line, cpfs_nfs_common.CPFS_PRIMARY, '10.10.2.233', '10.10.2.234')
    assert line == new_primary_line
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_primary_line, cpfs_nfs_common.CPFS_BACKUP, '10.10.2.23', '10.10.2.234')
    assert line == old_primary_line

    old_backup_line = BACKUP.format('10.10.2.12')
    new_backup_line = BACKUP.format('10.10.2.123')
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_backup_line, cpfs_nfs_common.CPFS_BACKUP, '10.10.2.1', '10.10.2.123')
    assert line == new_backup_line
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_backup_line, cpfs_nfs_common.CPFS_BACKUP, '10.10.2.12', '10.10.2.123')
    assert line == new_backup_line
    line = cpfs_nfs_common.try_update_haproxy_config_line(old_backup_line, cpfs_nfs_common.CPFS_PRIMARY, '10.10.2.1', '10.10.2.123')
    assert line == old_backup_line
