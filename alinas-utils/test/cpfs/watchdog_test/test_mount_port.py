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

import watchdog


PRIMARY_60000 = '   server cpfs_primary 10.10.2.233:60000 maxconn 2048 check port 60000 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions'


def test_get_mount_port_from_config():
    tmpdir = tempfile.mkdtemp()
    config_path = os.path.join(tmpdir, 'haproxy-config.test-domain')
    try:
        with open(config_path, 'w') as f:
            f.write('backend bk2049\n')
            f.write(PRIMARY_60000 + '\n')
        assert watchdog._get_mount_port_from_config(config_path) == 60000
    finally:
        os.unlink(config_path)
        os.rmdir(tmpdir)
