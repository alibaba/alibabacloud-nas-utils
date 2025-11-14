#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import json
import os

FS_ID = 'fs-deadbeef'
PID = 1234
PROXY = '127.0.0.1'
LOCAL_DNS = '{}-{}'.format(FS_ID, PROXY)
COMMAND = ['stunnel', '/some/config/file']
FILES = ['/tmp/foo', '/tmp/bar']
MNT = '/mnt/a'
NAS_DNS = 'www.baidu.com'
NAS_IP = '8.8.8.8'
CONFIG_FILE = 'alinas.config'
PORT = 30000

def test_write_state_file(mocker, tmpdir):
    state_file_dir = str(tmpdir)

    mocker.patch('mount_cpfs.resolve_dns', return_value=NAS_IP)
    ctx = mount_cpfs.MountContext('config', 'init', NAS_DNS, 'fs_id', 'path', MNT, {'proxy': PROXY, 'nas_ip': NAS_IP, 'backup_ip': NAS_IP, 'proxy_port': PORT})
    state_file = mount_cpfs.write_state_file(LOCAL_DNS,
                                               ctx,
                                               PID,
                                               COMMAND,
                                               CONFIG_FILE,
                                               FILES,
                                               state_file_dir)

    assert state_file == '~' + LOCAL_DNS
    assert os.path.exists(state_file_dir)

    state_file = os.path.join(state_file_dir, state_file)
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)

    assert PID == state.get('pid')
    assert COMMAND == state.get('cmd')
    assert CONFIG_FILE == state.get('config_file')
    assert FILES == state.get('files')
    assert LOCAL_DNS == state.get('local_dns')
    assert PROXY == state.get('local_ip')
    assert state.get('nas_ip') == NAS_IP
    assert state.get('nas_dns') == NAS_DNS
    assert state.get('mountpoint') == MNT
    assert state.get('timeo') == 45

    saved_sign = state.pop(mount_cpfs.STATE_SIGN, '')
    computed_sign = mount_cpfs.sign_state(state)
    assert saved_sign == computed_sign
