#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas
import json
import os
from datetime import datetime

FS_ID = 'fs-deadbeef'
PID = 1234
PROXY = '127.0.0.1'
UUID = 'TestUUID'
LOCAL_DNS = '{}-{}-{}'.format(FS_ID, PROXY, UUID)
COMMAND = ['stunnel', '/some/config/file']
FILES = ['/tmp/foo', '/tmp/bar']
MNT = '/mnt/a'
NAS_DNS = 'www.baidu.com'
NAS_IP = '8.8.8.8'
CONFIG_FILE = 'alinas.config'
DATETIME_FORMAT = "%y%m%d%H%M%SZ"

def test_write_state_file(mocker, tmpdir):
    state_file_dir = str(tmpdir)

    mocker.patch('mount_alinas.resolve_dns', return_value=NAS_IP)
    ctx = mount_alinas.MountContext('config', 'init', NAS_DNS, 'fs_id', 'path', MNT, None, {'proxy': PROXY, 'nas_ip': NAS_IP})
    state_file = mount_alinas.write_state_file(LOCAL_DNS,
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
    assert state.get('timeo') == 180

    saved_sign = state.pop(mount_alinas.STATE_SIGN, '')
    computed_sign = mount_alinas.sign_state(state)
    assert saved_sign == computed_sign

def test_write_state_file_with_cert(mocker, tmpdir):
    state_file_dir = str(tmpdir)

    current_time = datetime.utcnow()
    cert_creation_time = current_time.strftime(DATETIME_FORMAT)

    cert_details = {
        "accessPoint": "fsap-fedcba9876543210",
        "certificate": "/tmp/baz",
        "privateKey": "/tmp/key.pem",
        "mountStateDir": "fs-deadbeef.mount.dir.12345",
        "commonName": "fs-deadbeef.nas.aliyun.com",
        "region": "region",
        "fsId": FS_ID,
        "certificateCreationTime": cert_creation_time,
    }

    mocker.patch('mount_alinas.resolve_dns', return_value=NAS_IP)
    ctx = mount_alinas.MountContext('config', 'init', NAS_DNS, 'fs_id', 'path', MNT, None, {'proxy': PROXY, 'nas_ip': NAS_IP})
    state_file = mount_alinas.write_state_file(LOCAL_DNS,
                                               ctx,
                                               PID,
                                               COMMAND,
                                               CONFIG_FILE,
                                               FILES,
                                               state_file_dir,
                                               cert_details,
                                               UUID)

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
    assert UUID == state.get('uuid')
    assert state.get('nas_ip') == NAS_IP
    assert state.get('nas_dns') == NAS_DNS
    assert state.get('mountpoint') == MNT
    assert state.get('timeo') == 180
    assert cert_details["commonName"] == state.get("commonName")
    assert cert_details["certificate"] == state.get("certificate")
    assert cert_details["certificateCreationTime"] == state.get(
        "certificateCreationTime"
    )
    assert cert_details["mountStateDir"] == state.get("mountStateDir")
    assert cert_details["privateKey"] == state.get("privateKey")
    assert cert_details["region"] == state.get("region")
    assert cert_details["accessPoint"] == state.get("accessPoint")
    assert cert_details["fsId"] == state.get("fsId")

    saved_sign = state.pop(mount_alinas.STATE_SIGN, '')
    computed_sign = mount_alinas.sign_state(state)
    assert saved_sign == computed_sign

def test_write_unas_state_file(mocker, tmpdir):
    state_file_dir = str(tmpdir)
    mount_uuid = "mount_uuid_test"
    mount_point = "mount_point_test"
    mount_path = "mount_path_test"
    mount_cmd = "mount_cmd_test"
    mount_key = "mount_key_test"
    bind_tag = "bind_tag_test"
    sessmgr_required = True
    unas_state = mount_alinas.UnasState(mount_uuid, mount_point, mount_path, mount_cmd, mount_key, bind_tag, sessmgr_required)
    state_file = 'eac-' + mount_uuid
    new_file = mount_alinas.write_unas_state_file(unas_state._asdict(), state_file_dir, state_file)

    state = mount_alinas.load_unas_state_file(state_file_dir, state_file)
    assert mount_uuid == state['mountuuid']

