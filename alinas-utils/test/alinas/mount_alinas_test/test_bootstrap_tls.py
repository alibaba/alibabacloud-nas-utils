#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


from mock import MagicMock

import os
import mount_alinas
from configparser import ConfigParser


FS_ID = '123456ab00'
DNS_NAME = '{}-abc00.cn-beijing.nas.aliyuncs.com'.format(FS_ID)
REGION = "test-region"
AP_ID = 'test-ap123456'

def _get_config(mocker, stunnel_debug_enabled=False, stunnel_check_cert_hostname_supported=True,
                stunnel_check_cert_validity_supported=True, stunnel_check_cert_hostname=None,
                stunnel_check_cert_validity=None):

    mocker.patch('mount_alinas.get_version_specific_stunnel_options',
                 return_value=(stunnel_check_cert_hostname_supported, stunnel_check_cert_validity_supported, ))

    if stunnel_check_cert_hostname is None:
        stunnel_check_cert_hostname = stunnel_check_cert_hostname_supported

    if stunnel_check_cert_validity is None:
        stunnel_check_cert_validity = stunnel_check_cert_validity_supported

    config = ConfigParser()
    config.add_section(mount_alinas.CONFIG_SECTION)
    config.set(mount_alinas.CONFIG_SECTION, 'stunnel_debug_enabled', str(stunnel_debug_enabled))
    config.set(mount_alinas.CONFIG_SECTION, 'stunnel_check_cert_hostname', str(stunnel_check_cert_hostname))
    config.set(mount_alinas.CONFIG_SECTION, 'stunnel_check_cert_validity', str(stunnel_check_cert_validity))
    return mount_alinas.SafeConfig(config, None, None)


def _mock_popen(mocker, returncode=0):
    mocker.patch("mount_alinas.get_target_region", return_value=REGION)
    mocker.patch("mount_alinas.create_certificate")
    mocker.patch("os.rename")
    mocker.patch("os.kill")

    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)

def _mock_without_popen(mocker):
    mocker.patch("mount_alinas.get_target_region", return_value=REGION)
    mocker.patch("mount_alinas.start_watchdog")
    mocker.patch("socket.gethostname", return_value=DNS_NAME)
    mocker.patch("mount_alinas.write_state_file", return_value="~mocktempfile")
    mocker.patch("os.kill")

    write_config_mock = mocker.patch(
        "mount_alinas.write_stunnel_config_file", return_value="stunnel-config.local_dns"
    )
    return write_config_mock


def test_bootstrap_tls(mocker, tmpdir):
    popen_mock = _mock_popen(mocker)
    mocker.patch('mount_alinas.get_version_specific_stunnel_options', return_value=(False, False))

    config = _get_config(mocker)
    options = {
        'tls': None,
        'proxy': '127.0.1.1',
        'proxy_port': 8888,
        'verify': 0,
        'nas_ip': '8.8.8.8'
    }
    

    config_file, proc, args, cert_details = mount_alinas.bootstrap_tls(config,
                                                         fs_id=FS_ID,
                                                         mountpoint='mount_point',
                                                         local_dns='local_dns',
                                                         dns_name=DNS_NAME,
                                                         security_credentials=None,
                                                         options=options,
                                                         state_file_dir=str(tmpdir))

    assert config_file == os.path.join(str(tmpdir), 'stunnel-config.local_dns')
    assert args[0] == 'stunnel'
    assert args[1] == config_file
    assert cert_details['region'] == REGION
    assert cert_details['fsId'] == FS_ID
    assert cert_details['mountStateDir'] == "local_dns+"

    popen_mock.assert_called_once()

    pargs, _ = popen_mock.call_args
    pargs = pargs[0]
    assert pargs[0] == 'stunnel'
    assert pargs[1] == config_file

def test_bootstrap_tls_cert_created(mocker, tmpdir):
    without_popen_mock = _mock_without_popen(mocker)
    mocker.patch('mount_alinas.get_version_specific_stunnel_options', return_value=(False, False))

    config = _get_config(mocker)
    options = {
        'tls': None,
        'proxy': '127.0.1.1',
        'proxy_port': 8888,
        'verify': 0,
        'nas_ip': '8.8.8.8',
        'accesspoint': AP_ID
    }
    state_file_dir = str(tmpdir)
    tls_dict = mount_alinas.tls_paths_dictionary('local_dns+', state_file_dir)

    pk_path = os.path.join(state_file_dir, "privateKey.pem")
    mocker.patch("mount_alinas.get_private_key_path", return_value=pk_path)

    config_file, proc, args, cert_details = mount_alinas.bootstrap_tls(config,
                                                         fs_id=FS_ID,
                                                         mountpoint='mount_point',
                                                         local_dns='local_dns',
                                                         dns_name=DNS_NAME,
                                                         security_credentials=None,
                                                         options=options,
                                                         state_file_dir=str(tmpdir))

    assert config_file == 'stunnel-config.local_dns'
    assert args[0] == 'stunnel'
    assert args[1] == config_file
    assert cert_details['region'] == REGION
    assert cert_details['fsId'] == FS_ID
    assert cert_details['accessPoint'] == AP_ID
    assert cert_details['mountStateDir'] == "local_dns+"

    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "config.conf"))
    assert os.path.exists(pk_path)
