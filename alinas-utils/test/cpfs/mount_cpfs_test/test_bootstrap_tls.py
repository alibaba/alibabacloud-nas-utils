#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


from mock import MagicMock

import os
import mount_cpfs
import cpfs_nfs_common
from configparser import ConfigParser


FS_ID = '123456ab00'
DNS_NAME = '{}-abc00.cn-beijing.nas.aliyuncs.com'.format(FS_ID)


def _get_config(mocker, stunnel_debug_enabled=False, stunnel_check_cert_hostname_supported=True,
                stunnel_check_cert_validity_supported=True, stunnel_check_cert_hostname=None,
                stunnel_check_cert_validity=None):

    mocker.patch('mount_cpfs.get_version_specific_stunnel_options',
                 return_value=(stunnel_check_cert_hostname_supported, stunnel_check_cert_validity_supported, ))

    if stunnel_check_cert_hostname is None:
        stunnel_check_cert_hostname = stunnel_check_cert_hostname_supported

    if stunnel_check_cert_validity is None:
        stunnel_check_cert_validity = stunnel_check_cert_validity_supported

    config = ConfigParser()
    config.add_section(mount_cpfs.CONFIG_SECTION)
    config.set(mount_cpfs.CONFIG_SECTION, 'stunnel_debug_enabled', str(stunnel_debug_enabled))
    config.set(mount_cpfs.CONFIG_SECTION, 'stunnel_check_cert_hostname', str(stunnel_check_cert_hostname))
    config.set(mount_cpfs.CONFIG_SECTION, 'stunnel_check_cert_validity', str(stunnel_check_cert_validity))
    return cpfs_nfs_common.SafeConfig(config, None, None)


def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_bootstrap_tls(mocker, tmpdir):
    popen_mock = _mock_popen(mocker)
    mocker.patch('mount_cpfs.get_version_specific_stunnel_options', return_value=(False, False))

    config = _get_config(mocker)
    options = {
        'tls': None,
        'proxy': '127.0.1.1',
        'proxy_port': 8888,
        'verify': 0,
        'nas_ip': '8.8.8.8'
    }

    config_file, proc, args = mount_cpfs.bootstrap_tls(config,
                                                         dns_name=DNS_NAME,
                                                         local_dns='local_dns',
                                                         options=options,
                                                         state_file_dir=str(tmpdir))

    assert config_file == os.path.join(str(tmpdir), 'stunnel-config.local_dns')
    assert args[0] == 'stunnel'
    assert args[1] == config_file
    popen_mock.assert_called_once()

    pargs, _ = popen_mock.call_args
    pargs = pargs[0]
    assert pargs[0] == 'stunnel'
    assert pargs[1] == config_file
