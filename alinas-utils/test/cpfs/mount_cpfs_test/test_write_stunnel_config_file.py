#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import cpfs_nfs_common
import os
from configparser import ConfigParser

import pytest

FS_ID = '105364000'
DNS_NAME = '105364000-123ab.cn-beijing.nas.aliyuncs.com'
MOUNT_POINT = '/mnt/test'
PROXY = "127.0.0.1"
PORT = 8888
VERIFY_LEVEL = 2
LOCAL_DNS = '{}.{}'.format(FS_ID, PROXY)


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


def _validate_config(stunnel_config_file, expected_global_config, expected_alinas_config):
    actual_global_config = {}
    actual_alinas_config = {}

    # This assumes alinas-specific config comes after global config
    global_config = True
    with open(stunnel_config_file) as f:
        for line in f:
            line = line.strip()

            if line == '[alinas]':
                global_config = False
                continue

            conf = actual_global_config if global_config else actual_alinas_config

            assert '=' in line
            parts = line.split('=', 1)

            key = parts[0].strip()
            val = parts[1].strip()

            if key in conf:
                if type(conf[key]) is not list:
                    conf[key] = [conf[key]]
                conf[key].append(val)
            else:
                conf[key] = val

    assert expected_global_config == actual_global_config
    assert expected_alinas_config == actual_alinas_config


def _get_expected_alinas_config(proxy=PROXY, port=PORT, dns_name=DNS_NAME,
                                verify=mount_cpfs.DEFAULT_STUNNEL_VERIFY_LEVEL,
                                check_cert_hostname=True,
                                check_cert_validity=True,
                                disable_libwrap=True):

    expected_alinas_config = dict(mount_cpfs.STUNNEL_ALINAS_CONFIG)
    expected_alinas_config['accept'] = expected_alinas_config['accept'] % (proxy, port)
    expected_alinas_config['connect'] %= dns_name
    expected_alinas_config['verify'] = str(verify)

    if check_cert_hostname:
        expected_alinas_config['checkHost'] = dns_name

    if check_cert_validity:
        expected_alinas_config['OCSPaia'] = 'yes'

    if disable_libwrap:
        expected_alinas_config['libwrap'] = 'no'

    return expected_alinas_config


def _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported, stunnel_check_cert_hostname,
                              expected_check_cert_hostname_config_value):
    ca_mocker = mocker.patch('mount_cpfs.add_stunnel_ca_options')

    config_file = mount_cpfs.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_hostname_supported=stunnel_check_cert_hostname_supported,
                    stunnel_check_cert_hostname=stunnel_check_cert_hostname),
        str(tmpdir), LOCAL_DNS, PROXY, PORT, DNS_NAME, VERIFY_LEVEL)

    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_cpfs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_alinas_config(check_cert_hostname=expected_check_cert_hostname_config_value))


def _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported, stunnel_check_cert_validity,
                              expected_check_cert_validity_config_value):
    ca_mocker = mocker.patch('mount_cpfs.add_stunnel_ca_options')

    config_file = mount_cpfs.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_validity_supported=stunnel_check_cert_validity_supported,
                    stunnel_check_cert_validity=stunnel_check_cert_validity),
        str(tmpdir), LOCAL_DNS, PROXY, PORT, DNS_NAME, VERIFY_LEVEL)

    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_cpfs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_alinas_config(check_cert_validity=expected_check_cert_validity_config_value))


def _test_write_stunnel_config_file(mocker, tmpdir):
    ca_mocker = mocker.patch('mount_cpfs.add_stunnel_ca_options')
    state_file_dir = str(tmpdir)

    config_file = mount_cpfs.write_stunnel_config_file(_get_config(mocker),
                                                         state_file_dir,
                                                         LOCAL_DNS,
                                                         PROXY,
                                                         PORT,
                                                         DNS_NAME,
                                                         VERIFY_LEVEL)
    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_cpfs.STUNNEL_GLOBAL_CONFIG, _get_expected_alinas_config())


def test_write_stunnel_config_check_cert_hostname_supported_flag_not_set(mocker, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True,
                              stunnel_check_cert_hostname=None,
                              expected_check_cert_hostname_config_value=True)


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True,
                              stunnel_check_cert_hostname=False,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_true(mocker, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True,
                              stunnel_check_cert_hostname=True,
                              expected_check_cert_hostname_config_value=True)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_not_specified(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=False,
                              stunnel_check_cert_hostname=None,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=False,
                              stunnel_check_cert_hostname=False,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_true(mocker, capsys, tmpdir):
    mocker.patch('mount_cpfs.add_stunnel_ca_options')

    with pytest.raises(SystemExit) as ex:
        conf = _get_config(mocker, stunnel_check_cert_hostname_supported=False, stunnel_check_cert_hostname=True)
        mount_cpfs.write_stunnel_config_file(conf, str(tmpdir), LOCAL_DNS, PROXY, PORT, DNS_NAME,
                                               VERIFY_LEVEL)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'WARNING: Your client lacks sufficient controls' in err
    assert 'stunnel_check_cert_hostname' in err


def test_write_stunnel_config_check_cert_validity_supported_flag_not_set(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True,
                              stunnel_check_cert_validity=None,
                              expected_check_cert_validity_config_value=True)


def test_write_stunnel_config_check_cert_validity_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True,
                              stunnel_check_cert_validity=False,
                              expected_check_cert_validity_config_value=False)


def test_write_stunnel_config_check_cert_validity_supported_flag_set_true(mocker, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True,
                              stunnel_check_cert_validity=True,
                              expected_check_cert_validity_config_value=True)


def test_write_stunnel_config_check_cert_validity_not_supported_flag_not_set(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=False,
                              stunnel_check_cert_validity=None,
                              expected_check_cert_validity_config_value=False)


def test_write_stunnel_config_check_cert_validity_not_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=False,
                              stunnel_check_cert_validity=False,
                              expected_check_cert_validity_config_value=False)


def test_write_stunnel_config_check_cert_validity_not_supported_flag_set_true(mocker, capsys, tmpdir):
    mocker.patch('mount_cpfs.add_stunnel_ca_options')

    with pytest.raises(SystemExit) as ex:
        conf = _get_config(mocker, stunnel_check_cert_validity_supported=False, stunnel_check_cert_validity=True)
        mount_cpfs.write_stunnel_config_file(conf, str(tmpdir), LOCAL_DNS, PROXY, PORT, DNS_NAME,
                                               VERIFY_LEVEL)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'WARNING: Your client lacks sufficient controls' in err
    assert 'stunnel_check_cert_validity' in err


def test_write_stunnel_config_with_verify_level(mocker, tmpdir):
    ca_mocker = mocker.patch('mount_cpfs.add_stunnel_ca_options')

    verify = 0
    config_file = mount_cpfs.write_stunnel_config_file(_get_config(mocker, stunnel_check_cert_validity=True),
                                                         str(tmpdir),
                                                         LOCAL_DNS,
                                                         PROXY,
                                                         PORT, DNS_NAME, verify)
    ca_mocker.assert_not_called()

    _validate_config(config_file, mount_cpfs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_alinas_config(check_cert_validity=True, verify=verify))

