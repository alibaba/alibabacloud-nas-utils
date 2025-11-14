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

import pytest


def _test_main(mocker, mode, root=True):
    if mode == 'tls':
        options = {'tls': None}
    else:
        options = {'direct': None}

    if root:
        mocker.patch('os.geteuid', return_value=0)
    else:
        mocker.patch('os.geteuid', return_value=100)

    mount_cpfs.TLS_ENABLED = True
    read_config_mock = mocker.patch('cpfs_nfs_common.read_config', return_value='config')
    bootstrap_logging_mock = mocker.patch('cpfs_nfs_common.bootstrap_logging')
    check_unsupported_options_mock = mocker.patch('mount_cpfs.check_unsupported_options')
    get_init_system_mock = mocker.patch('mount_cpfs.get_init_system', return_value='init')
    check_network_status_mock = mocker.patch('mount_cpfs.check_network_status')
    parse_arguments_mock = mocker.patch('mount_cpfs.parse_arguments',
                                        return_value=('dns', 'fs', 'path', 'mp', options))
    mount_tls_mock = mocker.patch('mount_cpfs.mount_tls')
    mount_nfs_directly_mock = mocker.patch('mount_cpfs.mount_nfs_directly')

    mount_cpfs.main()

    read_config_mock.assert_called_once()
    bootstrap_logging_mock.assert_called_once()
    check_unsupported_options_mock.assert_called_once()
    get_init_system_mock.assert_called_once()
    check_network_status_mock.assert_called_once()
    parse_arguments_mock.assert_called_once()

    if mode == 'tls':
        mount_nfs_directly_mock.assert_not_called()
        mount_tls_mock.assert_called_once()

        ctx = mount_tls_mock.call_args[0][0]
        assert ctx.config == 'config'
        assert ctx.init_system == 'init'
        assert ctx.dns == 'dns'
        assert ctx.path == 'path'
        assert ctx.fs_id == 'fs'
        assert ctx.mountpoint == 'mp'
        assert ctx.options == options
    elif mode == 'direct':
        mount_tls_mock.assert_not_called()
        mount_nfs_directly_mock.assert_called_once()
        mount_nfs_directly_mock.assert_called_with('dns', 'path', 'mp', options)
    else:
        mount_nfs_directly_mock.assert_not_called()
        mount_tls_mock.assert_not_called()


def test_main_tls(mocker):
    _test_main(mocker, mode='tls')


def test_main_direct(mocker):
    _test_main(mocker, mode='direct')


def test_main_non_root(mocker, capsys):
    with pytest.raises(SystemExit) as ex:
        _test_main(mocker, mode='direct', root=False)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'only root' in err
