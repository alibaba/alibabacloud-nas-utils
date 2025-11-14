#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import pytest


FS_ID = 'cpfs-123456ab00-abc123.cn-beijing'
MP_URL = '{}.cpfs.aliyuncs.com'.format(FS_ID)


def _test_parse_arguments_help(capsys, help):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.parse_arguments(['mount', 'foo', 'bar', help])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in out


def test_parse_arguments_help_long(capsys):
    _test_parse_arguments_help(capsys, '--help')


def test_parse_arguments_help_short(capsys):
    _test_parse_arguments_help(capsys, '-h')


def test_parse_arguments_version(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.parse_arguments(['mount', 'foo', 'bar', '--version'])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert 'Version: %s' % mount_cpfs.VERSION in out


def test_parse_arguments_no_fs_id(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.parse_arguments(['mount'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in err


def test_parse_arguments_no_mount_point(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.parse_arguments(['mount', 'fs-deadbeef'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in err


def test_parse_arguments_non_alinas(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.parse_arguments(['mount', '127.0.0.1', '/dir'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'aliyun CPFS' in err


def test_parse_arguments_default_path():
    mp_url, fsid, path, mountpoint, options = mount_cpfs.parse_arguments(['mount', MP_URL, '/dir'])

    assert mp_url == MP_URL
    assert fsid == FS_ID
    assert '/' == path
    assert '/dir' == mountpoint
    assert options['vers'] == '3'


def test_parse_arguments_custom_path():
    mp_url, fsid, path, mp, options = mount_cpfs.parse_arguments(['mount', '{}:/home'.format(MP_URL), '/dir'])

    assert mp_url == MP_URL
    assert fsid == FS_ID
    assert '/home' == path
    assert '/dir' == mp
    assert options['vers'] == '3'


def test_parse_arguments():
    mp_url, fsid, path, mp, options = mount_cpfs.parse_arguments(
                ['mount', '{}:/home'.format(MP_URL), '/dir', '-o', 'foo,bar=baz,quux'])

    assert mp_url == MP_URL
    assert fsid == FS_ID
    assert '/home' == path
    assert '/dir' == mp
    assert {'foo': None, 'bar': 'baz', 'quux': None, 'vers': '3'} == options
