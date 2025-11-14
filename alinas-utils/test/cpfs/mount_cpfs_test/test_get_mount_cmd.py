#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import pytest


def test_no_vers(capsys):
    with pytest.raises(SystemExit) as ex:
        options = {}
        mount_cpfs.get_mount_cmd(options)

    assert ex.value.code != 0
    out, err = capsys.readouterr()
    assert 'Option vers is not specified: use vers=3 or vers=4.1' in err


def test_bad_vers(capsys):
    with pytest.raises(SystemExit) as ex:
        options = {'vers': '4.0'}
        mount_cpfs.get_mount_cmd(options)

    assert ex.value.code != 0
    out, err = capsys.readouterr()
    assert 'is wrong: use vers=3 or vers=4.1' in err


def test_vers3():
    options = {'vers': '3'}
    bin = mount_cpfs.get_mount_cmd(options)
    assert bin == '/sbin/mount.nfs'


def test_vers40():
    options = {'vers': '4.1'}
    bin = mount_cpfs.get_mount_cmd(options)
    assert bin == '/sbin/mount.nfs4'
