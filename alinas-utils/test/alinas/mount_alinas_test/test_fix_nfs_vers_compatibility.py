#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas
import pytest


def test_fix_nfs_vers_3():
    options = {'vers': '3'}
    mount_alinas.fix_nfs_vers_compatibility(options)
    assert options['vers'] == '3'


def test_fix_nfs_vers_40():
    options = {'vers': '4.0'}
    mount_alinas.fix_nfs_vers_compatibility(options)
    assert options['vers'] == '4'
    assert options['minorversion'] == '0'


def test_fix_nfs_vers_41():
    options = {'vers': '4.1'}
    with pytest.raises(SystemExit):
        mount_alinas.fix_nfs_vers_compatibility(options)
