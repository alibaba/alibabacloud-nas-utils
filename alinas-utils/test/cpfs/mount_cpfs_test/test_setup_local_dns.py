#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import tempfile
import mount_cpfs
import os


DNS = '123456ab00-abc00.cn-beijing.nas.aliyuncs.com'
IP = '127.0.1.1'


def test_setup_local_dns(tmpdir):
    tmpfile = tmpdir.join(tempfile.mktemp())
    tmpfile.write('', ensure=True)
    hostfile = str(tmpfile)
    mount_cpfs.setup_local_dns(DNS, IP, hostfile)

    oldattr = os.stat(hostfile)

    with open(hostfile) as f:
        assert f.read() == '{} {}\n'.format(IP, DNS)

    newattr = os.stat(hostfile)

    assert oldattr.st_ino == newattr.st_ino
    assert oldattr.st_mtime == newattr.st_mtime
    assert oldattr.st_ctime == newattr.st_ctime


def test_setup_local_dns_second_try(tmpdir):
    tmpfile = tmpdir.join(tempfile.mktemp())
    tmpfile.write('127.0.0.1 localhost\n::::1 localhost\n', ensure=True)

    hostfile = str(tmpfile)
    oldattr = os.stat(hostfile)

    mount_cpfs.setup_local_dns(DNS, IP, hostfile)

    with open(hostfile) as f:
        assert '{} {}\n'.format(IP, DNS) in f.readlines()

    newattr = os.stat(hostfile)
    assert oldattr.st_ino != newattr.st_ino
