#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import os
import tempfile

import watchdog


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def assert_file_not_changes(oldattr, tmpfile):
    attr = stat_file(tmpfile)
    assert oldattr.st_ino == attr.st_ino


def stat_file(tmpfile):
    return os.stat(os.path.join(tmpfile.dirname, tmpfile.basename))


def test_clean_up_local_dns(mocker, tmpdir):
    hostfile = create_temp_file(tmpdir, '127.0.0.1 localhost\n127.0.0.2 a.b.c\n')
    hostfilepath = str(hostfile)
    oldattr = os.stat(os.path.join(hostfile.dirname, hostfile.basename))

    watchdog.clean_up_local_dns(None, '127.0.0.1', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost', None, hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost', '127.0.0.0', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost0', '127.0.0.1', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('a.b.c', '127.0.0.2', hostfilepath)
    assert oldattr.st_ino != stat_file(hostfile).st_ino

    with open(hostfilepath) as f:
        lines = f.readlines()
        assert len(lines) == 1
        assert lines[0] == '127.0.0.1 localhost\n'


def test_clean_up_local_dns_badcase(mocker, tmpdir):
    hostfile = create_temp_file(tmpdir, '127.0.0.11 localhost-127.0.0.11')
    hostfilepath = str(hostfile)
    oldattr = os.stat(os.path.join(hostfile.dirname, hostfile.basename))

    watchdog.clean_up_local_dns('localhost-127.0.0.1', '127.0.0.1', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost-127.0.0.11', '127.0.0.1', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost-127.0.0.1', '127.0.0.11', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost-127.0.0.11', '127.0.0.112', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)

    watchdog.clean_up_local_dns('localhost-127.0.0.112', '127.0.0.11', hostfilepath)
    assert_file_not_changes(oldattr, hostfile)
