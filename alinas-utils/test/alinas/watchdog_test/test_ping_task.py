#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog


LOCAL_DNS = 'local_dns'
MP = 'mp'
TIMEOUT = 60


def test_ping_task_getters():
    task = watchdog.PingTask(LOCAL_DNS, MP, TIMEOUT)

    assert task.local_dns == LOCAL_DNS
    assert task.mountpoint == MP
    assert task.timeout == TIMEOUT


def test_ping_task_run(mocker):
    statvfs_mock = mocker.patch('os.statvfs')

    task = watchdog.PingTask(LOCAL_DNS, MP, TIMEOUT)
    task.run()

    statvfs_mock.assert_called_once()
    statvfs_mock.assert_called_with(MP)
