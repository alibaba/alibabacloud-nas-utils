#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

from mock import MagicMock


def test_add_and_poll(mocker):
    time_mock = mocker.patch('time.time', return_value=0)

    waiter = watchdog.EventWaiter()

    waiter.add_timer(1, 'data1', 'cb1')
    waiter.add_timer(1, 'data2', 'cb2')
    waiter.add_timer(3, 'data3', 'cb3')

    tasks = waiter.wait()
    assert len(tasks) == 0

    time_mock.return_value = 1
    tasks = waiter.wait()
    assert len(tasks) == 2

    tasks = sorted(tasks, key=lambda x: x[1])
    assert tasks[0][1] == 'data1'
    assert tasks[0][2] == 'cb1'
    assert tasks[1][1] == 'data2'
    assert tasks[1][2] == 'cb2'

    tasks = waiter.wait()
    assert len(tasks) == 0

    time_mock.return_value = 2
    tasks = waiter.wait()
    assert len(tasks) == 0

    time_mock.return_value = 4
    tasks = waiter.wait()
    assert len(tasks) == 1
    assert tasks[0][1] == 'data3'
    assert tasks[0][2] == 'cb3'


def test_interrupt():
    c = MagicMock()

    waiter = watchdog.EventWaiter()
    waiter._interrupted = c

    waiter.wait()
    c.wait.assert_called_once()

    c.reset_mock()
    waiter.interrupt()
    waiter.wait()

    c.wait.assert_not_called()

    c.reset_mock()
    waiter.interrupt()
    waiter.interrupt()
    waiter.interrupt()
    waiter.interrupt()
    waiter.wait()

    c.wait.assert_not_called()
    c.notify_all.assert_called_once()

    c.reset_mock()
    waiter.wait()
    c.wait.assert_called_once()


def test_wakeup(mocker):
    time_mock = mocker.patch('time.time', return_value=0)

    c = MagicMock()

    waiter = watchdog.EventWaiter()
    waiter.interrupt = c

    waiter.add_timer(10, 'data', 'cb')
    c.assert_called_once()

    c.reset_mock()
    waiter.add_timer(20, 'data', 'cb')
    c.assert_not_called()

    c.reset_mock()
    waiter.add_timer(0, 'data', 'cb')
    c.assert_called_once()
