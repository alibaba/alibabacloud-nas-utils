#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import fcntl
import os
from contextlib import contextmanager
from multiprocessing import Process, Event

import mount_alinas


def do_lock(lock_file, ready_event, exit_event):
    fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        ready_event.set()

    exit_event.wait()


@contextmanager
def lock_alinas(state_dir, expected_success):
    lock_file = os.path.join(state_dir, mount_alinas.ALINAS_LOCK)

    ready_event = Event()
    exit_event = Event()
    p = Process(target=do_lock, args=(lock_file, ready_event, exit_event))
    p.start()
    ready_event.wait()

    try:
        yield
    finally:
        exit_event.set()
        p.join()

    if expected_success:
        assert p.exitcode == 0
    else:
        assert p.exitcode != 0


def test_lock_alinas_conflict1(tmpdir):
    state_dir = str(tmpdir)

    with mount_alinas.lock_alinas(state_dir):
        assert os.path.exists(os.path.join(state_dir, mount_alinas.ALINAS_LOCK))

        with lock_alinas(state_dir, False):
            pass
