#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from watchdog import add_cgroup_limit, clean_up_cgroup_workspace, CGROUP_DIR, CGROUP_PROCS_FILE,\
        CGROUP_LIMIT_FILE, CGROUP_SWAP_CONTROL_FILE, CGROUP_OOM_CONTROL_FILE

import pytest
import os
import subprocess

UUID = 'thisuuid'

class PIDContainer(object):
    def __init__(self, pid):
        self.pid = pid

    def read(self):
        return self.pid

def assert_result(file_path, val):
    with open(file_path, 'r') as f:
        lines = f.readlines()
        assert val in lines[0]

def test_add_cgroup_limit(mocker):
    PID = os.popen("ps -ef | grep 'make test$' | grep -vw grep | awk '{print $2}'").read()
    mocker.patch('os.popen', return_value=PIDContainer(PID))
    add_cgroup_limit('', UUID)
    mocker.patch('os.popen', os.popen)

    dir_path = os.path.join(CGROUP_DIR, UUID)

    procs_path = os.path.join(dir_path, CGROUP_PROCS_FILE)
    limit_path = os.path.join(dir_path, CGROUP_LIMIT_FILE)
    swap_ctrl_path = os.path.join(dir_path, CGROUP_SWAP_CONTROL_FILE)
    oom_ctrl_path = os.path.join(dir_path, CGROUP_OOM_CONTROL_FILE)
    assert os.path.exists(dir_path)
    assert_result(procs_path, PID)
    assert_result(swap_ctrl_path, '0')
    assert_result(oom_ctrl_path, '0')
