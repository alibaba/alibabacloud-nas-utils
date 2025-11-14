#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


import os

import watchdog
import cpfs_nfs_common


def test_state_file_manager_normal(mocker, tmpdir):
    state_file = 'valid-json'
    state = {
        'a': 1,
        'b': 2
    }
    sign = cpfs_nfs_common.sign_state(state)
    tmpdir.join(state_file).write('{"a": 1, "b":2, "sign": "%s"}' % sign)
    fm = cpfs_nfs_common.StateFileManager()

    s = fm.load_state_file(str(tmpdir), state_file)
    assert s is not None
    assert s['a'] == 1
    assert s['b'] == 2


def test_state_file_manager_evict_non_json(mocker, tmpdir):
    state_file = 'invalid-json'
    tmpdir.join(state_file).write('{"a": 1, "b":2')
    fm = cpfs_nfs_common.StateFileManager()

    for i in range(10):
        s = fm.load_state_file(str(tmpdir), state_file)
        assert s is None

        assert os.path.exists(os.path.join(str(tmpdir), state_file))

    s = fm.load_state_file(str(tmpdir), state_file)
    assert s is None
    assert not os.path.exists(os.path.join(str(tmpdir), state_file))


def test_state_file_manager_evict_bad_sign(tmpdir):
    state_file = 'bad-sign'
    state = {
        'a': 1,
        'b': 2
    }
    sign = cpfs_nfs_common.sign_state(state)
    tmpdir.join(state_file).write('{"a": 2, "b":2, "sign": "%s"}' % sign)
    fm = cpfs_nfs_common.StateFileManager()

    for i in range(10):
        s = fm.load_state_file(str(tmpdir), state_file)
        assert s is None

        assert os.path.exists(os.path.join(str(tmpdir), state_file))

    s = fm.load_state_file(str(tmpdir), state_file)
    assert s is None
    assert not os.path.exists(os.path.join(str(tmpdir), state_file))


def test_state_file_manager_evict_no_sign(tmpdir):
    state_file = 'no-sign'
    state = {
        'a': 1,
        'b': 2
    }
    tmpdir.join(state_file).write('{"a": 2, "b":2}')
    fm = cpfs_nfs_common.StateFileManager()

    for i in range(10):
        s = fm.load_state_file(str(tmpdir), state_file)
        assert s is None

        assert os.path.exists(os.path.join(str(tmpdir), state_file))

    s = fm.load_state_file(str(tmpdir), state_file)
    assert s is None
    assert not os.path.exists(os.path.join(str(tmpdir), state_file))


def test_state_file_manager_revive(tmpdir):
    state_file = 'valid-json'
    state = {
        'a': 1,
        'b': 2
    }
    sign = 'abc'
    tmpdir.join(state_file).write('{"a": 1, "b":2, "sign": "%s"}' % sign)
    fm = cpfs_nfs_common.StateFileManager()
    for i in range(8):
        s = fm.load_state_file(str(tmpdir), state_file)
        assert s is None

        assert os.path.exists(os.path.join(str(tmpdir), state_file))

    tmpdir.join(state_file).write('{"a": 1, "b":2, "sign": "%s"}' % cpfs_nfs_common.sign_state(state))

    s = fm.load_state_file(str(tmpdir), state_file)
    assert s['a'] == 1
    assert s['b'] == 2
    assert os.path.exists(os.path.join(str(tmpdir), state_file))
