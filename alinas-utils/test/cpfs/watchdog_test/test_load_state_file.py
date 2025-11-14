#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import cpfs_nfs_common


def load_state_file(a, b):
    return cpfs_nfs_common.StateFileManager().load_state_file(a, b)


def test_load_not_exist(tmpdir):
    load_state_file(str(tmpdir), 'non_exist')


def test_load_bad_json(tmpdir):
    state_file = 'bad-json'
    tmpdir.join(state_file).write('abcde')

    assert load_state_file(str(tmpdir), state_file) is None


def test_load_json_no_sign(tmpdir):
    state_file = 'valid-json'
    tmpdir.join(state_file).write('{"a": 1, "b":2}')

    state = load_state_file(str(tmpdir), state_file)
    assert state is None


def test_load_json_bad_sign(tmpdir):
    state_file = 'valid-json'
    tmpdir.join(state_file).write('{"a": 1, "b":2, "sign": 123}')

    state = load_state_file(str(tmpdir), state_file)
    assert state is None


def test_load_json(tmpdir):
    state_file = 'valid-json'
    state = {
        'a': 1,
        'b': 2
    }
    sign = cpfs_nfs_common.sign_state(state)
    tmpdir.join(state_file).write('{"a": 1, "b":2, "sign": "%s"}' % sign)

    state = load_state_file(str(tmpdir), state_file)
    assert state
    assert state['a'] == 1
    assert state['b'] == 2
