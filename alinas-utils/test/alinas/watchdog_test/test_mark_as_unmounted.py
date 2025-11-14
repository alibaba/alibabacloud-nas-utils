#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json


def test_mark_as_unmounted(tmpdir):
    state_file = 'fs-deadbeef.mount.12345'
    state = {}

    tmpdir.join(state_file).write(json.dumps(state))

    updated_state = watchdog.mark_as_unmounted(state, str(tmpdir), state_file, 1024)

    assert updated_state.get('unmount_time') == 1024

    with open(str(tmpdir.join(state_file))) as f:
        file_state = json.load(f)

    assert file_state.get('unmount_time') == 1024
