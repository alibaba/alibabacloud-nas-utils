#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog


def test_non_existent_dir(tmpdir):
    state_files = watchdog.get_files_with_prefix(str(tmpdir.join('new-dir')))

    assert {} == state_files


def test_empty_dir(tmpdir):
    state_files = watchdog.get_files_with_prefix(str(tmpdir))

    assert {} == state_files


def test_no_state_files(tmpdir):
    tmpdir.join('~fs-deadbeef.mount.dir.127.0.0.1').write('')

    state_files = watchdog.get_files_with_prefix(str(tmpdir))

    assert {} == state_files


def test_state_files(tmpdir):
    non_alinas_config = 'fs-deadbeef.mount.dir.127.0.0.1'
    tmpdir.join(non_alinas_config).write('')

    alinas_config = 'alinas-deadbeef.127.0.0.1'
    tmpdir.join(alinas_config).write('')

    stunnel_config = 'stunnel-config.fs-deadbeef.mount.dir.127.0.0.1'
    tmpdir.join(stunnel_config).write('')

    state_files = watchdog.get_files_with_prefix(str(tmpdir))

    assert 1 == len(state_files)
    assert 'alinas-deadbeef.127.0.0.1' in state_files
    assert state_files['alinas-deadbeef.127.0.0.1'] == alinas_config
