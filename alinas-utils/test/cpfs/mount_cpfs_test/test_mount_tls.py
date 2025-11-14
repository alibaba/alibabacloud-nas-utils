#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
from contextlib import contextmanager


local_dns = 'alinas-abcde.127.0.0.1'
tx = mount_cpfs.Tx(local_dns)


@contextmanager
def dummy_context(*args, **kwargs):
    yield tx


def test_mount_proxy(mocker):
    start_tx_mock = mocker.patch('mount_cpfs.start_tx', side_effect=dummy_context)
    bootstrap_mock = mocker.patch('mount_cpfs.bootstrap_tls', return_value=('a', 'b', 'c'))

    ctx = mount_cpfs.MountContext('config', 'init', 'dns', 'fs-id', 'path', 'mp', 'options')
    mount_cpfs.mount_tls(ctx)

    bootstrap_mock.assert_called_once()
    bootstrap_mock.assert_called_with('config', local_dns, 'dns', 'options')
    start_tx_mock.assert_called_once()
    start_tx_mock.assert_called_with('Stunnel', ctx)

    assert tx.config_file == 'a'
    assert tx.process == 'b'
    assert tx.cmd == 'c'
