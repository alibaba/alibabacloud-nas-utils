#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import socket
import mount_alinas

import pytest
from mock import MagicMock


def test_wait_for_proxy_ready_good(mocker):
    mk = MagicMock()
    mocker.patch('socket.socket', return_value=mk)

    mount_alinas.wait_for_proxy_ready('a', 'b', 'c')

    mk.connect.assert_called_once()
    mk.connect.assert_called_with(('b', 'c'))
    mk.close.assert_called_once()


def test_wait_for_proxy_ready_bad(mocker, capsys):
    mk = MagicMock()
    mk.connect.side_effect = socket.error()
    mocker.patch('socket.socket', return_value=mk)

    with pytest.raises(SystemExit) as e:
        mount_alinas.wait_for_proxy_ready('a', 'b', 'c', 8)

    out, err = capsys.readouterr()
    assert 'Cannot start proxy for' in err
