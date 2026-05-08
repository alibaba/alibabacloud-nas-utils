#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas

import pytest


def test_wait_for_proxy_ready_good(mocker):
    # mock execute_with_timeout to return stunnel listening on the expected ip:port
    stdout = 'LISTEN  0  4096  127.0.1.1%lo:12049  0.0.0.0:*  users:(("stunnel",pid=2311460,fd=9))\n'
    mocker.patch('mount_alinas.execute_with_timeout', return_value=(None, 0, stdout, None))

    mount_alinas.wait_for_proxy_ready('a', '127.0.1.1', 12049)

def test_wait_for_proxy_mismatch(mocker, capsys):
    stdout = 'LISTEN  0  4096  127.0.1.11%lo:12049  0.0.0.0:*  users:(("stunnel",pid=2311460,fd=9))\n'
    mocker.patch('mount_alinas.execute_with_timeout', return_value=(None, 0, stdout, None))

    with pytest.raises(SystemExit) as e:
        mount_alinas.wait_for_proxy_ready('a', '127.0.1.1', 12049, 8)

    out, err = capsys.readouterr()
    assert 'Cannot start proxy for' in err

def test_wait_for_proxy_ready_bad(mocker, capsys):
    # mock execute_with_timeout to return rc != 0 (no stunnel listening)
    mocker.patch('mount_alinas.execute_with_timeout', return_value=(None, 1, None, None))

    with pytest.raises(SystemExit) as e:
        mount_alinas.wait_for_proxy_ready('a', '127.0.1.1', 12049, 8)

    out, err = capsys.readouterr()
    assert 'Cannot start proxy for' in err
