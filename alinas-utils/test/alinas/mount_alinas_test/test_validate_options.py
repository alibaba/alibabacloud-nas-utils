#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
import pytest

from mount_alinas import validate_options


def test_validate_tls():
    validate_options({})
    validate_options({'direct': None})
    validate_options({'tls': None, 'vers': '4.0'})
    validate_options({'tls': None, 'vers': '3'})

    with pytest.raises(SystemExit) as ex:
        validate_options({'tls': None, 'direct': None})

    assert ex.value.code == 1
