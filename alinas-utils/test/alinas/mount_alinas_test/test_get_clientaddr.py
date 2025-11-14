#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas


def test_get_clientaddr():
    addr = mount_alinas.get_clientaddr('www.example.com', '8.8.8.8')
    assert not addr.startswith('127.')
