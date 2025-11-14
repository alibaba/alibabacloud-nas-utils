#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


import watchdog


def test_get_local_dns():
    raw = 'alinas-6e1854899b-deo54.127.0.1.1:/ /mnt nfs ' \
          'vers=3,port=6000,mountaddr=127.0.1.1,mountport=6000,addr=127.0.1.1 0 0'
    assert watchdog.get_local_dns(watchdog.Mount._make(raw.strip().split())) == 'alinas-6e1854899b-deo54.127.0.1.1'
