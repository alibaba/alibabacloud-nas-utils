#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


import mount_alinas


def test_serialize_options_invalid():
    for i in mount_alinas.ALINAS_ONLY_OPTIONS:
        options = {i: 10}
        assert mount_alinas.serialize_options(options) == ''


def test_serialize_options_valid():
    options = {'rw': None}
    text = mount_alinas.serialize_options(options)
    assert text == 'rw'

    options = {'rw': None, 'retrans': 2, 'timeo': 3}
    text = mount_alinas.serialize_options(options)
    assert 'rw' in text
    assert 'retrans=2' in text
    assert 'timeo=3' in text
    assert text.count(',') == 2


def test_serialize_options_mix():
    options = {'retrans': 1, 'proxy': 10}
    assert mount_alinas.serialize_options(options) == 'retrans=1'
