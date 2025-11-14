#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas


def test_serialize_stunnel_config_no_header():
    conf = {
        "a": 1,
        "b": True,
        "c": [1, 2, 3]
    }

    r = mount_alinas.serialize_stunnel_config(conf)

    assert len(r) == 5
    assert 'a = 1' in r
    assert 'b = True' in r
    assert 'c = 1' in r
    assert 'c = 2' in r
    assert 'c = 3' in r


def test_serialize_stunnel_config_header():
    conf = {
        "a": [],
        "b": "10"
    }
    header = 'header'

    r = mount_alinas.serialize_stunnel_config(conf, header)

    assert len(r) == 2
    assert '[header]' in r
    assert 'b = 10' in r
