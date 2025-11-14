#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


import mount_alinas


def test_int():
    s1 = mount_alinas.sign_state({'a': 1})
    s2 = mount_alinas.sign_state({'a': '1'})
    assert s1 == s2


def test_str():
    s1 = mount_alinas.sign_state({'a': 'a'})
    s2 = mount_alinas.sign_state({'a': u'a'})
    assert s1 == s2


def test_int_list():
    s1 = mount_alinas.sign_state({'a': [1]})
    s2 = mount_alinas.sign_state({'a': ['1']})
    assert s1 == s2


def test_str_list():
    s1 = mount_alinas.sign_state({'a': ['a']})
    s2 = mount_alinas.sign_state({'a': [u'a']})
    assert s1 == s2


def test_key_order():
    s1 = mount_alinas.sign_state({'a': 1, 'b': 2})
    s2 = mount_alinas.sign_state({'b': 2, 'a': 1})
    assert s1 == s2
