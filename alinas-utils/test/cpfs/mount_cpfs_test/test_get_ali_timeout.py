#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


import mount_cpfs
import pytest


def test_str(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.get_ali_timeout({'alitimeo': 'abc'})

    assert ex.value.code != 0

    out, err = capsys.readouterr()
    assert 'Bad alitimeo' in err


def test_zero(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.get_ali_timeout({'alitimeo': '0'})

    assert ex.value.code != 0

    out, err = capsys.readouterr()
    assert 'Bad alitimeo' in err


def test_negative(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.get_ali_timeout({'alitimeo': -1})

    assert ex.value.code != 0

    out, err = capsys.readouterr()
    assert 'Bad alitimeo' in err


def test_first_try():
    assert mount_cpfs.get_ali_timeout({}) == 45
    assert mount_cpfs.get_ali_timeout({'alitimeo': 10}) == 10
    assert mount_cpfs.get_ali_timeout({'alitimeo': '20'}) == 20

