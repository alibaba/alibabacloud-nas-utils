#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_alinas
import tempfile

import pytest

CAPATH = '/capath'
CAFILE = '/cafile.crt'


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def test_use_existing_cafile(tmpdir):
    alinas_config = {}
    stunnel_cafile = str(create_temp_file(tmpdir))

    mount_alinas.add_stunnel_ca_options(alinas_config, stunnel_cafile)

    assert stunnel_cafile == alinas_config.get('CAfile')
    assert 'CApath' not in alinas_config


def test_use_missing_cafile(capsys):
    alinas_config = {}
    stunnel_cafile = '/missing1'

    with pytest.raises(SystemExit) as ex:
        mount_alinas.add_stunnel_ca_options(alinas_config, stunnel_cafile)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to find the alinas certificate authority file for verification' in err
