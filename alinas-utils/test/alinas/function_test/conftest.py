#
# Copyright 2020-2022 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import pytest


def pytest_addoption(parser):
    parser.addoption(
        '--server', action='store', help='the address of NAS filesystem for test'
    )
    parser.addoption(
        '--testdir', action='store', help='local directory for mount'
    )


@pytest.fixture
def server(request):
    return request.config.getoption('--server')


@pytest.fixture
def testdir(request):
    return request.config.getoption('--testdir')
