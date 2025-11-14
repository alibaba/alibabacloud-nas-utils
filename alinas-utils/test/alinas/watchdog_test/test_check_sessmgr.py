#
# Copyright 2020-2022 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import sys
import os
import shutil
from mock import MagicMock, patch, mock_open
import watchdog

def _mock_popen(mocker, returncode=0, returnmsg=''):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (returnmsg, 'stderr', )
    popen_mock.returncode = returncode
    return mocker.patch('subprocess.Popen', return_value=popen_mock)

def test_create_sessmgr_log_file(mocker):
    log_dir_path = os.getcwd()
    sessmgr_log = os.path.join(log_dir_path, 'sessmgrlog')
    watchdog.create_sessmgr_log_file(log_dir_path)
  
    sessmgr_conf = os.path.join(log_dir_path, 'log_conf.sessmgr.json')
    assert os.path.exists(sessmgr_log)
    shutil.rmtree(sessmgr_log)
    assert os.path.exists(sessmgr_conf)
    os.remove(sessmgr_conf)

def test_check_unas_sessmgr_dead(mocker, tmpdir):
    # sessmgr not alive
    tmpdir.join('test').write('')
    fd = open(str(tmpdir) + '/test')

    mock = mocker.patch("os.popen", return_value=fd)
    pmock = _mock_popen(mocker, 0, '')
    mocker.patch('watchdog.create_sessmgr_log_file', return_value='default')
    
    watchdog.check_unas_sessmgr('STATE_FILE_DIR')
    assert pmock.call_count == 1 
    fd.close()

def test_check_unas_sessmgr_alive(mocker, tmpdir):
    tmpdir.join('test').write('sessmgr')
    fd = open(str(tmpdir) + '/test')
    mock = mocker.patch("os.popen", return_value=fd)

    pmock = _mock_popen(mocker, 0, 'sessmgr')
    # sessmgr alive
    pmock.communicate.return_value = ('sessmgr', '', )
    watchdog.check_unas_sessmgr('STATE_FILE_DIR')
    assert pmock.call_count == 0
    fd.close()
