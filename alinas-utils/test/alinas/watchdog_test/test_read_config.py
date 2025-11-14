#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog


def test_file_404(tmpdir):
    config_file = str(tmpdir) + '/not-exist-config-file'
    config = watchdog.read_config(str(config_file))
    assert config is not None


def test_no_section(tmpdir):
    config_file = tmpdir.join('empty-file')

    config = watchdog.read_config(str(config_file))
    assert config is not None
    assert config.get(watchdog.WATCHDOG_CONFIG_SECTION, 'xxxx', 'default') == 'default'
    assert config.getint(watchdog.WATCHDOG_CONFIG_SECTION, 'a', 0, 1, 2) == 0
    assert config.getboolean(watchdog.WATCHDOG_CONFIG_SECTION, 'a', True) == True


def test_config_get(tmpdir):
    config_file = tmpdir.join('config_file')
    config_file.write('''\
[{}]
test = 1111
    '''.format(watchdog.WATCHDOG_CONFIG_SECTION))

    config = watchdog.read_config(str(config_file))
    assert config is not None
    assert config.get(watchdog.WATCHDOG_CONFIG_SECTION, 'test', 'default') == '1111'
    assert config.get(watchdog.WATCHDOG_CONFIG_SECTION, 'xxxx', 'default') == 'default'


def test_config_getint(tmpdir):
    config_file = tmpdir.join('config_file')
    config_file.write('''\
[{}]
test = 1111
    '''.format(watchdog.WATCHDOG_CONFIG_SECTION))

    config = watchdog.read_config(str(config_file))
    assert config is not None
    assert config.getint(watchdog.WATCHDOG_CONFIG_SECTION, 'test', 0, 0, 2000) == 1111
    assert config.getint(watchdog.WATCHDOG_CONFIG_SECTION, 'test', 0, 2000, 4000) == 2000
    assert config.getint(watchdog.WATCHDOG_CONFIG_SECTION, 'test', 0, 0, 1000) == 1000
    assert config.getint(watchdog.WATCHDOG_CONFIG_SECTION, 'xxxx', 0, 0, 2000) == 0


def test_config_getboolean(tmpdir):
    config_file = tmpdir.join('config_file')
    config_file.write('''\
[{}]
test = true
    '''.format(watchdog.WATCHDOG_CONFIG_SECTION))

    config = watchdog.read_config(str(config_file))
    assert config is not None
    assert config.getboolean(watchdog.WATCHDOG_CONFIG_SECTION, 'test', False) == True
    assert config.getboolean(watchdog.WATCHDOG_CONFIG_SECTION, 'xxxx', False) == False
    assert config.getboolean(watchdog.WATCHDOG_CONFIG_SECTION, 'xxxx', True) == True
