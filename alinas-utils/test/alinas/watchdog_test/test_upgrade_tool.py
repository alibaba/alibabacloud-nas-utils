import importlib.machinery
import importlib.util
import os
import sys

import pytest


UPGRADE_TOOL_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'dist', 'upgrade-tool'))


def _load_upgrade_tool():
    loader = importlib.machinery.SourceFileLoader(
        'upgrade_tool_for_test', UPGRADE_TOOL_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


upgrade_tool = _load_upgrade_tool()


@pytest.mark.parametrize('run_type', ['prehook', 'watch'])
def test_run_skips_non_posthook(mocker, run_type):
    which = mocker.patch.object(upgrade_tool.shutil, 'which')
    popen = mocker.patch.object(upgrade_tool, 'popen')

    upgrade_tool.run(run_type)

    which.assert_not_called()
    popen.assert_not_called()


def test_run_restarts_watchdog_with_systemctl(mocker):
    mocker.patch.object(
        upgrade_tool.shutil, 'which', return_value='/bin/systemctl')
    popen = mocker.patch.object(
        upgrade_tool, 'popen', side_effect=[(0, ''), (0, '')])

    upgrade_tool.run('posthook')

    assert popen.call_args_list == [
        mocker.call(['/bin/systemctl', 'daemon-reload']),
        mocker.call([
            '/bin/systemctl',
            'restart',
            upgrade_tool.WATCHDOG_SERVICE,
        ]),
    ]


def test_run_uses_process_probe_without_systemctl(mocker):
    mocker.patch.object(upgrade_tool.shutil, 'which', return_value=None)
    popen = mocker.patch.object(upgrade_tool, 'popen', return_value=(0, ''))

    upgrade_tool.run('posthook')

    popen.assert_called_once_with([
        sys.executable,
        upgrade_tool.PROCESS_PROBE_PATH,
        'kill-script',
        upgrade_tool.WATCHDOG_SCRIPT_PATH,
    ])


def test_run_reports_systemctl_restart_failure(mocker):
    mocker.patch.object(
        upgrade_tool.shutil, 'which', return_value='/bin/systemctl')
    popen = mocker.patch.object(
        upgrade_tool, 'popen', side_effect=[(0, ''), (1, 'failed')])

    with pytest.raises(SystemExit):
        upgrade_tool.run('posthook')

    assert popen.call_count == 2


def test_run_reports_process_probe_failure(mocker):
    mocker.patch.object(upgrade_tool.shutil, 'which', return_value=None)
    mocker.patch.object(
        upgrade_tool, 'popen', return_value=(2, 'probe failed'))

    with pytest.raises(SystemExit):
        upgrade_tool.run('posthook')
