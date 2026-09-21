#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""Process identity probes and CLI process cleanup helpers.

WARNING: cmdline/script helpers may block on the target process's mmap lock.
They are reserved for upgrade-tool's kill-script fallback when systemctl is
absent and MUST NOT be called from the watchdog main loop.
"""

import errno
import os
import signal
import sys
from collections import namedtuple


_DELETED_SUFFIX = ' (deleted)'


ProcessIdentity = namedtuple(
    'ProcessIdentity',
    ['pid', 'state', 'starttime', 'comm', 'exe'],
)


def normalize_exe_path(path):
    if not path:
        return ''
    if path.endswith(_DELETED_SUFFIX):
        path = path[:-len(_DELETED_SUFFIX)]
    return os.path.normpath(path)


def expected_exe_paths(paths):
    """Return normalized literal and real paths for configured executables."""
    result = set()
    for path in paths:
        normalized = normalize_exe_path(path)
        if not normalized:
            continue
        result.add(normalized)
        result.add(normalize_exe_path(os.path.realpath(normalized)))
    return result


def read_proc_stat(pid, proc_root='/proc'):
    """Return comm, state and starttime without reading process address space."""
    path = os.path.join(proc_root, str(pid), 'stat')
    with open(path, 'r') as stat_file:
        value = stat_file.read(4096).strip()

    left = value.find('(')
    right = value.rfind(')')
    if left <= 0 or right <= left:
        raise ValueError('malformed proc stat for pid %s' % pid)

    stat_pid = int(value[:left].strip())
    fields = value[right + 1:].strip().split()
    if stat_pid != pid or len(fields) <= 19:
        raise ValueError('incomplete proc stat for pid %s' % pid)

    return value[left + 1:right], fields[0], int(fields[19])


def read_process_exe(pid, proc_root='/proc'):
    path = os.path.join(proc_root, str(pid), 'exe')
    return normalize_exe_path(os.readlink(path))


def _read_process_cmdline(pid, proc_root='/proc'):
    """Read argv for the upgrade-tool fallback only; this is NOT a safe probe.

    Reading /proc/<pid>/cmdline accesses the target process's address space
    and may block indefinitely on mmap_lock (mmap_sem on older kernels),
    recreating the ps/FUSE I/O deadlock. NEVER call this function, directly
    or through the script helpers, from the watchdog main loop.
    """
    path = os.path.join(proc_root, str(pid), 'cmdline')
    with open(path, 'rb') as cmdline_file:
        value = cmdline_file.read(65536)
    return [os.fsdecode(arg) for arg in value.split(b'\0') if arg]


def read_process_identity(pid, proc_root='/proc'):
    """Read a stable-enough identity, rejecting PID reuse during the read."""
    comm, state, starttime = read_proc_stat(pid, proc_root)
    exe = ''
    try:
        exe = read_process_exe(pid, proc_root)
    except OSError as error:
        # A zombie normally has no executable link after its mm is released.
        if state != 'Z' or error.errno not in (errno.ENOENT, errno.ESRCH):
            raise

    second_comm, second_state, second_starttime = read_proc_stat(pid, proc_root)
    # Runnable/sleeping state may legitimately change between reads. PID
    # reuse or exec changes the stable identity fields we care about here.
    if (comm, starttime) != (second_comm, second_starttime):
        raise OSError(errno.ESRCH, 'process identity changed while probing')

    return ProcessIdentity(pid, second_state, starttime, comm, exe)


def same_process_identity(left, right):
    return bool(
        left and right
        and left.pid == right.pid
        and left.starttime == right.starttime
        and left.exe == right.exe
    )


def iter_process_identities(proc_root='/proc'):
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return

    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid <= 1:
            continue
        try:
            yield read_process_identity(pid, proc_root)
        except (IOError, OSError, ValueError):
            # Process creation/exit races are expected while walking procfs.
            continue


def find_processes_by_exe(paths, proc_root='/proc', include_zombie=False):
    matches = []
    accepted = expected_exe_paths(paths)
    for identity in iter_process_identities(proc_root):
        if not include_zombie and identity.state == 'Z':
            continue
        if identity.exe in accepted:
            matches.append(identity)
    return matches


def _process_runs_script(pid, accepted_paths, proc_root='/proc'):
    cmdline = _read_process_cmdline(pid, proc_root)
    return bool(
        len(cmdline) > 1
        and normalize_exe_path(cmdline[1]) in accepted_paths
    )


def find_processes_by_script(paths, proc_root='/proc'):
    """Match argv[1]; may block on cmdline, so NOT for the watchdog main loop."""
    matches = []
    accepted = expected_exe_paths(paths)
    for identity in iter_process_identities(proc_root):
        if identity.state == 'Z':
            continue
        try:
            if _process_runs_script(identity.pid, accepted, proc_root):
                matches.append(identity)
        except (IOError, OSError):
            continue
    return matches


def signal_process_if_same(identity, sig=signal.SIGKILL, proc_root='/proc'):
    """Signal only if PID, starttime and executable still match."""
    if not identity or identity.pid <= 1:
        return False
    try:
        current = read_process_identity(identity.pid, proc_root)
        if not same_process_identity(identity, current):
            return False
        os.kill(identity.pid, sig)
        return True
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return False
        raise


def kill_processes_by_exe(paths, proc_root='/proc'):
    """SIGKILL processes whose executable still matches one of ``paths``."""
    killed = 0
    for identity in find_processes_by_exe(paths, proc_root):
        if signal_process_if_same(identity, signal.SIGKILL, proc_root):
            killed += 1
    return killed


def signal_script_process_if_same(identity, paths, sig=signal.SIGKILL,
                                  proc_root='/proc'):
    """Revalidate and signal a script; may block, NOT for the watchdog main loop."""
    if not identity or identity.pid <= 1:
        return False
    accepted = expected_exe_paths(paths)
    try:
        current = read_process_identity(identity.pid, proc_root)
        if not same_process_identity(identity, current):
            return False
        if not _process_runs_script(identity.pid, accepted, proc_root):
            return False
        latest = read_process_identity(identity.pid, proc_root)
        if not same_process_identity(identity, latest):
            return False
        os.kill(identity.pid, sig)
        return True
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return False
        raise


def kill_processes_by_script(paths, proc_root='/proc'):
    """Kill matching scripts; may block on cmdline, NOT for the watchdog main loop."""
    killed = 0
    for identity in find_processes_by_script(paths, proc_root):
        if signal_script_process_if_same(
                identity, paths, signal.SIGKILL, proc_root):
            killed += 1
    return killed


def process_alive_seconds(pid, starttime, proc_root='/proc'):
    if pid <= 1 or starttime <= 0:
        return 0
    try:
        with open(os.path.join(proc_root, 'uptime'), 'r') as uptime_file:
            uptime = float(uptime_file.read(128).split()[0])
        ticks = float(os.sysconf('SC_CLK_TCK'))
        return max(0, int(uptime - starttime / ticks))
    except (IOError, OSError, ValueError, KeyError):
        return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ('kill-exe', 'kill-script') or any(
            not os.path.isabs(path) for path in argv[1:]):
        sys.stderr.write(
            'usage: process_probe.py (kill-exe|kill-script) '
            'ABSOLUTE_PATH [ABSOLUTE_PATH ...]\n')
        return 2

    paths = tuple(argv[1:])
    if argv[0] == 'kill-exe':
        kill_processes_by_exe(paths)
        return 0
    return 0 if kill_processes_by_script(paths) else 1


if __name__ == '__main__':
    sys.exit(main())
