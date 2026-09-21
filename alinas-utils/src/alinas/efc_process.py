#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""Side-effect-free EFC process probing based on the per-UUID POSIX lock."""

import ctypes
import errno
import fcntl
import os
import stat
import time
from collections import namedtuple

import process_probe


EFC_WORKSPACE_DIR = '/var/run/efc'
EFC_LOCK_SUFFIX = 'efc.lock'
EFC_PID_SUFFIX = 'efc.pid'

EFC_RUNNING = 'RUNNING'
EFC_DEAD = 'DEAD'
EFC_ZOMBIE_LOCKED = 'ZOMBIE_LOCKED'
EFC_LOCK_CONFLICT = 'LOCK_CONFLICT'
EFC_UNKNOWN = 'UNKNOWN'

EFC_READINESS_TIMEOUT = 3.0
EFC_READINESS_POLL_INTERVAL = 0.1

DETACH_DETACHED = 'DETACHED'
DETACH_RELEASED = 'RELEASED'
DETACH_ABORTED = 'ABORTED'
DETACH_ERROR = 'ERROR'
DETACH_WAIT = 'WAIT'

EFC_EXE_PATHS = (
    '/usr/bin/aliyun-alinas-efc',
    '/usr/bin/aliyun-alinas-eac',
)
_EFC_COMM_PREFIXES = ('aliyun-alinas-e',)


class _Flock(ctypes.Structure):
    # EFC supports 64-bit Linux on x86_64 and aarch64. Both ABIs use 64-bit
    # off_t and lay struct flock out as 32 bytes with l_pid at offset 24.
    _fields_ = [
        ('l_type', ctypes.c_short),
        ('l_whence', ctypes.c_short),
        ('l_start', ctypes.c_longlong),
        ('l_len', ctypes.c_longlong),
        ('l_pid', ctypes.c_int),
    ]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.fcntl.restype = ctypes.c_int


_ProbeBase = namedtuple(
    'EfcProbeResult',
    [
        'state',
        'owner_pid',
        'proc_state',
        'proc_starttime',
        'proc_comm',
        'lock_path',
        'lock_dev',
        'lock_inode',
        'pidfile_pid',
        'pidfile_match',
        'reason',
    ],
)


class EfcProbeResult(_ProbeBase):
    __slots__ = ()

    @property
    def identity(self):
        return (
            self.owner_pid,
            self.proc_starttime,
            self.lock_dev,
            self.lock_inode,
        )


def _result(state, lock_path, reason, owner_pid=0, proc_state='',
            proc_starttime=0, proc_comm='', lock_dev=0, lock_inode=0,
            pidfile_pid=0):
    return EfcProbeResult(
        state=state,
        owner_pid=owner_pid,
        proc_state=proc_state,
        proc_starttime=proc_starttime,
        proc_comm=proc_comm,
        lock_path=lock_path,
        lock_dev=lock_dev,
        lock_inode=lock_inode,
        pidfile_pid=pidfile_pid,
        pidfile_match=bool(owner_pid and pidfile_pid == owner_pid),
        reason=reason,
    )


def lock_path_for_uuid(mount_uuid, workspace_dir=EFC_WORKSPACE_DIR):
    if not mount_uuid or '/' in mount_uuid or '\x00' in mount_uuid:
        raise ValueError('invalid EFC mount UUID')
    return os.path.join(workspace_dir, '%s.%s' % (mount_uuid, EFC_LOCK_SUFFIX))


def pid_path_for_uuid(mount_uuid, workspace_dir=EFC_WORKSPACE_DIR):
    if not mount_uuid or '/' in mount_uuid or '\x00' in mount_uuid:
        raise ValueError('invalid EFC mount UUID')
    return os.path.join(workspace_dir, '%s.%s' % (mount_uuid, EFC_PID_SUFFIX))


def read_pidfile(path):
    fd = -1
    try:
        flags = (os.O_RDONLY | os.O_NONBLOCK
                 | getattr(os, 'O_CLOEXEC', 0)
                 | getattr(os, 'O_NOFOLLOW', 0))
        fd = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return 0
        value = os.read(fd, 64).decode('ascii').strip()
        pid = int(value)
        return pid if pid > 1 else 0
    except (IOError, OSError, UnicodeError, ValueError):
        return 0
    finally:
        if fd >= 0:
            os.close(fd)


def query_lock_owner(fd):
    lock = _Flock()
    lock.l_type = fcntl.F_WRLCK
    lock.l_whence = os.SEEK_SET
    lock.l_start = 0
    lock.l_len = 0
    lock.l_pid = 0

    if _libc.fcntl(fd, fcntl.F_GETLK, ctypes.byref(lock)) == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return lock.l_type, lock.l_pid


read_proc_stat = process_probe.read_proc_stat


def is_efc_comm(comm):
    return any(comm.startswith(prefix) for prefix in _EFC_COMM_PREFIXES)


def _same_path_inode(path, file_stat):
    path_stat = os.lstat(path)
    return (path_stat.st_dev, path_stat.st_ino) == (file_stat.st_dev, file_stat.st_ino)


def probe_efc(mount_uuid, workspace_dir=EFC_WORKSPACE_DIR, proc_root='/proc',
              efc_exe_paths=EFC_EXE_PATHS):
    """Return the EFC owner state without acquiring or modifying its lock."""
    try:
        lock_path = lock_path_for_uuid(mount_uuid, workspace_dir)
        pid_path = pid_path_for_uuid(mount_uuid, workspace_dir)
    except ValueError as error:
        return _result(EFC_UNKNOWN, '', str(error))

    pidfile_pid = read_pidfile(pid_path)
    flags = (os.O_RDONLY | os.O_NONBLOCK
             | getattr(os, 'O_CLOEXEC', 0)
             | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fd = os.open(lock_path, flags)
    except OSError as error:
        if error.errno == errno.ENOENT:
            return _result(EFC_DEAD, lock_path, 'lock file does not exist',
                           pidfile_pid=pidfile_pid)
        return _result(EFC_UNKNOWN, lock_path,
                       'open lock failed: %s' % error,
                       pidfile_pid=pidfile_pid)

    try:
        file_stat = os.fstat(fd)
        try:
            lock_type, owner_pid = query_lock_owner(fd)
        except OSError as error:
            return _result(EFC_UNKNOWN, lock_path,
                           'F_GETLK failed: %s' % error,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        try:
            if not _same_path_inode(lock_path, file_stat):
                return _result(EFC_UNKNOWN, lock_path,
                               'lock path inode changed during probe',
                               lock_dev=file_stat.st_dev,
                               lock_inode=file_stat.st_ino,
                               pidfile_pid=pidfile_pid)
        except OSError as error:
            return _result(EFC_UNKNOWN, lock_path,
                           'lock path disappeared during probe: %s' % error,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        if lock_type == fcntl.F_UNLCK:
            return _result(EFC_DEAD, lock_path, 'lock is not held',
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)
        if lock_type != fcntl.F_WRLCK or owner_pid <= 1:
            return _result(EFC_LOCK_CONFLICT, lock_path,
                           'unexpected lock type or owner',
                           owner_pid=owner_pid,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        try:
            proc_comm, proc_state, proc_starttime = read_proc_stat(owner_pid, proc_root)
        except (IOError, OSError, ValueError) as error:
            return _result(EFC_UNKNOWN, lock_path,
                           'read lock owner stat failed: %s' % error,
                           owner_pid=owner_pid,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        proc_exe = ''
        try:
            proc_exe = process_probe.read_process_exe(owner_pid, proc_root)
        except OSError as error:
            # Zombie processes commonly lose /proc/<pid>/exe. A matching
            # pidfile and the truncated EFC/EAC comm are required below.
            if proc_state != 'Z' or error.errno not in (errno.ENOENT, errno.ESRCH):
                return _result(EFC_UNKNOWN, lock_path,
                               'read lock owner exe failed: %s' % error,
                               owner_pid=owner_pid,
                               proc_state=proc_state,
                               proc_starttime=proc_starttime,
                               proc_comm=proc_comm,
                               lock_dev=file_stat.st_dev,
                               lock_inode=file_stat.st_ino,
                               pidfile_pid=pidfile_pid)

        try:
            second_type, second_owner = query_lock_owner(fd)
            if second_type != lock_type or second_owner != owner_pid:
                return _result(EFC_UNKNOWN, lock_path,
                               'lock owner changed during probe',
                               owner_pid=owner_pid,
                               proc_state=proc_state,
                               proc_starttime=proc_starttime,
                               proc_comm=proc_comm,
                               lock_dev=file_stat.st_dev,
                               lock_inode=file_stat.st_ino,
                               pidfile_pid=pidfile_pid)
            if not _same_path_inode(lock_path, file_stat):
                return _result(EFC_UNKNOWN, lock_path,
                               'lock path inode changed after owner check',
                               owner_pid=owner_pid,
                               proc_state=proc_state,
                               proc_starttime=proc_starttime,
                               proc_comm=proc_comm,
                               lock_dev=file_stat.st_dev,
                               lock_inode=file_stat.st_ino,
                               pidfile_pid=pidfile_pid)
        except OSError as error:
            return _result(EFC_UNKNOWN, lock_path,
                           'revalidate lock failed: %s' % error,
                           owner_pid=owner_pid,
                           proc_state=proc_state,
                           proc_starttime=proc_starttime,
                           proc_comm=proc_comm,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        accepted_exes = process_probe.expected_exe_paths(efc_exe_paths)
        if proc_state != 'Z' and proc_exe not in accepted_exes:
            return _result(EFC_LOCK_CONFLICT, lock_path,
                           'lock owner is not EFC/EAC: comm=%s exe=%s' % (
                               proc_comm, proc_exe),
                           owner_pid=owner_pid,
                           proc_state=proc_state,
                           proc_starttime=proc_starttime,
                           proc_comm=proc_comm,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        if proc_state == 'Z':
            owner_is_efc = is_efc_comm(proc_comm)
            state = (EFC_ZOMBIE_LOCKED
                     if owner_is_efc and pidfile_pid == owner_pid
                     else EFC_UNKNOWN)
            reason = 'zombie EFC still owns lock'
            if state == EFC_UNKNOWN:
                reason = 'zombie owner identity or pidfile does not match EFC'
            return _result(state, lock_path, reason,
                           owner_pid=owner_pid,
                           proc_state=proc_state,
                           proc_starttime=proc_starttime,
                           proc_comm=proc_comm,
                           lock_dev=file_stat.st_dev,
                           lock_inode=file_stat.st_ino,
                           pidfile_pid=pidfile_pid)

        reason = 'EFC owns lock'
        if pidfile_pid != owner_pid:
            reason = 'EFC owns lock but pidfile is missing or stale'
        return _result(EFC_RUNNING, lock_path, reason,
                       owner_pid=owner_pid,
                       proc_state=proc_state,
                       proc_starttime=proc_starttime,
                       proc_comm=proc_comm,
                       lock_dev=file_stat.st_dev,
                       lock_inode=file_stat.st_ino,
                       pidfile_pid=pidfile_pid)
    finally:
        os.close(fd)


def same_lock_identity(left, right):
    return bool(
        left and right
        and left.owner_pid == right.owner_pid
        and left.proc_starttime == right.proc_starttime
        and left.lock_dev == right.lock_dev
        and left.lock_inode == right.lock_inode
    )


def wait_efc_readiness(mount_uuid, timeout=EFC_READINESS_TIMEOUT,
                       workspace_dir=EFC_WORKSPACE_DIR, proc_root='/proc',
                       previous_probe=None, poll_interval=EFC_READINESS_POLL_INTERVAL,
                       probe_fn=None, monotonic_fn=None, sleep_fn=None):
    """Wait briefly for a new EFC lock owner to become ready.

    DEAD and UNKNOWN are retryable while EFC is starting. A verified zombie or
    lock conflict is terminal. During an upgrade, ``previous_probe`` makes the
    old lock owner insufficient: readiness requires a different owner identity.
    """
    do_probe = probe_fn or probe_efc
    monotonic = monotonic_fn or time.monotonic
    sleep = sleep_fn or time.sleep
    deadline = monotonic() + max(0.0, timeout)
    previous_owner = (
        previous_probe
        if previous_probe is not None
        and previous_probe.state == EFC_RUNNING
        else None
    )

    while True:
        current = do_probe(mount_uuid, workspace_dir, proc_root)
        if current.state == EFC_RUNNING:
            if previous_owner is None or not same_lock_identity(previous_owner, current):
                return current
        elif current.state in (EFC_ZOMBIE_LOCKED, EFC_LOCK_CONFLICT):
            return current

        remaining = deadline - monotonic()
        if remaining <= 0:
            return current
        sleep(min(max(0.0, poll_interval), remaining))


def detach_zombie_lock(mount_uuid, expected, workspace_dir=EFC_WORKSPACE_DIR,
                       proc_root='/proc'):
    """Detach a verified zombie-owned inode from the canonical lock path."""
    current = probe_efc(mount_uuid, workspace_dir, proc_root)
    if current.state == EFC_DEAD:
        return DETACH_RELEASED, current, ''
    if current.state != EFC_ZOMBIE_LOCKED:
        return DETACH_ABORTED, current, 'current state is %s' % current.state
    if not same_lock_identity(expected, current):
        return DETACH_ABORTED, current, 'zombie lock identity changed'
    if not current.pidfile_match:
        return DETACH_ABORTED, current, 'zombie owner does not match pidfile'

    quarantine_path = '%s.zombie.%s.%s.%s' % (
        current.lock_path,
        current.owner_pid,
        current.proc_starttime,
        current.lock_inode,
    )
    if os.path.lexists(quarantine_path):
        return DETACH_ERROR, current, 'quarantine path already exists'

    renamed = False
    try:
        os.rename(current.lock_path, quarantine_path)
        renamed = True
        quarantine_stat = os.lstat(quarantine_path)
        if (quarantine_stat.st_dev, quarantine_stat.st_ino) != (
                current.lock_dev, current.lock_inode):
            raise RuntimeError('quarantined inode does not match probe')
    except OSError as error:
        detail = 'detach zombie lock failed: %s' % error
    except RuntimeError as error:
        detail = str(error)
    else:
        return DETACH_DETACHED, current, quarantine_path

    # The path may have been replaced between the final probe and rename. If
    # there is still no canonical path, restore what was moved so an error
    # cannot accidentally make a live lock invisible.
    if renamed and os.path.lexists(quarantine_path):
        try:
            if not os.path.lexists(current.lock_path):
                os.rename(quarantine_path, current.lock_path)
                detail = '%s; canonical path restored' % detail
            else:
                detail = '%s; canonical path already recreated' % detail
        except OSError as restore_error:
            detail = '%s; restore failed: %s' % (detail, restore_error)

    return DETACH_ERROR, current, detail


def process_alive_seconds(probe, proc_root='/proc'):
    if not probe:
        return 0
    return process_probe.process_alive_seconds(
        probe.owner_pid, probe.proc_starttime, proc_root)
