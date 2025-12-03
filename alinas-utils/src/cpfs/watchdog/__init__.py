#!/usr/bin/env python3
#
# Copyright 2021-2022 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import errno
import fcntl
import heapq
import json
import logging
import logging.handlers
import os
import site
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import namedtuple
from multiprocessing.pool import ThreadPool as Pool
from signal import SIGHUP, signal

PACKAGE_PATH = "/opt/aliyun/cpfs/"
site.addsitedir(PACKAGE_PATH)

try:
    import cpfs_nfs_common
    from cpfs_nfs_common import fatal_error
except ImportError:
    sys.stderr.write("not found aliyun cpfs path: {}cpfs_nfs_commmon".format(PACKAGE_PATH))
    sys.exit(-1)

VERSION = 'unknown'

CONFIG_FILE = '/etc/aliyun/cpfs/cpfs-utils.conf'
CONFIG_SECTION = 'mount-watchdog'

LOG_DIR = '/var/log/aliyun/cpfs'
LOG_FILE = 'mount-watchdog.log'

STATE_FILE_DIR = '/var/run/cpfs'
STATE_SIGN = 'sign'

Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])


def get_version():
    global VERSION

    if VERSION == 'unknown':
        proc = subprocess.Popen("yum list --installed aliyun-alinas-utils | grep aliyun-alinas | awk '{ print $2 }'",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, _ = proc.communicate()
        stdout = stdout.decode().strip()

        if proc.returncode == 0 and stdout:
            VERSION = stdout

    return VERSION


def get_local_dns(mount):
    return mount.server.split(':')[0]

def get_state_files(state_file_dir):
    """
    Return a dict of the absolute path of state files in state_file_dir, keyed by the mountpoint and port portion of
    the filename.

    Map: dns -> state_file_name
    eg. cpfs-6e1854899b.cn-hangzhou.cpfs.aliyuncs.com  -> cpfs-6e1854899b.cn-hangzhou.cpfs.aliyuncs.com
    """
    state_files = {}

    try:
        if os.path.isdir(state_file_dir):
            for sf in os.listdir(state_file_dir):
                if not (sf.startswith('cpfs-') and sf.endswith('cpfs.aliyuncs.com')):
                    continue

                state_files[sf] = sf
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('List state files failed: msg=%s', str(e))

    return state_files


def start_proxy(child_procs, state_file, command):
    # launch the tunnel in a process group so if it has any child processes, they can be killed easily
    logging.info('Starting proxy: "%s"', ' '.join(command))

    # no need to specify env
    tunnel = subprocess.Popen(command, preexec_fn=os.setsid)

    if not cpfs_nfs_common.is_pid_running(tunnel.pid):
        raise RuntimeError('Failed to start proxy for {0}: command={1}'.format(state_file, command))

    logging.info('Started proxy, pid: %d', tunnel.pid)

    child_procs.append(tunnel)
    return tunnel.pid


# strong guarantee
def clean_up_mount_state(state_file_dir, state_file, pid, is_running):
    if is_running:
        cpfs_nfs_common.kill_proxy(pid)

    if cpfs_nfs_common.is_pid_running(pid):
        logging.info('Proxy: %d is still running, will retry termination', pid)
    else:
        logging.info('Proxy: %d is no longer running, cleaning up state', pid)
        state_file_path = os.path.join(state_file_dir, state_file)
        lock_file_path = state_file_path + '.lock'
        try:
            with open(state_file_path) as f:
                state = json.load(f)
        except IOError as e:
            if e.errno == errno.ENOENT:
                # someone removes the state file, we can do nothing better than ignoring it
                return

            raise

        for f in state.get('files', list()):
            logging.debug('Deleting %s', f)
            try:
                os.remove(f)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise

        try:
            os.remove(state_file_path)
            os.remove(lock_file_path)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

# strong guarantee
def restart_proxy(child_procs, state, state_file_dir, state_file):
    new_tunnel_pid = start_proxy(child_procs, state_file, state['cmd'])
    state['pid'] = new_tunnel_pid

    try:
        logging.debug('Rewriting %s with new pid: %d', state_file, new_tunnel_pid)
        cpfs_nfs_common.rewrite_state_file(state, state_file_dir, state_file)
    except:
        try:
            cpfs_nfs_common.kill_proxy(new_tunnel_pid)
        except:
            # kill failed, we can do nothing better than ignoring it
            fatal_error('Failed to cleanup unused pid {0}'.format(new_tunnel_pid))

        raise


def check_alinas_mounts(watchdog, unmount_grace_period_sec_cfg, state_file_dir=STATE_FILE_DIR):
    nfs_mounts = cpfs_nfs_common.get_current_local_nfs_mounts()
    logging.debug('Current local NFS mounts: %s', list(nfs_mounts.values()))

    state_files = get_state_files(state_file_dir)
    logging.debug('Current state files in "%s": %s', state_file_dir, list(state_files.values()))

    for local_dns, state_file in state_files.items():
        try:
            with cpfs_nfs_common.lock_file(state_file) as _:
                state = watchdog.load_state_file(state_file_dir, state_file)
                if not state:
                    continue

                is_running = cpfs_nfs_common.is_pid_running(state['pid'])

                current_time = time.time()
                if 'unmount_time' in state:
                    unmount_grace_period_sec = int(state.get('unmount_grace_period_sec', unmount_grace_period_sec_cfg))
                    if state['unmount_time'] + unmount_grace_period_sec < current_time:
                        logging.info('Unmount grace period expired for %s', state_file)
                        if 'hp_terminating' not in state:
                            state['hp_terminating'] = True
                            logging.debug('Marking ha proxy for %s as terminated', state_file)
                            cpfs_nfs_common.rewrite_state_file(state, STATE_FILE_DIR, state_file)
                            logging.info('rewrite state file:{}'.format(state))
                        clean_up_mount_state(state_file_dir, state_file, state['pid'], is_running)

                elif local_dns not in nfs_mounts:
                    logging.info('recheck mount for "%s', state_file)
                    nfs_mounts = cpfs_nfs_common.get_current_local_nfs_mounts()
                    if local_dns not in nfs_mounts:
                        logging.info('No mount found for "%s"', state_file)
                        cpfs_nfs_common.mark_as_unmounted(state, state_file_dir, state_file, current_time)

                else:
                    if is_running:
                        logging.debug('Proxy for %s is running', state_file)
                    else:
                        logging.warning('Proxy for %s is not running', state_file)
                        restart_proxy(watchdog.child_procs, state, state_file_dir, state_file)
        except MemoryError:
            raise
        except Exception as e:
            logging.exception('OS errors, just retry later: local_dns=%s, error=%s', local_dns, str(e))
            time.sleep(30)

    watchdog.handle_events(nfs_mounts)


def check_child_procs(child_procs):
    for proc in child_procs:
        proc.poll()
        if proc.returncode is not None:
            logging.warning('Child proxy process %d has exited, returncode=%d', proc.pid, proc.returncode)
            child_procs.remove(proc)


def parse_arguments(args=None):
    if args is None:
        args = sys.argv

    if '-h' in args[1:] or '--help' in args[1:]:
        sys.stdout.write('Usage: %s [--version] [-h|--help]\n' % args[0])
        sys.exit(0)

    if '--version' in args[1:]:
        sys.stdout.write('%s Version: %s\n' % (args[0], VERSION))
        sys.exit(0)

# kill and restart, don't resort to more complicated methods since it's a nontrivial task
# and should happens rather rarely
class RestartCommand(object):
    def __init__(self, local_id, state_file_dir):
        self._state_file_dir = state_file_dir
        self._local_id = local_id

    @property
    def state_file_path(self):
        return os.path.join(self._state_file_dir, self._local_id)

    def run(self, nfsmounts, watchdog):
        if self._local_id not in nfsmounts:
            logging.warning('Local id not found: local_id=%s', self._local_id)
            return

        state = watchdog.load_state_file(self._state_file_dir, self._local_id)
        if not state:
            logging.warning('State file not found: local_id=%s, dir=%s', self._local_id, self._state_file_dir)
            return

        logging.info('Restart proxy: local_dns=%s', self._local_id)
        self._reload(state, watchdog.child_procs)

    def _reload(self, state, child_procs):
        pid = state['pid']
        cpfs_nfs_common.kill_proxy(pid)
        restart_proxy(child_procs, state, self._state_file_dir, self._local_id)


class RefreshDnsCommand(RestartCommand):
    def __init__(self, local_id, state_file_dir):
        RestartCommand.__init__(self, local_id, state_file_dir)

    def run(self, nfsmounts, watchdog):
        if self._local_id not in nfsmounts:
            logging.warning('Local id not found: local_id=%s', self._local_id)
            return

        state = watchdog.load_state_file(self._state_file_dir, self._local_id)
        if not state:
            logging.warning('State file not found: local_id=%s, dir=%s', self._local_id, self._state_file_dir)
            return

        find_new_server = False
        old_primary_server = state['nas_ip']
        old_backup_server = state['backup_ip']
        new_primary_server = ""
        new_backup_server = ""
        nas_dns = state['nas_dns']
        need_resolve = False

        if not cpfs_nfs_common.cpfs_dns_contains_ip(nas_dns, old_primary_server):
            logging.warning('cpfs primary server:{} is shrunk, will resolve dns: {}'.format(old_primary_server, nas_dns))
            need_resolve = True
        else:
            if not cpfs_nfs_common.is_server_ready(old_primary_server, 2049):
                logging.warning('cpfs primary server:{} is down, try backup server:{}'.format(old_primary_server, old_backup_server))
                if not cpfs_nfs_common.is_server_ready(old_backup_server, 2049):
                    logging.warning('both cpfs primary server:{} and backup server:{} are down'.format(old_primary_server, old_backup_server))
                    need_resolve = True

        if not need_resolve:
            return

        # try resolve new server
        for _ in range(3):
            new_primary_server, new_backup_server = cpfs_nfs_common.resolve_cpfs_dns(nas_dns)
            if cpfs_nfs_common.is_server_ready(new_primary_server, 2049):
                find_new_server = True
                break

        if not find_new_server:
            logging.error('Refresh dns failed, not find new available servers: local_id=%s, old_primary_server=%s, old_backup_server=%s, new_primary_server=%s, new_backup_server=%s',
                    self._local_id, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
            return

        logging.info('Refresh dns: local_id=%s, old_primary_server=%s, old_backup_server=%s, new_primary_server=%s, new_backup_server=%s',
                    self._local_id, old_primary_server, old_backup_server, new_primary_server, new_backup_server)

        state['nas_ip'] = new_primary_server
        state['backup_ip'] = new_backup_server

        cpfs_nfs_common.update_haproxy_config_file(self._local_id, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
        self._reload(state, watchdog.child_procs)

class ReloadCommand(object):
    def run(self, nfsmounts, watchdog):
        for local_dns in nfsmounts:
            logging.info('Reload proxy: local_dns=%s', local_dns)

            watchdog.queue_restart_for(local_dns)


class EventBus(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._q = []

    def __len__(self):
        self._lock.acquire()
        try:
            return len(self._q)
        finally:
            self._lock.release()

    def append(self, cmd):
        self._lock.acquire()
        try:
            self._q.append(cmd)
        finally:
            self._lock.release()

    def fetch_and_remove(self):
        result = []

        self._lock.acquire()
        try:
            result, self._q = self._q, result
        finally:
            self._lock.release()

        return result


class PingTask(object):
    def __init__(self, local_dns, mountpoint, timeout):
        self._local_dns = local_dns
        self._mountpoint = mountpoint
        self._timeout = timeout
        self._done = False

    @property
    def done(self):
        return self._done

    @property
    def timeout(self):
        return self._timeout

    @property
    def local_dns(self):
        return self._local_dns

    @property
    def mountpoint(self):
        return self._mountpoint

    def run(self):
        try:
            logging.debug('Ping %s on %s at %s', self._local_dns, self._mountpoint, time.time())

            os.statvfs(self._mountpoint)
        except Exception as e:
            logging.error('Ping %s on %s failed: %s', self._local_dns, self._mountpoint, str(e))

    def complete(self):
        logging.debug('Ping completed: local_dns=%s, mountpoint=%s', self.local_dns, self.mountpoint)
        self._done = True


class EventWaiter(object):
    def __init__(self):
        self._interrupted = threading.Condition()
        self._has_pending_interruption = False
        self._events = []

    # basic guarantee
    def wait(self, timeout=60):
        sleep_interval = timeout if len(self._events) == 0 else max(0, self._events[0][0] - time.time())

        self._do_wait(sleep_interval)
        return self._do_poll()

    def _do_wait(self, sleep_interval):
        if sleep_interval > 0:
            self._interrupted.acquire()
            try:
                if self._has_pending_interruption:
                    self._has_pending_interruption = False
                else:
                    self._interrupted.wait(sleep_interval)
            finally:
                self._interrupted.release()

    def _do_poll(self):
        tasks = []
        now = time.time()
        while len(self._events) > 0 and self._events[0][0] <= now:
            tasks.append(heapq.heappop(self._events))

        return tasks

    # no except
    def interrupt(self):
        self._interrupted.acquire()
        try:
            if not self._has_pending_interruption:
                self._has_pending_interruption = True
                self._interrupted.notify_all()
        finally:
            self._interrupted.release()

    # strong guarantee
    def add_timer(self, timeout, data, callback):
        expired_at = time.time() + max(1, timeout)
        need_wakeup = self._need_wakeup(expired_at)
        heapq.heappush(self._events, (expired_at, data, callback))

        if need_wakeup:
            self.interrupt()

    def _need_wakeup(self, expired_at):
        blocking_at = None if len(self._events) == 0 else self._events[0]
        return not blocking_at or blocking_at[0] > expired_at

    # strong guarantee
    def event_count(self):
        return len(self._events)


class LiveDetector(object):
    PING_TIMEOUT_IN_SEC = 60 * 5

    def __init__(self, config, eventbus, watchdog, state_file_dir=STATE_FILE_DIR):
        self._state_file_dir = state_file_dir
        self._eventbus = eventbus
        self._watchdog = watchdog

        self._executor = None
        self._worker = threading.Thread(target=self._run)
        self._running = True

        self._event_waiter = EventWaiter()
        self._pending_refresh = None

        self._volumes = {}

    def _run(self):
        logging.info('LiveDetector is started')

        while self._running:
            try:
                tasks = self._event_waiter.wait()
                self._run_tasks(tasks)
            except Exception as e:
                fatal_error('Run tasks failed, cannot recover without loss: {0}'.format(str(e)))
            except:
                logging.warning('Exit the process')
                os._exit(-1)

            try:
                self._refresh()
            except Exception:
                logging.exception('Refresh failed, retry later')
            except:
                logging.warning('Exit the process')
                os._exit(-1)

        logging.info('LiveDetector is stopped')

    def _run_tasks(self, tasks):
        for expired_at, data, cb in tasks:
            cb(data)

    def _do_ping(self, data):
        local_dns, mountpoint, timeout = data

        if local_dns not in self._volumes:
            logging.debug('Ping a non exist mount, skipped: local_dns=%s', local_dns)
            return

        try:
            task = PingTask(local_dns, mountpoint, timeout)
            self._executor.apply_async(task.run, callback=lambda _: self._on_task_done(self, task))
        except:
            logging.exception('Init ping task failed, retry later')
            self._schedule_ping(local_dns, mountpoint, timeout)
        else:
            self._event_waiter.add_timer(self.PING_TIMEOUT_IN_SEC, task, self._do_ping_timeout)

    # called in executor threads
    @staticmethod
    def _on_task_done(detector, task):
        try:
            detector._event_waiter.add_timer(0, task, detector._do_ping_complete)
        except:
            fatal_error('Handle task completion callback failed: local_dns={0}'.format(task.local_dns))

    def _do_ping_complete(self, pingtask):
        # we don't care if the task is timed out or not, just schedule it
        pingtask.complete()
        self._schedule_ping(pingtask.local_dns, pingtask.mountpoint, pingtask.timeout)

    def _do_ping_timeout(self, pingtask):
        # won't reschedule here, restart and wait previous task to finish
        if pingtask.done:
            return

        logging.warning('Ping timeout, prepare to restart proxy: local_dns=%s, mountpoint=%s, timeout=%s',
                        pingtask.local_dns,
                        pingtask.mountpoint,
                        pingtask.timeout)
        self._eventbus.append(RestartCommand(pingtask.local_dns, self._state_file_dir))

    # strong guarantee
    def _refresh(self):
        if self._pending_refresh is None:
            return

        pending_refresh = self._pending_refresh
        self._pending_refresh = None  # loss is okay

        removed = [local_dns for local_dns in self._volumes if local_dns not in pending_refresh]
        added = [local_dns for local_dns in pending_refresh if local_dns not in self._volumes]

        for local_dns in removed:
            del self._volumes[local_dns]

        for local_dns in added:
            state = self._watchdog.load_state_file(self._state_file_dir, local_dns)
            if not state:
                logging.error('State file not found for %s', local_dns)
                continue

            timeout = state.get('timeo', 30) / 2
            mountpoint = state.get('mountpoint', None)
            if not mountpoint:
                logging.error('Mountpath is not specified: local_dns=%s', local_dns)
                mountpoint = '/'

            self._volumes[local_dns] = state
            try:
                self._schedule_ping(local_dns, mountpoint, timeout, force=True)
            except:
                del self._volumes[local_dns]

                raise

    def _schedule_ping(self, local_dns, mountpoint, timeout, force=False):
        if not force and local_dns not in self._volumes:
            return

        logging.debug('Schedule ping: local_dns=%s, mountpoint=%s, timeout=%s', local_dns, mountpoint, timeout)
        self._event_waiter.add_timer(timeout, (local_dns, mountpoint, timeout), self._do_ping)

    def start(self):
        self._running = True
        self._executor = Pool(4)
        self._worker.start()

    def stop(self):
        worker = self._worker
        executor = self._executor

        self._worker = None
        self._executor = None

        if worker:
            try:
                self._running = False
                self._event_waiter.interrupt()
            except:
                pass
            finally:
                worker.join()

        if executor:
            try:
                executor.close()
            except:
                pass
            finally:
                executor.join()

    def refresh(self, local_mounts):
        self._pending_refresh = local_mounts  # atomic
        self._wakeup()

    def _wakeup(self):
        self._event_waiter.interrupt()


# stateless
class DnsRefresher(object):
    def __init__(self, config, eventbus, watchdog, state_file_dir=STATE_FILE_DIR):
        self._refresh_interval = config.getint(CONFIG_SECTION, 'dns_refresh_interval',
                                               default=120,
                                               minvalue=60,
                                               maxvalue=24 * 3600)
        self._eventbus = eventbus
        self._watchdog = watchdog
        self._state_file_dir = state_file_dir

        self._worker = threading.Thread(target=self._run)
        self._running = True
        self._quit_signaled = threading.Condition()

    def _run(self):
        logging.info('DnsRefresher started: interval=%s', self._refresh_interval)

        while self._running:
            self._quit_signaled.acquire()
            try:
                self._quit_signaled.wait(self._refresh_interval)

                state_files = get_state_files(self._state_file_dir)

                for local_id in state_files:
                    self._check_dns(local_id)
            except Exception as e:
                logging.exception('Unexpected exception: msg=%s', str(e))
            except:
                logging.warning('Exit the process')
                os._exit(-1)
            finally:
                self._quit_signaled.release()

        logging.info('DnsRefresher stopped')

    # strong guarantee
    def _check_dns(self, local_id):
        state = self._watchdog.load_state_file(self._state_file_dir, local_id)
        if not state:
            logging.warning('State file not found: local_id=%s', local_id)
            return

        nas_dns = state['nas_dns']
        nas_ip = state['nas_ip']
        backup_ip = state['backup_ip']

        primary_die = not cpfs_nfs_common.is_server_ready(nas_ip, 2049)
        primary_shrink = not cpfs_nfs_common.cpfs_dns_contains_ip(nas_dns, nas_ip)
        if primary_shrink or (primary_die and not cpfs_nfs_common.is_server_ready(backup_ip, 2049)):
            logging.warning('Old server has died, try to change dns to new server: local_id=%s, dns=%s, old_primary_server=%s, old_backup_server=%s', local_id, nas_dns, nas_ip, backup_ip)
            self._eventbus.append(RefreshDnsCommand(local_id, self._state_file_dir))

    def start(self):
        logging.info('DnsRefresher is starting')

        self._running = True
        self._worker.start()

    def stop(self):
        logging.info('DnsRefresher is stopping')

        worker = self._worker
        self._worker = None

        if not worker:
            return

        self._quit_signaled.acquire()
        try:
            self._running = False
            self._quit_signaled.notify_all()
        except:
            pass
        finally:
            self._quit_signaled.release()
            worker.join()


class Watchdog(object):
    def __init__(self, config, state_file_dir=STATE_FILE_DIR):
        self._config = config
        self._state_file_dir = state_file_dir
        self._eventbus = EventBus()
        self._child_procs = []
        self._reload_requested = False
        self._detector = LiveDetector(self._config, self._eventbus, self, state_file_dir)
        self._refresher = DnsRefresher(self._config, self._eventbus, self, state_file_dir)
        self._file_manager = cpfs_nfs_common.StateFileManager()

    @property
    def child_procs(self):
        return self._child_procs

    def start(self):
        signal(SIGHUP, self._on_sighup)
        self._detector.start()
        self._refresher.start()

    def _on_sighup(self, *args):
        self._reload_requested = True

    def stop(self):
        self._refresher.stop()
        self._detector.stop()

    def handle_events(self, nfsmounts):
        self._handle_signals()
        self._run_commands(nfsmounts)
        self._detector.refresh(nfsmounts)

    def _handle_signals(self):
        reload_request = self._reload_requested

        if reload_request:
            self._eventbus.append(ReloadCommand())
            self._reload_requested = False

    def _run_commands(self, nfsmounts):
        for cmd in self._eventbus.fetch_and_remove():
            try:
                cmd.run(nfsmounts, self)
            except Exception as e:
                logging.exception('Run command failed: msg=%s', str(e))

    def queue_restart_for(self, local_dns):
        self._eventbus.append(RestartCommand(local_dns, self._state_file_dir))

    def load_state_file(self, state_file_dir, state_file):
        return self._file_manager.load_state_file(state_file_dir, state_file)


def main():
    parse_arguments()
    cpfs_nfs_common.check_env()

    config = cpfs_nfs_common.read_config(CONFIG_FILE)
    cpfs_nfs_common.bootstrap_logging(config, LOG_DIR, LOG_FILE, CONFIG_SECTION)

    poll_interval_sec = config.getint(CONFIG_SECTION, 'poll_interval_sec', default=1, minvalue=1, maxvalue=60)
    unmount_grace_period_sec = config.getint(CONFIG_SECTION, 'unmount_grace_period_sec',
                                             default=30, minvalue=10, maxvalue=600)

    watchdog = Watchdog(config)
    try:
        watchdog.start()

        while True:
            check_alinas_mounts(watchdog, unmount_grace_period_sec)
            check_child_procs(watchdog.child_procs)

            time.sleep(poll_interval_sec)
    finally:
        watchdog.stop()


if '__main__' == __name__:
    main()
