#!/usr/bin/env python3
# coding=utf-8
#
# Copyright 2021-2022 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
#
# Copy this script to /sbin/mount.cpfs-nfs and make sure it is executable.
#
# You will be able to mount an cpfs-nfs file system by its short name, by adding it
# to /etc/fstab. The syntax of an fstab entry is:
#
# [Device] [Mount Point] [File System Type] [Options] [Dump] [Pass]
#
# Add an entry like this:
#
#   0123456789-abcde.cn-qingdao.cpfs.aliyuncs.com     /mount_point    cpfs-nfs     _netdev         0   0
#
# Using the 'cpfs-nfs' type will cause '/sbin/mount.cpfs-nfs' to be called by 'mount -a'
# for this file system. The '_netdev' option tells the init system that the
# 'cpfs-nfs' type is a networked file system type. This has been tested with systemd
# (aliyun Linux 17.1, CentOS 7, RHEL 7, Debian 9, and Ubuntu 16.04)
#
# Once there is an entry in fstab, the file system can be mounted with:
#
#   sudo mount /mount_point
#
# The script will add recommended mount options, if not provided in fstab.

import errno
import fcntl
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections import namedtuple
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from signal import SIGTERM

try:
    from configparser import ConfigParser, NoOptionError, NoSectionError
except ImportError:
    import ConfigParser
    from ConfigParser import NoOptionError, NoSectionError

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    from urllib.parse import urlencode
except ImportError:
    from urllib2 import URLError, HTTPError, build_opener, urlopen, Request, HTTPHandler
    from urllib import urlencode

YELLOW = '\033[33m{}\033[0m'

DEFAULT_LOG_MSG = """
\033[33mIf you have questions about CPFS services,\033[0m
\033[33mDingTalk joins the technical support group, group number: \033[1;31;40m31045006299\033[0m,
\033[33mor DingTalk contacts expert support, DingTalk number: \033[1;31;40mifu-loafw7jyk\033[0m.
"""


def fatal_error(user_message, log_message=None, exit_code=1, exception=None):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n%s' % (user_message, DEFAULT_LOG_MSG))
    logging.error(log_message)
    if exception and issubclass(exception, Exception):
        raise exception.__class__(user_message)
    sys.exit(exit_code)


STATE_FILE_DIR = '/var/run/cpfs'
STATE_SIGN = 'sign'
ALINAS_LOCK = 'cpfs.lock'

LOCAL_DNS_PATTERN = re.compile('^(?P<mnt_id>[-0-9a-zA-Z]+).(?P<region>[-0-9a-zA-Z]+).cpfs.aliyuncs.com(.)?$')
Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])


def sign_state(state):
    import hashlib

    keys = sorted(state.keys())
    md5 = hashlib.md5()

    for key in keys:
        val = state[key]
        if type(val) is list:
            for x in val:
                md5.update(str(x).encode('utf-8'))
        else:
            md5.update(str(val).encode('utf-8'))

    return md5.hexdigest()


# strong guarantee
def rewrite_state_file(state, state_file_dir, state_file):
    with lock_alinas(state_file_dir) as _:
        tmp_state_file = os.path.join(state_file_dir, '~%s' % state_file)
        try:
            with open(tmp_state_file, 'w') as f:
                signed_state = dict(state)
                signed_state[STATE_SIGN] = sign_state(state)
                json.dump(signed_state, f)

            os.rename(tmp_state_file, os.path.join(state_file_dir, state_file))
        except Exception as e:
            try:
                os.unlink(tmp_state_file)
            except OSError:
                if e.errno == errno.ENOENT:
                    pass
            except:
                # others are ignored to avoid hide the root cause
                pass

            logging.error('rewrite state file failed, {}'.format(e))

            raise e


def get_random_index(weights):
    total_weight = sum(weights)
    random.seed(str(uuid.uuid1()))
    num = random.randint(0, total_weight - 1)
    for i, weight in enumerate(weights):
        num -= weight
        if num < 0:
            return i


def get_ips(ips, weights):
    main_index = get_random_index(weights)
    main_ip = ips.pop(main_index)
    weights.pop(main_index)
    if len(weights) == 0:
        return main_ip, main_ip
    backup_index = get_random_index(weights)
    backup_ip = ips[backup_index]
    return main_ip, backup_ip


REVOLVE_DNS_RETRY = 5


def _resolve_cpfs_dns(dns):
    if not dns.endswith('.'):
        dns += '.'
    for i in range(REVOLVE_DNS_RETRY):
        try:
            cmd = 'host -t TXT {0}|grep \'^{0}\''.format(dns)
            out = subprocess.check_output(cmd, shell=True).decode('utf-8')
            weight_ips = [line.split('"')[1] for line in out.strip().split('\n')]
            if len(weight_ips) < 2:
                logging.warning('Only one server ip found: \n%s', out)
            ips = []
            weights = []
            for weight_ip in weight_ips:
                outs = weight_ip.split()
                if len(outs) != 2:
                    fatal_error('Failed to decode domain: {0}'.format(weight_ip))
                ips.append(outs[0])
                weights.append(int(outs[1]))
            return ips, weights

        except Exception as e:
            if i == REVOLVE_DNS_RETRY - 1:
                fatal_error('Failed to resolve domain: {0}: {1}'.format(dns, e))
            else:
                time.sleep(0.1)


def resolve_cpfs_dns(dns):
    ips, weights = _resolve_cpfs_dns(dns)
    return get_ips(ips, weights)


def cpfs_dns_contains_ip(dns, ip):
    ips, _ = _resolve_cpfs_dns(dns)
    return ip in ips


def is_pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_proxy(pid):
    process_group = os.getpgid(pid)
    logging.info('Terminating running proxy - PID: %d, group ID: %s', pid, process_group)
    os.killpg(process_group, SIGTERM)


def is_proxy_ready(ip, port):
    sk = socket.socket()
    try:
        sk.connect((ip, port))
        return True
    except:
        return False
    finally:
        sk.close()


def is_server_ready(ip, port):
    sk = socket.socket()
    sk.settimeout(1)
    try:
        sk.connect((ip, port))
        return True
    except:
        return False
    finally:
        sk.close()


CPFS_PRIMARY = 'cpfs_primary'
CPFS_BACKUP = 'cpfs_backup'


def try_update_haproxy_config_line(line, server_type, old_server, new_server):
    """
    backend bk2049
       server cpfs_primary {remote}:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 on-marked-up shutdown-backup-sessions
       server cpfs_backup  {backup}:2049 maxconn 2048 check port 2049 inter 2s fall 8 rise 30 backup
    """
    old_server = '{}:2049'.format(old_server)
    new_server = '{}:2049'.format(new_server)
    params = line.strip().split()
    if len(params) < 3:
        return line
    if params[0] != 'server' or params[1] != server_type:
        return line
    if params[2] != old_server:
        logging.warning('Update haproxy configuration: old_%s in config %s not equal to %s, still switch', server_type, params[2], old_server)
    line = line.replace(params[2], new_server)
    return line

def get_haproxy_config_file_path(domain, state_file_dir=STATE_FILE_DIR):
    state = load_state_file(state_file_dir, domain)
    if 'config_file' in state:
        return state['config_file']
    else:
        return os.path.join(STATE_FILE_DIR, 'haproxy-config.%s' % domain)

def update_haproxy_config_file(local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server, state_file_dir=STATE_FILE_DIR):
    config_data = ""
    haproxy_config_file = get_haproxy_config_file_path(local_dns)
    tmp_haproxy_file_name = '~' + os.path.basename(haproxy_config_file)
    tmp_haproxy_config_file = os.path.join(os.path.dirname(haproxy_config_file), tmp_haproxy_file_name)
    try:
        with lock_file(local_dns) as _:
            with open(haproxy_config_file, 'r') as f:
                for line in f:
                    line = try_update_haproxy_config_line(line, CPFS_PRIMARY, old_primary_server, new_primary_server)
                    line = try_update_haproxy_config_line(line, CPFS_BACKUP, old_backup_server, new_backup_server)
                    config_data += line

            with open(tmp_haproxy_config_file, 'w') as f:
                f.write(config_data)

            os.rename(tmp_haproxy_config_file, haproxy_config_file)
            logging.info('Update haproxy configuration to %s: local_dns=%s, old_primary_server=%s, old_backup_server=%s, new_primary_server=%s, new_backup_server=%s',
                         haproxy_config_file, local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
    except:
        try:
            os.unlink(tmp_haproxy_config_file)
        except OSError as e:
            if e.errno == errno.ENOENT:
                return
        except:
            # others are ignored to avoid hide the root cause
            pass
        raise


def get_clientaddr(dns, ip):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sk.connect((ip, 2049))
        return sk.getsockname()[0]
    except IOError:
        fatal_error('Connection to {0}({1}) failed, please check the network'.format(dns, ip))
    finally:
        sk.close()


@contextmanager
def lock_alinas(state_file_dir=STATE_FILE_DIR):
    path = os.path.join(state_file_dir, ALINAS_LOCK)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)

    try:
        logging.debug('try lock {}'.format(ALINAS_LOCK))
        fcntl.lockf(fd, fcntl.LOCK_EX)
        logging.debug('lock acquired {}'.format(ALINAS_LOCK))
        yield
    except:
        logging.info('occurs error during lock file, {}'.format(traceback.format_exc()))
        raise
    finally:
        os.close(fd)
        logging.debug('lock released: {}'.format(ALINAS_LOCK))


@contextmanager
def lock_file(state_file, state_file_dir=STATE_FILE_DIR):
    if not os.path.exists(state_file_dir):
        os.makedirs(state_file_dir, exist_ok=True)

    state_file = state_file + '.lock'
    path = os.path.join(state_file_dir, state_file)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)

    try:
        logging.debug('try lock {}'.format(state_file))
        fcntl.lockf(fd, fcntl.LOCK_EX)
        logging.debug('lock acquired {}'.format(state_file))
        yield
    except:
        logging.info('occurs error during lock file, state_file:{}, {}'.format(state_file, traceback.format_exc()))
        raise
    finally:
        os.close(fd)
        logging.debug('lock released: {}'.format(state_file))


def is_integral(state):
    saved_sign = state.pop(STATE_SIGN, '')
    computed_sign = sign_state(state)
    return saved_sign == computed_sign


class StateFileManager(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._corrupted_files = {}

    def load_state_file(self, state_file_dir, state_file):
        state_file_path = os.path.join(state_file_dir, state_file)
        try:
            with open(state_file_path) as f:
                try:
                    state = json.load(f)
                    if is_integral(state):
                        result = state
                    else:
                        logging.error('State file for %s is modified by others, ignored', state_file_path)
                        result = None
                except ValueError:
                    logging.error('Unable to parse json in %s', state_file_path)
                    result = None

            if result:
                self.notify_good(state_file_path)
            else:
                self.notify_bad(state_file_path)

            return result
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise

            return None

    def notify_good(self, state_file_path):
        self._lock.acquire()
        try:
            if state_file_path in self._corrupted_files:
                del self._corrupted_files[state_file_path]
        finally:
            self._lock.release()

    def notify_bad(self, state_file_path):
        self._lock.acquire()
        try:
            self._corrupted_files[state_file_path] = self._corrupted_files.get(state_file_path, 0) + 1
            if self._corrupted_files[state_file_path] <= 10:
                return

            del self._corrupted_files[state_file_path]
        finally:
            self._lock.release()

        self._dump_state_file(state_file_path)
        self._safe_remove(state_file_path)

    def _dump_state_file(self, state_file_path):
        _1MB = 1024 * 1024
        try:
            size = os.path.getsize(state_file_path)
            if size >= _1MB:
                logging.warning('Dump state file failed, the file is too large: size=%s', size)
                return

            with open(state_file_path) as f:
                logging.warning('Dump state file: %s', f.read())
        except Exception as e:
            logging.warning('Dump state file %s failed, ignored: %s', state_file_path, str(e))

    def _safe_remove(self, state_file_path):
        logging.warning('Remove aged corrupted state file %s', state_file_path)
        try:
            os.unlink(state_file_path)
        except Exception:
            pass


def load_state_file(state_file_dir, state_file):
    state_manager = StateFileManager()
    return state_manager.load_state_file(state_file_dir, state_file)


def get_local_dns(mount):
    return mount.server.split(':')[0]


def is_alinas_mount(mount):
    return mount.server.startswith('cpfs-') and 'cpfs.aliyuncs.com' in mount.server and 'nfs' in mount.type


def get_current_local_nfs_mounts(mount_file='/proc/mounts'):
    """
    Return a dict of the current NFS mounts for servers running on localhost, keyed by the mountpoint and port as it
    appears in cpfs watchdog state files.

    Eg.
    cpfs-6e1854899b-deo54.cpfs.aliyuncs.com:/ /mnt nfs vers=3,port=30000,mountaddr=127.0.1.255,mountport=30000,addr=127.0.1.255 0 0
    """
    mounts = []

    with open(mount_file) as f:
        for mount in f:
            m = Mount._make(mount.strip().split())
            if is_alinas_mount(m):
                mounts.append(m)

    mount_dict = {}
    for m in mounts:
        mount_dict[get_local_dns(m)] = m

    return mount_dict


# strong guarantee
def mark_as_unmounted(state, state_file_dir, state_file, current_time):
    logging.debug('Marking %s as unmounted at %d', state_file, current_time)
    state['unmount_time'] = current_time

    rewrite_state_file(state, state_file_dir, state_file)

    return state


class SafeConfig(object):
    def __init__(self, config, configfile, configfile_error):
        self._config = config
        self.configfile = configfile
        self.configfile_error = configfile_error

    def get(self, section, key, default):
        try:
            return self._config.get(section, key)
        except:
            return default

    def getint(self, section, key, default, minvalue, maxvalue):
        try:
            value = self._config.getint(section, key)
            if value < minvalue:
                return minvalue
            elif value > maxvalue:
                return maxvalue
            else:
                return value
        except:
            return default

    def getboolean(self, section, key, default):
        try:
            return self._config.getboolean(section, key)
        except:
            return default


# If the file not exists, no side effects
def read_config(config_file):
    p = ConfigParser()
    files_loaded = p.read(config_file)
    if not files_loaded:
        msg = 'Config file {0} is not found, please be attention'.format(config_file)
        sys.stderr.write('{0}\n'.format(msg))
    return SafeConfig(p, config_file, configfile_error=not files_loaded)


def bootstrap_logging(config, log_dir, log_file, config_section):
    raw_level = config.get(config_section, 'logging_level', default='info')
    levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    level = levels.get(raw_level.lower())
    level_error = False

    if not level:
        # delay logging error about malformed log level until after logging is configured
        level_error = True
        level = logging.INFO

    max_bytes = config.getint(config_section, 'logging_max_bytes',
                              default=1048576, minvalue=1048576, maxvalue=1048576 * 16)
    file_count = config.getint(config_section, 'logging_file_count', default=8, minvalue=1, maxvalue=16)

    handler = RotatingFileHandler(os.path.join(log_dir, log_file), maxBytes=max_bytes, backupCount=file_count)
    handler.setFormatter(logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(lineno)d - %(message)s'))

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)

    if level_error:
        logging.error('Malformed logging level "%s", setting logging level to %s', raw_level, level)
    if config.configfile_error:
        logging.error('Config file %s is not found, please check', config.configfile)


def assert_root():
    if os.geteuid() != 0:
        fatal_error('only root can run mount.cpfs-nfs')


def assert_py3():
    version_info = sys.version_info
    major = version_info[0]
    if major < 3:
        fatal_error('only python3 is supported!')


def check_env():
    assert_root()
    assert_py3()
