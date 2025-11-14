#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import base64
import errno
import fcntl
import hashlib
import hmac
import itertools
import heapq
import json
import logging
import logging.handlers
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import re
import threading
import time
import uuid
import shutil
import struct
from datetime import datetime
from collections import namedtuple
from logging.handlers import RotatingFileHandler
from logging import StreamHandler
from multiprocessing.pool import ThreadPool as Pool
from signal import SIGHUP, SIGTERM
from contextlib import contextmanager

try:
    from configparser import ConfigParser, NoOptionError, NoSectionError
except ImportError:
    import ConfigParser
    from ConfigParser import NoOptionError, NoSectionError

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus
from datetime import datetime, timedelta

VERSION = 'unknown'
SERVICE = 'aliyun-alinas'
RPM_NAME = 'alinas-utils'

CONFIG_FILE = '/etc/aliyun/alinas/alinas-utils.conf'
WATCHDOG_CONFIG_SECTION = 'mount-watchdog'
NAS_AGENT_CONFIG_SECTION = 'nas-agent'
CLIENT_INFO_SECTION = "client-info"
CLIENT_SOURCE_STR_LEN_LIMIT = 100
DEFAULT_UNKNOWN_VALUE = "unknown"
# 50ms
DEFAULT_TIMEOUT = 0.05

OS_RELEASE_PATH = '/etc/os-release'
LOG_DIR = '/var/log/aliyun/alinas'
LOG_FILE = 'mount-watchdog.log'
NAS_AGENT_LOG_DIR = os.path.join(LOG_DIR, 'nas-agent')
NAS_AGENT_LOG_FILE = 'nas-agent.log'

# used in cgroup memory size calculation, get size via gdb, not accurate but enough
UNAS_SHM_PAGE_CAPACITY_FLAG = 'unas_LocalDataCacheMemory'
UNAS_SHM_PAGE_CAPACITY_DEFAULT = 12000
UNAS_SHM_PAGE_SIZE = 4160

UNAS_SHM_JOURNAL_CAPACITY_FLAG = 'unas_ShmJournalCapacity'
UNAS_SHM_JOURNAL_CAPACITY_DEFAULT = 262144
UNAS_SHM_JOURNAL_SIZE = 1472

UNAS_SHM_VOLUME_CAPACITY_FLAG = 'unas_ShmVolumeCapacity'
UNAS_SHM_VOLUME_CAPACITY_DEFAULT = 1
UNAS_SHM_VOLUME_SIZE = 73728

UNAS_SHM_FILE_CAPACITY_FLAG = 'unas_ShmFileCapacity'
UNAS_SHM_FILE_CAPACITY_DEFAULT = 0 # 0 for sys-file-max
UNAS_SHM_FILE_SIZE = 64

UNAS_SHM_DADI_CAPACITY_FLAG = 'tier_DadiMemCacheCapacityMB'
UNAS_SHM_DADI_CAPACITY_DEFAULT = 0

CGROUP_DIR = '/sys/fs/cgroup/memory/efc'
OLD_CGROUP_DIR = '/sys/fs/cgroup/memory/eac'
CGROUP_LIMIT_FILE = 'memory.limit_in_bytes'
CGROUP_PROCS_FILE = 'cgroup.procs'
CGROUP_SWAP_CONTROL_FILE = 'memory.swappiness'
CGROUP_OOM_CONTROL_FILE = 'memory.oom_control'
CGROUP_MEM_STAT_FILE = 'memory.stat'
CGROUP_BASE_MEMORY_LIMIT_SIZE = 30 * 1024 * 1024 * 1024 # not contain share memory
URING_MEMORY_LIMIT_SIZE = 15 * 1024 * 1024 * 1024
CGROUP_MEMORY_LIMIT_RATIO = 1 # percent of total memory

STATE_FILE_DIR = '/var/run/alinas'
EFC_WORKSPACE_DIR = '/var/run/efc'
OLD_EFC_WORKSPACE_DIR = '/var/run/eac'
STATE_SIGN = 'sign'
DNS_LOCK = 'dns.lock'
PRIVATE_KEY_FILE = '/etc/aliyun/alinas/privateKey.pem'
DATE_ONLY_FORMAT = '%Y%m%d'
SIGV4_DATETIME_FORMAT = '%Y%m%dT%H%M%SZ'
CERT_DATETIME_FORMAT = '%y%m%d%H%M%SZ'
DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN = 15
DEDFAULT_RAM_CONFIG_FILE = '/etc/aliyun/alinas/.credentials'
RAM_CONFIG_SECTION = 'NASCredentials'
CA_CONFIG_BODY = """dir = %s
RANDFILE = $dir/database/.rand

[ ca ]
default_ca = local_ca

[ local_ca ]
database = $dir/database/index.txt
serial = $dir/database/serial
private_key = %s
cert = $dir/certificate.pem
new_certs_dir = $dir/certs
default_md = sha256
preserve = no
policy = efsPolicy
x509_extensions = v3_ca

[ efsPolicy ]
CN = supplied

[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
CN = %s

%s

%s

%s
"""
# SigV4 Auth
ALGORITHM = 'ALIYUN4-HMAC-SHA256'
ALIYUN4_REQUEST = 'aliyun4_request'

HTTP_REQUEST_METHOD = 'GET'
CANONICAL_URI = '/'
CANONICAL_HEADERS_DICT = {"host": "%s"}
CANONICAL_HEADERS = '\n'.join(['%s:%s' % (k, v) for k, v in sorted(CANONICAL_HEADERS_DICT.items())])
SIGNED_HEADERS = ';'.join(CANONICAL_HEADERS_DICT.keys())
REQUEST_PAYLOAD = ''

NOT_BEFORE_MINS = 15
NOT_AFTER_HOURS = 3
DATE_ONLY_FORMAT = "%Y%m%d"
SIGV4_DATETIME_FORMAT = "%Y%m%dT%H%M%SZ"
CERT_DATETIME_FORMAT = "%y%m%d%H%M%SZ"

# unas configuration
SESSMGR_LOCK = 'sessmgr.lock'
SESSMGR_LOG_CONF_TEMPLATE_PATH = '/etc/aliyun/alinas/log_conf.efc.sessmgr.json'
SESSMGR_REQUIRED = 'sessmgr_required'

SESSMGR_BIN_NAME = 'aliyun-alinas-efc-sessmgrd'
OLD_SESSMGR_BIN_NAME = 'aliyun-alinas-eac-sessmgrd'
SESSMGR_BIN_PATH = '/usr/bin/%s' % SESSMGR_BIN_NAME
OLD_SESSMGR_BIN_PATH = '/usr/bin/%s' % OLD_SESSMGR_BIN_NAME
VFUSE_UTIL_BIN_NAME = 'aliyun-alinas-efc-vsutils'
VFUSE_UTIL_BIN_PATH = '/usr/bin/%s' % VFUSE_UTIL_BIN_NAME
NONFUSE_MOUNT_PATH = '/var/run/alinas/nonfuse_mounts'
NONFUSE_MOUNT_LOCK = 'nonfuse_mounts.lock'
UNAS_LOG_DIR = '/var/log/aliyun/alinas'
UNAS_LOG_FILE_GC_IN_SEC = 2 * 24 * 3600 # default 2 days
MONITOR_FILE_GC_IN_SEC = 3600 # default 1 hour
EAC_SOCKET_SUFFIX = 'eac.sock'
EFC_SOCKET_SUFFIX = 'efc.sock'
EFC_LOCK_SUFFIX = 'efc.lock'

UNAS_LOCK_STATEFILE_TIMEOUT = 20
UNAS_MOUNT_FAIL_MAX_CHECK_TIME = 60
UNAS_UMOUNT_FAIL_TIMEOUT = 180
UNAS_UMOUNT_KILL_PROCESS_MIN_ALIVE = 60
BIND_ROOT_PREFIX = 'bindroot-'
BIND_ROOT_DIR = STATE_FILE_DIR + '/bindroot'

NORMAL_UMOUNT = 0
FORCE_UMOUNT = 1
UNAS_UMOUNT_MSG_NUM = 213
BIND_TAG = 'bindtag'
MOUNTPOINTS_ENV = 'MOUNT_POINTS'

# nas-agent configuration
LAST_MOUNTPOINT_FILE_PATH = '/etc/aliyun/alinas/last-mountpoint'
NAS_AGENT_LOCAL_COMMANDS_PATH = '/etc/aliyun/alinas/nas-agent-commands-local.json'
NAS_AGENT_REMOTE_COMMANDS_DIR = '/etc/aliyun/alinas/nas-agent-commands-remote'
NAS_AGENT_REMOTE_REPO_PATTERN = 'https://aliyun-alinas-nas-agent-remote-commands-%s.oss-%s-internal.aliyuncs.com'
NAS_AGENT_REMOTE_COMMANDS_PATTERN = 'nas-agent-commands-%s.json'

NAS_AGENT_BIN_DIR = '/usr/local/nas-agent'
NAS_AGENT_BIN_NAME = 'nas-agent'
NAS_AGENT_ID_GEN_BIN_NAME = 'identifier-generator'
NAS_AGENT_BIN_PATH = os.path.join(NAS_AGENT_BIN_DIR, NAS_AGENT_BIN_NAME)
NAS_AGENT_ID_GEN_BIN_PATH = os.path.join(NAS_AGENT_BIN_DIR, NAS_AGENT_ID_GEN_BIN_NAME)
NAS_AGENT_SYS_CONF_DIR = '/etc/nas-agent'
NAS_AGENT_CONF_PATH = os.path.join(NAS_AGENT_SYS_CONF_DIR, 'nas-agent-config.json')
NAS_AGENT_ID_FILE_PATH = os.path.join(NAS_AGENT_SYS_CONF_DIR, 'user_defined_id')
NAS_AGENT_USER_DIR = os.path.join(NAS_AGENT_SYS_CONF_DIR, 'users')
NAS_AGENT_CLIENT_TYPE_EFC = 'efc'
NAS_AGENT_CLIENT_TYPE_NFS = 'nfs'
NAS_AGENT_CLIENT_TYPE_NFS_V3 = 'nfs3'
NAS_AGENT_CLIENT_TYPE_NFS_V4 = 'nfs4'
NAS_AGENT_CLIENT_TYPE_ALL = 'all'

Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])
MountEntity = namedtuple('MountEntity', ['clienttype', 'pid', 'mountuuid', 'connid', 'fsid', 'fstype', 'region', 'state', 'entries'])
UnasState = namedtuple('UnasState', ['mountuuid', 'mountpoint', 'mountpath', 'mountcmd', 'mountkey', BIND_TAG, SESSMGR_REQUIRED])

POD_UID_PATTERN = re.compile('^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$')
NAS_AGENT_MOUNTPOINT_PATTERNS = {
    'cpfs': re.compile(r'(?P<fsid>[0-9a-z]+-[0-9a-z]+)[-0-9a-z]+\.(?P<region>[-0-9a-z]+)\.cpfs\.aliyuncs\.com'),
    'extreme': re.compile(r'(?P<fsid>[0-9a-z]+)[-0-9a-z]+\.(?P<region>[-0-9a-z]+)\.extreme\.nas\.aliyuncs\.com'),
    'hybrid': re.compile(r'(?P<fsid>[0-9a-z]+)[-0-9a-z]+\.(?P<region>[-0-9a-z]+)\.nas\.aliyuncs\.com'),
    # do not support acceleration or no-region endpoint
    'oss': re.compile(r'(?P<fsid>[-0-9a-z]+)\.oss-(?P<region>[-0-9a-z]+?)(-internal)?\.aliyuncs\.com'),
    # oss accelerator endpoint, refer to https://help.aliyun.com/zh/oss/overview-77/#section-9t5-dsp-cze
    'oss-acc': re.compile(r'(?P<fsid>[-0-9a-z]+)\.(?P<region>[-0-9a-z]+?)-internal\.oss-data-acc\.aliyuncs\.com'),
}
NAS_AGENT_MOUNT_PATTERN = re.compile(r'^((?P<mount_uuid>[-0-9a-zA-Z]+):)?(?P<mountpoint>[^:]*):(?P<path>[^ ]+)')
NAS_AGENT_OPID_PATTERN = re.compile('<opid>')
NAS_AGENT_PID_PATTERN = re.compile('<pid>')
NAS_AGENT_UUID_PATTERN = re.compile('<uuid>')
NAS_AGENT_CONNID_PATTERN = re.compile('<connid>')
NAS_AGENT_PATH_PATTERN = re.compile('<path>')
NAS_AGENT_MOUNTPOINT_PATTERN = re.compile('<mountpoint>')

NAS_AGENT_LOGGER = None

PEXPORTER_BIN_NAME = 'aliyun-alinas-efc-pexporter'
PEXPORTER_BIN_PATH = '/usr/bin/%s' % PEXPORTER_BIN_NAME
PEXPORTER_LOG_CONF_TEMPLATE_PATH = '/etc/aliyun/alinas/log_conf.efc.pexporter.json'

MAIN_LOOP_TIME = 0
MAIN_LOOP_HANG_ABORT_THRES = 600  # seconds

PS_CMD = 'ps -eww -o pid,cmd,args '
#    PID CMD                         COMMAND
#  14190 /usr/bin/aliyun-alinas-efc- /usr/bin/aliyun-alinas-efc-sessmgrd --apsara_log_conf_path=/var/log/aliyun/alinas/log_conf.sessmgr.json
#  24309 /usr/bin/aliyun-alinas-efc  /usr/bin/aliyun-alinas-efc -o server=9ff4d4bbb1-tfj1.cn-zhangjiakou.nas.aliyuncs.com:/ -o mountpoint=/mnt/myc -o rw,protocol=efc,fstype=nas,net=tcp,fd_store=sessmgrd,client_owner=nas-test011122132022.ea134_a9voK4bB_1734320510421840,default_permissions,allow_other --unas_CoreFileSizeLimitSize=-1 -o mount_uuid=a9voK4bB --apsara_log_conf_path=/var/log/aliyun/alinas/efc-a9voK4bB/log_conf.efc.json

def fatal_error(user_message, log_message=None):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    sys.exit(1)

def binary_path_env():
    env = os.environ.copy()
    path = os.environ.get('PATH', '')
    path = path + ':/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin'
    env['PATH'] = path
    return env

def exec_cmd_in_subprocess(cmd, **kwargs):
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=binary_path_env(), **kwargs)
    stdmsg, errmsg = proc.communicate()
    stdmsg = stdmsg.decode(encoding='utf8')
    errmsg = errmsg.decode(encoding='utf8')
    if proc.returncode != 0:
        logging.error('Fail to exec cmd:%s, err:%s', cmd, errmsg.strip())
    return proc.returncode, str(stdmsg), str(errmsg).strip()


def get_system_release_id():
    system_id = 'unknown'
    system_version_id = 'unknown'
    try:
        with open(OS_RELEASE_PATH) as f:
            for line in f:
                if line.startswith('ID=') :
                    system_id = line.split('=')[1].strip().strip('"')
                if line.startswith('VERSION_ID=') :
                    system_version_id = line.split('=')[1].strip().strip('"')
    except IOError:
        logging.debug('Unable to read %s', OS_RELEASE_PATH)

    return system_id, system_version_id

def get_version():
    global VERSION

    if VERSION == 'unknown':
        cmd = ''
        system_id, _ = get_system_release_id()
        if 'ubuntu' in system_id:
            cmd = "dpkg -l | grep aliyun-alinas | awk '{ print $3 }'"
        else:
            cmd = "yum list installed aliyun-alinas-utils | grep aliyun-alinas | awk '{ print $2 }'"
        errcode, stdmsg, errmsg = exec_cmd_in_subprocess(cmd)

        if errcode == 0 and stdmsg:
            VERSION = stdmsg

    return VERSION

def unas_state_file_name(mount_uuid):
    return "eac-" + mount_uuid

def execute_with_timeout(command, timeout, ignore_error=False):
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, env=binary_path_env())
    timer = threading.Timer(timeout, lambda process: process.kill(), [proc])
    try:
        timer.start()
        stdout, stderr = proc.communicate()
        exe_time = datetime.now()
        stdout, stderr = stdout.decode('utf-8'), stderr.decode('utf-8')
        if proc.returncode != 0 and not ignore_error:
            logging.error('Fail to execute %s, rc %d', command, proc.returncode)
        return exe_time, proc.returncode, stdout, stderr
    except Exception as e:
        if not ignore_error:
            logging.error('Fail to execute "%s", error %s', command, str(e))
        return None, None, None, None
    finally:
        timer.cancel()


def download_file(url, path, timeout):
    command = 'wget "%s" -O "%s"' % (url, path)
    _, rc, *_ = execute_with_timeout(command, timeout, ignore_error=True)
    if rc == 0:
        return True
    try:
        if os.path.exists(path):
            os.remove(path)
    except IOError as e:
        logging.warning('Fail to remove temp file %s, error: %s', path, str(e))
    return False


@contextmanager
def lock_dns(state_file_dir=STATE_FILE_DIR):
    path = os.path.join(state_file_dir, DNS_LOCK)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)

    try:
        fcntl.lockf(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def bootstrap_logging(config, log_dir=LOG_DIR):
    log_type = config.get(WATCHDOG_CONFIG_SECTION, 'logging_type', default='file')
    raw_level = config.get(WATCHDOG_CONFIG_SECTION, 'logging_level', default='info')
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

    if log_type == 'file':
        max_bytes = config.getint(WATCHDOG_CONFIG_SECTION, 'logging_max_bytes',
                                default=1048576, minvalue=1048576, maxvalue=1048576*16)
        file_count = config.getint(WATCHDOG_CONFIG_SECTION, 'logging_file_count', default=8, minvalue=1, maxvalue=16)
        handler = RotatingFileHandler(os.path.join(log_dir, LOG_FILE), maxBytes=max_bytes, backupCount=file_count)
    else:
        handler = StreamHandler()
    handler.setFormatter(logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(lineno)d - %(message)s'))

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)

    if level_error:
        logging.error('Malformed logging level "%s", setting logging level to %s', raw_level, level)
    if config.configfile_error:
        logging.error('Config file %s is not found, please check', config.configfile)

    global NAS_AGENT_LOGGER
    NAS_AGENT_LOGGER = NasAgentLogger(config)

def check_mount(config):
    return config.getboolean(WATCHDOG_CONFIG_SECTION, 'check_mount', default=True)

def check_sessmgr(config, watchdog):
    # check config
    sessmgr_required = config.getboolean(WATCHDOG_CONFIG_SECTION, 'check_sessmgr', default=None)
    if sessmgr_required is not None:
        return sessmgr_required

    # check state file
    sessmgr_required = check_sessmgr_required(watchdog)
    return sessmgr_required

def check_nas_agent(config):
    return config.getboolean(WATCHDOG_CONFIG_SECTION, 'check_nas_agent', default=True)

def check_pexporter(config):
    return config.getboolean(WATCHDOG_CONFIG_SECTION, 'check_pexporter', default=False)

def discover_dadi(config):
    return config.getboolean(WATCHDOG_CONFIG_SECTION, 'discover_dadi', default=True)

def get_local_dns(mount):
    return mount.server.split(':')[0]

def is_alinas_mount(mount):
    return mount.server.startswith('alinas-') and 'nfs' in mount.type

MOUNT_TYPE_ALL='eac_efc'
MOUNT_TYPE_EFC='aliyun-alinas-efc'
MOUNT_TYPE_EAC='aliyun-alinas-eac'
def is_unas_mount(mount, mount_type):
    if mount_type == MOUNT_TYPE_ALL:
        return MOUNT_TYPE_EFC in mount.type or MOUNT_TYPE_EAC in mount.type
    else:
        return mount_type in mount.type

def get_unas_mount_type(mount_uuid, mount_file='/proc/mounts'):
    mounts = []
    try:
        get_mounts_from_file(mount_file, mounts)
        get_current_unas_mounts_from_nonfuse(MOUNT_TYPE_ALL, mounts)
        get_current_unas_mounts_from_virtfuse(MOUNT_TYPE_ALL, mounts)

        for mount in mounts:
            if mount_uuid == mount.server.split(':')[0]:
                return mount.type
        return None

    except Exception as e:
        fatal_error('Fail to get current mounts for %s, exception msg:%s' % (mount_uuid, str(e)))


def get_current_nfs_mounts(mount_file='/proc/mounts'):
    mounts = []

    with open(mount_file) as f:
        for mount in f:
            m = Mount._make(mount.strip().split())
            if 'nfs' in m.type:
                mounts.append(m)
    return mounts

def get_current_local_nfs_mounts(mount_file='/proc/mounts'):
    """
    Return a dict of the current NFS mounts for servers running on localhost, keyed by the mountpoint and port as it
    appears in alinas watchdog state files.

    Eg.
    alinas-6e1854899b-deo54.127.0.1.1:/ /mnt nfs vers=3,port=6000,mountaddr=127.0.1.1,mountport=6000,addr=127.0.1.1 0 0
    """

    mounts = get_current_nfs_mounts()
    mount_dict = {}
    for m in mounts:
        if not is_alinas_mount(m):
            continue
        mount_dict[get_local_dns(m)] = m

    return mount_dict

def get_current_unas_mounts_from_nonfuse(mount_type, mounts):
    with lock_state_file(STATE_FILE_DIR, NONFUSE_MOUNT_LOCK, UNAS_LOCK_STATEFILE_TIMEOUT):
        if not os.path.exists(NONFUSE_MOUNT_PATH):
            return
        
        get_mounts_from_file(NONFUSE_MOUNT_PATH, mounts, mount_type)

def get_current_unas_mounts_from_virtfuse(mount_type, mounts):
    if not os.path.exists(VFUSE_UTIL_BIN_PATH):
        return
    cur_uuids = [ m.mountpoint.split(':')[0] for m in mounts ]
    cmd = '%s getmounts' % VFUSE_UTIL_BIN_PATH
    res_lines = os.popen(cmd).readlines()
    for line in res_lines:
        line_split = line.strip().split()
        if len(line_split) <= 1:
            # empty line or dev name
            continue
        uuid = line_split[0].split(':')[0]
        if uuid in cur_uuids:
            # duplicated mount info
            continue

        # get mount info from rund guest bind mount
        line_split.append(None)  # freq
        line_split.append(None)  # passno
        tmp_m = Mount._make(line_split)
        if not is_unas_mount(tmp_m, mount_type):
            continue

        try:
            # get real local mountpoint from statefile
            state_file_path = os.path.join(STATE_FILE_DIR, unas_state_file_name(uuid))
            with open(state_file_path, 'r') as f:
                state = json.load(f)
                if not is_integral(state):
                    raise Exception("state file modified by others")
                line_split[1] = state['mountpoint']
                m = Mount._make(line_split)
                mounts.append(m)
                cur_uuids.append(uuid)
        except Exception as e:
            logging.info("get real local mountpoint from statefile failed, uuid:%s, err:%s" % (uuid, str(e)))
            continue

def get_mounts_from_file(mount_file, mounts, mount_type=None):
    with open(mount_file) as f:
        for mount in f.readlines():
            m = Mount._make(mount.strip().split())
            if mount_type and not is_unas_mount(m, mount_type):
                continue
            mounts.append(m)

def get_current_unas_mounts(mount_type, mount_file='/proc/mounts'):
    mounts = []
    try:
        get_mounts_from_file(mount_file, mounts, mount_type)
        get_current_unas_mounts_from_nonfuse(mount_type, mounts)
        get_current_unas_mounts_from_virtfuse(mount_type, mounts)

        # should handle the "upper" mounts fisrt
        # which is listed under the bottom of /proc/mounts
        mounts.reverse()

        logging.debug("get_current_unas_mounts %s" % mounts)
        return mounts

    except Exception as e:
        fatal_error('Fail to get all mounts, exception msg:%s' % str(e))

def get_files_with_prefix(state_file_dir, prefix='alinas'):
    """
    Fill up a dict of the absolute path of state files in state_file_dir, keyed by the mountpoint and port portion of
    the filename.

    Map: local_dns -> state_file_name
    eg. alinas-6e1854899b-123.127.0.1.1-ygb5puyV  -> alinas-6e1854899b-123.127.0.1.1-ygb5puyV
    """

    files = {}
    try:
        if os.path.isdir(state_file_dir):
            for sf in os.listdir(state_file_dir):
                if not sf.startswith(prefix):
                    continue
                if not os.path.isfile(os.path.join(state_file_dir, sf)):
                    continue

                files[sf] = sf
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.error('List state files failed: msg=%s', str(e))
    
    return files

@contextmanager
def lock_state_file(state_file_dir=STATE_FILE_DIR, lock_type=SESSMGR_LOCK, timeout=0):
    if not os.path.exists(state_file_dir):
       os.makedirs(state_file_dir, exist_ok=True)
    path = os.path.join(state_file_dir, lock_type)
    if timeout == 0:
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR)
            fcntl.lockf(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)
    else:
        locked = False
        start = time.time()
        while not locked:
            passed = time.time() - start
            if passed > timeout:
                raise Exception("lock_state_file timeout, path:%s", path)
            try:
                fd = os.open(path, os.O_CREAT | os.O_RDWR)
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                yield
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                time.sleep(0.3)
            finally:
                os.close(fd)

def is_pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def start_proxy_preexec_fn():
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def start_proxy(child_procs, state_file, command):
    # launch the tunnel in a process group so if it has any child processes, they can be killed easily
    logging.info('Starting proxy: "%s"', ' '.join(command))

    # no need to specify env
    tunnel = subprocess.Popen(command, preexec_fn=start_proxy_preexec_fn)

    if not is_pid_running(tunnel.pid):
        raise RuntimeError('Failed to start proxy for {0}: command={1}'.format(state_file, command))

    logging.info('Started proxy, pid: %d', tunnel.pid)

    child_procs.append(tunnel)
    return tunnel.pid


def dns_entry_matches(line, host, ip):
    entry = line.strip().split()
    return tuple(entry) == (ip, host)

def write_hostfile(lines, hostfile='/etc/hosts', tmpdir='/tmp', atomic_move=True):
    fd, path = tempfile.mkstemp(dir=tmpdir, text=True)
    try:
        os.write(fd, ''.join(lines).encode('utf-8'))
        os.fchmod(fd, 0o644)
        if atomic_move:
            os.rename(path, hostfile)
        else:
            shutil.move(path, hostfile)
    except:
        os.unlink(path)
        raise
    finally:
        os.close(fd)

# strong guarantee
def clean_up_local_dns(host, ip, hostfile='/etc/hosts'):
    """
    Remove the (ip, host) pair in the host file atomically
    """
    if not host or not ip:
        return

    logging.info('Cleanup dns: %s -> %s', host, ip)

    try:
        with open(hostfile, mode='r') as f:
            lines = f.readlines()
            lines2 = list(filter(lambda l: not dns_entry_matches(l, host, ip), lines))
    except IOError as e:
        if e.errno == errno.ENOENT:
            return

        raise

    # any exceptions will cause the cleanup fail
    if len(lines) != len(lines2):
        try:
            write_hostfile(lines2, hostfile, tmpdir='/tmp')
        except OSError as e:
            try:
                logging.warning('atomic rename hosts from /tmp not work, %s', str(e))
                write_hostfile(lines2, hostfile, tmpdir=os.path.dirname(hostfile))
            except OSError as e1:
                logging.warning('atomic rename hosts from current dir not work, %s', str(e1))
                write_hostfile(lines2, hostfile, tmpdir='/tmp', atomic_move=False)

def kill_proxy(pid):
    process_group = os.getpgid(pid)
    logging.info('Terminating running proxy - PID: %d, group ID: %s', pid, process_group)
    os.killpg(process_group, SIGTERM)

def is_deprecated_mount_state_dir(mount_state_dir):
    # deprecated mount state dir ends with .{tls_port}+
    pattern = r'\.(\d{4,5})\+$'
    match = re.search(pattern, mount_state_dir)
    return match is not None

# strong guarantee
def clean_up_mount_state(state_file_dir, state_file, pid, is_running, mount_state_dir=None):
    if is_running:
        kill_proxy(pid)

    if is_pid_running(pid):
        logging.info('Proxy: %d is still running, will retry termination', pid)
    else:
        logging.info('Proxy: %d is no longer running, cleaning up state', pid)
        state_file_path = os.path.join(state_file_dir, state_file)
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

        with lock_dns(state_file_dir):
            clean_up_local_dns(state.get('local_dns', None), state.get('local_ip', None))

        try:
            os.remove(state_file_path)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
        
        if mount_state_dir is not None and not is_deprecated_mount_state_dir(mount_state_dir):
            mount_state_dir_abs_path = os.path.join(state_file_dir, mount_state_dir)
            if os.path.isdir(mount_state_dir_abs_path):
                shutil.rmtree(mount_state_dir_abs_path)
            else:
                logging.debug(
                    "Attempt to remove mount state directory %s failed. Directory is not present.",
                    mount_state_dir_abs_path,
                )

# strong guarantee
def rewrite_state_file(state, state_file_dir, state_file):
    tmp_state_file = os.path.join(state_file_dir, '~%s' % state_file)
    try:
        with open(tmp_state_file, 'w') as f:
            signed_state = dict(state)
            signed_state[STATE_SIGN] = sign_state(state)
            json.dump(signed_state, f)

        os.rename(tmp_state_file, os.path.join(state_file_dir, state_file))
    except Exception as e:
        logging.error('Fail to rewrite state file, err msg:%s', str(e))
        try:
            os.unlink(tmp_state_file)
        except Exception as e1:
            logging.error('Fail to clear tmp state file in rewrite, err msg:%s', str(e1))

        raise


# strong guarantee
def mark_as_unmounted(state, state_file_dir, state_file, current_time):
    logging.debug('Marking %s as unmounted at %d', state_file, current_time)
    state['unmount_time'] = current_time

    rewrite_state_file(state, state_file_dir, state_file)

    return state


# strong guarantee
def restart_proxy(child_procs, state, state_file_dir, state_file):
    new_tunnel_pid = start_proxy(child_procs, state_file, state['cmd'])
    state['pid'] = new_tunnel_pid

    try:
        logging.debug('Rewriting %s with new pid: %d', state_file, new_tunnel_pid)
        rewrite_state_file(state, state_file_dir, state_file)
    except:
        try:
            kill_proxy(new_tunnel_pid)
        except:
            # kill failed, we can do nothing better than ignoring it
            fatal_error('Failed to cleanup unused pid {0}'.format(new_tunnel_pid))

        raise


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


def is_integral(state):
    saved_sign = state.pop(STATE_SIGN, '')
    computed_sign = sign_state(state)
    return saved_sign == computed_sign

def try_umount_unas(mount_uuid, mount_point, umount_flag, timeout=60):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    mount_type = get_unas_mount_type(mount_uuid)
    if mount_type is None:
        logging.error('get mount type by uuid %s failed' % (mount_uuid))
        return False
    elif MOUNT_TYPE_EAC in mount_type:
        conn = '%s/%s.%s' % (OLD_EFC_WORKSPACE_DIR, mount_uuid, EAC_SOCKET_SUFFIX)
    elif MOUNT_TYPE_EFC in mount_type:
        conn = '%s/%s.%s' % (EFC_WORKSPACE_DIR, mount_uuid, EFC_SOCKET_SUFFIX)
    else:
        logging.error('get mount type by uuid %s failed' % (mount_uuid))
        return False

    logging.info('Try to conn unas to umount, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
    sock.connect(conn)
    send_bytes = struct.pack('ii', UNAS_UMOUNT_MSG_NUM, umount_flag)

    try:
        sock.send(send_bytes)
        rec = sock.recv(1024)
        if not rec:
            logging.error('Fail to umount %s, process is closed' % (mount_point))
            return False

        rec_data = bytes.decode(rec)

        err = 0
        for r in rec_data:
            if r == '\0':
                break
            err = err*10 + int(r)

        if err == 0:
            logging.info('Unas umount return ok, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
            return True
        else:
            logging.error('Unas umount return error %d, uuid:%s mount_point:%s conn:%s' % (err, mount_uuid, mount_point, conn))
            return False

    except socket.timeout: # fail after timeout second of no activity
        logging.error('Unas umount timeout, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
        return False
    except Exception as e:
        logging.error('Unas umount fail %s, uuid:%s mount_point:%s conn:%s' % (str(e), mount_uuid, mount_point, conn))
        return False
    finally:
        sock.close()

def compare_unas_mountpoint(mp1, mp2):
    if mp1 == mp2:
        return True
    if mp1.startswith(BIND_ROOT_DIR) or mp2.startswith(BIND_ROOT_DIR):
        if mp1.find('run') > 0 and mp2.find('run') > 0:
            return mp1[mp1.find('run'):] == mp2[mp2.find('run'):]
    return False

def sync_umount_unas(mount_point, umount_flag):
    proc_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
    mounted = False
    mount_uuid = None
    for mount in proc_mounts:
        if compare_unas_mountpoint(mount.mountpoint, mount_point):
            mounted = True
            mount_uuid = mount.server.split(':')[0]
            break
    if not mounted:
        return True
    try:
        return try_umount_unas(mount_uuid, mount_point, umount_flag)
    except Exception as e:
        logging.error('Fail to umount %s, exception msg:%s' % (mount_point, str(e)))
        return False

def clean_bindroot(mount_uuid, mount_point, state):
    try:
        unas_proc_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        if not mount_point.startswith(BIND_ROOT_DIR):
            logging.error('Fail to clean unas bindroot, mountpoint error, uuid:%s mount_point:%s' % (mount_uuid, mount_point))
            return False
        if sync_umount_unas(mount_point, NORMAL_UMOUNT):
            # double-check bindroot mount not alive
            if is_unas_bindroot_mount_exist(mount_uuid, unas_proc_mounts):
                logging.error('Fail to clean unas bindroot, uuid exists in mounts still, uuid:%s mount_point:%s' % (mount_uuid, mount_point))
                return False
            if os.path.exists(mount_point):
                logging.warning('Cleanup unas bindroot, uuid:%s mount_point:%s' % (mount_uuid, mount_point))
                os.rmdir(mount_point)
            return True
        else:
            logging.error('Fail to clean unas bindroot, umount failed, uuid:%s mount_point:%s' % (mount_uuid, mount_point))
            return False
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
    except Exception as e:
        logging.error('Fail to clean unas bindroot uuid:%s mount_point:%s, exception msg:%s' % (mount_uuid, mount_point, str(e)))
        raise

def clean_up_unas_state(state_file_dir, state_file, state): 
    try:
        # clean state file
        state_file_path = os.path.join(state_file_dir, state_file)
        os.remove(state_file_path)
        # clean lock file
        uuid_lock_name = state['mountkey']
        lock_file_path = os.path.join(STATE_FILE_DIR, uuid_lock_name)
        os.remove(lock_file_path)
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise

# return unas status normal
def is_unas_running(unas_state, ps_mount_info):
    mount_uuid = unas_state.mountuuid
    regex_uuid = 'mount_uuid=%s' % mount_uuid 
    # unas process is still alive
    if ps_mount_info.find(regex_uuid) != -1:
        return True
         
    # exited unmormally, need lift by watchdog
    return False


def parse_val_from_kvstr(kvstr, key, default_val):
    if key in kvstr:
        idx = kvstr.index(key)
        return default_val if idx == len(kvstr) - 1 else kvstr[idx + 1]

    return default_val

def get_unas_mem_limit(mount_options):
    server = parse_val_from_kvstr(mount_options, 'server', '').split(':')[0]
    if server.endswith('.cpfs.aliyuncs.com'):
        limit_size = sys.maxsize
    else:
        limit_size = CGROUP_BASE_MEMORY_LIMIT_SIZE
        limit_size += 256 * UNAS_SHM_PAGE_SIZE * int(parse_val_from_kvstr(mount_options, UNAS_SHM_PAGE_CAPACITY_FLAG, UNAS_SHM_PAGE_CAPACITY_DEFAULT))
        limit_size += UNAS_SHM_VOLUME_SIZE * int(parse_val_from_kvstr(mount_options, UNAS_SHM_VOLUME_CAPACITY_FLAG, UNAS_SHM_VOLUME_CAPACITY_DEFAULT))
        limit_size += UNAS_SHM_JOURNAL_SIZE * int(parse_val_from_kvstr(mount_options, UNAS_SHM_JOURNAL_CAPACITY_FLAG, UNAS_SHM_JOURNAL_CAPACITY_DEFAULT))
        limit_size += get_unas_file_open_max_size(mount_options)
        limit_size += int(parse_val_from_kvstr(mount_options, UNAS_SHM_DADI_CAPACITY_FLAG, UNAS_SHM_DADI_CAPACITY_DEFAULT)) << 20
    return limit_size


def get_unas_file_open_max_size(mount_options):
    file_max = int(parse_val_from_kvstr(mount_options, UNAS_SHM_FILE_CAPACITY_FLAG, UNAS_SHM_FILE_CAPACITY_DEFAULT))
    if file_max == 0:
        f = open('/proc/sys/fs/file-max')
        file_max = int(f.read().strip())
        f.close()
    return file_max * UNAS_SHM_FILE_SIZE

def add_cgroup_limit(mount_cmd, mount_uuid, cgroup_dir=CGROUP_DIR):
    try:
        res = os.popen("cat /proc/mounts | grep cgroup | grep memory | tr ',' ' ' | awk '{print $4}'").read().strip()
        if res == 'ro':
            logging.info("/sys/fs/cgroup/memory mounts as read-only filesystem, skip add %s into cgroup limit" % mount_uuid)
            return

        if not os.path.exists(cgroup_dir):
            os.makedirs(cgroup_dir, exist_ok=True)

        dir_path = os.path.join(cgroup_dir, mount_uuid)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

        procs_path = os.path.join(dir_path, CGROUP_PROCS_FILE)
        limit_path = os.path.join(dir_path, CGROUP_LIMIT_FILE)
        swap_ctrl_path = os.path.join(dir_path, CGROUP_SWAP_CONTROL_FILE)
        oom_ctrl_path = os.path.join(dir_path, CGROUP_OOM_CONTROL_FILE)


        mount_options = re.split(' -o | --|=| |,', mount_cmd)
        # set limit size
        size = get_unas_mem_limit(mount_options)
        with open(limit_path, 'w') as f:
            f.write(str(size))

        # disable swap out when oom
        with open(swap_ctrl_path, 'w') as f:
            f.write('0')

        # enable kill process when oom, set oom_kill_disable flag to 0 in this file
        with open(oom_ctrl_path, 'w') as f:
            f.write('0')

        # sort ps output by start time and reserve the latest one to avoid failure in upgrade
        cmd = "ps -eww -o pid,start_time,cmd,args --sort=start_time | grep e[af]c | grep mount_uuid=%s | grep -vw grep | awk '{print $1}'" % mount_uuid
        pids = os.popen(cmd).read()
        if pids.endswith('\n'):
            pids = pids[:-1]

        pid = pids.split('\n')[-1]

        with open(procs_path, 'a') as f:
            f.write(pid)

    except Exception as e:
        logging.warning('add cgroup memory limit failed, uuid %s, %s, failure ignored' % (mount_uuid, str(e)))


def restart_unas_process(unas_state, state_file_dir = STATE_FILE_DIR): 
    logging.debug("try restart eac, (mount_uuid:%s, mount_point:%s)" % (unas_state.mountuuid, unas_state.mountpoint))

    try:
        mount_uuid = unas_state.mountuuid
        mount_cmd = unas_state.mountcmd 
        mount_point = unas_state.mountpoint
        errcode, _, errmsg = exec_cmd_in_subprocess(mount_cmd)

        if errcode == 0:
            add_cgroup_limit(mount_cmd, mount_uuid)
            logging.info('Remount %s at %s, uuid:%s Successfully, %s', unas_state.mountpath, mount_point, mount_uuid, mount_cmd)
        else:
            logging.error('Failed to remount %s at %s, uuid:%s returncode=%d, stderr="%s"' % \
                                (unas_state.mountpath, mount_point, mount_uuid, errcode, errmsg))

    except Exception as e:
        logging.error('restart eac process failed: msg=%s', str(e))
        raise

PAGE_SIZE = 4096

# print some internal info of efc to help debug
def get_unas_internal_info(mountpoint):
    cli_cmd = '{} -m {} -r '.format('/usr/bin/aliyun-alinas-efc-cli', mountpoint)
    # shmem
    fh_shm = os.popen(cli_cmd + 'peek/shm/fh').read().strip()
    volume_shm = os.popen(cli_cmd + 'peek/shm/volume').read().strip()
    page_shm = os.popen(cli_cmd + 'peek/shm/page').read().strip()
    journal_shm = os.popen(cli_cmd + 'peek/shm/journal').read().strip()
    file_shm = os.popen(cli_cmd + 'peek/shm/file').read().strip()

    # inode
    inode = os.popen(cli_cmd + 'peek/inode').read().strip()

    # page cache
    pagecache = os.popen(cli_cmd + 'peek/pagecache').read().strip()

    # journal
    journal = os.popen(cli_cmd + 'peek/journal').read().strip()

    # tcmalloc
    tcmalloc = os.popen(cli_cmd + 'peek/tcmalloc').read().strip()

    # readdir cache
    readdircache = os.popen(cli_cmd + 'peek/readdircache').read().strip()

    # generate result string
    res = 'EFC internal debug infos: inode:{}, page cache:{}, journal:{}, readdir cache:{}, tcmalloc:{}, volume shm:{}, file shm:{}, fh shm:{}, page shm:{}, journal shm:{}'.format(inode, pagecache, journal, readdircache, tcmalloc, volume_shm, file_shm, fh_shm, page_shm, journal_shm)
    return res

def check_unas_process_mem(unas_state):
    logging.debug("checking eac process mem_usage, (mount_uuid:%s, mount_point:%s)" % (unas_state.mountuuid, unas_state.mountpoint))
    try:
        mount_uuid = unas_state.mountuuid
        pid = os.popen(PS_CMD + "| grep e[af]c | grep mount_uuid=%s |grep -vw grep | awk '{print $1}'" % mount_uuid).read().strip()
        if len(pid) == 0:
            logging.debug("checking eac process mem_usage not exist, (mount_uuid:%s, mount_point:%s)" % (unas_state.mountuuid, unas_state.mountpoint))
            return
        with open("/proc/%s/statm" % pid, 'r') as f:
            stm = f.read().strip()
            resident = int(stm.split()[1]) * PAGE_SIZE
            share = int(stm.split()[2]) * PAGE_SIZE
            mount_cmd = unas_state.mountcmd
            mount_options = re.split(' -o | --|=| |,', mount_cmd)
            is_uring = parse_val_from_kvstr(mount_options, "efc_EnableIOUring", "false") == "true"
            memory_thres = CGROUP_BASE_MEMORY_LIMIT_SIZE + (URING_MEMORY_LIMIT_SIZE if is_uring else 0)
            if resident - share > memory_thres:
                logging.error("checking eac process mem_usage oom, (mount_uuid:%s, mount_point:%s), statm:%s" % (unas_state.mountuuid, unas_state.mountpoint, stm))
                if read_config().getboolean(WATCHDOG_CONFIG_SECTION, 'oom_kill', default=True):
                    logging.error("kill eac process, (mount_uuid:%s, mount_point:%s, debuginfo:%s)" % (unas_state.mountuuid, unas_state.mountpoint, get_unas_internal_info(unas_state.mountpoint)))
                    kill_process_uuid(mount_uuid, 0)
    except Exception as e:
        logging.error('check eac process mem_usage failed: msg=%s', str(e))

def create_sessmgr_log_file(global_log_dir=UNAS_LOG_DIR):
    '''
        sessmgr log/conf file path like this:
        eg.
            /var/log/aliyun/alinas/ (global_dir_path)
            |-- log_conf.sessmgr.json (log_conf_path)
            |-- sessmgrlog (log_dir_path)
                |-- sessmgr.LOG (log_path)     
    '''

    try:
        log_dir_path = os.path.join(global_log_dir, "sessmgrlog")
        if not os.path.exists(log_dir_path):
            os.makedirs(log_dir_path, exist_ok=True)

        log_conf_path = os.path.join(global_log_dir, "log_conf.sessmgr.json")
        if not os.path.exists(log_conf_path) and os.path.exists(SESSMGR_LOG_CONF_TEMPLATE_PATH):
            shutil.copy(SESSMGR_LOG_CONF_TEMPLATE_PATH, log_conf_path)

        return log_conf_path
    
    except IOError as e:
        logging.exception('Create sessmgr log file failed: msg=%s', str(e))
        if e.errno != errno.ENOENT and e.errno != errno.EEXIST:
            raise

sessmgr_restart_time = 0
SESSMGR_RESTART_ALARM_TIME = 600

def check_unas_sessmgr(state_file_dir = STATE_FILE_DIR):
    global sessmgr_restart_time
    try:
        with lock_state_file(state_file_dir, SESSMGR_LOCK, UNAS_LOCK_STATEFILE_TIMEOUT) as _:
            cmd = PS_CMD + '| grep %s | grep -vw grep' % SESSMGR_BIN_PATH
            info = os.popen(cmd).read()
            # sessmgr still alive
            if len(info) > 0:
                return
             
            sessmgr_conf_path = create_sessmgr_log_file() 
            sessmgr_log_path = " --apsara_log_conf_path=%s" % sessmgr_conf_path
            bootstrap_cmd = "nohup %s %s > %s/sessmgrd-efc.out 2>&1 &" % (SESSMGR_BIN_PATH, sessmgr_log_path, LOG_DIR)
            errcode, _, errmsg = exec_cmd_in_subprocess(bootstrap_cmd)

            if errcode == 0:
                logging.info('Successfully restart sessmgrd')
            else:
                message = 'Failed to init sessmgrd, stderr="%s"' % (errmsg)
                logging.error(message)

            now = time.time()
            if now < sessmgr_restart_time + SESSMGR_RESTART_ALARM_TIME:
                logging.error('ALARM:sessmgrd restart too frequently, last restart time:{0}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(sessmgr_restart_time))))
            sessmgr_restart_time = now

    except IOError as e:
        logging.exception('Check eac sessmgr failed: msg=%s', str(e))
        if e.errno != errno.ENOENT and e.errno != errno.EEXIST:
            raise


def get_nas_agent_pids():
    try:
        cmd = PS_CMD + "| grep '%s' | grep -vw grep | awk '{print $1}'" % NAS_AGENT_BIN_PATH
        ret = os.popen(cmd).read().strip()
        pids = [int(s) for s in ret.split('\n') if s]
        return pids
    except Exception as e:
        logging.error('Failed to get nas agent pids, error: %s', str(e))
        return []


def stop_nas_agent():
    try:
        pids = get_nas_agent_pids()
        for pid in pids:
            os.kill(pid, signal.SIGKILL)
    except Exception as e:
        logging.error('Failed to stop nas agent, error: %s', str(e))


def check_nas_agent_state():
    try:
        # wait until nas agent config exists
        if not os.path.exists(NAS_AGENT_CONF_PATH):
            return
        pids = get_nas_agent_pids()
        if len(pids) < 2:
            NAS_AGENT_LOGGER.rollover()
            stop_nas_agent()
            cmd = "%s --logtail_sys_conf_dir=%s --ilogtail_config=%s" % (
                NAS_AGENT_BIN_PATH, NAS_AGENT_SYS_CONF_DIR, NAS_AGENT_CONF_PATH)
            _, rc, _, stderr = execute_with_timeout(cmd, timeout=2)
            if rc == 0:
                logging.info('Successfully restart nas agent')
            else:
                logging.error('Failed to start nas agent, stderr: %s', str(stderr))
    except Exception as e:
        logging.error('Failed to start nas agent, error: %s', str(e))

def create_pexporter_log_file(global_log_dir=UNAS_LOG_DIR):
    try:
        log_dir_path = os.path.join(global_log_dir, "exporter")
        if not os.path.exists(log_dir_path):
            os.makedirs(log_dir_path, exist_ok=True)
        log_conf_path = os.path.join(global_log_dir, "log_conf.pexporter.json")
        if not os.path.exists(log_conf_path) and os.path.exists(PEXPORTER_LOG_CONF_TEMPLATE_PATH):
            shutil.copy(PEXPORTER_LOG_CONF_TEMPLATE_PATH, log_conf_path)
        return log_conf_path
    except IOError as e:
        logging.exception('Create pexporter log file failed: msg=%s', str(e))
        if e.errno != errno.ENOENT and e.errno != errno.EEXIST:
            raise

def check_pexporter_state():
    # start exporter for Promethues
    try:
        cmd = PS_CMD + '| grep %s | grep -vw grep' % PEXPORTER_BIN_PATH
        info = os.popen(cmd).read()
        # still alive
        if len(info) > 0:
            return
         
        pexporter_conf_path = create_pexporter_log_file() 
        pexporter_log_path = " --apsara_log_conf_path=%s" % pexporter_conf_path
        bootstrap_cmd = "nohup %s %s > %s/pexporter.out 2>&1 &" % (PEXPORTER_BIN_PATH, pexporter_log_path, LOG_DIR)
        errcode, _, errmsg = exec_cmd_in_subprocess(bootstrap_cmd)

        if errcode == 0:
            logging.info('Successfully restart pexporter')
        else:
            message = 'Failed to init pexporter, stderr="%s"' % (errmsg)
            logging.error(message)

    except IOError as e:
        logging.exception('Check eac pexporter failed: msg=%s', str(e))
        if e.errno != errno.ENOENT and e.errno != errno.EEXIST:
            raise

def try_clean_up_logs(clean_path, log_dir_name, log_file_name):
    try:
        cur_time = int(time.time())
        log_dir = os.path.join(clean_path, log_dir_name)
        if not os.path.exists(log_dir):
            return
        for d in os.listdir(log_dir):
            log_child_dir = os.path.join(log_dir, d)
            latest_log_path = os.path.join(log_child_dir, log_file_name) # /var/log/aliyun/alinas/efc-xxx/efclog/[time]/efc.LOG
            if not os.path.exists(latest_log_path):
                logging.warning("not found latest log file, clean up log dir:%s", log_child_dir)
                shutil.rmtree(log_child_dir)
                continue
            # get log file last modify time
            last_modify_time = int(os.path.getmtime(latest_log_path))
            if (cur_time - last_modify_time) > UNAS_LOG_FILE_GC_IN_SEC:
                logging.warning("exceed cleanup time, clean up log dir:%s", log_child_dir)
                shutil.rmtree(log_child_dir)
    except IOError as e:
        logging.exception('try_clean_up_logs failed: msg=%s', str(e))
        return

def schedule_clean_up_mount_files(log_file_dir=LOG_DIR, state_file_dir=STATE_FILE_DIR):
    # clean up log files when log time expired
    cur_time = int(time.time())
    log_files = get_files_with_prefix(log_file_dir, "eac-")
    log_files.update(get_files_with_prefix(log_file_dir, "efc-"))
    for mount_name in log_files:
        try:
            state_file_name = mount_name.replace('efc', 'eac')
            state_file_path = os.path.join(state_file_dir, state_file_name)
            if os.path.exists(state_file_path):
                continue

            is_new_name = mount_name.startswith("efc-")
            mount_file_dir = os.path.join(log_file_dir, mount_name) # /var/log/aliyun/alinas/efc-xxx/
            try_clean_up_logs(mount_file_dir, 'efclog' if is_new_name else 'eaclog', 'efc.LOG' if is_new_name else 'eac.LOG')
            try_clean_up_logs(mount_file_dir, 'vsclog', 'vsc.LOG')
            eac_log_dir = os.path.join(mount_file_dir, 'efclog' if is_new_name else 'eaclog')
            vsc_log_dir = os.path.join(mount_file_dir, 'vsclog')
            # all log files cleaned, remove mount dir
            if len(os.listdir(eac_log_dir)) == 0 and (not os.path.exists(vsc_log_dir) or len(os.listdir(vsc_log_dir)) == 0):
                logging.warning("cleanup efc log dir:%s", mount_file_dir)
                shutil.rmtree(mount_file_dir)
        except IOError as e:
            logging.exception('clean up eac mount files failed: msg=%s', str(e))
            continue

    for eac_file in os.listdir(EFC_WORKSPACE_DIR):
        try:
            m = POD_UID_PATTERN.match(eac_file)
            if m is None:
                continue
            pod_dir = os.path.join(EFC_WORKSPACE_DIR, eac_file) # /var/run/efc/{pod_uid}
            if not os.path.isdir(pod_dir):
                continue
            mps = os.listdir(pod_dir)
            for mp_name in mps:
                if mp_name == 'pod_info':
                    continue
                mp_path = pod_dir + '/' + mp_name
                if not os.path.exists(mp_path):
                    continue
                metric_path = mp_path + '/capacity_counter' # /var/run/efc/{pod_uid}/{mountpoint}/capacity_counter
                if os.path.exists(metric_path):
                    last_modify_time = int(os.path.getmtime(metric_path))
                    if (cur_time - last_modify_time) > MONITOR_FILE_GC_IN_SEC:
                        logging.warning('not updated for too long, clean metrics path %s' % mp_path)
                        shutil.rmtree(mp_path)
            mps = os.listdir(pod_dir)
            if len(mps) == 1 and mps[0] == 'pod_info' or len(mps) == 0:
                logging.warning('no metrics left, clean pod metrics path %s' % pod_dir)
                shutil.rmtree(pod_dir)
        except IOError as e:
            logging.exception('clean up eac monitor files failed: msg=%s', str(e))
            continue


def is_dadi_enabled():
    try:
        ps_cmd = "ps -eww -o args | grep aliyun-alinas-e[af]c"
        ps_info = os.popen(ps_cmd).read()
        for arg in re.findall('tier_EnableClusterCache=(\S+)', ps_info):
            if arg.lower() == 'true':
                return True
            for c in arg:
                if '1' <= c <= '9':
                    return True
                elif c != '0':
                    break
        return False
    except Exception as e:
        logging.warning('Failed to check if dadi is enabled')
        return False

last_dadi_discover_time = 0

def schedule_discover_dadi():
    global last_dadi_discover_time
    DADI_DISCOVER_INTERVAL = 60 # default 1min
    cur = int(time.time())
    if last_dadi_discover_time != 0 and (cur - last_dadi_discover_time < DADI_DISCOVER_INTERVAL):
        return

    last_dadi_discover_time = cur
    if not is_dadi_enabled():
        return

    discover_bash_path = '/usr/bin/aliyun-alinas-efc-dadi-kubediscover'
    try:
        cmd = 'sh %s' % discover_bash_path
        errcode, _, errmsg = exec_cmd_in_subprocess(cmd)

        if errcode == 0:
            logging.info('Successfully to discover dadi')
        else:
            logging.error('Failed to discover dadi, returncode=%d, stderr="%s"' % (errcode, errmsg))

    except Exception as e:
        logging.error('Failed to discover dadi, msg=%s', str(e))

def get_alinas_security_credentials(credentials_source):
    if credentials_source == 'default':
        config_file = DEDFAULT_RAM_CONFIG_FILE
    elif credentials_source.startswith('selfconfig'):
        config_file = credentials_source.split(':', 1)[1]
    else:
        logging.error('credentials_source not supported, %s', credentials_source)
        return None

    credentials = {}
    try:
        ram_config = read_config(config_file)
        credentials['AccessKeyId'] = ram_config.get(RAM_CONFIG_SECTION, 'accessKeyID', None)
        credentials['AccessKeySecret'] = ram_config.get(RAM_CONFIG_SECTION, 'accessKeySecret', None)
        credentials['SecurityToken'] = ram_config.get(RAM_CONFIG_SECTION, 'securityToken', None)
    except Exception as e:
        logging.error('Failed to read credentials from %s, msg=%s', config_file, str(e))
        return None

    if not credentials.get('AccessKeyId', None) or not credentials.get('AccessKeySecret', None):
        logging.error("access_key_id or access_key_secret not found")
        return None

    return credentials

def try_fix_credentials_source_for_old_version(mount_name, base_path=STATE_FILE_DIR):
    tls_paths = tls_paths_dictionary(mount_name, base_path)
    certificate_config = os.path.join(tls_paths["mount_dir"], "config.conf")
    try:
        with open(certificate_config, 'r') as file:
            content = file.read()
        if '[ alinas_client_auth ]' in content:
            return 'default'
    except Exception as e:
        logging.error('Failed to read certificate config from %s, msg=%s', certificate_config, str(e))
        return None

def check_certificate(config, state, state_file_dir, state_file, base_path=STATE_FILE_DIR):
    certificate_creation_time = datetime.strptime(
        state["certificateCreationTime"], CERT_DATETIME_FORMAT
    )
    certificate_exists = os.path.isfile(state["certificate"])
    certificate_renewal_interval_secs = (
        get_certificate_renewal_interval_mins(config) * 60
    )
    # creation instead of NOT_BEFORE datetime is used for refresh of cert because NOT_BEFORE derives from creation datetime
    should_refresh_cert = (
        get_utc_now() - certificate_creation_time
    ).total_seconds() > certificate_renewal_interval_secs

    if certificate_exists and not should_refresh_cert:
        return

    ap_state = state.get("accessPoint", None)
    if not certificate_exists:
        logging.debug(
            "Certificate (at %s) is missing. Recreating self-signed certificate"
            % state["certificate"]
        )
    else:
        logging.debug(
            "Refreshing self-signed certificate (at %s)" % state["certificate"]
        )

    credentials_source = state.get("credentialsMethod", None)
    if not credentials_source:
        credentials_source = try_fix_credentials_source_for_old_version(state["mountStateDir"], base_path=base_path)

    updated_certificate_creation_time = recreate_certificate(
        config,
        state["mountStateDir"],
        state["commonName"],
        state["fsId"],
        credentials_source,
        ap_state,
        state["region"],
        base_path=base_path,
    )
    if updated_certificate_creation_time:
        state["certificateCreationTime"] = updated_certificate_creation_time
        rewrite_state_file(state, state_file_dir, state_file)

        # send SIGHUP to force a reload of the configuration file to trigger the stunnel process to notice the new certificate
        pid = state.get("pid")
        if is_pid_running(pid):
            process_group = os.getpgid(pid)
            logging.info(
                "SIGHUP signal to stunnel. PID: %d, group ID: %s", pid, process_group
            )
            os.killpg(process_group, SIGHUP)
        else:
            logging.warning("TLS tunnel is not running for %s", state_file)


def create_required_directory(config, directory):
    mode = 0o750
    try:
        mode_str = config.get(WATCHDOG_CONFIG_SECTION, "state_file_dir_mode", default='750')
        try:
            mode = int(mode_str, 8)
        except ValueError:
            logging.warning(
                'Bad state_file_dir_mode "%s" in config file "%s"',
                mode_str,
                CONFIG_FILE,
            )
    except NoOptionError:
        pass

    try:
        os.makedirs(directory, mode, exist_ok=True)
        logging.debug("Expected %s not found, recreating asset", directory)
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise

def get_client_info(config):
    client_info = {}

    # source key/value pair in config file
    if config.has_option(CLIENT_INFO_SECTION, "source"):
        client_source = config.get(CLIENT_INFO_SECTION, "source", None)
        if 0 < len(client_source) <= CLIENT_SOURCE_STR_LEN_LIMIT:
            client_info["source"] = client_source
    if not client_info.get("source"):
        client_info["source"] = DEFAULT_UNKNOWN_VALUE

    client_info["alinas_utils_version"] = '%s-%s' % (RPM_NAME, get_version())

    return client_info

def recreate_certificate(
    config,
    mount_name,
    common_name,
    fs_id,
    credentials_source,
    ap_id,
    region,
    base_path=STATE_FILE_DIR,
):
    current_time = get_utc_now()
    tls_paths = tls_paths_dictionary(mount_name, base_path)

    certificate_config = os.path.join(tls_paths["mount_dir"], "config.conf")
    certificate_signing_request = os.path.join(tls_paths["mount_dir"], "request.csr")
    certificate = os.path.join(tls_paths["mount_dir"], "certificate.pem")

    ca_dirs_check(config, tls_paths["database_dir"], tls_paths["certs_dir"])
    ca_supporting_files_check(
        tls_paths["index"],
        tls_paths["index_attr"],
        tls_paths["serial"],
        tls_paths["rand"],
    )

    private_key = check_and_create_private_key(base_path)

    if credentials_source:
        public_key = os.path.join(tls_paths["mount_dir"], "publicKey.pem")
        create_public_key(private_key, public_key)

    client_info = get_client_info(config)
    config_body = create_ca_conf(
        config,
        certificate_config,
        common_name,
        tls_paths["mount_dir"],
        private_key,
        current_time,
        region,
        fs_id,
        credentials_source,
        ap_id=ap_id,
        client_info=client_info,
    )

    if not config_body:
        logging.error("Cannot recreate self-signed certificate")
        return None

    create_certificate_signing_request(
        certificate_config, private_key, certificate_signing_request
    )

    not_before = get_certificate_timestamp(current_time, minutes=-NOT_BEFORE_MINS)
    not_after = get_certificate_timestamp(current_time, hours=NOT_AFTER_HOURS)

    cmd = "openssl ca -startdate %s -enddate %s -selfsign -batch -notext -config %s -in %s -out %s" % (
        not_before,
        not_after,
        certificate_config,
        certificate_signing_request,
        certificate,
    )
    subprocess_call(cmd, "Failed to create self-signed client-side certificate")
    return current_time.strftime(CERT_DATETIME_FORMAT)

def get_private_key_path():
    """Wrapped for mocking purposes in unit tests"""
    return PRIVATE_KEY_FILE

def check_and_remove_lock_file(path, file):
    """
    There is a possibility of having a race condition as the lock file is getting deleted in both mount_efs and watchdog,
    so creating a function in order to check whether the path exist or not before removing the lock file.
    """
    try:
        os.close(file)
        os.remove(path)
        logging.debug("Removed %s successfully", path)
    except OSError as e:
        if not (e.errno == errno.ENOENT or e.errno == errno.EBADF):
            raise Exception("Could not remove %s. Unexpected exception: %s", path, e)
        else:
            logging.debug(
                "%s does not exist, The file is already removed nothing to do", path
            )

def check_and_create_private_key(base_path=STATE_FILE_DIR):
    # Creating RSA private keys is slow, so we will create one private key and allow mounts to share it.
    # This means, however, that we have to include a locking mechanism to ensure that the private key is
    # atomically created, as mounts occurring in parallel may try to create the key simultaneously.
    # The key should have been created during mounting, but the watchdog will recreate the private key if
    # it is missing.
    key = get_private_key_path()

    @contextmanager
    def open_lock_file():
        lock_file = os.path.join(base_path, "private-key-lock")
        f = os.open(lock_file, os.O_CREAT | os.O_DSYNC | os.O_EXCL | os.O_RDWR)
        try:
            lock_file_contents = "PID: %s" % os.getpid()
            os.write(f, lock_file_contents.encode("utf-8"))
            yield f
        finally:
            check_and_remove_lock_file(lock_file, f)

    def do_with_lock(function):
        while True:
            try:
                with open_lock_file():
                    return function()
            except OSError as e:
                if e.errno == errno.EEXIST:
                    logging.info(
                        "Failed to take out private key creation lock, sleeping %s (s)",
                        DEFAULT_TIMEOUT,
                    )
                    time.sleep(DEFAULT_TIMEOUT)
                else:
                    # errno.ENOENT: No such file or directory, errno.EBADF: Bad file descriptor
                    if e.errno == errno.ENOENT or e.errno == errno.EBADF:
                        logging.debug(
                            "lock file does not exist or Bad file descriptor, The file is already removed nothing to do."
                        )
                    else:
                        raise Exception(
                            "Could not remove lock file unexpected exception: %s", e
                        )

    def generate_key():
        if os.path.isfile(key):
            return

        cmd = (
            "openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:3072" % key
        )
        subprocess_call(cmd, "Failed to create private key")
        read_only_mode = 0o400
        os.chmod(key, read_only_mode)

    do_with_lock(generate_key)
    return key

def create_certificate_signing_request(config_path, private_key, csr_path):
    cmd = "openssl req -new -config %s -key %s -out %s" % (
        config_path,
        private_key,
        csr_path,
    )
    subprocess_call(cmd, "Failed to create certificate signing request (csr)")

def create_ca_conf(
    config,
    config_path,
    common_name,
    directory,
    private_key,
    date,
    region,
    fs_id,
    credentials_source,
    ap_id=None,
    client_info=None,
):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, "publicKey.pem")
    security_credentials = (
        get_alinas_security_credentials(credentials_source)
        if credentials_source
        else ""
    )

    if credentials_source and security_credentials is None:
        logging.error(
            "Failed to retrieve aliyun security credentials using lookup method: %s",
            credentials_source,
        )
        return None

    ca_extension_body = ca_extension_builder(
        ap_id, security_credentials, fs_id, client_info
    )
    alinas_client_auth_body = (
        alinas_client_auth_builder(
            public_key_path,
            security_credentials["AccessKeyId"],
            security_credentials["AccessKeySecret"],
            date,
            region,
            fs_id,
            security_credentials["SecurityToken"],
        )
        if credentials_source
        else ""
    )
    if credentials_source and not alinas_client_auth_body:
        logging.error(
            "Failed to create SigV4 signature section for OpenSSL config. Public Key path: %s",
            public_key_path,
        )
        return None

    alinas_client_info_body = alinas_client_info_builder(client_info, region) if client_info else ""
    full_config_body = CA_CONFIG_BODY % (
        directory,
        private_key,
        common_name,
        ca_extension_body,
        alinas_client_auth_body,
        alinas_client_info_body,
    )

    with open(config_path, "w") as f:
        f.write(full_config_body)

    return full_config_body

def ca_extension_builder(ap_id, security_credentials, fs_id, client_info):
    ca_extension_str = "[ v3_ca ]\nsubjectKeyIdentifier = hash"
    if ap_id:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:" + ap_id
    if security_credentials:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:alinas_client_auth"

    ca_extension_str += "\n1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:" + fs_id

    if client_info:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:alinas_client_info"

    return ca_extension_str

def alinas_client_auth_builder(
    public_key_path,
    access_key_id,
    secret_access_key,
    date,
    region,
    fs_id,
    session_token=None,
):
    public_key_hash = get_public_key_sha1(public_key_path)

    if not public_key_path:
        return None

    canonical_request = create_canonical_request(
        public_key_hash, date, access_key_id, region, fs_id, session_token
    )
    string_to_sign = create_string_to_sign(canonical_request, date, region)
    signature = calculate_signature(string_to_sign, date, secret_access_key, region)
    alinas_client_auth_str = "[ alinas_client_auth ]"
    alinas_client_auth_str += "\naccessKeyId = UTF8String:" + access_key_id
    alinas_client_auth_str += "\nsignature = OCTETSTRING:" + signature
    alinas_client_auth_str += "\nsigv4DateTime = UTCTIME:" + date.strftime(
        CERT_DATETIME_FORMAT
    )
    if session_token:
        alinas_client_auth_str += "\nsessionToken = EXPLICIT:0,UTF8String:" + session_token

    return alinas_client_auth_str

def alinas_client_info_builder(client_info, region):
    alinas_client_info_str = "[ alinas_client_info ]"
    for key, value in client_info.items():
        alinas_client_info_str += "\n%s = UTF8String:%s" % (key, value)
    alinas_client_info_str += "\nregion = EXPLICIT:0,UTF8String:%s" % (region)
    return alinas_client_info_str

def create_public_key(private_key, public_key):
    cmd = "openssl rsa -in %s -outform PEM -pubout -out %s" % (private_key, public_key)
    subprocess_call(cmd, "Failed to create public key")

def subprocess_call(cmd, error_message):
    """Helper method to run shell openssl command and to handle response error messages"""
    process = subprocess.Popen(
        cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    (output, err) = process.communicate()
    rc = process.poll()
    if rc != 0:
        logging.debug(
            '%s. Command %s failed, rc=%s, stdout="%s", stderr="%s"',
            error_message,
            cmd,
            rc,
            output,
            err,
        )
    else:
        return output, err

def ca_dirs_check(config, database_dir, certs_dir):
    """Check if mount's database and certs directories exist and if not, create directories (also create all intermediate
    directories if they don't exist)."""
    if not os.path.exists(database_dir):
        create_required_directory(config, database_dir)
    if not os.path.exists(certs_dir):
        create_required_directory(config, certs_dir)


def ca_supporting_files_check(index_path, index_attr_path, serial_path, rand_path):
    """Create all supporting openssl ca and req files if they're not present in their respective directories"""

    def _recreate_file_warning(path):
        logging.warning("Expected %s not found, recreating file", path)

    if not os.path.isfile(index_path):
        open(index_path, "w").close()
        _recreate_file_warning(index_path)
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, "w+") as f:
            f.write("unique_subject = no")
        _recreate_file_warning(index_attr_path)
    if not os.path.isfile(serial_path):
        with open(serial_path, "w+") as f:
            f.write("00")
        _recreate_file_warning(serial_path)
    if not os.path.isfile(rand_path):
        open(rand_path, "w").close()
        _recreate_file_warning(rand_path)

def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        "mount_dir": os.path.join(base_path, mount_name),
        "database_dir": os.path.join(base_path, mount_name, "database"),
        "certs_dir": os.path.join(base_path, mount_name, "certs"),
        "index": os.path.join(base_path, mount_name, "database/index.txt"),
        "index_attr": os.path.join(base_path, mount_name, "database/index.txt.attr"),
        "serial": os.path.join(base_path, mount_name, "database/serial"),
        "rand": os.path.join(base_path, mount_name, "database/.rand"),
    }

    return tls_dict

def get_public_key_sha1(public_key):
    # truncating public key to remove the header and footer '-----(BEGIN|END) PUBLIC KEY-----'
    with open(public_key, "r") as f:
        lines = f.readlines()
        lines = lines[1:-1]

    key = "".join(lines)
    key = bytearray(base64.b64decode(key))

    # Parse the public key to pull out the actual key material by looking for the key BIT STRING
    # Example:
    #     0:d=0  hl=4 l= 418 cons: SEQUENCE
    #     4:d=1  hl=2 l=  13 cons: SEQUENCE
    #     6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
    #    17:d=2  hl=2 l=   0 prim: NULL
    #    19:d=1  hl=4 l= 399 prim: BIT STRING
    cmd = "openssl asn1parse -inform PEM -in %s" % public_key
    output, err = subprocess_call(
        cmd, "Unable to ASN1 parse public key file, %s, correctly" % public_key
    )

    key_line = ""
    for line in output.splitlines():
        if "BIT STRING" in line.decode("utf-8"):
            key_line = line.decode("utf-8")

    if not key_line:
        logging.error("Public key file, %s, is incorrectly formatted" % public_key)
        return None

    key_line = key_line.replace(" ", "")

    # DER encoding TLV (Tag, Length, Value)
    # - the first octet (byte) is the tag (type)
    # - the next octets are the length - "definite form"
    #   - the first octet always has the high order bit (8) set to 1
    #   - the remaining 127 bits are used to encode the number of octets that follow
    #   - the following octets encode, as big-endian, the length (which may be 0) as a number of octets
    # - the remaining octets are the "value" aka content
    #
    # For a BIT STRING, the first octet of the value is used to signify the number of unused bits that exist in the last
    # content byte. Note that this is explicitly excluded from the SubjectKeyIdentifier hash, per
    # https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    #
    # Example:
    #   0382018f00...<subjectPublicKey>
    #   - 03 - BIT STRING tag
    #   - 82 - 2 length octets to follow (ignore high order bit)
    #   - 018f - length of 399
    #   - 00 - no unused bits in the last content byte
    offset = int(key_line.split(":")[0])
    key = key[offset:]

    num_length_octets = key[1] & 0b01111111

    # Exclude the tag (1), length (1 + num_length_octets), and number of unused bits (1)
    offset = 1 + 1 + num_length_octets + 1
    key = key[offset:]

    sha1 = hashlib.sha1()
    sha1.update(key)

    return sha1.hexdigest()

def create_canonical_request(
    public_key_hash, date, access_key, region, fs_id, session_token=None
):
    """
    Create a Canonical Request
    """
    formatted_datetime = date.strftime(SIGV4_DATETIME_FORMAT)
    credential = quote_plus(access_key + "/" + get_credential_scope(date, region))

    request = HTTP_REQUEST_METHOD + "\n"
    request += CANONICAL_URI + "\n"
    request += (
        create_canonical_query_string(
            public_key_hash, credential, formatted_datetime, session_token
        )
        + "\n"
    )
    request += CANONICAL_HEADERS % fs_id + "\n"
    request += SIGNED_HEADERS + "\n"

    sha256 = hashlib.sha256()
    sha256.update(REQUEST_PAYLOAD.encode())
    request += sha256.hexdigest()

    return request

def create_canonical_query_string(
    public_key_hash, credential, formatted_datetime, session_token=None
):
    canonical_query_params = {
        "Action": "Connect",
        # Public key hash is included in canonical request to tie the signature to a specific key pair to avoid replay attacks
        "PublicKeyHash": quote_plus(public_key_hash),
        "X-Alinas-Algorithm": ALGORITHM,
        "X-Alinas-Credential": credential,
        "X-Alinas-Date": quote_plus(formatted_datetime),
        "X-Alinas-Expires": 86400,
        "X-Alinas-SignedHeaders": SIGNED_HEADERS,
    }

    if session_token:
        canonical_query_params["X-Alinas-Security-Token"] = quote_plus(session_token)

    # Cannot use urllib.urlencode because it replaces the %s's
    return "&".join(
        ["%s=%s" % (k, v) for k, v in sorted(canonical_query_params.items())]
    )

def create_string_to_sign(canonical_request, date, region):
    string_to_sign = ALGORITHM + "\n"
    string_to_sign += date.strftime(SIGV4_DATETIME_FORMAT) + "\n"
    string_to_sign += get_credential_scope(date, region) + "\n"

    sha256 = hashlib.sha256()
    sha256.update(canonical_request.encode())
    string_to_sign += sha256.hexdigest()

    return string_to_sign

def calculate_signature(string_to_sign, date, secret_access_key, region):
    def _sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256)

    key_date = _sign(
        ("aliyun_v4" + secret_access_key).encode("utf-8"), date.strftime(DATE_ONLY_FORMAT)
    ).digest()
    add_region = _sign(key_date, region).digest()
    add_service = _sign(add_region, 'nas').digest()
    signing_key = _sign(add_service, "aliyun_v4_request").digest()

    return _sign(signing_key, string_to_sign).hexdigest()

def get_certificate_renewal_interval_mins(config):
    interval = DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN
    try:
        mins_from_config = config.get(WATCHDOG_CONFIG_SECTION, "tls_cert_renewal_interval_min", default=DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN)
        try:
            if int(mins_from_config) > 0:
                interval = int(mins_from_config)
            else:
                logging.warning(
                    'tls_cert_renewal_interval_min value in config file "%s" is lower than 1 minute. Defaulting '
                    "to %d minutes.",
                    CONFIG_FILE,
                    DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
                )
        except ValueError:
            logging.warning(
                'Bad tls_cert_renewal_interval_min value, "%s", in config file "%s". Defaulting to %d minutes.',
                mins_from_config,
                CONFIG_FILE,
                DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
            )
    except NoOptionError:
        logging.warning(
            'No tls_cert_renewal_interval_min value in config file "%s". Defaulting to %d minutes.',
            CONFIG_FILE,
            DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
        )

    return interval

def get_credential_scope(date, region):
    return "/".join([date.strftime(DATE_ONLY_FORMAT), region, SERVICE, ALIYUN4_REQUEST])

def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)

def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.utcnow()

def check_nfs_mounts(config, watchdog, unmount_grace_period_sec, state_file_dir=STATE_FILE_DIR):
    nfs_mounts = get_current_local_nfs_mounts()
    state_files = get_files_with_prefix(state_file_dir, 'alinas-')
    logging.debug('Current state files in "%s": %s', state_file_dir, list(state_files.values()))

    for local_dns, state_file in state_files.items():
        try:
            state = watchdog.load_state_file(state_file_dir, state_file)
            if not state:
                continue

            is_running = is_pid_running(state['pid'])

            current_time = time.time()
            if 'unmount_time' in state:
                if state['unmount_time'] + unmount_grace_period_sec < current_time:
                    logging.info('Unmount grace period expired for %s', state_file)
                    clean_up_mount_state(state_file_dir, state_file, state['pid'], is_running, state.get('mountStateDir'))
            elif local_dns not in nfs_mounts:
                logging.info('No mount found for "%s"', state_file)
                mark_as_unmounted(state, state_file_dir, state_file, current_time)
            else:
                if "certificate" in state:
                    check_certificate(config, state, state_file_dir, state_file)
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

    return nfs_mounts

def clean_shm_files(mount_uuid, mount_point, watchdog, shm_dir='/dev/shm', state_file_dir=STATE_FILE_DIR):
    shm_key = mount_uuid

    # gurantee nobody use these shmfiles
    # for different mounts, shm file will not be shared (except upgrade and failover)
    shm_files = [
                'volume_%s' % shm_key,
                 'journal_%s' % shm_key,
                 'page_%s' % shm_key,
                 'file_%s' % shm_key,
                 'bar_%s' % shm_key,
                 'fh_%s' % shm_key
                ]

    for fi in shm_files:
        file_path = os.path.join(shm_dir, fi)
        if os.path.exists(file_path):
            os.remove(file_path)
    
def check_unas_bindroot_ref_zero(mount_uuid, bind_mountpoint, unas_proc_mounts):
    try:
        ref = 0
        for m in unas_proc_mounts:
            split_dns = m.server.split(':')
            uuid = split_dns[0]
            if mount_uuid == uuid:
                if not compare_unas_mountpoint(bind_mountpoint, m.mountpoint):
                    ref += 1
        return ref == 0
    except Exception as e:
        logging.error('Fail check unas umount bindroot ref fail, uuid %s, bindroot:%s' % (mount_uuid, bind_mountpoint))
        raise

def is_unas_mounted(state, local_mount_dns, unas_proc_mounts):
    mount_uuid = state['mountuuid']
    # for bind mount, check ref count of bindroot
    if mount_uuid.startswith(BIND_ROOT_PREFIX):
        bind_mountpoint = state['mountpoint']
        if not check_unas_bindroot_ref_zero(mount_uuid, bind_mountpoint, unas_proc_mounts):
            return True
    else:
        for m in unas_proc_mounts:
            if m.server == local_mount_dns:
                return True
    return False

def is_unas_bindroot_mounted(state, unas_proc_mounts):
    mount_uuid = state['mountuuid']
    bind_mountpoint = state['mountpoint']
    if mount_uuid.startswith(BIND_ROOT_PREFIX):
        for m in unas_proc_mounts:
            split_dns = m.server.split(':')
            uuid = split_dns[0]
            if mount_uuid == uuid:
                if compare_unas_mountpoint(bind_mountpoint, m.mountpoint):
                    return True
    return False

def is_unas_bindroot_mount_exist(mount_uuid, unas_proc_mounts):
    for m in unas_proc_mounts:
        split_dns = m.server.split(':')
        uuid = split_dns[0]
        if mount_uuid == uuid:
            return True
    return False

def get_efc_options(mountcmd):
    return dict(re.findall('--(?P<name>[^=]*)=(?P<value>\S*)', mountcmd))

def remove_files_with_pattern(parent, pattern):
    if not os.path.exists(parent) or not os.path.isdir(parent):
        return

    for entry in os.listdir(parent):
        if pattern not in entry:
            continue
        cache_path = os.path.join(parent, entry)
        os.remove(cache_path)
        logging.warning('Removed dadi cache %s' % cache_path)

def clean_up_dadi_caches(mount_uuid, state):
    options = get_efc_options(state['mountcmd'])
    index_path = options.get('tier_DadiIndexPath', '/dev/shm')
    shmem_path = '/dev/shm'
    disk_paths = options.get('tier_DadiDiskCachePath', '')
    pattern = 'dadi.{}'.format(mount_uuid)
    remove_files_with_pattern(index_path, pattern)
    remove_files_with_pattern(shmem_path, pattern)
    for path in disk_paths.split(':'):
        if not path:
            continue
        remove_files_with_pattern(path.strip(), pattern)

def clean_up_cgroup_workspace(mount_uuid):
    workspace = os.path.join(CGROUP_DIR, mount_uuid)
    if os.path.exists(workspace):
        logging.warning('Cleanup unas cgroup workspace, dir:%s mount_uuid:%s' % (workspace, mount_uuid))
        os.rmdir(workspace)
    workspace = os.path.join(OLD_CGROUP_DIR, mount_uuid)
    if os.path.exists(workspace):
        logging.warning('Cleanup unas cgroup workspace, dir:%s mount_uuid:%s' % (workspace, mount_uuid))
        os.rmdir(workspace)

def clean_up_unas_workspace(mount_uuid):
    patterns = ['%s.efc.lock', '%s.efc.sock', '%s.monitor.sock']
    for p in patterns:
        file = os.path.join(EFC_WORKSPACE_DIR, p % mount_uuid)
        if os.path.exists(file):
            os.remove(file)
    logging.warning('Cleanup unas workspace with mountuuid:%s', mount_uuid)

def get_process_pid(process_regex):
    pid = 0
    try:
        cmd = PS_CMD + "| grep '%s' | grep -vw grep | awk '{print $1}'" % process_regex
        ret = os.popen(cmd).read().strip()
        if ret.isdigit():
            pid = int(ret)
    except:
        logging.exception('get process pid value error: regex:%s', process_regex)
    return pid

def get_connection_id(mount_uuid, mount_dir=None):
    conn_id = 0
    if mount_uuid:
        cmd = "cat /proc/self/mountinfo | grep %s | head -n 1 | awk -F'[ :]' '{ print $4 }'" % mount_uuid
    else:
        cmd = "cat /proc/self/mountinfo | awk -F '[ :]' '$6 == \"%s\" {print $4; exit }'" % mount_dir
    try:
        ret = os.popen(cmd).read().strip()
        if ret.isdigit():
            conn_id = int(ret)
    except:
        logging.exception('get connection id value error: mount_uuid:%s, mount_dir:%s', mount_uuid or '', mount_dir or '')
    return conn_id

def get_process_alive_sec(pid):
    alive = 0
    try:
        cmd = "ps -p %d -oetime= | tr '-' ':' | awk -F: '{ total=0; m=1; } { for (i=0; i < NF; i++) {total += $(NF-i)*m; m *= i >= 2 ? 24 : 60 }} {print total}'" % pid
        ret = os.popen(cmd).read().strip()
        if ret.isdigit():
            alive = int(ret)
    except:
        logging.exception('get process alive value error: pid:%d', pid)
    return alive

def kill_process_uuid(mount_uuid, min_alive_sec=0):
    ps_cmd = PS_CMD + "| grep e[af]c"
    ps_info = os.popen(ps_cmd).read()
    regex_mount = 'mount_uuid=%s' % mount_uuid 
    if regex_mount in ps_info:
        pid = get_process_pid(regex_mount)
        alive_sec = get_process_alive_sec(pid)
        if pid > 1 and alive_sec >= min_alive_sec:
            kill_cmd = "kill -9 %d" % pid
            errcode, _, _ = exec_cmd_in_subprocess(kill_cmd)
            logging.error("eac process killed uuid:%s pid: %d" % (mount_uuid, pid))
            if errcode != 0:
                raise RuntimeError('Fail to kill eac process when drop eac mount, uuid:%s', mount_uuid)

def drop_unas_mount(state, watchdog, state_file_dir, state_file):
    mount_uuid = state['mountuuid']
    mount_point = state['mountpoint']
   
    try: 
        # for bindroot mount, do umount bindroot first
        unas_proc_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        if mount_uuid.startswith(BIND_ROOT_PREFIX):
            if check_unas_bindroot_ref_zero(mount_uuid, mount_point, unas_proc_mounts):
                if not clean_bindroot(mount_uuid, mount_point, state):
                    # if umount fail too long, try kill process and retry
                    current_time = time.time()
                    if state['fail_check_time'] + UNAS_UMOUNT_FAIL_TIMEOUT < current_time:
                        kill_process_uuid(mount_uuid, UNAS_UMOUNT_KILL_PROCESS_MIN_ALIVE)
                    return

        # try kill eac process for safety
        kill_process_uuid(mount_uuid)
      
        # double check /proc/mounts after kill process
        unas_proc_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        local_mount_dns = state['mountuuid'] + ':' + state['mountpath']
        drop = True
        if is_unas_mounted(state, local_mount_dns, unas_proc_mounts):
            drop = False
        if is_unas_bindroot_mounted(state, unas_proc_mounts):
            drop = False

        # cleanup files
        if drop:
            logging.info('start clean eac mount files, %s', mount_uuid)
            clean_shm_files(mount_uuid, mount_point, watchdog)
            clean_up_dadi_caches(mount_uuid, state)
            clean_up_cgroup_workspace(mount_uuid)
            clean_up_unas_workspace(mount_uuid)
            clean_up_unas_state(state_file_dir, state_file, state)
            logging.info('success clean eac mount files, %s', mount_uuid)
        else:
            logging.error('fail clean eac mount files, mount_point still exists, %s', mount_uuid)

    except Exception as e:
        logging.exception('drop eac mount failed: uuid:%s, msg=%s', mount_uuid, str(e))
        raise

def valid_mountpoint_for_prometheus(mountpoint):
    # /var/lib/kubelet/pods/${pod_uid}/volumes/kubernetes.io~csi/${sub_remotepath}/...
    sp = mountpoint.split('/')
    return len(sp) >= 9 and sp[4] == 'pods' and sp[6] == 'volumes' and (sp[7] == 'kubernetes.io~csi' or sp[7] == 'alicloud~nas')

def leach_metrics_keys(state):
    mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
    keys_from_mounts = set()
    valid_keys = set()
    invalid_keys = set()
    mount_uuid = state['mountuuid']

    for mp in mounts:
        # 跳过不属于该root的mount point
        if not mount_uuid == mp.server.split(':')[0]:
            continue
        # 跳过不符合pod挂载路径的mount point
        if not valid_mountpoint_for_prometheus(mp.mountpoint):
            continue

        mp_elements = mp.mountpoint.split('/')
        if mp_elements[6] == 'volumes':
            remote_path = mp_elements[8]
        else:
            remote_path = mp_elements[7]
        # 从mount point中筛选出有效的pod挂载
        keys_from_mounts.add(mp_elements[5] + '/' + remote_path)

    keys_from_state = state.get('monitor_metrics_paths')
    for mkey in keys_from_state.keys():
        if mkey not in keys_from_mounts:
            invalid_keys.add(mkey)
        else:
            valid_keys.add(mkey)

    return valid_keys, invalid_keys

def larger_command(command_a, command_b):
    if command_a['version'].split('.') >= command_b['version'].split('.'):
        return command_a
    return command_b

def merge_command_contents(*configs):
    merged = {}
    for conf in configs:
        if conf is None or 'commands' not in conf:
            continue
        for key, command in conf['commands'].items():
            if 'version' not in command:
                continue
            if key not in merged:
                merged[key] = command
            else:
                merged[key] = larger_command(merged[key], command)
    return merged

METRICS_FILENAME = [
    'capacity_counter',
    'inodes_counter',
    'throughput_counter',
    'iops_counter',
    'latency_counter',
    'posix_counter',
    'posix_latency_counter',
    'tier_counter',
    'ioc_counter',
    'backend_throughput_counter',
    'backend_iops_counter',
    'backend_latency_counter',
    'backend_meta_qps_ounter',
    'backend_meta_latency_counter'
]

def update_monitor_metrics(state):
    if 'monitor_metrics_paths' in state:
        socket_path = '%s/%s.monitor.sock' % (EFC_WORKSPACE_DIR, state['mountuuid'])
        curl_cmd = 'curl --unix-socket %s 1/metrics' % socket_path
        try:
            metrics = os.popen(curl_cmd).read().strip().split('\n')
            metrics_types = len(METRICS_FILENAME)
            if len(metrics) <= 0:
                return

            valid_keys, invalid_keys = leach_metrics_keys(state)
            for k in valid_keys:
                dirname = '%s/%s' % (EFC_WORKSPACE_DIR, k)
                if not os.path.exists(dirname):
                    os.makedirs(dirname, exist_ok=True)

                for i in range(len(metrics)):
                    filename = '%s/%s' % (dirname, METRICS_FILENAME[i])
                    with open(filename, 'w') as f:
                        f.write(metrics[i])

            # 清理掉残留的挂载点统计数据
            for key in invalid_keys:
                invalid_dir_path = '%s/%s' % (EFC_WORKSPACE_DIR, key)
                if os.path.exists(invalid_dir_path):
                    logging.warning('found invalid key after leach, cleaning metrics path %s' % invalid_dir_path)
                    shutil.rmtree(invalid_dir_path)

        except Exception as e:
            logging.exception('update monitor metrics fail: msg=%s', str(e))


def skip_check_unas_mounts():
    # when hot upgrade in multi-tenancy, watchdog with wrong version don't need to check mounts
    # 1. new version watchdog don't need to check mounts before sidecar_version updated
    # 2. old version watchdog don't need to check mounts after sidecar_version updated
    try:
        local_version = os.environ.get('SIDECARSET_VERSION')
        if local_version is None:
            return False
        with open('/var/run/efc/sidecar_version') as f:
            cur_version = f.read().strip()
            if int(cur_version) != int(local_version):
                return True
            else:
                return False
    except Exception as e:
        logging.warning('check sidecarSet version fail:%s', str(e))
        return False

def check_unas_mounts(watchdog, state_file_dir=STATE_FILE_DIR):
    if skip_check_unas_mounts():
        return {}
    unas_proc_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
    state_files = get_files_with_prefix(state_file_dir, 'eac-')
    state_files.update(get_files_with_prefix(state_file_dir, 'efc-'))

    unas_mounts = {}
    try:

        # check unas mounts      
        ps_cmd = PS_CMD + "| grep e[af]c"
        ps_info = os.popen(ps_cmd).read()

        for _, state_file in state_files.items():
            try:
                state = watchdog.load_state_file(state_file_dir, state_file)
                if not state:
                   continue

                mount_uuid = state['mountuuid']
                local_mount_dns = state['mountuuid'] + ':' + state['mountpath']
                uuid_lock_name = state['mountkey']

                bind_tag = ''
                if BIND_TAG in state:
                    bind_tag = state[BIND_TAG]
                sessmgr_required = True
                if SESSMGR_REQUIRED in state:
                    sessmgr_required = state[SESSMGR_REQUIRED]

                unas_state = UnasState(state['mountuuid'], state['mountpoint'], state['mountpath'], state['mountcmd'], state['mountkey'], bind_tag, sessmgr_required)
                with lock_state_file(STATE_FILE_DIR, uuid_lock_name, UNAS_LOCK_STATEFILE_TIMEOUT):
                    if skip_check_unas_mounts():
                        return unas_mounts
                    # get state again with uuid lock held
                    state = watchdog.load_state_file(state_file_dir, state_file)
                    if not state:
                        continue
                    if is_unas_bindroot_mounted(state, unas_proc_mounts) and not is_unas_running(unas_state, ps_info):
                        pass
                    elif not is_unas_mounted(state, local_mount_dns, unas_proc_mounts):
                        current_time = time.time()
                        if 'fail_check_time' in state:
                            if state['fail_check_time'] + UNAS_MOUNT_FAIL_MAX_CHECK_TIME < current_time:
                                logging.info('Unmount grace period expired for eac mount: %s', state_file)
                                drop_unas_mount(state, watchdog, state_file_dir, state_file)
                        else:
                            logging.info('No eac mount found for "%s"', state_file)
                            state['fail_check_time'] =  current_time
                            rewrite_state_file(state, state_file_dir, state_file)
                        continue
     
                    if 'fail_check_time' in state:
                        del state['fail_check_time']
                        rewrite_state_file(state, state_file_dir, state_file)

                    check_unas_process_mem(unas_state)
         
                    if not is_unas_running(unas_state, ps_info):
                        if os.path.exists('%s/%s' % (EFC_WORKSPACE_DIR, "sidecar_exit")) \
                            and not os.path.exists('%s/%s.%s' % (EFC_WORKSPACE_DIR, mount_uuid, EFC_LOCK_SUFFIX)):
                            # happens in vfuse environment
                            # when efc exited safely after cleaning up its workspace while leaving a mount record in vfuse
                            # in this case, we ignore it
                            logging.info('Check eac status failed, mount_uuid:%s, no restart because efc lock not exist' % state['mountuuid'])
                        else:
                            # efc failover
                            logging.info('Check eac status failed, mount_uuid:%s, try restart' % state['mountuuid'])
                            restart_unas_process(unas_state)
                            
                    else: 
                        # eac mounts not needed processing by LiveDetector
                        # compose local dns by mount_uuid for live detector
                        #local_dns = 'eac-%s' % state['mountuuid']
                        #unas_mounts[local_dns] = state
                        pass

                    update_monitor_metrics(state)

            except MemoryError:
                raise
            except Exception as e:
                logging.exception('Check eac mounts failed: msg=%s', str(e))
                time.sleep(5)

        # clean up discard mount log files
        schedule_clean_up_mount_files(LOG_DIR, state_file_dir)

    except MemoryError:
        raise
    except Exception as e:
        logging.exception('Check eac mounts failed: msg=%s', str(e))
        time.sleep(5)
    
    return unas_mounts

def check_sessmgr_required(watchdog, state_file_dir=STATE_FILE_DIR):
    sessmgr_required = False
    state_files = get_files_with_prefix(state_file_dir, 'eac-')
    state_files.update(get_files_with_prefix(state_file_dir, 'efc-'))

    for _, state_file in state_files.items():
        try:
            state = watchdog.load_state_file(state_file_dir, state_file)
            if not state:
                continue
            # upgrade from old version
            if SESSMGR_REQUIRED not in state or state[SESSMGR_REQUIRED]:
                sessmgr_required = True
                break
        except Exception as e:
            logging.exception('Check eac mounts failed: msg=%s', str(e))
            return True

    return sessmgr_required

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
        sys.stdout.write('%s Version: %s\n' % (args[0], get_version()))
        sys.exit(0)


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write('only root can run aliyun-alinas-mount-watchdog\n')
        sys.exit(1)


def assert_py3():
    version_info = sys.version_info
    major = version_info[0]
    if major < 3:
        fatal_error('only python3 is supported!')

def delete_preload_env():
    try:
        del os.environ["LD_PRELOAD"]
    except Exception as e:
        pass

def check_env():
    assert_root()
    assert_py3()
    delete_preload_env()


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

    def has_option(self, section, key):
        return self._config.has_option(section, key)

# If the file not exists, no side effects
def read_config(config_file=CONFIG_FILE):
    p = ConfigParser()
    files_loaded = p.read(config_file)
    return SafeConfig(p, config_file, configfile_error=not files_loaded)


def resolve_dns(dns):
    return socket.gethostbyname(dns)


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


class EventItem(object):
    def __init__(self, data, callback):
        self.data = data
        self.callback = callback

    def __lt__(self, other):
        return other


class EventWaiter(object):
    def __init__(self):
        self._interrupted = threading.Condition()
        self._has_pending_interruption = False
        self._events = []

    def clear(self):
        self._events.clear()

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
            expired_at, item = heapq.heappop(self._events)
            tasks.append((expired_at, item.data, item.callback))

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
        heapq.heappush(self._events, (expired_at, EventItem(data, callback)))

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

    def __init__(self, config, watchdog, state_file_dir=STATE_FILE_DIR):
        self._state_file_dir = state_file_dir
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

        logging.warning('Ping timeout: local_dns=%s, mountpoint=%s, timeout=%s',
                        pingtask.local_dns,
                        pingtask.mountpoint,
                        pingtask.timeout)

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

            # for unas and nfs mounts, just ping dns to keepalive
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


class NasAgentLogger(object):
    def __init__(self, config):
        self._max_bytes = config.getint(NAS_AGENT_CONFIG_SECTION, 'logging_max_bytes',
                                        default=1048576, minvalue=1048576, maxvalue=1048576 * 16)
        self._file_count = config.getint(NAS_AGENT_CONFIG_SECTION, 'logging_file_count', default=8, minvalue=1, maxvalue=16)
        self._lock = threading.Lock()
        self._loggers = {}

    def _has_obsolete(self, log_file):
        return os.path.exists(log_file) and os.stat(log_file).st_size > 0

    def _create_logger(self, region):
        region_dir = os.path.join(NAS_AGENT_LOG_DIR, region)
        os.makedirs(region_dir, exist_ok=True)
        region_file = os.path.join(region_dir, NAS_AGENT_LOG_FILE)
        handler = RotatingFileHandler(region_file, maxBytes=self._max_bytes, backupCount=self._file_count)
        if self._has_obsolete(region_file):
            handler.doRollover()
        handler.setFormatter(logging.Formatter(fmt='%(message)s'))

        logger = logging.getLogger(region)
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        logger.propagate = False

        self._loggers[region] = logger

    def rollover(self):
        self._lock.acquire()
        try:
            for logger in self._loggers.values():
                handler = logger.handlers[0]
                if self._has_obsolete(handler.baseFilename):
                    handler.doRollover()
        except Exception as e:
            logging.error('Fail to rollover, error: %s', str(e))
        finally:
            self._lock.release()

    def submit(self, region, record):
        self._lock.acquire()
        try:
            if region not in self._loggers:
                self._create_logger(region)
            self._loggers[region].warning(json.dumps(record))
        except Exception as e:
            logging.error('Fail to dispatch log to %s, error: %s', region, str(e))
        finally:
            self._lock.release()


def parse_mountpoint(mountpoint):
    for fs_cat, mp_pat in NAS_AGENT_MOUNTPOINT_PATTERNS.items():
        mp_match = mp_pat.match(mountpoint)
        if mp_match is None:
            continue
        fsid, region = map(mp_match.group, ['fsid', 'region'])
        fstype = fs_cat
        if fs_cat == 'cpfs':
            fstype = fsid.split('-')[0]
        elif fs_cat == 'extreme':
            fsid = 'extreme-' + fsid
        elif fs_cat == 'oss-acc':
            fstype = 'oss'
            if region.startswith('cn-'):
                region_parts = region.split('-')
                if len(region_parts) > 2:
                    region = '-'.join(region_parts[:-1])
            else:
                while region and (region[-1] < '0' or region[-1] > '9'):
                    region = region[:-1]
        return fsid, fstype, region
    return None, None, None


class Command(object):
    EVENT_ADD_MOUNT = "ADD_MOUNT"
    EVENT_DEL_MOUNT = "DEL_MOUNT"
    EVENT_PID_CHANGED = "PID_CHANGED"

    def __init__(self, hostaddr, name, content):
        self._hostaddr = hostaddr
        self._name = name
        self._target = content.get('target', name)
        self._version = content.get('version')
        self._task = content.get('task', 'echo "missing task"')
        self._interval = content.get('interval', sys.maxsize)
        self._event = content.get('event')
        self._rules = content.get('rules', None)
        self._client_type = content.get('client_type', NAS_AGENT_CLIENT_TYPE_ALL)
        self._precondition = content.get('precondition', None)

    @property
    def name(self):
        return self._name

    @property
    def target(self):
        return self._target

    @property
    def version(self):
        return self._version

    @property
    def is_periodic(self):
        return self.event is None

    @property
    def interval(self):
        return self._interval

    @property
    def event(self):
        return self._event

    @property
    def client_type(self):
        return self._client_type

    @property
    def is_independent(self):
        return (not NAS_AGENT_OPID_PATTERN.search(self._task) and
                not NAS_AGENT_PID_PATTERN.search(self._task) and
                not NAS_AGENT_UUID_PATTERN.search(self._task) and
                not NAS_AGENT_CONNID_PATTERN.search(self._task) and
                not NAS_AGENT_PATH_PATTERN.search(self._task) and
                not NAS_AGENT_MOUNTPOINT_PATTERN.search(self._task))
    
    def match_client_type(self, client_type):
        if self.client_type == NAS_AGENT_CLIENT_TYPE_ALL:
            return True
        if self.client_type == NAS_AGENT_CLIENT_TYPE_NFS:
            return client_type in [NAS_AGENT_CLIENT_TYPE_NFS_V3, NAS_AGENT_CLIENT_TYPE_NFS_V4]
        return self.client_type == client_type

    def tasks(self, mount_entities, args=None):
        if self.is_independent:
            regions = set(e.region for e in mount_entities)
            return [("", "", regions, self._precondition, self._task)]
        elif self.is_periodic:
            tasks = []
            for client_type, pid, uuid, connid, fsid, _, region, _, entries in mount_entities:
                if not self.match_client_type(client_type):
                    continue
                task = self._task
                task = re.sub(NAS_AGENT_PID_PATTERN, str(pid), task)
                task = re.sub(NAS_AGENT_UUID_PATTERN, uuid, task)
                task = re.sub(NAS_AGENT_CONNID_PATTERN, str(connid), task)
                # choose first mountpoint for efc bindmount or same nfs device
                mountpoint = entries[0][1]
                task = re.sub(NAS_AGENT_MOUNTPOINT_PATTERN, mountpoint, task)
                precondition = self._precondition
                if precondition:
                    precondition = re.sub(NAS_AGENT_UUID_PATTERN, uuid, precondition)
                tasks.append((uuid, fsid, [region], precondition, task))
            return tasks
        elif self.event == self.EVENT_ADD_MOUNT or self.event == self.EVENT_DEL_MOUNT:
            path, mountpoint, (client_type, pid, uuid, connid, fsid, _, region, *_) = args
            if not self.match_client_type(client_type):
                return tasks
            task = self._task
            task = re.sub(NAS_AGENT_PID_PATTERN, str(pid), task)
            task = re.sub(NAS_AGENT_UUID_PATTERN, uuid, task)
            task = re.sub(NAS_AGENT_CONNID_PATTERN, str(connid), task)
            task = re.sub(NAS_AGENT_PATH_PATTERN, path, task)
            task = re.sub(NAS_AGENT_MOUNTPOINT_PATTERN, mountpoint, task)
            precondition = self._precondition
            if precondition:
                precondition = re.sub(NAS_AGENT_UUID_PATTERN, uuid, precondition)
            return [(uuid, fsid, [region], precondition, task)]
        else:
            opid, (client_type, pid, uuid, connid, fsid, _, region, *_) = args
            if not self.match_client_type(client_type):
                return tasks
            task = self._task
            task = re.sub(NAS_AGENT_OPID_PATTERN, str(opid), task)
            task = re.sub(NAS_AGENT_PID_PATTERN, str(pid), task)
            task = re.sub(NAS_AGENT_UUID_PATTERN, uuid, task)
            task = re.sub(NAS_AGENT_CONNID_PATTERN, str(connid), task)
            precondition = self._precondition
            if precondition:
                precondition = re.sub(NAS_AGENT_UUID_PATTERN, uuid, precondition)
            return [(uuid, fsid, [region], precondition, task)]

    def _match_rules(self, last_result, result):
        exe_time, output = result
        if not output:
            return None

        rows = output.split('\n')
        units = [[row, *row.split()] for row in rows]

        fields = {}
        for rule in self._rules:
            name, index, rtype = rule.get('name'), rule.get('index'), rule.get('type')
            if not name or index is None or not rtype:
                logging.error('Cannot parse rule %s in command %s', str(rule), self.name)
                return None
            if index < 0 or index >= len(units[0]):
                logging.error('Index %d is illegal for output "%s"', index, output)
                return None

            if rtype == 'compute':
                if last_result is None:
                    return None
                last_exe_time, last_output = last_result
                last_rows = last_output.split('\n')
                last_units = [[last_row, *last_row.split()] for last_row in last_rows]
                if len(last_units) != len(units) or len(last_units[0]) != len(units[0]):
                    logging.error('Can not compute "%s" with "%s"', last_output, output)
                    return None
                num = (float(units[0][index]) - float(last_units[0][index]))
                den = 0
                if len(units) == 1:
                    den = (exe_time - last_exe_time).total_seconds()
                elif len(units) == 2:
                    den = float(units[1][index]) - float(last_units[1][index])
                if num < 0 or den <= 0:
                    continue
                else:
                    fields[name] = num / den
            elif rtype == 'raw':
                fields[name] = units[0][index]
            elif rtype == 'json':
                try:
                    state = json.loads(units[0][index])
                except ValueError:
                    logging.error('Unable to parse json from result of task %s "%s"', self.name, self._task)
                    return None
                fields.update(state)
            else:
                logging.error('Unknown rule type %s in task %s', rtype, self.name)
        return fields

    def parse(self, uuid, fsid, last_result, result):
        exe_time, output = result
        record = {
            'type': self.target,
            'hostaddr': self._hostaddr,
            'microtime': exe_time.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'version': self.version,
        }
        if uuid:
            record.update({'mountuuid': uuid, 'fsid': fsid})

        if self._rules is None:
            record.update({self.target: output})
        else:
            fields = self._match_rules(last_result, result)
            if fields is None or len(fields) == 0:
                return None
            record.update(fields)

        return record


class CommandTask(object):
    def __init__(self, epoch, env_monitor, command_name, command_args):
        self._epoch = epoch
        self._env_monitor = env_monitor
        self._command_name = command_name
        self._command_args = command_args

    @property
    def epoch(self):
        return self._epoch

    @property
    def command_name(self):
        return self._command_name

    def _execute(self, command_content, ignore_error=False):
        logging.debug('Run command %s at %s', self.command_name, time.time())
        exe_time, rc, stdout, _ = execute_with_timeout(command_content, 2, ignore_error)
        if rc != 0:
            return rc, None, None
        else:
            return rc, exe_time, stdout.strip()

    def run(self):
        try:
            command = self._env_monitor.get_command(self.epoch, self.command_name)
            if command is None:
                logging.info('Command %s with epoch %d is expired, skipped')
                return {}
            mount_entities = self._env_monitor.get_mount_entities()
            if command.is_periodic:
                tasks = command.tasks(mount_entities)
            else:
                tasks = command.tasks(mount_entities, self._command_args)
            results = {}
            for uuid, fsid, regions, precondition, task in tasks:
                if precondition:
                    rc, exe_time, output = self._execute(precondition, ignore_error=True)
                    if rc != 0:
                        continue
                rc, exe_time, output = self._execute(task)
                if not output:
                    continue
                if self._command_args is None or not command.is_periodic:
                    last_result = None
                else:
                    last_result = self._command_args.get(uuid)
                record = command.parse(uuid, fsid, last_result, (exe_time, output))
                if record is not None:
                    if not regions and self._env_monitor.default_region:
                        regions.add(self._env_monitor.default_region)
                    for region in regions:
                        NAS_AGENT_LOGGER.submit(region, record)
                results[uuid] = exe_time, output
            return results
        except Exception as e:
            logging.error('Run command %s failed: %s', self.command_name, str(e))
            return {}

    def done(self, results):
        try:
            command = self._env_monitor.get_command(self.epoch, self.command_name)
            if command is not None and command.is_periodic:
                task = CommandTask(self.epoch, self._env_monitor, self.command_name, results)
                self._env_monitor.push_task(command.interval, task)
        except Exception as e:
            logging.error('Fail to run callback for %s, error %s', self.command_name, str(e))


class NasAgentConfigTask(object):
    def __init__(self, config, env_monitor):
        self._fsid = None
        self._region = None
        self._config = config
        self._env_monitor = env_monitor

    @property
    def command_name(self):
        return '__check_nas_agent_config__'

    def _server_name(self, region):
        if region == 'cn-shanghai-finance':
            return 'cn-shanghai-finance-1'
        if region == 'cn-beijing-finance':
            return 'cn-beijing-finance-1'
        if region == 'cn-shenzhen-finance-1':
            return 'cn-shenzhen-finance'
        if region == 'cn-wulanchabu-oxs':
            return 'cn-wulanchabu'
        return region

    def _get_possible_mounts_from_last_mountpoint(self):
        mounts = []
        try:
            with open(LAST_MOUNTPOINT_FILE_PATH) as f:
                mountpoint = f.read()
                fsid, fstype, region = parse_mountpoint(mountpoint)
                if fsid is not None:
                    mounts.append((fsid, fstype, region))
        except Exception as e:
            if e.errno != errno.ENOENT:
                logging.error('Failed to read last mountpoint, error %s', str(e))
        return mounts

    def _get_possible_mounts_from_mountints_env(self):
        mounts = []
        try:
            if not os.environ.get(MOUNTPOINTS_ENV):
                return mounts
            j = json.loads(os.environ[MOUNTPOINTS_ENV])
            for mp in j["mountPoints"]:
                fsid, fstype, region = parse_mountpoint(mp["mountPointID"].strip())
                if fsid is not None:
                    mounts.append((fsid, fstype, region))
        except Exception as e:
            logging.error('Failed to _get_region_and_fsid from env, %s' % str(e))
        return mounts

    def _get_possible_mounts(self):
        mounts = []
        mounts.extend(self._get_possible_mounts_from_last_mountpoint())
        mounts.extend(self._get_possible_mounts_from_mountints_env())
        return mounts

    def _config_server(self, server_name):
        return 'http://logtail.%s-intranet.log.aliyuncs.com' % server_name

    def _endpoint(self, server_name):
        return '%s-intranet.log.aliyuncs.com' % server_name

    def _check_network(self, endpoint):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((endpoint, 80))
            return True
        except Exception as e:
            return False
        finally:
            sock.close()

    def _nas_agent_config(self, server_name):
        return {
            'config_server_address': self._config_server(server_name),
            'data_server_list': [{
                'cluster': server_name,
                'endpoint': self._endpoint(server_name),
            }],
            "cpu_usage_limit": 0.4,
            "mem_usage_limit": 384,
            "max_bytes_per_sec": 20971520,
            "bytes_per_sec": 1048576,
            "buffer_file_num": 25,
            "buffer_file_size": 20971520,
            "buffer_map_num": 5,
            "streamlog_open": False,
            "streamlog_pool_size_in_mb": 50,
            "streamlog_rcv_size_each_call": 1024,
            "streamlog_formats": [],
            "streamlog_tcp_port": 11111,
        }

    def _region_in_config(self):
        try:
            with open(NAS_AGENT_CONF_PATH) as f:
                conf = json.load(f)
                addr = conf['config_server_address']
                return re.findall(r'http://logtail\.(.*)-intranet\.log\.aliyuncs\.com', addr)[0]
        except Exception as e:
            logging.error('Fail to read nas agent config, error %s', str(e))
        return None

    def run(self):
        if os.path.exists(NAS_AGENT_CONF_PATH):
            self._region = self._region_in_config()
            return

        mount_entities = self._env_monitor.get_mount_entities()
        mounts = [(e.fsid, e.fstype, e.region) for e in mount_entities]
        if not mounts:
            # there is no mount currently, get region and fsid from file and env
            mounts.extend(self._get_possible_mounts())
        for fsid, fstype, region in mounts:
            server = self._server_name(region)
            endpoint = self._endpoint(server)
            if self._check_network(endpoint):
                try:
                    temppath = '%s.temp' % NAS_AGENT_CONF_PATH
                    if os.path.exists(temppath):
                        os.truncate(temppath, 0)
                    with open(temppath, 'w') as f:
                        json.dump(self._nas_agent_config(server), f)
                    os.rename(temppath, NAS_AGENT_CONF_PATH)
                    self._fsid = fsid
                    self._region = region
                    return
                except Exception as e:
                    logging.error('Fail to write nas agent config, error %s', str(e))

    def done(self, result):
        try:
            if self._region:
                self._env_monitor.update_temporary_mount(self._fsid, self._region)
                return

            task = NasAgentConfigTask(self._config, self._env_monitor)
            interval = self._config.getint(NAS_AGENT_CONFIG_SECTION, 'detect_nas_agent_endpoint_interval', default=5, minvalue=5, maxvalue=30)
            self._env_monitor.push_task(interval, task)
        except Exception as e:
            logging.error('Fail to run callback for %s, error %s', self.command_name, str(e))


class UpdateCommandsTask(object):
    def __init__(self, config, env_monitor, repo):
        self._env_monitor = env_monitor
        self._config = config
        self._repo = repo

    @property
    def command_name(self):
        return '__update_commands__'

    @property
    def repo(self):
        return self._repo

    def _check_repo(self):
        if self._repo is None:
            if not os.path.exists(NAS_AGENT_CONF_PATH):
                return False
            with open(NAS_AGENT_CONF_PATH) as f:
                conf = json.load(f)
                addr = conf['config_server_address']
                region = re.findall(r'http://logtail\.(.*)-intranet\.log\.aliyuncs\.com', addr)[0]
                self._repo = NAS_AGENT_REMOTE_REPO_PATTERN % (region, region)
        return self._repo is not None

    def run(self):
        try:
            # invalidate remote commands now
            self._env_monitor.update_commands([])
            return

            remote_files = []
            if self._check_repo():
                keys = [self._env_monitor.hostname, *(e.fsid for e in self._env_monitor.get_mount_entities())]
                all_keys = [get_version(), *(hashlib.md5(key.encode('utf-8')).hexdigest() for key in keys)]
                for key in all_keys:
                    name = NAS_AGENT_REMOTE_COMMANDS_PATTERN % key
                    url = '%s/%s' % (self.repo, name)
                    os.makedirs(NAS_AGENT_REMOTE_COMMANDS_DIR, exist_ok=True)
                    destpath = os.path.join(NAS_AGENT_REMOTE_COMMANDS_DIR, name)
                    if download_file(url, destpath, timeout=2):
                        remote_files.append(destpath)
                        logging.info('Downloaded remote config %s', name)
                    elif os.path.exists(destpath):
                        os.remove(destpath)
                        logging.info('Remove remove config %s', name)

            self._env_monitor.update_commands(remote_files)
        except Exception as e:
            logging.error('Failed to update commands, error: %s', str(e))

    def done(self, result):
        try:
            task = UpdateCommandsTask(self._config, self._env_monitor, self.repo)
            interval = self._config.getint(NAS_AGENT_CONFIG_SECTION, 'update_commands_interval', default=5, minvalue=5, maxvalue=300)
            self._env_monitor.push_task(interval, task)
        except Exception as e:
            logging.error('Fail to run callback for %s, error %s', self.command_name, str(e))


class UpdateMountEntitiesTask(object):
    FuseRequest = namedtuple('FuseRequest', ['unique', 'opcode', 'nodeid', 'pid', 'flags', 'sent_time'])

    DEBUG_REQ_PATTERN = re.compile(
        r'^unique:(?P<unique>[0-9]+) '
        r'opcode:(?P<opcode>[0-9]+) '
        r'nodeid:(?P<nodeid>[0-9]+) '
        r'pid:(?P<pid>[0-9]+) '
        r'flags:(?P<flags>[0-9]+) '
        r'sent_time:(?P<sent_time>[0-9]+)'
    )

    STATE_NORMAL = 'NORMAL'
    STATE_IOHANG = 'HANG'
    STATE_UNKNOWN = 'UNKNOWN'

    def __init__(self, config, env_monitor, total_requests):
        self._config = config
        self._io_hang_timeout_us = config.getint(NAS_AGENT_CONFIG_SECTION, 'io_hang_timeout_us',
                                                 default=180000000, minvalue=60000000, maxvalue=300000000)
        self._io_hang_timeout_req_count = config.getint(
            NAS_AGENT_CONFIG_SECTION, 'io_hang_timeout_req_count', default=4, minvalue=1, maxvalue=10)
        self._debug_max_req_count = config.getint(
            NAS_AGENT_CONFIG_SECTION, 'debug_max_req_count', default=64, minvalue=32, maxvalue=128)

        self._env_monitor = env_monitor
        self._total_requests = {} if total_requests is None else total_requests

    @property
    def command_name(self):
        return '__update_mount_entities__'

    @property
    def total_requests(self):
        return self._total_requests

    def _get_fuse_requests(self, connid):
        conn = str(connid)
        if os.path.exists(os.path.join('/sys/fs/alifuse/connections', conn)):
            conndir = os.path.join('/sys/fs/alifuse/connections', conn)
        elif os.path.exists(os.path.join('/sys/fs/fuse/connections', conn)):
            conndir = os.path.join('/sys/fs/fuse/connections', conn)
        else:
            return None
        fuse_requests = {}
        try:
            with open(os.path.join(conndir, 'waiting_debug')) as f:
                for line in f.readlines()[:-1]:
                    if len(fuse_requests) >= self._debug_max_req_count:
                        break
                    match = self.DEBUG_REQ_PATTERN.match(line)
                    if match is None:
                        continue
                    unique, opcode, nodeid, pid, flags, sent_time = map(int, map(match.group, ['unique', 'opcode', 'nodeid', 'pid', 'flags', 'sent_time']))
                    fuse_requests[unique] = self.FuseRequest._make([unique, opcode, nodeid, pid, flags, int(sent_time)])
        except Exception as e:
            logging.error('Failed to read waiting_debug file %s, error %s', os.path.join(conndir, 'waiting_debug'), str(e))
            return None
        return fuse_requests

    def _check_efc_state(self, fsid, mountuuid, connid, last_requests):
        fuse_requests = self._get_fuse_requests(connid)
        if fuse_requests is None:
            return self.STATE_UNKNOWN, {}

        for unique in fuse_requests.keys():
            if unique in last_requests:
                fuse_requests[unique] = last_requests[unique]

        now = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1e6)
        timeout_reqs = [req for req in fuse_requests.values() if req.sent_time + self._io_hang_timeout_us < now]
        if len(timeout_reqs) >= self._io_hang_timeout_req_count:
            waiting_times = [now - req.sent_time for req in fuse_requests.values()]
            min_time, max_time = min(waiting_times), max(waiting_times)
            requests = '; '.join(('unique:%s opcode:%s nodeid:%s pid:%s flags:%s sent_time:%d waiting_time:%d' % (*req, now - req.sent_time)) for req in fuse_requests.values())
            logging.error(
                'Found io hang, fsid %s, mountuuid %s, total count %d, min time %d, max time %d, timeout requests [%s]',
                fsid,
                mountuuid,
                len(timeout_reqs),
                min_time,
                max_time,
                requests
            )
            return self.STATE_IOHANG, fuse_requests
        return self.STATE_NORMAL, fuse_requests

    def _parse_mount(self, mount):
        match = NAS_AGENT_MOUNT_PATTERN.match(mount.server)
        if match is None:
            return None
        mount_uuid, mountpoint, path = map(match.group, ['mount_uuid', 'mountpoint', 'path'])
        fsid, fstype, region = parse_mountpoint(mountpoint)
        if fsid is None:
            return None
        return mount_uuid, fsid, fstype, region, path

    def run(self):
        mount_entities = {}
        mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        for mount in mounts:
            res = self._parse_mount(mount)
            if res is None:
                logging.warning('Fail to match server %s', mount.server)
                continue
            mount_uuid, fsid, fstype, region, path = res
            # same bindroot entries are grouped
            if mount_uuid in mount_entities:
                mount_entities[mount_uuid].entries.append((path, mount.mountpoint))
                continue
            pid = get_process_pid('mount_uuid=%s' % mount_uuid)
            if pid == 0:
                logging.warning('Fail to get pid for %s', mount_uuid)
                pid = -1
                # use pid as -1 below, for sometimes the efc process is not running
            conn_id = get_connection_id(mount_uuid)
            if conn_id == 0:
                logging.error('Fail to get connection id for %s', mount_uuid)
            last_requests = self._total_requests.get(mount_uuid, {})
            state, curr_requests = self._check_efc_state(fsid, mount_uuid, conn_id, last_requests)
            self._total_requests[mount_uuid] = curr_requests
            mount_entities[mount_uuid] = MountEntity._make([NAS_AGENT_CLIENT_TYPE_EFC, pid, mount_uuid, conn_id, fsid, fstype, region, state, [(path, mount.mountpoint)]])

        mounts = get_current_nfs_mounts()
        for mount in mounts:
            res = self._parse_mount(mount)
            if res is None:
                logging.warning('Fail to match server %s', mount.server)
                continue
            _, fsid, fstype, region, path = res
            conn_id = get_connection_id(None, mount.mountpoint)
            client_type = NAS_AGENT_CLIENT_TYPE_NFS_V4 if 'nfs4' in mount.type else NAS_AGENT_CLIENT_TYPE_NFS_V3
            mount_uuid = '%s-%s' % (client_type, conn_id)
            # same device entries are grouped
            if mount_uuid in mount_entities:
                mount_entities[mount_uuid].entries.append((path, mount.mountpoint))
            else:
                mount_entities[mount_uuid] = MountEntity._make([client_type, None, mount_uuid, conn_id, fsid, fstype, region, self.STATE_NORMAL, [(path, mount.mountpoint)]])

        for entity in mount_entities.values():
            entity.entries.sort()

        self._env_monitor.update_mount_entities(list(mount_entities.values()))

    def done(self, results):
        try:
            task = UpdateMountEntitiesTask(self._config, self._env_monitor, self.total_requests)
            interval = self._config.getint(NAS_AGENT_CONFIG_SECTION, 'update_mount_entities_interval', default=5, minvalue=5, maxvalue=300)
            self._env_monitor.push_task(interval, task)
        except Exception as e:
            logging.error('Fail to run callback for %s, error %s', self.command_name, str(e))


class EnvMonitor(object):
    def __init__(self, config):
        self._config = config
        self._lock = threading.Lock()
        self._commands = {}
        self._using_remote = False
        self._mount_entities = []
        self._hostname = socket.gethostname()
        self._hostaddr = socket.gethostbyname(self._hostname)

        self._upload_mount_info_interval = config.getint(
            NAS_AGENT_CONFIG_SECTION, 'upload_mount_info_interval', default=10, minvalue=5, maxvalue=300)
        self._upload_mount_info_time = None

        self._default_region = None

        self._executor = None
        self._worker = threading.Thread(target=self._run)
        self._running= False

        self._event_waiter = EventWaiter()

    @property
    def hostname(self):
        return self._hostname

    @property
    def default_region(self):
        return self._default_region

    @staticmethod
    def parse_command_file(command_file):
        try:
            with open(command_file) as f:
                conf = json.load(f)
                return conf
        except (ValueError, IOError) as e:
            logging.error('Load conf %s failed, error %s', command_file, str(e))
        return None

    def get_command(self, epoch, name):
        self._lock.acquire()
        try:
            curr, command = self._commands.get(name, (-1, None))
            if epoch != curr:
                return None
            return command
        finally:
            self._lock.release()

    def _trigger(self, event, *args):
        self._lock.acquire()
        try:
            commands = self._commands
        finally:
            self._lock.release()

        for _, (epoch, command) in commands.items():
            if not command.is_periodic and command.event == event:
                task = CommandTask(epoch, self, command.name, args)
                self.push_task(0, task)

    def update_temporary_mount(self, fsid, region):
        self._default_region = region
        if fsid and not self._mount_entities:
            self._update_user_defined_ids([fsid])

    def update_commands(self, remote_files):
        remote_confs = []
        for command_file in remote_files:
            conf = self.parse_command_file(command_file)
            if conf is not None:
                remote_confs.append(conf)

        old_commands = {}
        self._lock.acquire()
        try:
            old_commands = self._commands
        finally:
            self._lock.release()

        should_update = not old_commands or remote_confs or (self._using_remote and not remote_confs)

        if not should_update:
            return

        self._using_remote = bool(remote_confs)

        local_conf = self.parse_command_file(NAS_AGENT_LOCAL_COMMANDS_PATH)
        command_contents = merge_command_contents(local_conf, *remote_confs)
        commands = {}
        for name, content in command_contents.items():
            commands[name] = Command(self._hostaddr, name, content)

        changed_commands = []
        merged_commands = {}
        for name, (epoch, old_command) in old_commands.items():
            if name in commands:
                command = commands.get(name)
                if old_command.version == command.version:
                    merged_commands[name] = (epoch, old_command)
                else:
                    merged_commands[name] = (epoch + 1, command)
                    changed_commands.append(name)
        for name, command in commands.items():
            if name not in merged_commands:
                merged_commands[name] = (0, command)
                changed_commands.append(name)

        self._lock.acquire()
        try:
            self._commands = merged_commands
        finally:
            self._lock.release()

        self._start_periodic_commands(changed_commands)

    def _is_generated_by_env_monitor(self, udid):
        if not '-' in udid:
            return False
        *segments, _ = udid.split('-')
        fsid = '-'.join(segments)
        _, rc, stdout, _ = execute_with_timeout('%s %s' % (NAS_AGENT_ID_GEN_BIN_PATH, fsid), 1)
        if stdout is None:
            logging.error('Fail to check user defined id %s' % udid)
            return False
        if rc == 0 and stdout:
            return udid == stdout
        return False

    def _update_user_defined_ids(self, fsids):
        ids = set()
        for fsid in fsids:
            _, rc, stdout, _ = execute_with_timeout('%s %s' % (NAS_AGENT_ID_GEN_BIN_PATH, fsid), 1)
            if stdout is None:
                logging.error('Fail to generator id for %s' % fsid)
                continue
            if rc == 0 and stdout:
                ids.add(stdout.strip())
        try:
            if os.path.exists(NAS_AGENT_ID_FILE_PATH):
                with open(NAS_AGENT_ID_FILE_PATH) as fp:
                    for line in fp:
                        line = line.strip()
                        if self._is_generated_by_env_monitor(line):
                            continue
                        ids.add(line)
                os.truncate(NAS_AGENT_ID_FILE_PATH, 0)
            with open(NAS_AGENT_ID_FILE_PATH, 'w') as f:
                for id in ids:
                    f.write('%s\n' % id)
        except IOError as e:
            logging.error('Fail to update nas agent ids, error: %s', str(e))

    def update_mount_entities(self, mount_entities):
        if (self._upload_mount_info_time is None or
                (datetime.now() - self._upload_mount_info_time).total_seconds() > self._upload_mount_info_interval or
                any(e.state != UpdateMountEntitiesTask.STATE_NORMAL for e in mount_entities)):
            epoch = int(time.time() * 1000)
            now = datetime.now()
            for client_type, pid, uuid, connid, fsid, fstype, region, state, entries in mount_entities:
                record = {
                    'type': 'mount_info',
                    'hostaddr': self._hostaddr,
                    'microtime': now.strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'epoch': epoch,
                    'client_type': client_type,
                    'pid': pid,
                    'mountuuid': uuid,
                    'connid': connid,
                    'fsid': fsid,
                    'fstype': fstype,
                    'state': state,
                    'entries': ' '.join(str(e) for e in entries),
                }
                NAS_AGENT_LOGGER.submit(region, record)
            self._upload_mount_info_time = now

        events = []

        old_mount_entities = self.get_mount_entities()
        if old_mount_entities is None:
            old_mounts = {}
        else:
            old_mounts =  {e.mountuuid: e for e in old_mount_entities}

        mounts = {e.mountuuid: e for e in mount_entities}

        for mountuuid, mount in mounts.items():
            if mountuuid in old_mounts:
                old_pid = old_mounts[mountuuid].pid
                if mount.pid != old_pid:
                    events.append((Command.EVENT_PID_CHANGED, old_pid, mount))
                old_entries = old_mounts[mountuuid].entries
                entries = mounts[mountuuid].entries
                for path, mountpoint in [e for e in entries if e not in old_entries]:
                    events.append((Command.EVENT_ADD_MOUNT, path, mountpoint, mount))
                for path, mountpoint in [e for e in old_entries if e not in entries]:
                    events.append((Command.EVENT_DEL_MOUNT, path, mountpoint, mount))
            else:
                for path, mountpoint in mount.entries:
                    events.append((Command.EVENT_ADD_MOUNT, path, mountpoint, mount))

        for old_mount in old_mount_entities:
            if old_mount.mountuuid not in mounts:
                for path, mountpoint in old_mount.entries:
                    events.append((Command.EVENT_DEL_MOUNT, path, mountpoint, old_mount))

        if not events:
            return

        self._lock.acquire()
        try:
            self._mount_entities = mount_entities
        finally:
            self._lock.release()

        for event in events:
            self._trigger(*event)

        fsids = []
        for mount in mount_entities:
            if mount.fstype == 'oss':
                fsids.append(mount.fsid)
            else:
                fsids.append(mount.fsid.split('-')[-1])

        self._update_user_defined_ids(fsids)

    def get_mount_entities(self):
        self._lock.acquire()
        try:
            return self._mount_entities
        finally:
            self._lock.release()

    def _start_periodic_commands(self, names):
        self._lock.acquire()
        try:
            for name in names:
                epoch, command = self._commands.get(name, (-1, None))
                if command is not None and command.is_periodic:
                    task = CommandTask(epoch, self, command.name, None)
                    self.push_task(0, task)
        finally:
            self._lock.release()

    def _start_update_mount_entities_task(self):
        if self._config.getboolean(WATCHDOG_CONFIG_SECTION, 'update_mount_entities_task', default=True):
            blocked_task = UpdateMountEntitiesTask(self._config, self, None)
            res = blocked_task.run()
            blocked_task.done(res)

    def _start_nas_agent_config_task(self):
        if self._config.getboolean(WATCHDOG_CONFIG_SECTION, 'nas_agent_config_task', default=True):
            blocked_task = NasAgentConfigTask(self._config, self)
            res = blocked_task.run()
            blocked_task.done(res)

    def _start_update_commands_task(self):
        if self._config.getboolean(WATCHDOG_CONFIG_SECTION, 'update_commands_task', default=True):
            blocked_task = UpdateCommandsTask(self._config, self, None)
            res = blocked_task.run()
            blocked_task.done(res)

    def _run(self):
        logging.info('EnvMonitor is started')

        self._start_update_mount_entities_task()
        self._start_nas_agent_config_task()
        self._start_update_commands_task()

        while self._running:
            try:
                tasks = self._event_waiter.wait()
                self._run_tasks(tasks)
            except Exception as e:
                self._event_waiter.clear()
                logging.error('EnvMonitor run tasks failed, cannot recover without loss: {0}'.format(str(e)))

    def _run_tasks(self, tasks):
        try:
            for _, task, cb in tasks:
                self._executor.apply_async(cb, callback=task.done)
        except Exception as e:
            logging.error('Failed to run tasks, error: %s', str(e))

    def push_task(self, timeout, task):
        self._event_waiter.add_timer(timeout, task, task.run)

    def start(self):
        try:
            os.makedirs(NAS_AGENT_USER_DIR, exist_ok=True)
            user = self._config.get(NAS_AGENT_CONFIG_SECTION, 'nas_agent_user', default='1241392231042436')
            mode = stat.S_IFREG | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IWUSR
            os.mknod(os.path.join(NAS_AGENT_USER_DIR, user), mode)
        except OSError as e:
            if e.errno != errno.EEXIST:
                logging.error('Failed to create user file, error %s', str(e))
                return

        self._running = True
        self._executor = Pool(4)
        self._worker.start()

    def stop(self):
        if not self._running:
            return

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
                logging.error('Fail to stop env monitor pool')
            finally:
                executor.join()


class MountWatchdog(object):
    def __init__(self, config, state_file_dir=STATE_FILE_DIR):
        self._config = config
        self._state_file_dir = state_file_dir
        self._child_procs = []
        self._detector = LiveDetector(self._config, self, state_file_dir)
        self._file_manager = StateFileManager()

    @property
    def child_procs(self):
        return self._child_procs

    def start(self):
        self._detector.start()

    def stop(self):
        self._detector.stop()

    def handle_events(self, localmounts):
        self._detector.refresh(localmounts)

    def load_state_file(self, state_file_dir, state_file):
        return self._file_manager.load_state_file(state_file_dir, state_file)

def create_workspace():
    try:
        if os.path.isdir(OLD_EFC_WORKSPACE_DIR):
            if os.path.islink(EFC_WORKSPACE_DIR):
                if os.readlink(EFC_WORKSPACE_DIR) != './eac':
                    os.unlink(EFC_WORKSPACE_DIR)
                    os.symlink('./eac', EFC_WORKSPACE_DIR)
                else:
                    pass
            else:
                os.symlink('./eac', EFC_WORKSPACE_DIR)
        else:
            os.makedirs(EFC_WORKSPACE_DIR, exist_ok=True)
    except Exception as e:
        if e.errno != errno.EEXIST and e.errno != errno.ENOENT:
            fatal_error('Fail to create workspace, exception msg:%s' % str(e))

def adjust_memory_limit():
    global CGROUP_BASE_MEMORY_LIMIT_SIZE
    memory_limit = int(os.popen("free -m | grep Mem | awk '{print $2}'").read().strip()) * CGROUP_MEMORY_LIMIT_RATIO * 1024 * 1024 / 100
    if CGROUP_BASE_MEMORY_LIMIT_SIZE < memory_limit:
        CGROUP_BASE_MEMORY_LIMIT_SIZE = memory_limit

def update_loop_time():
    global MAIN_LOOP_TIME
    MAIN_LOOP_TIME = time.time()

def check_loop_time():
    global MAIN_LOOP_TIME
    while True:
        now = time.time()
        if MAIN_LOOP_TIME > 0 and now > MAIN_LOOP_TIME + MAIN_LOOP_HANG_ABORT_THRES:
            logging.error(f'main loop has been hang from {MAIN_LOOP_TIME}, abort')
            os._exit(1)
        time.sleep(60)

def start_main_loop_checker():
    main_loop_check_thread = threading.Thread(target=check_loop_time)
    main_loop_check_thread.daemon = True
    main_loop_check_thread.start()
    logging.info("main loop checker start")

def main():
    parse_arguments()
    check_env()

    config = read_config()
    bootstrap_logging(config)

    poll_interval_sec = config.getint(WATCHDOG_CONFIG_SECTION, 'poll_interval_sec', default=3, minvalue=1, maxvalue=60)
    unmount_grace_period_sec = config.getint(WATCHDOG_CONFIG_SECTION, 'unmount_grace_period_sec',
                                             default=30, minvalue=10, maxvalue=600)

    adjust_memory_limit()

    create_workspace()

    watchdog = None
    env_monitor = None

    # all subprocess will ignore SIGTERM, if you do not like this, see start_proxy()
    signal.signal(SIGTERM, signal.SIG_IGN)

    try:
        start_main_loop_checker()

        if check_mount(config):
            watchdog = MountWatchdog(config)
            watchdog.start()

        if check_mount(config) or check_nas_agent(config):
            env_monitor = EnvMonitor(config)
            env_monitor.start()

        while True:
            update_loop_time()
            if check_nas_agent(config):
                check_nas_agent_state()
            if check_pexporter(config):
                check_pexporter_state()
            if check_sessmgr(config, watchdog):
                check_unas_sessmgr()
            if check_mount(config):
                local_mounts = check_nfs_mounts(config, watchdog, unmount_grace_period_sec)
                local_mounts.update(check_unas_mounts(watchdog))
                watchdog.handle_events(local_mounts)
                check_child_procs(watchdog.child_procs)
            if discover_dadi(config):
                schedule_discover_dadi()

            time.sleep(poll_interval_sec)
    finally:
        if watchdog:
            watchdog.stop()
        if env_monitor:
            env_monitor.stop()
        stop_nas_agent()


if '__main__' == __name__:
    main()

