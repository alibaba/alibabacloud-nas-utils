#!/usr/bin/env python3
#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
#
# Copy this script to /sbin/mount.alinas and make sure it is executable.
#
# You will be able to mount an alinas file system by its short name, by adding it
# to /etc/fstab. The syntax of an fstab entry is:
#
# [Device] [Mount Point] [File System Type] [Options] [Dump] [Pass]
#
# Add an entry like this:
#
#   0123456789-abcde.cn-qingdao.nas.aliyuncs.com     /mount_point    alinas     _netdev         0   0
#
# Using the 'alinas' type will cause '/sbin/mount.alinas' to be called by 'mount -a'
# for this file system. The '_netdev' option tells the init system that the
# 'alinas' type is a networked file system type. This has been tested with systemd
# (aliyun Linux 17.1, CentOS 7, RHEL 7, Debian 9, and Ubuntu 16.04)
#
# Once there is an entry in fstab, the file system can be mounted with:
#
#   sudo mount /mount_point
#
# The script will add recommended mount options, if not provided in fstab.

import base64
import fcntl
import hashlib
import hmac
import itertools
import json
import logging
import os
import errno
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import hashlib
import struct
from uuid import uuid4
import shutil
import platform
import math

from collections import namedtuple
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from logging import StreamHandler
from threading import Timer


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

from datetime import datetime, timedelta

VERSION = 'unknown'
SERVICE = 'aliyun-alinas'
RPM_NAME = 'alinas-utils'
PROXY_DEFAULT_PORT = 12049

CONFIG_FILE = '/etc/aliyun/alinas/alinas-utils.conf'
CONFIG_SECTION = 'mount'
CLIENT_INFO_SECTION = "client-info"
CLIENT_SOURCE_STR_LEN_LIMIT = 100
DEFAULT_UNKNOWN_VALUE = "unknown"
# 50ms
DEFAULT_TIMEOUT = 0.05

LAST_MOUNTPOINT_FILE_PATH = '/etc/aliyun/alinas/last-mountpoint'

LOG_DIR = '/var/log/aliyun/alinas'
LOG_FILE = 'mount.log'

STATE_FILE_DIR = '/var/run/alinas'
EFC_WORKSPACE_DIR = '/var/run/efc'
OLD_EFC_WORKSPACE_DIR = '/var/run/eac'
STATE_SIGN = 'sign'
ALINAS_LOCK = 'alinas.lock'
DNS_LOCK = 'dns.lock'
SESSMGR_SOCKET_PATH = os.path.join(EFC_WORKSPACE_DIR, 'sessmgrd.sock')
PROMETHEUS_METRICS_FILE_DIR = EFC_WORKSPACE_DIR
PRIVATE_KEY_FILE = '/etc/aliyun/alinas/privateKey.pem'

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
policy = alinasPolicy
x509_extensions = v3_ca

[ alinasPolicy ]
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
DATE_ONLY_FORMAT = '%Y%m%d'
SIGV4_DATETIME_FORMAT = '%Y%m%dT%H%M%SZ'
CERT_DATETIME_FORMAT = '%y%m%d%H%M%SZ'

# used in cgroup memory size calculation, get size via gdb, not accurate but enough
UNAS_SHM_PAGE_CAPACITY_FLAG = 'g_unas_LocalDataCacheMemory'
UNAS_SHM_PAGE_CAPACITY_DEFAULT = 12000
UNAS_SHM_PAGE_SIZE = 4160

UNAS_SHM_JOURNAL_CAPACITY_FLAG = 'g_unas_ShmJournalCapacity'
UNAS_SHM_JOURNAL_CAPACITY_DEFAULT = 262144
UNAS_SHM_JOURNAL_SIZE = 1472

UNAS_SHM_VOLUME_CAPACITY_FLAG = 'g_unas_ShmVolumeCapacity'
UNAS_SHM_VOLUME_CAPACITY_DEFAULT = 1
UNAS_SHM_VOLUME_SIZE = 73728

UNAS_SHM_FILE_CAPACITY_FLAG = 'g_unas_ShmFileCapacity'
UNAS_SHM_FILE_CAPACITY_DEFAULT = 0 # 0 for sys-file-max
UNAS_SHM_FILE_SIZE = 64

UNAS_SHM_DADI_CAPACITY_FLAG = 'g_tier_DadiMemCacheCapacityMB'
UNAS_SHM_DADI_CAPACITY_DEFAULT = 0

CGROUP_DIR = '/sys/fs/cgroup/memory/efc'
OLD_CGROUP_DIR = '/sys/fs/cgroup/memory/eac'
CGROUP_LIMIT_FILE = 'memory.limit_in_bytes'
CGROUP_PROCS_FILE = 'cgroup.procs'
CGROUP_SWAP_CONTROL_FILE = 'memory.swappiness'
CGROUP_OOM_CONTROL_FILE = 'memory.oom_control'
CGROUP_BASE_MEMORY_LIMIT_SIZE = 30 * 1024 * 1024 * 1024 # not contain share memory
CGROUP_MEMORY_LIMIT_RATIO = 1 # percent of total memory

# efc configure
UNAS_APP_NAME = 'efc'
UNAS_MOUNT_LOCK = 'unas_mount.lock'
UNAS_MOUNT_LOCK_PREFIX = 'mount-lock-eac-'
ALIFUSE_LOCK = 'alifuse.lock'
ALIFUSE_CTL_LOCK = 'alifusectl.lock'
ALIFUSE_MODULE_NAME = 'alifuse'
ALIFUSE_FILE_NAME = 'efc-alifuse'
ALIFUSE_MODULE_PATH = '/usr/bin/%s.ko' % ALIFUSE_FILE_NAME
ALIFUSE_CTL_MOUNT_PATH = '/sys/fs/alifuse/connections'
FUSE_CTL_MOUNT_PATH = '/sys/fs/fuse/connections'
ALIFUSE_DEV_NAME = '/dev/alifuse'
FUSE_DEV_NAME = '/dev/fuse'
FUSE_DEV_IOC_RECOVER = 3230197193 # ioctl请求标签号
FUSE_DEV_IOC_RECOVER_SIZE = 136 # ioctl请求参数的size
SESSMGR_LOCK = 'sessmgr.lock'
SESSMGR_LOG_CONF_TEMPLATE_PATH = '/etc/aliyun/alinas/log_conf.efc.sessmgr.json'
SESSMGR_BIN_NAME = 'aliyun-alinas-efc-sessmgrd'
SESSMGR_REQUIRED = 'sessmgr_required'
OLD_SESSMGR_BIN_NAME = 'aliyun-alinas-eac-sessmgrd'
SESSMGR_BIN_PATH = '/usr/bin/%s' % SESSMGR_BIN_NAME
EFC_SOCKET_SUFFIX = 'efc.sock'
EAC_SOCKET_SUFFIX = 'eac.sock'
EFC_LOCK_SUFFIX = 'efc.lock'
EFC_MINIMUM_SUPPORTED_KERNEL_VERSIONS_CONFIG = '/etc/aliyun/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json'

VFUSE_UTIL_BIN_NAME = 'aliyun-alinas-efc-vsutils'
VFUSE_UTIL_BIN_PATH = '/usr/bin/%s' % VFUSE_UTIL_BIN_NAME

CMDUTIL_BIN_NAME = 'aliyun-alinas-efc-cmd'
CMDUTIL_BIN_PATH = '/usr/bin/%s' % CMDUTIL_BIN_NAME

NONFUSE_MOUNT_PATH = '/var/run/alinas/nonfuse_mounts'
NONFUSE_MOUNT_LOCK = 'nonfuse_mounts.lock'

UNAS_DEFAULT_ENABLE_BINDMOUNT = True
BIND_ROOT_PREFIX = 'bindroot-'
BIND_ROOT_DIR = STATE_FILE_DIR + '/bindroot'

UNAS_BIN_NAME = 'aliyun-alinas-efc'
UNAS_BIN_PATH = '/usr/bin/%s' % UNAS_BIN_NAME
UNAS_LOG_CONF_TEMPLATE_PATH = '/etc/aliyun/alinas/log_conf.efc.json'
VSC_LOG_CONF_TEMPLATE_PATH = '/etc/aliyun/alinas/log_conf.vsc.json'
UNAS_LOG_DIR = '/var/log/aliyun/alinas'

UNAS_MOUNT_LOCK_TIMEOOUT = 20
UNAS_MOUNT_TIMEOUT = 120
UNAS_MOUNT_POINT_CHECK_TIMEOUT = 10
UNAS_MOUNT_LOCK_FAIL_RECHECK_TIME = 600

NORMAL_UMOUNT = 0
FORCE_UMOUNT = 1
UNAS_UMOUNT_MSG_NUM = 213
UNAS_UMOUNT_BUSY_SLEEP = 0.5
UNAS_UMOUNT_BUSY_MAX_SLEEP = 5
BIND_TAG = 'bindtag'

FS_ID_PATTERN = re.compile('^(?P<fs_id>[-0-9a-z.]+)(?::(?P<path>/.*))?$')
MP_URL_PATTERN = re.compile('^(?P<url>[-0-9a-z.]+)(?::(?P<path>/.*))?$')

DEFAULT_STUNNEL_VERIFY_LEVEL = 2
DEFAULT_STUNNEL_CAFILE = '/etc/aliyun/alinas/alinas-utils.crt'
DEFAULT_STUNNEL_TLS_CIPHERS = 'AES256-GCM-SHA384'
DEFAULT_ALI_TIMEOUT = 180
Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])
UnasState = namedtuple('UnasState', ['mountuuid', 'mountpoint', 'mountpath', 'mountcmd', 'mountkey', BIND_TAG, SESSMGR_REQUIRED])

SHM_SIZE_ALIGNMENT_KB = 1024

ALINAS_ONLY_OPTIONS = [
    'tls',
    'proxy',
    'proxy_port',
    'nas_ip',
    'direct',
    'verify',
    'alitimeo',
    'trybind',
    'upgrade',
    'netcheck',
    'flagcheck',
    'kernel_version_check',
    'no_atomic_move',
    'assign_uuid',
    'no_start_watchdog',
    'overlaybd_mount',
    'no_kernel_permission',
    'auto_fallback_nfs',
    'accesspoint',
    'ram',
    'ram_config_file',
    'tls_ciphers',
    'no_add_cgroup',
    UNAS_APP_NAME,
    BIND_TAG
]

UNSUPPORTED_OPTIONS = [
    'cafile',
    'capath',
]

STUNNEL_GLOBAL_CONFIG = {
    'fips': 'no',
    'foreground': 'yes',
    'socket': [
        'l:SO_REUSEADDR=yes',
        'a:SO_BINDTODEVICE=lo',
    ],
}

STUNNEL_ALINAS_CONFIG = {
    'client': 'yes',
    'accept': '%s:%s',
    'connect': '%s:2049',
    'sslVersion': 'TLSv1.2',
    'renegotiation': 'no',
    'TIMEOUTbusy': '20',
    'TIMEOUTclose': '0',
    'TIMEOUTidle': '70',
    'delay': 'yes'
}


WATCHDOG_BIN_NAME = 'aliyun-alinas-mount-watchdog'
WATCHDOG_BIN_PATH = '/usr/bin/%s' % WATCHDOG_BIN_NAME
WATCHDOG_SERVICE = 'aliyun-alinas-mount-watchdog'
SYSTEM_RELEASE_PATH = '/etc/system-release'
OS_RELEASE_PATH = '/etc/os-release'
RHEL8_RELEASE_NAME = 'Red Hat Enterprise Linux release 8'
CENTOS8_RELEASE_NAME = 'CentOS Linux release 8'
ALICLOUD_LINUX3_RELEASE_NAME = 'Alibaba Cloud Linux release 3 (Soaring Falcon)'
ALICLOUD_LINUX3_LIFSEA_RELEASE_NAME = 'Alibaba Cloud Linux Lifsea (ContainerOS) release 3'
SKIP_NO_LIBWRAP_RELEASES = [RHEL8_RELEASE_NAME, CENTOS8_RELEASE_NAME, ALICLOUD_LINUX3_RELEASE_NAME, ALICLOUD_LINUX3_LIFSEA_RELEASE_NAME]
SKIP_NO_LIBWRAP_RELEASE_IDS = {'alinux' : '3'}

PS_CMD = 'ps -eww -o pid,cmd,args '
#    PID CMD                         COMMAND
#  14190 /usr/bin/aliyun-alinas-efc- /usr/bin/aliyun-alinas-efc-sessmgrd --apsara_log_conf_path=/var/log/aliyun/alinas/log_conf.sessmgr.json
#  24309 /usr/bin/aliyun-alinas-efc  /usr/bin/aliyun-alinas-efc -o server=9ff4d4bbb1-tfj1.cn-zhangjiakou.nas.aliyuncs.com:/ -o mountpoint=/mnt/myc -o rw,protocol=efc,fstype=nas,net=tcp,fd_store=sessmgrd,client_owner=nas-test011122132022.ea134_a9voK4bB_1734320510421840,default_permissions,allow_other --unas_CoreFileSizeLimitSize=-1 -o mount_uuid=a9voK4bB --apsara_log_conf_path=/var/log/aliyun/alinas/efc-a9voK4bB/log_conf.efc.json


MountContext = namedtuple('MountContext', ('config', 'init_system', 'dns', 'fs_id', 'path', 'mountpoint', 'credentials', 'options'))


def fatal_error(user_message, log_message=None, exit_code=1):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    sys.exit(exit_code)


def get_version():
    global VERSION

    if VERSION == 'unknown':
        cmd = ''
        system_id, _ = get_system_release_id()
        if 'ubuntu' in system_id:
            cmd = "dpkg -l | grep aliyun-alinas | awk '{ print $3 }'"
        else:
            cmd = "yum list installed aliyun-alinas-utils | grep aliyun-alinas | awk '{ print $2 }'"
        proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, _ = proc.communicate()
        stdout = stdout.decode().strip()

        if proc.returncode == 0 and stdout:
            VERSION = stdout

    return VERSION


def parse_options(options):
    opts = {}
    for o in options.split(','):
        if '=' in o:
            k, v = o.split('=', 1)
            opts[k] = v
        else:
            opts[o] = None
    return opts


def validate_options(options):
    if UNAS_APP_NAME in options:
        return

    if 'tls' in options:
        if 'direct' in options:
            fatal_error('Option tls conflicts with direct')

    if 'alitimeo' in options:
        get_ali_timeout(options)


def ip_is_used(ip, state_file_dir):
    if not os.path.isdir(state_file_dir):
        return False

    return any([sf.endswith(ip) for sf in os.listdir(state_file_dir)])


def choose_proxy_addr(config, state_file_dir=STATE_FILE_DIR):
    port = config.getint(CONFIG_SECTION, 'proxy_port',
                         default=PROXY_DEFAULT_PORT,
                         minvalue=8000,
                         maxvalue=65535)

    for i in range(1, 256):
        for j in range(1, 255):
            try:
                ip = '127.0.%d.%d' % (i, j)
                if ip_is_used(ip, state_file_dir):
                    continue

                sock = socket.socket()
                sock.bind((ip, port))
                sock.close()
                return ip, port
            except socket.error:
                continue

    fatal_error('Failed to find a loopback ip from 127.0.1.1 ~ 127.0.0.255.254 with port %s' % port)


VALID_EFC_RUN_MODE = ['efc_tcp_nas', 'efc_vsc_cpfs', 'efc_tcp_cpfs', 'nfs3_tcp_cpfs', 'oss_tcp_oss']

def get_efc_run_mode(options):
    if options.get('protocol') == 'nfs3':
        # compatible with legacy options
        options.setdefault('fstype', 'cpfs')
        options.setdefault('net', 'tcp')
    elif options.get('protocol') == 'oss':
        options.setdefault('fstype', 'oss')
        options.setdefault('net', 'tcp')
    else:
        options.setdefault('protocol', 'efc')   # default
        options.setdefault('fstype', 'nas')     # default
        options.setdefault('net', 'tcp')        # default

    fstype, protocol, net = map(options.get, ['fstype', 'protocol', 'net'])

    run_mode = '%s_%s_%s' % (protocol, net, fstype)

    if not run_mode in VALID_EFC_RUN_MODE:
        fatal_error('options wrong, fstype:%s, protocol:%s, net:%s' % (fstype, protocol, net))
    return run_mode

UMOUNT_NEED_HELP = ['2.23.1', '2.32.1', '2.37.2-4ubuntu3.4', '2.39.3-9ubuntu6.3']
UMOUNT_NOT_NEED_HELP = ['2.23.2']

def write_umount_helper_info(mount_path, mount_point, helper_info_path='/run/mount/utab'):
    try:
        system_id, _ = get_system_release_id()
        if 'ubuntu' in system_id:
            version = os.popen("dpkg -l | grep libmount | awk '{print $3}'").read().strip()
        else:
            version = os.popen("rpm -qi libmount | grep Version | awk '{print $3}'").read().strip()
        if version in UMOUNT_NEED_HELP:
            with open(helper_info_path, 'a+') as f:
                f.write("SRC=%s TARGET=%s ROOT=/ OPTS=uhelper=fuse.aliyun-alinas-efc\n" % (mount_path, mount_point))
    except Exception as e:
        logging.warning("write_umount_helper_info fail, error msg:%s" % str(e))


def get_remote_root_path(ctx):
    if get_efc_run_mode(ctx.options) == 'nfs3_tcp_cpfs':
        return '/share'
    return '/'


def get_relative_path_to_bind_root(ctx):
    if get_efc_run_mode(ctx.options) == 'nfs3_tcp_cpfs':
        return ctx.path[6:]
    return ctx.path

def serialize_stunnel_config(config, header=None):
    lines = []

    if header:
        lines.append('[%s]' % header)

    for k, v in config.items():
        if type(v) is list:
            for item in v:
                lines.append('%s = %s' % (k, item))
        else:
            lines.append('%s = %s' % (k, v))

    return lines


def add_stunnel_ca_options(alinas_config, stunnel_cafile=DEFAULT_STUNNEL_CAFILE):
    if not os.path.exists(stunnel_cafile):
        fatal_error('Failed to find the alinas certificate authority file for verification',
                    'Failed to find the alinas CAfile "%s"' % stunnel_cafile)
    alinas_config['CAfile'] = stunnel_cafile


def is_stunnel_option_supported(stunnel_output, stunnel_option_name):
    supported = False
    for line in stunnel_output:
        if line.startswith(stunnel_option_name):
            supported = True
            break

    if not supported:
        logging.warning('stunnel does not support "%s"', stunnel_option_name)

    return supported


def get_version_specific_stunnel_options(_):
    proc = subprocess.Popen(['stunnel', '-help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = proc.communicate()

    stunnel_output = err.decode('utf-8').splitlines()

    check_host_supported = is_stunnel_option_supported(stunnel_output, 'checkHost')
    ocsp_aia_supported = is_stunnel_option_supported(stunnel_output, 'OCSPaia')

    return check_host_supported, ocsp_aia_supported


def get_system_release_version():
    try:
        with open(SYSTEM_RELEASE_PATH) as f:
            return f.read().strip()
    except IOError:
        logging.debug('Unable to read %s', SYSTEM_RELEASE_PATH)

    try:
        with open(OS_RELEASE_PATH) as f:
            for line in f:
                if 'PRETTY_NAME' in line:
                    return line.split('=')[1].strip().strip('"')
    except IOError:
        logging.debug('Unable to read %s', OS_RELEASE_PATH)

    return 'unknown'

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

def support_libwrap_config():
    system_release_version = get_system_release_version()
    if any(release in system_release_version for release in SKIP_NO_LIBWRAP_RELEASES):
        return False

    system_id, system_version_id = get_system_release_id()
    if system_id in SKIP_NO_LIBWRAP_RELEASE_IDS and SKIP_NO_LIBWRAP_RELEASE_IDS[system_id] == system_version_id:
        return False

    return True

def write_stunnel_config_file(config, state_file_dir, local_dns, tls_host, port, dns_name, verify_level,
                              log_dir=LOG_DIR, cert_details=None, tls_ciphers=None):
    """
    Serializes stunnel configuration to a file. Unfortunately this does not conform to Python's config file format,
    so we have to hand-serialize it.
    """

    global_config = dict(STUNNEL_GLOBAL_CONFIG)
    if config.getboolean(CONFIG_SECTION, 'stunnel_debug_enabled', default=False):
        global_config['debug'] = 'debug'
        global_config['output'] = os.path.join(log_dir, '%s.stunnel.log' % local_dns)

    alinas_config = dict(STUNNEL_ALINAS_CONFIG)
    alinas_config['accept'] = alinas_config['accept'] % (tls_host, port)
    alinas_config['connect'] = alinas_config['connect'] % dns_name
    alinas_config['verify'] = verify_level
    if verify_level > 0:
        add_stunnel_ca_options(alinas_config)

    if cert_details:
        alinas_config["cert"] = cert_details["certificate"]
        alinas_config["key"] = cert_details["privateKey"]
    if tls_ciphers:
        alinas_config['ciphers'] = tls_ciphers

    check_host_supported, ocsp_aia_supported = get_version_specific_stunnel_options(config)

    tls_controls_message = 'WARNING: Your client lacks sufficient controls to properly enforce TLS. ' \
                           'Please upgrade stunnel, or disable "%%s" in %s.' % CONFIG_FILE

    if config.getboolean(CONFIG_SECTION, 'stunnel_check_cert_hostname', default=False):
        if check_host_supported:
            alinas_config['checkHost'] = dns_name
        else:
            fatal_error(tls_controls_message % 'stunnel_check_cert_hostname')

    if config.getboolean(CONFIG_SECTION, 'stunnel_check_cert_validity', default=False):
        if ocsp_aia_supported:
            alinas_config['OCSPaia'] = 'yes'
        else:
            fatal_error(tls_controls_message % 'stunnel_check_cert_validity')

    if support_libwrap_config():
        alinas_config['libwrap'] = 'no'

    stunnel_config = '\n'.join(serialize_stunnel_config(global_config) +
                               serialize_stunnel_config(alinas_config, 'alinas'))
    logging.debug('Writing stunnel configuration:\n%s', stunnel_config)

    stunnel_config_file = os.path.join(state_file_dir, 'stunnel-config.%s' % local_dns)

    with open(stunnel_config_file, 'w') as f:
        f.write(stunnel_config)

    return stunnel_config_file


def get_ali_timeout(options):
    timeout = options.get('alitimeo', DEFAULT_ALI_TIMEOUT)

    try:
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError()
    except:
        fatal_error('Bad alitimeo: should be a positive integer: alitimeo={0}'.format(timeout))

    return timeout


def resolve_dns(dns):
    try:
        return socket.gethostbyname(dns)
    except:
        fatal_error('Failed to resolve dns: {0}'.format(dns))


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


def write_state_file(local_dns, ctx, tunnel_pid, command, config_file, files, state_file_dir, cert_details=None, uuid=None):
    """
    Return the name of the temporary file containing TLS tunnel state, prefixed with a '~'. This file needs to be
    renamed to a non-temporary version following a successful mount.
    """
    state_file = '~' + local_dns
    bind_tag = ''
    if BIND_TAG in ctx.options:
        bind_tag = ctx.options[BIND_TAG]

    state = {
        'pid': tunnel_pid,
        'cmd': command,
        'config_file': config_file,
        'files': files,
        'local_dns': local_dns,
        'local_ip': ctx.options['proxy'],
        'nas_dns': ctx.dns,
        'nas_ip': ctx.options['nas_ip'],
        'mountpoint': os.path.abspath(ctx.mountpoint),
        'timeo': get_ali_timeout(ctx.options),
        BIND_TAG: bind_tag
    }
    if cert_details:
        state.update(cert_details)
    if uuid:
        state['uuid'] = uuid

    state[STATE_SIGN] = sign_state(state)

    with open(os.path.join(state_file_dir, state_file), 'w') as f:
        json.dump(state, f)

    return state_file


def test_proxy_process(proxy_name, proxy_proc, fs_id):
    proxy_proc.poll()

    if proxy_proc.returncode is not None:
        out, err = proxy_proc.communicate()
        out, err = out.decode('utf-8'), err.decode('utf-8')
        user_msg = 'Failed to initialize proxy %s for %s' % (proxy_name, fs_id)
        log_msg = 'Failed to start proxy %s (errno=%d). stdout="%s" stderr="%s"' % \
                  (proxy_name, proxy_proc.returncode, out.strip(), err.strip())
        fatal_error(user_msg, log_msg)


def poll_proxy_process(proxy_name, proxy_proc, fs_id, mount_completed):
    """
    poll the proxy process health every .5s during the mount attempt to fail fast if the proxy dies - since this is not
    called from the main thread, if the proxy fails, exit uncleanly with os._exit

    this might cause garbage temporary config files, but it would be rare and we won't pay more attention to this
    """
    while not mount_completed.is_set():
        try:
            test_proxy_process(proxy_name, proxy_proc, fs_id)
        except SystemExit as e:
            os._exit(e.code)
        mount_completed.wait(.5)


def get_init_system_by_comm(comm_file='/proc/1/comm'):
    init_system = 'unknown'

    try:
        with open(comm_file) as f:
            init_system = f.read().strip()
    except IOError:
        logging.warning('Unable to read %s', comm_file)

    return init_system


def get_init_system(comm_file='/proc/1/comm'):
    if os.path.exists(comm_file):
        init_system = get_init_system_by_comm(comm_file)
    else:
        # for low version kernels
        init_system = 'init'

    logging.debug('Identified init system: %s', init_system)
    return init_system


def check_network_status(fs_id, init_system, options):
    if 'umount_flag' in options:
        return

    if 'netcheck' in options and options['netcheck'] == 'none':
        logging.debug('Not testing network')
        return

    if init_system != 'systemd':
        logging.debug('Not testing network on non-systemd init systems')
        return

    with open(os.devnull, 'w') as devnull:
        rc = subprocess.call(['systemctl', 'status', 'network.target'], stdout=devnull, stderr=devnull)

    if rc != 0:
        fatal_error('Failed to mount %s because the network was not yet available, add "_netdev" to your mount options'
                    % fs_id, exit_code=0)


def start_watchdog(init_system):
    if init_system == 'init':
        proc = subprocess.Popen(['/sbin/status', WATCHDOG_SERVICE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status, _ = proc.communicate()
        if 'stop' in status:
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(['/sbin/start', WATCHDOG_SERVICE], stdout=devnull, stderr=devnull)
        elif 'start' in status:
            logging.debug('%s is already running', WATCHDOG_SERVICE)

    elif init_system == 'systemd':
        rc = subprocess.call(['systemctl', 'is-active', '--quiet', WATCHDOG_SERVICE])
        if rc != 0:
            with open(os.devnull, 'w') as devnull:
                rc = subprocess.call(['systemctl', 'start', WATCHDOG_SERVICE], stdout=devnull, stderr=devnull)
                if rc != 0:
                    error_message = 'Could not start %s, systemctl start failed, rc:%d' % (WATCHDOG_SERVICE, rc)
                    fatal_error(error_message)
        else:
            logging.debug('%s is already running', WATCHDOG_SERVICE)

    else:
        error_message = 'Could not start %s, unrecognized init system "%s"' % (WATCHDOG_SERVICE, init_system)
        fatal_error(error_message)


class Tx(object):
    def __init__(self, local_dns):
        self.config_file = None
        self.process = None
        self.cmd = None
        self.local_dns = local_dns

    def commit(self, config_file, process, cmd, cert_details=None):
        self.config_file = config_file
        self.process = process
        self.cmd = cmd
        self.cert_details = cert_details


def compose_local_dns_with_uuid(fs_id, ip, is_tls=False):
    if is_tls:
        return gen_tls_local_dns_with_uuid(fs_id, ip)
    else:
        return '{0}.{1}'.format(fs_id, ip), None

def atomic_write_hostfile(options, lines, hostfile='/etc/hosts', tmpdir='/tmp'):
    fd, path = tempfile.mkstemp(dir=tmpdir, text=True)
    try:
        os.write(fd, ''.join(lines).encode('utf-8'))
        os.fchmod(fd, 0o644)
        os.rename(path, hostfile)
    except:
        os.unlink(path)
        raise
    finally:
        os.close(fd)

def setup_local_dns(dns, ip, options, hostfile='/etc/hosts'):
    logging.info('Setup dns: %s -> %s', dns, ip)

    if 'no_atomic_move' in options:
        with open(hostfile, 'a') as f:
            f.write('\n{0} {1}\n'.format(ip, dns))
        return

    with open(hostfile) as f:
        lines = f.readlines()
        lines.append('\n{0} {1}\n'.format(ip, dns))

        try:
            atomic_write_hostfile(options, lines, hostfile, tmpdir='/tmp')
        except OSError as e:
            logging.warning('atomic rename hosts from /tmp not work, %s', str(e))
            atomic_write_hostfile(options, lines, hostfile, tmpdir=os.path.dirname(hostfile))

def wait_for_proxy_ready(local_dns, proxy_ip, proxy_port, timeout=60):
    deadline = time.time() + timeout

    sleep_time = 0.001
    while time.time() < deadline:
        if is_proxy_ready(proxy_ip, proxy_port):
            return
        else:
            time.sleep(sleep_time)
            sleep_time *= 2

    fatal_error('Cannot start proxy for {}'.format(local_dns))


def is_proxy_ready(ip, port):
    sk = socket.socket()
    try:
        sk.connect((ip, port))
        return True
    except:
        return False
    finally:
        sk.close()


def get_clientaddr(dns, ip):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sk.connect((ip, 2049))
        return sk.getsockname()[0]
    except IOError:
        fatal_error('Connection to {0}({1}) failed, please check the network'.format(dns, ip))
    finally:
        sk.close()

def lock_file(file_dir, name, timeout=0):
    path = os.path.join(file_dir, name)
    if timeout == 0:
        try:
            fd = os.open(path, os.O_CREAT | os.O_RDWR)
            fcntl.lockf(fd, fcntl.LOCK_EX)
            return fd
        except Exception as e:
            raise
    else:
        start = time.time()
        while True:
            passed = time.time() - start
            if passed > timeout:
                logging.error("lock_file timeout, path:%s", path)
                return -1
            try:
                fd = os.open(path, os.O_CREAT | os.O_RDWR)
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except Exception as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    return -1
                time.sleep(0.3)

def unlock_file(fd):
    if fd and fd > 0:
        try:
            fcntl.lockf(fd, fcntl.LOCK_UN)
        except IOError as e:
            raise


@contextmanager
def lock_alinas(state_file_dir=STATE_FILE_DIR, lock_type=ALINAS_LOCK, timeout=0):
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
                raise Exception("lock_alinas timeout, path:%s", path)
            try:
                fd = os.open(path, os.O_CREAT | os.O_RDWR)
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                yield
            except Exception as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                time.sleep(0.3)
            finally:
                os.close(fd)


@contextmanager
def lock_dns(state_file_dir=STATE_FILE_DIR):
    path = os.path.join(state_file_dir, DNS_LOCK)
    fd = os.open(path, os.O_CREAT | os.O_RDWR)

    try:
        fcntl.lockf(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

@contextmanager
def start_tx(tx_name, ctx, state_file_dir=STATE_FILE_DIR):
    if 'no_start_watchdog' in ctx.options:
        # in some env(eg. functioncompute), watchdog started by runtime, no init_system
        logging.warning('No init system, no start watchdog')
    else:
        start_watchdog(ctx.init_system)

    if not os.path.exists(state_file_dir):
        os.makedirs(state_file_dir, exist_ok=True)

    with lock_alinas(state_file_dir) as _:
        host, port = choose_proxy_addr(ctx.config, state_file_dir)
        local_dns, uuid = compose_local_dns_with_uuid(ctx.fs_id, host, 'tls' in ctx.options)
        nas_ip = resolve_dns(ctx.dns)
        ctx.options['proxy'] = host
        ctx.options['proxy_port'] = port
        ctx.options['nas_ip'] = nas_ip
        ctx.options['clientaddr'] = get_clientaddr(ctx.dns, nas_ip)

        tx = Tx(local_dns)
        yield tx

        # commit point
        try:
            tmp_state_file = write_state_file(local_dns,
                                              ctx,
                                              tx.process.pid,
                                              tx.cmd,
                                              tx.config_file,
                                              [tx.config_file],
                                              state_file_dir,
                                              cert_details=tx.cert_details,
                                              uuid=uuid)
        except:
            tx.process.kill()
            raise

        try:
            mount_completed = threading.Event()
            t = threading.Thread(target=poll_proxy_process, args=(tx_name, tx.process, ctx.fs_id, mount_completed))
            t.start()

            try:
                with lock_dns(state_file_dir):
                    setup_local_dns(local_dns, host, ctx.options)
                wait_for_proxy_ready(local_dns, host, port)
                mount_nfs_directly(local_dns, ctx.path, ctx.mountpoint, ctx.options)
            except:
                tx.process.kill()
                raise
            finally:
                mount_completed.set()
                t.join()
        finally:
            os.rename(os.path.join(state_file_dir, tmp_state_file),
                      os.path.join(state_file_dir, tmp_state_file[1:]))

def get_alinas_security_credentials(options):
    if 'ram' not in options:
        return None

    credentials = {}
    if 'ram_config_file' in options:
        ram_config_file = os.path.abspath(options.get('ram_config_file'))
        credentials['Source'] = 'selfconfig:' + ram_config_file
    else:
        ram_config_file = DEDFAULT_RAM_CONFIG_FILE
        credentials['Source'] = 'default'

    ram_config = read_config(ram_config_file)
    credentials['AccessKeyId'] = ram_config.get(RAM_CONFIG_SECTION, 'accessKeyID', None)
    credentials['AccessKeySecret'] = ram_config.get(RAM_CONFIG_SECTION, 'accessKeySecret', None)
    credentials['SecurityToken'] = ram_config.get(RAM_CONFIG_SECTION, 'securityToken', None)

    if not credentials.get('AccessKeyId', None) or not credentials.get('AccessKeySecret', None):
        fatal_error("access_key_id or access_key_secret not found")

    return credentials

def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        "mount_dir": os.path.join(base_path, mount_name),
        # every mount will have its own ca mode assets due to lack of multi-threading support in openssl
        "database_dir": os.path.join(base_path, mount_name, "database"),
        "certs_dir": os.path.join(base_path, mount_name, "certs"),
        "index": os.path.join(base_path, mount_name, "database/index.txt"),
        "index_attr": os.path.join(base_path, mount_name, "database/index.txt.attr"),
        "serial": os.path.join(base_path, mount_name, "database/serial"),
        "rand": os.path.join(base_path, mount_name, "database/.rand"),
    }

    return tls_dict

def create_certificate(
    config,
    mount_name,
    common_name,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
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

    if security_credentials:
        public_key = os.path.join(tls_paths["mount_dir"], "publicKey.pem")
        create_public_key(private_key, public_key)

    create_ca_conf(
        certificate_config,
        common_name,
        tls_paths["mount_dir"],
        private_key,
        current_time,
        region,
        fs_id,
        security_credentials,
        ap_id,
        client_info,
    )
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
    There is a possibility of having a race condition as the lock file is getting deleted in both mount_alinas and watchdog,
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
        err_msg = "Public key file, %s, is incorrectly formatted" % public_key
        fatal_error(err_msg, err_msg)

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

def get_credential_scope(date, region):
    return "/".join([date.strftime(DATE_ONLY_FORMAT), region, SERVICE, ALIYUN4_REQUEST])

def get_target_region(config, fs_id):
    if config.has_option(CONFIG_SECTION, "region"):
        return config.get(CONFIG_SECTION, "region", "region")
    region = fs_id.split('.')[-1]
    return region

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

def create_certificate_signing_request(config_path, private_key, csr_path):
    cmd = "openssl req -new -config %s -key %s -out %s" % (
        config_path,
        private_key,
        csr_path,
    )
    subprocess_call(cmd, "Failed to create certificate signing request (csr)")


def create_ca_conf(
    config_path,
    common_name,
    directory,
    private_key,
    date,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, "publicKey.pem")
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
            security_credentials.get('SecurityToken', None)
        )
        if security_credentials
        else ""
    )
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
    retry_times = 3
    for retry in range(retry_times):
        process = subprocess.Popen(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )
        (output, err) = process.communicate()
        rc = process.poll()
        if rc != 0:
            logging.error(
                'Command %s failed, rc=%s, stdout="%s", stderr="%s"'
                % (cmd, rc, output, err),
                exc_info=True,
            )
            try:
                process.kill()
            except OSError:
                # Silently fail if the subprocess has exited already
                pass
        else:
            return output, err
    error_message = "%s, error is: %s" % (error_message, err)
    fatal_error(error_message, error_message)


def ca_dirs_check(config, database_dir, certs_dir):
    """Check if mount's database and certs directories exist and if not, create directories (also create all intermediate
    directories if they don't exist)."""
    if not os.path.exists(database_dir):
        create_required_directory(config, database_dir)
    if not os.path.exists(certs_dir):
        create_required_directory(config, certs_dir)


def ca_supporting_files_check(index_path, index_attr_path, serial_path, rand_path):
    """Recreate all supporting openssl ca and req files if they're not present in their respective directories"""
    if not os.path.isfile(index_path):
        open(index_path, "w").close()
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, "w+") as f:
            f.write("unique_subject = no")
    if not os.path.isfile(serial_path):
        with open(serial_path, "w+") as f:
            f.write("00")
    if not os.path.isfile(rand_path):
        open(rand_path, "w").close()


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.utcnow()

def create_required_directory(config, directory):
    mode = 0o750
    try:
        mode_str = config.get(CONFIG_SECTION, "state_file_dir_mode", default='750')
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
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise

def bootstrap_tls(config, fs_id, mountpoint, local_dns, dns_name, security_credentials, options, state_file_dir=STATE_FILE_DIR):
    host = options['proxy']
    port = options['proxy_port']
    remote = options['nas_ip']

    verify_level = int(options.get('verify', DEFAULT_STUNNEL_VERIFY_LEVEL))
    options['verify'] = verify_level

    cert_details = {}

    ap_id = options.get('accesspoint')
    if ap_id:
        cert_details["accessPoint"] = ap_id

    tls_ciphers = options.get("tls_ciphers")
    if not tls_ciphers:
        tls_ciphers = DEFAULT_STUNNEL_TLS_CIPHERS
    elif tls_ciphers == 'original':
        tls_ciphers = None

    client_info = get_client_info(config)
    region = get_target_region(config, fs_id)

    cert_details["mountStateDir"] = local_dns + "+"
    # common name for certificate signing request is max 64 characters
    cert_details["commonName"] = socket.gethostname()[0:64]
    cert_details["region"] = region
    cert_details["certificateCreationTime"] = create_certificate(
            config,
            cert_details["mountStateDir"],
            cert_details["commonName"],
            cert_details["region"],
            fs_id,
            security_credentials,
            ap_id,
            client_info,
            base_path=state_file_dir,
    )
    cert_details["certificate"] = os.path.join(
            state_file_dir, cert_details["mountStateDir"], "certificate.pem"
    )
    cert_details["privateKey"] = get_private_key_path()
    cert_details["fsId"] = fs_id
    if security_credentials and 'Source' in security_credentials:
        cert_details['credentialsMethod'] = security_credentials['Source']

    stunnel_config_file = write_stunnel_config_file(config,
                                                    state_file_dir,
                                                    local_dns,
                                                    host, port,
                                                    remote,
                                                    verify_level,
                                                    cert_details=cert_details,
                                                    tls_ciphers=tls_ciphers)

    tunnel_args = ['stunnel', stunnel_config_file]

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily
    # by the mount watchdog
    logging.info('Starting TLS tunnel: "%s"', ' '.join(tunnel_args))
    tunnel_proc = subprocess.Popen(tunnel_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    logging.info('Started TLS tunnel, pid: %d', tunnel_proc.pid)

    return stunnel_config_file, tunnel_proc, tunnel_args, cert_details


def fix_nfs_vers_compatibility(options):
    vers = options['vers']

    if vers not in ['3', '4.0']:
        fatal_error('Internal error: vers shoud be 3 or 4.0')

    if vers != '3':
        del options['vers']
        options['vers'] = '4'
        options['minorversion'] = '0'


def serialize_options(options):
    def to_nfs_option(k, v):
        if v is None:
            return k
        return '%s=%s' % (str(k), str(v))

    nfs_options = [to_nfs_option(k, v) for k, v in options.items() if k not in ALINAS_ONLY_OPTIONS]

    return ','.join(nfs_options)


def get_nfs_mount_options(options):
    # If you change these options, update the man page as well at man/mount.alinas.8
    if 'nfsvers' in options:
        options['vers'] = options['nfsvers']
        del options['nfsvers']

    if 'vers' not in options:
        options['vers'] = '3'
    if 'rsize' not in options:
        options['rsize'] = '1048576'
    if 'wsize' not in options:
        options['wsize'] = '1048576'
    if 'soft' not in options and 'hard' not in options:
        options['hard'] = None
    if 'timeo' not in options:
        options['timeo'] = '600'
    if 'retrans' not in options:
        options['retrans'] = '2'
    if 'noresvport' not in options:
        options['noresvport'] = None

    options['vers'] = str(options['vers'])

    if 'tls' in options and 'proxy' not in options:
        fatal_error('Internal error: "tls" without "proxy"')

    if 'accesspoint' in options and 'tls' not in options:
        fatal_error('Internal error: "accesspoint" without "tls"')

    if 'proxy' in options:
        if 'proxy_port' not in options:
            fatal_error('Internal error: "proxy" without "proxy_port"')
        if 'port' in options:
            fatal_error('The "port" should only be used with "direct"')
        options['port'] = options['proxy_port']

    if options['vers'] == '3':
        port = options.get('proxy_port', 2049)
        options['port'] = port
        options['mountport'] = port
        options['nolock'] = None
        options['proto'] = 'tcp'

    fix_nfs_vers_compatibility(options)

    return options


def get_mount_cmd(options):
    if 'vers' not in options:
        fatal_error('Option vers is not specified: use vers=3 or vers=4.0')

    vers = str(options['vers'])
    if vers == '3':
        return '/sbin/mount.nfs'
    elif vers == '4':
        return '/sbin/mount.nfs4'
    else:
        fatal_error('Option vers {} is wrong: use vers=3 or vers=4.0'.format(vers))


def mount_nfs_directly(remote, path, mountpoint, options):
    mount_path = '%s:%s' % (remote, path)

    options = get_nfs_mount_options(options)
    mount_cmd = get_mount_cmd(options)
    command = [mount_cmd, mount_path, mountpoint, '-o', serialize_options(options)]

    logging.info('Executing: "%s"', ' '.join(command))

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, err = proc.communicate()

    if proc.returncode == 0:
        logging.info('Successfully mounted %s at %s', remote, mountpoint)
    else:
        err = err.decode('utf-8')
        message = 'Failed to mount %s at %s: returncode=%d, stderr="%s"' % \
                  (remote, mountpoint, proc.returncode, err.strip())
        fatal_error(err.strip(), message, proc.returncode)


def mount_tls(ctx):
    logging.info('Mount tls: fs=%s, dns=%s, path=%s, mp=%s, options=%s',
                 ctx.fs_id,
                 ctx.dns,
                 ctx.path,
                 ctx.mountpoint,
                 ctx.options)

    with start_tx('Stunnel', ctx) as tx:
        config_file, process, cmd, cert_details = bootstrap_tls(ctx.config, ctx.fs_id, ctx.mountpoint, tx.local_dns, ctx.dns, ctx.credentials, ctx.options)
        tx.commit(config_file, process, cmd, cert_details)


def write_unas_state_file(state, state_file_dir, state_file):
    '''
        state file like this:
            /var/run/alinas/eac-a79c3712-8d74-11ec-afc1-00163e05b018
            | mountuuid:xxx | mountpoint:xxx | mountpath:xxx | mountcmd:xxx | sign:xxxx | 
    '''

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
        except Exception as e1:
            logging.error('Fail to unlink tmp state file, err msg=%s', str(e1))

        fatal_error('Fail to write %s state file, err msg:%s' % (UNAS_APP_NAME, str(e)))

def is_integral(state):
    saved_sign = state.pop(STATE_SIGN, '')
    computed_sign = sign_state(state)
    return saved_sign == computed_sign

def load_unas_state_file(state_file_dir, state_file):
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
        return result
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        return None

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


def check_sessmgr_alive():
    regex_sessmgr = SESSMGR_BIN_NAME
    try:
        cmd = PS_CMD + "| grep sessmgr"
        info = os.popen(cmd).read()
        return regex_sessmgr in info

    except Exception as e:
        fatal_error('Fail to check sessmgr alive, exception msg:%s', str(e))

def check_watchdog_alive():
    regex_watchdog = WATCHDOG_BIN_NAME
    try:
        cmd = PS_CMD + "| grep watchdog"
        info = os.popen(cmd).read()
        return regex_watchdog in info

    except Exception as e:
        fatal_error('Fail to check watchdog alive, exception msg:%s', str(e))

def get_unas_mount_file_path(mount_uuid, global_dir=UNAS_LOG_DIR):
    dir_path = os.path.join(global_dir, 'efc-' + mount_uuid)
    log_conf_path = os.path.join(dir_path, "log_conf.efc.json")
    vsc_log_conf_path = os.path.join(dir_path, "log_conf.vsc.json")
    return dir_path, log_conf_path, vsc_log_conf_path


def rename_file(tmp_file, dst_file):
    try:
        os.rename(tmp_file, dst_file)
    except Exception as e:
        try:
            os.unlink(tmp_file)
        except Exception as e1:
            logging.error('Fail to clear tmp file:%s, err msg:%s', tmp_file, str(e1))
        raise e

def create_unas_mount_dir(options, mount_uuid, global_dir=UNAS_LOG_DIR):
    '''
        sessmgr log/conf file path like this:
        eg.
            /var/log/aliyun/alinas/ (global_dir_path)
            |-- log_conf.sessmgr.json (log_conf_path)
            |-- sessmgrlog (log_dir_path)
                |-- sessmgr.LOG (log_path)
        
        efc log/conf file path like this:
        eg.
            /var/log/aliyun/alinas/efc-a79c3712-8d74-11ec-afc1-00163e05b018/ (dir_path)
            |-- log_conf.efc.json (log_conf_path)
            |-- log_conf.vsc.json (vsc_log_conf_path)
            |-- efclog (log_dir_path)
                |-- efc.LOG (log_path)
            |-- vsclog (vsc_log_dir_path)
                |-- vsc.LOG (vsc_log_path)
    '''

    LOG_FILE_PATH_NAME = 'LogFilePath'
    try:
        with open(UNAS_LOG_CONF_TEMPLATE_PATH, 'r') as f:
            lines = f.readlines()

        # newcreate log dir peer mount
        dir_path = os.path.join(global_dir, "efc-" + mount_uuid)
        current = str(int(time.time()))

        ### efc log
        log_dir_path = os.path.join(dir_path, "efclog") #efc log path
        log_dir_path = os.path.join(log_dir_path, current)
        if not os.path.exists(log_dir_path):
            os.makedirs(log_dir_path, exist_ok=True)

        # dynamic update unas log conf content
        log_conf_path = os.path.join(dir_path, "log_conf.efc.json")
        tmp_log_conf_path = os.path.join(dir_path, "~log_conf.efc.json")
        with open(tmp_log_conf_path, 'w') as f:
            for line in lines:
                item = line.split(":")[0]
                if item.find(LOG_FILE_PATH_NAME) != -1:
                    log_name = line.split("/")[-1].split('"')[0]
                    log_path = os.path.join(log_dir_path, log_name)
                    new_line = item + ":" + ('"%s"' % log_path) + ",\n"
                    f.writelines(new_line)
                else:
                    f.writelines(line)
        rename_file(tmp_log_conf_path, log_conf_path)

        if get_efc_run_mode(options) == "efc_vsc_cpfs":
            with open(VSC_LOG_CONF_TEMPLATE_PATH, 'r') as f:
                lines = f.readlines()
            ### vsc log
            vsc_log_dir_path = os.path.join(dir_path, "vsclog")
            vsc_log_dir_path = os.path.join(vsc_log_dir_path, current)
            if not os.path.exists(vsc_log_dir_path):
                os.makedirs(vsc_log_dir_path, exist_ok=True)

            vsc_log_conf_path = os.path.join(dir_path, "log_conf.vsc.json")
            tmp_log_conf_path = os.path.join(dir_path, "~log_conf.vsc.json")
            with open(tmp_log_conf_path, 'w') as f:
                for line in lines:
                    item = line.split(":")[0]
                    if item.find(LOG_FILE_PATH_NAME) != -1:
                        log_name = line.split("/")[-1].split('"')[0]
                        log_path = os.path.join(vsc_log_dir_path, log_name)
                        new_line = item + ":" + ('"%s"' % log_path) + ",\n"
                        f.writelines(new_line)
                    else:
                        f.writelines(line)
            rename_file(tmp_log_conf_path, vsc_log_conf_path)

    except Exception as e:
        fatal_error('Fail to create mount dir, exception msg:%s' % str(e))

MOUNT_TYPE_ALL='eac_efc'
MOUNT_TYPE_EFC='aliyun-alinas-efc'
MOUNT_TYPE_EAC='aliyun-alinas-eac'

def is_unas_mount(mount, mount_type):
    if mount_type == MOUNT_TYPE_ALL:
        return MOUNT_TYPE_EAC in mount.type or MOUNT_TYPE_EFC in mount.type
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
        fatal_error('Fail to get current %s mounts, exception msg:%s' % (UNAS_APP_NAME, str(e)))


def compare_unas_mountpoint(mp1, mp2):
    if mp1 == mp2:
        return True
    if mp1.startswith(BIND_ROOT_DIR) or mp2.startswith(BIND_ROOT_DIR):
        if mp1.find('run') > 0 and mp2.find('run') > 0:
            return mp1[mp1.find('run'):] == mp2[mp2.find('run'):]
    return False

def get_current_unas_mounts_from_nonfuse(mount_type, mounts):
    with lock_alinas(STATE_FILE_DIR, NONFUSE_MOUNT_LOCK, UNAS_MOUNT_LOCK_TIMEOOUT):
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

        # should handle the "upper" mounts first
        # which is listed under the bottom of /proc/mounts
        mounts.reverse()

        logging.debug("get_current_unas_mounts %s" % mounts)
        return mounts

    except Exception as e:
        fatal_error('Fail to get current %s mounts, exception msg:%s' % (UNAS_APP_NAME, str(e)))

def check_socket_ready(socket_path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
        return True
    except:
        return False
    finally:
        sock.close()

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

def start_sessmgr(global_dir=LOG_DIR):
    if check_sessmgr_alive():
        return

    try:
        with lock_alinas(STATE_FILE_DIR, SESSMGR_LOCK) as _:
            # double check with lock held
            if check_sessmgr_alive():
                return

            sessmgr_conf_path = create_sessmgr_log_file() 
            sessmgr_log_path = " --apsara_log_conf_path=%s" % sessmgr_conf_path
            bootstrap_cmd = "nohup %s %s > %s/sessmgrd-efc.out 2>&1 &" % (SESSMGR_BIN_PATH, sessmgr_log_path, LOG_DIR)
            errcode, stdmsg, errmsg = exec_cmd_in_subprocess(bootstrap_cmd, preexec_fn=os.setsid)

            if errcode != 0:
                fatal_error('Failed to init sessmgrd, errmsg=%s' % (errmsg))

            # wait sessmgr socket ready
            max_retry = 10
            while True:
                if check_socket_ready(SESSMGR_SOCKET_PATH):
                    break
                time.sleep(1)
                max_retry = max_retry - 1
                if max_retry <= 0:
                    fatal_error('Failed to init sessmgrd, wait sessmgr socket ready failed')

            logging.info('Successfully init sessmgrd')

    except Exception as e:
        fatal_error('Fail to start sessmgr, exception msg:%s' % str(e))


def mount_alifuse():
    try:
        with lock_alinas(STATE_FILE_DIR, ALIFUSE_LOCK) as _:
            lsmod_cmd = "lsmod"
            errcode, stdmsg, errmsg = exec_cmd_in_subprocess(lsmod_cmd)
            if errcode != 0:
                logging.warning('Alifuse module check and install failed, errmsg:%s' % errmsg)

            if ALIFUSE_MODULE_NAME in stdmsg:
                return

            insmod_cmd = "insmod %s" % ALIFUSE_MODULE_PATH
            errcode, stdmsg, errmsg = exec_cmd_in_subprocess(insmod_cmd)
            if errcode != 0:
                logging.warning('Alifuse module check and install failed, errmsg:%s' % errmsg)

    except Exception as e:
        logging.warning('Fail to mount alifuse, exception msg:%s' % str(e))

def mount_fuse():
    try:
        modprobe_cmd = "modprobe fuse"
        errcode, stdmsg, errmsg = exec_cmd_in_subprocess(modprobe_cmd)
        if errcode != 0:
            logging.warning('Fuse module modprobe failed, errmsg:%s' % errmsg)

    except Exception as e:
        logging.warning('Fail to mount fuse, exception msg:%s' % str(e))

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

def fuse_kernel_has_recovery():
    support = False

    # try open ALIFUSE_DEV_NAME
    if os.path.exists(ALIFUSE_DEV_NAME):
        fd = os.open(ALIFUSE_DEV_NAME, os.O_RDWR | os.O_CLOEXEC)
        if fd > 0:
            try:
                fcntl.ioctl(fd, FUSE_DEV_IOC_RECOVER, bytearray(FUSE_DEV_IOC_RECOVER_SIZE))
            except OSError as e:
                if e.errno == errno.EINVAL:
                    support = True
            finally:
                os.close(fd)

            if support:
                logging.info('alifuse kernel support failover')
                return support

    # try open FUSE_DEV_NAME
    if os.path.exists(FUSE_DEV_NAME):
        fd = os.open(FUSE_DEV_NAME, os.O_RDWR | os.O_CLOEXEC)
        if fd > 0:
            try:
                fcntl.ioctl(fd, FUSE_DEV_IOC_RECOVER, bytearray(FUSE_DEV_IOC_RECOVER_SIZE))
            except OSError as e:
                if e.errno == errno.EINVAL:
                    support = True
            finally:
                os.close(fd)

            if support:
                logging.info('fuse kernel support failover')
                return support

    logging.info('fuse kernel not support failover')
    return support

def check_sessmgr_required(ctx, mount_uuid, mount_upgrade):
    sessmgr_required = False

    # first mount, check mount options and kernel recovery capacity
    if not mount_upgrade:
        if 'fd_store' not in ctx.options:
            if fuse_kernel_has_recovery():
                ctx.options['fd_store'] = 'kernel'
            else:
                ctx.options['fd_store'] = 'sessmgrd'
        if ctx.options['fd_store'] == 'sessmgrd':
            sessmgr_required = True
        else:
            sessmgr_required = False
    # upgrade from old version
    else:
        state_file = unas_state_file_name(mount_uuid)
        state = load_unas_state_file(STATE_FILE_DIR, state_file)
        if not state or SESSMGR_REQUIRED not in state:
            sessmgr_required = True
        else:
            sessmgr_required = state[SESSMGR_REQUIRED]

    logging.info('Successfully check_sessmgr_required, %s' % sessmgr_required)
    return sessmgr_required

def check_start_sessmgr(ctx):
    # check start sessmgr in this runtime
    start = ctx.config.getboolean(CONFIG_SECTION, 'start_sessmgr', default=True)
    logging.info('Successfully check_start_sessmgr, %s' % start)
    return start

def prepare_mount_unas(config):
    # alifuse module check & helped insmod
    mount_alifuse()
    mount_fuse()
    # mount /sys/fs/alifuse/connections (alifusectl)
    alifuse_ret = mount_fuse_ctl("alifusectl", ALIFUSE_CTL_MOUNT_PATH)

    fuse_ret = mount_fuse_ctl("fusectl", FUSE_CTL_MOUNT_PATH)

    if alifuse_ret == 1 and fuse_ret == 1:
        fatal_error("alifusectl or fusectl should exist one!")

def wait_mount_completed(mount_uuid, mount_path, timeout=3):
    deadline = time.time() + timeout
    local_mount_dns = mount_uuid + ':' + mount_path
    sleep_time = 0.1
    try:
        while time.time() < deadline:
            unas_mounts = get_current_unas_mounts(MOUNT_TYPE_EFC)
            for m in unas_mounts:
                if m.server == local_mount_dns:
                    return True

            if not check_unas_process(mount_uuid) and \
                not os.path.exists('%s/%s.%s' % (EFC_WORKSPACE_DIR, mount_uuid, EFC_LOCK_SUFFIX)):
                logging.error('{0}, uuid:{1} dead'.format(UNAS_BIN_PATH, mount_uuid))
                break

            time.sleep(sleep_time)

        return False

    except Exception as e:
        fatal_error('Fail to wait mount completed, exception msg:%s' % str(e))

def is_fuse_ctl_mount(mount_type, mount_path, mount_file='/proc/mounts'):
    with open(mount_file) as f:
        for mount in f.readlines():
            m = Mount._make(mount.strip().split())
            if m.mountpoint == mount_path:
                return True
    return False


def mount_fuse_ctl(mount_type, mount_path, mount_file='/proc/mounts'):
    try:
        with lock_alinas(STATE_FILE_DIR, ALIFUSE_CTL_LOCK) as _:
            if is_fuse_ctl_mount(mount_type, mount_path, mount_file):
                return 0

            mount_cmd = "mount -t %s %s %s" % (mount_type, mount_type, mount_path)
            errcode, stdmsg, errmsg = exec_cmd_in_subprocess(mount_cmd)
            if errcode != 0:
                if is_fuse_ctl_mount(mount_type, mount_path, mount_file):
                    return 0
                logging.warning("Fail to mount alifusectl, please check path:%s" % mount_path)
                return 1
            return 0

    except Exception as e:
        logging.waring('Fail to mount %s, exception msg:%s' % (mount_type, str(e)))
        return 1

def serialize_unas_options(options, mount_uuid):
    unas_options = []
    unas_flags = []
    client_owner_param = str(socket.gethostname())
    for k, v in options.items():
        if k in ALINAS_ONLY_OPTIONS:
            continue

        if v is None:
            unas_options.append(k)
        elif k.startswith('g_'):
            flag_name = '--' + k[2:]
            unas_flags.append('%s=%s' % (flag_name, str(v)))
        elif k == 'client_owner':
            client_owner_param = str(v)
        else:
            unas_options.append('%s=%s' % (str(k), str(v)))

    unique_str = mount_uuid + '_' + str(int(time.time() * 1000000))
    owner_str = client_owner_param + '_' + unique_str
    unas_options.append('%s=%s' % ('client_owner', owner_str))

    return ','.join(unas_options), ' '.join(unas_flags)

def precheck_unas_flag(fs_type, mount_path, options):
    if 'flagcheck' in options and options['flagcheck'] == 'none':
        logging.info('Not flag check')
        return
    if fs_type == 'cpfs':
        config_map = {}
        precheck_fs_config(mount_path, options, config_map)
        efc_need_lease = True
        backend_support_lease = False
        if 'g_lease_Enable' in options:
            if options['g_lease_Enable'] == 'false':
                efc_need_lease = False
            logging.info('efc mount sepcify g_lease_Enable: %s', options['g_lease_Enable'])
        if 'lease_enabled' in config_map and not config_map['lease_enabled']:
            backend_support_lease = False
        elif 'lease_enabled' in config_map and config_map['lease_enabled']:
            backend_support_lease = True
        if efc_need_lease and backend_support_lease:
            options['g_lease_Enable'] = 'true'
        else:
            options['g_lease_Enable'] = 'false'

def gen_unas_mount_cmd(uuid, mount_point, mount_path, options, log_path, vsc_log_path):
    mount_cmd = UNAS_BIN_PATH
    fs_type = options.get('fstype')
    precheck_unas_flag(fs_type, mount_path, options)
    mount_uuid = "-o mount_uuid=%s" % uuid
    mount_point = "-o mountpoint=%s" % mount_point
    mount_path = "-o server=%s" % (mount_path)
    unas_options, unas_flags = serialize_unas_options(options, uuid)
    if 'no_kernel_permission' in options:
        all_options = "-o %s,allow_other" % (unas_options)
    else:
        all_options = "-o %s,default_permissions,allow_other" % (unas_options)
    log_path = "--apsara_log_conf_path=%s" % log_path
    vsc_log_path = "--vsc_log_conf_path=%s" % vsc_log_path if get_efc_run_mode(options) == "efc_vsc_cpfs" else ""

    mount_cmd = ' '.join([mount_cmd, mount_path, mount_point, all_options, unas_flags, mount_uuid, log_path, vsc_log_path])
    logging.debug('Executing: %s', mount_cmd)
    return mount_cmd

uuidChars = ("a", "b", "c", "d", "e", "f",
       "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
       "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5",
       "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I",
       "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V",
       "W", "X", "Y", "Z")

def unas_state_file_name(mount_uuid):
    return "eac-" + mount_uuid

def check_unas_mount_exist(mount_point, mount_path = None):
    try:
        # check /proc/mounts
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_EFC)
        for m in unas_mounts:
            split_dns = m.server.split(':')
            mount_uuid = split_dns[0]
            mount_domain = split_dns[1]
            mount_server_path = split_dns[2]
            if mount_path is None:
                if compare_unas_mountpoint(m.mountpoint, mount_point):
                    return mount_uuid
                else:
                    continue

            mount_path_split = mount_path.split(':')
            if len(mount_path_split) != 2:
                fatal_error('mount path %s format wrong' % (mount_path))
            [new_domain, new_server_path] = mount_path_split
            if mount_domain == new_domain and os.path.realpath(mount_server_path) == os.path.realpath(new_server_path) and compare_unas_mountpoint(m.mountpoint, mount_point):
                return mount_uuid
        return None

    except Exception as e:
        fatal_error('Check unas mount exist failed: path:%s, mountpoint:%s, msg=%s' % (mount_path, mount_point, str(e)))

def bindroot_uuid_prefix(dns):
    return BIND_ROOT_PREFIX + hashlib.md5(dns.encode('utf-8')).hexdigest()[:5]

def parse_bindroot_uuid_prefix(uuid):
    items = uuid.split('-')
    return items[0] + '-' + items[1]

def gen_short_uuid():
    long_uuid = str(uuid4()).replace('-', '')
    uuid = ''
    # short uuid, 8 bytes
    for i in range(0,8):
        sub = long_uuid[i * 4: i * 4 + 4]
        x = int(sub,16)
        uuid += uuidChars[x % 0x3E]
    return uuid

def gen_unas_uuid(is_bindroot, bind_root_dns):
    try:
        while True:
            uuid = gen_short_uuid()
            if is_bindroot:
                uuid_prefix = bindroot_uuid_prefix(bind_root_dns)
                uuid = uuid_prefix + '-' + uuid
            # check uuid not duplicated
            state_file_path = os.path.join(STATE_FILE_DIR, unas_state_file_name(uuid))
            if not os.path.exists(state_file_path):
                return uuid
    except Exception as e:
        fatal_error('Fail to gen unas uuid %s' % (str(e)))

def tls_local_dns(fs_id, ip, uuid=None):
    if uuid:
        return '{}.tls.{}-{}'.format(fs_id, ip, uuid)
    return '{}.tls.{}'.format(fs_id, ip)

def gen_tls_local_dns_with_uuid(fs_id, ip):
    try:
        while True:
            uuid = gen_short_uuid()
            local_dns = tls_local_dns(fs_id, ip, uuid)
            # check uuid not duplicated
            state_file_path = os.path.join(STATE_FILE_DIR, local_dns)
            if not os.path.exists(state_file_path):
                return local_dns, uuid
    except Exception as e:
        fatal_error('Fail to gen tls local dns %s' % (str(e)))

def check_unas_process(mount_uuid):
    ps_cmd = PS_CMD + "| grep efc"
    ps_info = os.popen(ps_cmd).read()
    regex_uuid = 'mount_uuid=%s' % mount_uuid
    if ps_info.find(regex_uuid) != -1:
        return True
    return False

def check_unas_lock_available(mount_uuid):
    state_file = unas_state_file_name(mount_uuid)
    state = load_unas_state_file(STATE_FILE_DIR, state_file)
    if not state:
        logging.error('check_unas_lock_available load state file failed:%s' % (state_file))
        return False
    lock_fail_time = 0
    if 'lock_fail_time' in state:
        lock_fail_time = int(state['lock_fail_time'])
    now = int(time.time())
    # reset every 10 mins
    if lock_fail_time > 0 and now >= lock_fail_time + UNAS_MOUNT_LOCK_FAIL_RECHECK_TIME:
        lock_fail_time = 0
    return lock_fail_time == 0

def update_lock_available_state(mount_uuid, success):
    state_file = unas_state_file_name(mount_uuid)
    state = load_unas_state_file(STATE_FILE_DIR, state_file)
    if not state:
        logging.error('update_lock_available load state file failed:%s' % (state_file))
        return
    if success:
        lock_fail_time = 0
    else:
        lock_fail_time = int(time.time())
    state['lock_fail_time'] = str(lock_fail_time)
    write_unas_state_file(state, STATE_FILE_DIR, state_file)

def check_mount_options_match(mount, ctx):
    opts = parse_options(mount.options)
    if not (('ro' in opts) == ('ro' in ctx.options)):
        return False
    return True

def double_check_unas_bindmount(ctx, bind_mountpoint, bind_mount_uuid):
    try:
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_EFC)

        bind_tag = ''
        if BIND_TAG in ctx.options:
            bind_tag = ctx.options[BIND_TAG]

        for m in unas_mounts:
            split_dns = m.server.split(':')
            mount_uuid = split_dns[0]
            server = split_dns[1]
            path = split_dns[2]
            if ctx.dns == server and mount_uuid == bind_mount_uuid:
                real_mountpoint = BIND_ROOT_DIR + '/' + mount_uuid
                if not compare_unas_mountpoint(real_mountpoint, bind_mountpoint):
                    continue
                if path != get_remote_root_path(ctx) or not compare_unas_mountpoint(m.mountpoint, real_mountpoint):
                    logging.info('bind mount path/mountpoint mismatch, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_mount_options_match(m, ctx):
                    logging.info('bind mount options mismatch, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_unas_process(mount_uuid):
                    logging.error('bind mount root process not exist, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_unas_lock_available(mount_uuid):
                    logging.error('bind mount check lock available fail, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue

                root_bind_tag = ''
                state_file = unas_state_file_name(mount_uuid)
                state = load_unas_state_file(STATE_FILE_DIR, state_file)
                if state:
                    if BIND_TAG in state:
                        root_bind_tag = state[BIND_TAG]

                # check bind tag is the same
                if bind_tag != root_bind_tag:
                    continue

                return True
        # double check bindroot fail
        return False

    except Exception as e:
        fatal_error('double check %s bindmount failed: msg=%s' % (UNAS_APP_NAME, str(e)))

def check_unas_bindmount(ctx):
    try:
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_EFC)

        bind_tag = ''
        if BIND_TAG in ctx.options:
            bind_tag = ctx.options[BIND_TAG]

        for m in unas_mounts:
            split_dns = m.server.split(':')
            mount_uuid = split_dns[0]
            server = split_dns[1]
            path = split_dns[2]
            if ctx.dns == server and mount_uuid.startswith(BIND_ROOT_PREFIX):
                real_mountpoint = BIND_ROOT_DIR + '/' + mount_uuid
                if path != get_remote_root_path(ctx) or not compare_unas_mountpoint(m.mountpoint, real_mountpoint):
                    logging.info('bind mount path/mountpoint mismatch skip, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_mount_options_match(m, ctx):
                    logging.info('bind mount options mismatch, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_unas_process(mount_uuid):
                    logging.error('bind mount root process not exist, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue
                if not check_unas_lock_available(mount_uuid):
                    logging.error('bind mount check lock available fail, uuid:%s path:%s mountpoint:%s' % (mount_uuid, path, m.mountpoint))
                    continue

                root_bind_tag = ''
                state_file = unas_state_file_name(mount_uuid)
                state = load_unas_state_file(STATE_FILE_DIR, state_file)
                if state:
                    if BIND_TAG in state:
                        root_bind_tag = state[BIND_TAG]

                # check bind tag is the same
                if bind_tag != root_bind_tag:
                    continue

                return real_mountpoint, mount_uuid
        # not found exists bindroot, prepare one
        mount_uuid = gen_unas_uuid(True, ctx.dns)
        return None, mount_uuid

    except Exception as e:
        fatal_error('Check %s bindmount failed: msg=%s' % (UNAS_APP_NAME, str(e)))

def get_bindroot_mountpoint(bindroot_uuid):
    try:
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_EFC)
        for m in unas_mounts:
            split_dns = m.server.split(':')
            mount_uuid = split_dns[0]
            server = split_dns[1]
            path = split_dns[2]
            expect_mountpoint = BIND_ROOT_DIR + '/' + mount_uuid
            if mount_uuid == bindroot_uuid and compare_unas_mountpoint(m.mountpoint, expect_mountpoint):
                return expect_mountpoint
        return None

    except Exception as e:
        fatal_error('Get bindroot of uuid %s failed: msg=%s' % (bindroot_uuid, str(e)))

def check_mountpoint_uuid(mount_point):
    try:
        # check /proc/mounts
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        
        for m in unas_mounts:
            mp = m.mountpoint
            if mount_point == mp:
                split_dns = m.server.split(':')
                mount_uuid = split_dns[0]
                return mount_uuid
        return None
    except Exception as e:
        fatal_error('Check mountpoint %s uuid failed: msg=%s' % (mount_point, str(e)))

def check_and_mount_dev_shm():
    with open('/proc/meminfo', 'r') as meminfo:
        mem_total_line = next(line for line in meminfo if 'MemTotal' in line)
        mem_total_kb = int(mem_total_line.split()[1])
    mount_cmd = ''
    half_mem_kb = math.ceil(mem_total_kb // 2 * 0.9 / SHM_SIZE_ALIGNMENT_KB) * SHM_SIZE_ALIGNMENT_KB
    errcode, stdmsg, errmsg = exec_cmd_in_subprocess("mount")
    if errcode != 0:
        logging.error('check_and_mount_dev_shm: show mount fail, err:%d' % errcode)
        return False
    if '/dev/shm' in stdmsg:
        errcode, stdmsg, errmsg = exec_cmd_in_subprocess("df -k /dev/shm")
        if errcode != 0:
            logging.error('check_and_mount_dev_shm: df /dev/shm fail, err:%d' % errcode)
            return False
        shm_size_kb = int(stdmsg.splitlines()[1].split()[1])
        if shm_size_kb >= half_mem_kb:
            logging.info('check_and_mount_dev_shm: check ok, current_size_kb:%d target_size_kb:%d' % (shm_size_kb, half_mem_kb))
            return True
        else:
            logging.warning('check_and_mount_dev_shm: /dev/shm mounted but need remount, current_size_kb:%d target_size_kb:%d' % (shm_size_kb, half_mem_kb))
            mount_cmd = "sudo mount -o remount,size=%dK /dev/shm" % half_mem_kb
    else:
        logging.warning('check_and_mount_dev_shm: /dev/shm not mounted, target_size_kb:%d' % (half_mem_kb))
        mount_cmd = "sudo mount -t tmpfs -o size=%dK tmpfs /dev/shm" % half_mem_kb
    logging.warning('check_and_mount_dev_shm: will run mount cmd: %s' % mount_cmd)
    errcode, stdmsg, errmsg = exec_cmd_in_subprocess(mount_cmd)
    if errcode != 0:
        logging.error('check_and_mount_dev_shm: run mount cmd fail, err:%d' % errcode)
        return False
    logging.warning('check_and_mount_dev_shm: run mount cmd success')
    return True

def execute(cmd, timeout, output_when_error=False, force_timeout=False):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    timer = Timer(timeout, lambda process: process.kill(), [p])

    try:
        timer.start()
        if force_timeout:
            try:
                stdout, stderr = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                logging.error('Execute %s timeout' % cmd)
                return -1
        else:
            stdout, stderr = p.communicate()
        stdout, stderr = stdout.decode('utf-8'), stderr.decode('utf-8')
        if p.returncode != 0:
            if output_when_error:
                print(stderr, file=sys.stderr)
            logging.error('Fail to execute %s, stdout:%s, stderr:%s' % (cmd, stdout, stderr))
        else:
            logging.info('Successfully execute %s' % (cmd))
        return p.returncode

    except Exception as e:
        fatal_error('Fail to execute %s, msg:%s' % (cmd, str(e)))
    finally:
        timer.cancel()


def valid_mountpoint_for_prometheus(mountpoint):
    # /var/lib/kubelet/pods/${pod_uid}/volumes/kubernetes.io~csi/${sub_remotepath}/...
    sp = mountpoint.split('/')
    return len(sp) >= 9 and sp[4] == 'pods' and sp[6] == 'volumes' and (sp[7] == 'kubernetes.io~csi' or sp[7] == 'alicloud~nas')


def get_uuid_lock_name(mount_uuid):
    if mount_uuid.startswith(BIND_ROOT_PREFIX):
        bindroot_prefix = parse_bindroot_uuid_prefix(mount_uuid)
        return UNAS_MOUNT_LOCK_PREFIX + bindroot_prefix + '.lock'
    else:
        return UNAS_MOUNT_LOCK_PREFIX + mount_uuid + '.lock'

def precheck_fs_config(mount_path, options, config_map):
    if not os.path.exists(CMDUTIL_BIN_PATH):
        fatal_error('fail to find cmdutil binary')
    protocol = options.get('protocol')
    net_type = options.get('net')
    cmd = '%s --cmdline_command=precheckconfig --cmdline_server=%s --cmdline_protocol=%s --cmdline_net_type=%s' % (CMDUTIL_BIN_PATH, mount_path, protocol, net_type)
    errcode, stdmsg, errmsg = exec_cmd_in_subprocess(cmd)
    if errcode != 0 and 'lease_enabled' not in stdmsg:
        fatal_error('Failed to get precheckconfig, cmd:%s, errcode:%s, stdmsg:%s, errmsg:%s' % (cmd, errcode, stdmsg, errmsg))
    logging.info("precheck_fs_config cmd:%s, stdmsg:%s" % (cmd, stdmsg))
    if 'lease_enabled:false' in stdmsg:
        config_map.update({'lease_enabled': False})
    elif 'lease_enabled:true' in stdmsg:
        config_map.update({'lease_enabled': True})

def get_mount_err_log(uuid):
    try:
        log_path = "%s/%s-%s/stderr" %(UNAS_LOG_DIR, UNAS_APP_NAME, uuid)
        with open(log_path, 'r') as file:
            return ', '.join(file.read().strip().split('\n'))
    except Exception as e:
        logging.error('Fail to read from %s, exception msg:%s' % (log_path, str(e)))
        return ""

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

def run_mount_unas(ctx, mount_uuid, mount_point, mount_path, is_upgrade, sessmgr_required):
    try:
        if is_upgrade:
            state_file = unas_state_file_name(mount_uuid)
            state = load_unas_state_file(STATE_FILE_DIR, state_file)
            if not state:
                fatal_error('load state file:%s for upgrade failed' % (state_file))
            mount_cmd = state['mountcmd']
            logging.warning('before upgrade, efc internal infos:%s' % get_unas_internal_info(mount_point))
        else:
            _, log_conf_path, vsc_log_conf_path = get_unas_mount_file_path(mount_uuid)
            mount_cmd = gen_unas_mount_cmd(mount_uuid, mount_point, mount_path, ctx.options, log_conf_path, vsc_log_conf_path)
            bind_tag = ''
            if BIND_TAG in ctx.options:
                bind_tag = ctx.options[BIND_TAG]
            # record mount state for crash failover, do this before boosting unas for safety
            # record mount state include uuid & log info, (failover will not change them)
            state_file = unas_state_file_name(mount_uuid)
            unas_state = UnasState(mount_uuid, mount_point, mount_path, mount_cmd, get_uuid_lock_name(mount_uuid), bind_tag, sessmgr_required)
            write_unas_state_file(unas_state._asdict(), STATE_FILE_DIR, state_file)
            logging.info('Write state file success: %s' % state_file)

        # create mount dir(unas log)
        create_unas_mount_dir(ctx.options, mount_uuid)
        errcode = execute(mount_cmd, UNAS_MOUNT_TIMEOUT)

        if errcode == 0:
            mounted = wait_mount_completed(mount_uuid, mount_path, UNAS_MOUNT_TIMEOUT)
            if mounted:
                info = 'mount'
                if 'upgrade' in ctx.options:
                    info = 'upgrade'
                add_cgroup_limit(ctx, mount_uuid)
                logging.info('Successfully %s %s at %s', info, mount_path, mount_point)
                print("%s %s:%s successfully" % (info, UNAS_APP_NAME, mount_path))
            else:
                fatal_error('Fail to mount %s:%s:%s [%s]' % (UNAS_APP_NAME, mount_uuid, mount_path, get_mount_err_log(mount_uuid)))
        else:
            fatal_error('Fail to mount %s:%s:%s' % (UNAS_APP_NAME, mount_uuid, mount_path))

    except Exception as e:
        fatal_error('Fail to mount %s, exception msg:%s' % (UNAS_APP_NAME, str(e)))

def do_bind_mount(ctx, bind_mountpoint, mount_point):
    mount_path = ctx.dns + ":" + ctx.path
    bindmount_src = bind_mountpoint + get_relative_path_to_bind_root(ctx)
    mount_cmd = 'mount --bind %s %s' % (bindmount_src, mount_point)
    errcode = execute(mount_cmd, UNAS_MOUNT_TIMEOUT, True, force_timeout=True)
    if errcode == 0:
        logging.info('Successfully bind mounted %s at %s', bindmount_src, mount_point)
        print("Mount(bind) %s:%s successfully" % (UNAS_APP_NAME, mount_path))
    else:
        message = 'Failed to bind mount %s at %s: returncode=%d' % \
                   (bindmount_src, mount_point, errcode)
        fatal_error(message)

def do_bind_umount(bind_mountpoint, mount_point, umount_flag):
    # -i means do not call the /sbin/umount.<filesystem> helper
    # should not use force umount here
    umount_cmd = 'umount -i %s' % (mount_point)
    errcode = execute(umount_cmd, UNAS_MOUNT_TIMEOUT, True)
    if errcode == 0:
        logging.info('Successfully umount bind %s at %s', mount_point, bind_mountpoint)
    else:
        message = 'Failed to umount bind %s at %s: returncode=%d' % \
                   (mount_point, bind_mountpoint, errcode)
        fatal_error(message)

def mount_bindroot(ctx, mount_uuid, is_upgrade, sessmgr_required):
    try:
        mount_point = BIND_ROOT_DIR + '/' + mount_uuid
        mount_path = ctx.dns + ":" + get_remote_root_path(ctx)
        if not is_upgrade: # avoid access mount dir in upgrading
            if not os.path.exists(BIND_ROOT_DIR):
                os.makedirs(BIND_ROOT_DIR, exist_ok=True)
            if not os.path.exists(mount_point):
                os.makedirs(mount_point, exist_ok=True)
        run_mount_unas(ctx, mount_uuid, mount_point, mount_path, is_upgrade, sessmgr_required)
        return mount_point
    except Exception as e:
        fatal_error('Mount bindroot %s failed: msg=%s' % (ctx.dns, str(e)))

def get_unas_mem_limit(ctx):
    if ctx.dns.endswith('.cpfs.aliyuncs.com') or '.oss-' in ctx.dns:
        limit_size = sys.maxsize
    else:
        limit_size = CGROUP_BASE_MEMORY_LIMIT_SIZE
        limit_size += 256 * UNAS_SHM_PAGE_SIZE * int(ctx.options.get(UNAS_SHM_PAGE_CAPACITY_FLAG, UNAS_SHM_PAGE_CAPACITY_DEFAULT))
        limit_size += UNAS_SHM_VOLUME_SIZE * int(ctx.options.get(UNAS_SHM_VOLUME_CAPACITY_FLAG, UNAS_SHM_VOLUME_CAPACITY_DEFAULT))
        limit_size += UNAS_SHM_JOURNAL_SIZE * int(ctx.options.get(UNAS_SHM_JOURNAL_CAPACITY_FLAG, UNAS_SHM_JOURNAL_CAPACITY_DEFAULT))
        limit_size += get_unas_file_open_max_size(ctx)
        limit_size += int(ctx.options.get(UNAS_SHM_DADI_CAPACITY_FLAG, UNAS_SHM_DADI_CAPACITY_DEFAULT)) << 20
    return limit_size

def get_unas_file_open_max_size(ctx):
    file_max = int(ctx.options.get(UNAS_SHM_FILE_CAPACITY_FLAG, UNAS_SHM_FILE_CAPACITY_DEFAULT))
    if file_max == 0:
        f = open('/proc/sys/fs/file-max')
        file_max = int(f.read().strip())
        f.close()
    return file_max * UNAS_SHM_FILE_SIZE

def add_cgroup_limit(ctx, mount_uuid, cgroup_dir=CGROUP_DIR):
    try:
        if 'no_add_cgroup' in ctx.options:
            logging.info("no_add_cgroup in mount options, skip add %s into cgroup limit" % mount_uuid)
            return

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

        # set limit size
        size = get_unas_mem_limit(ctx)
        with open(limit_path, 'w') as f:
            f.write(str(size))

        # disable swap out when oom
        with open(swap_ctrl_path, 'w') as f:
            f.write('0')

        # enable kill process when oom, set oom_kill_disable flag to 0 in this file
        with open(oom_ctrl_path, 'w') as f:
            f.write('0')

        # sort ps output by start time and reserve the latest one to avoid failure in upgrade
        cmd = "ps -eww -o pid,start_time,cmd,args --sort=start_time | grep efc | grep mount_uuid=%s | grep -vw grep | awk '{print $1}'" % mount_uuid
        pids = os.popen(cmd).read()
        if pids.endswith('\n'):
            pids = pids[:-1]

        pid = pids.split('\n')[-1]

        with open(procs_path, 'a') as f:
            f.write(pid)

    except Exception as e:
        logging.warning('add cgroup memory limit failed, uuid %s, %s, failure ignored' % (mount_uuid, str(e)))


def version_tuple(v):
    return tuple(map(int, (v.replace('-', '.').split("."))))

def version_compare(v1, v2):
    tv1 = version_tuple(v1)
    tv2 = version_tuple(v2)
    if tv1 > tv2:
        return 1
    elif tv1 < tv2:
        return -1
    else:
        return 0

def version_relex_match(v1, v2):
    tv1 = version_tuple(v1)
    tv2 = version_tuple(v2)
    return tv1[0] == tv2[0] and tv1[1] == tv2[1]

def get_system_kernel_version():
    # parse numeric parts only. e.g., '4.19.91-27.4.al7.x86_64' -> '4.19.91-27.4'
    version = re.match(r'\d+([.-]\d+)*', platform.release())
    if version:
        return version.group()
    else:
        logging.error('parse system kernel version failed, version str: %s', platform.release())
        return None

def parse_json_file(path):
    try:
        with open(path) as f:
            conf = json.load(f)
            return conf
    except (ValueError, IOError) as e:
        logging.error('Load conf %s failed, error %s', path, str(e))
    return None

def check_kernel_version_for_unas(options):
    if 'kernel_version_check' in options and options['kernel_version_check'] == 'none':
        logging.info('Not checking kernel version')
        return True

    system = get_system_release_version()
    version = get_system_kernel_version()
    if not version:
        return False
    minimum_supported_kernels = parse_json_file(EFC_MINIMUM_SUPPORTED_KERNEL_VERSIONS_CONFIG)
    if not minimum_supported_kernels:
        return False

    support = False
    supported_versions = []
    for key in minimum_supported_kernels:
        if key in system:
            supported_versions = minimum_supported_kernels[key]

    for v in supported_versions:
        if version_relex_match(version, v) and version_compare(version, v) >= 0:
            support = True

    if not support:
        logging.warning('kernel %s version %s not support efc' % (system, version))

    return support

def fuse_mount(options):
    if 'g_nonfuse_Enable' in options and options['g_nonfuse_Enable'] == 'true':
        return False
    return True

def mount_unas(ctx):
    uuid_lock_name = None
    uuid_lock = None
    try:
        auto_fallback_nfs = 'auto_fallback_nfs' in ctx.options
        if not check_kernel_version_for_unas(ctx.options):
            if auto_fallback_nfs:
                logging.warning('kernel not support efc, fallback to nfs mount with default options')
                return mount_nfs_directly(ctx.dns, ctx.path, ctx.mountpoint, {})
            else:
                fatal_error("kernel not support efc, mount failed")

        if auto_fallback_nfs and not fuse_kernel_has_recovery():
            logging.warning('kernel not support fuse recovery, fallback to nfs mount with default options')
            return mount_nfs_directly(ctx.dns, ctx.path, ctx.mountpoint, {})

        if not os.path.exists(STATE_FILE_DIR):
            os.makedirs(STATE_FILE_DIR, exist_ok=True)

        if 'no_start_watchdog' in ctx.options:
            # in some env(eg. functioncompute), watchdog started by runtime, no init_system
            logging.warning('No init system, no start watchdog')
        else:
            start_watchdog(ctx.init_system)

        mount_options = ctx.options
        if 'trybind' not in mount_options:
            if UNAS_DEFAULT_ENABLE_BINDMOUNT:
                mount_options['trybind'] = 'yes'
            else:
                mount_options['trybind'] = 'no'

        if 'accesspoint' in mount_options:
            mount_options['no_kernel_permission'] = 'true'
            mount_options['g_unas_Accesspoint'] = mount_options["accesspoint"]
            mount_options['g_unas_DoConnectHandShake'] = 'true'

        if 'no_kernel_permission' in mount_options:
            mount_options['g_unas_EnableUserSpacePermissionCheck'] = 'true'

        if 'ram' in mount_options:
            akid = ctx.credentials["AccessKeyId"]
            aksecret = ctx.credentials["AccessKeySecret"]
            token = ctx.credentials.get('SecurityToken', None)
            mount_options['g_unas_AkId'] = akid
            if token:
                mount_options['g_unas_SecurityToken'] = token

            region = get_target_region(ctx.config, ctx.fs_id)
            current_time = get_utc_now()
            date = current_time.strftime(SIGV4_DATETIME_FORMAT)
            mount_options['g_unas_Signature'] = calculate_signature(date, current_time, aksecret, region)
            mount_options['g_unas_SigningDate'] = date

        mount_point = ctx.mountpoint
        mount_path = ctx.dns + ":" + ctx.path
        mount_upgrade = ('upgrade' in mount_options)
        mount_bind = ('trybind' in mount_options and mount_options['trybind'] == 'yes')

        if fuse_mount(mount_options):
            prepare_mount_unas(ctx.config)

            # check whether local mount_point exists
            mount_point_exist_cmd = 'stat %s/' % mount_point
            if execute(mount_point_exist_cmd, UNAS_MOUNT_POINT_CHECK_TIMEOUT) != 0:
                fatal_error('Fail to mount %s, local path:%s not exist or anomaly' % (UNAS_APP_NAME, mount_point))

        mount_uuid = ''
        bind_mountpoint = ''
        # hold global lock to find or create uuid, and then take uuid lock
        with lock_alinas(STATE_FILE_DIR, UNAS_MOUNT_LOCK, UNAS_MOUNT_LOCK_TIMEOOUT):
            if mount_upgrade:
                mount_uuid = check_unas_mount_exist(mount_point, mount_path)
                if mount_uuid:
                    logging.info('Try to upgrade %s at %s, uuid:%s' % (mount_path, mount_point, mount_uuid))
                else:
                    fatal_error("Can't find upgrade target %s %s" % (mount_point, mount_path))
                mount_bind = False

                # upgrade for bindroot mount
                if mount_uuid.startswith(BIND_ROOT_PREFIX):
                    mount_point = get_bindroot_mountpoint(mount_uuid)
                    if not mount_point:
                        fatal_error("Can't find bindroot mountpoint for upgrade %s" % (mount_uuid))
                    mount_bind = True
            else:
                if check_unas_mount_exist(mount_point):
                    fatal_error("Can't overwrite the same local mount path(%s), see mount -l" % (mount_point))

                if mount_bind:
                    bind_mountpoint, mount_uuid = check_unas_bindmount(ctx)
                    if bind_mountpoint:
                        logging.info('Found exist bindroot %s at %s' % (bind_mountpoint, mount_point))
                    elif mount_uuid:
                        logging.info('Will mount new bindroot of %s uuid:%s' % (ctx.dns, mount_uuid))
                    else:
                        fatal_error('Bindmount %s failed: msg=%s' % (ctx.dns, str(e)))

                if not mount_uuid:
                    mount_uuid = gen_unas_uuid(False, None)
                    logging.info('Try to new mount %s at %s, uuid:%s' % (mount_path, mount_point, mount_uuid))
                    if not check_and_mount_dev_shm():
                        fatal_error('check_and_mount_dev_shm failed')

            uuid_lock_name = get_uuid_lock_name(mount_uuid)
            uuid_lock = lock_file(STATE_FILE_DIR, uuid_lock_name, UNAS_MOUNT_LOCK_TIMEOOUT)
            lock_ok = (uuid_lock > 0)
            update_lock_available_state(mount_uuid, lock_ok)

        if uuid_lock:
            sessmgr_required = False
            if fuse_mount(mount_options):
                sessmgr_required = check_sessmgr_required(ctx, mount_uuid, mount_upgrade)
            if sessmgr_required and check_start_sessmgr(ctx):
                start_sessmgr()

            if mount_bind:
                if mount_upgrade:
                    bind_mountpoint = mount_bindroot(ctx, mount_uuid, mount_upgrade, sessmgr_required)
                    logging.info('Upgraded mount bindroot, uuid:%s mount_point:%s' % (mount_uuid, mount_point))
                    return

                if not bind_mountpoint:
                    bind_mountpoint = mount_bindroot(ctx, mount_uuid, mount_upgrade, sessmgr_required)

                # check statefile again
                if not double_check_unas_bindmount(ctx, bind_mountpoint, mount_uuid):
                    fatal_error('Bindmount root check failed, uuid:%s mount_point:%s server:%s' % (mount_uuid, bind_mountpoint, ctx.dns))

                # do bind to bindroot
                do_bind_mount(ctx, bind_mountpoint, mount_point)
            else:
                run_mount_unas(ctx, mount_uuid, mount_point, mount_path, mount_upgrade, sessmgr_required)

            if not mount_upgrade and valid_mountpoint_for_prometheus(mount_point):
                update_prometheus(ctx, mount_uuid)

            if not mount_upgrade and fuse_mount(mount_options):
                write_umount_helper_info(mount_path, mount_point)
                if mount_bind:
                    # write another entry in /run/mount/utab when bindmount
                    # because when umounting an efc bindmount, the umount cmd is called twice(1. umount 2. umount -i)
                    # so we need to write two entry
                    write_umount_helper_info(mount_path, mount_point)

    except Exception as e:
        logging.error("Exception:{}".format(e), exc_info=True)
        fatal_error('Fail to mount %s, exception msg:%s' % (UNAS_APP_NAME, str(e)))
    finally:
        unlock_file(uuid_lock)

def update_prometheus(ctx, mount_uuid):
    # makedir
    sp = ctx.mountpoint.split('/')
    pod_path = PROMETHEUS_METRICS_FILE_DIR + '/' + sp[5]
    if not os.path.exists(pod_path):
        os.makedirs(pod_path, exist_ok=True)
    if sp[6] == 'volumes':
        remotepath = sp[8]
    else:
        remotepath = sp[7]
    metrics_path = pod_path + '/' + remotepath
    if not os.path.exists(metrics_path):
        os.makedirs(metrics_path, exist_ok=True)
    # update state file to record mounts under monitoring
    state_file = unas_state_file_name(mount_uuid)
    state = load_unas_state_file(STATE_FILE_DIR, state_file)
    if not state:
        fatal_error('check efc state file:%s failed' % (state_file))

    monitor_metrics_paths = state.get('monitor_metrics_paths', {})
    key = '%s/%s' % (sp[5], remotepath)
    if key in monitor_metrics_paths:
        monitor_metrics_paths[key] = monitor_metrics_paths[key] + 1
    else:
        monitor_metrics_paths[key] = 1
    state['monitor_metrics_paths'] = monitor_metrics_paths
    write_unas_state_file(state, STATE_FILE_DIR, state_file)

def check_unas_mountpoint_ref_zero(mount_uuid, mountpoint):
    try:
        # read /proc/mounts
        unas_mounts = get_current_unas_mounts(MOUNT_TYPE_ALL)
        ref = 0
        for m in unas_mounts:
            split_dns = m.server.split(':')
            uuid = split_dns[0]
            if mount_uuid == uuid:
                if not compare_unas_mountpoint(mountpoint, m.mountpoint):
                    ref += 1
        return ref == 0
    except Exception as e:
        fatal_error('Fail check unas umount bindroot ref fail, uuid %s, bindroot:%s' % (mount_uuid, mountpoint))

def try_umount_unas(mount_uuid, mount_point, umount_flag, timeout=60):
    start = time.time()
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        mount_type = get_unas_mount_type(mount_uuid)
        if mount_type is None:
            fatal_error('get mount type by mount uuid %s failed' % (mount_uuid))
        elif MOUNT_TYPE_EAC in mount_type:
            conn = '%s/%s.%s' % (OLD_EFC_WORKSPACE_DIR, mount_uuid, EAC_SOCKET_SUFFIX)
        elif MOUNT_TYPE_EFC in mount_type:
            conn = '%s/%s.%s' % (EFC_WORKSPACE_DIR, mount_uuid, EFC_SOCKET_SUFFIX)
        else:
            fatal_error('get mount type by mount uuid %s failed' % (mount_uuid))

        logging.info('Try to conn unas to umount, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
        sock.connect(conn)
        send_bytes = struct.pack('ii', UNAS_UMOUNT_MSG_NUM, umount_flag)

        try:
            sock.send(send_bytes)
            rec = sock.recv(1024)
            if not rec:
                fatal_error('Fail to umount %s:%s, %s process is closed' % (UNAS_APP_NAME, mount_point, UNAS_APP_NAME))

            rec_data = bytes.decode(rec)

            err = 0
            data = []
            for r in rec_data:
                if r == '\0':
                    break
                data.append(r)
            err = int(''.join(data))

            if err == 0:
                logging.info('Unas umount return ok, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
                return True
            elif err == errno.EBUSY:
                logging.info('Unas umount busy, try again uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
                if time.time() > start + UNAS_UMOUNT_BUSY_MAX_SLEEP:
                    logging.error('Unas umount busy fail, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
                    fatal_error('Fail to umount %s:%s, error:%s' % (UNAS_APP_NAME, mount_point, os.strerror(err)), None, err)
                else:
                    print('Efc umount busy, try again')
                    time.sleep(UNAS_UMOUNT_BUSY_SLEEP)
                    continue
            else:
                logging.error('Unas umount return error %d, uuid:%s mount_point:%s conn:%s' % (err, mount_uuid, mount_point, conn))
                fatal_error('Fail to umount %s:%s, error:%s' % (UNAS_APP_NAME, mount_point, os.strerror(err)), None, err)

        except socket.timeout: # fail after timeout second of no activity
            logging.error('Unas umount timeout, uuid:%s mount_point:%s conn:%s' % (mount_uuid, mount_point, conn))
            fatal_error('Timeout for waiting %s umount, mountpoint:%s may busy' % (UNAS_APP_NAME, mount_point))
        except Exception as e:
            logging.error('Unas umount fail %s, uuid:%s mount_point:%s conn:%s' % (str(e), mount_uuid, mount_point, conn))
            fatal_error('Fail to umount %s, mountpoint:%s, exception msg:%s' % (UNAS_APP_NAME, mount_point, str(e)))
        finally:
            sock.close()

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
        fatal_error('Fail to umount %s:%s, exception msg:%s' % (UNAS_APP_NAME, mount_point, str(e)))

def run_umount_unas(ctx, mount_uuid, mount_point, umount_flag):
    try:
        state_file = unas_state_file_name(mount_uuid)
        state = load_unas_state_file(STATE_FILE_DIR, state_file)
        if not state:
            fatal_error('Fail to umount %s, not found statefile %s' % (mount_point, state_file))

        umount_ok = False
        if mount_uuid.startswith(BIND_ROOT_PREFIX):
            bind_mountpoint = state['mountpoint']
            if compare_unas_mountpoint(mount_point, bind_mountpoint):
                fatal_error("Not allowed to umount bindroot (%s) directly. use 'umount -i' if you really want" % (mount_point))
            else:
                do_bind_umount(bind_mountpoint, mount_point, umount_flag)

            if check_unas_mountpoint_ref_zero(mount_uuid, bind_mountpoint):
                umount_ok = sync_umount_unas(bind_mountpoint, umount_flag)
            else:
                umount_ok = True
        else:
            if check_unas_mountpoint_ref_zero(mount_uuid, mount_point):
                umount_ok = sync_umount_unas(mount_point, umount_flag)
            else:
                if mount_point == state['mountpoint']:
                    fatal_error("There are some bind mount(s) to %s, umount them at first\n\nTry 'grep %s /proc/mounts' for help" % (mount_point, mount_uuid))
                else:
                    do_bind_umount(state['mountpoint'], mount_point, umount_flag)

        if umount_ok:
            print('Successful umount %s:%s' % (UNAS_APP_NAME, mount_point))

            state_file = unas_state_file_name(mount_uuid)
            state = load_unas_state_file(STATE_FILE_DIR, state_file)
            if not state:
                logging.error('load efc state file:%s/%s failed' % (STATE_FILE_DIR, state_file))

            try:
                if valid_mountpoint_for_prometheus(mount_point):
                    sp = mount_point.split('/')
                    pod_path = PROMETHEUS_METRICS_FILE_DIR + '/' + sp[5]
                    if sp[6] == 'volumes':
                        remotepath = sp[8]
                    else:
                        remotepath = sp[7]
                    metrics_path = pod_path + '/' + remotepath

                    monitor_metrics_paths = state.get('monitor_metrics_paths', {})
                    key = '%s/%s' % (sp[5], remotepath)
                    if key in monitor_metrics_paths:
                        monitor_metrics_paths[key] = monitor_metrics_paths[key] - 1
                        if monitor_metrics_paths[key] == 0:
                            del monitor_metrics_paths[key]
                            logging.warning('umount, cleaning metrics path %s' % metrics_path)
                            shutil.rmtree(metrics_path)
                            fnames = os.listdir(pod_path)
                            # remove file created by ack
                            if (len(fnames) == 1 and fnames[0] == 'pod_info' or len(fnames) == 0):
                                logging.warning('umount, cleaning pod path %s' % pod_path)
                                shutil.rmtree(pod_path)
                        state['monitor_metrics_paths'] = monitor_metrics_paths
                        write_unas_state_file(state, STATE_FILE_DIR, state_file)
            except Exception as inner_e:
                logging.error('clean prometheus file failed: %s' % str(inner_e))

    except Exception as e:
        fatal_error('Fail to umount %s, exception msg:%s' % (UNAS_APP_NAME, str(e)))

def umount_unas(ctx):
    uuid_lock_name = None
    uuid_lock = None
    try:
        mount_point = ctx.mountpoint
        umount_flag = ctx.options['umount_flag']
        mount_uuid = ''
        # hold global lock to find uuid, and then take uuid lock
        with lock_alinas(STATE_FILE_DIR, UNAS_MOUNT_LOCK, UNAS_MOUNT_LOCK_TIMEOOUT):
            mount_uuid = check_mountpoint_uuid(mount_point)
            if not mount_uuid:
                fatal_error('Can not found efc mount uuid %s' % (mount_point))
            else:
                logging.info('Try to umount %s uuid:%s' % (mount_point, mount_uuid))
            uuid_lock_name = get_uuid_lock_name(mount_uuid)
            uuid_lock = lock_file(STATE_FILE_DIR, uuid_lock_name, UNAS_MOUNT_LOCK_TIMEOOUT)

        if uuid_lock is not None and uuid_lock > 0:
            run_umount_unas(ctx, mount_uuid, mount_point, umount_flag)

    except Exception as e:
        fatal_error('Fail to umount %s, exception msg:%s' % (UNAS_APP_NAME, str(e)))
    finally:
        unlock_file(uuid_lock)

def get_umount_flag(options):
    # do not support flags now
    return NORMAL_UMOUNT

def parse_arguments(args=None):
    """Parse arguments, return (mp_url, fsid, path, mountpoint, options)"""
    if args is None:
        args = sys.argv

    def usage(out=sys.stderr, exit_code=1):
        out.write('Usage: mount.alinas [--version] [-h|--help] <mp_url> <mountpoint> [-o <options>]\n')
        sys.exit(exit_code)

    if '-h' in args[1:] or '--help' in args[1:]:
        usage(out=sys.stdout, exit_code=0)

    if '--version' in args[1:]:
        sys.stdout.write('%s Version: %s\n' % (args[0], get_version()))
        sys.exit(0)

    device = None
    mountpoint = None
    options = {}

    if '-u' in args[1:] and UNAS_APP_NAME in args[1:]:
        mountpoint = args[2]
        options['umount_flag'] = get_umount_flag(args[3:])
        options[UNAS_APP_NAME] = None
        if 'overlaybd_mount' in args[1:]:
            # When overlaybd mount, ctx.mountpoint is a uuid for overlaybd.uds file
            # eg: /var/run/efc/uuid/overlaybd.uds
            uds_path = EFC_WORKSPACE_DIR + '/' + mountpoint + '/overlaybd.uds'
            mountpoint = uds_path
        return None, None, None, mountpoint, options

    if len(args) > 1:
        device = args[1]  # dcpfs-xxx-xxx.cn-wulanchabu.cpfs.aliyuncs.com:/
    if len(args) > 2:
        mountpoint = args[2]  # /mnt
    if len(args) > 4 and args[3] == '-o':  # -o a=b,c=d
        options = parse_options(args[4])

    if not device or not mountpoint:
        usage()

    validate_options(options)

    match = MP_URL_PATTERN.match(device)
    if not match:
        fatal_error('Invalid mount device when parse mountpoint url: %s' % device)

    mp_url = match.group('url')
    if 'accesspoint' not in options and mp_url.startswith('ap-'):
        options['accesspoint'] = mp_url.split('.')[0]
        logging.info('Parse access point %s from url: %s', options['accesspoint'], mp_url)

    match = FS_ID_PATTERN.match(device)
    if not match:
        fatal_error('Invalid mount device: %s' % device)

    fs_id = ''
    path = ''

    if UNAS_APP_NAME in options:
        run_mode = get_efc_run_mode(options)
        if run_mode == 'nfs3_tcp_cpfs':
            fs_id = 'alinas-' + match.group('fs_id').split('.cpfs.')[0]
            path = match.group('path')
            if not mp_url.endswith('.cpfs.aliyuncs.com'):
                fatal_error('Invalid mountpoint url: only aliyun CPFS is supported')
            if not path.startswith('/share'):
                fatal_error('Invalid remote server path: %s: must starts with "/share"' % path)
        elif run_mode == 'efc_tcp_nas':
            fs_id = 'alinas-' + match.group('fs_id').split('.nas.')[0]
            path = match.group('path') or '/'
            if not mp_url.endswith('.nas.aliyuncs.com'):
                fatal_error('Invalid mountpoint url: only aliyun NAS is supported')
        else:
            path = match.group('path') or '/'
            # TODO: check for efc_vsc_cpfs
    else:
        # tls or nfs
        fs_id = 'alinas-' + match.group('fs_id').split('.nas.')[0]
        path = match.group('path') or '/'
        if not mp_url.endswith('.nas.aliyuncs.com'):
            fatal_error('Invalid mountpoint url: only aliyun NAS is supported')

    if 'overlaybd_mount' in options:
        options['kernel_version_check'] = 'none'
        options['trybind'] = 'no'
        options['g_nonfuse_Enable'] = 'true'

        # When overlaybd mount, ctx.mountpoint is a uuid for overlaybd.uds file
        # eg: /var/run/efc/uuid/overlaybd.uds
        uds_path = EFC_WORKSPACE_DIR + '/' + mountpoint + '/overlaybd.uds'
        os.makedirs(os.path.dirname(uds_path), exist_ok=True)
        mountpoint = uds_path

    return mp_url, fs_id, path, mountpoint, options


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write('only root can run mount.alinas\n')
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
    if not files_loaded:
        msg = 'Config file {0} is not found, please be attention'.format(config_file)
        sys.stderr.write('{0}\n'.format(msg))
    return SafeConfig(p, config_file, configfile_error=not files_loaded)


def bootstrap_logging(config, log_dir=LOG_DIR):
    log_type = config.get(CONFIG_SECTION, 'logging_type', default='file')
    raw_level = config.get(CONFIG_SECTION, 'logging_level', default='info')
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
        max_bytes = config.getint(CONFIG_SECTION, 'logging_max_bytes',
                              default=1048576, minvalue=1048576, maxvalue=1048576*16)
        file_count = config.getint(CONFIG_SECTION, 'logging_file_count', default=8, minvalue=1, maxvalue=16)
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


def check_unsupported_options(options):
    for unsupported_option in UNSUPPORTED_OPTIONS:
        if unsupported_option in options:
            warn_message = 'The "%s" option is not supported and has been ignored, as aliyun-alinas-utils relies on ' \
                           'a built-in trust store.' % unsupported_option
            sys.stderr.write('WARN: %s\n' % warn_message)
            logging.warning(warn_message)
            del options[unsupported_option]

def adjust_memory_limit():
    global CGROUP_BASE_MEMORY_LIMIT_SIZE
    memory_limit = int(os.popen("free -m | grep Mem | awk '{print $2}'").read().strip()) * CGROUP_MEMORY_LIMIT_RATIO * 1024 * 1024 / 100
    if CGROUP_BASE_MEMORY_LIMIT_SIZE < memory_limit:
        CGROUP_BASE_MEMORY_LIMIT_SIZE = memory_limit

def save_mountpoint(mountpoint):
    if mountpoint is None:
        return

    valid_pattern = r'^(?P<fsid>[-0-9a-z]+)-[0-9a-z]+\.(?P<region>[-0-9a-z]+)\.\w+\.aliyuncs\.com'
    if not re.match(valid_pattern, mountpoint):
        return
    try:
        if os.path.exists(LAST_MOUNTPOINT_FILE_PATH):
            os.truncate(LAST_MOUNTPOINT_FILE_PATH, 0)
        with open(LAST_MOUNTPOINT_FILE_PATH, 'w') as f:
            f.write(mountpoint)
    except Exception as e:
        logging.error('Fail to save mountpoint, error %s', str(e))

def main():
    check_env()

    config = read_config()
    bootstrap_logging(config)

    # dns_name: xxx.[cpfs|nas].aliyuncs.com
    # fs_id: alinas-123456ab12-123ab
    # path: remote_path, /
    # mountpoint: local_path, /mnt
    dns_name, fs_id, path, mountpoint, options = parse_arguments()
    if path and ' ' in path or mountpoint and ' ' in mountpoint:
        fatal_error('Do not support space in path now')

    logging.info('Mount request: version=%s options=%s dns_name=%s, fs_id=%s, path=%s, mountpoint=%s', 
                get_version(), options, dns_name, fs_id, path, mountpoint)
    check_unsupported_options(options)

    init_system = get_init_system()
    adjust_memory_limit()

    check_network_status(fs_id, init_system, options)

    security_credentials = get_alinas_security_credentials(options)

    # create workspace
    create_workspace()

    save_mountpoint(dns_name)

    ctx = MountContext(config, init_system, dns_name, fs_id, path, mountpoint, security_credentials, options)

    if UNAS_APP_NAME in options:
        if 'umount_flag' in options:
            umount_unas(ctx)
        else:
            mount_unas(ctx)
    elif 'tls' in options:
        mount_tls(ctx)
    else:
        mount_nfs_directly(dns_name, path, mountpoint, options)


if '__main__' == __name__:
    main()
