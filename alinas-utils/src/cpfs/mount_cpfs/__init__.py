#!/usr/bin/env python3
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

import json
import logging
import os
import random
import re
import shutil
import site
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import namedtuple
from contextlib import contextmanager

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


PACKAGE_PATH = "/opt/aliyun/cpfs/"
site.addsitedir(PACKAGE_PATH)

try:
    import cpfs_nfs_common
    from cpfs_nfs_common import fatal_error
    from cpfs_nfs_common import warning_info
except ImportError:
    sys.stderr.write("not found aliyun cpfs path: {}cpfs_nfs_commmon".format(PACKAGE_PATH))
    sys.exit(-1)

VERSION = 'unknown'
TLS_ENABLED = True
PROXY_DEFAULT_PORT = 12049
CPFS_PROXY_DEFAULT_ADDR = "127.0.1.255"
CPFS_PROXY_PORT_MIN = 30000
CPFS_PROXY_PORT_MAX = 60000

CONFIG_FILE = '/etc/aliyun/cpfs/cpfs-utils.conf'
CONFIG_SECTION = 'mount'
WATCHDOG_CONFIG_SECTION = 'mount-watchdog'

LOG_DIR = '/var/log/aliyun/cpfs'
LOG_FILE = 'mount.log'

STATE_FILE_DIR = '/var/run/cpfs'
STATE_SIGN = 'sign'
ALINAS_LOCK = 'cpfs.lock'

FS_ID_PATTERN = re.compile('^(?P<fs_id>[-0-9a-zA-Z.]+).cpfs.aliyuncs.com(?::(?P<path>/.*))?$')
MP_URL_PATTERN = re.compile('^(?P<url>[-0-9a-zA-Z.]+)(?::(?P<path>/.*))?$')

DEFAULT_CAFILE = '/etc/aliyun/cpfs/alinas-utils.crt'
DEFAULT_ALI_TIMEOUT = 45
DEFAULT_MOUNT_PORT = 2049
DEFAULT_TLS_MOUNT_PORT = 60000

Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])

ALINAS_ONLY_OPTIONS = [
    'tls',
    'proxy',
    'proxy_port',
    'nas_ip',
    'backup_ip',
    'direct',
    'verify',
    # When using alinas-utils in containerized environment, watchdog can not be started using init or systemd
    # and there should be an external manager process responsible for starting watchdog.
    'no_start_watchdog',
    'alitimeo',
    'hp_config_dir', # To specify ha proxy config path.
    'unmount_grace_period_sec', # To specify unmount grace period for the exact mount point.
    'mount_port' # The port for mount.
]

UNSUPPORTED_OPTIONS = [
    'cafile',
    'capath',
]

HAPROXY_CONFIG_TMPL = """
global
    maxconn 4096
    log /dev/log local0 info
    stats socket {stats_socket} mode 600 level operator
    stats timeout 30s
defaults
    mode    tcp
    balance leastconn
    log global
    timeout client      {timeout}s
    timeout server      {timeout}s
    timeout connect     3s
    timeout tunnel      45s
    timeout server-fin  5s
    timeout client-fin  5s
    retries 3
frontend cpfs2049
    bind {proxy_ip}:{proxy_port}
    default_backend bk2049
backend bk2049
    server cpfs_primary {remote}:{mount_port} maxconn 2048 check port {mount_port} inter 2s fall 8 rise 30 on-marked-down shutdown-sessions on-marked-up shutdown-backup-sessions
    server cpfs_backup  {backup}:{mount_port} maxconn 2048 check port {mount_port} inter 2s fall 8 rise 30 backup
"""

HAPROXY_CONFIG_SSL_TMPL = """
global
    maxconn 4096
    log /dev/log local0 info
    stats socket {stats_socket} mode 600 level operator
    stats timeout 30s

defaults
    mode    tcp
    balance leastconn
    log global
    timeout client      {timeout}s
    timeout server      {timeout}s
    timeout connect     3s
    timeout tunnel      45s
    timeout server-fin  5s
    timeout client-fin  5s
    retries 3

frontend cpfs2049
    bind {proxy_ip}:{proxy_port}
    default_backend bk2049

backend bk2049
    server cpfs_primary {remote}:{mount_port} maxconn 2048 check ssl ca-file {cafile} verify required inter 2s fall 8 rise 30 on-marked-down shutdown-sessions on-marked-up shutdown-backup-sessions
    server cpfs_backup  {backup}:{mount_port} maxconn 2048 check ssl ca-file {cafile} verify required inter 2s fall 8 rise 30 backup
"""

WATCHDOG_SERVICE = 'aliyun-cpfs-mount-watchdog'

MountContext = namedtuple('MountContext', ('config', 'init_system', 'dns', 'fs_id', 'path', 'mountpoint', 'options'))


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


def parse_options(options):
    opts = {}
    for o in options.split(','):
        if '=' in o:
            k, v = o.split('=')
            opts[k] = v
        else:
            opts[o] = None
    return opts


def fix_options_vers(options):
    if 'nfsvers' in options:
        options['vers'] = options['nfsvers']
        del options['nfsvers']

    if 'vers' not in options:
        options['vers'] = '3'  # default vers is 3

    vers = options['vers']
    if vers != '3' and vers != '4.0' and vers != '4.1':
        fatal_error('Option vers is wrong: use vers=3 or vers=4.0 or vers=4.1')


def validate_options(options):
    if 'tls' in options:
        if 'direct' in options:
            fatal_error('Option tls conflicts with direct')

        #if options['vers'] != '4.0':
        #    fatal_error('Option tls must be used with vers=4.0')

    if 'alitimeo' in options:
        get_ali_timeout(options)


def check_hp_in_use_port(ip, port, state_file_dir=STATE_FILE_DIR):
    pattern = r"^\s*bind\s+([\d\.]+):(\d+)"
    for _, state_file in cpfs_nfs_common.get_state_files(state_file_dir).items():
        state = cpfs_nfs_common.load_state_file(state_file_dir, state_file)
        if not state:
            continue
        
        hp_path = state.get('config_file')
        if not hp_path or not os.path.exists(hp_path):
            continue
        
        try:
            with open(hp_path, 'r') as f:
                content = f.read()
        except (IOError, OSError) as e:
            logging.warning('Failed to read config file %s: %s', hp_path, e)
            continue

        matches = re.findall(pattern, content, re.MULTILINE)

        if any(hp_ip == ip and int(hp_port) == port for hp_ip, hp_port in matches):
            return True
    
    return False


def cpfs_port_is_used(ip, port):
    # Use ss built-in filter
    cmd = 'ss -ntapH src {0}:{1} or dst {0}:{1}| grep -w {0}:{1}'.format(ip, port)
    with open(os.devnull, 'w') as devnull:
        rc = subprocess.call(cmd, shell=True, stdout=devnull, stderr=devnull)
        if rc == 0:
            return True
    return check_hp_in_use_port(ip, port)


def choose_cpfs_proxy_addr(config):
    ip = config.get(CONFIG_SECTION, 'cpfs_proxy_addr', default=CPFS_PROXY_DEFAULT_ADDR)
    cpfs_proxy_port_min = config.getint(CONFIG_SECTION, 'cpfs_proxy_port_min', default=CPFS_PROXY_PORT_MIN, minvalue=30000, maxvalue=60000)
    cpfs_proxy_port_max = config.getint(CONFIG_SECTION, 'cpfs_proxy_port_max', default=CPFS_PROXY_PORT_MAX, minvalue=60000, maxvalue=65535)
    for port in range(cpfs_proxy_port_min, cpfs_proxy_port_max):
        try:
            if cpfs_port_is_used(ip, port):
                continue

            sock = socket.socket()
            sock.bind((ip, port))
            sock.close()
            return ip, port
        except socket.error:
            continue

    fatal_error('Failed to find a loopback port from %s ~ %s with ip %s' % cpfs_proxy_port_min, cpfs_proxy_port_max, ip)

def get_ali_timeout(options):
    timeout = options.get('alitimeo', DEFAULT_ALI_TIMEOUT)

    try:
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError()
    except:
        fatal_error('Bad alitimeo: should be a positive integer: alitimeo={0}'.format(timeout))

    return timeout


def get_random_index(weights):
    total_weight = sum(weights)
    random.seed(uuid.uuid1())
    num = random.randint(0, total_weight - 1)
    for i, weight in enumerate(weights):
        num -= weight
        if num < 0:
            return i


def resolve_dns(dns):
    try:
        return socket.gethostbyname(dns)
    except:
        fatal_error('Failed to resolve dns: {0}'.format(dns))


import hashlib


def _expand_apparmor_alternation(pattern):
    """Expand AppArmor alternation syntax {a,b} and return all possible paths.

    Example: /{,var/}run/haproxy.sock* ->
        ['/run/haproxy.sock*', '/var/run/haproxy.sock*']
    """
    match = re.search(r'\{([^}]+)\}', pattern)
    if not match:
        return [pattern]

    options = match.group(1).split(',')
    results = []
    for option in options:
        expanded = pattern[:match.start()] + option + pattern[match.end():]
        results.extend(_expand_apparmor_alternation(expanded))
    return results


def get_apparmor_writable_dir(profile_path):
    """查找AppArmor配置中具有写权限的目录"""
    if not os.path.exists(profile_path):
        logging.debug('Trying to get apparmor writable dir, didn\'t find file path at %s', profile_path)
        return None

    writable_dirs = set()

    with open(profile_path, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        # skip comment line
        if not line or line.startswith('#'):
            continue

        # regex to match optional qualifiers + path + permission
        # path must contain at least one wildcard '*'
        # permission must contain both 'r' (read) and 'w' (write), which are
        # required for haproxy to create and use the stats socket, and for the
        # watchdog to read it. 'l' (link) and 'k' (lock) are optional.
        match = re.match(r'^\s*((?:audit|deny|owner|allow)\s+)*\s*(/[^#\s]*\*[^#\s]*)\s+([a-z]*),?\s*$', line)
        if not match:
            continue

        permissions = match.group(3)
        if 'r' not in permissions or 'w' not in permissions:
            continue

        # skip deny rules (e.g. "deny /path/* w," or "audit deny /path/* w,")
        qualifiers_prefix = line[:match.start(2)]
        if 'deny' in qualifiers_prefix:
            continue

        path_pattern = match.group(2)

        # Expand alternation and pick the first option that is not a system directory.
        # This avoids losing valid paths like /var/run/ when /run/ is excluded.
        expanded_options = _expand_apparmor_alternation(path_pattern)
        selected = None
        for expanded in expanded_options:
            if not expanded.startswith(('/sys/', '/proc/', '/dev/', '/run/', '/tmp/', '/var/tmp/')):
                selected = expanded
                break
        if selected is None:
            continue

        logging.info("Found writable path_pattern: %s (selected: %s) in apparmor config", path_pattern, selected)
        writable_dirs.add(selected)

    if not writable_dirs:
        warning_info("Profile for apparmor is found, but no writable dirs is found. " \
            "If error like PERMISSION DENIED is seen, please specify ha proxy config path (hp_config_dir) in options.")

    return next(iter(writable_dirs), None)


def get_haproxy_socket_name(dns, options=None, state_file_dir=STATE_FILE_DIR,
                            apparmor_profile_path=None):
    """生成 HAProxy stats socket 文件名，使用 dns 的 MD5 前 8 位"""
    if apparmor_profile_path is None:
        apparmor_profile_path = os.path.join('/etc/apparmor.d', 'usr.sbin.haproxy')

    hash_str = hashlib.md5(dns.encode('utf-8')).hexdigest()[:8]

    # 对于socket文件，我们需要一个可写的目录，而不是配置文件的目录
    if options is not None:
        # 获取AppArmor可写路径模式
        apparmor_pattern = get_apparmor_writable_dir(apparmor_profile_path)
        if apparmor_pattern:
            # 根据AppArmor配置中的路径模式生成socket文件名
            socket_path = construct_path_from_pattern(apparmor_pattern, hash_str)
            # 确保目录存在
            socket_dir = os.path.dirname(socket_path)
            os.makedirs(socket_dir, exist_ok=True)
            return socket_path
        else:
            # 如果没有AppArmor配置或没找到可写目录，则使用load_ha_proxy_path的默认结果
            socket_dir = load_ha_proxy_path(options, apparmor_profile_path, state_file_dir)
    else:
        socket_dir = state_file_dir  # 使用默认目录作为fallback

    # 确保socket_dir是目录，如果是文件则使用其父目录
    if os.path.isfile(socket_dir):
        socket_dir = os.path.dirname(socket_dir)

    # 确保目录存在
    os.makedirs(socket_dir, exist_ok=True)

    # 默认情况下使用标准命名
    return os.path.join(socket_dir, 'haproxy-%s.sock' % hash_str)


def construct_path_from_pattern(pattern, hash_str):
    """根据AppArmor路径模式构造实际的文件路径"""
    # Expand AppArmor alternation syntax and pick the first option.
    # Caller (get_apparmor_writable_dir) has already filtered out excluded paths.
    pattern = _expand_apparmor_alternation(pattern)[0]

    # 没有通配符：将pattern视为目录，在其下创建socket文件。
    # 实际使用中，get_apparmor_writable_dir 只返回包含 '*' 的pattern，
    # 此分支为防御性处理。
    if '*' not in pattern:
        return os.path.join(pattern, 'haproxy-%s.sock' % hash_str)

    # 多个通配符的情况：将socket放在第一个通配符之前的目录中。
    # 例如 /var/lib/*/*.sock -> /var/lib/haproxy-hash.sock
    # 例如 /var/lib/haproxy/** -> /var/lib/haproxy/haproxy-hash.sock
    if pattern.count('*') > 1:
        prefix_before_first_star = pattern.split('*', 1)[0]
        dir_part = os.path.dirname(prefix_before_first_star)
        return os.path.join(dir_part, 'haproxy-%s.sock' % hash_str)

    prefix, suffix = pattern.split('*', 1)

    # /path/* 这种形式
    if not suffix:
        if prefix.endswith('/'):
            return os.path.join(prefix, 'haproxy-%s.sock' % hash_str)
        else:
            dir_part = os.path.dirname(prefix)
            base = os.path.basename(prefix)
            return os.path.join(dir_part, '%s-haproxy-%s' % (base, hash_str))

    # /path/*.suffix 或 /path/prefix*.suffix 形式
    dir_part = os.path.dirname(prefix)
    base = os.path.basename(prefix)

    if not base:
        # /*.suffix
        file_name = 'haproxy-%s%s' % (hash_str, suffix)
    elif base.endswith('.'):
        # prefix. + *.suffix -> prefix.haproxy-hash.suffix
        file_name = base + 'haproxy-%s%s' % (hash_str, suffix)
    else:
        # prefix + *.suffix -> prefix-haproxy-hash.suffix
        file_name = '%s-haproxy-%s%s' % (base, hash_str, suffix)

    return os.path.join(dir_part, file_name)


def write_haproxy_config_file(_, hp_config_dir, dns, proxy_ip, proxy_port, remote, backup, mount_port, options, is_ssl=False):
    """
    Serializes haproxy configuration to a file. Unfortunately this does not conform to Python's config file format,
    so we have to hand-serialize it.
    """
    if is_ssl and not os.path.exists(DEFAULT_CAFILE):
        fatal_error('Failed to find the alinas certificate authority file for verification',
                    'Failed to find the alinas CAfile "%s"' % DEFAULT_CAFILE)
    # Move CA file to the same folder as hp_config_dir in case security enhancement limits the location to read crt
    CA_file_name = os.path.basename(DEFAULT_CAFILE)
    CA_file = os.path.join(hp_config_dir, CA_file_name)
    try:
        shutil.copy2(DEFAULT_CAFILE, CA_file)
        logging.debug("Copy file from %s to %s succeeded.", DEFAULT_CAFILE, CA_file)
    except Exception as e:
        logging.debug("Copy file from %s to %s failed with exception as %s.", DEFAULT_CAFILE, CA_file, str(e))
        CA_file = DEFAULT_CAFILE

    stats_socket = get_haproxy_socket_name(dns, options, hp_config_dir)
    haproxy_config = make_config(proxy_ip, proxy_port, remote, backup, mount_port, options, is_ssl, CA_file, stats_socket)
    logging.debug('Write haproxy configuration:\n%s', haproxy_config)

    haproxy_config_file = os.path.join(hp_config_dir, 'haproxy-config.%s' % dns)

    with open(haproxy_config_file, 'w') as f:
        f.write(haproxy_config)

    logging.info('Generate haproxy configuration to %s: local_dns=%s, proxy_ip=%s',
                 haproxy_config_file, dns, proxy_ip)
    return haproxy_config_file

def make_config(proxy_ip, proxy_port, remote, backup, mount_port, options, is_ssl, CA_file, stats_socket):
    if is_ssl:
        return HAPROXY_CONFIG_SSL_TMPL.format(stats_socket=stats_socket,
                                              timeout=get_ali_timeout(options),
                                              proxy_ip=proxy_ip,
                                              proxy_port=proxy_port,
                                              remote=remote,
                                              backup=backup,
                                              mount_port=mount_port,
                                              cafile=CA_file)
    else:
        return HAPROXY_CONFIG_TMPL.format(stats_socket=stats_socket,
                                        timeout=get_ali_timeout(options),
                                        proxy_ip=proxy_ip,
                                        proxy_port=proxy_port,
                                        remote=remote,
                                        backup=backup,
                                        mount_port=mount_port)

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


def write_state_file(local_dns, ctx, tunnel_pid, command, config_file, files, state_file_dir, unmount_grace_period_sec=None):
    """
    Return the name of the temporary file containing TLS tunnel state, prefixed with a '~'. This file needs to be
    renamed to a non-temporary version following a successful mount.
    """
    state_file = '~' + local_dns

    state = {
        'pid': tunnel_pid,
        'cmd': command,
        'config_file': config_file,
        'files': files,
        'local_dns': local_dns,
        'local_ip': ctx.options['proxy'],
        'nas_dns': ctx.dns,
        'nas_ip': ctx.options['nas_ip'],
        'backup_ip': ctx.options['backup_ip'],
        'proxy_port': ctx.options['proxy_port'],
        'mountpoint': os.path.abspath(ctx.mountpoint),
        'timeo': get_ali_timeout(ctx.options),
        'stats_socket': get_haproxy_socket_name(local_dns, ctx.options, state_file_dir)
    }
    if (unmount_grace_period_sec is not None):
        state['unmount_grace_period_sec'] = unmount_grace_period_sec
    state[STATE_SIGN] = sign_state(state)

    with open(os.path.join(state_file_dir, state_file), 'w') as f:
        json.dump(state, f)

    return state_file

def classify_haproxy_error(error_msg):
    # permission level
    if re.search(rb'permission denied|operation not permitted', error_msg, re.IGNORECASE):
        if re.search(rb'config', error_msg, re.IGNORECASE):
            return "Permission denied for reading configuration file. Please check security configuration or use another configuration path."
        else:
            return "Permission denied or Operation not permitted for ha proxy."
    
    return None


def test_proxy_process(proxy_name, proxy_proc, fs_id):
    proxy_proc.poll()

    if proxy_proc.returncode is not None:
        out, err = proxy_proc.communicate()
        err_parsed = classify_haproxy_error(err.strip())
        user_msg = 'Failed to initialize proxy %s for %s.' % (proxy_name, fs_id)
        if err_parsed is not None:
            user_msg += 'Error Msg is %s.' % (err_parsed)
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
    if 'netcheck' in options and options['netcheck'] == 'none':
        logging.debug('Not testing network')
        del options['netcheck']
        return

    if init_system != 'systemd':
        logging.debug('Not testing network on non-systemd init systems')
        return

    with open(os.devnull, 'w') as devnull:
        rc = subprocess.call(['systemctl', 'status', 'network.target'], stdout=devnull, stderr=devnull)

        if rc != 0:
            fatal_error('Failed to mount %s because the network was not yet available, add "_netdev" to your mount options'
                        % fs_id, exit_code=0)


def start_watchdog(ctx):
    if 'no_start_watchdog' in ctx.options:
        logging.warning('skip starting watchdog')
        return

    init_system = ctx.init_system
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
                subprocess.Popen(['systemctl', 'start', WATCHDOG_SERVICE], stdout=devnull, stderr=devnull)
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

    def commit(self, config_file, process, cmd):
        self.config_file = config_file
        self.process = process
        self.cmd = cmd


def setup_local_dns(dns, ip, hostfile='/etc/hosts'):
    with open(hostfile) as f:
        lines = f.readlines()
        lines.append('{0} {1}\n'.format(ip, dns))

        fd, path = tempfile.mkstemp(text=True)
        try:
            os.write(fd, ''.join(lines).encode('utf-8'))
            os.rename(path, hostfile)
            os.chmod(hostfile, 0o644)
        except:
            os.unlink(path)
            raise
        finally:
            os.close(fd)


def wait_for_proxy_ready(local_dns, proxy_ip, proxy_port, timeout=10):
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


def get_clientaddr(dns, ip, port):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sk.connect((ip, port))
        return sk.getsockname()[0]
    except IOError:
        fatal_error('Connection to {0}({1}) failed, please check the network'.format(dns, ip))
    finally:
        sk.close()

def detect_haproxy_version():
    env = {'PATH': '/usr/sbin:/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin'}
    proc = subprocess.Popen(['haproxy', '-v'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    out, _ = proc.communicate()
    output = out.decode('utf-8').splitlines()
    if len(output) == 0 or output[0].find('version') < 0:
        logging.warning('Failed to detect haproxy version, ignored')
        return 'unknown'

    return output[0]

@contextmanager
def start_tx(tx_name, ctx, is_ssl, state_file_dir=STATE_FILE_DIR):
    start_watchdog(ctx)

    if not os.path.exists(state_file_dir):
        os.makedirs(state_file_dir, exist_ok=True)

    nas_ip = ""
    backup_ip = ""
    with cpfs_nfs_common.lock_alinas(state_file_dir) as _:
        host, port = choose_cpfs_proxy_addr(ctx.config)
        nas_ip, backup_ip = cpfs_nfs_common.resolve_cpfs_dns(ctx.dns)
        local_dns = ctx.dns
        ctx.options['proxy'] = host
        ctx.options['proxy_port'] = port
        ctx.options['nas_ip'] = nas_ip
        ctx.options['backup_ip'] = backup_ip
        ctx.options['clientaddr'] = get_clientaddr(ctx.dns, nas_ip, int(ctx.options.get('mount_port', DEFAULT_TLS_MOUNT_PORT if is_ssl else DEFAULT_MOUNT_PORT)))
        unmount_grace_period_sec_opt = ctx.options.get('unmount_grace_period_sec', None)

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
                                              unmount_grace_period_sec_opt)
        except:
            tx.process.kill()
            raise

        try:
            mount_completed = threading.Event()
            t = threading.Thread(target=poll_proxy_process, args=(tx_name, tx.process, ctx.fs_id, mount_completed))
            t.start()

            try:
                wait_for_proxy_ready(local_dns, host, port)
                mount_nfs_directly(local_dns, ctx.path, ctx.mountpoint, ctx.options)
            except:
                # mount failed, mark state file as unmounted
                current_time = time.time()
                state = cpfs_nfs_common.load_state_file(state_file_dir, tmp_state_file)
                cpfs_nfs_common.mark_as_unmounted(state, state_file_dir, tmp_state_file, current_time)
                raise
            finally:
                mount_completed.set()
                t.join()
        finally:
            os.rename(os.path.join(state_file_dir, tmp_state_file),
                      os.path.join(state_file_dir, tmp_state_file[1:]))


def bootstrap_proxy(config, dns_name, options, state_file_dir=STATE_FILE_DIR, is_ssl=False):
    proxy = options['proxy']
    port = options['proxy_port']
    remote = options['nas_ip']
    backup = options['backup_ip']

    # ha proxy config dir choose: customer specify in options -> apparmor whitelisted path -> default
    hp_config_dir = load_ha_proxy_path(options, os.path.join('/etc/apparmor.d', 'usr.sbin.haproxy'), state_file_dir)
    mount_port = int(options.get('mount_port', DEFAULT_TLS_MOUNT_PORT if is_ssl else DEFAULT_MOUNT_PORT))

    logging.debug('haproxy config dir value is %s', hp_config_dir)

    proxy_config_file = write_haproxy_config_file(config, hp_config_dir, dns_name, proxy, port, remote, backup, mount_port, options, is_ssl)

    # the env is required, or the popen cannot find haproxy in some OS, I don't know why
    env = {'PATH': '/usr/sbin:/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin'}
    proxy_args = ['haproxy', '-f', proxy_config_file]

    # launch the proxy in a process group so if it has any child processes, they can be killed easily
    # by the mount watchdog
    logging.info('Starting haproxy: "%s"', ' '.join(proxy_args))
    proxy_proc = subprocess.Popen(proxy_args,
                                  env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  preexec_fn=os.setsid)
    logging.info('Started haproxy, pid: %d', proxy_proc.pid)

    return proxy_config_file, proxy_proc, proxy_args

def get_apparmor_enforced_dir(profile_path):
    if not os.path.exists(profile_path):
        logging.debug('Trying to get apparmor dir, didn\'t find file path at %s', profile_path)
        return None

    readable_dirs = set()

    with open(profile_path, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        # skip comment line
        if not line or line.startswith('#'):
            continue

        # regex to match optional qualifiers + path + permission
        # path must contain at least one wildcard '*'
        # permission must contain 'r' (read)
        match = re.match(r'^\s*((?:audit|deny|owner|allow)\s+)*\s*(/[^#\s]*\*[^#\s]*)\s+([a-z]*r[a-z]*),?\s*$', line)
        if not match:
            continue

        # skip deny rules
        qualifiers_prefix = line[:match.start(2)]
        if 'deny' in qualifiers_prefix:
            continue

        path_pattern = match.group(2)

        # Expand alternation and pick the first option under /etc/
        expanded_options = _expand_apparmor_alternation(path_pattern)
        selected = None
        for expanded in expanded_options:
            if expanded.startswith('/etc/'):
                selected = expanded
                break
        if selected is None:
            continue

        permissions = match.group(3)
        logging.info("Found path_pattern: %s (selected: %s) and permission %s in apparmor config",
                     path_pattern, selected, permissions)

        # Extract the directory part before the first wildcard
        prefix_before_star = selected.split('*', 1)[0]
        if prefix_before_star.endswith('/'):
            dir_path = prefix_before_star
        else:
            dir_path = os.path.dirname(prefix_before_star) + '/'
        readable_dirs.add(dir_path)

    if not readable_dirs:
        warning_info("Profile for apparmor is found, but no readable dirs is found. " \
            "If error like PERMISSION DENIED is seen, please specify ha proxy config path (hp_config_dir) in options.")

    return next(iter(readable_dirs), None)


 # ha proxy config dir choose: customer specify in options -> apparmor whitelisted path -> default
def load_ha_proxy_path(options, apparmor_ha_profile, default_config_dir):
    hp_config_dir = options.get('hp_config_dir')
    if hp_config_dir is None:
        hp_config_dir = get_apparmor_enforced_dir(apparmor_ha_profile)
    if hp_config_dir is None:
        hp_config_dir = default_config_dir
    return hp_config_dir


# Prerequisite: Please make sure config_file_path exists
def is_sslconfig(config_file_path):
    with open(config_file_path, 'r') as f:
        content = f.read()
    
    if 'ssl ca-file' in content:
        return True
    else:
        return False


# Prerequisite: Please make sure config_file_path exists
def get_old_mount_port(config_file_path):
    with open(config_file_path, 'r') as f:
        content = f.read()
     # 匹配server行中的IP:端口格式
    server_pattern = r'^\s*server\s+\w+\s+((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\s+maxconn'
    matches = re.findall(server_pattern, content, re.MULTILINE)
    
    if matches:
        _, last_port = matches[-1]
        return last_port
    else:
        return DEFAULT_TLS_MOUNT_PORT if "check ssl ca-file" in content else DEFAULT_MOUNT_PORT


def should_reuse_proxy(nas_dns, mount_port, unmount_grace_period_sec_cfg, is_ssl=False, state_file_dir=STATE_FILE_DIR):
    try:
        state = cpfs_nfs_common.load_state_file(state_file_dir, nas_dns)
        if not state:
            return False
        unmount_grace_period_sec = int(state.get('unmount_grace_period_sec', unmount_grace_period_sec_cfg))
        state_dns = state['nas_dns']
        ha_proxy_terminating = False
        if 'hp_terminating' in state:
            logging.info('Failed to reuse proxy for [%s] because it is terminating.', nas_dns)
            ha_proxy_terminating = True
        if not os.path.exists(state['config_file']):
            logging.info('Config path [%s] exists in state file, but not exist in file system.', state['config_file'])
            return False
        old_is_ssl = is_sslconfig(state['config_file'])
        old_mount_port = int(get_old_mount_port(state['config_file']))
        # Cannot reuse proxy and need to kill the running one since it's not been terminated.
        if (is_ssl != old_is_ssl or mount_port != old_mount_port) and not ha_proxy_terminating:
            if 'unmount_time' in state:
                unmount_time = state['unmount_time']
                fatal_error('Cannot mount with %s and port %s now, please wait %d seconds for the unmount to complete.' % ('tls' if is_ssl else 'non-tls', mount_port, unmount_grace_period_sec - int(time.time() - unmount_time) + 1))
            else:
                fatal_error('Cannot mount with %s and port %s now, no unmount_time information is found, please check your mounting state.' % ('tls' if is_ssl else 'non-tls', mount_port))
        if nas_dns == state_dns and not ha_proxy_terminating:
            return True
        else:
            return False
    except Exception as e:
        logging.exception('OS errors, just retry later: dns=%s, error=%s', nas_dns, str(e))
        time.sleep(30)


def fix_nfs_vers_compatibility(options):
    vers = options['vers']

    if vers not in ['3', '4.1']:
        fatal_error('Internal error: vers shoud be 3 or 4.1')

    if vers == '4.1':
        del options['vers']
        options['vers'] = '4.1'
        options['minorversion'] = '1'


def serialize_options(options):
    def to_nfs_option(k, v):
        if v is None:
            return k
        return '%s=%s' % (str(k), str(v))

    nfs_options = [to_nfs_option(k, v) for k, v in options.items() if k not in ALINAS_ONLY_OPTIONS]

    return ','.join(nfs_options)


def get_nfs_mount_options(options):
    # If you change these options, update the man page as well at man/mount.cpfs-nfs.8
    if 'nfsvers' in options:
        options['vers'] = options['nfsvers']
        del options['nfsvers']

    if 'vers' not in options:
        options['vers'] = '3'  # default vers = 3
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
        fatal_error('Option vers is not specified: use vers=3 or vers=4.1')

    vers = str(options['vers'])
    if vers == '3':
        return '/sbin/mount.nfs'
    elif vers == '4.1':
        return '/sbin/mount.nfs4'
    else:
        fatal_error('Option vers is wrong: use vers=3 or vers=4.1')


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

    with start_tx('Haproxy_ssl', ctx, is_ssl=True) as tx:
        config_file, process, cmd = bootstrap_proxy(ctx.config, ctx.dns, ctx.options, is_ssl=True)
        tx.commit(config_file, process, cmd)


def mount_nfs_proxy(ctx):
    logging.info('Mount with haproxy: fs=%s, dns=%s, path=%s, mp=%s, options=%s',
                 ctx.fs_id,
                 ctx.dns,
                 ctx.path,
                 ctx.mountpoint,
                 ctx.options)

    with start_tx('Haproxy', ctx, is_ssl=False) as tx:
        config_file, process, cmd = bootstrap_proxy(ctx.config, ctx.dns, ctx.options)
        tx.commit(config_file, process, cmd)


def mount_nfs_reuse_proxy(ctx, is_ssl):
    state = cpfs_nfs_common.load_state_file(STATE_FILE_DIR, ctx.dns)
    if not state:
        fatal_error("mount {0} error, please check state file in {1}".format(ctx.dns, STATE_FILE_DIR))
    if not cpfs_nfs_common.is_hp_running(state['pid'], ctx.dns):
        fatal_error("mount {0} error, please check haproxy pid {1} is running".format(ctx.dns, state['pid']))

    start_watchdog(ctx)

    ctx.options['proxy_port'] = state['proxy_port']
    ctx.options['proxy'] = state['local_ip']
    ctx.options['clientaddr'] = get_clientaddr(ctx.dns, state['nas_ip'], int(ctx.options.get('mount_port', DEFAULT_TLS_MOUNT_PORT if is_ssl else DEFAULT_MOUNT_PORT)))

    logging.info('Mount reuse haproxy: fs=%s, dns=%s, path=%s, mp=%s, options=%s',
                 ctx.fs_id,
                 ctx.dns,
                 ctx.path,
                 ctx.mountpoint,
                 ctx.options)

    mount_nfs_directly(ctx.dns, ctx.path, ctx.mountpoint, ctx.options)
    if 'unmount_time' in state:
        state.pop('unmount_time')
        state['mountpoint'] = ctx.mountpoint
        if 'unmount_grace_period_sec' in ctx.options:
            state['unmount_grace_period_sec'] = ctx.options['unmount_grace_period_sec']
        elif 'unmount_grace_period_sec' in state:
            state.pop('unmount_grace_period_sec')
        cpfs_nfs_common.rewrite_state_file(state, STATE_FILE_DIR, ctx.dns)
        logging.info('rewrite state file:{}'.format(state))


def parse_arguments(args=None):
    """Parse arguments, return (mp_url, fsid, path, mountpoint, options)"""
    if args is None:
        args = sys.argv

    def usage(out=sys.stderr, exit_code=1):
        out.write('Usage: mount.cpfs-nfs [--version] [-h|--help] <mp_url> <mountpoint> [-o <options>]\n')
        sys.exit(exit_code)

    if '-h' in args[1:] or '--help' in args[1:]:
        usage(out=sys.stdout, exit_code=0)

    if '--version' in args[1:]:
        sys.stdout.write('%s Version: %s\n' % (args[0], get_version()))
        sys.exit(0)

    device = None
    mountpoint = None
    options = {}

    if len(args) > 1:
        device = args[1]
    if len(args) > 2:
        mountpoint = args[2]
    if len(args) > 4 and args[3] == '-o':
        options = parse_options(args[4])

    if not device or not mountpoint:
        usage()

    fix_options_vers(options)
    validate_options(options)

    match = MP_URL_PATTERN.match(device)
    if not match:
        fatal_error('Invalid mount device when parse mountpoint url: %s' % device)

    mp_url = match.group('url')
    if not mp_url.endswith('.cpfs.aliyuncs.com'):
        fatal_error('Invalid mountpoint url: only aliyun CPFS is supported')

    match = FS_ID_PATTERN.match(device)
    if not match:
        fatal_error('Invalid mount device: %s' % device)

    fs_id = match.group('fs_id')
    path = match.group('path') or '/'

    return mp_url, fs_id, path, mountpoint, options


def check_unsupported_options(options):
    for unsupported_option in UNSUPPORTED_OPTIONS:
        if unsupported_option in options:
            warn_message = 'The "%s" option is not supported and has been ignored, as aliyun-cpfs-utils relies on ' \
                           'a built-in trust store.' % unsupported_option
            sys.stderr.write('WARN: %s\n' % warn_message)
            logging.warning(warn_message)
            del options[unsupported_option]

# 1230 Requirement: we don't allow customer to mount a single mountpoint with tls and non-tls at the same time
# Please make sure the check is in the same lock with mount operation, otherwise the check may be invalid
def check_unsupported_operations(dns_name, options):
    state = cpfs_nfs_common.load_state_file(STATE_FILE_DIR, dns_name)
    if not state: # no mount point with same dns name exists before, no need to check
        return
    if 'unmount_time' in state: # the old mount point is unmounted, no need to check
        logging.info('Old mount point for [%s] is in unmounted state, no need to check', dns_name)
        return
    if 'config_file' not in state: 
        logging.info('Config file for [%s] does not exist in state, no need to check.', dns_name)
        return
    elif os.path.exists(state['config_file']):
        state['config_file'] = os.path.realpath(state['config_file'])
        old_is_ssl = is_sslconfig(state['config_file'])
        new_is_ssl = 'tls' in options
        if old_is_ssl != new_is_ssl:
            fatal_error('The mountpoint %s is already mounted with %s, mixing tls and non-tls is not supported in this version.' % (dns_name, 'tls' if old_is_ssl else 'non-tls'))

def main():
    cpfs_nfs_common.check_env()

    config = cpfs_nfs_common.read_config(CONFIG_FILE)
    cpfs_nfs_common.bootstrap_logging(config, LOG_DIR, LOG_FILE, CONFIG_SECTION)

    # fs_id: cpfs-123456ab12-123ab
    dns_name, fs_id, path, mountpoint, options = parse_arguments()

    logging.info('Mount request: version=%s options=%s', get_version(), options)
    check_unsupported_options(options)

    init_system = get_init_system()
    check_network_status(fs_id, init_system, options)

    ctx = MountContext(config, init_system, dns_name, fs_id, path, mountpoint, options)
    unmount_grace_period_sec = config.getint(WATCHDOG_CONFIG_SECTION, 'unmount_grace_period_sec',
                                            default=30, minvalue=10, maxvalue=600)

    if 'tls' in options:
        if TLS_ENABLED:
            with cpfs_nfs_common.lock_file(dns_name) as _:
                check_unsupported_operations(dns_name, options)
                if should_reuse_proxy(dns_name, int(options.get('mount_port', DEFAULT_TLS_MOUNT_PORT)), unmount_grace_period_sec, is_ssl=True):
                    mount_nfs_reuse_proxy(ctx, is_ssl=True)
                else:
                    mount_tls(ctx)
        else:
            fatal_error('TLS is not supported in the current version, please contact Aliyun NAS Team')
    elif 'direct' in options:
        nas_ip, backup_ip = cpfs_nfs_common.resolve_cpfs_dns(dns_name)
        logging.info('Resolved %s to nas_ip=%s, backup_ip=%s', dns_name, nas_ip, backup_ip)
        mount_nfs_directly(nas_ip, path, mountpoint, options)

    else:
        with cpfs_nfs_common.lock_file(dns_name) as _:
            check_unsupported_operations(dns_name, options)
            if should_reuse_proxy(dns_name, int(options.get('mount_port', DEFAULT_MOUNT_PORT)), unmount_grace_period_sec):
                mount_nfs_reuse_proxy(ctx, is_ssl=False)
            else:
                mount_nfs_proxy(ctx)


if '__main__' == __name__:
    main()
