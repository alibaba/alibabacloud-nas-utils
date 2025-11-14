#!/usr/bin/env python3
#
# Copyright 2021-2022 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import argparse
import os
import site
import sys
import re
import subprocess
import logging
from collections import namedtuple
import time

PACKAGE_PATH = "/opt/aliyun/cpfs/"
site.addsitedir(PACKAGE_PATH)


try:
    import cpfs_nfs_common
    from cpfs_nfs_common import fatal_error
except ImportError:
    sys.stderr.write("not found aliyun cpfs path: {}cpfs_nfs_commmon".format(PACKAGE_PATH))
    sys.exit(-1)

CONFIG_FILE = '/etc/aliyun/cpfs/cpfs-utils.conf'
CONFIG_SECTION = 'client-tool'
LOG_DIR = '/var/log/aliyun/cpfs'
LOG_FILE = 'cpfs-client-tool.log'
Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])
STATE_FILE_DIR = '/var/run/cpfs'

LOCAL_DNS_PATTERN = re.compile('^(?P<mnt_id>[-0-9a-zA-Z]+).(?P<region>[-0-9a-zA-Z]+).cpfs.aliyuncs.com')
IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def get_haproxy_pid(local_dns):
    try:
        cmd = ("ps -ef | grep haproxy | grep -vw grep | grep %s | awk '{print $2}'" % local_dns)
        return subprocess.check_output(cmd, shell=True)
    except:
        fatal_error('Failed to get proxy pid: {0}'.format(local_dns)) 


def wait_for_haproxy_ready(local_dns, timeout=30):
    deadline = time.time() + timeout 

    sleep_time = 0.001
    while time.time() < deadline:
        try: 
            pid_out = get_haproxy_pid(local_dns)
            pid = int(pid_out.decode('utf-8').split('\n')[0])
            if cpfs_nfs_common.is_pid_running(pid):
                return 
        except:
            time.sleep(sleep_time)
            sleep_time *= 2
            logging.info('wait time: {}'.format(sleep_time))
    
    fatal_error('Cannot start haproxy for {}'.format(local_dns))


def update_alicpfs_server(local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server):
    nfs_mounts = cpfs_nfs_common.get_current_local_nfs_mounts()
    if local_dns in nfs_mounts:
        pid_out = get_haproxy_pid(local_dns)
        pid = int(pid_out.decode('utf-8').split('\n')[0])
        if cpfs_nfs_common.is_pid_running(pid):
            cpfs_nfs_common.update_haproxy_config_file(local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
            try:
                cpfs_nfs_common.kill_proxy(pid)
                wait_for_haproxy_ready(local_dns)
                logging.info('update aliyun cpfs server success, local_dns=%s, old_primary_server=%s, old_backup_server=%s, new_primary_server=%s, new_backup_server=%s',
                local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
            except:
                fatal_error('Failed to kill haproxy pid {0}'.format(pid))
    else:
        logging.warning('No mount found for "%s"', local_dns)

def get_haproxy_server(local_dns, state_file_dir=STATE_FILE_DIR):
    primary_server = ''
    backup_server = ''
    haproxy_config_file = os.path.join(state_file_dir, 'haproxy-config.%s' % local_dns)
    try:
        with open(haproxy_config_file, 'r') as f:
            for line in f:
                if 'cpfs_primary' in line:
                    primary_server = line.split(':2049')[0].split('cpfs_primary ')[1].strip()
                if 'cpfs_backup' in line:
                    backup_server = line.split(':2049')[0].split('cpfs_backup ')[1].strip()
        return primary_server, backup_server
    except:
        fatal_error('get haproxy server failed, domain is:{}'.format(local_dns))
                    

def change_alicpfs_server(local_dns):
    nfs_mounts = cpfs_nfs_common.get_current_local_nfs_mounts()
    if local_dns in nfs_mounts:
        old_primary_server, old_backup_server = get_haproxy_server(local_dns)
        new_primary_server, new_backup_server = cpfs_nfs_common.resolve_cpfs_dns(local_dns)
        update_alicpfs_server(local_dns, old_primary_server, old_backup_server, new_primary_server, new_backup_server)
        logging.info('change aliyun cpfs server automatically, domain:{}'.format(local_dns))


def check_server_in_proxy_config(config, key, server):
    with open(config, 'r') as f:
        for line in f:
            if key in line:
                if server not in line:
                    fatal_error('Invalid server: {}, please check haproxy config {}'.format(server, line))

def check_domain(domain):
    match = LOCAL_DNS_PATTERN.match(domain)
    if not match:
        fatal_error('Invalid dns: %s' % domain)

    mnt_id = match.group('mnt_id')
    if mnt_id is None:
        fatal_error('Invalid mount point id: %s' % mnt_id)

    region = match.group('region')
    if region is None:
        fatal_error('Invalid region: %s' % region)


def check_arguments(args):
    check_domain(args.domain)

    haproxy_config_file = os.path.join(STATE_FILE_DIR, 'haproxy-config.%s' % args.domain)
    match = IP_PATTERN.match(args.old_primary_server)
    if not match:
        fatal_error('Invalid old primary server: %s' % args.old_primary_server)

    check_server_in_proxy_config(haproxy_config_file, 'cpfs_primary', args.old_primary_server) 

    match = IP_PATTERN.match(args.old_backup_server)
    if not match:
        fatal_error('Invalid old backup server: %s' % args.old_backup_server)

    check_server_in_proxy_config(haproxy_config_file, 'cpfs_backup', args.old_backup_server) 

    match = IP_PATTERN.match(args.new_primary_server)
    if not match:
        fatal_error('Invalid new primary server: %s' % args.new_primary_server)
    ret = cpfs_nfs_common.is_server_ready(args.new_primary_server, 2049)
    if not ret:
        fatal_error('Invalid new primary server: %s' % args.new_primary_server)

    match = IP_PATTERN.match(args.new_backup_server)
    if not match:
        fatal_error('Invalid new backup server: %s' % args.new_backup_server)
    ret = cpfs_nfs_common.is_server_ready(args.new_backup_server, 2049)
    if not ret:
        fatal_error('Invalid new backup server: %s' % args.new_backup_server)

def main():
    cpfs_nfs_common.check_env()

    config = cpfs_nfs_common.read_config(CONFIG_FILE)
    cpfs_nfs_common.bootstrap_logging(config, LOG_DIR, LOG_FILE, CONFIG_SECTION)

    parser = argparse.ArgumentParser(
        description='alibaba cloud cpfs nfs client switch connection server tool.')

    sw_parser = parser.add_subparsers(dest='action', title='action to load balance')
    domain_args = argparse.ArgumentParser(add_help=False)
    domain_args.add_argument('--domain', dest='domain', type=str, required=True,
                             help='mount point domain name')

    # manual switch
    manual_parser = sw_parser.add_parser('manual', parents=[domain_args], help='switch server manually')
    manual_parser.add_argument('--old_primary_server', type=str,
                        help='old primary server', required=True)
    manual_parser.add_argument('--old_backup_server', type=str,
                            help='old backup server', required=True)
    manual_parser.add_argument('--new_primary_server', type=str,
                            help='new primary server', required=True)
    manual_parser.add_argument('--new_backup_server', type=str,
                            help='new backup server', required=True)

    # auto switch
    auto_parser = sw_parser.add_parser('auto', parents=[domain_args], help='switch server automatically by resolve dns, primary server switching is not guaranteed')

    args = parser.parse_args()
    
    if args.action is None:
        parser.print_help()
        sys.exit(1)
    
    elif args.action == 'manual':
        check_arguments(args)
        update_alicpfs_server(args.domain, args.old_primary_server, args.old_backup_server, args.new_primary_server, args.new_backup_server)
    elif args.action == 'auto':
        check_domain(args.domain)
        change_alicpfs_server(args.domain)
        

if '__main__' == __name__:
    main()
