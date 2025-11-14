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
import json
import os
import re
import site
import sys

PACKAGE_PATH = "/opt/aliyun/cpfs/"
site.addsitedir(PACKAGE_PATH)

try:
    import cpfs_nfs_common
    from cpfs_nfs_common import fatal_error as log_error
except ImportError:
    sys.stderr.write("not found aliyun cpfs path: {}cpfs_nfs_commmon".format(PACKAGE_PATH))
    sys.exit(-1)

IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def log_info(msg):
    sys.stdout.write('%s\n' % msg)


def get_main_ip(dns):
    state_file = os.path.join(cpfs_nfs_common.STATE_FILE_DIR, dns)
    if not os.path.exists(state_file):
        log_info('Mount point %s is not mounted' % dns)
        return None
    config = json.load(open(state_file))
    if 'nas_ip' not in config:
        log_info('Mount point %s is not mounted' % dns)
        return None
    log_info('Mount point %s is mounted' % dns)
    return config['nas_ip']


def ping(dns):
    main_ip = get_main_ip(dns)
    if not main_ip:
        log_info('Try to resolve %s' % dns)
        main_ip, _ = cpfs_nfs_common.resolve_cpfs_dns(dns)
    log_info('Got server ip %s' % main_ip)
    os.execvp('ping', ['ping', main_ip])


def domain(dns):
    match = cpfs_nfs_common.LOCAL_DNS_PATTERN.match(dns)
    if not match:
        msg = 'Invalid mount point domain name format: %s' % dns
        log_error(msg, ValueError)

    mnt_id = match.group('mnt_id')
    if mnt_id is None or '-' not in mnt_id.strip('-'):
        msg = 'Invalid mount point id: %s' % mnt_id
        log_error(msg, ValueError)

    region = match.group('region')
    if region is None or '-' not in region.strip('-'):
        msg = 'error: Invalid region: %s' % region
        log_error(msg, ValueError)
    return dns


def main():
    parser = argparse.ArgumentParser(description='alibaba cloud cpfs nfs client tool.')
    parser.add_argument('-d', '--domain', dest='domain', type=domain, required=True,
                        help='mount point domain name')

    args = parser.parse_args()
    ping(args.domain)


if '__main__' == __name__:
    main()
