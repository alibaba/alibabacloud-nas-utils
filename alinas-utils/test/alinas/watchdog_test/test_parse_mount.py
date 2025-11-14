#
# Copyright 2020-2021 Alibaba Group Holding Limited
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from configparser import ConfigParser

import watchdog

def test_parse_hybrid_mount():
    config = ConfigParser()
    safe_config = watchdog.SafeConfig(config, None, None)
    task = watchdog.UpdateMountEntitiesTask(safe_config, None, None)
    hybrid_mount = watchdog.Mount._make([
        "jfkakj:abcdefg-jdka.cn-hangzhou.nas.aliyuncs.com:/",
        "/mnt",
        "alifuse.aliyun-alinas-efc",
        "rw",
        "0",
        "0"
    ])
    res = task._parse_mount(hybrid_mount)
    assert res is not None
    mount_uuid, fsid, fstype, region, path = res
    assert mount_uuid == 'jfkakj'
    assert fsid == 'abcdefg'
    assert fstype == 'hybrid'
    assert region == 'cn-hangzhou'
    assert path == '/'

def test_parse_extreme_mount():
    config = ConfigParser()
    safe_config = watchdog.SafeConfig(config, None, None)
    task = watchdog.UpdateMountEntitiesTask(safe_config, None, None)
    extreme_mount = watchdog.Mount._make([
        "jfkakj:abcdefg-jdka.cn-hangzhou.extreme.nas.aliyuncs.com:/",
        "/mnt",
        "alifuse.aliyun-alinas-efc",
        "rw",
        "0",
        "0"
    ])
    res = task._parse_mount(extreme_mount)
    assert res is not None
    mount_uuid, fsid, fstype, region, path = res
    assert mount_uuid == 'jfkakj'
    assert fsid == 'extreme-abcdefg'
    assert fstype == 'extreme'
    assert region == 'cn-hangzhou'
    assert path == '/'

def test_parse_cpfs_mount():
    config = ConfigParser()
    safe_config = watchdog.SafeConfig(config, None, None)
    task = watchdog.UpdateMountEntitiesTask(safe_config, None, None)
    cpfs_mount = watchdog.Mount._make([
        "jfkakj:cpfs-0092c983e790jfka-dfask1babadb6863n.cn-hangzhou.cpfs.aliyuncs.com:/share",
        "/mnt",
        "alifuse.aliyun-alinas-efc",
        "rw",
        "0",
        "0"
    ])
    res = task._parse_mount(cpfs_mount)
    assert res is not None
    mount_uuid, fsid, fstype, region, path = res
    assert mount_uuid == 'jfkakj'
    assert fsid == 'cpfs-0092c983e790jfka'
    assert fstype == 'cpfs'
    assert region == 'cn-hangzhou'
    assert path == '/share'

def test_parse_vpc_cpfs_mount():
    config = ConfigParser()
    safe_config = watchdog.SafeConfig(config, None, None)
    task = watchdog.UpdateMountEntitiesTask(safe_config, None, None)
    vpc_cpfs_mount = watchdog.Mount._make([
        "jfkakj:cpfs-0092c983e790jfka-vpc-b6863n.cn-hangzhou.cpfs.aliyuncs.com:/",
        "/mnt",
        "alifuse.aliyun-alinas-efc",
        "rw",
        "0",
        "0"
    ])
    res = task._parse_mount(vpc_cpfs_mount)
    assert res is not None
    mount_uuid, fsid, fstype, region, path = res
    assert mount_uuid == 'jfkakj'
    assert fsid == 'cpfs-0092c983e790jfka'
    assert fstype == 'cpfs'
    assert region == 'cn-hangzhou'
    assert path == '/'

def test_parse_dcpfs_mount():
    config = ConfigParser()
    safe_config = watchdog.SafeConfig(config, None, None)
    task = watchdog.UpdateMountEntitiesTask(safe_config, None, None)
    dcpfs_mount = watchdog.Mount._make([
        "jfkakj:dcpfs-0092c983e790jfka-dfask1babadb6863n.cn-hangzhou.cpfs.aliyuncs.com:/",
        "/mnt",
        "alifuse.aliyun-alinas-efc",
        "rw",
        "0",
        "0"
    ])
    res = task._parse_mount(dcpfs_mount)
    assert res is not None
    mount_uuid, fsid, fstype, region, path = res
    assert mount_uuid == 'jfkakj'
    assert fsid == 'dcpfs-0092c983e790jfka'
    assert fstype == 'dcpfs'
    assert region == 'cn-hangzhou'
    assert path == '/'
