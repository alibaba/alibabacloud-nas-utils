#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_cpfs
import pytest


def test_get_default_nfs_mount_options():
    nfs_opts = mount_cpfs.get_nfs_mount_options({})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'vers=4.1' not in nfs_opts
    assert 'vers=3' in nfs_opts
    assert 'minorversion=1' not in nfs_opts
    assert 'nfsvers=4.1' not in nfs_opts
    assert 'rsize=1048576' in nfs_opts
    assert 'wsize=1048576' in nfs_opts
    assert 'hard' in nfs_opts
    assert 'timeo=600' in nfs_opts
    assert 'retrans=2' in nfs_opts


def test_nfsvers_to_vers():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'nfsvers': 4.1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'nfsvers=4.1' not in nfs_opts
    assert 'vers=4.1' in nfs_opts
    assert 'minorversion=1' in nfs_opts


def test_override_nfs_version_alternate_option():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'vers': 4.1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'nfsvers=4.0' not in nfs_opts
    assert 'nfsvers=4.1' not in nfs_opts
    assert 'vers=4.1' in nfs_opts
    assert 'minorversion=1' in nfs_opts


def test_override_rsize():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'rsize': 1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'rsize=1' in nfs_opts
    assert 'rsize=1048576' not in nfs_opts


def test_override_wsize():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'wsize': 1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'wsize=1' in nfs_opts
    assert 'wsize=1048576' not in nfs_opts


def test_override_recovery_soft():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'soft': None})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'soft' in nfs_opts
    assert 'soft=' not in nfs_opts
    assert 'hard' not in nfs_opts


def test_override_timeo():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'timeo': 1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'timeo=1' in nfs_opts
    assert 'timeo=600' not in nfs_opts


def test_override_retrans():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'retrans': 1})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'retrans=1' in nfs_opts
    assert 'retrans=2' not in nfs_opts


def test_tls_without_proxy(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.get_nfs_mount_options({'tls': None})
        nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert '"tls" without "proxy"' in err


def test_tls():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'tls': None, 'proxy': '127.0.0.1', 'proxy_port': 9000})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'tls' not in nfs_opts
    assert 'vers=4.0' not in nfs_opts
    assert 'vers=3' in nfs_opts
    assert 'minorversion=0' not in nfs_opts
    assert 'nfsvers=4.0' not in nfs_opts
    assert 'rsize=1048576' in nfs_opts
    assert 'wsize=1048576' in nfs_opts
    assert 'hard' in nfs_opts
    assert 'timeo=600' in nfs_opts
    assert 'retrans=2' in nfs_opts
    assert 'port=9000' in nfs_opts
    assert 'mountport=9000' in nfs_opts


def test_proxy_without_proxyport(capsys):
    with pytest.raises(SystemExit) as ex:
        nfs_opts = mount_cpfs.get_nfs_mount_options({'proxy': '127.0.0.1'})
        nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert ex.value.code != 0

    out, err = capsys.readouterr()
    assert '"proxy" without "proxy_port"' in err


def test_proxy_with_port(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_cpfs.get_nfs_mount_options({'proxy': '127.0.0.1', 'port': 3030, 'proxy_port': 8888})
        nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'used with "direct"' in err


def test_proxy():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'proxy': '127.0.0.1', 'proxy_port': 8000})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'port=8000' in nfs_opts
    assert 'proxy_port=8000' not in nfs_opts
    assert 'proxy=127.0.0.1' not in nfs_opts


def test_proxy_v3():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'proxy': '127.0.0.1', 'proxy_port': 8000, 'vers': 3})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'port=8000' in nfs_opts
    assert 'mountport=8000' in nfs_opts
    assert 'proxy_port=8000' not in nfs_opts
    assert 'proxy=127.0.0.1' not in nfs_opts
    assert 'nolock' in nfs_opts
    assert 'tcp' in nfs_opts


def test_bare_v3():
    nfs_opts = mount_cpfs.get_nfs_mount_options({'vers': 3})
    nfs_opts = mount_cpfs.serialize_options(nfs_opts)

    assert 'port=2049' in nfs_opts
    assert 'mountport=2049' in nfs_opts
    assert 'nolock' in nfs_opts
    assert 'tcp' in nfs_opts
