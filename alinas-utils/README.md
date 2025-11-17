# alinas-utils

Utilities for Aliyun Alinas File System (alinas)

The `alinas-utils` package has been verified against the following Linux distributions:

| Distribution | Package Type | `init` System |
| ------------ | ------------ | ------------- |
| Aliyun Linux 3.2104 | `rpm` | `systemd` |
| Aliyun Linux 2.1903 | `rpm` | `systemd` |
| CentOS 7 | `rpm` | `systemd` |
| CentOS 8 | `rpm` | `systemd` |
| RHEL 7 | `rpm`| `systemd` |
| RHEL 8 | `rpm`| `systemd` |
| SUSE 15 | `rpm`| `systemd` |
| Debian 9 | `deb` | `systemd` |
| Debian 10 | `deb` | `systemd` |
| Ubuntu 16.04 | `deb` | `systemd` |
| Ubuntu 18.04 | `deb` | `systemd` |
| Ubuntu 20.04 | `deb` | `systemd` |

## Prerequisites

* `nfs-utils` (RHEL/CentOS/aliyun Linux) or `nfs-common` (Debian/Ubuntu)
* OpenSSL 1.0.2+
* Python 3.4+
* `stunnel` 4.56+

## Installation

Other distributions require building the package from source and installing it.

- To build and install an RPM for CentOS and RedHat:

```
$ sudo yum -y install rpm-build make
$ cd alinas-utils
$ make rpm
$ sudo yum -y install build/aliyun-alinas-utils*noarch.rpm
```

- To build and install a Debian package:

```
$ sudo apt-get update
$ sudo apt-get -y install binutils
$ cd alinas-utils
$ ./build-deb.sh
$ sudo apt-get -y install ./build/aliyun-alinas-utils*noarch.deb
```

for alinas use git-lfs to download the [nas-agent_aarch64](src/alinas/nas_agent/nas-agent_aarch64)
```
$ git lfs pull
```

## Usage

### mount.alinas

`alinas-utils` includes a mount helper utility to simplify mounting and using alinas file systems.

To mount with the recommended default options, simply run:

```
$ sudo mount -t alinas file-system-mountpoint alinas-mount-point/
```

To mount automatically with recommended options, add an `/etc/fstab` entry like:

```
file-system-mountpoint local-mount-point alinas _netdev 0 0
```

To mount over TLS, simply add the `tls` option:

```
$ sudo mount -t alinas -o tls file-system-mountpoint alinas-mount-point/
```

To mount over TLS automatically, add an `/etc/fstab` entry like:

```
file-system-mountpoint local-mount-point alinas _netdev,tls 0 0
```

#### aliyun-alinas-mount-watchdog

`alinas-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either `upstart` or `systemd` depending on your Linux distribution, and is started automatically the first time an alinas file system is mounted over TLS.

## Troubleshooting

If you run into a problem with alinas-utils, please open an issue in this repository. We can more easily assist you if relevant logs are provided. You can find the log file at /var/log/aliyun/cpfs/mount.log.

## Upgrading haproxy for RHEL/CentOS

By default, when using the alinas mount helper with TLS, it enforces use of the Online Certificate Status Protocol (OCSP) and certificate hostname checking. The alinas mount helper uses the `haproxy` program for its TLS functionality. Please note that some versions of Linux do not include a version of `haproxy` that supports these TLS features by default. When using such a Linux version, mounting an alinas file system using TLS will fail.

## License Summary

This code is made available under the MIT license.
