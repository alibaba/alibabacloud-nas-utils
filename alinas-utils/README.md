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
| OpenSUSE Leap | `rpm`| `systemd` |
| SLES 15 | `rpm`| `systemd` |
| Debian 9 | `deb` | `systemd` |
| Debian 10 | `deb` | `systemd` |
| Ubuntu 16.04 | `deb` | `systemd` |
| Ubuntu 18.04 | `deb` | `systemd` |
| Ubuntu 20.04 | `deb` | `systemd` |

## Prerequisites

* `nfs-utils` (RHEL/CentOS/Aliyun Linux) or `nfs-common` (Debian/Ubuntu)
* `OpenSSL` 1.0.2+
* `Python` 3.4+
* `stunnel` 4.56+
* `haproxy` 1.5.0+
* `bind-utils`

## Installation

Other distributions require building the package from source and installing it.

- To build and install an RPM for CentOS/RedHat/Aliyun Linux:

```
$ sudo yum -y install git rpm-build make gcc-g++ # remove gcc-g++ here if you already installed a compatible version following GCC Version Requirements instruction
$ git clone https://github.com/alibaba/alibabacloud-nas-utils.git
$ cd alinas-utils
$ make rpm
$ sudo yum -y install build/aliyun-alinas-utils*generic.x86_64.rpm
```

- To build and install an RPM for OpenSUSE/SLES:

```
$ sudo zypper refresh
$ sudo zypper install -y git rpm-build make gcc-c++ # remove gcc-c++ here if you already installed a compatible version following GCC Version Requirements instruction
$ git clone https://github.com/alibaba/alibabacloud-nas-utils.git
$ cd alinas-utils
$ make rpm
$ sudo zypper --no-gpg-checks install -y build/aliyun-alinas-utils*generic.x86_64.rpm
```

- To build and install a Debian package for Debian/Ubuntu:

```
$ sudo apt-get update
$ sudo apt-get -y install binutils
$ cd alinas-utils
$ ./build-deb.sh
$ sudo apt-get -y install ./build/aliyun-alinas-utils*.deb
```

for alinas use git-lfs to download the [nas-agent_aarch64](src/alinas/nas_agent/nas-agent_aarch64)

```
$ git lfs pull
```

## Usage

### mount.alinas

`alinas-utils` includes a mount helper utility to Mount the NFS file system with encryption in transit enabled.

   * NFSv3 protocol

     ```plaintext
     sudo mount -t alinas -o tls,vers=3 file-system-id.region.nas.aliyuncs.com:/ /mnt
     ```
   * NFSv4.0 protocol

     ```plaintext
     sudo mount -t alinas -o tls,vers=4.0 file-system-id.region.nas.aliyuncs.com:/ /mnt
     ```

   The following table describes the parameters that you can configure in the mount command.

   **Note** 

   When you mount a file system, the NAS client automatically uses the parameters that can ensure the optimal performance. You do not need to add parameters on your own.

| **Parameter** | **Description** |
| --- | --- |
| *file-system-id.region.nas.aliyuncs.com*:*/* */mnt* | The command syntax is \<Domain name of a mount target>:\<Name of a shared directory>\<Path of a mount directory>. You must replace the domain name, directory name, and directory path with their actual values.  <lu><li> *Domain name of a mount target*: To view the domain name, perform the following steps: Log on to the NAS console. On the **File System List** page, find the file system that you want to manage and click **Manage** in the Actions column. On the **Mount Targets** tab, view the domain name of the mount target. </li><li> *Name of a shared directory*: specifies the root directory / or a subdirectory. If you specify a subdirectory such as /share, make sure that the subdirectory exists in the NAS file system. </li><li> *Path of a mount directory*: specifies a subdirectory such as /mnt of a Linux ECS instance. Make sure that the subdirectory exists in the local file system. </li></lu>|
| vers | The protocol version of the NFS file system.  <lu><li> vers=3: uses NFSv3 to mount the file system </li><li> vers=4: uses NFSv4.0 to mount the file system </li></lu>|
| tls | Enables TLS. |

### mount.cpfs-nfs

   ```shell
   sudo mount -t cpfs-nfs -o vers=3,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport file-system-id.region.cpfs.aliyuncs.com:/share/path /mnt
   ```

The following table describes the parameters in the mount command.

| **Parameter**| **Description**|
|-----|-----|
| file-system-id.region.cpfs.aliyuncs.com:/share/path /mnt | Indicates **<mount_address>** **<local_mount_path_on_current_server>**. Replace them with your actual values.  <lu><li> Mount address: The mount address of the export directory. In the File Storage NAS console, go to the file system list page. Click **Manage** next to the target file system to go to the **Protocol Service** page. In the **Actions** column, click **Export Directory** to go to the **Export Directory** panel and obtain the mount address. <br/> Example: `cpfs-196f91a8e58b****-195ceeac7b6ac****.cn-chengdu.cpfs.aliyuncs.com:/share/fileset`</li><li> Local path to mount on the current server: The root directory (/) or a subdirectory (for example, /mnt) of the Linux ECS instance. If it is a subdirectory, make sure the subdirectory exists.</li></lu>|
| vers | The file system version. CPFS supports mounting file systems only over the NFSv3 protocol.|
| Mount options | When you mount a file system, you can select multiple mount options. Separate the options with commas (,). The options are described as follows: <ul><li>rsize: Defines the size of the data block for reading data between the client and the file system. Recommended value: 1048576.</li><li>wsize: Defines the size of the data block for writing data between the client and the file system. Recommended value: 1048576.  **Note**  To change the I/O size parameters (rsize and wsize), use the maximum value (1048576) to avoid performance degradation. </li><li>hard: If Cloud Parallel File Storage (CPFS) is temporarily unavailable, local applications that use files on the file system stop and wait until the file system is back online. We recommend that you enable this parameter.</li><li>timeo: Specifies the time, in tenths of a second, that the CPFS-NFS client waits for a response before it retries sending a request to the file system. Recommended value: 600 (60 seconds).  **Note**  If you must change the timeout parameter (timeo), use a value of 150 or greater. The unit for the timeo parameter is tenths of a second, so a value of 150 represents 15 seconds. </li><li>retrans: The number of times the CPFS-NFS client retries a request. Recommended value: 2. </li><li>noresvport: Uses a new TCP port for network reconnection to ensure that the connection is not interrupted during network fault recovery. We recommend that you enable this parameter. **Important** We do not recommend using the soft option because it poses a data consistency risk. If you use the soft option, you are responsible for any associated risks.   Avoid setting any other mount options that are different from the default values. If you change the read or write buffer size or disable attribute caching, performance may degrade.</li><li>hp_config_dir: Uses user-specified ha proxy config path in case access to HAProxy configuration file path is limited by some security enhancement mechanisms like apparmor, selinux and etc. Default config path is under /var/run/cpfs.</li><li>unmount_grace_period_sec: Uses a user-specified unmount grace period (in seconds). The HA proxy will be reused for the same CPFS if an unmount and mount occur within this period. When switching between TLS and non-TLS modes, users should wait for the entire grace period before reconnecting.</li></ul> |

### aliyun-alinas-mount-watchdog

`alinas-utils` contains a watchdog process to monitor the health of TLS mounts. This process is managed by either
`upstart` or `systemd` depending on your Linux distribution, and is started automatically the first time an alinas file
system is mounted over TLS.

## Troubleshooting

If you run into a problem with alinas-utils, please open an issue in this repository. We can more easily assist you if
relevant logs are provided. You can find the log file at /var/log/aliyun/cpfs/mount.log.

## Upgrading haproxy for RHEL/CentOS

By default, when using the alinas mount helper with TLS, it enforces use of the Online Certificate Status Protocol (
OCSP) and certificate hostname checking. The alinas mount helper uses the `haproxy` program for its TLS functionality.
Please note that some versions of Linux do not include a version of `haproxy` that supports these TLS features by
default. When using such a Linux version, mounting an alinas file system using TLS will fail.

## License Summary

This code is made available under the MIT license.
