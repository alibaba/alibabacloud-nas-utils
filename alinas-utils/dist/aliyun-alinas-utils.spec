#
# Copyright 2021-2022 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

%global with_systemd 1
%global python_requires python3
%global platform %{dist}
%global __strip /bin/true

%undefine __brp_mangle_shebangs

Name      : aliyun-alinas-utils
Version   : %{version}
Release   : %{build_id}%{platform}
Summary   : This package provides utilities for simplifying the use of alinas and cpfs file systems

Group     : aliyun/Tools
License   : MIT
URL       : https://www.aliyun.com/product/nas

Packager  : aliyun.com, Inc. <https://www.aliyun.com/>
Vendor    : aliyun.com

BuildArch : %{arch}

Requires  : nfs-utils
Requires  : haproxy >= 1.5.0
Requires  : stunnel >= 4.56
Requires  : openssl >= 1.0.2
Requires  : bind-utils
Requires  : iproute
Requires  : %{python_requires}

%if %{with_systemd}
BuildRequires    : systemd
%{?systemd_requires}
%else
Requires(post)   : /sbin/chkconfig
Requires(preun)  : /sbin/service /sbin/chkconfig
Requires(postun) : /sbin/service
%endif

Source    : %{name}.tar.gz

%description
This package provides utilities for simplifying the use of alinas and cpfs file systems

%prep
%setup -n %{name}

%install
mkdir -p %{buildroot}%{_sysconfdir}/aliyun/cpfs
mkdir -p %{buildroot}%{_sysconfdir}/aliyun/alinas
%if %{with_systemd}
mkdir -p %{buildroot}%{_unitdir}
install -p -m 644 %{_builddir}/%{name}/dist/cpfs/aliyun-cpfs-mount-watchdog.service %{buildroot}%{_unitdir}/aliyun-cpfs-mount-watchdog.service
install -p -m 644 %{_builddir}/%{name}/dist/alinas/aliyun-alinas-mount-watchdog.service %{buildroot}%{_unitdir}/aliyun-alinas-mount-watchdog.service
%else
mkdir -p %{buildroot}%{_sysconfdir}/init
install -p -m 644 %{_builddir}/%{name}/dist/cpfs/aliyun-cpfs-mount-watchdog.conf %{buildroot}%{_sysconfdir}/init/aliyun-cpfs-mount-watchdog.conf
install -p -m 644 %{_builddir}/%{name}/dist/alinas/aliyun-alinas-mount-watchdog.conf %{buildroot}%{_sysconfdir}/init/aliyun-alinas-mount-watchdog.conf
%endif

mkdir -p %{buildroot}/sbin
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}%{_localstatedir}/log/aliyun/alinas
mkdir -p %{buildroot}%{_localstatedir}/log/aliyun/cpfs
mkdir -p %{buildroot}/opt/aliyun/cpfs
mkdir -p %{buildroot}/opt/aliyun/cpfs/tools
mkdir -p %{buildroot}/usr/local/nas-agent
mkdir -p %{buildroot}/etc/nas-agent

install -p -m 644 %{_builddir}/%{name}/dist/alinas/alinas-utils.conf %{buildroot}%{_sysconfdir}/aliyun/alinas/alinas-utils.conf
install -p -m 444 %{_builddir}/%{name}/dist/alinas-utils.crt %{buildroot}%{_sysconfdir}/aliyun/alinas/alinas-utils.crt
install -p -m 755 %{_builddir}/%{name}/src/alinas/mount_alinas/__init__.py %{buildroot}/sbin/mount.alinas
install -p -m 755 %{_builddir}/%{name}/src/alinas/mount_alinas/umount.efc.sh %{buildroot}/sbin/umount.alifuse.aliyun-alinas-efc
install -p -m 755 %{_builddir}/%{name}/src/alinas/mount_alinas/umount.efc.sh %{buildroot}/sbin/umount.alifuse.aliyun-alinas-eac
install -p -m 755 %{_builddir}/%{name}/src/alinas/mount_alinas/umount.efc.sh %{buildroot}/sbin/umount.fuse.aliyun-alinas-efc
install -p -m 755 %{_builddir}/%{name}/src/alinas/watchdog/__init__.py %{buildroot}/usr/bin/aliyun-alinas-mount-watchdog

install -p -m 644 %{_builddir}/%{name}/dist/cpfs/cpfs-utils.conf %{buildroot}%{_sysconfdir}/aliyun/cpfs/cpfs-utils.conf
install -p -m 444 %{_builddir}/%{name}/dist/alinas-utils.crt %{buildroot}%{_sysconfdir}/aliyun/cpfs/alinas-utils.crt
install -p -m 755 %{_builddir}/%{name}/src/cpfs/mount_cpfs/__init__.py %{buildroot}/sbin/mount.cpfs-nfs
install -p -m 755 %{_builddir}/%{name}/src/cpfs/watchdog/__init__.py %{buildroot}/usr/bin/aliyun-cpfs-mount-watchdog
install -p -m 755 %{_builddir}/%{name}/src/cpfs/cpfs_nfs_common/__init__.py %{buildroot}/opt/aliyun/cpfs/cpfs_nfs_common.py
install -p -m 755 %{_builddir}/%{name}/src/cpfs/cpfs_nfs_tool/cpfsu.sh %{buildroot}/usr/sbin/cpfsu
install -p -m 755 %{_builddir}/%{name}/src/cpfs/cpfs_nfs_tool/ping.py %{buildroot}/opt/aliyun/cpfs/tools/ping
install -p -m 755 %{_builddir}/%{name}/src/cpfs/cpfs_nfs_tool/switch_server.py %{buildroot}/opt/aliyun/cpfs/tools/switch_server

install -p -m 755 %{_builddir}/%{name}/src/alinas/nas_agent/nas-agent_%{arch} %{buildroot}/usr/local/nas-agent/nas-agent
install -p -m 755 %{_builddir}/%{name}/src/alinas/nas_agent/ca-bundle.crt %{buildroot}/usr/local/nas-agent/ca-bundle.crt
install -p -m 755 %{_builddir}/%{name}/src/alinas/nas_agent/identifier-generator %{buildroot}/usr/local/nas-agent/identifier-generator
install -p -m 755 %{_builddir}/%{name}/src/alinas/nas_agent/aliyun-alinas-nfsiostat %{buildroot}/sbin/aliyun-alinas-nfsiostat
install -p -m 644 %{_builddir}/%{name}/dist/nas_agent/nas-agent-commands-local.json %{buildroot}%{_sysconfdir}/aliyun/alinas/nas-agent-commands-local.json
install -p -m 644 %{_builddir}/%{name}/dist/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json %{buildroot}%{_sysconfdir}/aliyun/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json

%files
%defattr(-,root,root,-)
%if %{with_systemd}
%{_unitdir}/aliyun-cpfs-mount-watchdog.service
%{_unitdir}/aliyun-alinas-mount-watchdog.service
%else
%config(noreplace) %{_sysconfdir}/init/aliyun-cpfs-mount-watchdog.conf
%config(noreplace) %{_sysconfdir}/init/aliyun-alinas-mount-watchdog.conf
%endif
%{_sysconfdir}/aliyun/cpfs/alinas-utils.crt
%{_sysconfdir}/aliyun/alinas/alinas-utils.crt
%{_sysconfdir}/aliyun/alinas/nas-agent-commands-local.json
/sbin/mount.alinas
/sbin/umount.alifuse.aliyun-alinas-efc
/sbin/umount.alifuse.aliyun-alinas-eac
/sbin/umount.fuse.aliyun-alinas-efc
/sbin/aliyun-alinas-nfsiostat
/sbin/mount.cpfs-nfs
/opt/aliyun/cpfs/cpfs_nfs_common.py
%exclude /opt/aliyun/cpfs/cpfs_nfs_common.pyc
%exclude /opt/aliyun/cpfs/cpfs_nfs_common.pyo
/usr/sbin/cpfsu
/opt/aliyun/cpfs/tools/ping
/opt/aliyun/cpfs/tools/switch_server
/usr/bin/aliyun-cpfs-mount-watchdog
/usr/bin/aliyun-alinas-mount-watchdog

/var/log/aliyun

%config(noreplace) %{_sysconfdir}/aliyun/cpfs/cpfs-utils.conf
%config(noreplace) %{_sysconfdir}/aliyun/alinas/alinas-utils.conf
%config(noreplace) %{_sysconfdir}/aliyun/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json

/usr/local/nas-agent
/etc/nas-agent

%if %{with_systemd}
%post
%systemd_post aliyun-cpfs-mount-watchdog.service
%systemd_post aliyun-alinas-mount-watchdog.service
if [ "$1" = 1 ]; then
    ps -eww -o pid,cmd,args | grep -v grep | grep haproxy | grep cpfs.aliyuncs.com
    if [ $? -eq 0 ]; then
        /bin/systemctl enable aliyun-cpfs-mount-watchdog.service &> /dev/null || true
        /bin/systemctl start aliyun-cpfs-mount-watchdog.service &> /dev/null || true
    fi
fi

%preun
%systemd_preun aliyun-cpfs-mount-watchdog.service
%systemd_preun aliyun-alinas-mount-watchdog.service

%postun
%systemd_postun_with_restart aliyun-cpfs-mount-watchdog.service
%systemd_postun_with_restart aliyun-alinas-mount-watchdog.service

if [ $1 -eq 1 ]; then
    systemctl is-active --quiet aliyun-alinas-mount-watchdog.service
    if [ $? -ne 0 ]; then
        # 在多租容器场景下进行rpm升级，需要用kill来重启watchdog
        ps -eww -o pid,cmd,args | grep aliyun-alinas-mount-watchdog | grep -v grep | awk '{print $1}' | xargs -I {} kill -9 {}
    fi
fi

ps -eww -o pid,cmd,args | grep /usr/local/nas-agent/nas-agent | grep -v grep | awk '{print $1}' | xargs -I {} kill -9 {}

if [ $1 -eq 0 ]; then
    rm -rf /usr/local/nas-agent
    rm -rf /etc/nas-agent
    rm -rf /etc/aliyun/alinas/nas-agent-commands-remote
    rm -f /etc/aliyun/alinas/last-mountpoint
fi

%else

%post
if [ "$1" = 1 ]; then
    ps -eww -o pid,cmd,args | grep -v grep | grep haproxy | grep cpfs.aliyuncs.com
    if [ $? -eq 0 ]; then
        /sbin/restart aliyun-cpfs-mount-watchdog.service &> /dev/null || true
    fi
fi

%preun
if [ $1 -eq 0 ]; then
   /sbin/stop aliyun-cpfs-mount-watchdog &> /dev/null || true
   /sbin/stop aliyun-alinas-mount-watchdog &> /dev/null || true
fi

%postun
if [ $1 -eq 1 ]; then
    /sbin/restart aliyun-cpfs-mount-watchdog &> /dev/null || true
    /sbin/restart aliyun-alinas-mount-watchdog &> /dev/null || true
fi

ps -eww -o pid,cmd,args | grep /usr/local/nas-agent/nas-agent | grep -v grep | awk '{print $1}' | xargs -I {} kill -9 {}

if [ $1 -eq 0 ]; then
    rm -rf /usr/local/nas-agent
    rm -rf /etc/nas-agent
    rm -rf /etc/aliyun/alinas/nas-agent-commands-remote
    rm -f /etc/aliyun/alinas/last-mountpoint
fi

%endif

%clean
