#!/usr/bin/env sh
#
# Copyright 2020-2021 Alibaba Group Holding Limited
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

set -eux

VERSION_NUM=$(cat VERSION)
GIT_CIMMIT_TIMESTAMP=$(git log -1 --format=%ci | awk '{print $1$2}' | tr -d '\-:')
GIT_COMMIT_ID=$(git rev-parse --short=6 HEAD)
ARCH=$(uname -m)
FULL_VERSION=${VERSION_NUM}.${GIT_CIMMIT_TIMESTAMP}.${GIT_COMMIT_ID}

BASE_DIR=$(pwd)
BUILD_ROOT=${BASE_DIR}/build/debbuild

echo 'Cleaning deb build workspace'
rm -rf ${BUILD_ROOT}
mkdir -p ${BUILD_ROOT}

echo 'Creating application directories'
mkdir -p ${BUILD_ROOT}/etc/aliyun/cpfs
mkdir -p ${BUILD_ROOT}/etc/aliyun/alinas
mkdir -p ${BUILD_ROOT}/etc/init/
mkdir -p ${BUILD_ROOT}/etc/systemd/system
mkdir -p ${BUILD_ROOT}/sbin
mkdir -p ${BUILD_ROOT}/usr/bin
mkdir -p ${BUILD_ROOT}/usr/sbin
mkdir -p ${BUILD_ROOT}/var/log/aliyun/cpfs
mkdir -p ${BUILD_ROOT}/var/log/aliyun/alinas
mkdir -p ${BUILD_ROOT}/opt/aliyun/cpfs
mkdir -p ${BUILD_ROOT}/opt/aliyun/cpfs/tools
mkdir -p ${BUILD_ROOT}/usr/local/nas-agent
mkdir -p ${BUILD_ROOT}/etc/nas-agent

echo 'Copying application files'
install -p -m 644 dist/cpfs/aliyun-cpfs-mount-watchdog.conf ${BUILD_ROOT}/etc/init
install -p -m 644 dist/alinas/aliyun-alinas-mount-watchdog.conf ${BUILD_ROOT}/etc/init
install -p -m 644 dist/cpfs/aliyun-cpfs-mount-watchdog.service ${BUILD_ROOT}/etc/systemd/system
install -p -m 644 dist/alinas/aliyun-alinas-mount-watchdog.service ${BUILD_ROOT}/etc/systemd/system
install -p -m 444 dist/alinas-utils.crt ${BUILD_ROOT}/etc/aliyun/cpfs
install -p -m 444 dist/alinas-utils.crt ${BUILD_ROOT}/etc/aliyun/alinas
install -p -m 644 dist/cpfs/cpfs-utils.conf ${BUILD_ROOT}/etc/aliyun/cpfs
install -p -m 644 dist/alinas/alinas-utils.conf ${BUILD_ROOT}/etc/aliyun/alinas
install -p -m 644 dist/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json ${BUILD_ROOT}/etc/aliyun/alinas
install -p -m 755 src/cpfs/mount_cpfs/__init__.py ${BUILD_ROOT}/sbin/mount.cpfs-nfs
install -p -m 755 src/alinas/mount_alinas/__init__.py ${BUILD_ROOT}/sbin/mount.alinas
install -p -m 755 src/alinas/mount_alinas/umount.efc.sh ${BUILD_ROOT}/sbin/umount.alifuse.aliyun-alinas-eac
install -p -m 755 src/alinas/mount_alinas/umount.efc.sh ${BUILD_ROOT}/sbin/umount.alifuse.aliyun-alinas-efc
install -p -m 755 src/alinas/mount_alinas/umount.efc.sh ${BUILD_ROOT}/sbin/umount.fuse.aliyun-alinas-efc
install -p -m 755 src/alinas/watchdog/__init__.py ${BUILD_ROOT}/usr/bin/aliyun-alinas-mount-watchdog
install -p -m 755 src/cpfs/watchdog/__init__.py ${BUILD_ROOT}/usr/bin/aliyun-cpfs-mount-watchdog
install -p -m 755 src/cpfs/cpfs_nfs_common/__init__.py ${BUILD_ROOT}/opt/aliyun/cpfs/cpfs_nfs_common.py
install -p -m 755 src/cpfs/cpfs_nfs_tool/cpfsu.sh ${BUILD_ROOT}/usr/sbin/cpfsu
install -p -m 755 src/cpfs/cpfs_nfs_tool/ping.py ${BUILD_ROOT}/opt/aliyun/cpfs/tools/ping
install -p -m 755 src/cpfs/cpfs_nfs_tool/switch_server.py ${BUILD_ROOT}/opt/aliyun/cpfs/tools/switch_server
install -p -m 755 src/alinas/nas_agent/nas-agent_${ARCH} ${BUILD_ROOT}/usr/local/nas-agent/nas-agent
install -p -m 755 src/alinas/nas_agent/ca-bundle.crt ${BUILD_ROOT}/usr/local/nas-agent/ca-bundle.crt
g++ -o std=c++11 src/alinas/nas_agent/identifier-generator.c -o src/alinas/nas_agent/identifier-generator
install -p -m 755 src/alinas/nas_agent/identifier-generator ${BUILD_ROOT}/usr/local/nas-agent/identifier-generator
install -p -m 644 dist/nas_agent/nas-agent-commands-local.json ${BUILD_ROOT}/etc/aliyun/alinas/nas-agent-commands-local.json

echo 'Copying install scripts'
install -p -m 755 dist/scriptlets/before-install ${BUILD_ROOT}/preinst
install -p -m 755 dist/scriptlets/after-install-upgrade ${BUILD_ROOT}/postinst
install -p -m 755 dist/scriptlets/before-remove ${BUILD_ROOT}/prerm
install -p -m 755 dist/scriptlets/after-remove ${BUILD_ROOT}/postrm

echo 'Copying control file'
install -p -m 644 dist/aliyun-alinas-utils.control ${BUILD_ROOT}/control
sed -i "s/\${Version}/$FULL_VERSION/g" ${BUILD_ROOT}/control

echo 'Copying conffiles'
install -p -m 644 dist/aliyun-alinas-utils.conffiles ${BUILD_ROOT}/conffiles

echo 'Creating deb binary file'
echo '2.0'> ${BUILD_ROOT}/debian-binary

echo 'Setting permissions'
find ${BUILD_ROOT} -type d | xargs chmod 755;

echo 'Creating tar'
cd ${BUILD_ROOT}
tar czf control.tar.gz control conffiles preinst postinst prerm postrm --owner=0 --group=0
tar czf data.tar.gz etc sbin usr var opt --owner=0 --group=0
cd ${BASE_DIR}

echo 'Building deb'
DEB=${BUILD_ROOT}/aliyun-alinas-utils-${FULL_VERSION}.${ARCH}.deb
ar r ${DEB} ${BUILD_ROOT}/debian-binary
ar r ${DEB} ${BUILD_ROOT}/control.tar.gz
ar r ${DEB} ${BUILD_ROOT}/data.tar.gz

echo 'Copying deb to output directory'
cp ${BUILD_ROOT}/aliyun-alinas-utils*deb build/
