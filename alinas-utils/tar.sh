set -e

pushd $(pwd)

RPM_SPEC="dist/aliyun-alinas-utils.spec"
PKG_PATH="build/pkg/"
PATH_LIST="path-list"
CHECKSUM_LIST="checksum-list"
ARCH=$(arch)
VERSION=$(rpm -qi build/aliyun-alinas-utils*generic*rpm | egrep 'Version' | awk '{print $NF}')
RELEASE=$(rpm -qi build/aliyun-alinas-utils*generic*rpm | egrep 'Release' | awk '{print $NF}')
TAG=${VERSION}-${RELEASE}.${ARCH}
TAR_CMD="tar cvf aliyun-alinas-utils-${TAG}.tar ${PATH_LIST} ${CHECKSUM_LIST}"

rm -rf $PKG_PATH
mkdir -p $PKG_PATH

while IFS= read -r line; do
	if [[ ${line} != install* ]]; then
		continue
	fi
	line="${line//%{_builddir\}/.}"
	line="${line//%{buildsubdir\}/build/${BUILD_MODE}}"
	line="${line//%{buildmode\}/${BUILD_MODE}}"
	line="${line//%{_topdir\}/.}"
	line="${line//SPECS/dist}"
	line="${line//%{buildroot\}/}"
	line="${line//%{name\}/}"
	line="${line//%{arch\}/${ARCH}}"
	line="${line//%{_sysconfdir\}//etc}"
	line="${line//%{_unitdir\}//usr/lib/systemd/system}"
	local_path=$(echo $line | awk '{print $5}')
	install_path=$(echo $line | awk '{print $6}')
	mod=$(echo $line | awk '{print $4}')
	echo "$local_path --> $install_path"
	name=$(basename $install_path)

	if [ -f $PKG_PATH/$name ]; then
		checksum1=$(md5sum $PKG_PATH/$name | awk '{print $1}')
		checksum2=$(md5sum $local_path | awk '{print $1}')
		if [[ $checksum1 = $checksum2 ]]; then
			echo "same file $name with different path $install_path, only tar once"
		else
			echo "ERROR: same file name $name with different content"
			exit 1
		fi
	else
		cp $local_path $PKG_PATH/$name
		chmod 0${mod} $PKG_PATH/$name
		TAR_CMD=${TAR_CMD}" ${name}"
	fi
	echo ${install_path} >> ${PKG_PATH}/${PATH_LIST}
	md5sum ${local_path} | awk '{print $1}' >> ${PKG_PATH}/${CHECKSUM_LIST}
done < ${RPM_SPEC}

cd $PKG_PATH
echo $TAR_CMD
bash -c "$TAR_CMD"

popd
