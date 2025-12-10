#
# Copyright 2017-2018 amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

PACKAGE_NAME = aliyun-alinas-utils
PACKAGE_VERSION = $(shell grep -E 'Version|Release' dist/aliyun-alinas-utils.spec | awk -F':|%' '{ print $$2 }' | tr '\n' ' ' | awk '{ print $$1 "-" $$2 }')
BUILD_ID = $(shell git log -1 --format=%ci | awk '{print $$1$$2}' | tr -d '\-:').$(shell git rev-parse --short=6 HEAD)
SOURCE_TARBALL = $(PACKAGE_NAME).tar.gz
SPECFILE = $(PACKAGE_NAME).spec
BUILD_DIR = build/rpmbuild
export PYTHONPATH := $(shell pwd)/src

.PHONY: all
all: rpm deb tar

.PHONY: all-arm
all-arm: rpm-arm deb tar

.PHONY: clean
clean:
	rm -rf build/*
	rm -rf $(BUILD_DIR)
	rm -rf $(PACKAGE_NAME)
	rm -f $(SOURCE_TARBALL)
	rm -f $(SPECFILE)

.PHONY: id-gen
id-gen:
	g++ -std=c++11 -O2 src/alinas/nas_agent/identifier-generator.c -o src/alinas/nas_agent/identifier-generator
	strip src/alinas/nas_agent/identifier-generator

.PHONY: tarball
tarball: clean
	mkdir -p $(PACKAGE_NAME)

	mkdir -p $(PACKAGE_NAME)/dist
	mkdir -p $(PACKAGE_NAME)/dist/cpfs
	mkdir -p $(PACKAGE_NAME)/dist/alinas
	cp -p dist/alinas/aliyun-alinas-mount-watchdog.conf $(PACKAGE_NAME)/dist/alinas
	cp -p dist/alinas/aliyun-alinas-mount-watchdog.service $(PACKAGE_NAME)/dist/alinas
	cp -p dist/cpfs/aliyun-cpfs-mount-watchdog.conf $(PACKAGE_NAME)/dist/cpfs
	cp -p dist/cpfs/aliyun-cpfs-mount-watchdog.service $(PACKAGE_NAME)/dist/cpfs
	cp -p dist/cpfs/cpfs-utils.conf $(PACKAGE_NAME)/dist/cpfs
	cp -p dist/alinas/alinas-utils.conf $(PACKAGE_NAME)/dist/alinas
	cp -p dist/alinas/aliyun-alinas-efc-minimum-supported-kernel-versions.json $(PACKAGE_NAME)/dist/alinas

	cp -p dist/alinas-utils.crt $(PACKAGE_NAME)/dist


	mkdir -p $(PACKAGE_NAME)/src
	mkdir -p $(PACKAGE_NAME)/src/cpfs
	mkdir -p $(PACKAGE_NAME)/src/alinas
	cp -rp src/cpfs/mount_cpfs $(PACKAGE_NAME)/src/cpfs
	cp -rp src/cpfs/watchdog $(PACKAGE_NAME)/src/cpfs
	cp -rp src/cpfs/cpfs_nfs_tool $(PACKAGE_NAME)/src/cpfs
	cp -rp src/cpfs/cpfs_nfs_common $(PACKAGE_NAME)/src/cpfs
	cp -rp src/alinas/mount_alinas $(PACKAGE_NAME)/src/alinas
	cp -rp src/alinas/watchdog $(PACKAGE_NAME)/src/alinas

	cp -rp dist/nas_agent $(PACKAGE_NAME)/dist
	cp -rp src/alinas/nas_agent $(PACKAGE_NAME)/src/alinas
	rm -f $(PACKAGE_NAME)/src/alinas/nas_agent/identifier-generator.c

	tar -czf $(SOURCE_TARBALL) $(PACKAGE_NAME)/*

.PHONY: specfile
specfile: clean
	ln -sf dist/$(SPECFILE) $(SPECFILE)

.PHONY: sources
sources: tarball specfile

.PHONY: rpm-only
rpm-only: rpm-only-generic rpm-only-al7 rpm-only-al8 rpm-only-el7 rpm-only-el8 rpm-only-lp15

.PHONY: rpm-only-al7
rpm-only-al7:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .al7" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.al7.*.rpm build
	for file in build/*.al7.*.rpm; do dest=$$(echo $$file | sed s/[^.]*\.rpm/noarch.rpm/g); mv $$file $$dest; done

.PHONY: rpm-only-al8
rpm-only-al8:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .al8" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.al8.*.rpm build

.PHONY: rpm-only-el7
rpm-only-el7:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .el7" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.el7.*rpm build

.PHONY: rpm-only-el8
rpm-only-el8:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .el8" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.el8.*rpm build

.PHONY: rpm-only-lp15
rpm-only-lp15:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .lp15" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.lp15.*rpm build

.PHONY: rpm-only-generic
rpm-only-generic:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
	--define "_topdir `pwd`/$(BUILD_DIR)" \
	--define "version `cat VERSION|awk -F- '{print $$1}'`" \
	--define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
	--define "dist .generic" \
	--define "arch x86_64"
	cp $(BUILD_DIR)/RPMS/*/*.generic.*rpm build

.PHONY: rpm-arm-only
rpm-arm-only: rpm-arm-al8 rpm-arm-generic

.PHONY: rpm-arm-al8
rpm-arm-al8:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
        --define "_topdir `pwd`/$(BUILD_DIR)" \
        --define "version `cat VERSION|awk -F- '{print $$1}'`" \
        --define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
        --define "dist .al8" \
        --define "arch aarch64"
	cp $(BUILD_DIR)/RPMS/*/*.al8.*.rpm build

.PHONY: rpm-arm-generic
rpm-arm-generic:
	mkdir -p $(BUILD_DIR)/{SPECS,COORD_SOURCES,DATA_SOURCES,BUILD,RPMS,SOURCES,SRPMS}
	cp $(SPECFILE) $(BUILD_DIR)/SPECS
	cp $(SOURCE_TARBALL) $(BUILD_DIR)/SOURCES
	rpmbuild -ba $(BUILD_DIR)/SPECS/$(SPECFILE) \
        --define "_topdir `pwd`/$(BUILD_DIR)" \
        --define "version `cat VERSION|awk -F- '{print $$1}'`" \
        --define "build_id `cat VERSION|awk -F- '{print $$2}'`.$(BUILD_ID)" \
        --define "dist .generic" \
        --define "arch aarch64"
	cp $(BUILD_DIR)/RPMS/*/*.generic.*.rpm build

.PHONY: install-rpm
install-rpm:
	yum install -y rpm-build

.PHONY: rpm
rpm: id-gen sources rpm-only

.PHONY: rpm-arm
rpm-arm: id-gen sources rpm-arm-only

.PHONY: deb
deb:
	./build-deb.sh 

.PHONY: test
test:
	./test.sh

.PHONY: pack
pack:
	git archive HEAD -o alinas.tgz

.PHONY: tar
tar:
	./tar.sh
