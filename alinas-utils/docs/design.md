# Introduction
This document sketch the design and implementation of alinas-utils.

# Version Management
Note that, every time a new version is released, please update the following places:

+ src/mount_alinas/__init__.py::VERSION
+ src/watchdog/__init__.py::VERSION
+ dist/aliyun-alinas-utils.spec::Version
+ dist/aliyun-alinas-utils.control::Version
+ VERSION

# DNS Management
Every tls mounts will modify `/etc/hosts` to create a new dns entry such that `df -h` can yield meaningful results, otherwise,
we can only see 127.0.1.1, which is not human-readable.