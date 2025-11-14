#!/bin/bash
cd "$(dirname "$0")" || return

# usage:
# sh test.sh [<nas-filesystem>] [<local-test-dir>]

virtualenv build/.envs/alinas-utils --python=python3.6
source build/.envs/alinas-utils/bin/activate
pip install -r requirements.txt
PYTHONPATH=./src/alinas/ pytest  ./test/alinas/mount_alinas_test/
PYTHONPATH=./src/alinas/ pytest  ./test/alinas/watchdog_test/
PYTHONPATH=./src/cpfs/ pytest -x ./test/cpfs/

if [[ -n "$2" ]]; then
    PYTHONPATH=./src/alinas/ pytest -x ./test/alinas/function_test/ --server=$1 --testdir=$2
fi
