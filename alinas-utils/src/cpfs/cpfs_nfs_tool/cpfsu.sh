#!/bin/bash

TOOL_DIR=/opt/aliyun/cpfs/tools

Usage() {
    APP=$(basename "$0")
    echo "Usage: $APP <command> [args]
Available Command:
        Name                 Description
--------------------------------------------------------------------------------
        ping                 check cpfs mount target available
        switch_server        switch cpfs connection server
--------------------------------------------------------------------------------
"
}

if [ -z "$1" ]; then
    Usage
    exit 1
fi

command="$1"

case $command in
"ping")
    shift
    cmd="$TOOL_DIR/ping $*"
    $cmd
;;
"switch_server")
    shift
    cmd="$TOOL_DIR/switch_server $*"
    $cmd
;;
*)
    Usage
;;
esac