#!/usr/bin/sh

SERVER_IP=192.168.1.10
SERVER_TUN_IP=10.80.80.1
DEFAULT_ROUTER=192.168.1.1

if [ $# -ge 1 ]; then
    SERVER_IP=$1
fi

if [ $# -ge 2 ]; then
    SERVER_TUN_IP=$2
fi

if [ $# -ge 3 ]; then
    DEFAULT_ROUTER=$3
fi

set -x
ip route add $SERVER_IP via $DEFAULT_ROUTER proto static
ip route add default via $SERVER_TUN_IP proto static
