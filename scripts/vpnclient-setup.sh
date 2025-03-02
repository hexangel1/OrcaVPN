#!/bin/sh

SERVER_IP=${SERVER_IP:-${1:-'192.168.1.1'}}
SERVER_TUN_IP=${SERVER_TUN_IP:-${2:-'10.80.80.1'}}
DEFAULT_ROUTER=${DEFAULT_ROUTER:-${3:-'192.168.1.1'}}

set -x
ip route add $SERVER_IP via $DEFAULT_ROUTER proto static
ip route add default via $SERVER_TUN_IP proto static
