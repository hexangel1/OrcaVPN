#!/bin/sh

SERVER_IP=${SERVER_IP:-${1:-'198.51.100.49'}}
SERVER_TUN_IP=${SERVER_TUN_IP:-${2:-'10.80.80.1'}}

GUESS_ROUTER=$(ip route get $SERVER_IP | head -n 1 | awk '/via/ { print $3 }')
DEFAULT_ROUTER=${DEFAULT_ROUTER:-${3:-${GUESS_ROUTER:-'192.168.1.1'}}}

set -x
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
ip route add $SERVER_IP via $DEFAULT_ROUTER proto static
ip route add default via $SERVER_TUN_IP proto static
