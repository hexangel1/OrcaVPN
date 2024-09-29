#!/usr/bin/sh

INET_DEV='eth0'
TUN_DEV='orca-gate'
PRIVATE='10.0.0.0/24'

if [ $# -ge 1 ]; then
    INET_DEV=$1
fi

if [ $# -ge 2 ]; then
    TUN_DEV=$2
fi

if [ $# -ge 3 ]; then
    PRIVATE=$3
fi

set -x
sysctl net.ipv4.ip_forward=1
iptables -A FORWARD -i $TUN_DEV -o $INET_DEV -j ACCEPT
iptables -A FORWARD -i $INET_DEV -o $TUN_DEV -j ACCEPT
iptables -t nat -I POSTROUTING -s $PRIVATE -o $INET_DEV -j MASQUERADE
