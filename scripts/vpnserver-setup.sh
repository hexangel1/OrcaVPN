#!/usr/bin/sh

INET_DEV='eth0'
TUN_DEV='orca-gate'
PRIVATE='10.80.80.0/24'

if [ $# -ge 1 ]; then
    INET_DEV=$1
fi

if [ $# -ge 2 ]; then
    TUN_DEV=$2
fi

if [ $# -ge 3 ]; then
    PRIVATE=$3
fi

RULE1="-i ${TUN_DEV} -o ${INET_DEV} -j ACCEPT"
RULE2="-i ${INET_DEV} -o ${TUN_DEV} -j ACCEPT"
RULE3="-t nat -s ${PRIVATE} -o ${INET_DEV} -j MASQUERADE"

set -x
sysctl net.ipv4.ip_forward=1 >/dev/null
iptables -C FORWARD $RULE1 2>/dev/null || iptables -A FORWARD $RULE1
iptables -C FORWARD $RULE2 2>/dev/null || iptables -A FORWARD $RULE2
iptables -C POSTROUTING $RULE3 2>/dev/null || iptables -I POSTROUTING $RULE3
