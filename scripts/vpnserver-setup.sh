#!/bin/sh

INET_DEV=${INET_DEV:-${1:-'eth0'}}
TUN_DEV=${TUN_DEV:-${2:-'orca-gate'}}
PRIVATE_NET=${PRIVATE_NET:-${3:-'10.80.80.0/24'}}

RULE1="-i ${TUN_DEV} -o ${INET_DEV} -j ACCEPT"
RULE2="-i ${INET_DEV} -o ${TUN_DEV} -j ACCEPT"
RULE3="-t nat -s ${PRIVATE_NET} -o ${INET_DEV} -j MASQUERADE"
RULE4="-i ${INET_DEV} --proto icmp --icmp-type echo-request -j DROP"

set -x
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -C FORWARD $RULE1 2>/dev/null || iptables -A FORWARD $RULE1
iptables -C FORWARD $RULE2 2>/dev/null || iptables -A FORWARD $RULE2
iptables -C POSTROUTING $RULE3 2>/dev/null || iptables -I POSTROUTING $RULE3
iptables -C INPUT $RULE4 2>/dev/null || iptables -A INPUT $RULE4
