#!/usr/bin/sh

TUN_DEV='vpn-tun0'
INET_DEV='wlp0s20f3'
PRIVATE='10.0.0.0/24'

set -x
sysctl net.ipv4.ip_forward=1
iptables -A FORWARD -i $TUN_DEV -o $INET_DEV -j ACCEPT
iptables -A FORWARD -i $INET_DEV -o $TUN_DEV -j ACCEPT
iptables -t nat -I POSTROUTING -s $PRIVATE -o $INET_DEV -j MASQUERADE
