#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

if [ $# -ne 1 ]; then
    echo "Select configuration mode: server or client"
    exit 1
fi

DIR_PREFIX='/usr/local'
MODE=$1

if [ $MODE != "server" ] && [ $MODE != "client" ]; then
    echo "Invalid configuration mode"
    exit 1
fi

set -x
make
install src/orcavpn $DIR_PREFIX/sbin/
install scripts/vpn$MODE-setup.sh $DIR_PREFIX/sbin/
install config/$MODE/orcavpn.conf $DIR_PREFIX/etc/ --mode=644
install config/$MODE/orcavpn.service /etc/systemd/system/ --mode=644
make clean
systemctl enable orcavpn
