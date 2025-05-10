#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

DIR_PREFIX='/usr/local'

set -x
systemctl stop orcavpn
systemctl disable orcavpn
rm -f $DIR_PREFIX/sbin/orcavpn
rm -f $DIR_PREFIX/sbin/vpnserver-setup.sh
rm -f $DIR_PREFIX/sbin/vpnclient-setup.sh
rm -f $DIR_PREFIX/etc/orcavpn.conf
rm -f /etc/systemd/system/orcavpn.service
