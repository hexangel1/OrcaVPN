#!/usr/bin/sh

DIR_PREFIX='/usr/local'

set -x
systemctl stop orcavpn
systemctl disable orcavpn
rm -f $DIR_PREFIX/bin/orcavpn
rm -f $DIR_PREFIX/etc/orcavpn.conf
rm -f /etc/systemd/system/orcavpn.service
