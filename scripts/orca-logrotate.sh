#!/usr/bin/sh

LOGFILE=/var/log/orcavpn.log
ROTATIONS=4

set -x
rm -f "${LOGFILE}.$ROTATIONS"
for i in $(seq $(($ROTATIONS-1)) -1 1); do
    if [ -e "${LOGFILE}.$i" ]; then
        mv "${LOGFILE}.$i" "${LOGFILE}.$((i+1))"
    fi
done

mv $LOGFILE "${LOGFILE}.1"
systemctl reload orcavpn.service
