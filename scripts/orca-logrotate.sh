#!/bin/sh

LOGFILE=/var/log/orcavpn.log
FILESIZE_MB_LIMIT=10
ROTATIONS=4

if [ ! -f $LOGFILE ]; then
    echo "${LOGFILE} not exists"
    exit 1
fi

if [ $# -ne 1 ] || [ $1 != "-f" ]; then
    LOGFILE_SIZE=$(du -m $LOGFILE | cut -f1)
    if [ $LOGFILE_SIZE -le $FILESIZE_MB_LIMIT ]; then
        echo "current log file size <= ${FILESIZE_MB_LIMIT}MB"
        exit 0
    fi
fi

rm -f "${LOGFILE}.${ROTATIONS}.gz"
if [ -f "${LOGFILE}.1" ]; then
    gzip "${LOGFILE}.1"
fi

for i in $(seq $(($ROTATIONS-1)) -1 1); do
    if [ -f "${LOGFILE}.$i.gz" ]; then
        mv "${LOGFILE}.$i.gz" "${LOGFILE}.$((i+1)).gz"
    fi
done

mv $LOGFILE "${LOGFILE}.1"
systemctl reload orcavpn.service
