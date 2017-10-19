#!/bin/sh
#
# Legacy action script for "service unit loadconfig"

CONFIG=/etc/unit/config

if [ -n "$1" ] ; then
    CONFIG=$1
fi

if [ ! -e ${CONFIG} ]; then
    echo "Could not find ${CONFIG} for loading" >&2
    exit 1
fi

echo "Loading configuration from ${CONFIG}..."

curl -sS -X PUT --data-binary @${CONFIG} --unix-socket /var/run/control.unit.sock localhost

if [ $? -ne 0 ]; then
    echo "Loading failed!" >&2
    exit 1
fi

exit 0
