#!/bin/sh
#
# Legacy action script for "service unit saveconfig"

CONFIG=/etc/unit/config

if [ -n "$1" ] ; then
    CONFIG=$1
fi

curl -sS --unix-socket /var/run/control.unit.sock localhost >${CONFIG}.new

if [ $? -ne 0 ]; then
    echo "Could not retreive configuration" >&2
    rm -f ${CONFIG}.new
    exit 1
fi

mv ${CONFIG}.new ${CONFIG}

echo "The following configuration has been saved to ${CONFIG}:"
cat ${CONFIG}

exit 0
