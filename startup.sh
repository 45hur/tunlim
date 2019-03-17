#!/bin/bash
NUM_OF_CPUS="`nproc`"
echo "Detected # of CPU cores: $NUM_OF_CPUS"

TOTAL_RAM=$(free -k | awk '/^Mem:/{print $2}')
export KNOT_CACHE_SIZE="$(($TOTAL_RAM/4000))"
if [[ "${KNOT_CACHE_SIZE}" -gt 2048 ]]; then
     export KNOT_CACHE_SIZE=2048
fi

echo "Resolver cache size (MB): $KNOT_CACHE_SIZE"

rm -rf /tty/tty/* /var/lib/kres/cache/*
sed -i "s|NUM_OF_CPUS|$NUM_OF_CPUS|g" /etc/supervisor/conf.d/kres.conf
supervisord -c /etc/supervisor/conf.d/kres.conf -n
