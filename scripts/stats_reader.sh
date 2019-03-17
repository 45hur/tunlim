#!/bin/bash
TTYDIR=/var/lib/kres/tty/
python stats_reader.py $TTYDIR`ls $TTYDIR | head -1`
