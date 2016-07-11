#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# wrapper for run.sh launcher for running P4 authentication PoC without mininet

./run.sh --nanolog ipc:///tmp/bm-log.ipc --log-file /tmp/bm2.log --log-flush "$@"
