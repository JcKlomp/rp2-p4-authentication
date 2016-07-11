#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# to easily start the nanomsg logger
# when tail -f /tmp/p4s.s1.verbose.log.txt is not enough and debugging is enabled during compilation:
# @102,1-8
# args.append('--log-file /tmp/p4s.%s.verbose.log --log-flush --debugger' % self.name)

sudo ../../tools/nanomsg_client.py "$@"
