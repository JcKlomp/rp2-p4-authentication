#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# to easily compile the p4 program and possbily automatically repair certain compile flows

p4c-bmv2 --json simple_router.json simple_router.p4

# old work around for gre_checksum literals 
#perl -i -0pe 's/                    "type": "hexstr",\n                    "value": "0x0",\n                    "bitwidth": 0\n                },/                    "type": "hexstr",\n                    "value": "0x0000",\n                    "bitwidth": 16\n                },/' simple_router.json


#perl -i -0pe 's/                    "type": "hexstr",\n                    "value": "0x01",\n                    "bitwidth": 16\n                },/                    "type": "hexstr",\n                    "value": "0xabcd",\n                    "bitwidth": 16\n                },/' simple_router.json
