#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# Put mininet host h2 down and up (can be used to demonstrate that correctly
# authenticated packets get through put are not replied to when the destination
# is down)

# usage:
# mn> h2 sh ../targets/simple_router_auth_poc/mininet-host-down.sh down|up

down(){
  # set link s1 - h2 down and to up again so that packets will travel over that
  # link (but h2 will not reply because routing info is now missing)
  echo "shutting link down"
  ip link set eth0 down
  ip link set eth0 up
}

up(){
  echo "restoring reachability"
  ip route add default via 10.0.1.1 dev eth0
  ip neighbor add 10.0.1.1 lladdr 00:aa:bb:00:00:01 dev eth0
}

"$1"
