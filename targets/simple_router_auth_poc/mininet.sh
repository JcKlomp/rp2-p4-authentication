#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# laucher for p4-mininet which also automatically starts Wireshark to work around an annoying bug that necessitates restarting Wirehark (double interfaces listed and inability to capture traffic after restarting Mininet)

if [[ $1 == "-n" ]]; then
  shift
else
  sniffer="wireshark"
fi

test -n "$DISPLAY" && test -n $(which "$sniffer") && ws=1

test -n "$ws" && echo "*** launching sniffer in the background" && (sleep 1 && "$sniffer" -i s1-eth1 -i s1-eth2 -k) &>/dev/null &

echo "*** adding table entries in the background"
(sleep 2 && ./add_entries.sh >/dev/null) &

echo "*** launching Mininet:"
pushd .
cd ../../mininet/
sudo python 1sw_demo.py --behavioral-exe ../targets/simple_router_auth_poc/simple_router --json ../targets/simple_router_auth_poc/simple_router.json "$@"
popd
echo "*** Mininet exited"

test -n "$ws" && echo "*** killing sniffer" && pkill -f "$sniffer -i s1-eth1 -i s1-eth2 -k"
