#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# tshark parser for P4 authentication demonstration
# usage: script.sh -i eth0 [...]

#if [[ $2 == 's1-eth1' ]]; then
#  echo -e "# Src \t=> Dst Proto Type Payload ID Seq Chksum"
#fi

tpgreen=$(tput setab 2)
tpyellow=$(tput setab 3)
tpbold=$(tput bold)
tpreset=$(tput sgr0)

while read line; do
  #echo -n $line | awk '{print $1,$2,$3,$4,$5}'
  number=$(echo $line | awk '{print $1}')
  src=$(echo $line | awk '{print $2}')
  dst=$(echo $line | awk '{print $3}')
  proto=$(echo $line | awk '{print $4}')
  type=$(echo $line | awk '{print $5}') # icmptype or gre proto
  data=$(echo $line | awk '{print $6}')
  id_key=$(echo $line | awk '{print $7}')
  seq=$(echo $line | awk '{print $8}')
  chksum=$(echo $line | awk '{print $9}')

  if [[ $proto == "47" ]]; then
    proto="GRE "
  elif [[ $proto == "1" ]]; then
    proto="ICMP"
  fi

  if [[ $type == "0" ]]; then
    type="RPLY"
  elif [[ $type == "8" ]]; then
    type="RQST"
  elif [[ $type == "0x00000000" ]]; then
    type="ICMP"
  fi

  data2=$(echo ${data:24})
  if [[ -z $data2 ]]; then
    data2=$data
  fi
  # prevent UTF-8 garbage from normal ping command
  #if [[ ${data:0:} == *[[:ascii:]]* ]]; then
  #  data2="[...]01234567"
  #fi
  #echo $data2
  # doesn't work
  # easiest work around is to use a terminal that simply doesn't show it (e.g., tmux by default)
  data3=$(echo -e $(echo -n "\x${data2}" | sed 's/:/\\x/g'))

  # fix checksum to 16 bits
  chksum=$(echo $chksum | sed 's/0000//')

  if [[ $src == '10.0.0.10' ]]; then
    src="${tpgreen}$src${tpreset}"
  else
    src="${tpyellow}$src${tpreset}"
  fi

  # improve layout
  if [[ ${#number} < 2 ]]; then
    number=" $number"
  fi

  if [[ ${#data3} < 3 ]]; then
      tab="    "
  elif [[ ${#data3} < 4 ]]; then
      tab="   "
  elif [[ ${#data3} < 5 ]]; then
    tab="  "
  elif [[ ${#data3} < 6 ]]; then
    tab=" "
  elif [[ ${#data3} < 7 ]]; then
    tab=""
  fi

  echo -e "$number $src => $dst $proto $type ${tpbold}$data3${tpreset} $tab $id_key $seq $chksum"

done < <(tshark -l -T fields -E separator=' ' -e frame.number -e ip.src -e ip.dst -e ip.proto -e icmp.type -e gre.proto -e data.data -e gre.key -e gre.sequence_number -e gre.checksum "$@" 2>/dev/null)


