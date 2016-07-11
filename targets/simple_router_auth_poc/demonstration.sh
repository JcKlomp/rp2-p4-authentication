#!/bin/bash
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# control script for P4 authentication demonstration
# usage: start tmux session
# then : . script.sh
# or   : source script.sh
#
# or tmux new "bash -c '. script.sh" # but this creates interactivity problems
#
# on very slow systems the timeout for adding the table entries defined in mininet.sh might need to be increased

end_demonstration(){
  tmux kill-session
  clear
}

export PS1="[p4@demonstration \W]\$ "

tmux set -g mouse on
tmux bind -n WheelUpPane if-shell -F -t = "#{mouse_any_flag}" "send-keys -M" "if -Ft= '#{pane_in_mode}' 'send-keys -M' 'select-pane -t=; copy-mode -e; send-keys -M'"

tmux set-option -g utf8 on

tmux split-window -h
tmux split-window -v -t 1 -p 20
tmux split-window -v -t 0 -p 20

tmux select-pane -t 0

# the p4 force_drop action (truncation of the packet to zero) still creates a weird empty (zero-length) ethernet frame on the egress interface which trips up tshark so tshark on that interface needs to be restarted
# another work around is to listen on multiple interfaces
# while loop used to restart tshark, also for the eth1 because it might make it easier if mininet is killed
tmux send-keys -t 1 "export PS1=\"\"; sleep 1 && while true; do ./tshark.sh -i s1-eth1; done & clear && echo -e \"H1 - \e[1mS1-ETH1\e[0m - S1: \n\e[4m# Src        => Dst       Prot Type Data    ID         Seq Chksum\e[0m\"" C-m

tmux send-keys -t 2 "export PS1=\"\"; sleep 1 && while true; do ./tshark.sh -i s1-eth2; done & clear && echo -e \"S1 - \e[1mS1-ETH2\e[0m - H2: \n\e[4m# Src        => Dst       Prot Type Data    ID         Seq Chksum\e[0m\"" C-m


tmux select-pane -t 3

tmux send-keys -t 3 "export PS1=\"$ \"; end_demonstration(){
  tmux kill-session
}; clear" C-m
tmux send-keys -t 3 "./mininet.sh -n" C-m

sudo python2 packet_sender.py
