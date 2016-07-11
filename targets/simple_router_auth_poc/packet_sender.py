#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# (C) 2016 Jeroen Klomp
#
# License: GPLv3

# run as root (for Scapy)
# sudo python packet_sender.py

"""
packet sender - Scapy wrapper for P4 authentication PoC.
"""

from scapy.all import *

from threading import Thread

import os
import random
import time

import cmd
import traceback
import sys

if os.geteuid() != 0:
    print "usage: run as root"
    print "sudo python packet_sender.py\n"
    exit("root is required for Scapy; exiting")

print "### packet_sender.py ###\n"

# use emoticons to make output more clear
if "CLEAN" not in os.environ:
    happy_face = "\033[42m◔‿◔\033[0m\n"
    sad_face = "\033[41m◕⁔◕\033[0m\n"
else:
    happy_face = ""
    sad_face = ""

# warning message
if "NOWARN" not in os.environ:
    print ("!!! warning: this script runs as root and is able to execute user"
    " input; its only application is to test and demonstrate the P4 "
    "authentication proof of concept; use with care !!!\n")


# command line interpreter
class MyCli(cmd.Cmd):
    """Simple command processor."""
    
    ps_arguments = [
        '123456789 0xabcd seq_num',
        '987654321 0x1234 seq_num',
        '0x00000000 0x0000 seq_num',
        'identifier hash_key seq_num']
    aps_arguments = [
        '123456789 0xabcd seq_num',
        '987654321 0x1234 seq_num',
        '0x00000000 0x0000 seq_num',
        'identifier hash_key seq_num']
    p4_cli_arguments = [
        'table_dump gre_key',
        'table_add gre_key set_gre_key_valid 0x00000000 => 2 0x0000']

    def do_packet_send(self, line):
        print "#### sending 1 packet ####"
        if not line:
            ps(identifier, hash_key, seq_num)
        else:
            command = line.split(' ')
            # interpret variables
            for item in command:
                command[command.index(item)] = eval(item)
            ps(*command)
        # wait a bit for the sniffer to complete
        # so that the terminal behaves better
        time.sleep(1)

    def do_auto_packet_send(self, line):
        global amount
        global verbose
        if not line:
            aps(amount, identifier, hash_key, seq_num, 0, 0, 0)
        else:
            command = line.split(' ')
            # interpret variables
            for item in command:
                command[command.index(item)] = eval(item)

            if len(command) > 3:
                # swap amount around
                amount = command[3]
                del command[3]
            aps(amount, *command)
        # wait a bit for the sniffer to complete
        # so that the terminal behaves better
        time.sleep(1)

    def do_p4_cli(self, line):
        # this uses the shell instead of using python directly
        # probably better to switch to subprocess and of course do some checking
        line = line.replace(' ', '\\ ') # escape spaces
        line = line.replace('>', '\\>') # prevent bash redirection
        command = "bash -c .'/runtime_CLI <<<" + line + "'"
        os.system(command)

    def do_verbose(self, line):
        global verbose
        if not line:
            # switch verbose
            verbose += 1
            verbose = verbose % 2
        else:
            verbose = int(line)
        if verbose:
            print "verbose enabled"
        else:
            print "verbose disabled"

    def do_set_sequence_number(self, line):
        global seq_num
        if not line:
            seq_num += 1
        elif "+" in line:
            seq_num += int(line.replace('+', ''))
        elif "-" in line:
            seq_num -= int(line.replace('-', ''))
        else:
            seq_num = int(line)
        print "sequence number set to '%s'" % seq_num

    def complete_packet_send(self, text, line, begidx, endidx):
        if not text:
            completions = self.ps_arguments[:]
        else:
            completions = [ f
                            for f in self.ps_arguments
                            if f.startswith(text)
                            ]
        return completions

    def complete_auto_packet_send(self, text, line, begidx, endidx):
        if not text:
            completions = self.aps_arguments[:]
        else:
            completions = [ f
                            for f in self.aps_arguments
                            if f.startswith(text)
                            ]
        return completions

    def complete_p4_cli(self, text, line, begidx, endidx):
        if not text:
            completions = self.p4_cli_arguments[:]
        else:
            completions = [ f
                            for f in self.p4_cli_arguments
                            if f.startswith(text)
                            ]
        return completions

    # handle ctrl-c
    def cmdloop(self):
        try:
            cmd.Cmd.cmdloop(self)
        except KeyboardInterrupt as e:
            print '^C'
            self.cmdloop()

    def do_EOF(self, line):
        return True
    
    def emptyline(self):
        return


            
    def default(self, line):
        # interpret all other commands and behave like a normal interactive
        # python terminal (afap e.g., variable assignment works)
        # not really necessary anymore since seq_num can now be set via cli cmd
        try:
            # eval expression (e.g., exec function)
            eval(line)
        except:
            try:
                # eval statement (e.g., assignment) in global scope
                exec line in globals()
            except Exception:
                print(traceback.format_exc())
                # or
                print(sys.exc_info()[0])


# sniffer
# sniffing is necessary because srp[1] doesn't recognise replies
# thread is required because otherwise sniff blocks
def sniff_thread(*var):
    global verbose
    #print 'start sniffer'
    # Scapy BPF filter seems buggy
    # spawns tcpdump -i ens3 -ddd -s 1600 (src host 10.0... (wrong interface)
    #pkts = sniff(count=2, timeout=1, iface='s1-eth1', filter="(src host
    #10.0.0.10 and dst host 10.0.1.10) or (src host 10.0.1.10 and dst host
    #10.0.0.10)")
    pkts = sniff(count=2, timeout=1, iface='s1-eth1')
    
    try:
        if verbose:
            # first test pkts (otherwise print is always executed)
            if pkts[1]:
                print "\nresponse:"
                pkts[1].show()

        sent = str(pkts[0].getlayer(Raw))[8:] # strip off raw ICMP part
        received = str(pkts[1].getlayer(Raw))
        if sent != received or var[0] != sent or var[0] != received:
            print ("\nunexpected payload; original: %s, sent: %s, "
                "received: %s") % (var[0], sent, received)
            print sad_face
        elif verbose:
            print "\npayloads match"
            print happy_face
        elif not verbose:
            print "\nresponse: %s" % received
            print happy_face
    except:
        print "\nno response"
        print sad_face


# work around buggy Scapy BPF filter by limiting unwanted packets via iptables
# (s1-eth2 not necessary for the sniffer but easier on the eyes when dumping
# both interfaces)
os.system("sudo ip6tables -I OUTPUT -o s1-eth1 --j DROP")
os.system("sudo ip6tables -I OUTPUT -o s1-eth2 --j DROP")


# packet send
def ps(identifier=123456789, hash_key=0xabcd, lseq_num=123, forge='', format='', 
        payload=''):
    global verbose
    if not payload:
        payload = str(random.randint(1, 1000))
    # create packet
    ip = IP(dst='10.0.1.10', src='10.0.0.10')
    # use hash_key as offset
    # so that the key is included in the checksum calculation
    gre = GRE(key_present=1,key=identifier,seqnum_present=1,
        seqence_number=lseq_num,offset=hash_key,chksum_present=1)
    
    if not format:
        packet = ip/gre/ICMP()/payload
    elif format == 1:
        icmprqst = '\x08\x00\x05\xdc\x00\x00\x00\x00'
        payload = icmprqst + payload
        packet = ip/gre/payload
    elif format == 2:
        packet = ip/gre/payload
    else:
        packet = ip/gre/ip/ICMP()/payload
    
    # create new packet based from first packet so that checksum is calculated
    packet2=IP(str(packet))

    # remove offset (for keyed hash) from packet
    del packet2[GRE].offset

    if forge == 1:
        # forge packet payload
        forged_payload =  str(random.randint(1, 1000))
        rawload = packet2.getlayer(Raw).load
        rawload += forged_payload
        #packet2[GRE].payload = rawload
        packet2[Raw].load = rawload

        print "forging payload '%s' with '%s' \
            appended" % (payload, forged_payload)
        payload = payload + forged_payload

        # set fixed checksum for testing
        #packet2[GRE].chksum = 0xc74b
        # fix ip length
        packet2[IP].len += len(forged_payload)

    elif forge == 2:
        # forge offset (doesn't work because field is already used for hash_key)
        forged_offset = random.randint(1, 65536)
        #forged_offset = 0x1234
        print "forging offset to %s" % (forged_offset)
        packet2[GRE].offset = forged_offset

    elif forge == 3:
        # forge sequence number
        forged_sequence = random.randint(1, 65536)
        #forged_offset = 0x1234
        print "forging sequence number to %s" % (forged_sequence)
        packet2[GRE].seqence_number = forged_sequence

    elif forge == 4:
        # forge protocol
        forged_protocol = random.randint(1, 65536)
        print "forging protocol type to %s" % (forged_protocol)
        packet2[GRE].proto = forged_protocol

    print ("sending packet: identifier: %s (0x%x), hash key: 0x%x, "
        "sequence number: %s, checksum: 0x%x, payload: %s") % (identifier, 
        identifier, hash_key, lseq_num, packet2[GRE].chksum, payload)

    if verbose:
        print "Packet to be sent:"
        packet2.show2()
        print ""

    # sniff for responses in background
    my_thread = Thread(target=sniff_thread, args=(payload,))
    my_thread.start()

    # give sniffer a little time to initialise
    time.sleep(0.1)
    
    # send packet that includes the keyed checksum
    sendp(Ether()/packet2, iface='s1-eth1', verbose=0)

    # update sequence number
    # handy for aps and ps with seq_num+1
    global seq_num
    seq_num = lseq_num


# auto packet send
def aps(amount=5, identifier=123456789, hash_key=0xabcd, lseq_num=123, *args):
    current = 0
    print "#### sending %s packets ####" % amount
    while current < amount:
        print "### packet %s of %s ###" % (current+1, amount)
        ps(identifier, hash_key, lseq_num, *args)
        current += 1
        lseq_num += 1
        # sniffer can't handle too much traffic currently
        #print 'sleep'
        time.sleep(1)

# default values
identifier = 123456789
hash_key = 0xabcd
global seq_num
seq_num=123
payload='coco1234coco'
amount = 5
verbose=1

# easier to type (no longer needed due to the cmd module's command completion)
#id = identifier
#k = hash_key
#c = seq_num
#p = payload
#a = amount

# print default values so that they can easily be used in interactive terminal
print "default values:"
print "\tidentifier \t= %s" % identifier
print "\thash_key  \t= 0x%x" % hash_key
print "\tseq_num  \t= %s" % seq_num
#print "\tpayload  \t= %s" % payload
print "\tamount  \t= %s" % amount

print "\nsend packets via following python function:"
print "\t> ps(identifier, hash_key, seq_num)\n"
# print "ps(identifier, hash_key, seq_num, forge, format, payload)"
# print "aps(amount identifier, hash_key, seq_num, forge, format, payload)"
print "...or via the following interactive command function:"
print "\t> packet_send identifier hash_key seq_num\n"
# print "packet_send identifier hash_key seq_num forge format payload"
print "...or via their automated alternatives (aps and auto_packet_send)"
# print "auto_packet_send identifier hash_key seq_num amount forge format payload"


if __name__ == '__main__':
    prompt = MyCli()
    prompt.prompt = '> '
    prompt.cmdloop()

# vim: tw=80 colorcolumn=81 ts=4 sw=4 softtabstop=4 expandtab
