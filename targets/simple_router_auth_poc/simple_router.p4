/* Original work Copyright 2013-present Barefoot Networks, Inc.
 * Modified work Copyright 2016 Jeroen Klomp
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// headers
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

//
// gre header
//

// simplified gre header (compound flags and fixed optional fields assumed)
header_type gre_t {
    fields {
        flags : 16;  // flags as compound field otherwise the flags are set to 0 after egress (not really necessary anymore since the header is removed after authentication)
        protocolType : 16;
        checksum : 16;
        offset: 16;
        key : 32;
        sequenceNumber : 32;
  }
}

// parser
parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

#define IP_PROT_GRE 0x2f

// gre header type needs to be defined prior to parsing ipv4, otherwise some fields stay undefined
header gre_t gre;

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        IP_PROT_GRE : parse_gre;
        default : ingress;
    }
}

//
// generic actions
//

action _no_op() {
    //no_op(); // primitive not implemented so just do nothing
}

action _drop() {
    drop();
}

action force_drop() {
    drop(); // drop action is not dropping gre traffic; only other traffic
    //modify_field(standard_metadata.egress_port, 511); // action that drop() does behind the curtain, doesn't work either
    truncate(0); // truncating the packet to zero works, although the switch still present an empty frame to the nic
}

//
// normal simple_router functionality
//

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_port, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

//
// gre metadata
//

header_type gre_metadata_t {
    fields {
        validKey : 1;
        index : 16;
        hashKey : 16;
        prevSequenceNumber : 32;
        computedHash : 16;
        emptyChecksum : 16; // never assigned, always 0x0000; used for checksum calculation
  }
}

metadata gre_metadata_t gre_metadata;

// sequence number counter
register sequence_number_reg {
    width: 32;
    static: gre_update;
    instance_count: 65536;
}

//
// gre checksum
//

// cleaned-up version of gre_checksum_list that uses metadata fields instead of #defines which seems to cause problems in the json representation
field_list gre_checksum_list {
        gre.flags;
        gre.protocolType;
        gre_metadata.emptyChecksum;
        gre_metadata.hashKey; // dynamic hash_key via offset field
        gre.key; // identifier
        gre.sequenceNumber;
        payload;
}

field_list_calculation gre_checksum {
    input {
        gre_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

// useful for testing purposes (better to use the debugger though), but not needed/functional anymore since this is now handled by modify_field_with_hash_based_offset (with dynamic hash_keys)
/*
calculated_field gre.checksum  {
    verify gre_checksum if (valid(gre));
    update gre_checksum if (valid(gre));
}
*/

// parser_exception do not appear to be implemented
/*
parser_exception p4_pe_checksum {
    //set_metadata(gre_metadata.gre_parse_error, 1);
    return ingress;
    //parser_drop; // either set metadata and return or drop packet
}
*/

parser parse_gre {
    extract(gre);
    return ingress;
}


//
// gre actions
//

action set_gre_key_invalid() {
    modify_field(gre_metadata.validKey, 0);
}

action set_gre_key_valid(idx, key) {
    modify_field(gre_metadata.validKey, 1);
    modify_field(gre_metadata.hashKey, key);
    modify_field(gre_metadata.index, idx);
    get_gre_sequence_number();
}

// register for sequence number
action get_gre_sequence_number() {
    register_read(gre_metadata.prevSequenceNumber, sequence_number_reg, gre_metadata.index);
}

action update_gre_sequence_number() {
    register_write(sequence_number_reg, gre_metadata.index, gre.sequenceNumber);
    //remove_gre(); // remove gre header (table gre_remove and gre_update_sequence_number could be merged, then this entry could be used)
}

action compute_gre_hash() {
    modify_field_with_hash_based_offset(gre_metadata.computedHash, 0, gre_checksum, 65536);
}

// remove gre header and repair ip proto: ip/gre/icmp -> ip/icmp
#define IP_PROT_ICMP 0x01

action remove_gre() {
    remove_header(gre);
    modify_field(ipv4.protocol, IP_PROT_ICMP); // static proto following gre header
    add_to_field(ipv4.totalLen, -16); // reduce length to accommodate for removal of gre header
}

//
// gre tables
//

// gre key (identifier) table
table gre_key {
    reads {
        gre.key : exact;
    }
    actions {
        //_drop; // doesn't work properly
        //force_drop; // appears to still allow traversal of wrong tables; instead use set_gre_key_invalid
        set_gre_key_valid;
        set_gre_key_invalid;
    }
}

table gre_compute_hash {
    actions {
        compute_gre_hash;
    }
}

// update sequence number
table gre_update {
    actions {
        update_gre_sequence_number;
    }
}

// not a valid hash
table gre_drop {
    actions {
        //_drop; // doesn't work properly
        force_drop;
    }
}

// not a valid sequence number
table gre_drop2 {
    actions {
        //_drop; // doesn't work properly
        force_drop;
    }
}

// not a valid key (identifier)
table gre_drop3 {
    actions {
        //_drop; // doesn't work properly
        force_drop;
    }
}

table gre_remove {
    actions {
        remove_gre;
    }
}

//
// control
//

control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(ipv4_lpm);  // normal ipv4 routing functionality
        apply(forward);   // normal forwarding functionality
    }
}

control egress {
    if (valid(gre)) {
        apply(gre_key);
        if (gre_metadata.validKey == 1) {
            if ((gre.sequenceNumber > gre_metadata.prevSequenceNumber) and (gre.sequenceNumber < gre_metadata.prevSequenceNumber + 125)) { // sliding window of valid sequence numbers
                apply(gre_compute_hash);
                if (gre.checksum == gre_metadata.computedHash) {
                    apply(gre_update); // store new sequence number
                    apply(gre_remove); // remove gre header
                }
                else {
                    apply(gre_drop); // not a valid hash
                } 
            }
            else {
                apply(gre_drop2); // not a valid sequence number
            }
        }
        // following is unnecessary if the table gre_key has a drop action by default, but this will result in the tables (e.g., gre_compute_hash) above being applied nonetheless
        // therefore work around by explicitly setting validKey to 0 and applying gre_drop3 table
        else {
            apply(gre_drop3); // not a valid key (identifier)
        }
    }
    apply(send_frame); // normal forwarding functionality
}
