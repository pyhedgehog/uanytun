/*
 *  uAnytun
 *
 *  uAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation uAnytun has no support for multiple connections
 *  or synchronisation. It is a small single threaded implementation intended
 *  to act as a client on small platforms.
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *  
 *
 *  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of uAnytun.
 *
 *  uAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  uAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ENCRYPTED_PACKET_H_
#define _ENCRYPTED_PACKET_H_

#define ENCRYPTED_PACKET_SIZE_MAX 1600
#define ENCRYPTED_PACKET_AUTHTAG_SIZE 10

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0000
#define PAYLOAD_TYPE_TUN4 0x0800
#define PAYLOAD_TYPE_TUN6 0x86DD 

struct __attribute__ ((__packed__)) encrypted_packet_header_struct {
  seq_nr_t seq_nr_;
  sender_id_t sender_id_;
  mux_t mux_;
};
typedef struct encrypted_packet_header_struct encrypted_packet_header_t;

struct encrypted_packet_struct {
  u_int32_t payload_length_;
  u_int8_t* auth_tag_;
  union __attribute__ ((__packed__)) {
    u_int8_t buf_[ENCRYPTED_PACKET_SIZE_MAX];
    encrypted_packet_header_t header_;
 } data_;
};
typedef struct encrypted_packet_struct encrypted_packet_t;

void encrypted_packet_init(encrypted_packet_t* packet);

u_int32_t encrypted_packet_get_header_length();

u_int8_t* encrypted_packet_get_packet(encrypted_packet_t* packet);
u_int32_t encrypted_packet_get_length(encrypted_packet_t* packet);
void encrypted_packet_set_length(encrypted_packet_t* packet, u_int32_t len);

u_int8_t* encrypted_packet_get_payload(encrypted_packet_t* packet);
u_int32_t encrypted_packet_get_payload_length(encrypted_packet_t* packet);
void encrypted_packet_set_payload_length(encrypted_packet_t* packet, u_int32_t len);

u_int8_t* encrypted_packet_get_auth_portion(encrypted_packet_t* packet);
u_int32_t encrypted_packet_get_auth_portion_length(encrypted_packet_t* packet);

u_int8_t* encrypted_packet_get_auth_tag(encrypted_packet_t* packet);
u_int32_t encrypted_packet_get_auth_tag_length(encrypted_packet_t* packet);

void encrypted_packet_add_auth_tag(encrypted_packet_t* packet);
void encrypted_packet_remove_auth_tag(encrypted_packet_t* packet);

seq_nr_t encrypted_packet_get_seq_nr(encrypted_packet_t* packet);
void encrypted_packet_set_seq_nr(encrypted_packet_t* packet, seq_nr_t seq_nr);

sender_id_t encrypted_packet_get_sender_id(encrypted_packet_t* packet);
void encrypted_packet_set_sender_id(encrypted_packet_t* packet, sender_id_t sender_id);

mux_t encrypted_packet_get_mux(encrypted_packet_t* packet);
void encrypted_packet_set_mux(encrypted_packet_t* packet, mux_t mux);


#endif
