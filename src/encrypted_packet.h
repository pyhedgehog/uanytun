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
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2017 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of uAnytun.
 *
 *  uAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  uAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef UANYTUN_encrypted_packet_h_INCLUDED
#define UANYTUN_encrypted_packet_h_INCLUDED

#define ENCRYPTED_PACKET_SIZE_MAX 1600

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
  u_int32_t auth_tag_length_;
  union __attribute__ ((__packed__)) {
    u_int8_t buf_[ENCRYPTED_PACKET_SIZE_MAX];
    encrypted_packet_header_t header_;
 } data_;
};
typedef struct encrypted_packet_struct encrypted_packet_t;

void encrypted_packet_init(encrypted_packet_t* packet, u_int32_t auth_tag_length);

u_int32_t encrypted_packet_get_minimum_length(encrypted_packet_t* packet);

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

seq_nr_t encrypted_packet_get_seq_nr(encrypted_packet_t* packet);
void encrypted_packet_set_seq_nr(encrypted_packet_t* packet, seq_nr_t seq_nr);

sender_id_t encrypted_packet_get_sender_id(encrypted_packet_t* packet);
void encrypted_packet_set_sender_id(encrypted_packet_t* packet, sender_id_t sender_id);

mux_t encrypted_packet_get_mux(encrypted_packet_t* packet);
void encrypted_packet_set_mux(encrypted_packet_t* packet, mux_t mux);


#endif
