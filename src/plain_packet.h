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
 *  Copyright (C) 2007-2014 Christian Pointner <equinox@anytun.org>
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
 */

#ifndef UANYTUN_plain_packet_h_INCLUDED
#define UANYTUN_plain_packet_h_INCLUDED

#define PLAIN_PACKET_SIZE_MAX 1600

#define PAYLOAD_TYPE_TAP 0x6558
#define PAYLOAD_TYPE_TUN 0x0000
#define PAYLOAD_TYPE_TUN4 0x0800
#define PAYLOAD_TYPE_TUN6 0x86DD
#define PAYLOAD_TYPE_UNKNOWN 0xFFFF

struct plain_packet_struct {
  u_int32_t payload_length_;
  union __attribute__ ((__packed__)) {
    u_int8_t buf_[PLAIN_PACKET_SIZE_MAX];
    payload_type_t payload_type_;
  } data_;
};
typedef struct plain_packet_struct plain_packet_t;

void plain_packet_init(plain_packet_t* packet);

u_int32_t plain_packet_get_header_length();

u_int8_t* plain_packet_get_packet(plain_packet_t* packet);
u_int32_t plain_packet_get_length(plain_packet_t* packet);
void plain_packet_set_length(plain_packet_t* packet, u_int32_t len);

u_int8_t* plain_packet_get_payload(plain_packet_t* packet);
u_int32_t plain_packet_get_payload_length(plain_packet_t* packet);
void plain_packet_set_payload_length(plain_packet_t* packet, u_int32_t len);

payload_type_t plain_packet_get_type(plain_packet_t* packet);
void plain_packet_set_type(plain_packet_t* packet, payload_type_t type);


#endif
