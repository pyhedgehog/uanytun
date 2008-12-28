/*
 *  µAnytun
 *
 *  µAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation µAnytun has no support for multiple connections
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
 *  This file is part of µAnytun.
 *
 *  µAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  µAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with µAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

enum cipher_type_enum { unknown, null, aes_ctr };
typedef enum cipher_type_enum cipher_type_t;

struct cipher_struct {
  cipher_type_t type_;
  buffer_t key_;
  buffer_t salt_;
};
typedef struct cipher_struct cipher_t;

void cipher_init(cipher_t** c, const char* type);
void cipher_set_key(cipher_t* c, u_int8_t* key, u_int32_t len);
void cipher_set_salt(cipher_t* c, u_int8_t* salt, u_int32_t len);
void cipher_close(cipher_t** c);

void cipher_encrypt(cipher_t* c, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
void cipher_decrypt(cipher_t* c, encrypted_packet_t* in, plain_packet_t* out);

u_int32_t cipher_null_encrypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen);
u_int32_t cipher_null_decrypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen);

#endif
