/*
 *  �Anytun
 *
 *  �Anytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation �Anytun has no support for multiple connections
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
 *  This file is part of �Anytun.
 *
 *  �Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  �Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with �Anytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CIPHER_H_
#define _CIPHER_H_

#include <gcrypt.h>
#include "key_derivation.h"

enum cipher_type_enum { c_unknown, c_null, c_aes_ctr };
typedef enum cipher_type_enum cipher_type_t;

struct cipher_struct {
  cipher_type_t type_;
  u_int16_t key_length_;
  buffer_t key_;
  buffer_t salt_;
  gcry_cipher_hd_t handle_;
};
typedef struct cipher_struct cipher_t;

int cipher_init(cipher_t* c, const char* type);
void cipher_close(cipher_t* c);

int cipher_encrypt(cipher_t* c, key_derivation_t* kd, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
int cipher_decrypt(cipher_t* c, key_derivation_t* kd, encrypted_packet_t* in, plain_packet_t* out);

int32_t cipher_null_crypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen);

int cipher_aesctr_init(cipher_t* c);
void cipher_aesctr_close(cipher_t* c);
buffer_t cipher_aesctr_calc_ctr(cipher_t* c, key_derivation_t* kd, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
int32_t cipher_aesctr_crypt(cipher_t* c, key_derivation_t* kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);

#endif
