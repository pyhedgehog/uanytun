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

#ifndef _KEY_DERIVATION_H_
#define _KEY_DERIVATION_H_

#include <gcrypt.h>

enum satp_prf_label_enum {
  LABEL_SATP_ENCRYPTION  = 0x00,
  LABEL_SATP_MSG_AUTH    = 0x01,
  LABEL_SATP_SALT        = 0x02,
};
typedef enum satp_prf_label_enum satp_prf_label_t;

enum key_derivation_type_enum { unknown, null, aes_ctr };
typedef enum key_derivation_type_enum key_derivation_type_t;

struct key_derivation_struct {
  key_derivation_type_t type_;
  int8_t ld_kdr_;
  buffer_t master_key_;
  buffer_t master_salt_;
  gcry_cipher_hd_t handle_;
};
typedef struct key_derivation_struct key_derivation_t;

int key_derivation_init(key_derivation_t* kd, const char* type, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len);
void key_derivation_close(key_derivation_t* kd);
void key_derivation_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

void key_derivation_null_generate(u_int8_t* key, u_int32_t len);

int key_derivation_aesctr_init(key_derivation_t* kd, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len);
void key_derivation_aesctr_close(key_derivation_t* kd);
buffer_t key_derivation_aesctr_calc_ctr(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr);
void key_derivation_aesctr_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

#endif
