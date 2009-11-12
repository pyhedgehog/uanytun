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

#ifndef UANYUTN_cipher_h_INCLUDED
#define UANYUTN_cipher_h_INCLUDED

#ifndef NO_CRYPT
#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif
#include "key_derivation.h"
#else
enum key_derivation_dir_enum { kd_inbound = 0, kd_outbound = 1 };
typedef enum key_derivation_dir_enum key_derivation_dir_t;
typedef u_int8_t key_derivation_t;
#endif

enum cipher_type_enum { c_unknown, c_null, c_aes_ctr };
typedef enum cipher_type_enum cipher_type_t;

struct cipher_struct {
  cipher_type_t type_;
  u_int16_t key_length_;
  buffer_t key_;
  buffer_t salt_;
  void* params_;
};
typedef struct cipher_struct cipher_t;

int cipher_init(cipher_t* c, const char* type);
void cipher_close(cipher_t* c);

int cipher_encrypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
int cipher_decrypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* in, plain_packet_t* out);

int32_t cipher_null_crypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen);


#ifndef NO_CRYPT

#define C_AESCTR_DEFAULT_KEY_LENGTH 128
#define C_AESCTR_CTR_LENGTH 16
#define C_AESCTR_SALT_LENGTH 14

union __attribute__((__packed__)) cipher_aesctr_ctr_union {
  u_int8_t buf_[C_AESCTR_CTR_LENGTH];
  struct __attribute__ ((__packed__)) {
    u_int8_t buf_[C_AESCTR_SALT_LENGTH];
    u_int16_t zero_;
  } salt_;
  struct __attribute__((__packed__)) {
    u_int8_t fill_[C_AESCTR_SALT_LENGTH - sizeof(mux_t) - sizeof(sender_id_t) - 2*sizeof(u_int8_t) - sizeof(seq_nr_t)];
    mux_t mux_;
    sender_id_t sender_id_;
    u_int8_t empty_[2];
    seq_nr_t seq_nr_;
    u_int16_t zero_;
  } params_;
};
typedef union cipher_aesctr_ctr_union cipher_aesctr_ctr_t;

struct cipher_aesctr_param_struct {
#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_;
#else
  AES_KEY aes_key_;
  u_int8_t ecount_buf_[AES_BLOCK_SIZE];
#endif
  cipher_aesctr_ctr_t ctr_;
};
typedef struct cipher_aesctr_param_struct cipher_aesctr_param_t;

int cipher_aesctr_init(cipher_t* c);
void cipher_aesctr_close(cipher_t* c);
int cipher_aesctr_calc_ctr(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
int32_t cipher_aesctr_crypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux);
#endif

#endif
