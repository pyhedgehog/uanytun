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

#ifndef _KEY_DERIVATION_H_
#define _KEY_DERIVATION_H_

#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/aes.h>
#endif

#include "options.h"

#define LABEL_ENC 0
#define LABEL_AUTH 1
#define LABEL_SALT 2
#define LABEL_NIL 3

#define LABEL_LEFT_ENC 0xDEADBEEF
#define LABEL_RIGHT_ENC 0xDEAE0010
#define LABEL_LEFT_SALT 0xDF10416F
#define LABEL_RIGHT_SALT 0xDF13FF90
#define LABEL_LEFT_AUTH 0xE0000683
#define LABEL_RIGHT_AUTH 0xE001B97C

enum key_derivation_type_enum { kd_unknown, kd_null, kd_aes_ctr };
typedef enum key_derivation_type_enum key_derivation_type_t;
enum key_derivation_dir_enum { kd_inbound, kd_outbound };
typedef enum key_derivation_dir_enum key_derivation_dir_t;

struct key_derivation_struct {
  key_derivation_type_t type_;
  u_int16_t key_length_;
  role_t role_;
  int8_t anytun02_compat_;
  buffer_t master_key_;
  buffer_t master_salt_;
  void* params_;
};
typedef struct key_derivation_struct key_derivation_t;

int key_derivation_init(key_derivation_t* kd, const char* type, role_t role, int8_t anytun02_compat, const char* passphrase, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len);
#ifndef NO_PASSPHRASE
int key_derivation_generate_master_key(key_derivation_t* kd, const char* passphrase, u_int16_t key_length);
int key_derivation_generate_master_salt(key_derivation_t* kd, const char* passphrase, u_int16_t salt_length);
#endif
void key_derivation_close(key_derivation_t* kd);
int key_derivation_generate(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);
satp_prf_label_t convert_label(role_t role, key_derivation_dir_t dir, satp_prf_label_t label);

int key_derivation_null_generate(u_int8_t* key, u_int32_t len);


#define KD_AESCTR_DEFAULT_KEY_LENGTH 128
#define KD_AESCTR_CTR_LENGTH 16
#define KD_AESCTR_SALT_LENGTH 14

union __attribute__((__packed__)) key_derivation_aesctr_ctr_union {
  u_int8_t buf_[KD_AESCTR_CTR_LENGTH];
  struct __attribute__ ((__packed__)) {
    u_int8_t buf_[KD_AESCTR_SALT_LENGTH];
    u_int16_t zero_;
  } salt_;
  struct __attribute__((__packed__)) {
    u_int8_t fill_[KD_AESCTR_SALT_LENGTH - sizeof(satp_prf_label_t) - sizeof(seq_nr_t)];
    satp_prf_label_t label_;
    seq_nr_t seq_;
    u_int16_t zero_;
  } params_;
  struct __attribute__((__packed__)) {
    u_int8_t fill_[KD_AESCTR_SALT_LENGTH - sizeof(u_int8_t) - 2*sizeof(u_int8_t) - sizeof(seq_nr_t)];
    u_int8_t label_;
    u_int8_t seq_fill_[2];
    seq_nr_t seq_;
    u_int16_t zero_;
  } params_compat_;
};
typedef union key_derivation_aesctr_ctr_union key_derivation_aesctr_ctr_t;

struct key_derivation_aesctr_param_struct {
#ifndef USE_SSL_CRYPTO
  gcry_cipher_hd_t handle_;
#else
  AES_KEY aes_key_;
  u_int8_t ecount_buf_[AES_BLOCK_SIZE];
#endif
  key_derivation_aesctr_ctr_t ctr_;
};
typedef struct key_derivation_aesctr_param_struct key_derivation_aesctr_param_t;

int key_derivation_aesctr_init(key_derivation_t* kd, const char* passphrase);
void key_derivation_aesctr_close(key_derivation_t* kd);
int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr);
int key_derivation_aesctr_generate(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

#endif
