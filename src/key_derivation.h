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

#define KD_LABEL_COUNT 3
enum satp_prf_label_enum {
  LABEL_SATP_ENCRYPTION  = 0x00,
  LABEL_SATP_MSG_AUTH    = 0x01,
  LABEL_SATP_SALT        = 0x02,
};
typedef enum satp_prf_label_enum satp_prf_label_t;

enum key_derivation_type_enum { kd_unknown, kd_null, kd_aes_ctr };
typedef enum key_derivation_type_enum key_derivation_type_t;
enum key_store_dir_enum { kd_inbound = 0, kd_outbound = 1 };
typedef enum key_store_dir_enum key_store_dir_t;

struct key_store_struct {
  buffer_t key_;
  seq_nr_t r_;
};
typedef struct key_store_struct key_store_t;

struct key_derivation_struct {
  key_derivation_type_t type_;
  u_int16_t key_length_;
  int8_t ld_kdr_;
  buffer_t master_key_;
  buffer_t master_salt_;
  key_store_t key_store_[2][KD_LABEL_COUNT];
  void* params_;
};
typedef struct key_derivation_struct key_derivation_t;

int key_derivation_init(key_derivation_t* kd, const char* type, int8_t ld_kdr, const char* passphrase, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len);
#ifndef NO_PASSPHRASE
int key_derivation_generate_master_key(key_derivation_t* kd, const char* passphrase, u_int16_t key_length);
int key_derivation_generate_master_salt(key_derivation_t* kd, const char* passphrase, u_int16_t salt_length);
#endif
void key_derivation_close(key_derivation_t* kd);
int key_derivation_generate(key_derivation_t* kd, key_store_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

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
#ifndef ANYTUN_02_COMPAT
  struct __attribute__((__packed__)) {
    u_int8_t fill_[KD_AESCTR_SALT_LENGTH - sizeof(u_int8_t) - sizeof(seq_nr_t)];
    u_int8_t label_;
    seq_nr_t r_;
    u_int16_t zero_;
  } params_;
#else
  struct __attribute__((__packed__)) {
    u_int8_t fill_[KD_AESCTR_SALT_LENGTH - sizeof(u_int8_t) - 2 - sizeof(seq_nr_t)];
    u_int8_t label_;
    u_int8_t r_fill_[2];
    seq_nr_t r_;
    u_int16_t zero_;
  } params_;
#endif
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
int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, key_store_dir_t dir, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr);
int key_derivation_aesctr_generate(key_derivation_t* kd, key_store_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

#endif
