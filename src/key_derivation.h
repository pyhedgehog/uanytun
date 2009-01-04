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

#ifndef _KEY_DERIVATION_H_
#define _KEY_DERIVATION_H_

#include <gcrypt.h>
#ifndef NO_LIBGMP
#include <gmp.h>
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
  key_store_t key_store_[KD_LABEL_COUNT];
  void* params_;
};
typedef struct key_derivation_struct key_derivation_t;

int key_derivation_init(key_derivation_t* kd, const char* type, int8_t ld_kdr, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len);
void key_derivation_close(key_derivation_t* kd);
int key_derivation_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

int key_derivation_null_generate(u_int8_t* key, u_int32_t len);


#define KD_AES_CTR_LENGTH 16
#define KD_AES_CTR_ZERO_LENGTH 2
#ifdef NO_LIBGMP
union __attribute__ ((__packed__)) key_derivation_aesctr_ctr_buf_union {
  u_int8_t buf_[KD_AES_CTR_LENGTH];
  struct __attribute__ ((__packed__)) {
    u_int8_t buf_[KD_AES_CTR_LENGTH - KD_AES_CTR_ZERO_LENGTH];
    u_int8_t zero_[KD_AES_CTR_ZERO_LENGTH];
  } salt_;
#ifndef ANYTUN_02_COMPAT
  struct __attribute__ ((__packed__)) {
    u_int8_t fill_[KD_AES_CTR_LENGTH - sizeof(u_int8_t) - sizeof(seq_nr_t) - KD_AES_CTR_ZERO_LENGTH];
    u_int8_t label_;
    seq_nr_t r_;
    u_int8_t zero_[KD_AES_CTR_ZERO_LENGTH];
  } params_;
#else
  struct __attribute__ ((__packed__)) {
    u_int8_t fill_[KD_AES_CTR_LENGTH - sizeof(u_int8_t) - 2 - sizeof(seq_nr_t) - KD_AES_CTR_ZERO_LENGTH];
    u_int8_t label_;
    u_int8_t r_fill_[2];
    seq_nr_t r_;
    u_int8_t zero_[KD_AES_CTR_ZERO_LENGTH];
  } params_;
#endif
};
typedef union key_derivation_aesctr_ctr_buf_union key_derivation_aesctr_ctr_buf_t;

struct key_derivation_aesctr_ctr_struct {
  u_int32_t length_;
  u_int8_t* buf_;
  key_derivation_aesctr_ctr_buf_t ctr_;
};
typedef struct key_derivation_aesctr_ctr_struct key_derivation_aesctr_ctr_t;
#endif

struct key_derivation_aesctr_param_struct {
  gcry_cipher_hd_t handle_;
#ifndef NO_LIBGMP
  buffer_t ctr_;
  mpz_t mp_ctr;
  mpz_t mp_key_id;
#else
  key_derivation_aesctr_ctr_t ctr_;
#endif
};
typedef struct key_derivation_aesctr_param_struct key_derivation_aesctr_param_t;

int key_derivation_aesctr_init(key_derivation_t* kd);
void key_derivation_aesctr_close(key_derivation_t* kd);
int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr);
int key_derivation_aesctr_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len);

#endif
