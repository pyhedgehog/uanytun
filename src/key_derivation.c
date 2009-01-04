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

#include "datatypes.h"

#include "key_derivation.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

#ifndef NO_LIBGMP
#include <gmp.h>
#endif

int key_derivation_init(key_derivation_t* kd, const char* type, int8_t ld_kdr, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len)
{
  if(!kd) 
    return -1;

  kd->type_ = kd_unknown;
  if(!strcmp(type, "null"))
    kd->type_ = kd_null;
  else if(!strcmp(type, "aes-ctr"))
    kd->type_ = kd_aes_ctr;
  else {
    log_printf(ERR, "unknown key derivation type");
    return -1;
  }

  kd->ld_kdr_ = ld_kdr;
  if(ld_kdr > (int8_t)(sizeof(seq_nr_t) * 8))
    kd->ld_kdr_ = sizeof(seq_nr_t) * 8;

  kd->key_length_ = key_len * sizeof(key[0]) * 8;
  kd->handle_ = 0;

  int i;
  for(i = 0; i<KD_LABEL_COUNT; ++i) {
    kd->key_store_[i].key_.buf_ = NULL;
    kd->key_store_[i].key_.length_ = 0;
    kd->key_store_[i].r_ = 0;
  }

  if(!key) {
    kd->master_key_.buf_ = NULL;
    kd->master_key_.length_ = 0;
  }
  else {
    kd->master_key_.buf_ = malloc(key_len);
    if(!kd->master_key_.buf_)
      return -2;
    memcpy(kd->master_key_.buf_, key, key_len);
    kd->master_key_.length_ = key_len;
  }

  if(!salt) {
    kd->master_salt_.buf_ = NULL;
    kd->master_salt_.length_ = 0;
  }
  else {
    kd->master_salt_.buf_ = malloc(salt_len);
    if(!kd->master_salt_.buf_) {
      if(kd->master_key_.buf_)
        free(kd->master_key_.buf_);
      return -2;
    }
    memcpy(kd->master_salt_.buf_, salt, salt_len);
    kd->master_salt_.length_ = salt_len;
  }

  int ret = 0;
  if(kd->type_ == kd_aes_ctr)
    ret = key_derivation_aesctr_init(kd);

  if(ret)
    key_derivation_close(kd);

  return ret;
}

void key_derivation_close(key_derivation_t* kd)
{
  if(!kd)
    return;

  if(kd->type_ == kd_aes_ctr)
    key_derivation_aesctr_close(kd);

  if(kd->master_key_.buf_)
    free(kd->master_key_.buf_);
  if(kd->master_salt_.buf_)
    free(kd->master_salt_.buf_);

  int i;
  for(i = 0; i<KD_LABEL_COUNT; ++i) {
    if(kd->key_store_[i].key_.buf_)
      free(kd->key_store_[i].key_.buf_);
  }
}

int key_derivation_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !key) 
    return -1;

  if(label >= KD_LABEL_COUNT) {
    log_printf(ERR, "label 0x%02X out of range", label);
    return -1;
  }

  int ret = 0;
  if(kd->type_ == kd_null)
    ret = key_derivation_null_generate(key, len);
  else if(kd->type_ == kd_aes_ctr)
    ret = key_derivation_aesctr_generate(kd, label, seq_nr, key, len);
  else {
    log_printf(ERR, "unknown key derivation type");
    return -1;
  }
  return ret;
}

/* ---------------- NULL Key Derivation ---------------- */

int key_derivation_null_generate(u_int8_t* key, u_int32_t len)
{
  memset(key, 0, len);
  return 1;
}

/* ---------------- AES-Ctr Key Derivation ---------------- */

int key_derivation_aesctr_init(key_derivation_t* kd)
{
  if(!kd)
    return -1;

  int algo;
  switch(kd->key_length_) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    log_printf(ERR, "key derivation key length of %d Bits is not supported", kd->key_length_);
    return -1;
  }
  }

  gcry_error_t err = gcry_cipher_open(&kd->handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERR, "failed to open key derivation cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  } 

  err = gcry_cipher_setkey(kd->handle_, kd->master_key_.buf_, kd->master_key_.length_);
  if(err) {
    log_printf(ERR, "failed to set key derivation key: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }

  return 0;
}

void key_derivation_aesctr_close(key_derivation_t* kd)
{
  if(!kd)
    return;

  if(kd->handle_)
    gcry_cipher_close(kd->handle_);
}

int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, key_store_t* result, satp_prf_label_t label, seq_nr_t seq_nr)
{
  if(!kd || !result)
    return -1;

  seq_nr_t r = 0;
  if(kd->ld_kdr_ >= 0)
    r = seq_nr >> kd->ld_kdr_;

  if(kd->key_store_[label].key_.buf_ && kd->key_store_[label].r_ == r) {
    if(!r || (seq_nr % r))
      return 0;
  }
  result->r_ = r;

  int faked_msb = 0;
  if(!kd->master_salt_.buf_[0]) {
    kd->master_salt_.buf_[0] = 1;
    faked_msb = 1;
  }

#ifndef NO_LIBGMP
  mpz_t ctr, key_id;
  mpz_init2(ctr, 128);
  mpz_init2(key_id, 128);

  mpz_import(ctr, kd->master_salt_.length_, 1, 1, 0, 0, kd->master_salt_.buf_);

  mpz_set_ui(key_id, label);
#ifndef ANYTUN_02_COMPAT
  mpz_mul_2exp(key_id, key_id, (sizeof(r) * 8));
#else
  mpz_mul_2exp(key_id, key_id, 48);
#endif
  mpz_add_ui(key_id, key_id, r);

  mpz_xor(ctr, ctr, key_id);
  mpz_mul_2exp(ctr, ctr, 16);

  if(result->key_.buf_)
    free(result->key_.buf_);
  result->key_.buf_ = mpz_export(NULL, (size_t*)&(result->key_.length_), 1, 1, 0, 0, ctr);
  mpz_clear(ctr);
  mpz_clear(key_id);
#endif

#ifndef ANYTUN_02_COMPAT
  if(faked_msb) {
    kd->master_salt_.buf_[0] = 0;
    result->key_.buf_[0] = 0;
  }
#endif

  return 1;
}

int key_derivation_aesctr_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !kd->master_key_.buf_ || !kd->master_salt_.buf_) {
    log_printf(ERR, "key derivation not initialized or no key or salt set");
    return -1;
  }

  key_store_t ctr;
  ctr.key_.buf_ = NULL;
  ctr.key_.length_ = 0;
  ctr.r_ = 0;
  int ret = key_derivation_aesctr_calc_ctr(kd, &ctr, label, seq_nr);
  if(ret < 0) {
    log_printf(ERR, "failed to calculate key derivation CTR");
    return -1;
  }
  else if(!ret) {
    if(len > kd->key_store_[label].key_.length_) {
      log_printf(WARNING, "stored (old) key for label 0x%02X is too short, filling with zeros", label);
      memset(key, 0, len);
      len = kd->key_store_[label].key_.length_;
    }
    memcpy(key, kd->key_store_[label].key_.buf_, len);
    return 0;
  }

  gcry_error_t err = gcry_cipher_reset(kd->handle_);
  if(err) {
    log_printf(ERR, "failed to reset key derivation cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }

  err = gcry_cipher_setctr(kd->handle_, ctr.key_.buf_, ctr.key_.length_);
  free(ctr.key_.buf_);

  if(err) {
    log_printf(ERR, "failed to set key derivation CTR: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }

  memset(key, 0, len);
  err = gcry_cipher_encrypt(kd->handle_, key, len, NULL, 0);
  if(err) {
    log_printf(ERR, "failed to generate key derivation bitstream: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }
  
  if(!kd->ld_kdr_)
    return 1;

  if(!kd->key_store_[label].key_.buf_) {
    kd->key_store_[label].key_.length_ = 0;
    kd->key_store_[label].key_.buf_ = malloc(len);
    if(!kd->key_store_[label].key_.buf_)
      return -2;

    kd->key_store_[label].key_.length_ = len;
  }
  else if(kd->key_store_[label].key_.length_ < len) {
    u_int8_t* tmp = realloc(kd->key_store_[label].key_.buf_, len);
    if(!tmp)
      return -2;

    kd->key_store_[label].key_.buf_ = tmp;
    kd->key_store_[label].key_.length_ = len;
  }

  memcpy(kd->key_store_[label].key_.buf_, key, len);
  kd->key_store_[label].r_ = ctr.r_;

  return 1;
}
