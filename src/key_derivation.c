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
  kd->params_ = NULL;

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

  if(kd->params_)
    free(kd->params_);
  kd->params_ = malloc(sizeof(key_derivation_aesctr_param_t));
  if(!kd->params_)
    return -2;

  key_derivation_aesctr_param_t* params = kd->params_;

#ifndef USE_SSL_CRYPTO
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

  gcry_error_t err = gcry_cipher_open(&params->handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERR, "failed to open key derivation cipher: %s", gcry_strerror(err));
    return -1;
  } 

  err = gcry_cipher_setkey(params->handle_, kd->master_key_.buf_, kd->master_key_.length_);
  if(err) {
    log_printf(ERR, "failed to set key derivation key: %s", gcry_strerror(err));
    return -1;
  }
#else
  int ret = AES_set_encrypt_key(kd->master_key_.buf_, kd->master_key_.length_*8, &params->aes_key_);
  if(ret) {
    log_printf(ERR, "failed to set key derivation ssl aes-key (code: %d)", ret);
    return -1;
  }
#endif

  return 0;
}

void key_derivation_aesctr_close(key_derivation_t* kd)
{
  if(!kd)
    return;

  if(kd->params_) {
    key_derivation_aesctr_param_t* params = kd->params_;

#ifndef USE_SSL_CRYPTO
    if(params->handle_)
      gcry_cipher_close(params->handle_);
#endif

    free(kd->params_);
  }
}

int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr)
{
  if(!kd || !kd->params_ || !r)
    return -1;

  key_derivation_aesctr_param_t* params = kd->params_;

  *r = 0;
  if(kd->ld_kdr_ >= 0)
    *r = seq_nr >> kd->ld_kdr_;

  if(kd->key_store_[label].key_.buf_ && kd->key_store_[label].r_ == *r) {
    if(!(*r) || (seq_nr % (*r)))
      return 0;
  }

  int faked_msb = 0;
  if(!kd->master_salt_.buf_[0]) {
    kd->master_salt_.buf_[0] = 1;
    faked_msb = 1;
  }

  if(kd->master_salt_.length_ != KD_AESCTR_SALT_LENGTH) {
    log_printf(ERR, "master salt has the wrong length");
    return -1;
  }
  memcpy(params->ctr_.salt_.buf_, kd->master_salt_.buf_, KD_AESCTR_SALT_LENGTH);
  params->ctr_.salt_.zero_ = 0;
  params->ctr_.params_.label_ ^= label;
  params->ctr_.params_.r_ ^= SEQ_NR_T_HTON(*r);

#ifndef ANYTUN_02_COMPAT
  if(faked_msb) {
    kd->master_salt_.buf_[0] = 0;
    params->ctr_.buf_[0] = 0;
  }
#endif

  return 1;
}

int key_derivation_aesctr_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !kd->params_ || !kd->master_key_.buf_ || !kd->master_salt_.buf_) {
    log_printf(ERR, "key derivation not initialized or no key or salt set");
    return -1;
  }

  key_derivation_aesctr_param_t* params = kd->params_;

  seq_nr_t r;
  int ret = key_derivation_aesctr_calc_ctr(kd, &r, label, seq_nr);
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

#ifndef USE_SSL_CRYPTO
  gcry_error_t err = gcry_cipher_reset(params->handle_);
  if(err) {
    log_printf(ERR, "failed to reset key derivation cipher: %s", gcry_strerror(err));
    return -1;
  }

  err = gcry_cipher_setctr(params->handle_, params->ctr_.buf_, KD_AESCTR_CTR_LENGTH);

  if(err) {
    log_printf(ERR, "failed to set key derivation CTR: %s", gcry_strerror(err));
    return -1;
  }

  memset(key, 0, len);
  err = gcry_cipher_encrypt(params->handle_, key, len, NULL, 0);
  if(err) {
    log_printf(ERR, "failed to generate key derivation bitstream: %s", gcry_strerror(err));
    return -1;
  }
#else
  if(KD_AESCTR_CTR_LENGTH != AES_BLOCK_SIZE) {
    log_printf(ERR, "failed to set key derivation CTR: size don't fits");
    return -1;
  }
  u_int32_t num = 0;
  memset(params->ecount_buf, 0, AES_BLOCK_SIZE);
  memset(key, 0, len);
  AES_ctr128_encrypt(key, key, len, &params->aes_key_, params->ctr_.buf_, params->ecount_buf, &num);
#endif
  
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
  kd->key_store_[label].r_ = r;

  return 1;
}
