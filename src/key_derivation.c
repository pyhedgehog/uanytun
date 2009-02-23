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

#include "datatypes.h"

#include "key_derivation.h"

#ifdef USE_SSL_CRYPTO
#include <openssl/sha.h>
#endif

#include "log.h"

#include <stdlib.h>
#include <string.h>

int key_derivation_init(key_derivation_t* kd, const char* type, int8_t ld_kdr, int8_t anytun02_compat, const char* passphrase, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len)
{
  if(!kd) 
    return -1;

  kd->anytun02_compat_ = anytun02_compat;
  kd->key_length_ = 0;

  kd->type_ = kd_unknown;
  if(!strcmp(type, "null"))
    kd->type_ = kd_null;
  else if(!strncmp(type, "aes-ctr", 7)) {
    kd->type_ = kd_aes_ctr;
    if(type[7] == 0) {
      kd->key_length_ = KD_AESCTR_DEFAULT_KEY_LENGTH;
    }
    else if(type[7] != '-') 
      return -1;
    else {
      const char* tmp = &type[8];
      kd->key_length_ = atoi(tmp);
    }
  }
  else {
    log_printf(ERROR, "unknown key derivation type");
    return -1;
  }

  kd->ld_kdr_ = ld_kdr;
  if(ld_kdr > (int8_t)(sizeof(seq_nr_t) * 8))
    kd->ld_kdr_ = sizeof(seq_nr_t) * 8;

  kd->params_ = NULL;

  int d, i;
  for(d = 0; d<2; ++d) {
    for(i = 0; i<KD_LABEL_COUNT; ++i) {
      kd->key_store_[d][i].key_.buf_ = NULL;
      kd->key_store_[d][i].key_.length_ = 0;
      kd->key_store_[d][i].r_ = 0;
    }
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
    ret = key_derivation_aesctr_init(kd, passphrase);

  if(ret)
    key_derivation_close(kd);

  return ret;
}

#ifndef NO_PASSPHRASE
int key_derivation_generate_master_key(key_derivation_t* kd, const char* passphrase, u_int16_t key_length)
{
  if(!kd || !passphrase)
    return -1;

  if(kd->master_key_.buf_) {
    log_printf(ERROR, "master key and passphrase provided, ignoring passphrase");
    return 0;
  }    
  log_printf(NOTICE, "using passphrase to generate master key");

  if(!key_length || (key_length % 8)) {
    log_printf(ERROR, "bad master key length");
    return -1;
  }

#ifndef USE_SSL_CRYPTO
  if(key_length > (gcry_md_get_algo_dlen(GCRY_MD_SHA256) * 8)) {
#else
  if(key_length > (SHA256_DIGEST_LENGTH * 8)) {
#endif
    log_printf(ERROR, "master key too long for passphrase algorithm");
    return -1;
  }

  buffer_t digest;
#ifndef USE_SSL_CRYPTO
  digest.length_ = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
#else
  digest.length_ = SHA256_DIGEST_LENGTH;
#endif
  digest.buf_ = malloc(digest.length_);
  if(!digest.buf_)
    return -2;


#ifndef USE_SSL_CRYPTO
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest.buf_, passphrase, strlen(passphrase));
#else
  SHA256(passphrase, strlen(passphrase), digest.buf_);
#endif

  kd->master_key_.length_ = key_length/8;
  kd->master_key_.buf_ = malloc(kd->master_key_.length_);
  if(!kd->master_key_.buf_) {
    kd->master_key_.length_ = 0;
    free(digest.buf_);
    return -2;
  }

  memcpy(kd->master_key_.buf_, &digest.buf_[digest.length_ - kd->master_key_.length_], kd->master_key_.length_);
  free(digest.buf_);

  return 0;
}

int key_derivation_generate_master_salt(key_derivation_t* kd, const char* passphrase, u_int16_t salt_length)
{
  if(!kd || !passphrase)
    return -1;

  if(kd->master_salt_.buf_) {
    log_printf(ERROR, "master salt and passphrase provided, ignoring passphrase");
    return 0;
  }    
  log_printf(NOTICE, "using passphrase to generate master salt");

  if(!salt_length || (salt_length % 8)) {
    log_printf(ERROR, "bad master salt length");
    return -1;
  }

#ifndef USE_SSL_CRYPTO
  if(salt_length > (gcry_md_get_algo_dlen(GCRY_MD_SHA1) * 8)) {
#else
  if(salt_length > (SHA_DIGEST_LENGTH * 8)) {
#endif
    log_printf(ERROR, "master salt too long for passphrase algorithm");
    return -1;
  }

  buffer_t digest;
#ifndef USE_SSL_CRYPTO
  digest.length_ = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
#else
  digest.length_ = SHA_DIGEST_LENGTH;
#endif
  digest.buf_ = malloc(digest.length_);
  if(!digest.buf_)
    return -2;

#ifndef USE_SSL_CRYPTO
  gcry_md_hash_buffer(GCRY_MD_SHA1, digest.buf_, passphrase, strlen(passphrase));
#else
  SHA1(passphrase, strlen(passphrase), digest.buf_);
#endif

  kd->master_salt_.length_ = salt_length/8;
  kd->master_salt_.buf_ = malloc(kd->master_salt_.length_);
  if(!kd->master_salt_.buf_) {
    kd->master_salt_.length_ = 0;
    free(digest.buf_);
    return -2;
  }

  memcpy(kd->master_salt_.buf_, &digest.buf_[digest.length_ - kd->master_salt_.length_], kd->master_salt_.length_);
  free(digest.buf_);

  return 0;
}
#endif

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

  int d, i;
  for(d = 0; d<2; ++d) {
    for(i = 0; i<KD_LABEL_COUNT; ++i) {
      if(kd->key_store_[d][i].key_.buf_)
        free(kd->key_store_[d][i].key_.buf_);
    }
  }
}

int key_derivation_generate(key_derivation_t* kd, key_store_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !key) 
    return -1;

  if(label >= KD_LABEL_COUNT) {
    log_printf(ERROR, "label 0x%02X out of range", label);
    return -1;
  }

  int ret = 0;
  if(kd->type_ == kd_null)
    ret = key_derivation_null_generate(key, len);
  else if(kd->type_ == kd_aes_ctr)
    ret = key_derivation_aesctr_generate(kd, dir, label, seq_nr, key, len);
  else {
    log_printf(ERROR, "unknown key derivation type");
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

int key_derivation_aesctr_init(key_derivation_t* kd, const char* passphrase)
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
  params->handle_ = 0;
#endif

#ifndef NO_PASSPHRASE
  if(passphrase) {
    int ret = key_derivation_generate_master_key(kd, passphrase, kd->key_length_);
    if(ret)
      return ret;
    ret = key_derivation_generate_master_salt(kd, passphrase, KD_AESCTR_SALT_LENGTH*8);
    if(ret)
      return ret;
  }
#endif

#ifndef USE_SSL_CRYPTO
  int algo;
  switch(kd->key_length_) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    log_printf(ERROR, "key derivation key length of %d Bits is not supported", kd->key_length_);
    return -1;
  }
  }

  gcry_error_t err = gcry_cipher_open(&params->handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERROR, "failed to open key derivation cipher: %s", gcry_strerror(err));
    return -1;
  } 

  err = gcry_cipher_setkey(params->handle_, kd->master_key_.buf_, kd->master_key_.length_);
  if(err) {
    log_printf(ERROR, "failed to set key derivation key: %s", gcry_strerror(err));
    return -1;
  }
#else
  int ret = AES_set_encrypt_key(kd->master_key_.buf_, kd->master_key_.length_*8, &params->aes_key_);
  if(ret) {
    log_printf(ERROR, "failed to set key derivation ssl aes-key (code: %d)", ret);
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

int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, key_store_dir_t dir, seq_nr_t* r, satp_prf_label_t label, seq_nr_t seq_nr)
{
  if(!kd || !kd->params_ || !r)
    return -1;

  key_derivation_aesctr_param_t* params = kd->params_;

  *r = 0;
  if(kd->ld_kdr_ >= 0)
    *r = seq_nr >> kd->ld_kdr_;

  if(kd->key_store_[dir][label].key_.buf_ && kd->key_store_[dir][label].r_ == *r) {
    if(!(*r) || (seq_nr % (*r)))
      return 0;
  }

  if(kd->master_salt_.length_ != KD_AESCTR_SALT_LENGTH) {
    log_printf(ERROR, "master salt has the wrong length");
    return -1;
  }
  memcpy(params->ctr_.salt_.buf_, kd->master_salt_.buf_, KD_AESCTR_SALT_LENGTH);
  params->ctr_.salt_.zero_ = 0;
  if(kd->anytun02_compat_) {
    params->ctr_.params_compat_.label_ ^= label;
    params->ctr_.params_compat_.r_ ^= SEQ_NR_T_HTON(*r);
  }
  else {
    params->ctr_.params_.label_ ^= label;
    params->ctr_.params_.r_ ^= SEQ_NR_T_HTON(*r);
  }

  return 1;
}

int key_derivation_aesctr_generate(key_derivation_t* kd, key_store_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !kd->params_ || !kd->master_key_.buf_ || !kd->master_salt_.buf_) {
    log_printf(ERROR, "key derivation not initialized or no key or salt set");
    return -1;
  }

  key_derivation_aesctr_param_t* params = kd->params_;

  seq_nr_t r;
  int ret = key_derivation_aesctr_calc_ctr(kd, dir, &r, label, seq_nr);
  if(ret < 0) {
    log_printf(ERROR, "failed to calculate key derivation CTR");
    return -1;
  }
  else if(!ret) {
    if(len > kd->key_store_[dir][label].key_.length_) {
      log_printf(WARNING, "stored (old) key for label 0x%02X is too short, filling with zeros", label);
      memset(key, 0, len);
      len = kd->key_store_[dir][label].key_.length_;
    }
    memcpy(key, kd->key_store_[dir][label].key_.buf_, len);
    return 0;
  }

#ifndef USE_SSL_CRYPTO
  gcry_error_t err = gcry_cipher_reset(params->handle_);
  if(err) {
    log_printf(ERROR, "failed to reset key derivation cipher: %s", gcry_strerror(err));
    return -1;
  }

  err = gcry_cipher_setctr(params->handle_, params->ctr_.buf_, KD_AESCTR_CTR_LENGTH);
  if(err) {
    log_printf(ERROR, "failed to set key derivation CTR: %s", gcry_strerror(err));
    return -1;
  }

  memset(key, 0, len);
  err = gcry_cipher_encrypt(params->handle_, key, len, NULL, 0);
  if(err) {
    log_printf(ERROR, "failed to generate key derivation bitstream: %s", gcry_strerror(err));
    return -1;
  }
#else
  if(KD_AESCTR_CTR_LENGTH != AES_BLOCK_SIZE) {
    log_printf(ERROR, "failed to set key derivation CTR: size don't fits");
    return -1;
  }
  u_int32_t num = 0;
  memset(params->ecount_buf_, 0, AES_BLOCK_SIZE);
  memset(key, 0, len);
  AES_ctr128_encrypt(key, key, len, &params->aes_key_, params->ctr_.buf_, params->ecount_buf_, &num);
#endif
  
  if(!kd->ld_kdr_)
    return 1;

  if(!kd->key_store_[dir][label].key_.buf_) {
    kd->key_store_[dir][label].key_.length_ = 0;
    kd->key_store_[dir][label].key_.buf_ = malloc(len);
    if(!kd->key_store_[dir][label].key_.buf_)
      return -2;

    kd->key_store_[dir][label].key_.length_ = len;
  }
  else if(kd->key_store_[dir][label].key_.length_ < len) {
    u_int8_t* tmp = realloc(kd->key_store_[dir][label].key_.buf_, len);
    if(!tmp)
      return -2;

    kd->key_store_[dir][label].key_.buf_ = tmp;
    kd->key_store_[dir][label].key_.length_ = len;
  }

  memcpy(kd->key_store_[dir][label].key_.buf_, key, len);
  kd->key_store_[dir][label].r_ = r;

  return 1;
}
