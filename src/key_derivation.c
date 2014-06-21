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
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Christian Pointner <equinox@anytun.org>
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

#include "datatypes.h"

#include "key_derivation.h"

#if defined(USE_SSL_CRYPTO)
#include <openssl/sha.h>
#elif defined(USE_NETTLE)
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/ctr.h>
#endif

#include "log.h"

#include <stdlib.h>
#include <string.h>

int key_derivation_init(key_derivation_t* kd, const char* type, role_t role, const char* passphrase, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len)
{
  if(!kd)
    return -1;

  kd->role_ = role;
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

  switch(role) {
  case ROLE_LEFT: log_printf(NOTICE, "key derivation role: left"); break;
  case ROLE_RIGHT: log_printf(NOTICE, "key derivation role: right"); break;
  default: log_printf(NOTICE, "key derivation role: unknown"); break;
  }
  kd->params_ = NULL;

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
    log_printf(WARNING, "master key and passphrase provided, ignoring passphrase");
    return 0;
  }
  log_printf(NOTICE, "using passphrase to generate master key");

  if(!key_length || (key_length % 8)) {
    log_printf(ERROR, "bad master key length");
    return -1;
  }

#if defined(USE_SSL_CRYPTO)
  if(key_length > (SHA256_DIGEST_LENGTH * 8)) {
#elif defined(USE_NETTLE)
  if(key_length > (SHA256_DIGEST_SIZE * 8)) {
#else  // USE_GCRYPT is the default
  if(key_length > (gcry_md_get_algo_dlen(GCRY_MD_SHA256) * 8)) {
#endif
    log_printf(ERROR, "master key too long for passphrase algorithm");
    return -1;
  }

  buffer_t digest;
#if defined(USE_SSL_CRYPTO)
  digest.length_ = SHA256_DIGEST_LENGTH;
#elif defined(USE_NETTLE)
  digest.length_ = SHA256_DIGEST_SIZE;
#else  // USE_GCRYPT is the default
  digest.length_ = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
#endif
  digest.buf_ = malloc(digest.length_);
  if(!digest.buf_)
    return -2;


#if defined(USE_SSL_CRYPTO)
  SHA256((const u_int8_t*)passphrase, strlen(passphrase), digest.buf_);
#elif defined(USE_NETTLE)
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, strlen(passphrase), (const u_int8_t*)passphrase);
  sha256_digest(&ctx, digest.length_, digest.buf_);
#else  // USE_GCRYPT is the default
  gcry_md_hash_buffer(GCRY_MD_SHA256, digest.buf_, passphrase, strlen(passphrase));
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
    log_printf(WARNING, "master salt and passphrase provided, ignoring passphrase");
    return 0;
  }
  log_printf(NOTICE, "using passphrase to generate master salt");

  if(!salt_length || (salt_length % 8)) {
    log_printf(ERROR, "bad master salt length");
    return -1;
  }

#if defined(USE_SSL_CRYPTO)
  if(salt_length > (SHA_DIGEST_LENGTH * 8)) {
#elif defined(USE_NETTLE)
  if(salt_length > (SHA1_DIGEST_SIZE * 8)) {
#else  // USE_GCRYPT is the default
  if(salt_length > (gcry_md_get_algo_dlen(GCRY_MD_SHA1) * 8)) {
#endif
    log_printf(ERROR, "master salt too long for passphrase algorithm");
    return -1;
  }

  buffer_t digest;
#if defined(USE_SSL_CRYPTO)
  digest.length_ = SHA_DIGEST_LENGTH;
#elif defined(USE_NETTLE)
  digest.length_ = SHA1_DIGEST_SIZE;
#else  // USE_GCRYPT is the default
  digest.length_ = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
#endif
  digest.buf_ = malloc(digest.length_);
  if(!digest.buf_)
    return -2;

#if defined(USE_SSL_CRYPTO)
  SHA1((const u_int8_t*)passphrase, strlen(passphrase), digest.buf_);
#elif defined(USE_NETTLE)
  struct sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, strlen(passphrase), (const u_int8_t*)passphrase);
  sha1_digest(&ctx, digest.length_, digest.buf_);
#else  // USE_GCRYPT is the default
  gcry_md_hash_buffer(GCRY_MD_SHA1, digest.buf_, passphrase, strlen(passphrase));
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
}

int key_derivation_generate(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !key)
    return -1;

  if(label >= LABEL_NIL) {
    log_printf(ERROR, "unknown label 0x%02X", label);
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

satp_prf_label_t convert_label(role_t role, key_derivation_dir_t dir, satp_prf_label_t label)
{
  switch(label) {
  case LABEL_ENC: {
    if(dir == kd_outbound) {
      if(role == ROLE_LEFT) return LABEL_LEFT_ENC;
      if(role == ROLE_RIGHT) return LABEL_RIGHT_ENC;
    }
    else {
      if(role == ROLE_LEFT) return LABEL_RIGHT_ENC;
      if(role == ROLE_RIGHT) return LABEL_LEFT_ENC;
    }
    break;
  }
  case LABEL_SALT: {
    if(dir == kd_outbound) {
      if(role == ROLE_LEFT) return LABEL_LEFT_SALT;
      if(role == ROLE_RIGHT) return LABEL_RIGHT_SALT;
    }
    else {
      if(role == ROLE_LEFT) return LABEL_RIGHT_SALT;
      if(role == ROLE_RIGHT) return LABEL_LEFT_SALT;
    }
    break;
  }
  case LABEL_AUTH: {
    if(dir == kd_outbound) {
      if(role == ROLE_LEFT) return LABEL_LEFT_AUTH;
      if(role == ROLE_RIGHT) return LABEL_RIGHT_AUTH;
    }
    else {
      if(role == ROLE_LEFT) return LABEL_RIGHT_AUTH;
      if(role == ROLE_RIGHT) return LABEL_LEFT_AUTH;
    }
    break;
  }
  }

  return label;
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
#ifdef USE_GCRYPT
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

#if defined(USE_SSL_CRYPTO)
  int ret = AES_set_encrypt_key(kd->master_key_.buf_, kd->master_key_.length_*8, &params->aes_key_);
  if(ret) {
    log_printf(ERROR, "failed to set key derivation ssl aes-key (code: %d)", ret);
    return -1;
  }
#elif defined(USE_NETTLE)
  aes_set_encrypt_key(&params->ctx_, kd->master_key_.length_, kd->master_key_.buf_);
#else  // USE_GCRYPT is the default
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
#endif

  return 0;
}

void key_derivation_aesctr_close(key_derivation_t* kd)
{
  if(!kd)
    return;

  if(kd->params_) {
#ifdef USE_GCRYPT
    key_derivation_aesctr_param_t* params = kd->params_;
    if(params->handle_)
      gcry_cipher_close(params->handle_);
#endif

    free(kd->params_);
  }
}

int key_derivation_aesctr_calc_ctr(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr)
{
  if(!kd || !kd->params_)
    return -1;

  key_derivation_aesctr_param_t* params = kd->params_;

  if(kd->master_salt_.length_ != KD_AESCTR_SALT_LENGTH) {
    log_printf(ERROR, "master salt has wrong length");
    return -1;
  }
  memcpy(params->ctr_.salt_.buf_, kd->master_salt_.buf_, KD_AESCTR_SALT_LENGTH);
  params->ctr_.salt_.zero_ = 0;
  params->ctr_.params_.label_ ^= SATP_PRF_LABEL_T_HTON(convert_label(kd->role_, dir, label));
  params->ctr_.params_.seq_ ^= SEQ_NR_T_HTON(seq_nr);

  return 0;
}

int key_derivation_aesctr_generate(key_derivation_t* kd, key_derivation_dir_t dir, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !kd->params_ || !kd->master_key_.buf_ || !kd->master_salt_.buf_) {
    log_printf(ERROR, "key derivation not initialized or no key or salt set");
    return -1;
  }

  key_derivation_aesctr_param_t* params = kd->params_;

  if(key_derivation_aesctr_calc_ctr(kd, dir, label, seq_nr)) {
    log_printf(ERROR, "failed to calculate key derivation CTR");
    return -1;
  }

#if defined(USE_SSL_CRYPTO)
  if(KD_AESCTR_CTR_LENGTH != AES_BLOCK_SIZE) {
    log_printf(ERROR, "failed to set key derivation CTR: size don't fits");
    return -1;
  }
  u_int32_t num = 0;
  memset(params->ecount_buf_, 0, AES_BLOCK_SIZE);
  memset(key, 0, len);
  AES_ctr128_encrypt(key, key, len, &params->aes_key_, params->ctr_.buf_, params->ecount_buf_, &num);
#elif defined(USE_NETTLE)
  if(KD_AESCTR_CTR_LENGTH != AES_BLOCK_SIZE) {
    log_printf(ERROR, "failed to set cipher CTR: size doesn't fit");
    return -1;
  }
  memset(key, 0, len);
  ctr_crypt(&params->ctx_, (nettle_crypt_func *)(aes_encrypt), AES_BLOCK_SIZE, params->ctr_.buf_, len, key, key);
#else  // USE_GCRYPT is the default
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
#endif

  return 0;
}
