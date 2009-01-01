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

#include <string.h>

#include <gmp.h>


int key_derivation_init(key_derivation_t* kd, const char* type, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len)
{
  if(!kd) 
    return -1;

  kd->type_ = unknown;
  if(!strcmp(type, "null"))
    kd->type_ = null;
  else if(!strcmp(type, "aes-ctr"))
    kd->type_ = aes_ctr;
  else {
    log_printf(ERR, "unknown key derivation type");
    return -1;
  }

  kd->ld_kdr_ = -1;
  kd->handle_ = 0;

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
  if(kd->type_ == aes_ctr)
    ret = key_derivation_aesctr_init(kd, key, key_len, salt, salt_len);

  return ret;
}

void key_derivation_close(key_derivation_t* kd)
{
  if(!kd)
    return;

  if(kd->type_ == aes_ctr)
    key_derivation_aesctr_close(kd);

  if(kd->master_key_.buf_)
    free(kd->master_key_.buf_);
  if(kd->master_salt_.buf_)
    free(kd->master_salt_.buf_);
}

void key_derivation_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd) 
    return;

  if(kd->type_ == null)
    key_derivation_null_generate(key, len);
  else if(kd->type_ == aes_ctr)
    key_derivation_aesctr_generate(kd, label, seq_nr, key, len);
  else {
    log_printf(ERR, "unknown cipher type");
    return;
  }
}

/* ---------------- NULL Key Derivation ---------------- */

void key_derivation_null_generate(u_int8_t* key, u_int32_t len)
{
  memset(key, 0, len);
}

/* ---------------- AES-Ctr Key Derivation ---------------- */

int key_derivation_aesctr_init(key_derivation_t* kd, u_int8_t* key, u_int32_t key_len, u_int8_t* salt, u_int32_t salt_len)
{
  if(!kd)
    return -1;

  gcry_error_t err = gcry_cipher_open(&kd->handle_, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERR, "failed to open cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  } 

  err = gcry_cipher_setkey(kd->handle_, kd->master_key_.buf_, kd->master_key_.length_);
  if(err) {
    log_printf(ERR, "failed to set cipher key: %s/%s", gcry_strerror(err), gcry_strsource(err));
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

buffer_t key_derivation_aesctr_calc_ctr(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr)
{
  buffer_t result;
  result.buf_ = NULL;
  result.length_ = 0;

  if(!kd)
    return result;

  // see at: http://tools.ietf.org/html/rfc3711#section-4.3
  // *  Let r = index DIV key_derivation_rate (with DIV as defined above).
  // *  Let key_id = <label> || r.
  // *  Let x = key_id XOR master_salt, where key_id and master_salt are
  //    aligned so that their least significant bits agree (right-
  //    alignment).
  //

  mpz_t ctr, key_id, r;
  mpz_init2(ctr, 128);
  mpz_init2(key_id, 128);
  mpz_init2(r, 128);

  int faked_msb = 0;
  if(!kd->master_salt_.buf_[0])
    kd->master_salt_.buf_[0] = 1;

  if(kd->ld_kdr_ == -1)
    mpz_set_ui(r, 0);
  else {
    mpz_t seq;
    mpz_init2(seq, 32);
    mpz_set_ui(seq, seq_nr);

    mpz_set_ui(r, 1);
    mpz_mul_2exp(r, r, kd->ld_kdr_);

    mpz_fdiv_q(r, seq, r);

    mpz_clear(seq);
  }
/*  TODO: generate key only if index % r == 0, except it is the first time */

  mpz_set_ui(key_id, label);
  mpz_mul_2exp(key_id, key_id, 48);
  mpz_add(key_id, key_id, r);

  mpz_import(ctr, kd->master_salt_.length_, 1, 1, 0, 0, kd->master_salt_.buf_);

  mpz_xor(ctr, ctr, key_id);
  mpz_mul_2exp(ctr, ctr, 16);

  result.buf_ = mpz_export(NULL, (size_t*)&result.length_, 1, 1, 0, 0, ctr);
  if(faked_msb) {
    kd->master_salt_.buf_[0] = 0;
    result.buf_[0] = 0;
  }

  mpz_clear(ctr);
  mpz_clear(key_id);
  mpz_clear(r);

  return result;
}

void key_derivation_aesctr_generate(key_derivation_t* kd, satp_prf_label_t label, seq_nr_t seq_nr, u_int8_t* key, u_int32_t len)
{
  if(!kd || !kd->master_key_.buf_ || !kd->master_salt_.buf_) {
    log_printf(ERR, "cipher not initialized or no key or salt set");
    return;
  }

  gcry_error_t err = gcry_cipher_reset(kd->handle_);
  if(err) {
    log_printf(ERR, "failed to reset cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return;
  }

  buffer_t ctr = key_derivation_aesctr_calc_ctr(kd, label, seq_nr);
  if(!ctr.buf_) {
    log_printf(ERR, "failed to calculate cipher CTR");
    return;
  }
  err = gcry_cipher_setctr(kd->handle_, ctr.buf_, ctr.length_);
  free(ctr.buf_);

  if(err) {
    log_printf(ERR, "failed to set cipher CTR: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return;
  }

  memset(key, 0, len);
  err = gcry_cipher_encrypt(kd->handle_, key, len, NULL, 0);
  if(err) {
    log_printf(ERR, "failed to generate cipher bitstream: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return;
  }
}
