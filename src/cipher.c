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

#include "datatypes.h"

#include "plain_packet.h"
#include "encrypted_packet.h"

#include "cipher.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

#ifndef NO_LIBGMP
#include <gmp.h>
#endif

int cipher_init(cipher_t* c, const char* type)
{
  if(!c) 
    return -1;

  c->key_length_ = 0;

  c->type_ = c_unknown;
  if(!strcmp(type, "null"))
    c->type_ = c_null;
#ifndef NO_CRYPT
  else if(!strncmp(type, "aes-ctr", 7)) {
    c->type_ = c_aes_ctr;
    if(type[7] == 0) {
      c->key_length_ = 128;
    }
    else if(type[7] != '-') 
      return -1;
    else {
      const char* tmp = &type[8];
      c->key_length_ = atoi(tmp);
    }
  }
#endif
  else {
    log_printf(ERR, "unknown cipher type");
    return -1;
  }

#ifndef NO_CRYPT
  c->handle_ = 0;
#endif

  c->key_.buf_ = NULL;
  c->key_.length_ = 0;

  c->salt_.buf_ = NULL;
  c->salt_.length_ = 0;

  int ret = 0;
#ifndef NO_CRYPT
  if(c->type_ == c_aes_ctr)
    ret = cipher_aesctr_init(c);
#endif

  if(ret)
    cipher_close(c);

  return ret;
}

void cipher_close(cipher_t* c)
{
  if(!c)
    return;

#ifndef NO_CRYPT
  if(c->type_ == c_aes_ctr)
    cipher_aesctr_close(c);
#endif

  if(c->key_.buf_)
    free(c->key_.buf_);
  if(c->salt_.buf_)
    free(c->salt_.buf_);
}


int cipher_encrypt(cipher_t* c, key_derivation_t* kd, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c) 
    return -1;

	int32_t len;
  if(c->type_ == c_null)
    len = cipher_null_crypt(plain_packet_get_packet(in), plain_packet_get_length(in), 
                            encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out));
#ifndef NO_CRYPT
  else if(c->type_ == c_aes_ctr)
    len = cipher_aesctr_crypt(c, kd, plain_packet_get_packet(in), plain_packet_get_length(in),
                              encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out),
                              seq_nr, sender_id, mux);
#endif
  else {
    log_printf(ERR, "unknown cipher type");
    return -1;
  }

  if(len < 0)
    return 0;

	encrypted_packet_set_sender_id(out, sender_id);
  encrypted_packet_set_seq_nr(out, seq_nr);
  encrypted_packet_set_mux(out, mux);

  encrypted_packet_set_payload_length(out, len);

  return 0;
}

int cipher_decrypt(cipher_t* c, key_derivation_t* kd, encrypted_packet_t* in, plain_packet_t* out)
{
  if(!c) 
    return -1;

	int32_t len;
  if(c->type_ == c_null)
    len = cipher_null_crypt(encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                            plain_packet_get_packet(out), plain_packet_get_length(out));
#ifndef NO_CRYPT
  else if(c->type_ == c_aes_ctr)
    len = cipher_aesctr_crypt(c, kd, encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                              plain_packet_get_packet(out), plain_packet_get_length(out),
                              encrypted_packet_get_seq_nr(in), encrypted_packet_get_sender_id(in),
                              encrypted_packet_get_mux(in));
#endif
  else {
    log_printf(ERR, "unknown cipher type");
    return -1;
  }
  
  if(len < 0)
    return 0;

	plain_packet_set_length(out, len);

  return 0;
}

/* ---------------- NULL Cipher ---------------- */

int32_t cipher_null_crypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen)
{
	memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

#ifndef NO_CRYPT
/* ---------------- AES-Ctr Cipher ---------------- */

int cipher_aesctr_init(cipher_t* c)
{
  if(!c)
    return -1;

  if(c->key_.buf_)
    free(c->key_.buf_);

  c->key_.length_ = c->key_length_/8;
  c->key_.buf_ = malloc(c->key_.length_);
  if(!c->key_.buf_)
    return -2;

  if(c->salt_.buf_)
    free(c->salt_.buf_);

  c->salt_.length_ = 14;
  c->salt_.buf_ = malloc(c->salt_.length_);
  if(!c->salt_.buf_)
    return -2;

  int algo;
  switch(c->key_length_) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    log_printf(ERR, "cipher key length of %d Bits is not supported", c->key_length_);
    return -1;
  }
  }

  gcry_error_t err = gcry_cipher_open(&c->handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERR, "failed to open cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  } 

  return 0;
}

void cipher_aesctr_close(cipher_t* c)
{
  if(!c)
    return;

  if(c->handle_)
    gcry_cipher_close(c->handle_);
}

buffer_t cipher_aesctr_calc_ctr(cipher_t* c, key_derivation_t* kd, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  buffer_t result;
  result.buf_ = NULL;
  result.length_ = 0;

  if(!c)
    return result;
  
  int ret = key_derivation_generate(kd, LABEL_SATP_SALT, seq_nr, c->salt_.buf_, c->salt_.length_);
  if(ret < 0)
    return result;

  int faked_msb = 0;
  if(!c->salt_.buf_[0]) {
    c->salt_.buf_[0] = 1;
    faked_msb = 1;
  }

#ifndef NO_LIBGMP
  mpz_t ctr, sid_mux, seq;
  mpz_init2(ctr, 128);
  mpz_init2(sid_mux, 128);
  mpz_init2(seq, 128);
  
  mpz_import(ctr, c->salt_.length_, 1, 1, 0, 0, c->salt_.buf_);

  mpz_set_ui(sid_mux, mux);
  mpz_mul_2exp(sid_mux, sid_mux, (sizeof(sender_id) * 8));
  mpz_add_ui(sid_mux, sid_mux, sender_id);
  mpz_mul_2exp(sid_mux, sid_mux, 48);

  mpz_set_ui(seq, seq_nr);

  mpz_xor(ctr, ctr, sid_mux);
  mpz_xor(ctr, ctr, seq);

  mpz_mul_2exp(ctr, ctr, 16);

  result.buf_ = mpz_export(NULL, (size_t*)&result.length_, 1, 1, 0, 0, ctr);
  mpz_clear(ctr);
  mpz_clear(sid_mux);
  mpz_clear(seq);
#endif

#ifndef ANYTUN_02_COMPAT
  if(faked_msb) {
    c->salt_.buf_[0] = 0;
    result.buf_[0] = 0;
  }
#endif

  return result;
}

int32_t cipher_aesctr_crypt(cipher_t* c, key_derivation_t* kd, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c)
    return -1;

  if(!kd) {
    log_printf(ERR, "no key derivation supplied");
    return -1;
  }

  int ret = key_derivation_generate(kd, LABEL_SATP_ENCRYPTION, seq_nr, c->key_.buf_, c->key_.length_);
  if(ret < 0)
    return ret;
  
  gcry_error_t err;
  if(ret) { // a new key got generated
    err = gcry_cipher_setkey(c->handle_, c->key_.buf_, c->key_.length_);
    if(err) {
      log_printf(ERR, "failed to set cipher key: %s/%s", gcry_strerror(err), gcry_strsource(err));
      return -1;
    }
  } // no new key got generated
  else {
    err = gcry_cipher_reset(c->handle_);
    if(err) {
      log_printf(ERR, "failed to reset cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
      return -1;
    }
  }

  buffer_t ctr = cipher_aesctr_calc_ctr(c, kd, seq_nr, sender_id, mux);
  if(!ctr.buf_) {
    log_printf(ERR, "failed to calculate cipher CTR");
    return -1;
  }
  err = gcry_cipher_setctr(c->handle_, ctr.buf_, ctr.length_);
  free(ctr.buf_);

  if(err) {
    log_printf(ERR, "failed to set cipher CTR: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }

  err = gcry_cipher_encrypt(c->handle_, out, olen, in, ilen);
  if(err) {
    log_printf(ERR, "failed to de/encrypt packet: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  }

  return (ilen < olen) ? ilen : olen;  
}
#endif
