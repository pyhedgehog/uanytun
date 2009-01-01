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

#include "plain_packet.h"
#include "encrypted_packet.h"

#include "cipher.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

#include <gmp.h>

int cipher_init(cipher_t* c, const char* type)
{
  if(!c) 
    return -1;

  c->type_ = unknown;
  if(!strcmp(type, "null"))
    c->type_ = null;
  else if(!strcmp(type, "aes-ctr"))
    c->type_ = aes_ctr;
  else {
    log_printf(ERR, "unknown cipher type");
    return -1;
  }

  c->key_length_ = 0;
  c->handle_ = 0;

  c->key_.buf_ = NULL;
  c->key_.length_ = 0;

  c->salt_.buf_ = NULL;
  c->salt_.length_ = 0;

  int ret = 0;
  if(c->type_ == aes_ctr)
    ret = cipher_aesctr_init(c, 128);

  return ret;
}

void cipher_set_key(cipher_t* c, u_int8_t* key, u_int32_t len)
{
  if(!c) 
    return;
  if(c->type_ == null)
    return;

  if(c->key_.buf_)
    free(c->key_.buf_);
  c->key_.buf_ = malloc(len);
  if(!c->key_.buf_) {
    c->key_.length_ = 0;
    return;
  }
  memcpy(c->key_.buf_, key, len);
  c->key_.length_ = len;
}

void cipher_set_salt(cipher_t* c, u_int8_t* salt, u_int32_t len)
{
  if(!c) 
    return;
  if(c->type_ == null)
    return;

  if(c->salt_.buf_)
    free(c->salt_.buf_);
  c->salt_.buf_ = malloc(len);
  if(!c->salt_.buf_) {
    c->salt_.length_ = 0;
    return;
  }
  memcpy(c->salt_.buf_, salt, len);
  c->salt_.length_ = len;
  if(!c->salt_.buf_[0])
    c->salt_.buf_[0] = 1; // TODO: this is a outstandingly ugly workaround
}

void cipher_close(cipher_t* c)
{
  if(!c)
    return;

  if(c->type_ == aes_ctr)
    cipher_aesctr_close(c);

  if(c->key_.buf_)
    free(c->key_.buf_);
  if(c->salt_.buf_)
    free(c->salt_.buf_);
}

void cipher_encrypt(cipher_t* c, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c) 
    return;

	u_int32_t len;
  if(c->type_ == null)
    len = cipher_null_crypt(plain_packet_get_packet(in), plain_packet_get_length(in), 
                            encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out));
  else if(c->type_ == aes_ctr)
    len = cipher_aesctr_crypt(c, plain_packet_get_packet(in), plain_packet_get_length(in),
                              encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out),
                              seq_nr, sender_id, mux);
  else {
    log_printf(ERR, "unknown cipher type");
    return;
  }

	encrypted_packet_set_sender_id(out, sender_id);
  encrypted_packet_set_seq_nr(out, seq_nr);
  encrypted_packet_set_mux(out, mux);

  encrypted_packet_set_payload_length(out, len);
}

void cipher_decrypt(cipher_t* c, encrypted_packet_t* in, plain_packet_t* out)
{
  if(!c) 
    return;

	u_int32_t len;
  if(c->type_ == null)
    len = cipher_null_crypt(encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                            plain_packet_get_packet(out), plain_packet_get_length(out));
  else if(c->type_ == aes_ctr)
    len = cipher_aesctr_crypt(c, encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                              plain_packet_get_packet(out), plain_packet_get_length(out),
                              encrypted_packet_get_seq_nr(in), encrypted_packet_get_sender_id(in),
                              encrypted_packet_get_mux(in));
  else {
    log_printf(ERR, "unknown cipher type");
    return;
  }
  
	plain_packet_set_length(out, len);
}

/* ---------------- NULL Cipher ---------------- */

u_int32_t cipher_null_crypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen)
{
	memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

/* ---------------- AES-Ctr Cipher ---------------- */

int cipher_aesctr_init(cipher_t* c, int key_length)
{
  c->key_length_ = key_length;
  
  int algo;
  switch(key_length) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  default: {
    log_printf(ERR, "key length of %d Bits is not supported", key_length);
    return -1;
  }
  }

  gcry_error_t err = gcry_cipher_open( &c->handle_, algo, GCRY_CIPHER_MODE_CTR, 0 );
  if(err) {
    log_printf(ERR, "failed to open cipher: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  } 
}

void cipher_aesctr_close(cipher_t* c)
{
  if(!c)
    return;

  if(c->handle_)
    gcry_cipher_close(c->handle_);
}

buffer_t cipher_aesctr_calc_ctr(cipher_t* c, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  buffer_t result;
  result.buf_ = NULL;
  result.length_ = 0;

  mpz_t ctr, sid_mux, seq;
  mpz_init2(ctr, 128);
  mpz_init2(sid_mux, 96);
  mpz_init2(seq, 48);
  
  mpz_import(ctr, c->salt_.length_, 1, 1, 0, 0, c->salt_.buf_);
  mpz_mul_2exp(ctr, ctr, 16);

  mpz_set_ui(sid_mux, mux);
  mpz_mul_2exp(sid_mux, sid_mux, 16);
  mpz_add_ui(sid_mux, sid_mux, sender_id);
  mpz_mul_2exp(sid_mux, sid_mux, 64);

  mpz_set_ui(seq, seq_nr);
  mpz_mul_2exp(seq, seq, 16);

  mpz_xor(ctr, ctr, sid_mux);
  mpz_xor(ctr, ctr, seq);

  result.buf_ = mpz_export(NULL, (size_t*)&result.length_, 1, 1, 0, 0, ctr);

  mpz_clear(ctr);
  mpz_clear(sid_mux);
  mpz_clear(seq);

  return result;
}

u_int32_t cipher_aesctr_crypt(cipher_t* c, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c)
    return;

  gcry_error_t err = gcry_cipher_setkey(c->handle_, c->key_.buf_, c->key_.length_);
  if(err) {
    log_printf(ERR, "failed to set cipher key: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return 0;
  }

  buffer_t ctr = cipher_aesctr_calc_ctr(c, seq_nr, sender_id, mux);
  if(!ctr.buf_) {
    log_printf(ERR, "failed to calculate cipher CTR");
    return 0;
  }
  err = gcry_cipher_setctr(c->handle_, ctr.buf_, ctr.length_);
  free(ctr.buf_);

  if(err) {
    log_printf(ERR, "failed to set cipher CTR: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return 0;
  }

  err = gcry_cipher_encrypt(c->handle_, out, olen, in, ilen);
  if(err) {
    log_printf(ERR, "failed to generate cipher bitstream: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return 0;
  }

  return (ilen < olen) ? ilen : olen;  
}
