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

#include "plain_packet.h"
#include "encrypted_packet.h"

#include "cipher.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

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
      c->key_length_ = C_AESCTR_DEFAULT_KEY_LENGTH;
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
    log_printf(ERROR, "unknown cipher type");
    return -1;
  }

  c->params_ = NULL;

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


int cipher_encrypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c)
    return -1;

  int32_t len;
  if(c->type_ == c_null)
    len = cipher_null_crypt(plain_packet_get_packet(in), plain_packet_get_length(in),
                            encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out));
#ifndef NO_CRYPT
  else if(c->type_ == c_aes_ctr)
    len = cipher_aesctr_crypt(c, kd, dir, plain_packet_get_packet(in), plain_packet_get_length(in),
                              encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out),
                              seq_nr, sender_id, mux);
#endif
  else {
    log_printf(ERROR, "unknown cipher type");
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

int cipher_decrypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* in, plain_packet_t* out)
{
  if(!c)
    return -1;

  int32_t len;
  if(c->type_ == c_null)
    len = cipher_null_crypt(encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                            plain_packet_get_packet(out), plain_packet_get_length(out));
#ifndef NO_CRYPT
  else if(c->type_ == c_aes_ctr)
    len = cipher_aesctr_crypt(c, kd, dir, encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                              plain_packet_get_packet(out), plain_packet_get_length(out),
                              encrypted_packet_get_seq_nr(in), encrypted_packet_get_sender_id(in),
                              encrypted_packet_get_mux(in));
#endif
  else {
    log_printf(ERROR, "unknown cipher type");
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

  c->salt_.length_ = C_AESCTR_SALT_LENGTH;
  c->salt_.buf_ = malloc(c->salt_.length_);
  if(!c->salt_.buf_)
    return -2;

  if(c->params_)
    free(c->params_);
  c->params_ = malloc(sizeof(cipher_aesctr_param_t));
  if(!c->params_)
    return -2;

#ifdef USE_GCRYPT
  int algo;
  switch(c->key_length_) {
  case 128: algo = GCRY_CIPHER_AES128; break;
  case 192: algo = GCRY_CIPHER_AES192; break;
  case 256: algo = GCRY_CIPHER_AES256; break;
  default: {
    log_printf(ERROR, "cipher key length of %d Bits is not supported", c->key_length_);
    return -1;
  }
  }

  cipher_aesctr_param_t* params = c->params_;
  gcry_error_t err = gcry_cipher_open(&params->handle_, algo, GCRY_CIPHER_MODE_CTR, 0);
  if(err) {
    log_printf(ERROR, "failed to open cipher: %s", gcry_strerror(err));
    return -1;
  }
#endif

  return 0;
}

void cipher_aesctr_close(cipher_t* c)
{
  if(!c)
    return;

  if(c->params_) {
#ifdef USE_GCRYPT
    cipher_aesctr_param_t* params = c->params_;
    gcry_cipher_close(params->handle_);
#endif
    free(c->params_);
  }
}

int cipher_aesctr_calc_ctr(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c || !c->params_)
    return -1;

  cipher_aesctr_param_t* params = c->params_;

  int ret = key_derivation_generate(kd, dir, LABEL_SALT, seq_nr, c->salt_.buf_, C_AESCTR_SALT_LENGTH);
  if(ret < 0)
    return ret;

  memcpy(params->ctr_.salt_.buf_, c->salt_.buf_, C_AESCTR_SALT_LENGTH);
  params->ctr_.salt_.zero_ = 0;
  params->ctr_.params_.mux_ ^= MUX_T_HTON(mux);
  params->ctr_.params_.sender_id_ ^= SENDER_ID_T_HTON(sender_id);
  params->ctr_.params_.seq_nr_ ^= SEQ_NR_T_HTON(seq_nr);

  return 0;
}

int32_t cipher_aesctr_crypt(cipher_t* c, key_derivation_t* kd, key_derivation_dir_t dir, u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c || !c->params_) {
    log_printf(ERROR, "cipher not initialized");
    return -1;
  }

  if(!kd) {
    log_printf(ERROR, "no key derivation supplied");
    return -1;
  }

  cipher_aesctr_param_t* params = c->params_;

  int ret = key_derivation_generate(kd, dir, LABEL_ENC, seq_nr, c->key_.buf_, c->key_.length_);
  if(ret < 0)
    return ret;

#ifdef USE_SSL_CRYPTO
  ret = AES_set_encrypt_key(c->key_.buf_, c->key_length_, &params->aes_key_);
  if(ret) {
    log_printf(ERROR, "failed to set cipher key (code: %d)", ret);
    return -1;
  }
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_cipher_setkey(params->handle_, c->key_.buf_, c->key_.length_);
  if(err) {
    log_printf(ERROR, "failed to set cipher key: %s", gcry_strerror(err));
    return -1;
  }
#endif

  ret = cipher_aesctr_calc_ctr(c, kd, dir, seq_nr, sender_id, mux);
  if(ret < 0) {
    log_printf(ERROR, "failed to calculate cipher CTR");
    return ret;
  }

#ifdef USE_SSL_CRYPTO
  if(C_AESCTR_CTR_LENGTH != AES_BLOCK_SIZE) {
    log_printf(ERROR, "failed to set cipher CTR: size doesn't fit");
    return -1;
  }
  u_int32_t num = 0;
  memset(params->ecount_buf_, 0, AES_BLOCK_SIZE);
  AES_ctr128_encrypt(in, out, (ilen < olen) ? ilen : olen, &params->aes_key_, params->ctr_.buf_, params->ecount_buf_, &num);
#else  // USE_GCRYPT is the default
  err = gcry_cipher_setctr(params->handle_, params->ctr_.buf_, C_AESCTR_CTR_LENGTH);
  if(err) {
    log_printf(ERROR, "failed to set cipher CTR: %s", gcry_strerror(err));
    return -1;
  }

  err = gcry_cipher_encrypt(params->handle_, out, olen, in, ilen);
  if(err) {
    log_printf(ERROR, "failed to de/encrypt packet: %s", gcry_strerror(err));
    return -1;
  }
#endif

  return (ilen < olen) ? ilen : olen;
}
#endif
