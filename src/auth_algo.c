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
 *  Copyright (C) 2007-2017 Christian Pointner <equinox@anytun.org>
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "datatypes.h"

#include "encrypted_packet.h"

#include "auth_algo.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

auth_algo_type_t auth_algo_get_type(const char* type)
{
  if(!strcmp(type, "null"))
    return aa_null;
  else if(!strcmp(type, "sha1"))
    return aa_sha1;

  return aa_unknown;
}

u_int32_t auth_algo_get_max_length(const char* type)
{
  switch(auth_algo_get_type(type)) {
  case aa_null: return 0;
  case aa_sha1: return SHA1_LENGTH;
  default: return 0;
  }
}

int auth_algo_init(auth_algo_t* aa, const char* type)
{
  if(!aa)
    return -1;

  aa->type_ = auth_algo_get_type(type);
  if(aa->type_ == aa_unknown) {
    log_printf(ERROR, "unknown auth algo type");
    return -1;
  }

  aa->params_ = NULL;

  aa->key_.buf_ = NULL;
  aa->key_.length_ = 0;

  int ret = 0;
  if(aa->type_ == aa_sha1)
    ret = auth_algo_sha1_init(aa);

  if(ret)
    auth_algo_close(aa);

  return ret;
}

void auth_algo_close(auth_algo_t* aa)
{
  if(!aa)
    return;

  if(aa->type_ == aa_sha1)
    auth_algo_sha1_close(aa);

  if(aa->key_.buf_)
    free(aa->key_.buf_);
}

void auth_algo_generate(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet)
{
  if(!aa)
    return;

  if(aa->type_ == aa_null)
    return;
  else if(aa->type_ == aa_sha1)
    auth_algo_sha1_generate(aa, kd, dir, packet);
  else {
    log_printf(ERROR, "unknown auth algo type");
    return;
  }
}

int auth_algo_check_tag(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet)
{
  if(!aa)
    return 0;

  if(aa->type_ == aa_null)
    return 1;
  else if(aa->type_ == aa_sha1)
    return auth_algo_sha1_check_tag(aa, kd, dir, packet);
  else {
    log_printf(ERROR, "unknown auth algo type");
    return 0;
  }
}

/* ---------------- HMAC Sha1 Auth Algo ---------------- */

int auth_algo_sha1_init(auth_algo_t* aa)
{
  if(!aa)
    return -1;

  if(aa->key_.buf_)
    free(aa->key_.buf_);

  aa->key_.length_ = SHA1_LENGTH;
  aa->key_.buf_ = malloc(aa->key_.length_);
  if(!aa->key_.buf_)
    return -2;

  if(aa->params_)
    free(aa->params_);
  aa->params_ = calloc(1, sizeof(auth_algo_sha1_param_t));
  if(!aa->params_)
    return -2;

#if defined(USE_SSL_CRYPTO)
  auth_algo_sha1_param_t* params = aa->params_;
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if ((params->ctx_ = HMAC_CTX_new()) == NULL) {
    log_printf(ERROR, "failed to allocate HMAC_CTX");
    return -2;
  }
# else
  if ((params->ctx_ = calloc(1, sizeof(HMAC_CTX))) == NULL) {
    log_printf(ERROR, "failed to allocate HMAC_CTX");
    return -2;
  }
  HMAC_CTX_init(params->ctx_);
# endif
  HMAC_Init_ex(params->ctx_, NULL, 0, EVP_sha1(), NULL);
#elif defined(USE_NETTLE)
  // nothing here
#else  // USE_GCRYPT is the default
  auth_algo_sha1_param_t* params = aa->params_;
  gcry_error_t err = gcry_md_open(&params->handle_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if(err) {
    log_printf(ERROR, "failed to open message digest algo: %s", gcry_strerror(err));
    return -1;
  }
#endif

  return 0;
}

void auth_algo_sha1_close(auth_algo_t* aa)
{
  if(!aa)
    return;

  if(aa->params_) {
#if defined(USE_SSL_CRYPTO)
    auth_algo_sha1_param_t* params = aa->params_;
    if(params->ctx_) {
# if OPENSSL_VERSION_NUMBER >= 0x10100000L
      HMAC_CTX_free(params->ctx_);
# else
      HMAC_CTX_cleanup(params->ctx_);
      free(params->ctx_);
# endif
    }
#elif defined(USE_NETTLE)
    // nothing here
#else  // USE_GCRYPT is the default
    auth_algo_sha1_param_t* params = aa->params_;
    if(params->handle_)
      gcry_md_close(params->handle_);
#endif

    free(aa->params_);
  }

}

void auth_algo_sha1_generate(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet)
{
  if(!encrypted_packet_get_auth_tag_length(packet))
    return;

  if(!aa || !aa->params_) {
    log_printf(ERROR, "auth algo not initialized");
    return;
  }
  if(!kd) {
    log_printf(ERROR, "no key derivation supplied");
    return;
  }
  auth_algo_sha1_param_t* params = aa->params_;

  int ret = key_derivation_generate(kd, dir, LABEL_AUTH, encrypted_packet_get_seq_nr(packet), aa->key_.buf_, aa->key_.length_);
  if(ret < 0)
    return;

#if defined(USE_SSL_CRYPTO)
  HMAC_Init_ex(params->ctx_, aa->key_.buf_, aa->key_.length_, EVP_sha1(), NULL);

  u_int8_t hmac[SHA1_LENGTH];
  HMAC_Update(params->ctx_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  HMAC_Final(params->ctx_, hmac, NULL);
#elif defined(USE_NETTLE)
  hmac_sha1_set_key(&params->ctx_, aa->key_.length_, aa->key_.buf_);

  u_int8_t hmac[SHA1_LENGTH];
  hmac_sha1_update(&params->ctx_, encrypted_packet_get_auth_portion_length(packet), encrypted_packet_get_auth_portion(packet));
  hmac_sha1_digest(&params->ctx_, SHA1_LENGTH, hmac);
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_md_setkey(params->handle_, aa->key_.buf_, aa->key_.length_);
  if(err) {
    log_printf(ERROR, "failed to set hmac key: %s", gcry_strerror(err));
    return;
  }

  gcry_md_reset(params->handle_);
  gcry_md_write(params->handle_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  gcry_md_final(params->handle_);
  u_int8_t* hmac = gcry_md_read(params->handle_, 0);
#endif

  u_int8_t* tag = encrypted_packet_get_auth_tag(packet);
  u_int32_t length = (encrypted_packet_get_auth_tag_length(packet) < SHA1_LENGTH) ? encrypted_packet_get_auth_tag_length(packet) : SHA1_LENGTH;

  if(length > SHA1_LENGTH)
    memset(tag, 0, encrypted_packet_get_auth_tag_length(packet));

  memcpy(&tag[encrypted_packet_get_auth_tag_length(packet) - length], &hmac[SHA1_LENGTH - length], length);
}


int auth_algo_sha1_check_tag(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet)
{
  if(!encrypted_packet_get_auth_tag_length(packet))
    return 1;

  if(!aa || !aa->params_) {
    log_printf(ERROR, "auth algo not initialized");
    return 0;
  }
  if(!kd) {
    log_printf(ERROR, "no key derivation supplied");
    return 0;
  }
  auth_algo_sha1_param_t* params = aa->params_;

  int ret = key_derivation_generate(kd, dir, LABEL_AUTH, encrypted_packet_get_seq_nr(packet), aa->key_.buf_, aa->key_.length_);
  if(ret < 0)
    return 0;

#if defined(USE_SSL_CRYPTO)
  HMAC_Init_ex(params->ctx_, aa->key_.buf_, aa->key_.length_, EVP_sha1(), NULL);

  u_int8_t hmac[SHA1_LENGTH];
  HMAC_Update(params->ctx_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  HMAC_Final(params->ctx_, hmac, NULL);
#elif defined(USE_NETTLE)
  hmac_sha1_set_key(&params->ctx_, aa->key_.length_, aa->key_.buf_);

  u_int8_t hmac[SHA1_LENGTH];
  hmac_sha1_update(&params->ctx_, encrypted_packet_get_auth_portion_length(packet), encrypted_packet_get_auth_portion(packet));
  hmac_sha1_digest(&params->ctx_, SHA1_LENGTH, hmac);
#else  // USE_GCRYPT is the default
  gcry_error_t err = gcry_md_setkey(params->handle_, aa->key_.buf_, aa->key_.length_);
  if(err) {
    log_printf(ERROR, "failed to set hmac key: %s", gcry_strerror(err));
    return -1;
  }

  gcry_md_reset(params->handle_);
  gcry_md_write(params->handle_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  gcry_md_final(params->handle_);
  u_int8_t* hmac = gcry_md_read(params->handle_, 0);
#endif

  u_int8_t* tag = encrypted_packet_get_auth_tag(packet);
  u_int32_t length = (encrypted_packet_get_auth_tag_length(packet) < SHA1_LENGTH) ? encrypted_packet_get_auth_tag_length(packet) : SHA1_LENGTH;

  if(length > SHA1_LENGTH) {
    u_int32_t i;
    for(i=0; i < (encrypted_packet_get_auth_tag_length(packet) - SHA1_LENGTH); ++i)
      if(tag[i]) return 0;
  }

  int result = memcmp(&tag[encrypted_packet_get_auth_tag_length(packet) - length], &hmac[SHA1_LENGTH - length], length);

  if(result)
    return 0;

  return 1;
}
