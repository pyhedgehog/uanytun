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

#include "encrypted_packet.h"

#include "auth_algo.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>

int auth_algo_init(auth_algo_t* aa, const char* type)
{
  if(!aa) 
    return -1;

  aa->type_ = aa_unknown;
  if(!strcmp(type, "null"))
    aa->type_ = aa_null;
  else if(!strcmp(type, "sha1"))
    aa->type_ = aa_sha1;
  else {
    log_printf(ERR, "unknown auth algo type");
    return -1;
  }

  aa->handle_ = 0;

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

void auth_algo_generate(auth_algo_t* aa, key_derivation_t* kd, encrypted_packet_t* packet)
{
  if(!aa) 
    return;

	u_int32_t len;
  if(aa->type_ == aa_null)
    return;
  else if(aa->type_ == aa_sha1)
    auth_algo_sha1_generate(aa, kd, packet);
  else {
    log_printf(ERR, "unknown auth algo type");
    return;
  }
}

int auth_algo_check_tag(auth_algo_t* aa, key_derivation_t* kd, encrypted_packet_t* packet)
{
  if(!aa) 
    return;

	u_int32_t len;
  if(aa->type_ == aa_null)
    return 1;
  else if(aa->type_ == aa_sha1)
    return auth_algo_sha1_check_tag(aa, kd, packet);
  else {
    log_printf(ERR, "unknown auth algo type");
    return;
  }
}

/* ---------------- HMAC Sha1 Auth Algo ---------------- */

int auth_algo_sha1_init(auth_algo_t* aa)
{
  if(!aa)
    return -1;

  gcry_error_t err = gcry_md_open(&aa->handle_, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
  if(err) {
    log_printf(ERR, "failed to open message digest algo: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return -1;
  } 

  return 0;
}

void auth_algo_sha1_close(auth_algo_t* aa)
{
  if(!aa)
    return;

  if(aa->handle_)
    gcry_md_close(aa->handle_);
}


void auth_algo_sha1_generate(auth_algo_t* aa, key_derivation_t* kd, encrypted_packet_t* packet)
{
  if(!aa) {
    log_printf(ERR, "auth algo not initialized");
    return;
  }
  if(!kd) {
    log_printf(ERR, "no key derivation supplied");
    return;
  }


  if(!aa->key_.buf_) {
    aa->key_.length_ = SHA1_LENGTH;
    aa->key_.buf_ = malloc(aa->key_.length_);
    if(!aa->key_.buf_) {
      log_printf(ERR, "memory error at auth algo generate");
      return;
    }
  }

  int ret = key_derivation_generate(kd, LABEL_SATP_MSG_AUTH, encrypted_packet_get_seq_nr(packet), aa->key_.buf_, aa->key_.length_);
  if(ret < 0)
    return;
  gcry_error_t err = gcry_md_setkey(aa->handle_, aa->key_.buf_, aa->key_.length_);
  if(err) {
    log_printf(ERR, "failed to set hmac key: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return;
  } 

  encrypted_packet_add_auth_tag(packet);

  gcry_md_reset(aa->handle_);

  gcry_md_write(aa->handle_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  gcry_md_final(aa->handle_);

  u_int8_t* tag = encrypted_packet_get_auth_tag(packet);
  u_int8_t* hmac = gcry_md_read(aa->handle_, 0);
  u_int32_t length = (encrypted_packet_get_auth_tag_length(packet) < SHA1_LENGTH) ? encrypted_packet_get_auth_tag_length(packet) : SHA1_LENGTH;

  if(length > SHA1_LENGTH)
    memset(tag, 0, encrypted_packet_get_auth_tag_length(packet));

  memcpy(&tag[encrypted_packet_get_auth_tag_length(packet) - length], &hmac[SHA1_LENGTH - length], length);
}


int auth_algo_sha1_check_tag(auth_algo_t* aa, key_derivation_t* kd, encrypted_packet_t* packet)
{
  if(!aa) {
    log_printf(ERR, "auth algo not initialized");
    return 0;
  }
  if(!kd) {
    log_printf(ERR, "no key derivation supplied");
    return 0;
  }

  if(!aa->key_.buf_) {
    aa->key_.length_ = SHA1_LENGTH;
    aa->key_.buf_ = malloc(aa->key_.length_);
    if(!aa->key_.buf_) {
      log_printf(ERR, "memory error at auth algo check tag");
      return;
    }
  }

  int ret = key_derivation_generate(kd, LABEL_SATP_MSG_AUTH, encrypted_packet_get_seq_nr(packet), aa->key_.buf_, aa->key_.length_);
  if(ret < 0)
    return 0;
  gcry_error_t err = gcry_md_setkey(aa->handle_, aa->key_.buf_, aa->key_.length_);
  if(err) {
    log_printf(ERR, "failed to set hmac key: %s/%s", gcry_strerror(err), gcry_strsource(err));
    return;
  } 

  gcry_md_reset(aa->handle_);

  gcry_md_write(aa->handle_, encrypted_packet_get_auth_portion(packet), encrypted_packet_get_auth_portion_length(packet));
  gcry_md_final(aa->handle_);

  u_int8_t* tag = encrypted_packet_get_auth_tag(packet);
  u_int8_t* hmac = gcry_md_read(aa->handle_, 0);
  u_int32_t length = (encrypted_packet_get_auth_tag_length(packet) < SHA1_LENGTH) ? encrypted_packet_get_auth_tag_length(packet) : SHA1_LENGTH;

  if(length > SHA1_LENGTH) {
    u_int32_t i;
    for(i=0; i < (encrypted_packet_get_auth_tag_length(packet) - SHA1_LENGTH); ++i)
      if(tag[i]) return 0; 
  }
  
  int result = memcmp(&tag[encrypted_packet_get_auth_tag_length(packet) - length], &hmac[SHA1_LENGTH - length], length);
  encrypted_packet_remove_auth_tag(packet);
  
  if(result)
    return 0;

  return 1;
}