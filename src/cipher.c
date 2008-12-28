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

void cipher_init(cipher_t** c, const char* type)
{
  if(!c) 
    return;

  *c = malloc(sizeof(cipher_t));
  if(!*c)
    return;

  (*c)->type_ = unknown;
  if(!strcmp(type, "null"))
    (*c)->type_ = null;
  else if(!strcmp(type, "aes-ctr"))
    (*c)->type_ = aes_ctr;
  else {
    log_printf(ERR, "unknown cipher type");
  }

  (*c)->key_.buf_ = NULL;
  (*c)->key_.length_ = 0;

  (*c)->salt_.buf_ = NULL;
  (*c)->salt_.length_ = 0;
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
}

void cipher_close(cipher_t** c)
{
  if(!c || !(*c))
    return;

  if((*c)->key_.buf_)
    free((*c)->key_.buf_);
  if((*c)->salt_.buf_)
    free((*c)->salt_.buf_);

  free(*c);
  *c = NULL;
}

void cipher_encrypt(cipher_t* c, plain_packet_t* in, encrypted_packet_t* out, seq_nr_t seq_nr, sender_id_t sender_id, mux_t mux)
{
  if(!c) 
    return;

	u_int32_t len;
  if(c->type_ = null)
    len = cipher_null_encrypt(plain_packet_get_packet(in), plain_packet_get_length(in), 
                              encrypted_packet_get_payload(out), encrypted_packet_get_payload_length(out));
  else if(c->type_ = aes_ctr)
    len = cipher_aesctr_encrypt(plain_packet_get_packet(in), plain_packet_get_length(in), 
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
  if(c->type_ = null)
    len = cipher_null_decrypt(encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                              plain_packet_get_packet(out), plain_packet_get_length(out));
  else if(c->type_ = aes_ctr)
    len = cipher_aesctr_decrypt(encrypted_packet_get_payload(in), encrypted_packet_get_payload_length(in),
                                plain_packet_get_packet(out), plain_packet_get_length(out), 
                                encrypted_packet_get_seq_nr(in), encrypted_packet_get_sender_id(in), 
                                encrypted_packet_get_mux(in));
  else {
    log_printf(ERR, "unknown cipher type");
    return;
  }
  
	plain_packet_set_length(out, len);
}

u_int32_t cipher_null_encrypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen)
{
	memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}

u_int32_t cipher_null_decrypt(u_int8_t* in, u_int32_t ilen, u_int8_t* out, u_int32_t olen)
{
	memcpy(out, in, (ilen < olen) ? ilen : olen);
  return (ilen < olen) ? ilen : olen;
}
