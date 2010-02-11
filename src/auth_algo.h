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
 *  Copyright (C) 2007-2010 Christian Pointner <equinox@anytun.org>
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

#ifndef UANYTUN_auth_algo_h_INCLUDED
#define UANYTUN_auth_algo_h_INCLUDED

#ifndef USE_SSL_CRYPTO
#include <gcrypt.h>
#else
#include <openssl/hmac.h>
#endif
#include "key_derivation.h"
#include "encrypted_packet.h"

enum auth_algo_type_enum { aa_unknown, aa_null, aa_sha1 };
typedef enum auth_algo_type_enum auth_algo_type_t;

struct auth_algo_struct {
  auth_algo_type_t type_;
  buffer_t key_;
  void* params_;
};
typedef struct auth_algo_struct auth_algo_t;

auth_algo_type_t auth_algo_get_type(const char* type);
u_int32_t auth_algo_get_max_length(const char* type);
int auth_algo_init(auth_algo_t* aa, const char* type);
void auth_algo_close(auth_algo_t* aa);

void auth_algo_generate(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);
int auth_algo_check_tag(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);


#define SHA1_LENGTH 20

struct auth_algo_sha1_param_struct {
#ifndef USE_SSL_CRYPTO
  gcry_md_hd_t handle_;
#else
  HMAC_CTX ctx_;
#endif
};
typedef struct auth_algo_sha1_param_struct auth_algo_sha1_param_t;

int auth_algo_sha1_init(auth_algo_t* aa);
void auth_algo_sha1_close(auth_algo_t* aa);
void auth_algo_sha1_generate(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);
int auth_algo_sha1_check_tag(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);

#endif
