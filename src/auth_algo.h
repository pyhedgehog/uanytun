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
 *  Copyright (C) 2007-2016 Christian Pointner <equinox@anytun.org>
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

#ifndef UANYTUN_auth_algo_h_INCLUDED
#define UANYTUN_auth_algo_h_INCLUDED

#if defined(USE_SSL_CRYPTO)
#include <openssl/hmac.h>
#elif defined(USE_NETTLE)
#include <nettle/hmac.h>
#else  // USE_GCRYPT is the default
#include <gcrypt.h>
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
#if defined(USE_SSL_CRYPTO)
  HMAC_CTX ctx_;
#elif defined(USE_NETTLE)
  struct hmac_sha1_ctx ctx_;
#else  // USE_GCRYPT is the default
  gcry_md_hd_t handle_;
#endif
};
typedef struct auth_algo_sha1_param_struct auth_algo_sha1_param_t;

int auth_algo_sha1_init(auth_algo_t* aa);
void auth_algo_sha1_close(auth_algo_t* aa);
void auth_algo_sha1_generate(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);
int auth_algo_sha1_check_tag(auth_algo_t* aa, key_derivation_t* kd, key_derivation_dir_t dir, encrypted_packet_t* packet);

#endif
