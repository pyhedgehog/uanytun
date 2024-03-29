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

#ifndef UANYTUN_datatypes_h_INCLUDED
#define UANYTUN_datatypes_h_INCLUDED

#include <stdint.h>
#include <arpa/inet.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
/* typedef int8_t int8_t; */
/* typedef int16_t int16_t; */
/* typedef int32_t int32_t; */
/* typedef int64_t int64_t; */

typedef u_int32_t window_size_t;

typedef u_int32_t seq_nr_t;
#define SEQ_NR_T_NTOH(a) ntohl(a)
#define SEQ_NR_T_HTON(a) htonl(a)
#define SEQ_NR_MAX UINT32_MAX

typedef u_int16_t sender_id_t;
#define SENDER_ID_T_NTOH(a) ntohs(a)
#define SENDER_ID_T_HTON(a) htons(a)

typedef u_int16_t payload_type_t;
#define PAYLOAD_TYPE_T_NTOH(a) ntohs(a)
#define PAYLOAD_TYPE_T_HTON(a) htons(a)

typedef u_int16_t mux_t;
#define MUX_T_NTOH(a) ntohs(a)
#define MUX_T_HTON(a) htons(a)

typedef u_int32_t satp_prf_label_t;
#define SATP_PRF_LABEL_T_NTOH(a) ntohl(a)
#define SATP_PRF_LABEL_T_HTON(a) htonl(a)

struct buffer_struct {
  u_int32_t length_;
  u_int8_t* buf_;
};
typedef struct buffer_struct buffer_t;

#endif
