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

#ifndef UANYTUN_udp_h_INCLUDED
#define UANYTUN_udp_h_INCLUDED

#include "options.h"

#include <sys/types.h>
#include <sys/socket.h>

typedef struct {
  socklen_t len_;
  struct sockaddr_storage addr_;
} udp_endpoint_t;

struct udp_socket_struct {
  int fd_;
  unsigned int idx_;
  udp_endpoint_t local_end_;
  udp_endpoint_t remote_end_;
  int remote_end_set_;
  struct udp_socket_struct* next_;
};
typedef struct udp_socket_struct udp_socket_t;

struct udp_struct {
  udp_socket_t* socks_;
  udp_socket_t* active_sock_;
  int rail_mode_;
};
typedef struct udp_struct udp_t;

int udp_init(udp_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type, int rail_mode);
int udp_fill_fd_set(udp_t* sock, fd_set* set);
int udp_has_remote(udp_t* sock);
int udp_resolv_remote(udp_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type);
void udp_update_remote(udp_t* sock, int fd, udp_endpoint_t* remote);
void udp_close(udp_t* sock);

char* udp_endpoint_to_string(udp_endpoint_t* e);

int udp_read(udp_t* sock, int fd, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end);
int udp_write(udp_t* sock, u_int8_t* buf, u_int32_t len);

#endif
