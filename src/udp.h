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
 *  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
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

#ifndef UANYUTN_udp_h_INCLUDED
#define UANYUTN_udp_h_INCLUDED

#include "options.h"

#include <sys/types.h>
#include <sys/socket.h>

typedef struct sockaddr_storage udp_endpoint_t;

struct udp_socket_struct {
  int fd_;
  udp_endpoint_t local_end_;
  udp_endpoint_t remote_end_;
  int remote_end_set_;
};
typedef struct udp_socket_struct udp_socket_t;

int udp_init(udp_socket_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type);
int udp_set_remote(udp_socket_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type);
void udp_close(udp_socket_t* sock);

char* udp_endpoint_to_string(udp_endpoint_t e);
char* udp_get_local_end_string(udp_socket_t* sock);
char* udp_get_remote_end_string(udp_socket_t* sock);

int udp_read(udp_socket_t* sock, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end);
int udp_write(udp_socket_t* sock, u_int8_t* buf, u_int32_t len);

#endif
