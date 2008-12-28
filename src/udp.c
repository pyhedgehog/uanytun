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

#include "udp.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <netdb.h>

void udp_init(udp_socket_t** sock, const char* local_addr, const char* port)
{
  if(!sock || !port) 
    return;
 
  *sock = malloc(sizeof(udp_socket_t));
  if(!*sock)
    return;

  struct addrinfo hints, *res;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_PASSIVE;

  int errcode = getaddrinfo(local_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERR, "Error resolving local address: %s", gai_strerror(errcode));
    free(*sock);
    *sock = NULL;
    return;
  }

  memcpy(&((*sock)->local_end_), res->ai_addr, sizeof(*(res->ai_addr)));
  (*sock)->fd_ = socket(res->ai_family, SOCK_DGRAM, 0);
  if((*sock)->fd_ < 0) {
    log_printf(ERR, "Error on opening udp socket: %m");
    free(*sock);
    *sock = NULL;
    return;
  }

  errcode = bind((*sock)->fd_, res->ai_addr, res->ai_addrlen);
  if(errcode) {
    log_printf(ERR, "Error on binding udp socket: %m");
    free(*sock);
    *sock = NULL;
    return;
  }
  
  freeaddrinfo(res);
}

void udp_set_remote(udp_socket_t* sock, const char* remote_addr, const char* port)
{
  if(!sock || !remote_addr || !port) 
    return;

  struct addrinfo hints, *res;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_CANONNAME;

  int errcode = getaddrinfo(remote_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERR, "Error resolving remote address: %s", gai_strerror(errcode));
    return;
  }
  memcpy(&(sock->remote_end_), res->ai_addr, sizeof(*(res->ai_addr)));
  freeaddrinfo(res);
}

void udp_close(udp_socket_t** sock)
{
  if(!sock || !(*sock))
    return;

  if((*sock)->fd_ > 0)
    close((*sock)->fd_);
}
  
int udp_read(udp_socket_t* sock, u_int8_t* buf, u_int32_t len, struct sockaddr_storage* remote_end_)
{
  if(!sock || !remote_end_)
    return -1;

  return 0;
}

int udp_write(udp_socket_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock)
    return -1;

  return 0;
}

