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
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
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

#include "udp.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>

int udp_init(udp_socket_t* sock, const char* local_addr, const char* port)
{
  if(!sock || !port) 
    return;
 
  sock->fd_ = 0;
  memset(&(sock->local_end_), 0, sizeof(sock->local_end_));
  memset(&(sock->remote_end_), 0, sizeof(sock->local_end_));
  sock->remote_end_set_ = 0;

  struct addrinfo hints, *res;

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_PASSIVE;

#ifdef NO_UDPV6
  hints.ai_family = PF_INET;
#else
  hints.ai_family = PF_UNSPEC;
#endif

  int errcode = getaddrinfo(local_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERR, "Error resolving local address: %s", gai_strerror(errcode));
    udp_close(sock);
    return -1;
  }

  memcpy(&(sock->local_end_), res->ai_addr, sizeof(*(res->ai_addr)));

  sock->fd_ = socket(res->ai_family, SOCK_DGRAM, 0);
  if(sock->fd_ < 0) {
    log_printf(ERR, "Error on opening udp socket: %m");
    freeaddrinfo(res);
    udp_close(sock);
    return -1;
  }

  errcode = bind(sock->fd_, res->ai_addr, res->ai_addrlen);
  if(errcode) {
    log_printf(ERR, "Error on binding udp socket: %m");
    freeaddrinfo(res);
    udp_close(sock);
    return -1;
  }
  
  freeaddrinfo(res);

  return 0;
}

void udp_set_remote(udp_socket_t* sock, const char* remote_addr, const char* port)
{
  if(!sock || !remote_addr || !port) 
    return;

  struct addrinfo hints, *res;

  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;

#ifdef NO_UDPV6
  hints.ai_family = PF_INET;
#else
  hints.ai_family = PF_UNSPEC;
#endif

  int errcode = getaddrinfo(remote_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERR, "Error resolving remote address: %s", gai_strerror(errcode));
    return;
  }
  memcpy(&(sock->remote_end_), res->ai_addr, sizeof(*(res->ai_addr)));
  sock->remote_end_set_ = 1;
  freeaddrinfo(res);
}

void udp_close(udp_socket_t* sock)
{
  if(!sock)
    return;

  if(sock->fd_ > 0)
    close(sock->fd_);
}

char* udp_endpoint_to_string(udp_endpoint_t e)
{
  void* ptr;
  u_int16_t port;
  size_t addrstr_len = 0;
  char* addrstr;

  switch (((struct sockaddr *)&e)->sa_family)
  {
  case AF_INET:
    ptr = &((struct sockaddr_in *)&e)->sin_addr;
    port = ntohs(((struct sockaddr_in *)&e)->sin_port);
    addrstr_len = INET_ADDRSTRLEN + 1;
    break;
#ifndef NO_UDPV6
  case AF_INET6:
    ptr = &((struct sockaddr_in6 *)&e)->sin6_addr;
    port = ntohs(((struct sockaddr_in6 *)&e)->sin6_port);
    addrstr_len = INET6_ADDRSTRLEN + 1;
    break;
#endif
  default:
    return "";
  }
  addrstr = malloc(addrstr_len);
  if(!addrstr)
    return NULL;
  inet_ntop (((struct sockaddr *)&e)->sa_family, ptr, addrstr, addrstr_len);
  char* ret;
  asprintf(&ret, "%s:%d", addrstr, port);
  free(addrstr);
  return ret;
}

char* udp_get_local_end_string(udp_socket_t* sock)
{
  if(!sock)
    return "";

  return udp_endpoint_to_string(sock->local_end_);
}

char* udp_get_remote_end_string(udp_socket_t* sock)
{
  if(!sock || !sock->remote_end_set_)
    return "";

  return udp_endpoint_to_string(sock->remote_end_);
}
 
int udp_read(udp_socket_t* sock, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end)
{
  if(!sock || !remote_end)
    return -1;

  int socklen = sizeof(*remote_end);
  return recvfrom(sock->fd_, buf, len, 0, (struct sockaddr *)remote_end, &socklen);
}

int udp_write(udp_socket_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock)
    return -1;

  return sendto(sock->fd_, buf, len, 0, (struct sockaddr *)&(sock->remote_end_), sizeof(sock->remote_end_));;
}

