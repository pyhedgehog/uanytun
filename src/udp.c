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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int udp_init(udp_socket_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type)
{
  if(!sock || !port) 
    return -1;
 
  sock->fd_ = 0;
  memset(&(sock->local_end_), 0, sizeof(sock->local_end_));
  memset(&(sock->remote_end_), 0, sizeof(sock->local_end_));
  sock->remote_end_set_ = 0;

  struct addrinfo hints, *res;

  res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags |= AI_PASSIVE;

  switch(resolv_type) {
  case IPV4_ONLY: hints.ai_family = PF_INET; break;
  case IPV6_ONLY: hints.ai_family = PF_INET6; break;
  default: hints.ai_family = PF_UNSPEC; break;
  }

  int errcode = getaddrinfo(local_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERROR, "Error resolving local address (%s:%s): %s", (local_addr) ? local_addr : "*", port, gai_strerror(errcode));
    udp_close(sock);
    return -1;
  }

  if(!res) {
    udp_close(sock);
    log_printf(ERROR, "getaddrinfo returned no address for %s:%s", local_addr, port);
    return -1;
  }

  memcpy(&(sock->local_end_), res->ai_addr, res->ai_addrlen);

  sock->fd_ = socket(res->ai_family, SOCK_DGRAM, 0);
  if(sock->fd_ < 0) {
    log_printf(ERROR, "Error on opening udp socket: %s", strerror(errno));
    freeaddrinfo(res);
    udp_close(sock);
    return -1;
  }

  errcode = bind(sock->fd_, res->ai_addr, res->ai_addrlen);
  if(errcode) {
    log_printf(ERROR, "Error on binding udp socket: %s", strerror(errno));
    freeaddrinfo(res);
    udp_close(sock);
    return -1;
  }
  
#ifdef NO_V4MAPPED
  if(res->ai_family == AF_INET6) {
    log_printf(NOTICE, "disabling V4-Mapped addresses");
    int on = 1;
    if(setsockopt(sock->fd_, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)))
      log_printf(ERROR, "Error on setting IPV6_V6ONLY socket option: %s", strerror(errno));
  }
#endif
  freeaddrinfo(res);

  return 0;
}

int udp_set_remote(udp_socket_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type)
{
  if(!sock || !remote_addr || !port) 
    return -1;

  struct addrinfo hints, *res;

  res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;

  switch(resolv_type) {
  case IPV4_ONLY: hints.ai_family = PF_INET; break;
  case IPV6_ONLY: hints.ai_family = PF_INET6; break;
  default: hints.ai_family = PF_UNSPEC; break;
  }

  int errcode = getaddrinfo(remote_addr, port, &hints, &res);
  if (errcode != 0) {
    log_printf(ERROR, "Error resolving remote address (%s:%s): %s", (remote_addr) ? remote_addr : "*", port, gai_strerror(errcode));
    return -1;
  }
  if(!res) {
    log_printf(ERROR, "getaddrinfo returned no address for %s:%s", remote_addr, port);
    return -1;
  }
  memcpy(&(sock->remote_end_), res->ai_addr, res->ai_addrlen);
  sock->remote_end_set_ = 1;
  freeaddrinfo(res);

  return 0;
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
  char* addrstr, *ret;
  char addrport_sep = ':';

  switch (((struct sockaddr *)&e)->sa_family)
  {
  case AF_INET:
    ptr = &((struct sockaddr_in *)&e)->sin_addr;
    port = ntohs(((struct sockaddr_in *)&e)->sin_port);
    addrstr_len = INET_ADDRSTRLEN + 1;
    addrport_sep = ':';
    break;
  case AF_INET6:
    ptr = &((struct sockaddr_in6 *)&e)->sin6_addr;
    port = ntohs(((struct sockaddr_in6 *)&e)->sin6_port);
    addrstr_len = INET6_ADDRSTRLEN + 1;
    addrport_sep = '.';
    break;
  default:
    asprintf(&ret, "unknown address type");
    return ;
  }
  addrstr = malloc(addrstr_len);
  if(!addrstr)
    return NULL;
  inet_ntop (((struct sockaddr *)&e)->sa_family, ptr, addrstr, addrstr_len);
  asprintf(&ret, "%s%c%d", addrstr, addrport_sep ,port);
  free(addrstr);
  return ret;
}

char* udp_get_local_end_string(udp_socket_t* sock)
{
  if(!sock)
    return NULL;

  return udp_endpoint_to_string(sock->local_end_);
}

char* udp_get_remote_end_string(udp_socket_t* sock)
{
  if(!sock || !sock->remote_end_set_)
    return NULL;

  return udp_endpoint_to_string(sock->remote_end_);
}
 
int udp_read(udp_socket_t* sock, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end)
{
  if(!sock || !remote_end)
    return -1;

  socklen_t socklen = sizeof(*remote_end);
  return recvfrom(sock->fd_, buf, len, 0, (struct sockaddr *)remote_end, &socklen);
}

int udp_write(udp_socket_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock)
    return -1;

  socklen_t socklen = sizeof(sock->remote_end_);
#ifdef NO_V4MAPPED
  if((((struct sockaddr *)&sock->local_end_)->sa_family) == AF_INET)
    socklen = sizeof(struct sockaddr_in);
  else if ((((struct sockaddr *)&sock->local_end_)->sa_family) == AF_INET6)
    socklen = sizeof(struct sockaddr_in6);
#endif
  return sendto(sock->fd_, buf, len, 0, (struct sockaddr *)&(sock->remote_end_), socklen);;
}

