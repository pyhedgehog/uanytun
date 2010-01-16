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

int udp_init(udp_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type)
{
  if(!sock || !port) 
    return -1;

  sock->socks_ = NULL;
  sock->active_sock_ = NULL;
  memset(&(sock->remote_end_), 0, sizeof(sock->remote_end_));
  sock->remote_end_set_ = 0;

  struct addrinfo hints, *res;

  res = NULL;
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

  switch(resolv_type) {
  case IPV4_ONLY: hints.ai_family = AF_INET; break;
  case IPV6_ONLY: hints.ai_family = AF_INET6; break;
  default: hints.ai_family = AF_UNSPEC; break;
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

  struct addrinfo* r = res;
  udp_socket_t* prev_sock = NULL;
  while(r) {
    udp_socket_t* new_sock = malloc(sizeof(udp_socket_t));
    if(!new_sock) {
      log_printf(ERROR, "memory error at udp_init");
      freeaddrinfo(res);
      udp_close(sock);
      return -2;
    }
    memset(&(new_sock->local_end_), 0, sizeof(new_sock->local_end_));
    new_sock->next_ = NULL;

    if(!sock->socks_) {
      sock->socks_ = new_sock;
      prev_sock = new_sock;
    }
    else {
      prev_sock->next_ = new_sock;
      prev_sock = new_sock;
    }
    
    memcpy(&(new_sock->local_end_), r->ai_addr, r->ai_addrlen);
    new_sock->fd_ = socket(r->ai_family, SOCK_DGRAM, 0);
    if(new_sock->fd_ < 0) {
      log_printf(ERROR, "Error on opening udp socket: %s", strerror(errno));
      freeaddrinfo(res);
      udp_close(sock);
      return -1;
    }

    if(r->ai_family == AF_INET6) {
      int on = 1;
      if(setsockopt(new_sock->fd_, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)))
        log_printf(ERROR, "Error on setting IPV6_V6ONLY socket option: %s", strerror(errno));
    }

    errcode = bind(new_sock->fd_, r->ai_addr, r->ai_addrlen);
    if(errcode) {
      log_printf(ERROR, "Error on binding udp socket: %s", strerror(errno));
      freeaddrinfo(res);
      udp_close(sock);
      return -1;
    }
  
    char* local_string = udp_endpoint_to_string(new_sock->local_end_);
    if(local_string) {
      log_printf(NOTICE, "listening on: %s", local_string);
      free(local_string);
    }

    r = r->ai_next;
  }

  freeaddrinfo(res);

  return 0;
}

int udp_init_fd_set(udp_t* sock, fd_set* set)
{
  int max_fd = 0;

  udp_socket_t* s = sock->socks_;
  while(s) {
    FD_SET(s->fd_, set);
    max_fd = s->fd_ > max_fd ? s->fd_ : max_fd;
    s = s->next_;
  }

  return max_fd;
}

int udp_set_remote(udp_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type)
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

  if(!sock->active_sock_) {
    udp_socket_t* s = sock->socks_;
    while(s) {
      if((((struct sockaddr *)&s->local_end_)->sa_family) == res->ai_family) {
        sock->active_sock_ = s;
        break;
      }
      s = s->next_;
    }
  }

  freeaddrinfo(res);

  return 0;
}

void udp_set_active_sock(udp_t* sock, int fd)
{
  if(!sock || (sock->active_sock_ && sock->active_sock_->fd_ == fd))
    return;

  udp_socket_t* s = sock->socks_;
  while(s) {
    if(s->fd_ == fd) {
      sock->active_sock_ = s;
      return;
    }
    s = s->next_;
  }
}

void udp_close(udp_t* sock)
{
  if(!sock)
    return;

  while(sock->socks_) {
    if(sock->socks_->fd_ > 0)
      close(sock->socks_->fd_);
    
    udp_socket_t*s = sock->socks_;
    sock->socks_ = sock->socks_->next_;
    
    free(s);
  }
  sock->socks_ = NULL;
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

char* udp_get_remote_end_string(udp_t* sock)
{
  if(!sock || !sock->remote_end_set_)
    return NULL;

  return udp_endpoint_to_string(sock->remote_end_);
}
 
int udp_read(udp_t* sock, int fd, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end)
{
  if(!sock || !remote_end)
    return -1;

  socklen_t socklen = sizeof(*remote_end);
  return recvfrom(fd, buf, len, 0, (struct sockaddr *)remote_end, &socklen);
}

int udp_write(udp_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock || !sock->remote_end_set_ || !sock->active_sock_)
    return 0;

  socklen_t socklen = sizeof(sock->remote_end_);
  if((((struct sockaddr *)&sock->active_sock_->local_end_)->sa_family) == AF_INET)
    socklen = sizeof(struct sockaddr_in);
  else if ((((struct sockaddr *)&sock->active_sock_->local_end_)->sa_family) == AF_INET6)
    socklen = sizeof(struct sockaddr_in6);

  return sendto(sock->active_sock_->fd_, buf, len, 0, (struct sockaddr *)&(sock->remote_end_), socklen);
}

