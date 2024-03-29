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

#define _GNU_SOURCE
#include <stdio.h>

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

#ifndef AI_ADDRCONFIG 
#define AI_ADDRCONFIG 0 
#endif

static int udp_resolv_local(udp_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type, unsigned int* idx)
{
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
  udp_socket_t* prev_sock = sock->socks_;
  while(prev_sock && prev_sock->next_) prev_sock = prev_sock->next_;
  while(r) {
    udp_socket_t* new_sock = malloc(sizeof(udp_socket_t));
    if(!new_sock) {
      log_printf(ERROR, "memory error at udp_init");
      freeaddrinfo(res);
      udp_close(sock);
      return -2;
    }
    memset(&(new_sock->local_end_.addr_), 0, sizeof(new_sock->local_end_.addr_));
    new_sock->local_end_.len_ = sizeof(new_sock->local_end_.addr_);
    memset(&(new_sock->remote_end_.addr_), 0, sizeof(new_sock->remote_end_.addr_));
    new_sock->remote_end_.len_ = sizeof(new_sock->remote_end_.addr_);
    new_sock->remote_end_set_ = 0;
    new_sock->next_ = NULL;
    new_sock->idx_ = (*idx)++;

    if(!sock->socks_) {
      sock->socks_ = new_sock;
      prev_sock = new_sock;
    }
    else {
      prev_sock->next_ = new_sock;
      prev_sock = new_sock;
    }

    memcpy(&(new_sock->local_end_.addr_), r->ai_addr, r->ai_addrlen);
    new_sock->local_end_.len_ = r->ai_addrlen;
    new_sock->fd_ = socket(new_sock->local_end_.addr_.ss_family, SOCK_DGRAM, 0);
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

    errcode = bind(new_sock->fd_, (struct sockaddr*)&(new_sock->local_end_.addr_), new_sock->local_end_.len_);
    if(errcode) {
      log_printf(ERROR, "Error on binding udp socket: %s", strerror(errno));
      freeaddrinfo(res);
      udp_close(sock);
      return -1;
    }

    char* local_string = udp_endpoint_to_string(&(new_sock->local_end_));
    if(local_string) {
      log_printf(NOTICE, "socket[%d] listening on: %s", new_sock->idx_, local_string);
      free(local_string);
    }

    r = r->ai_next;
  }

  freeaddrinfo(res);
  return 0;
}

static int udp_split_port_range(const char* port, const char* colon, u_int32_t* low, u_int32_t* high)
{
  *low = atoi(port);
  *high = atoi(colon+1);
  if(*low < 1 || *low > 65535 || *high < 1 || *high > 65535 || *high < *low) {
    log_printf(ERROR, "illegal port range");
    return -1;
  }
  return 0;
}

int udp_init(udp_t* sock, const char* local_addr, const char* port, resolv_addr_type_t resolv_type, int rail_mode)
{
  if(!sock || !port)
    return -1;

  sock->socks_ = NULL;
  sock->active_sock_ = NULL;
  sock->rail_mode_ = rail_mode;

  unsigned int idx = 0;
  const char* colon = strchr(port, ':');
  if(!colon) {
    int ret = udp_resolv_local(sock, local_addr, port, resolv_type, &idx);
    if(ret)
      return ret;
  } else {
    if(!rail_mode)
      log_printf(WARNING, "A port range has been defined - enabling RAIL mode");
    sock->rail_mode_ = 1;

    u_int32_t port_num, port_end;
    if(udp_split_port_range(port, colon, &port_num, &port_end))
      return -1;
    do {
      char port_str[10];
      snprintf(port_str, sizeof(port_str), "%d", port_num);
      int ret = udp_resolv_local(sock, local_addr, port_str, resolv_type, &idx);
      if(ret)
        return ret;

      port_num++;
    } while(port_num <= port_end);
  }

  if(sock->rail_mode_)
    log_printf(NOTICE, "RAIL mode enabled");

  return 0;
}

int udp_fill_fd_set(udp_t* sock, fd_set* set)
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

int udp_has_remote(udp_t* sock)
{
  if(!sock->rail_mode_ && (!sock->active_sock_ || !sock->active_sock_->remote_end_set_))
    return 0;

  udp_socket_t* s = sock->socks_;
  while(s) {
    if(s->remote_end_set_)
      return 1;
    s = s->next_;
  }

  return 0;
}

static int udp_resolv_remote__(udp_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type)
{
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

  int found = 0;
  struct addrinfo* r = res;
  while(r) {
    udp_socket_t* s = sock->socks_;
    while(s) {
      if(s->local_end_.addr_.ss_family == r->ai_family && !(s->remote_end_set_)) {
        sock->active_sock_ = s;
        break;
      }
      s = s->next_;
    }

    if(s) {
      memcpy(&(s->remote_end_.addr_), r->ai_addr, r->ai_addrlen);
      s->remote_end_.len_ = r->ai_addrlen;
      s->remote_end_set_ = 1;
      found = 1;
      char* remote_string = udp_endpoint_to_string(&(s->remote_end_));
      if(remote_string) {
        log_printf(NOTICE, "socket[%d] set remote end to: %s", s->idx_, remote_string);
        free(remote_string);
      }
      break;
    }

    r = r->ai_next;
  }
  freeaddrinfo(res);

  if(!found)
    log_printf(WARNING, "no remote address for '%s' found that fits any of the local address families", remote_addr);

  return 0;
}

int udp_resolv_remote(udp_t* sock, const char* remote_addr, const char* port, resolv_addr_type_t resolv_type)
{
  if(!sock || !remote_addr || !port)
    return -1;

  const char* colon = strchr(port, ':');
  if(!colon) {
    return udp_resolv_remote__(sock, remote_addr, port, resolv_type);
  } else {
    if(!sock->rail_mode_)
      log_printf(WARNING, "A port range has been defined - enabling RAIL mode");
    sock->rail_mode_ = 1;

    u_int32_t port_num, port_end;
    if(udp_split_port_range(port, colon, &port_num, &port_end))
      return -1;
    do {
      char port_str[10];
      snprintf(port_str, sizeof(port_str), "%d", port_num);
      int ret = udp_resolv_remote__(sock, remote_addr, port_str, resolv_type);
      if(ret)
        return ret;

      port_num++;
    } while(port_num <= port_end);
  }

  return 0;
}

void udp_update_remote(udp_t* sock, int fd, udp_endpoint_t* remote)
{
  if(!sock)
    return;

  if(!(sock->active_sock_) || sock->active_sock_->fd_ != fd) {
    udp_socket_t* s = sock->socks_;
    while(s) {
      if(s->fd_ == fd) {
        sock->active_sock_ = s;
        break;
      }
      s = s->next_;
    }
  }

  if(!remote)
    return;

  if(sock->active_sock_) {
    if(remote->len_ != sock->active_sock_->remote_end_.len_ ||
       memcmp(&(remote->addr_), &(sock->active_sock_->remote_end_.addr_), remote->len_)) {
      memcpy(&(sock->active_sock_->remote_end_.addr_), &(remote->addr_), remote->len_);
      sock->active_sock_->remote_end_.len_ = remote->len_;
      sock->active_sock_->remote_end_set_ = 1;
      char* addrstring = udp_endpoint_to_string(remote);
      log_printf(NOTICE, "socket[%d] autodetected remote host changed %s", sock->active_sock_->idx_, addrstring);
      free(addrstring);
    }
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
  sock->active_sock_ = NULL;
}

char* udp_endpoint_to_string(udp_endpoint_t* e)
{
  if(!e)
    return strdup("<null>");

  char addrstr[INET6_ADDRSTRLEN + 1], portstr[6], *ret;
  char addrport_sep = ':';

  switch(e->addr_.ss_family)
  {
  case AF_INET: addrport_sep = ':'; break;
  case AF_INET6: addrport_sep = '.'; break;
  case AF_UNSPEC: return NULL;
  default: return strdup("<unknown address type>");
  }

  int errcode  = getnameinfo((struct sockaddr *)&(e->addr_), e->len_, addrstr, sizeof(addrstr), portstr, sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV);
  if (errcode != 0) return NULL;
  int len = asprintf(&ret, "%s%c%s", addrstr, addrport_sep ,portstr);
  if(len == -1) return NULL;
  return ret;
}


int udp_read(udp_t* sock, int fd, u_int8_t* buf, u_int32_t len, udp_endpoint_t* remote_end)
{
  if(!sock || !buf || !remote_end)
    return -1;

  return recvfrom(fd, buf, len, 0, (struct sockaddr *)&(remote_end->addr_), &(remote_end->len_));
}


static int udp_write_active_sock(udp_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock->active_sock_ || !sock->active_sock_->remote_end_set_)
    return 0;

  return sendto(sock->active_sock_->fd_, buf, len, 0, (struct sockaddr *)&(sock->active_sock_->remote_end_.addr_), sock->active_sock_->remote_end_.len_);
}

static int udp_write_rail(udp_t* sock, u_int8_t* buf, u_int32_t len)
{
  int i=0;

  udp_socket_t* s = sock->socks_;
  while(s) {
    if(s->remote_end_set_) {
      sendto(s->fd_, buf, len, 0, (struct sockaddr *)&(s->remote_end_.addr_), s->remote_end_.len_);
      i++;
    }
    s = s->next_;
  }

  return len;
}

int udp_write(udp_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock || !buf)
    return 0;

  if(sock->rail_mode_)
    return udp_write_rail(sock, buf, len);

  return udp_write_active_sock(sock, buf, len);
}
