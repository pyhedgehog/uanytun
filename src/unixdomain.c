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

#define _GNU_SOURCE
#include "datatypes.h"

#include "unixdomain.h"

#include "log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>


int unixdomain_init(unixdomain_t* sock, const char* path)
{
  if(!sock)
    return -1;

  sock->client_fd_ = -1;
  sock->server_fd_ = -1;
  memset(&(sock->server_addr_), 0, sizeof(sock->server_addr_));
  sock->server_addr_.sun_family = AF_UNIX;

  if(!path)
    return 0;

  sock->server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if(sock->server_fd_ < 0) {
    log_printf(ERROR, "Error on opening unix domain socket: %s", strerror(errno));
    return -1;
  }

  strncpy(sock->server_addr_.sun_path, path, sizeof(sock->server_addr_.sun_path)-1);

  unlink(sock->server_addr_.sun_path); // remove stale socket
      // TODO: error handling

  bind(sock->server_fd_, (struct sockaddr*)&(sock->server_addr_), sizeof(sock->server_addr_));
      // TODO: error handling

  listen(sock->server_fd_, 1);
      // TODO: error handling

  log_printf(NOTICE, "unixdomain socket listening on: %s", sock->server_addr_.sun_path);

  return 0;
}

int unixdomain_fill_fd_set(unixdomain_t* sock, fd_set* set)
{
  int max_fd = 0;

  if(sock->server_fd_ >= 0) {
    FD_SET(sock->server_fd_, set);
    max_fd = sock->server_fd_ > max_fd ? sock->server_fd_ : max_fd;
  }

  if(sock->client_fd_ >= 0) {
    FD_SET(sock->client_fd_, set);
    max_fd = sock->client_fd_ > max_fd ? sock->client_fd_ : max_fd;
  }

  return max_fd;
}

void unixdomain_close(unixdomain_t* sock)
{
  if(!sock)
    return;

  if(sock->client_fd_ >= 0)
    close(sock->client_fd_);
  if(sock->server_fd_ >= 0) {
    close(sock->server_fd_);
    unlink(sock->server_addr_.sun_path);
        // TODO: error handling?
  }
}

int unixdomain_accept(unixdomain_t* sock)
{
  if(!sock)
    return -1;

  int new_client = accept(sock->server_fd_, NULL, NULL);
  if(new_client < 0) {
        //  TODO: error HANDLING
    return -1;
  }

  if(sock->client_fd_ < 0)
    sock->client_fd_ = new_client;
  else
    close(new_client);

  return 0;
}

int unixdomain_read(unixdomain_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock || !buf || sock->client_fd_ < 0)
    return -1;

  return recv(sock->client_fd_, buf, len, 0);
}


int unixdomain_write(unixdomain_t* sock, u_int8_t* buf, u_int32_t len)
{
  if(!sock || !buf || sock->client_fd_ < 0)
    return 0;

  return send(sock->client_fd_, buf, len, 0);
}
